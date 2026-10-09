/**
 * The remediation loop (CONTRACTS.md):
 *   trace_captured → antibody_drafted → replay_proven → semgrep_rescan → receipt_signed → ruling_published
 *   → immunity_verified → timeToImmunityMs
 * Every step is real: synthesis + proof come from @immune/core over the live store corpus, semgrep runs the
 * generated YAML against integrations/semgrep/targets, the receipt is HMAC-signed, the ruling is published
 * (local / Senso) and immunity is verified by re-running the identical scenario (same family + seed) through a
 * fresh gate and asserting the exfil step is denied.
 */
import {
  applyProof,
  complete,
  createLlmRefiner,
  describeMatch,
  detectLlm,
  newId,
  prove,
  receiptSecret,
  replayTrace,
  runSemgrep,
  semgrepAvailable,
  signReceipt,
  synthesizeAntibody,
  synthesizeAntibodyWithRefine,
  type Finding,
  type ProofReport,
  type Remediation,
  type RemediationStep,
  type RemediationStepName,
  type Rule,
  type Ruling,
  type Trace,
} from '@immune/core';
import { runScenario } from '@immune/demo';
import { ALLOWLIST, type Engine, type ScenarioRef } from './engine';
import { publishRuling } from './senso';
import { semgrepTargetsDir } from './paths';
import { FAMILY_META, hostOf, phaseOfTrace } from '@/lib/format';
import { citationText } from '@/lib/citation';

const pct = (x: number) => `${(x * 100).toFixed(2)}%`;
const ms = (x: number) => `${Math.round(x * 10) / 10} ms`;

function dedupeFindings(fs: Finding[]): Finding[] {
  const seen = new Set<string>();
  return fs.filter((f) => {
    const k = `${f.detector}|${f.ruleId ?? ''}|${f.evidence}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

/**
 * The antigen fed to the synthesizer: the breach step plus the session context the agent read before it
 * (the malicious definition / the injected result). The store keeps one trace per step; the replayable
 * unit for synthesis + proof is the step chain.
 */
export function buildAntigen(engine: Engine, breach: Trace): { antigen: Trace; sessionTraces: Trace[] } {
  const session = (engine.sessions.get(breach.sessionId) ?? [breach]).slice().sort((a, b) => a.ts - b.ts);
  const before = session.filter((t) => t.ts <= breach.ts);
  const defT = [...before].reverse().find((t) => t.toolDef);
  const resT = [...before].reverse().find((t) => t.result);
  const antigen: Trace = {
    ...breach,
    toolDef: breach.toolDef ?? defT?.toolDef,
    result: breach.result ?? resT?.result,
    findings: dedupeFindings([...(defT?.findings ?? []), ...(resT?.findings ?? []), ...breach.findings]),
  };
  return { antigen, sessionTraces: session };
}

function phasesOf(t: Trace): string[] {
  const out: string[] = [];
  if (t.toolDef) out.push('tool_def');
  if (t.result) out.push('tool_result');
  if (t.attemptedCall) out.push('tool_call');
  return out;
}

function rulingTitle(antigen: Trace, rule: Rule): string {
  const fam = FAMILY_META[antigen.family]?.label ?? antigen.family;
  const call = antigen.attemptedCall;
  const tool = call?.tool ?? rule.match.tool ?? 'the tool';
  const host = call ? hostOf(Object.values(call.args ?? {}).find((v) => typeof v === 'string' && /^https?:\/\//i.test(v))) : null;
  const dest = host ? ` to ${host}` : '';
  switch (antigen.family) {
    case 'poisoned_description':
      return `${fam}: a tool description may not steer the agent into ${tool}${dest}`;
    case 'result_injection':
      return `${fam}: instructions read from ${antigen.result?.tool ?? 'a tool result'} may not drive ${tool}${dest}`;
    case 'secret_exfil':
      return `${fam}: credentials may not leave the session via ${tool}${dest}`;
    case 'rug_pull':
      return `${fam}: a trusted ${antigen.result?.tool ?? antigen.toolDef?.name ?? 'tool'} may not change behaviour and redirect the agent${dest}`;
    case 'homoglyph_spoof':
      return `${fam}: look-alike tool ${antigen.toolDef?.name ?? antigen.result?.tool ?? tool} may not stand in for a trusted one`;
    case 'indirect_fetch':
      return `${fam}: fetched content may not drive ${tool}${dest}`;
    default:
      return `${fam}: ${tool}${dest} is denied`;
  }
}

function rulingSummary(antigen: Trace, rule: Rule, proof: ProofReport, receiptId: string, ref: ScenarioRef | undefined): string {
  const fam = FAMILY_META[antigen.family];
  const call = antigen.attemptedCall;
  const what = call ? `attempted ${call.tool}(${Object.keys(call.args ?? {}).join(', ')}) with capabilities ${call.capabilities.join('/') || 'none'}` : 'took an unauthorized step';
  const read = antigen.result ? ` after reading ${antigen.result.tool} content that carried the instruction` : antigen.toolDef ? ` after being served a ${antigen.toolDef.name} definition that carried the instruction` : '';
  const variant = ref ? `${antigen.family}/${ref.variant}${ref.mutate ? ` (novel mutation, seed ${ref.seed})` : ''}` : `${antigen.family}/${antigen.variant}`;
  return (
    `${fam?.description ?? ''} In session ${antigen.sessionId} (${variant}) the agent ${what}${read}; the gate allowed it (breach ${antigen.id}). ` +
    `This is forbidden: ${fam?.label ?? antigen.family} turns the agent into an exfiltration channel regardless of destination. ` +
    `Antibody ${rule.id} now matches ${describeMatch(rule.match)} → ${rule.action}${rule.companions?.length ? ` (plus ${rule.companions.length} companion rule${rule.companions.length > 1 ? 's' : ''} on the content the agent reads)` : ''}. ` +
    `Replay proof over ${proof.corpusSize} traces: catch rate ${pct(proof.catchRateBefore)} → ${pct(proof.catchRateAfter)}, false positives ${pct(proof.fpRateBefore)} → ${pct(proof.fpRateAfter)}; receipt ${receiptId}.`
  );
}

export async function runRemediation(engine: Engine, rem: Remediation, breach: Trace, ref: ScenarioRef | undefined, opts: { skipIfCovered: boolean }): Promise<void> {
  rem.startedAt = Date.now();
  const stepOf = (name: RemediationStepName): RemediationStep => rem.steps.find((s) => s.name === name)!;
  const emit = () => engine.bus.emit('remediation', structuredClone(rem));
  emit();

  async function run<T>(name: RemediationStepName, fn: (s: RemediationStep) => Promise<T>): Promise<T> {
    const s = stepOf(name);
    s.status = 'running';
    s.startedAt = Date.now();
    emit();
    try {
      const out = await fn(s);
      s.finishedAt = Date.now();
      if (s.status === 'running') s.status = 'done';
      emit();
      return out;
    } catch (err) {
      s.finishedAt = Date.now();
      s.status = 'failed';
      const msg = (err as Error)?.message ?? String(err);
      s.detail = s.detail ? `${s.detail} · ${msg}` : msg;
      emit();
      throw err;
    }
  }

  const fail = (err: unknown) => {
    rem.status = 'failed';
    rem.finishedAt = Date.now();
    emit();
    engine.emitLog('error', `remediation ${rem.id} failed: ${(err as Error)?.message ?? String(err)}`);
    engine.scheduleMetrics();
  };

  try {
    /* 1 ───────────────────────────────────────────── trace_captured */
    const { antigen, sessionTraces } = await run('trace_captured', async (s) => {
      const built = buildAntigen(engine, breach);
      s.detail = `antigen ${breach.id} · session ${breach.sessionId} · ${built.sessionTraces.length} step${built.sessionTraces.length === 1 ? '' : 's'} · ${breach.family}/${breach.variant}${ref ? ` · seed ${ref.seed}` : ''} · phases ${phasesOf(built.antigen).join('+') || phaseOfTrace(breach)}`;
      s.data = { antigenId: breach.id, sessionTraceIds: built.sessionTraces.map((t) => t.id), seed: ref?.seed };
      return built;
    });

    // Already covered by a rule promoted since the breach (e.g. an earlier remediation in the same ×10 batch)?
    const coveredBy = opts.skipIfCovered ? replayTrace(engine.activeRules(), antigen, { allowlist: ALLOWLIST, secrets: engine.gate.secrets }) : undefined;
    let rule: Rule | undefined;
    let proof: ProofReport | undefined;
    let corpusInfo = '';

    if (coveredBy && coveredBy.decision !== 'allow' && coveredBy.blockedBy) {
      const existing = engine.rules.find((r) => r.id === coveredBy.blockedBy) ?? engine.rules.find((r) => r.companions?.some((c) => c.id === coveredBy.blockedBy));
      const why = `already covered by ${coveredBy.blockedBy}${existing?.receiptId ? ` · receipt ${existing.receiptId}` : ''}${existing?.rulingId ? ` · ruling ${existing.rulingId}` : ''}`;
      for (const name of ['antibody_drafted', 'replay_proven', 'semgrep_rescan', 'receipt_signed', 'ruling_published'] as const) {
        const s = stepOf(name);
        s.status = 'skipped';
        s.detail = why;
        s.startedAt = s.finishedAt = Date.now();
      }
      rule = existing;
      rem.ruleId = existing?.id;
      rem.receiptId = existing?.receiptId;
      rem.rulingId = existing?.rulingId;
      emit();
    } else {
      /* 2 ─────────────────────────────────────────── antibody_drafted */
      const corpus = await run('antibody_drafted', async (s) => {
        const c = await engine.store.corpus();
        corpusInfo = `${c.traces.length} traces from ${engine.storeInfo.kind} in ${ms(c.ms)}`;
        const llm = detectLlm();
        const llmRefine = llm.provider !== 'none' ? createLlmRefiner((p, o) => complete(p, o), c.traces) : undefined;
        const synthOpts = { allowlist: ALLOWLIST, secrets: engine.gate.secrets, llmRefine };
        let drafted = await synthesizeAntibodyWithRefine(antigen, c.traces, synthOpts);
        if (llmRefine) {
          const deterministic = synthesizeAntibody(antigen, c.traces, { allowlist: ALLOWLIST, secrets: engine.gate.secrets });
          if (JSON.stringify(deterministic.match) !== JSON.stringify(drafted.match) || deterministic.name !== drafted.name) drafted = { ...drafted, origin: 'llm' };
        }
        const existing = engine.rules.find((r) => r.id === drafted.id);
        if (existing) drafted = { ...drafted, version: existing.version + 1 };
        drafted = { ...drafted, derivedFrom: [breach.id], status: 'candidate' };
        engine.replaceRule(drafted);
        engine.bus.emit('rule', drafted);
        rule = drafted;
        rem.ruleId = drafted.id;
        s.detail = `${drafted.id} · ${describeMatch(drafted.match)} → ${drafted.action}${drafted.companions?.length ? ` · +${drafted.companions.length} companion` : ''}${drafted.semgrep ? ' · semgrep yaml' : ''} · corpus ${corpusInfo}${llmRefine ? ` · refined by ${llm.provider}${llm.model ? ` ${llm.model}` : ''}` : ' · deterministic'}`;
        s.data = { ruleId: drafted.id, corpusSize: c.traces.length, corpusMs: c.ms, llm: llm.provider };
        return c;
      });

      /* 3 ─────────────────────────────────────────── replay_proven */
      proof = await run('replay_proven', async (s) => {
        const p = prove(rule!, engine.rules, corpus.traces, [antigen], { allowlist: ALLOWLIST, secrets: engine.gate.secrets, storeMs: Math.round(corpus.ms * 100) / 100 });
        rule = applyProof(rule!, p);
        engine.replaceRule(rule);
        engine.bus.emit('rule', rule);
        s.detail = `${p.reason} · replay ${ms(p.replayMs)}${p.storeMs !== undefined ? ` · ${engine.storeInfo.kind} corpus fetch ${ms(p.storeMs)} (${p.corpusSize} rows)` : ''}`;
        s.data = { catchRateBefore: p.catchRateBefore, catchRateAfter: p.catchRateAfter, fpRateBefore: p.fpRateBefore, fpRateAfter: p.fpRateAfter, corpusSize: p.corpusSize, corpusHash: p.corpusHash, promoted: p.promoted };
        if (!p.promoted) throw new Error(`antibody rejected — ${p.reason}`);
        return p;
      });

      /* 4 ─────────────────────────────────────────── semgrep_rescan */
      await run('semgrep_rescan', async (s) => {
        if (!rule!.semgrep) {
          s.status = 'skipped';
          s.detail = 'no source-level sink identified for this antibody — nothing to scan';
          return;
        }
        const avail = await semgrepAvailable();
        if (!avail.installed) {
          s.status = 'skipped';
          s.detail = `semgrep not installed — ${avail.detail ?? 'not on PATH'}`;
          return;
        }
        const targets = semgrepTargetsDir();
        const res = await runSemgrep(rule!.semgrep, [targets], { timeoutMs: 60_000 });
        proof!.semgrep = { ran: res.ran, findings: res.findings, ok: res.ok, summary: res.summary };
        rule = { ...rule!, proof: proof! };
        engine.replaceRule(rule);
        engine.bus.emit('rule', rule);
        const hits = res.results.slice(0, 4).map((r) => `${r.path.split('/').slice(-1)[0]}:${r.line}`).join(', ');
        s.data = { ran: res.ran, findings: res.findings, ok: res.ok, results: res.results.slice(0, 10), command: res.command, ms: res.ms };
        if (!res.ran) {
          s.status = 'failed'; // non-fatal: the runtime antibody is proven; the source scan could not run
          s.detail = `semgrep ${avail.version} could not run — ${res.summary}`;
          return;
        }
        s.detail = `semgrep ${avail.version} · ${res.findings} finding${res.findings === 1 ? '' : 's'} in integrations/semgrep/targets${hits ? ` (${hits})` : ''} · ${ms(res.ms)}${res.ok ? '' : ` · ${res.errors[0] ?? 'errors'}`}`;
      });

      /* 5 ─────────────────────────────────────────── receipt_signed */
      await run('receipt_signed', async (s) => {
        const secret = receiptSecret();
        const receipt = signReceipt(rule!, proof!, secret.secret);
        rule = { ...rule!, receiptId: receipt.id };
        engine.replaceRule(rule);
        engine.receipts.unshift(receipt);
        rem.receiptId = receipt.id;
        engine.bus.emit('receipt', receipt);
        engine.bus.emit('rule', rule);
        s.detail = `${receipt.id} · HMAC-SHA256 over sha256(canonicalJson({ruleId, proof})) · payload ${receipt.payloadHash.slice(0, 16)}… · ${secret.isDefault ? 'dev secret (set IMMUNE_RECEIPT_SECRET)' : 'IMMUNE_RECEIPT_SECRET'}`;
        s.data = { receiptId: receipt.id, payloadHash: receipt.payloadHash };
      });

      /* 6 ─────────────────────────────────────────── ruling_published */
      await run('ruling_published', async (s) => {
        const ruling: Ruling = {
          id: newId('ru'),
          ruleId: rule!.id,
          title: rulingTitle(antigen, rule!),
          summary: rulingSummary(antigen, rule!, proof!, rule!.receiptId!, ref),
          evidenceTraceIds: sessionTraces.map((t) => t.id),
          receiptId: rule!.receiptId!,
          publishedTo: 'local',
          createdAt: Date.now(),
        };
        const pub = await publishRuling(ruling, { family: antigen.family, match: describeMatch(rule!.match), proof: proof! });
        ruling.publishedTo = pub.publishedTo;
        if (pub.externalId) ruling.externalId = pub.externalId;
        engine.rulings.unshift(ruling);
        rule = { ...rule!, rulingId: ruling.id };
        engine.replaceRule(rule); // citationFor() now resolves for the gate
        rem.rulingId = ruling.id;
        engine.bus.emit('ruling', ruling);
        engine.bus.emit('rule', rule);
        s.detail = `${ruling.id} · ${pub.detail} · "${citationText(ruling)}"`;
        s.data = { rulingId: ruling.id, publishedTo: ruling.publishedTo, externalId: ruling.externalId };
      });
    }

    /* 7 ───────────────────────────────────────────── immunity_verified */
    await run('immunity_verified', async (s) => {
      const sessionId = newId('ses');
      const { gate, inner } = engine.runGate();
      let traces: Trace[];
      let how: string;
      if (ref) {
        const raw = runScenario({ family: ref.family, variant: ref.mutate ? undefined : ref.variant, mutate: ref.mutate, seed: ref.seed, gate, sessionId, allowlist: ALLOWLIST });
        traces = engine.normalize(raw, sessionId);
        for (const t of traces) engine.scenarioIndex.set(t.id, { ...ref, sessionId });
        how = `re-ran ${ref.family}/${ref.variant}${ref.mutate ? ` (seed ${ref.seed})` : ''} in fresh session ${sessionId}`;
      } else {
        // proxy-ingested breach: replay the recorded steps through a fresh gate in a new session
        const base = Date.now();
        traces = [];
        const mk = (partial: Partial<Trace>, verdict: { decision: Trace['decision']; findings: Finding[]; blockedBy?: string; citation?: string; latencyMs: number; tainted: boolean }, i: number): Trace => ({
          id: newId('tr'),
          sessionId,
          ts: base + i,
          family: antigen.family,
          variant: antigen.variant,
          label: 'attack',
          tainted: verdict.tainted,
          findings: verdict.findings,
          decision: verdict.decision,
          breached: false,
          blockedBy: verdict.blockedBy,
          citation: verdict.citation,
          latencyMs: verdict.latencyMs,
          ...partial,
        });
        let i = 0;
        if (antigen.toolDef) traces.push(mk({ toolDef: antigen.toolDef }, gate.inspectToolDef(antigen.toolDef, sessionId), i++));
        if (antigen.result) traces.push(mk({ result: antigen.result }, gate.inspectResult({ callId: newId('call'), ts: base, ...antigen.result }, sessionId), i++));
        if (antigen.attemptedCall) {
          const c = antigen.attemptedCall;
          const def = antigen.toolDef?.name === c.tool ? antigen.toolDef : { server: c.server, name: c.tool, description: '', inputSchema: {}, capabilities: c.capabilities };
          const v = gate.inspectCall({ id: newId('call'), sessionId, server: c.server, tool: c.tool, args: c.args, ts: base }, def, sessionId);
          traces.push(mk({ attemptedCall: c, breached: v.decision === 'allow' }, v, i++));
        }
        how = `replayed the recorded ${antigen.family} steps through a fresh gate in session ${sessionId}`;
      }
      engine.absorbQuarantine(inner, traces);
      await engine.recordTraces(traces, { emit: true, source: 'verify' });

      const exfil = [...traces].reverse().find((t) => t.attemptedCall);
      const breachedAgain = traces.filter((t) => t.breached);
      const citation = exfil?.citation ?? traces.find((t) => t.citation)?.citation;
      s.data = { sessionId, traceIds: traces.map((t) => t.id), exfilTraceId: exfil?.id, blockedBy: exfil?.blockedBy, citation };
      if (!exfil || breachedAgain.length || exfil.decision === 'allow' || !exfil.blockedBy) {
        throw new Error(`${how} → identical attack was NOT denied (${exfil ? `${exfil.attemptedCall!.tool} ${exfil.decision}${exfil.blockedBy ? ` by ${exfil.blockedBy}` : ', no blocking rule'}` : 'no call recorded'})`);
      }
      s.detail = `${how} → ${exfil.attemptedCall!.tool} ${exfil.decision.toUpperCase()} by ${exfil.blockedBy}${citation ? ` · "${citation}"` : ' · no citation'}`;
    });

    rem.finishedAt = Date.now();
    rem.timeToImmunityMs = rem.finishedAt - breach.ts;
    rem.status = 'immune';
    engine.ttiHistory.push({ ts: rem.finishedAt, ms: rem.timeToImmunityMs, remediationId: rem.id, family: rem.family });
    emit();
    engine.emitLog('info', `${rem.id} immune in ${ms(rem.timeToImmunityMs)} · ${rem.family} · antibody ${rem.ruleId ?? '—'} · ruling ${rem.rulingId ?? '—'}`);
    engine.scheduleMetrics();
  } catch (err) {
    fail(err);
  }
}
