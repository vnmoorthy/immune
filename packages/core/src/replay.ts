/**
 * Replay — re-run the gate's policy over a corpus of traces with a given rule set, and prove a candidate.
 *
 * A trace may carry up to three phase subjects (toolDef / result / attemptedCall). Replay evaluates each
 * present phase in gate order; a flagged result taints the later tool_call evaluation exactly as the live
 * gate would. Registry-dependent findings recorded on the trace (rug_pull, homoglyph) are reused because
 * the pin/trust registries are not part of the trace.
 */
import { performance } from 'node:perf_hooks';
import type { Decision, Finding, Phase, ProofReport, ReplayCounts, Rule, Trace } from './types.js';
import { sha256 } from './ids.js';
import type { SecretRegistry } from './detectors/index.js';
import { DECISION_RANK, type PolicyInput, evaluateRules, expandRules } from './policy.js';

export interface ReplayOptions {
  allowlist?: string[];
  secrets?: SecretRegistry;
  /** reuse rug_pull / homoglyph findings recorded on the trace (default true) */
  reuseRecordedFindings?: boolean;
}

export interface TraceReplay {
  decision: Decision;
  findings: Finding[];
  blockedBy?: string;
  citation?: string;
  phases: Phase[];
  /** session taint state after replaying this trace */
  tainted: boolean;
}

/** Findings that depend on gate registries rather than content; reused verbatim during replay. */
export const REGISTRY_DETECTORS: ReadonlySet<string> = new Set(['rug_pull', 'homoglyph']);

export function isCaught(decision: Decision): boolean {
  return decision !== 'allow';
}

/** Phase inputs reconstructed from a trace, in gate order (tool_def → tool_result → tool_call). */
export function traceToInputs(trace: Trace): PolicyInput[] {
  const inputs: PolicyInput[] = [];
  if (trace.toolDef) inputs.push({ phase: 'tool_def', sessionId: trace.sessionId, toolDef: trace.toolDef });
  if (trace.result) inputs.push({ phase: 'tool_result', sessionId: trace.sessionId, result: trace.result });
  if (trace.attemptedCall) {
    inputs.push({
      phase: 'tool_call',
      sessionId: trace.sessionId,
      toolDef: trace.toolDef,
      call: {
        server: trace.attemptedCall.server,
        tool: trace.attemptedCall.tool,
        args: trace.attemptedCall.args ?? {},
        capabilities: trace.attemptedCall.capabilities ?? [],
      },
    });
  }
  return inputs;
}

/** Replay one trace against a rule set. */
export function replayTrace(rules: Rule[], trace: Trace, opts: ReplayOptions = {}): TraceReplay {
  const inputs = traceToInputs(trace);
  const recorded = opts.reuseRecordedFindings === false ? [] : (trace.findings ?? []).filter((f) => REGISTRY_DETECTORS.has(f.detector));
  let tainted = Boolean(trace.tainted);
  let decision: Decision = 'allow';
  let blockedBy: string | undefined;
  let citation: string | undefined;
  const findings: Finding[] = [];
  const phases: Phase[] = [];

  for (const input of inputs) {
    phases.push(input.phase);
    const res = evaluateRules(rules, input, {
      tainted,
      allowlist: opts.allowlist,
      secrets: opts.secrets,
      extraFindings: input.phase === 'tool_def' ? recorded : undefined,
    });
    if (input.phase === 'tool_result' && res.decision !== 'allow') tainted = true;
    findings.push(...res.findings);
    if (DECISION_RANK[res.decision] > DECISION_RANK[decision]) {
      decision = res.decision;
      blockedBy = res.blockedBy;
      citation = res.citation;
    }
  }
  const out: TraceReplay = { decision, findings, phases, tainted };
  if (blockedBy) out.blockedBy = blockedBy;
  if (citation) out.citation = citation;
  return out;
}

export interface ReplayDetail {
  counts: ReplayCounts;
  /** attack trace ids caught */
  caughtIds: string[];
  /** benign trace ids blocked/flagged (false positives) */
  fpIds: string[];
  ms: number;
}

/** Replay a corpus; also returns which ids were caught / false-positive. */
export function replayDetailed(rules: Rule[], corpus: Trace[], opts: ReplayOptions = {}): ReplayDetail {
  const t0 = performance.now();
  const counts: ReplayCounts = { attacksTotal: 0, attacksCaught: 0, benignTotal: 0, benignBlocked: 0 };
  const caughtIds: string[] = [];
  const fpIds: string[] = [];
  for (const trace of corpus) {
    const caught = isCaught(replayTrace(rules, trace, opts).decision);
    if (trace.label === 'attack') {
      counts.attacksTotal++;
      if (caught) {
        counts.attacksCaught++;
        caughtIds.push(trace.id);
      }
    } else {
      counts.benignTotal++;
      if (caught) {
        counts.benignBlocked++;
        fpIds.push(trace.id);
      }
    }
  }
  return { counts, caughtIds, fpIds, ms: performance.now() - t0 };
}

/** Replay a corpus with a rule set → counts. */
export function replay(rules: Rule[], corpus: Trace[], opts: ReplayOptions = {}): ReplayCounts {
  return replayDetailed(rules, corpus, opts).counts;
}

export function rateOf(numerator: number, denominator: number): number {
  return denominator > 0 ? numerator / denominator : 0;
}

export function ratesOf(counts: ReplayCounts): { catchRate: number; fpRate: number } {
  return { catchRate: rateOf(counts.attacksCaught, counts.attacksTotal), fpRate: rateOf(counts.benignBlocked, counts.benignTotal) };
}

/** sha256 over the sorted, de-duplicated trace ids — identifies the exact corpus a proof ran on. */
export function corpusHash(corpus: Trace[]): string {
  const ids = [...new Set(corpus.map((t) => t.id))].sort();
  return sha256(ids.join('\n'));
}

export interface ProveExtras extends ReplayOptions {
  semgrep?: { ran: boolean; findings: number; ok: boolean; summary: string };
  storeMs?: number;
  /** clock, for deterministic tests */
  now?: number;
}

const pct = (x: number) => `${(x * 100).toFixed(2)}%`;

/**
 * Prove a candidate antibody: replay before/after over corpus ∪ targets.
 * promoted ⇔ targetCaught && catchRateAfter > catchRateBefore && fpRateAfter <= fpRateBefore
 */
export function prove(candidate: Rule, currentRules: Rule[], corpus: Trace[], targets: Trace[], extras: ProveExtras = {}): ProofReport {
  const t0 = performance.now();
  const candidateSet = expandRules([candidate]).filter((r) => r.status !== 'revoked');
  const candidateIds = new Set(candidateSet.map((r) => r.id));
  const current = expandRules(currentRules).filter((r) => r.status !== 'revoked' && !candidateIds.has(r.id));
  const withCandidate = [...current, ...candidateSet];

  // the targets must be part of the replayed corpus so the catch rate can move
  const byId = new Map<string, Trace>();
  for (const t of corpus) byId.set(t.id, t);
  for (const t of targets) byId.set(t.id, t);
  const replayCorpus = [...byId.values()];

  const opts: ReplayOptions = { allowlist: extras.allowlist, secrets: extras.secrets, reuseRecordedFindings: extras.reuseRecordedFindings };
  const before = replay(current, replayCorpus, opts);
  const after = replay(withCandidate, replayCorpus, opts);
  const { catchRate: catchRateBefore, fpRate: fpRateBefore } = ratesOf(before);
  const { catchRate: catchRateAfter, fpRate: fpRateAfter } = ratesOf(after);

  const targetResults = targets.map((t) => ({ id: t.id, caught: isCaught(replayTrace(withCandidate, t, opts).decision) }));
  const targetCaught = targets.length > 0 && targetResults.every((r) => r.caught);

  const promoted = targetCaught && catchRateAfter > catchRateBefore && fpRateAfter <= fpRateBefore;
  const reasons: string[] = [];
  if (!targets.length) reasons.push('no target traces');
  else if (!targetCaught) reasons.push(`target not caught (${targetResults.filter((r) => !r.caught).map((r) => r.id).join(', ')})`);
  if (!(catchRateAfter > catchRateBefore)) reasons.push(`catch rate did not improve (${pct(catchRateBefore)} → ${pct(catchRateAfter)})`);
  if (!(fpRateAfter <= fpRateBefore)) reasons.push(`false positives increased (${before.benignBlocked} → ${after.benignBlocked} of ${after.benignTotal} benign)`);
  const reason = promoted
    ? `caught ${targets.length} target${targets.length > 1 ? 's' : ''}; catch rate ${pct(catchRateBefore)} → ${pct(catchRateAfter)} (${after.attacksCaught}/${after.attacksTotal}); FP rate ${pct(fpRateBefore)} → ${pct(fpRateAfter)} (${after.benignBlocked}/${after.benignTotal}); corpus ${replayCorpus.length}`
    : `not promoted: ${reasons.join('; ')}`;

  const report: ProofReport = {
    ruleId: candidate.id,
    corpusSize: replayCorpus.length,
    corpusHash: corpusHash(replayCorpus),
    before,
    after,
    catchRateBefore,
    catchRateAfter,
    fpRateBefore,
    fpRateAfter,
    targetCaught,
    replayMs: Math.round((performance.now() - t0) * 1000) / 1000,
    promoted,
    reason,
    ts: extras.now ?? Date.now(),
  };
  if (extras.semgrep) report.semgrep = { ran: extras.semgrep.ran, findings: extras.semgrep.findings, ok: extras.semgrep.ok, summary: extras.semgrep.summary };
  if (extras.storeMs !== undefined) report.storeMs = extras.storeMs;
  return report;
}

/** Copy of the rule (and its companions) carrying the proof and the resulting status (promoted / candidate). */
export function applyProof(rule: Rule, proof: ProofReport): Rule {
  const status = (r: Rule): Rule['status'] => (proof.promoted ? 'promoted' : r.status === 'revoked' ? 'revoked' : 'candidate');
  const out: Rule = { ...rule, proof, status: status(rule) };
  if (rule.companions?.length) out.companions = rule.companions.map((c) => ({ ...c, proof, status: status(c) }));
  return out;
}
