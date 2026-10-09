/**
 * corpus.ts — fast, pure trace generation for flooding the store.
 *
 * No agent loop, no Gate: generateCorpus clones precomputed variant templates
 * into Trace rows as fast as possible (50k rows in well under ~3s). It reuses
 * the exact same variant payloads as attacks.ts, so a rule synthesized from a
 * live breach replays meaningfully over the flood.
 *
 * Each generated trace carries a `decision` that reflects what Immune's builtin
 * detection would do (a robust, capability- and destination-aware heuristic
 * kept deliberately close to the detector semantics in CONTRACTS.md). An
 * optional `rules` set can only strengthen a decision, mirroring replay.
 */

import type { Capability, Decision, Finding, Trace } from '@immune/core';
import {
  type AttackVariant,
  allVariants,
  benignTraffic,
  mutate,
  mutateNaive,
  ATTACK_FAMILIES,
} from './attacks.js';
import {
  DEFAULT_ALLOWLIST,
  type HeuristicRule,
  capabilitiesOf,
  clampExcerpt,
  findingForRule,
  firstHost,
  hasHomoglyph,
  isAllowedHost,
  looksLikeSecret,
  makeIdGen,
  mulberry32,
  ruleMatches,
  strongerDecision,
} from './util.js';

export interface GenerateCorpusOpts {
  /** number of attack traces to generate. */
  attacks: number;
  /** number of benign traces to generate. */
  benign: number;
  /** deterministic seed. */
  seed?: number;
  /** optional rules; when present they can only strengthen a decision. */
  rules?: HeuristicRule[];
  /** allowlist for the destination detector. */
  allowlist?: readonly string[];
}

/** A precomputed, cloneable trace shape (everything except id/sessionId/ts). */
interface TraceTemplate {
  family: Trace['family'];
  variant: string;
  label: 'attack' | 'benign';
  toolDef?: Trace['toolDef'];
  result?: Trace['result'];
  attemptedCall?: Trace['attemptedCall'];
  tainted: boolean;
  findings: Finding[];
  decision: Decision;
  breached: boolean;
  blockedBy?: string;
}

/** Capabilities for a variant's hijack call (fall back to its tool def). */
function callCapabilities(v: AttackVariant): Capability[] {
  const caps = capabilitiesOf(v.tool);
  if (caps.length) return caps;
  if (v.toolDef && v.toolDef.name === v.tool) return v.toolDef.capabilities;
  return v.toolDef?.capabilities ?? [];
}

/** Destination host for a variant's hijack call. */
function callHost(v: AttackVariant): string | undefined {
  const argsText = JSON.stringify(v.args);
  return firstHost(argsText) ?? v.destinationHost;
}

/**
 * Robust builtin classification — what the gate's builtin detectors would do to
 * this attack with no synthesized rules in play. Destination- and capability-
 * aware, so it is not fooled by paraphrase/obfuscation.
 */
function classifyAttack(
  v: AttackVariant,
  allowlist: readonly string[],
): { decision: Decision; findings: Finding[]; tainted: boolean; carriesSecret: boolean; host?: string } {
  const findings: Finding[] = [];
  let decision: Decision = 'allow';
  const caps = callCapabilities(v);
  const host = callHost(v);
  const carriesSecret = v.carriesSecret || looksLikeSecret(JSON.stringify(v.args));

  // evasive class: compliance phrasing below the injection threshold, allowlisted sink, transformed secret —
  // the builtin gate allows it (verified against the real Gate), so the corpus records it as a breach.
  if (v.evasive) return { decision: 'allow', findings: [], tainted: false, carriesSecret: true, host };

  // homoglyph look-alike tool name
  if (v.toolDef && hasHomoglyph(v.toolDef.name)) {
    findings.push({
      detector: 'homoglyph',
      severity: 'high',
      message: `Look-alike tool name "${v.toolDef.name}" shadows a trusted tool.`,
      evidence: clampExcerpt(v.toolDef.name),
    });
    decision = strongerDecision(decision, 'quarantine');
  }

  // rug pull: definition changed from a trusted original
  if (v.family === 'rug_pull' && v.originalToolDef && v.toolDef && v.originalToolDef.hash !== v.toolDef.hash) {
    findings.push({
      detector: 'rug_pull',
      severity: 'high',
      message: `Tool "${v.toolDef.name}" definition changed after being trusted.`,
      evidence: clampExcerpt(v.toolDef.description),
    });
    decision = strongerDecision(decision, 'quarantine');
  }

  // poisoned description / result injection: imperative text in def or content
  if (v.delivery === 'poisoned_tool_description' || v.delivery === 'changed_tool_def') {
    findings.push({
      detector: 'poisoned_description',
      severity: 'medium',
      message: 'Tool description carries imperative instructions to the agent.',
      evidence: clampExcerpt(v.payload),
    });
    decision = strongerDecision(decision, 'flag');
  } else if (v.delivery === 'doc_content' || v.delivery === 'fetched_page') {
    findings.push({
      detector: 'result_injection',
      severity: 'medium',
      message: 'Tool result carries instructions that attempt to hijack the agent.',
      evidence: clampExcerpt(v.payload),
    });
    decision = strongerDecision(decision, 'flag');
  }

  // secret exfil: a credential is being shipped out
  if (carriesSecret) {
    findings.push({
      detector: 'secret_exfil',
      severity: 'critical',
      message: 'Outbound call carries a credential-looking token.',
      evidence: 'secret token in call args',
    });
    decision = strongerDecision(decision, 'block');
  }

  // destination allowlist: network/exec egress to a non-allowed host
  if ((caps.includes('network') || caps.includes('exec')) && host && !isAllowedHost(host, allowlist)) {
    findings.push({
      detector: 'destination',
      severity: 'high',
      message: `Destination host "${host}" is not in the allowlist.`,
      evidence: host,
    });
    decision = strongerDecision(decision, 'block');
  }

  return { decision, findings, tainted: v.tainting, carriesSecret, host };
}

/** Build an attack template (decision computed once, cloned many times). */
function attackTemplate(v: AttackVariant, allowlist: readonly string[], rules?: HeuristicRule[]): TraceTemplate {
  const { decision, findings, tainted, carriesSecret, host } = classifyAttack(v, allowlist);
  const caps = callCapabilities(v);

  const result =
    v.delivery === 'doc_content'
      ? { server: 'acme', tool: 'read_shared_doc', content: v.payload }
      : v.delivery === 'fetched_page'
        ? { server: 'acme', tool: 'fetch_url', content: v.payload }
        : undefined;

  let finalDecision = decision;
  const finalFindings = [...findings];
  let blockedBy: string | undefined;

  // optional rules can only strengthen
  if (rules && rules.length) {
    const text =
      v.delivery === 'doc_content' || v.delivery === 'fetched_page'
        ? v.payload
        : JSON.stringify(v.args);
    for (const rule of rules) {
      const matched = ruleMatches(rule, {
        phase: 'tool_call',
        server: 'acme',
        tool: v.tool,
        text: `${text} ${JSON.stringify(v.args)}`,
        capabilities: caps,
        tainted,
        host,
        carriesSecret,
      });
      if (matched) {
        finalFindings.push(findingForRule(rule, `Matched synthesized rule ${rule.id}.`, text));
        const next = strongerDecision(finalDecision, rule.action);
        if (next !== finalDecision) {
          finalDecision = next;
          blockedBy = rule.id;
        }
      }
    }
  }

  return {
    family: v.family,
    variant: v.variant,
    label: 'attack',
    toolDef: v.toolDef,
    result,
    attemptedCall: { server: 'acme', tool: v.tool, args: v.args, capabilities: caps },
    tainted,
    findings: finalFindings,
    decision: finalDecision,
    breached: finalDecision === 'allow',
    blockedBy,
  };
}

/** Build the benign templates (always allowed under a correct allowlist). */
function benignTemplates(count: number, seed: number, allowlist: readonly string[]): TraceTemplate[] {
  const sessions = benignTraffic(Math.max(24, Math.min(count, 200)), seed);
  const templates: TraceTemplate[] = [];
  for (const s of sessions) {
    for (const call of s.calls) {
      const caps = capabilitiesOf(call.tool);
      const host = firstHost(JSON.stringify(call.args));
      // a correct benign session never leaves the allowlist
      const findings: Finding[] = [];
      const decision: Decision = 'allow';
      templates.push({
        family: 'benign',
        variant: 'legit',
        label: 'benign',
        attemptedCall: { server: 'acme', tool: call.tool, args: call.args, capabilities: caps },
        tainted: false,
        findings,
        decision,
        breached: false,
      });
      void host;
      void allowlist;
    }
  }
  return templates;
}

/**
 * Generate a corpus of `attacks` attack traces and `benign` benign traces.
 * Pure + deterministic given `seed`. Fast enough for 50k+ rows.
 */
export function generateCorpus(opts: GenerateCorpusOpts): Trace[] {
  const seed = opts.seed ?? 1;
  const allowlist = opts.allowlist ?? DEFAULT_ALLOWLIST;
  const rng = mulberry32((seed * 2654435761) >>> 0);
  const idGen = makeIdGen('tr', rng);
  const sidGen = makeIdGen('sess', rng);

  // attack template pool: all hand-written variants + a batch of mutated ones
  const pool: TraceTemplate[] = [];
  for (const v of allVariants()) pool.push(attackTemplate(v, allowlist, opts.rules));
  for (const family of ATTACK_FAMILIES) {
    for (let k = 0; k < 4; k++) {
      pool.push(attackTemplate(mutateNaive(family, seed * 97 + k), allowlist, opts.rules));
    }
    // the evasive class the builtin gate misses — these are the corpus breaches an antibody must learn to catch
    for (let k = 0; k < 3; k++) {
      pool.push(attackTemplate(mutate(family, seed * 131 + k), allowlist, opts.rules));
    }
  }

  const benignPool = benignTemplates(opts.benign, seed, allowlist);

  const out: Trace[] = new Array(Math.max(0, opts.attacks) + Math.max(0, opts.benign));
  let w = 0;
  const now = Date.now();

  // spread timestamps over a plausible recent window for timeline charts
  const spanMs = 60 * 60 * 1000;

  for (let i = 0; i < opts.attacks; i++) {
    const t = pool[i % pool.length]!;
    out[w++] = cloneTemplate(t, idGen(), sidGen(), now - Math.floor(rng() * spanMs), 0.2 + rng() * 2.4);
  }
  for (let i = 0; i < opts.benign; i++) {
    const t = benignPool.length ? benignPool[i % benignPool.length]! : FALLBACK_BENIGN;
    out[w++] = cloneTemplate(t, idGen(), sidGen(), now - Math.floor(rng() * spanMs), 0.1 + rng() * 1.2);
  }

  return out;
}

const FALLBACK_BENIGN: TraceTemplate = {
  family: 'benign',
  variant: 'legit',
  label: 'benign',
  attemptedCall: { server: 'acme', tool: 'lookup_customer', args: { id: '1001' }, capabilities: ['read'] },
  tainted: false,
  findings: [],
  decision: 'allow',
  breached: false,
};

function cloneTemplate(
  t: TraceTemplate,
  id: string,
  sessionId: string,
  ts: number,
  latencyMs: number,
): Trace {
  return {
    id,
    sessionId,
    ts,
    family: t.family,
    variant: t.variant,
    label: t.label,
    toolDef: t.toolDef,
    result: t.result,
    attemptedCall: t.attemptedCall,
    tainted: t.tainted,
    findings: t.findings,
    decision: t.decision,
    breached: t.breached,
    blockedBy: t.blockedBy,
    latencyMs: Math.round(latencyMs * 100) / 100,
  };
}
