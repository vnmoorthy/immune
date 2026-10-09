/**
 * Policy: turns detector findings + declarative antibody rules into one decision.
 * Precedence: quarantine > block > flag > allow.
 *
 * Builtin rules (origin 'builtin', id `rl_builtin_<detector>`) are enforced by their detector; their
 * `match` is a declarative summary for display. Revoking a builtin rule disables enforcement of that
 * detector ("blocked unless the rule allows"). Synthesized / llm rules are matched declaratively.
 */
import type { Capability, Decision, Finding, Rule, RuleMatch, Severity } from './types.js';
import {
  type DetectorInput,
  type HashPinRegistry,
  type SecretRegistry,
  type TrustedTools,
  argsText,
  excerpt,
  extractHosts,
  findSecretsInArgs,
  hostAllowed,
  makeFinding,
  normalizeText,
  runDetectors,
  textViews,
} from './detectors/index.js';

export const DECISION_RANK: Record<Decision, number> = { allow: 0, flag: 1, block: 2, quarantine: 3 };

export function compareDecisions(a: Decision, b: Decision): number {
  return DECISION_RANK[a] - DECISION_RANK[b];
}

export function maxDecision(...decisions: Decision[]): Decision {
  let out: Decision = 'allow';
  for (const d of decisions) if (DECISION_RANK[d] > DECISION_RANK[out]) out = d;
  return out;
}

export function minDecision(a: Decision, b: Decision): Decision {
  return DECISION_RANK[a] <= DECISION_RANK[b] ? a : b;
}

/** 2025-01-01T00:00:00Z — fixed createdAt for builtin rules so they hash identically everywhere. */
export const BUILTIN_CREATED_AT = 1735689600000;

export const BUILTIN_RULE_IDS = {
  poisoned_description: 'rl_builtin_poisoned_description',
  rug_pull: 'rl_builtin_rug_pull',
  homoglyph: 'rl_builtin_homoglyph',
  result_injection: 'rl_builtin_result_injection',
  secret_exfil: 'rl_builtin_secret_exfil',
  destination: 'rl_builtin_destination',
  taint_gate: 'rl_builtin_taint_gate',
} as const satisfies Record<string, string>;

export type BuiltinDetector = keyof typeof BUILTIN_RULE_IDS;

export function isBuiltinRule(rule: Rule): boolean {
  return rule.origin === 'builtin' || rule.id.startsWith('rl_builtin_');
}

/** Flatten `companions` (one level) into the rule list, de-duplicated by id, order preserved. */
export function expandRules(rules: Rule[]): Rule[] {
  const seen = new Set<string>();
  const out: Rule[] = [];
  const push = (r: Rule) => {
    if (!r || seen.has(r.id)) return;
    seen.add(r.id);
    out.push(r);
  };
  for (const r of rules) {
    push(r);
    for (const c of r.companions ?? []) push(c);
  }
  return out;
}

/** Detector id a builtin rule enforces, if any. */
export function detectorForRule(rule: Rule): BuiltinDetector | undefined {
  for (const [det, id] of Object.entries(BUILTIN_RULE_IDS)) if (id === rule.id) return det as BuiltinDetector;
  return undefined;
}

/** Canonical phrases shown as the "match summary" of builtin rules (enforcement is by the detector). */
const POISON_SUMMARY_PATTERNS = [
  '<important>',
  'do not (tell|mention|inform)[^.]{0,20}the user',
  '~/\\.ssh|\\.env\\b|\\.aws/credentials|id_rsa',
  'pass[^.]{0,40}(contents?|value)[^.]{0,40}as[^.]{0,20}(parameter|argument|sidenote)',
];
const INJECTION_SUMMARY_PATTERNS = [
  'ignore[^.]{0,30}(previous|prior|above)[^.]{0,20}instructions',
  'you must now (call|invoke|run|send|post)',
  '(send|post|forward|upload)[^.]{0,60}(credentials?|secrets?|tokens?|api[ _-]?keys?)[^.]{0,40}(to|via)[^.]{0,20}https?://',
  '(note|attention|message) (to|for) the (ai|assistant|agent)',
];

/** The seven builtin antibodies. `allowlist` is embedded in the destination rule's match for display. */
export function builtinRules(allowlist?: string[]): Rule[] {
  const base = {
    version: 1,
    createdAt: BUILTIN_CREATED_AT,
    origin: 'builtin' as const,
    derivedFrom: [] as string[],
    status: 'promoted' as const,
  };
  return [
    {
      ...base,
      id: BUILTIN_RULE_IDS.poisoned_description,
      name: 'Poisoned tool description',
      match: { phase: 'tool_def', patterns: POISON_SUMMARY_PATTERNS },
      action: 'quarantine',
      severity: 'critical',
    },
    {
      ...base,
      id: BUILTIN_RULE_IDS.rug_pull,
      name: 'Rug pull — definition changed after pinning',
      match: { phase: 'tool_def' },
      action: 'quarantine',
      severity: 'critical',
    },
    {
      ...base,
      id: BUILTIN_RULE_IDS.homoglyph,
      name: 'Look-alike tool name (homoglyph / edit distance)',
      match: { phase: 'tool_def' },
      action: 'quarantine',
      severity: 'critical',
    },
    {
      ...base,
      id: BUILTIN_RULE_IDS.result_injection,
      name: 'Instruction injection in tool result',
      match: { phase: 'tool_result', patterns: INJECTION_SUMMARY_PATTERNS },
      action: 'flag',
      severity: 'high',
    },
    {
      ...base,
      id: BUILTIN_RULE_IDS.secret_exfil,
      name: 'Secret in outbound call arguments',
      match: { phase: 'tool_call', capabilities: ['network', 'exec', 'write'], carriesSecret: true },
      action: 'block',
      severity: 'critical',
    },
    {
      ...base,
      id: BUILTIN_RULE_IDS.destination,
      name: 'Destination host not allowlisted',
      match: { phase: 'tool_call', capabilities: ['network', 'exec'], destinationNotIn: [...(allowlist ?? [])] },
      action: 'block',
      severity: 'high',
    },
    {
      ...base,
      id: BUILTIN_RULE_IDS.taint_gate,
      name: 'Tainted session — sensitive capability gate',
      match: { phase: 'tool_call', afterTainted: true, capabilities: ['network', 'exec', 'write', 'secret'] },
      action: 'block',
      severity: 'high',
    },
  ];
}

/* ------------------------------------------------------------------------------------------------
 * Matching
 * ---------------------------------------------------------------------------------------------- */

export type PolicyInput = DetectorInput;

export interface PolicyContext {
  tainted?: boolean;
  taintReason?: string;
  allowlist?: string[];
  secrets?: SecretRegistry;
  pins?: HashPinRegistry;
  trusted?: TrustedTools;
  /** precomputed detector findings — when present, detectors are NOT run */
  findings?: Finding[];
  /** extra findings merged into the evaluation (e.g. registry-dependent findings recorded on a trace) */
  extraFindings?: Finding[];
  /** the subject tool is currently quarantined */
  quarantined?: { reason: string; since: number } | null;
  /** citation text for a rule (e.g. its published ruling); default uses rule.rulingId */
  citationFor?: (rule: Rule) => string | undefined;
}

export interface PolicyResult {
  decision: Decision;
  findings: Finding[];
  blockedBy?: string;
  citation?: string;
}

export interface RuleMatchResult {
  matched: boolean;
  evidence: string;
  why: string;
}

interface Subject {
  server: string;
  tool: string;
  text: string;
  caps: Capability[];
  args?: Record<string, unknown>;
}

function subjectOf(input: PolicyInput): Subject | null {
  switch (input.phase) {
    case 'tool_def': {
      const d = input.toolDef;
      if (!d) return null;
      let schema = '';
      try {
        schema = d.inputSchema ? JSON.stringify(d.inputSchema) : '';
      } catch {
        schema = '';
      }
      return { server: d.server, tool: d.name, text: `${d.name}\n${d.description ?? ''}\n${schema}`, caps: d.capabilities ?? [] };
    }
    case 'tool_result': {
      const r = input.result;
      if (!r) return null;
      return { server: r.server, tool: r.tool, text: r.content ?? '', caps: [] };
    }
    case 'tool_call': {
      const c = input.call;
      if (!c) return null;
      return { server: c.server, tool: c.tool, text: argsText(c.args), caps: c.capabilities ?? input.toolDef?.capabilities ?? [], args: c.args };
    }
    default:
      return null;
  }
}

const PATTERN_CACHE = new Map<string, RegExp | null>();
const PATTERN_CACHE_MAX = 2048;
const PATTERN_MAX_LEN = 600;

/** A pattern is case-sensitive when its source contains a literal uppercase letter (escape classes like \W, \S don't count). */
export function patternIsCaseSensitive(src: string): boolean {
  return /[A-Z]/.test(src.replace(/\\./g, ''));
}

/** Compile a pattern source (cached). Case-insensitive unless it contains literal uppercase. Null for invalid / oversized sources. */
export function compilePattern(src: string): RegExp | null {
  const hit = PATTERN_CACHE.get(src);
  if (hit !== undefined) return hit;
  let re: RegExp | null = null;
  if (typeof src === 'string' && src.length > 0 && src.length <= PATTERN_MAX_LEN) {
    const base = patternIsCaseSensitive(src) ? '' : 'i';
    try {
      re = new RegExp(src, `${base}u`);
    } catch {
      try {
        re = new RegExp(src, base);
      } catch {
        re = null;
      }
    }
  }
  if (PATTERN_CACHE.size >= PATTERN_CACHE_MAX) {
    const first = PATTERN_CACHE.keys().next().value;
    if (first !== undefined) PATTERN_CACHE.delete(first);
  }
  PATTERN_CACHE.set(src, re);
  return re;
}

export function hasDeclarativeConstraint(match: RuleMatch): boolean {
  return Boolean(
    match.server ||
      match.tool ||
      (match.patterns && match.patterns.length) ||
      (match.capabilities && match.capabilities.length) ||
      match.afterTainted === true ||
      (match.destinationNotIn && match.destinationNotIn.length) ||
      match.carriesSecret === true,
  );
}

const eqi = (a: string | undefined, b: string | undefined) => (a ?? '').toLowerCase() === (b ?? '').toLowerCase();

/** Declarative match of one rule against one inspection. `patterns` are ANY-of; every other present field must hold. */
export function ruleMatches(rule: Rule, input: PolicyInput, ctx: PolicyContext = {}): RuleMatchResult {
  const no = (why: string): RuleMatchResult => ({ matched: false, evidence: '', why });
  const m = rule.match;
  if (!m || m.phase !== input.phase) return no('phase');
  if (!hasDeclarativeConstraint(m)) return no('no constraints');
  const subject = subjectOf(input);
  if (!subject) return no('no subject');
  const why: string[] = [];
  let evidence = '';

  if (m.server && !eqi(m.server, subject.server)) return no('server');
  if (m.server) why.push(`server=${m.server}`);
  if (m.tool && !eqi(m.tool, subject.tool)) return no('tool');
  if (m.tool) why.push(`tool=${m.tool}`);
  if (m.afterTainted === true) {
    if (!(ctx.tainted ?? input.tainted)) return no('not tainted');
    why.push('session tainted');
  }
  if (m.capabilities && m.capabilities.length) {
    const hit = m.capabilities.filter((c) => subject.caps.includes(c));
    if (!hit.length) return no('capabilities');
    why.push(`capability ${hit.join('/')}`);
  }
  if (m.patterns && m.patterns.length) {
    const views = textViews(normalizeText(subject.text));
    let found = false;
    for (const src of m.patterns) {
      const re = compilePattern(src);
      if (!re) continue;
      for (const view of views) {
        re.lastIndex = 0;
        const hit = re.exec(view);
        if (hit) {
          found = true;
          evidence = excerpt(view, hit.index, hit[0].length);
          why.push(`pattern /${src.length > 48 ? `${src.slice(0, 45)}…` : src}/`);
          break;
        }
      }
      if (found) break;
    }
    if (!found) return no('patterns');
  }
  if (m.destinationNotIn && m.destinationNotIn.length) {
    const refs = extractHosts(subject.args ?? {});
    if (!refs.length) return no('no destination');
    const bad = refs.filter((r) => !hostAllowed(r.host, m.destinationNotIn!));
    if (!bad.length) return no('destination allowlisted');
    const hosts = [...new Set(bad.map((b) => b.host))];
    why.push(`destination ${hosts.join(', ')} not allowlisted`);
    if (!evidence) evidence = bad.map((b) => `${b.path}: ${b.url ?? b.host}`).join('; ');
  }
  if (m.carriesSecret === true) {
    const hits = findSecretsInArgs(subject.args ?? {}, ctx.secrets ?? input.secrets);
    if (!hits.length) return no('no secret');
    why.push(`carries secret (${[...new Set(hits.map((h) => h.kind))].join(', ')})`);
    if (!evidence) evidence = hits.map((h) => `${h.path ?? 'args'}=${h.redacted}`).join('; ');
  }
  return { matched: true, evidence, why: why.join('; ') };
}

/** Enforcement decision for a detector finding under a rule's action ceiling. */
export function decisionForSeverity(ceiling: Decision, severity: Severity): Decision {
  switch (severity) {
    case 'critical':
    case 'high':
      return ceiling;
    case 'medium':
      return minDecision(ceiling, 'flag');
    default:
      return 'allow';
  }
}

interface Contribution {
  decision: Decision;
  rule?: Rule;
  finding: Finding;
}

function winnerRank(c: Contribution): number {
  const r = c.rule;
  if (!r) return 4;
  if (r.rulingId) return 0;
  if (!isBuiltinRule(r) && r.status === 'promoted') return 1;
  if (!isBuiltinRule(r)) return 2;
  return 3;
}

export function defaultCitation(rule: Rule): string | undefined {
  return rule.rulingId ? `${rule.rulingId}: ${rule.name}` : undefined;
}

function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const f of findings) {
    const key = `${f.detector}|${f.ruleId ?? ''}|${f.evidence}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  return out;
}

/**
 * Evaluate detectors + rules for one inspection.
 * - detector findings are enforced through their builtin rule (if present & not revoked)
 * - non-builtin rules are matched declaratively
 * - decision = max over contributions; blockedBy = the winning rule (block/quarantine only)
 */
export function evaluateRules(rules: Rule[], input: PolicyInput, ctx: PolicyContext = {}): PolicyResult {
  const active = expandRules(rules).filter((r) => r.status !== 'revoked');
  const detectorInput: DetectorInput = {
    ...input,
    tainted: ctx.tainted ?? input.tainted,
    taintReason: ctx.taintReason ?? input.taintReason,
    allowlist: ctx.allowlist ?? input.allowlist,
    secrets: ctx.secrets ?? input.secrets,
    pins: ctx.pins ?? input.pins,
    trusted: ctx.trusted ?? input.trusted,
  };
  const detected = ctx.findings ?? runDetectors(detectorInput);
  const findings: Finding[] = [];
  const contributions: Contribution[] = [];

  const subject = subjectOf(input);
  if (ctx.quarantined && subject) {
    const f = makeFinding('quarantined', 'critical', `Tool ${subject.server}/${subject.tool} is quarantined: ${ctx.quarantined.reason}`, ctx.quarantined.reason);
    findings.push(f);
    contributions.push({ decision: 'quarantine', finding: f });
  }

  for (const f of [...detected, ...(ctx.extraFindings ?? [])]) {
    const ruleId = (BUILTIN_RULE_IDS as Record<string, string>)[f.detector];
    const rule = ruleId ? active.find((r) => r.id === ruleId) : undefined;
    if (rule) {
      const bound: Finding = { ...f, ruleId: rule.id };
      findings.push(bound);
      contributions.push({ decision: decisionForSeverity(rule.action, f.severity), rule, finding: bound });
    } else {
      findings.push(f); // informational: detector without an active builtin rule (revoked) or non-enforcing detector
    }
  }

  for (const rule of active) {
    if (isBuiltinRule(rule)) continue; // enforced by detectors above
    const m = ruleMatches(rule, input, ctx);
    if (!m.matched) continue;
    const f = makeFinding(`rule:${rule.id}`, rule.severity, `Antibody "${rule.name}" matched: ${m.why}`, m.evidence, rule.id);
    findings.push(f);
    contributions.push({ decision: rule.action, rule, finding: f });
  }

  const decision = maxDecision(...contributions.map((c) => c.decision));
  let blockedBy: string | undefined;
  let citation: string | undefined;
  if (decision !== 'allow') {
    const winners = contributions.filter((c) => c.decision === decision).sort((a, b) => winnerRank(a) - winnerRank(b));
    const winner = winners[0];
    if (winner?.rule) {
      if (decision === 'block' || decision === 'quarantine') blockedBy = winner.rule.id;
      citation = ctx.citationFor?.(winner.rule) ?? defaultCitation(winner.rule);
    }
  }
  return { decision, findings: dedupeFindings(findings), blockedBy, citation };
}

/** One-line human summary of a rule's declarative match, for the antibodies table. */
export function describeMatch(match: RuleMatch): string {
  const parts: string[] = [match.phase];
  if (match.server) parts.push(`server=${match.server}`);
  if (match.tool) parts.push(`tool=${match.tool}`);
  if (match.afterTainted) parts.push('after tainted');
  if (match.capabilities?.length) parts.push(`caps ${match.capabilities.join('|')}`);
  if (match.patterns?.length) parts.push(`${match.patterns.length} pattern${match.patterns.length > 1 ? 's' : ''}: ${match.patterns.map((p) => `/${p.length > 40 ? `${p.slice(0, 37)}…` : p}/`).join(' ')}`);
  if (match.destinationNotIn?.length) parts.push(`destination ∉ {${match.destinationNotIn.slice(0, 3).join(', ')}${match.destinationNotIn.length > 3 ? ', …' : ''}}`);
  if (match.carriesSecret) parts.push('carries secret');
  return parts.join(' · ');
}
