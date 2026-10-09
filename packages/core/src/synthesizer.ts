/**
 * Synthesizer — turns a breach trace (antigen) into a candidate antibody rule, deterministically.
 *
 *  1. tool_call breach carrying a REGISTERED secret under a transform (chunked / reversed / split / raw)
 *     → primary rule { phase: tool_call, patterns: [secret-transform pattern, distinguishing arg segment],
 *       capabilities: [network, exec, write] } — no server/tool constraint, block, critical.
 *  2. otherwise choose the phase to block (family preference, then "must catch the breach, zero benign hits")
 *     and extract distinguishing phrases from the injected payload that occur in <= 1% of benign traces,
 *     plus destination host, capability + taint signature, carriesSecret.
 *  3. if the agent read a tool_result / tool_def on the way to the breach, a secondary FLAG rule for that
 *     phase is attached (rule.companions[0]; also returned as `secondary` by synthesizeAntibodySet).
 *  4. emit Semgrep YAML when a sink is identifiable (tool text / secrets → fetch() / webhook body / exec).
 *
 * Optional `llmRefine` hook (async) can broaden the patterns; every LLM-proposed pattern is validated
 * locally (compiles, still catches the breach, <= 1% benign) before it is accepted.
 */
import { stringify as yamlStringify } from 'yaml';
import type { AttackFamily, Capability, Decision, Phase, Rule, RuleMatch, Severity, Trace } from './types.js';
import { deterministicId } from './ids.js';
import {
  SENSITIVE_CAPABILITIES,
  SecretRegistry,
  type TransformedSecretHit,
  argsText,
  extractHosts,
  findSecretsInArgs,
  findTransformedSecret,
  hostAllowed,
  normalizeText,
  reverseString,
  stripToAlnum,
  walkStrings,
} from './detectors/index.js';
import { compilePattern, ruleMatches, type PolicyInput } from './policy.js';
import { isCaught, replayTrace, traceToInputs } from './replay.js';

export type LlmRefine = (draft: Rule, breach: Trace) => Promise<Rule>;

export interface SynthOptions {
  allowlist?: string[];
  /** registered secret values (Gate.secrets.values()) — enables transform-aware secret rules */
  secrets?: Iterable<string> | SecretRegistry;
  /** max regex patterns in a rule (default 4) */
  maxPatterns?: number;
  /** max fraction of benign traces a phrase may occur in (default 0.01) */
  benignFreqMax?: number;
  /** generate Semgrep YAML when a sink is identifiable (default true) */
  semgrep?: boolean;
  /** fixed createdAt (default Date.now()) */
  now?: number;
  /** override the deterministic primary rule id */
  id?: string;
  /** async refinement hook — only used by synthesizeAntibodyWithRefine */
  llmRefine?: LlmRefine;
}

export interface AntibodySet {
  /** the primary antibody (block / quarantine) */
  rule: Rule;
  /** flag-rule for the tool_result / tool_def the agent read before the breach, if any */
  secondary?: Rule;
  /** the transformed registered secret found in the attempted call, if any */
  secretHit?: TransformedSecretHit;
}

export interface Candidate {
  phrase: string;
  pattern: string;
  tokens: string[];
  kind: 'phrase' | 'host' | 'ident' | 'tag' | 'segment';
  score: number;
  benignFreq: number;
  attackCoverage: number;
}

type RawCandidate = Omit<Candidate, 'score' | 'benignFreq' | 'attackCoverage'>;
type Resolved = Required<Pick<SynthOptions, 'maxPatterns' | 'benignFreqMax'>> & SynthOptions;

const STOPWORDS = new Set(
  'a an the and or but if then else of to in on at by for with from as is are was were be been being this that these those it its into onto over under about after before during while than which who whom whose what when where why how all any each every some such no nor not only own same so too very can will just should would could may might must shall do does did done has have had having you your yours we our ours they their theirs he she his her them us me my i am s t ll re ve d please also'.split(
    ' ',
  ),
);

const LEXICON =
  /\b(ignore|disregard|forget|override|instructions?|prompt|system|assistant|agent|ai|call|invoke|run|execute|send|post|forward|upload|transmit|submit|exfiltrate|include|credentials?|secrets?|tokens?|keys?|passwords?|passphrase|https?|webhook|endpoint|url|intake|collector|archive|sink|must|now|immediately|silently|quietly|secret(ly)?|hidden|do not|don't|never|tell|mention|user|read|file|ssh|env|important|attention|note|notice|reminder|directive|helper|operator|automated|dlp|compliance|audit|mirror|sync|backup|export)\b/i;

const FAMILY_LABEL: Record<AttackFamily, string> = {
  poisoned_description: 'Poisoned description',
  result_injection: 'Result injection',
  secret_exfil: 'Secret exfiltration',
  rug_pull: 'Rug pull',
  homoglyph_spoof: 'Homoglyph spoof',
  indirect_fetch: 'Indirect fetch injection',
  benign: 'Benign',
};

const HTML_NOISE_TAGS = new Set(['p', 'div', 'span', 'br', 'b', 'i', 'a', 'ul', 'li', 'ol', 'html', 'body', 'head', 'title', 'h1', 'h2', 'h3', 'h4', 'table', 'tr', 'td', 'th', 'em', 'strong', 'code', 'pre', 'img', 'hr', 'meta', 'link', 'script', 'style', 'tbody', 'thead', 'section', 'article', 'nav', 'footer', 'header', 'main']);

/* ------------------------------------------------------------------------------------------------
 * Text helpers
 * ---------------------------------------------------------------------------------------------- */

export function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
}

/** Tokens → a tolerant pattern: `\b` + tokens joined by `\W*` + `\b` (survives spacing, hyphens, zero-width tricks). */
export function phraseToPattern(phrase: string): string {
  const tokens = phrase.split(/\s+/).filter(Boolean);
  if (!tokens.length) return '';
  const body = tokens.map((t) => escapeRegex(t)).join('\\W*');
  const lead = /^[a-z0-9]/i.test(tokens[0]!) ? '\\b' : '';
  const trail = /[a-z0-9]$/i.test(tokens[tokens.length - 1]!) ? '\\b' : '';
  return `${lead}${body}${trail}`;
}

/** The text a rule of `phase` is matched against for a trace (mirrors policy.subjectOf). */
export function phaseText(trace: Trace, phase: Phase): string | undefined {
  switch (phase) {
    case 'tool_def': {
      const d = trace.toolDef;
      if (!d) return undefined;
      let schema = '';
      try {
        schema = d.inputSchema ? JSON.stringify(d.inputSchema) : '';
      } catch {
        schema = '';
      }
      return `${d.name}\n${d.description ?? ''}\n${schema}`;
    }
    case 'tool_result':
      return trace.result?.content;
    case 'tool_call':
      return trace.attemptedCall ? argsText(trace.attemptedCall.args) : undefined;
    default:
      return undefined;
  }
}

function tokenize(sentence: string): string[] {
  return sentence
    .split(/\s+/)
    .map((w) => w.replace(/^[^a-z0-9`<]+|[^a-z0-9`>]+$/gi, ''))
    .filter((w) => w.length > 0 && w.length <= 64);
}

const HOST_RE = /\b(?:https?:\/\/)?((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:[a-z]{2,}))(?::\d+)?(?:\/[^\s"'<>)]*)?/gi;
const IDENT_RE = /\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b/g;
const TAG_RE = /<\/?\s*([a-z][a-z0-9_-]*)\b[^>]*>/gi;
const SEGMENT_RE = /[A-Za-z0-9][A-Za-z0-9._-]{3,63}/g;

/** Candidate phrases (1–4 word shingles + hosts + identifiers + tags) from a payload text (tool_result / tool_def). */
export function extractCandidatePhrases(text: string): RawCandidate[] {
  const norm = normalizeText(text);
  const views = [norm.normalized, ...norm.decoded, ...norm.hiddenBlocks];
  const seen = new Map<string, RawCandidate>();
  const add = (phrase: string, kind: Candidate['kind'], tokens: string[]) => {
    const key = phrase.toLowerCase();
    if (seen.has(key)) return;
    const pattern = phraseToPattern(key);
    if (!pattern || !compilePattern(pattern)) return;
    seen.set(key, { phrase: key, pattern, tokens: tokens.map((t) => t.toLowerCase()), kind });
  };

  for (const view of views) {
    for (const m of view.matchAll(HOST_RE)) {
      const host = m[1]!.toLowerCase();
      if (host.split('.').length >= 2 && !/^\d+(\.\d+)+$/.test(host) && host.length >= 6) add(host, 'host', [host]);
    }
    for (const m of view.matchAll(IDENT_RE)) add(m[0], 'ident', [m[0]]);
    const sentences = view
      .split(/[.!?;\n]+|\s[-–—]\s|<[^>]*>/)
      .map((s) => s.trim())
      .filter((s) => s.length >= 4);
    for (const sentence of sentences) {
      const toks = tokenize(sentence);
      for (let n = 1; n <= 4; n++) {
        for (let i = 0; i + n <= toks.length; i++) {
          const gram = toks.slice(i, i + n);
          const first = gram[0]!.toLowerCase();
          const last = gram[n - 1]!.toLowerCase();
          if (STOPWORDS.has(first) || STOPWORDS.has(last)) continue;
          const content = gram.filter((t) => t.length >= 4 && !STOPWORDS.has(t.toLowerCase()));
          if (!content.length) continue;
          if (n === 1 && (gram[0]!.length < 6 || /^\d+$/.test(gram[0]!))) continue;
          add(gram.join(' '), 'phrase', gram);
        }
      }
    }
  }
  for (const m of text.matchAll(TAG_RE)) {
    const tag = m[1]!.toLowerCase();
    if (!HTML_NOISE_TAGS.has(tag)) add(`<${tag}>`, 'tag', [`<${tag}>`]);
  }
  return [...seen.values()];
}

function jsonKeys(value: unknown, out = new Set<string>(), depth = 0): Set<string> {
  if (depth > 8 || !value || typeof value !== 'object') return out;
  if (Array.isArray(value)) {
    for (const v of value) jsonKeys(v, out, depth + 1);
    return out;
  }
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    out.add(k.toLowerCase());
    jsonKeys(v, out, depth + 1);
  }
  return out;
}

/**
 * Candidates from tool-call args (JSON): non-allowlisted hosts, path-like segments ("ops-archive", "dlp-export",
 * "intake_v2"), and 2–4 word phrases from text-like string values ("dlp format", "integration key").
 * Bare dictionary words are skipped — they are too generic to be a distinguishing signal.
 */
export function extractArgCandidates(args: Record<string, unknown>, opts: { allowlist?: string[]; secret?: string | null } = {}): RawCandidate[] {
  const raw = argsText(args);
  const keys = jsonKeys(args);
  const secretCores = opts.secret ? [stripToAlnum(opts.secret).toLowerCase(), reverseString(stripToAlnum(opts.secret).toLowerCase())] : [];
  const touchesSecret = (tokens: string[]) =>
    secretCores.length > 0 &&
    tokens.some((t) => {
      const alnum = stripToAlnum(t).toLowerCase();
      return alnum.length >= 3 && secretCores.some((c) => c.includes(alnum));
    });
  const seen = new Map<string, RawCandidate>();
  const add = (phrase: string, kind: Candidate['kind'], tokens: string[]) => {
    if (seen.has(phrase)) return;
    const pattern = phraseToPattern(phrase);
    if (!pattern || !compilePattern(pattern)) return;
    seen.set(phrase, { phrase, pattern, tokens, kind });
  };
  for (const h of extractHosts(args)) {
    if (opts.allowlist?.length && hostAllowed(h.host, opts.allowlist)) continue;
    if (h.host.split('.').length >= 2) add(h.host, 'host', [h.host]);
  }
  for (const m of raw.matchAll(SEGMENT_RE)) {
    const seg = m[0].replace(/^[._-]+|[._-]+$/g, '').toLowerCase();
    if (seg.length < 4 || /^[0-9._-]+$/.test(seg)) continue;
    if (keys.has(seg)) continue;
    if (touchesSecret([seg])) continue;
    if (/^(https?|wss?|true|false|null|undefined|string|number|object|array)$/.test(seg)) continue;
    if (opts.allowlist?.length && (opts.allowlist.some((a) => a.toLowerCase().includes(seg)) || (seg.includes('.') && hostAllowed(seg, opts.allowlist)))) continue;
    // path-like / identifier-like only: needs a separator or a digit (plain dictionary words are too generic)
    if (!/[-_./]|\d/.test(seg)) continue;
    add(seg, 'segment', [seg]);
  }
  walkStrings(args, (_path, s) => {
    if (s.length < 8 || s.split(/\s+/).length < 2) return;
    for (const c of extractCandidatePhrases(s)) {
      if (c.kind === 'phrase' && c.tokens.length < 2) continue;
      if (c.kind === 'host' && opts.allowlist?.length && hostAllowed(c.phrase, opts.allowlist)) continue;
      if (touchesSecret(c.tokens)) continue;
      add(c.phrase, c.kind, c.tokens);
    }
  });
  return [...seen.values()];
}

/* ------------------------------------------------------------------------------------------------
 * Scoring & selection
 * ---------------------------------------------------------------------------------------------- */

function patternHits(pattern: string, texts: string[]): number {
  const re = compilePattern(pattern);
  if (!re) return 0;
  let n = 0;
  for (const t of texts) {
    re.lastIndex = 0;
    if (re.test(t)) n++;
  }
  return n;
}

function scoreCandidates(cands: RawCandidate[], benignTexts: string[], attackTexts: string[], benignFreqMax: number): Candidate[] {
  const out: Candidate[] = [];
  const benignBlob = benignTexts.join('\n');
  for (const c of cands) {
    let benignFreq = 0;
    if (benignTexts.length) {
      // cheap prefilter (literal containment); patterns with \W* joins are broader, so verify with the regex
      const lit = c.phrase.toLowerCase();
      if (benignBlob.includes(lit) || c.tokens.length > 1 || c.kind !== 'phrase') benignFreq = patternHits(c.pattern, benignTexts) / benignTexts.length;
    }
    if (benignFreq > benignFreqMax) continue;
    const attackCoverage = attackTexts.length ? patternHits(c.pattern, attackTexts) / attackTexts.length : 0;
    let score = 10 * attackCoverage;
    score += Math.min(c.tokens.length, 4) * 1.5;
    if (c.kind === 'host') score += 6;
    if (c.kind === 'ident') score += 4;
    if (c.kind === 'tag') score += 3;
    if (c.kind === 'segment') score += 2 + (/[-_]/.test(c.phrase) ? 2 : 0) + Math.min(c.phrase.length, 24) / 8;
    if (LEXICON.test(c.phrase)) score += 2.5;
    score += Math.min(c.phrase.length, 40) / 20;
    score -= benignFreq * 100;
    out.push({ ...c, score, benignFreq, attackCoverage });
  }
  return out.sort((a, b) => b.score - a.score || b.phrase.length - a.phrase.length || a.phrase.localeCompare(b.phrase));
}

function selectPhrases(scored: Candidate[], max: number): Candidate[] {
  const chosen: Candidate[] = [];
  const covered = new Set<string>();
  for (const c of scored) {
    if (chosen.length >= max) break;
    const toks = c.tokens;
    const overlap = toks.filter((t) => covered.has(t)).length;
    if (c.kind === 'phrase' && toks.length > 0 && overlap / toks.length >= 0.5) continue;
    if (chosen.some((x) => x.phrase.includes(c.phrase) || c.phrase.includes(x.phrase))) continue;
    chosen.push(c);
    for (const t of toks) covered.add(t);
  }
  return chosen;
}

function severityFor(family: AttackFamily, phase: Phase): Severity {
  if (family === 'secret_exfil' || family === 'rug_pull' || family === 'poisoned_description') return 'critical';
  return phase === 'tool_def' ? 'critical' : 'high';
}

function actionFor(phase: Phase): Decision {
  return phase === 'tool_def' ? 'quarantine' : 'block';
}

function corpusTexts(breach: Trace, corpus: Trace[], phase: Phase): { benign: string[]; attack: string[] } {
  const benign: string[] = [];
  const attack: string[] = [];
  for (const t of corpus) {
    if (t.id === breach.id) continue;
    const pt = phaseText(t, phase);
    if (pt === undefined) continue;
    if (t.label === 'benign') benign.push(normalizeText(pt).normalized);
    else if (t.family === breach.family) attack.push(normalizeText(pt).normalized);
  }
  return { benign, attack };
}

interface Draft {
  phase: Phase;
  match: RuleMatch;
  phrases: Candidate[];
  hosts: string[];
}

function buildDraft(breach: Trace, phase: Phase, corpus: Trace[], o: Resolved): Draft | null {
  const text = phaseText(breach, phase);
  if (text === undefined) return null;
  const texts = corpusTexts(breach, corpus, phase);
  const raw = phase === 'tool_call' && breach.attemptedCall ? extractArgCandidates(breach.attemptedCall.args ?? {}, { allowlist: o.allowlist }) : extractCandidatePhrases(text);
  const phrases = selectPhrases(scoreCandidates(raw, texts.benign, texts.attack, o.benignFreqMax), o.maxPatterns);
  const match: RuleMatch = { phase };
  const hosts: string[] = [];

  if (phase === 'tool_call' && breach.attemptedCall) {
    const call = breach.attemptedCall;
    const caps = (call.capabilities ?? []).filter((c) => SENSITIVE_CAPABILITIES.includes(c));
    if (caps.length) match.capabilities = caps as Capability[];
    if (breach.tainted) match.afterTainted = true;
    const refs = extractHosts(call.args ?? {});
    for (const r of refs) if (!hosts.includes(r.host)) hosts.push(r.host);
    if (o.allowlist?.length && refs.some((r) => !hostAllowed(r.host, o.allowlist!))) match.destinationNotIn = [...o.allowlist];
    if (findSecretsInArgs(call.args ?? {}).length) match.carriesSecret = true;
  } else {
    for (const m of text.matchAll(HOST_RE)) {
      const h = m[1]!.toLowerCase();
      if (!hosts.includes(h) && h.split('.').length >= 2) hosts.push(h);
    }
  }

  const patterns = phrases.map((p) => p.pattern);
  for (const h of hosts) {
    const hp = phraseToPattern(h);
    const allowed = o.allowlist?.length ? hostAllowed(h, o.allowlist) : false;
    if (!allowed && patterns.length < o.maxPatterns + 2 && !patterns.includes(hp)) patterns.push(hp);
  }
  if (patterns.length) match.patterns = patterns;

  // a tool_call rule must be narrower than "any network call"
  if (phase === 'tool_call' && !match.patterns && !match.destinationNotIn && !match.carriesSecret && breach.attemptedCall) {
    match.tool = breach.attemptedCall.tool;
    match.server = breach.attemptedCall.server;
  }
  if (phase === 'tool_def' && breach.toolDef && breach.family === 'homoglyph_spoof') {
    match.tool = breach.toolDef.name;
    match.server = breach.toolDef.server;
  }
  return { phase, match, phrases, hosts };
}

function preferredPhases(breach: Trace): Phase[] {
  const order: Phase[] = [];
  const push = (p: Phase) => {
    if (!order.includes(p)) order.push(p);
  };
  switch (breach.family) {
    case 'poisoned_description':
    case 'rug_pull':
    case 'homoglyph_spoof':
      push('tool_def');
      push('tool_result');
      push('tool_call');
      break;
    case 'secret_exfil':
      push('tool_call');
      push('tool_result');
      push('tool_def');
      break;
    default:
      push('tool_result');
      push('tool_call');
      push('tool_def');
  }
  return order.filter((p) => phaseText(breach, p) !== undefined);
}

function inputFor(trace: Trace, phase: Phase): PolicyInput | undefined {
  return traceToInputs(trace).find((i) => i.phase === phase);
}

function catches(rule: Rule, breach: Trace, allowlist?: string[]): boolean {
  return isCaught(replayTrace([rule], breach, { allowlist }).decision);
}

function benignHits(rule: Rule, corpus: Trace[], allowlist?: string[]): number {
  let n = 0;
  for (const t of corpus) {
    if (t.label !== 'benign') continue;
    const input = inputFor(t, rule.match.phase);
    if (!input) continue;
    if (ruleMatches(rule, input, { tainted: t.tainted, allowlist }).matched) n++;
  }
  return n;
}

function secretValues(s: SynthOptions['secrets']): string[] {
  if (!s) return [];
  if (s instanceof SecretRegistry) return s.values();
  return [...s].filter((x): x is string => typeof x === 'string' && x.length > 0);
}

function summaryOf(phrases: Candidate[], hosts: string[]): string {
  return phrases
    .slice(0, 2)
    .map((p) => `"${p.phrase}"`)
    .concat(hosts.slice(0, 1).map((h) => `host ${h}`))
    .join(', ');
}

/* ------------------------------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------------------------------- */

/**
 * Deterministic antibody synthesis. Same breach + corpus + options → identical rules.
 * Returns the primary rule and, when the agent read a tool_result / tool_def on the way, a secondary flag-rule.
 */
export function synthesizeAntibodySet(breach: Trace, corpus: Trace[], opts: SynthOptions = {}): AntibodySet {
  const o: Resolved = { maxPatterns: 4, benignFreqMax: 0.01, semgrep: true, ...opts };
  const createdAt = o.now ?? Date.now();
  const phases = preferredPhases(breach);
  if (!phases.length) throw new Error(`breach trace ${breach.id} has no toolDef / result / attemptedCall to synthesize from`);

  let primary: Rule | undefined;
  let secretHit: TransformedSecretHit | undefined;

  // 1) transformed registered secret in the attempted call → capability-only tool_call rule
  const secrets = secretValues(o.secrets);
  if (breach.attemptedCall && secrets.length) {
    const hit = findTransformedSecret(argsText(breach.attemptedCall.args ?? {}), secrets);
    if (hit.transform && hit.pattern) {
      const rule = buildSecretTransformRule(breach, corpus, hit, createdAt, o);
      if (catches(rule, breach, o.allowlist)) {
        primary = rule;
        secretHit = hit;
      }
    }
  }

  // 2) generic: best phase by (catches breach, fewest benign hits), family preference first
  if (!primary) {
    let best: { rule: Rule; fp: number; caught: boolean } | undefined;
    for (const phase of phases) {
      const draft = buildDraft(breach, phase, corpus, o);
      if (!draft) continue;
      const rule = assemble(breach, draft, createdAt, o);
      const caught = catches(rule, breach, o.allowlist);
      const fp = caught ? benignHits(rule, corpus, o.allowlist) : Number.POSITIVE_INFINITY;
      const cand = { rule, fp, caught };
      if (!best || (!best.caught && caught) || (best.caught && caught && fp < best.fp)) best = cand;
      if (caught && fp === 0) break;
    }
    if (!best) throw new Error(`could not synthesize an antibody for trace ${breach.id}`);
    primary = best.rule;
  }

  // 3) secondary flag-rule for the phase the agent read before acting
  const secondary = buildSecondary(breach, corpus, primary, createdAt, o);
  const set: AntibodySet = { rule: primary };
  if (secondary) set.secondary = secondary;
  if (secretHit) set.secretHit = secretHit;
  return set;
}

/** Contract entry point: the primary rule; a secondary flag-rule (if any) is attached as `rule.companions[0]`. */
export function synthesizeAntibody(breach: Trace, corpus: Trace[], opts: SynthOptions = {}): Rule {
  const set = synthesizeAntibodySet(breach, corpus, opts);
  return set.secondary ? { ...set.rule, companions: [set.secondary] } : set.rule;
}

function buildSecretTransformRule(breach: Trace, corpus: Trace[], hit: TransformedSecretHit, createdAt: number, o: Resolved): Rule {
  const call = breach.attemptedCall!;
  const texts = corpusTexts(breach, corpus, 'tool_call');
  const extras = selectPhrases(scoreCandidates(extractArgCandidates(call.args ?? {}, { allowlist: o.allowlist, secret: hit.secret }), texts.benign, texts.attack, o.benignFreqMax), 2);
  const patterns = [hit.pattern!, ...extras.map((e) => e.pattern)].slice(0, Math.max(2, o.maxPatterns));
  const rule: Rule = {
    id: o.id ?? deterministicId('rl', `antibody:${breach.id}:tool_call`),
    name: `Transformed registered secret in outbound call (${hit.transform}) · ${breach.variant}${extras.length ? ` · ${summaryOf(extras, [])}` : ''}`.slice(0, 160),
    version: 1,
    createdAt,
    origin: 'synthesized',
    derivedFrom: [breach.id],
    match: { phase: 'tool_call', patterns, capabilities: ['network', 'exec', 'write'] },
    action: 'block',
    severity: 'critical',
    status: 'candidate',
  };
  if (o.semgrep !== false) rule.semgrep = generateSecretSinkSemgrepRule(breach, rule, hit);
  return rule;
}

function assemble(breach: Trace, draft: Draft, createdAt: number, o: Resolved): Rule {
  const rule: Rule = {
    id: o.id ?? deterministicId('rl', `antibody:${breach.id}:${draft.phase}`),
    name: `${FAMILY_LABEL[breach.family] ?? breach.family} antibody · ${breach.variant}${summaryOf(draft.phrases, draft.hosts) ? ` · ${summaryOf(draft.phrases, draft.hosts)}` : ''}`.slice(0, 160),
    version: 1,
    createdAt,
    origin: 'synthesized',
    derivedFrom: [breach.id],
    match: draft.match,
    action: actionFor(draft.phase),
    severity: severityFor(breach.family, draft.phase),
    status: 'candidate',
  };
  if (o.semgrep !== false) {
    const yaml = draft.match.carriesSecret || breach.family === 'secret_exfil' ? generateSecretSinkSemgrepRule(breach, rule) : generateSemgrepRule(breach, rule);
    if (yaml) rule.semgrep = yaml;
  }
  return rule;
}

function buildSecondary(breach: Trace, corpus: Trace[], primary: Rule, createdAt: number, o: Resolved): Rule | undefined {
  const phase: Phase | undefined =
    primary.match.phase !== 'tool_result' && breach.result ? 'tool_result' : primary.match.phase !== 'tool_def' && breach.toolDef ? 'tool_def' : undefined;
  if (!phase) return undefined;
  const draft = buildDraft(breach, phase, corpus, o);
  const patterns = draft?.match.patterns;
  if (!patterns?.length) return undefined;
  const rule: Rule = {
    id: deterministicId('rl', `antibody:${breach.id}:${phase}:secondary`),
    name: `${phase === 'tool_result' ? 'Injected instruction in tool result' : 'Suspicious tool definition'} · ${breach.variant} · ${summaryOf(draft!.phrases, draft!.hosts)}`.slice(0, 160),
    version: 1,
    createdAt,
    origin: 'synthesized',
    derivedFrom: [breach.id],
    match: { phase, patterns },
    action: 'flag',
    severity: 'high',
    status: 'candidate',
  };
  return catches(rule, breach, o.allowlist) ? rule : undefined;
}

/** Synthesize, then optionally refine with the async hook. The refined rule must still catch the breach. */
export async function synthesizeAntibodyWithRefine(breach: Trace, corpus: Trace[], opts: SynthOptions = {}): Promise<Rule> {
  const draft = synthesizeAntibody(breach, corpus, opts);
  if (!opts.llmRefine) return draft;
  try {
    const refined = await opts.llmRefine(draft, breach);
    if (!refined || refined.id !== draft.id || refined.match?.phase !== draft.match.phase) return draft;
    if (!catches(refined, breach, opts.allowlist)) return draft;
    if (benignHits(refined, corpus, opts.allowlist) > benignHits(draft, corpus, opts.allowlist)) return draft;
    return refined.companions || !draft.companions ? refined : { ...refined, companions: draft.companions };
  } catch {
    return draft;
  }
}

/* ------------------------------------------------------------------------------------------------
 * Semgrep
 * ---------------------------------------------------------------------------------------------- */

/** A sink is identifiable when attacker-influenced text could reach a network/exec call. */
export function identifySink(breach: Trace): 'network' | 'exec' | undefined {
  const caps = breach.attemptedCall?.capabilities ?? [];
  if (caps.includes('exec')) return 'exec';
  if (caps.includes('network')) return 'network';
  if (breach.result && (breach.family === 'result_injection' || breach.family === 'indirect_fetch' || breach.family === 'secret_exfil')) return 'network';
  return undefined;
}

const NETWORK_SINKS = [
  { pattern: 'fetch($SINK, ...)' },
  { pattern: 'new URL($SINK, ...)' },
  { pattern: 'axios.$M($SINK, ...)' },
  { pattern: 'axios($SINK, ...)' },
  { pattern: 'http.request($SINK, ...)' },
  { pattern: 'https.request($SINK, ...)' },
  { pattern: 'http.get($SINK, ...)' },
  { pattern: 'https.get($SINK, ...)' },
  { pattern: 'got($SINK, ...)' },
];
const BODY_SINKS = [
  { pattern: 'fetch(..., { body: $SINK, ... })' },
  { pattern: 'fetch(..., { headers: $SINK, ... })' },
  { pattern: 'axios.post(..., $SINK, ...)' },
  { pattern: 'axios.put(..., $SINK, ...)' },
  { pattern: 'axios.patch(..., $SINK, ...)' },
  { pattern: 'sendWebhook(..., $SINK, ...)' },
  { pattern: 'send_webhook(..., $SINK, ...)' },
  { pattern: 'new URLSearchParams($SINK)' },
];
const EXEC_SINKS = [
  { pattern: 'exec($SINK, ...)' },
  { pattern: 'execSync($SINK, ...)' },
  { pattern: 'spawn($SINK, ...)' },
  { pattern: 'spawnSync($SINK, ...)' },
  { pattern: 'execFile($SINK, ...)' },
  { pattern: 'execFileSync($SINK, ...)' },
  { pattern: 'child_process.$M($SINK, ...)' },
  { pattern: '$CP.exec($SINK, ...)' },
  { pattern: '$CP.execSync($SINK, ...)' },
  { pattern: '$CP.spawn($SINK, ...)' },
  { pattern: 'eval($SINK)' },
  { pattern: 'new Function($SINK)' },
];

function semgrepMetadata(breach: Trace, rule: Rule, extra: Record<string, unknown>): Record<string, unknown> {
  return {
    category: 'security',
    technology: ['mcp', 'node'],
    confidence: 'MEDIUM',
    likelihood: 'HIGH',
    impact: 'HIGH',
    subcategory: ['vuln'],
    immune: { ruleId: rule.id, derivedFrom: rule.derivedFrom, family: breach.family, variant: breach.variant, phase: rule.match.phase, ...extra },
    references: ['https://owasp.org/www-project-top-10-for-large-language-model-applications/', 'https://modelcontextprotocol.io/specification'],
  };
}

function toYaml(doc: unknown, header: string): string {
  return `# ${header}\n${yamlStringify(doc, { lineWidth: 0 })}`;
}

/** Semgrep taint rule (TypeScript/JavaScript): tool-result / tool-argument text → fetch() / child_process / URL sinks. */
export function generateSemgrepRule(breach: Trace, rule: Rule): string | undefined {
  const sink = identifySink(breach);
  if (!sink) return undefined;
  const slug = `immune-${breach.family.replace(/_/g, '-')}-${rule.id.replace(/^rl_/, '').slice(0, 12)}`;
  const hosts = rule.match.patterns?.filter((p) => /\\\./.test(p) && !/\{0,3\}/.test(p)).map((p) => p.replace(/\\b/g, '').replace(/\\W\*/g, ' ').replace(/\\/g, '')) ?? [];
  const message =
    `Text that came from a tool result or tool argument reaches a ${sink === 'exec' ? 'command execution' : 'network'} sink without validation. ` +
    `Immune antibody ${rule.id} (derived from trace ${breach.id}, ${breach.family}/${breach.variant})${hosts.length ? `; observed destination ${hosts.join(', ')}` : ''}. ` +
    `Validate the value against an allowlist before passing it to fetch()/exec().`;
  const metadata = semgrepMetadata(breach, rule, { sink, hosts });
  const doc = {
    rules: [
      {
        id: `${slug}-taint`,
        mode: 'taint',
        languages: ['typescript', 'javascript'],
        severity: 'ERROR',
        message,
        metadata,
        'pattern-sources': [
          { pattern: 'args.$FIELD' },
          { pattern: 'args[$KEY]' },
          { pattern: 'input.$FIELD' },
          { pattern: 'params.$FIELD' },
          { pattern: '$REQ.params.arguments.$FIELD' },
          { pattern: 'callTool(...)' },
          { pattern: 'await callTool(...)' },
          { pattern: '$RESULT.content' },
          { pattern: '(await $RES.text())' },
          { pattern: '(await $RES.json())' },
          { pattern: 'readSharedDoc(...)' },
          { pattern: 'read_shared_doc(...)' },
          { pattern: 'fetchUrl(...)' },
          { pattern: 'fetch_url(...)' },
        ],
        'pattern-sinks': [{ patterns: [{ 'pattern-either': sink === 'exec' ? EXEC_SINKS : [...NETWORK_SINKS, ...EXEC_SINKS] }, { 'focus-metavariable': '$SINK' }] }],
      },
      {
        id: `${slug}-direct`,
        languages: ['typescript', 'javascript'],
        severity: 'WARNING',
        message: `Tool argument passed straight into ${sink === 'exec' ? 'a shell/exec' : 'a network'} call (Immune antibody ${rule.id}). Validate it first.`,
        metadata: { ...metadata, confidence: 'HIGH' },
        'pattern-either': [
          { pattern: 'fetch(String(args.$F), ...)' },
          { pattern: 'fetch(args.$F, ...)' },
          { pattern: 'fetch(`...${args.$F}...`, ...)' },
          { pattern: 'new URL(args.$F, ...)' },
          { pattern: 'new URL(String(args.$F), ...)' },
          { pattern: 'exec(`...${args.$F}...`, ...)' },
          { pattern: 'execSync(`...${args.$F}...`, ...)' },
          { pattern: 'exec(String(args.$F), ...)' },
          { pattern: 'execSync(String(args.$F), ...)' },
          { pattern: 'spawn(args.$F, ...)' },
          { pattern: 'spawn(String(args.$F), ...)' },
          { pattern: 'child_process.$M(`...${args.$F}...`, ...)' },
        ],
      },
    ],
  };
  return toYaml(doc, `Generated by Immune — antibody ${rule.id} (${breach.family}/${breach.variant}); derived from trace ${breach.id}`);
}

/** Semgrep taint rule: secret-looking values / get_api_credentials output → fetch() URLs, webhook bodies, exec. */
export function generateSecretSinkSemgrepRule(breach: Trace, rule: Rule, hit?: TransformedSecretHit): string {
  const slug = `immune-secret-exfil-${rule.id.replace(/^rl_/, '').slice(0, 12)}`;
  const transform = hit?.transform ?? null;
  const message =
    `A secret (API credentials, tokens, env secrets) flows into a network or exec sink — this is how the ${breach.family}/${breach.variant} breach exfiltrated it` +
    `${transform ? ` (${transform} transform of a registered secret)` : ''}. Immune antibody ${rule.id}, derived from trace ${breach.id}. ` +
    `Never pass credentials into outbound URLs, webhook bodies or shell commands; scope secrets to the call that needs them.`;
  const metadata = semgrepMetadata(breach, rule, { transform, secretRedacted: hit?.redacted ?? null, sink: 'secret' });
  const doc = {
    rules: [
      {
        id: `${slug}-taint`,
        mode: 'taint',
        languages: ['typescript', 'javascript'],
        severity: 'ERROR',
        message,
        metadata,
        'pattern-sources': [
          { pattern: 'get_api_credentials(...)' },
          { pattern: 'getApiCredentials(...)' },
          { pattern: 'callTool("get_api_credentials", ...)' },
          { pattern: "callTool('get_api_credentials', ...)" },
          { pattern: 'process.env.$KEY' },
          { pattern: 'process.env[$KEY]' },
          { pattern: '$O.apiKey' },
          { pattern: '$O.api_key' },
          { pattern: '$O.apiSecret' },
          { pattern: '$O.secret' },
          { pattern: '$O.secretKey' },
          { pattern: '$O.secret_key' },
          { pattern: '$O.token' },
          { pattern: '$O.accessToken' },
          { pattern: '$O.access_token' },
          { pattern: '$O.password' },
          { pattern: '$O.credentials' },
          { pattern: '$O.privateKey' },
          { pattern: '$O.private_key' },
          { pattern: 'readFileSync("=~/(\\.env|credentials|id_rsa|id_ed25519|\\.ssh|\\.aws)/", ...)' },
        ],
        'pattern-sinks': [
          { patterns: [{ 'pattern-either': NETWORK_SINKS }, { 'focus-metavariable': '$SINK' }] },
          { patterns: [{ 'pattern-either': BODY_SINKS }, { 'focus-metavariable': '$SINK' }] },
          { patterns: [{ 'pattern-either': EXEC_SINKS }, { 'focus-metavariable': '$SINK' }] },
        ],
      },
      {
        id: `${slug}-direct`,
        languages: ['typescript', 'javascript'],
        severity: 'WARNING',
        message: `Credentials obtained from get_api_credentials() are passed straight into an outbound call (Immune antibody ${rule.id}).`,
        metadata: { ...metadata, confidence: 'HIGH' },
        patterns: [
          { 'pattern-inside': '$CREDS = get_api_credentials(...);\n...\n' },
          {
            'pattern-either': [
              { pattern: 'fetch(..., $CREDS, ...)' },
              { pattern: 'fetch(`...${$CREDS}...`, ...)' },
              { pattern: 'fetch(..., { body: $CREDS, ... })' },
              { pattern: 'fetch(..., { body: `...${$CREDS}...`, ... })' },
              { pattern: 'fetch(..., { body: JSON.stringify({..., $K: $CREDS, ...}), ... })' },
              { pattern: 'execSync(`...${$CREDS}...`, ...)' },
              { pattern: 'exec(`...${$CREDS}...`, ...)' },
              { pattern: 'spawn($X, [..., $CREDS, ...], ...)' },
            ],
          },
        ],
      },
    ],
  };
  return toYaml(doc, `Generated by Immune — antibody ${rule.id} (${breach.family}/${breach.variant}); secret → sink; derived from trace ${breach.id}`);
}

/* ------------------------------------------------------------------------------------------------
 * LLM refinement
 * ---------------------------------------------------------------------------------------------- */

export type CompleteFn = (prompt: string, opts?: { json?: boolean }) => Promise<string | null>;

/**
 * Build an `llmRefine` hook on top of a completion function. The model proposes extra regex patterns
 * (synonyms, encodings, split tokens); each is validated locally — compiles, catches the breach, and
 * occurs in <= benignFreqMax of the benign corpus — before it is merged. Never throws; falls back to the draft.
 */
export function createLlmRefiner(complete: CompleteFn, corpus: Trace[], opts: { benignFreqMax?: number; maxPatterns?: number } = {}): LlmRefine {
  const benignFreqMax = opts.benignFreqMax ?? 0.01;
  const maxPatterns = opts.maxPatterns ?? 8;
  return async (draft, breach) => {
    const payload = (phaseText(breach, draft.match.phase) ?? '').slice(0, 1500);
    const prompt = [
      'You are hardening an MCP firewall rule (an "antibody") that blocks a prompt-injection / exfiltration attack on an AI agent.',
      `Phase: ${draft.match.phase}. Attack family: ${breach.family}. Current JavaScript regex patterns (ANY-of; case-insensitive unless they contain uppercase):`,
      ...(draft.match.patterns ?? []).map((p) => `  - ${p}`),
      'Attack payload excerpt:',
      '"""',
      payload,
      '"""',
      'Propose up to 6 additional JavaScript regex sources (no flags, no delimiters) that would catch obvious variants of this payload',
      '(synonyms, re-phrasings, hyphen/space splitting, other destination hosts) WITHOUT matching ordinary business documents, customer records or reports.',
      'Also propose a short descriptive name (<= 80 chars).',
      'Respond with JSON only: {"patterns": ["..."], "name": "...", "notes": "..."}',
    ].join('\n');
    let raw: string | null = null;
    try {
      raw = await complete(prompt, { json: true });
    } catch {
      raw = null;
    }
    if (!raw) return draft;
    let parsed: { patterns?: unknown; name?: unknown } | undefined;
    try {
      const start = raw.indexOf('{');
      const end = raw.lastIndexOf('}');
      parsed = JSON.parse(start >= 0 && end > start ? raw.slice(start, end + 1) : raw) as { patterns?: unknown; name?: unknown };
    } catch {
      return draft;
    }
    const proposed = Array.isArray(parsed?.patterns) ? parsed!.patterns.filter((p): p is string => typeof p === 'string' && p.length > 0 && p.length <= 300) : [];
    const benign = corpus.filter((t) => t.label === 'benign');
    const accepted: string[] = [];
    for (const src of proposed) {
      if (!compilePattern(src)) continue;
      const probe: Rule = { ...draft, companions: undefined, match: { ...draft.match, patterns: [src] } };
      if (!catches(probe, breach)) continue;
      const hits = benign.filter((t) => {
        const input = inputFor(t, draft.match.phase);
        return input ? ruleMatches(probe, input, { tainted: t.tainted }).matched : false;
      }).length;
      if (benign.length && hits / benign.length > benignFreqMax) continue;
      if (!accepted.includes(src) && !(draft.match.patterns ?? []).includes(src)) accepted.push(src);
    }
    if (!accepted.length) return draft;
    const patterns = [...(draft.match.patterns ?? []), ...accepted].slice(0, maxPatterns);
    const name = typeof parsed?.name === 'string' && parsed.name.trim().length > 0 ? parsed.name.trim().slice(0, 80) : draft.name;
    return { ...draft, name, origin: 'llm', version: draft.version + 1, match: { ...draft.match, patterns } };
  };
}
