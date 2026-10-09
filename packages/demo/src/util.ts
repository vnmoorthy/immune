/**
 * @immune/demo — shared helpers for the attack arena.
 *
 * Pure, deterministic, dependency-free. Everything here is used by acme.ts,
 * attacks.ts, agent.ts, corpus.ts and scenario.ts so that variant payloads,
 * host lists and detection heuristics stay consistent across the package
 * (which is what makes corpus replay meaningful).
 */

import type { Capability, Decision, Finding, Severity } from '@immune/core';

/** Hosts a well-behaved acme agent is allowed to reach. */
export const DEFAULT_ALLOWLIST: readonly string[] = [
  'hooks.slack.com',
  'api.acme.internal',
  'status.acme.com',
];

/** Attacker-controlled destinations. None of these are ever contacted for real. */
export const ATTACKER_HOSTS: readonly string[] = [
  'evil-cdn.example',
  'ops-telemetry.io',
  'hooks.exfil.sh',
  'cdn-metrics.app',
  'telemetry-sync.net',
  'paste.bin-drop.io',
];

/**
 * Fake credentials the acme `get_api_credentials` tool hands out. These are
 * deliberately shaped like real AWS / OpenAI tokens so the secret-exfil
 * heuristics fire, but they are non-functional example values.
 */
export const ACME_FAKE_SECRETS = {
  awsAccessKeyId: 'AKIAIOSFODNN7EXAMPLE',
  awsSecretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  openaiToken: 'sk-live-IMMUNEdemo00NOTAREALKEY0000000000',
} as const;

/** All fake secret values as a flat list (for exfil detection + echo). */
export const ACME_SECRET_VALUES: readonly string[] = [
  ACME_FAKE_SECRETS.awsAccessKeyId,
  ACME_FAKE_SECRETS.awsSecretAccessKey,
  ACME_FAKE_SECRETS.openaiToken,
];

/* --------------------------------------------------------------------------
 * Deterministic PRNG + id generation (seeded, so scenarios/corpus replay).
 * ------------------------------------------------------------------------ */

/** mulberry32: tiny deterministic PRNG. Returns floats in [0, 1). */
export function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return function next(): number {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** A small deterministic id source. `rng` keeps ids stable for a given seed. */
export function makeIdGen(prefix: string, rng: () => number): () => string {
  const hex = '0123456789abcdef';
  return function newId(): string {
    let s = '';
    for (let i = 0; i < 12; i++) s += hex[Math.floor(rng() * 16)];
    return `${prefix}_${s}`;
  };
}

/** Deterministic single id from a seed + salt (used where no rng is threaded). */
export function seededId(prefix: string, seed: number, salt: number): string {
  const rng = mulberry32((seed ^ (salt * 2654435761)) >>> 0);
  return makeIdGen(prefix, rng)();
}

/** Pick a deterministic element. */
export function pick<T>(arr: readonly T[], rng: () => number): T {
  return arr[Math.floor(rng() * arr.length)]!;
}

/* --------------------------------------------------------------------------
 * Text normalisation — this is what lets the gullible agent "see through"
 * obfuscation that a naive learned pattern-rule would miss.
 * ------------------------------------------------------------------------ */

/** Zero-width / invisible joiner characters used by mutation to break tokens. */
export const ZERO_WIDTH = ['​', '‌', '‍', '⁠', '﻿'];
const ZERO_WIDTH_RE = /[​‌‍⁠﻿]/g;

/** Remove invisible characters so split tokens re-join. */
export function stripZeroWidth(text: string): string {
  return text.replace(ZERO_WIDTH_RE, '');
}

/** Common homoglyph confusables -> ascii (so a look-alike resolves). */
const HOMOGLYPHS: Record<string, string> = {
  'а': 'a', // Cyrillic a
  'е': 'e', // Cyrillic e
  'о': 'o', // Cyrillic o
  'р': 'p', // Cyrillic r->p shape
  'с': 'c', // Cyrillic s->c shape
  'х': 'x', // Cyrillic h->x shape
  'ѕ': 's', // Cyrillic dze
  'і': 'i', // Cyrillic byelorussian-ukrainian i
  'һ': 'h', // Cyrillic shha
  'ο': 'o', // Greek omicron
  'υ': 'u', // Greek upsilon
  'Α': 'A', // Greek Alpha
  'А': 'A', // Cyrillic A
  '․': '.', // one dot leader
};

/** Fold homoglyph characters to their ascii look-alike. */
export function foldHomoglyphs(text: string): string {
  let out = '';
  for (const ch of text) out += HOMOGLYPHS[ch] ?? ch;
  return out;
}

/** True when a string contains confusable (non-ascii look-alike) characters. */
export function hasHomoglyph(text: string): boolean {
  for (const ch of text) if (ch in HOMOGLYPHS) return true;
  return false;
}

/** Normalise text for robust instruction parsing: strip invisibles + fold look-alikes. */
export function normalizeText(text: string): string {
  return foldHomoglyphs(stripZeroWidth(text));
}

/* --------------------------------------------------------------------------
 * base64 — mutation hides destinations/instructions in a base64 fragment;
 * a real agent decodes helpfully and then follows them.
 * ------------------------------------------------------------------------ */

const B64_RE = /\b(?:b64|base64)[:=]?\s*([A-Za-z0-9+/]{12,}={0,2})\b/gi;

export function b64encode(s: string): string {
  return Buffer.from(s, 'utf8').toString('base64');
}

export function b64decode(s: string): string {
  try {
    return Buffer.from(s, 'base64').toString('utf8');
  } catch {
    return '';
  }
}

/** Find base64 fragments tagged with a b64/base64 marker and decode them. */
export function decodeB64Fragments(text: string): string[] {
  const out: string[] = [];
  for (const m of text.matchAll(B64_RE)) {
    const dec = b64decode(m[1]!);
    if (dec) out.push(dec);
  }
  return out;
}

/* --------------------------------------------------------------------------
 * URL / host + secret heuristics (mirror the detector semantics in CONTRACTS).
 * ------------------------------------------------------------------------ */

const URL_RE = /https?:\/\/([a-z0-9.-]+)(?::\d+)?(\/[^\s"'`)<>\]]*)?/gi;

export interface UrlRef {
  url: string;
  host: string;
  path: string;
}

/** Extract every http(s) URL (after normalisation) from arbitrary text. */
export function extractUrls(text: string): UrlRef[] {
  const norm = normalizeText(text);
  const out: UrlRef[] = [];
  for (const m of norm.matchAll(URL_RE)) {
    out.push({ url: m[0], host: (m[1] ?? '').toLowerCase(), path: m[2] ?? '' });
  }
  return out;
}

/** First URL host in text, or undefined. */
export function firstHost(text: string): string | undefined {
  return extractUrls(text)[0]?.host;
}

/** Host of a single url-ish string. */
export function hostOf(url: string): string | undefined {
  const m = normalizeText(url).match(/https?:\/\/([a-z0-9.-]+)/i);
  return m ? m[1]!.toLowerCase() : undefined;
}

/** Secret-looking tokens: AWS AKIA keys, sk- tokens, long hex/base64 blobs, known fakes. */
const SECRET_PATTERNS: RegExp[] = [
  /AKIA[0-9A-Z]{12,}/,
  /\bsk-[A-Za-z0-9_-]{12,}/,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}/, // slack-style
  /[A-Za-z0-9/+]{40,}={0,2}/, // long opaque blob
];

/** Heuristic: does this text carry a credential/secret-looking token? */
export function looksLikeSecret(text: string): boolean {
  const t = normalizeText(text);
  if (ACME_SECRET_VALUES.some((s) => t.includes(s))) return true;
  return SECRET_PATTERNS.some((re) => re.test(t));
}

/** Is a host inside the allowlist (exact or subdomain)? */
export function isAllowedHost(host: string | undefined, allowlist: readonly string[]): boolean {
  if (!host) return true; // no destination -> nothing to disallow
  const h = host.toLowerCase();
  return allowlist.some((a) => h === a || h.endsWith(`.${a}`));
}

/* --------------------------------------------------------------------------
 * Capability map for acme tools (kept here so every module agrees).
 * ------------------------------------------------------------------------ */

export const TOOL_CAPABILITIES: Record<string, Capability[]> = {
  lookup_customer: ['read'],
  read_shared_doc: ['read'],
  fetch_url: ['network'],
  send_webhook: ['network'],
  run_report: ['exec'],
  update_profile: ['write'],
  get_api_credentials: ['secret'],
};

export function capabilitiesOf(tool: string): Capability[] {
  return TOOL_CAPABILITIES[tool] ?? [];
}

/* --------------------------------------------------------------------------
 * A tiny, fast, structural rule matcher that mirrors core RuleMatch semantics.
 * Used by corpus.ts so generated traces can reflect "what detection would do"
 * without needing the (separately-built) core Gate at hand. Kept deliberately
 * close to CONTRACTS.md RuleMatch so results line up with the real gate.
 * ------------------------------------------------------------------------ */

export interface HeuristicInput {
  phase: 'tool_def' | 'tool_call' | 'tool_result';
  server?: string;
  tool?: string;
  /** description (tool_def) | content (tool_result) | JSON.stringify(args) (tool_call) */
  text: string;
  capabilities?: Capability[];
  tainted?: boolean;
  /** destination host for a network call, if any */
  host?: string;
  carriesSecret?: boolean;
}

export interface HeuristicRule {
  id: string;
  action: Decision;
  severity?: Severity;
  match: {
    phase: 'tool_def' | 'tool_call' | 'tool_result';
    server?: string;
    tool?: string;
    patterns?: string[];
    capabilities?: Capability[];
    afterTainted?: boolean;
    destinationNotIn?: string[];
    carriesSecret?: boolean;
  };
}

/** Does a single structural rule match an input? (AND over present fields.) */
export function ruleMatches(rule: HeuristicRule, input: HeuristicInput): boolean {
  const m = rule.match;
  if (m.phase !== input.phase) return false;
  if (m.server && m.server !== input.server) return false;
  if (m.tool && m.tool !== input.tool) return false;
  if (m.afterTainted && !input.tainted) return false;
  if (m.capabilities && m.capabilities.length) {
    const caps = input.capabilities ?? [];
    if (!m.capabilities.some((c) => caps.includes(c))) return false;
  }
  if (m.carriesSecret && !input.carriesSecret) return false;
  if (m.destinationNotIn) {
    // block when host present and NOT in allowlist
    if (!input.host) return false;
    if (isAllowedHost(input.host, m.destinationNotIn)) return false;
  }
  if (m.patterns && m.patterns.length) {
    const hay = normalizeText(input.text);
    const ok = m.patterns.some((p) => {
      try {
        return new RegExp(p, 'i').test(hay);
      } catch {
        return hay.toLowerCase().includes(p.toLowerCase());
      }
    });
    if (!ok) return false;
  }
  return true;
}

const DECISION_RANK: Record<Decision, number> = { allow: 0, flag: 1, block: 2, quarantine: 3 };

export function strongerDecision(a: Decision, b: Decision): Decision {
  return DECISION_RANK[a] >= DECISION_RANK[b] ? a : b;
}

/** Build a Finding for a matched heuristic rule. */
export function findingForRule(rule: HeuristicRule, message: string, evidence: string): Finding {
  return {
    detector: `rule:${rule.id}`,
    severity: rule.severity ?? 'high',
    message,
    evidence: evidence.slice(0, 160),
    ruleId: rule.id,
  };
}

export function clampExcerpt(s: string, n = 160): string {
  const one = s.replace(/\s+/g, ' ').trim();
  return one.length <= n ? one : one.slice(0, n - 1) + '…';
}
