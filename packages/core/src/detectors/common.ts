/**
 * Shared detector plumbing: input shape, text normalization / de-obfuscation, evidence excerpts.
 * Everything here is pure and allocation-light — detectors must stay well under 2ms per inspection.
 */
import type { Capability, Finding, Phase, Severity, ToolDef } from '../types.js';
import type { HashPinRegistry } from './rugPull.js';
import type { TrustedTools } from './homoglyph.js';
import type { SecretRegistry } from './secretExfil.js';

export interface CallSubject {
  server: string;
  tool: string;
  args: Record<string, unknown>;
  capabilities: Capability[];
}

export interface ResultSubject {
  server: string;
  tool: string;
  content: string;
}

/** One inspection. Only the field matching `phase` is required; the rest is session/registry context. */
export interface DetectorInput {
  phase: Phase;
  sessionId?: string;
  /** tool_def phase subject; also consulted in tool_call phase for capabilities */
  toolDef?: ToolDef;
  /** tool_result phase subject */
  result?: ResultSubject;
  /** tool_call phase subject */
  call?: CallSubject;
  /** session already tainted by an earlier flagged result */
  tainted?: boolean;
  /** human-readable reason the session is tainted (shown as taint_gate evidence) */
  taintReason?: string;
  /** destination allowlist (hosts, `*.wildcards` allowed). Empty/undefined = destination detector disabled */
  allowlist?: string[];
  /** rug-pull hash pins */
  pins?: HashPinRegistry;
  /** trusted (server, tool) identities for look-alike detection */
  trusted?: TrustedTools;
  /** values registered via Gate.registerSecret */
  secrets?: SecretRegistry;
}

export type Detector = (input: DetectorInput) => Finding[];

export const SENSITIVE_CAPABILITIES: readonly Capability[] = ['network', 'exec', 'write', 'secret'];

export function makeFinding(
  detector: string,
  severity: Severity,
  message: string,
  evidence: string,
  ruleId?: string,
): Finding {
  const f: Finding = { detector, severity, message, evidence: clean(evidence) };
  if (ruleId) f.ruleId = ruleId;
  return f;
}

/* ------------------------------------------------------------------------------------------------
 * Text normalization
 * ---------------------------------------------------------------------------------------------- */

/** Zero-width / invisible / bidi-control / variation-selector / Unicode-tag characters. */
export const INVISIBLE_RE =
  /[­͏؜ᅟᅠ឴឵᠋-᠎​-‏‪-‮⁠-⁯ㅤ︀-️﻿ﾠ]|[\u{E0000}-\u{E007F}]|[\u{1D173}-\u{1D17A}]/gu;

/** Unicode "tag" block (U+E0000..E007F) encodes ASCII invisibly — decode it. */
const TAG_RE = /[\u{E0020}-\u{E007E}]/gu;

/** Visually confusable → ASCII. NFKC handles fullwidth, math alphanumerics, ligatures; this covers scripts. */
const CONFUSABLES: Record<string, string> = {
  // Cyrillic lowercase
  а: 'a', е: 'e', о: 'o', р: 'p', с: 'c', у: 'y', х: 'x', і: 'i', ј: 'j', ѕ: 's', һ: 'h', ԁ: 'd', ԛ: 'q', ԝ: 'w',
  ѵ: 'v', ӏ: 'l', ь: 'b', ғ: 'f', ԍ: 'g', ҏ: 'p', ҳ: 'x', ү: 'y', ӽ: 'x', ԉ: 'n', н: 'h', к: 'k', т: 't', м: 'm', в: 'b',
  // Cyrillic uppercase
  А: 'A', В: 'B', Е: 'E', К: 'K', М: 'M', Н: 'H', О: 'O', Р: 'P', С: 'C', Т: 'T', Х: 'X', У: 'Y', Ѕ: 'S', І: 'I',
  Ј: 'J', Ԛ: 'Q', Ԝ: 'W', Ѵ: 'V', Ғ: 'F', Ԍ: 'G', Ӏ: 'I',
  // Greek
  α: 'a', ο: 'o', ν: 'v', ρ: 'p', τ: 't', υ: 'u', ι: 'i', κ: 'k', ϲ: 'c', ε: 'e', η: 'n', μ: 'u', ω: 'w', ϳ: 'j',
  ϱ: 'p', ϵ: 'e', ϖ: 'w', ꭓ: 'x', Α: 'A', Β: 'B', Ε: 'E', Ζ: 'Z', Η: 'H', Ι: 'I', Κ: 'K', Μ: 'M', Ν: 'N', Ο: 'O',
  Ρ: 'P', Τ: 'T', Υ: 'Y', Χ: 'X',
  // Latin extended / IPA / letterlike / misc
  ı: 'i', ȷ: 'j', ɑ: 'a', ɡ: 'g', ʏ: 'y', ꜱ: 's', ƅ: 'b', ƈ: 'c', ɗ: 'd', ҫ: 'c', ℓ: 'l', ℹ: 'i', ℯ: 'e', ℴ: 'o',
  ꬲ: 'e', ꞇ: 't', ꞅ: 's', ꬵ: 'f', ꬷ: 'l', ꭇ: 'r', ɩ: 'i', ʟ: 'l', ᴛ: 't', ᴜ: 'u', ᴡ: 'w', ᴢ: 'z', ᴅ: 'd', ᴇ: 'e',
  // Armenian
  ո: 'n', ս: 'u', օ: 'o', ց: 'g', ա: 'w', ք: 'f',
};

const CONFUSABLE_RE = new RegExp(`[${Object.keys(CONFUSABLES).join('')}]`, 'gu');

/** Count whitespace-delimited words mixing ASCII letters with confusable non-ASCII letters (classic obfuscation). */
export function countMixedScriptWords(raw: string): number {
  let n = 0;
  for (const word of raw.split(/\s+/)) {
    if (word.length < 3) continue;
    if (!/[a-zA-Z]/.test(word)) continue;
    CONFUSABLE_RE.lastIndex = 0;
    if (CONFUSABLE_RE.test(word)) n++;
    CONFUSABLE_RE.lastIndex = 0;
  }
  return n;
}

export interface NormalizedText {
  raw: string;
  /** NFKC → strip marks → fold confusables → strip invisibles → lowercase → collapse whitespace */
  normalized: string;
  /** `normalized` with every non-alphanumeric removed (defeats "i.g.n.o.r.e" / "ig-nore" splitting) */
  squeezed: string;
  /** one level of hidden layers: base64 blobs, %-encoding, HTML entities, Unicode tag smuggling (normalized) */
  decoded: string[];
  zeroWidthCount: number;
  confusableCount: number;
  /** text hidden in HTML comments / hidden tags / zero-size or invisible spans (normalized) */
  hiddenBlocks: string[];
}

/** Fold a string to its ASCII-ish skeleton: NFKC, strip combining marks, confusables → Latin, lowercase. */
export function foldConfusables(s: string): { text: string; folded: number } {
  let folded = 0;
  const text = s
    .normalize('NFKC')
    .normalize('NFD')
    .replace(/\p{M}+/gu, '')
    .replace(CONFUSABLE_RE, (ch) => {
      folded++;
      return CONFUSABLES[ch] ?? ch;
    })
    .toLowerCase();
  return { text, folded };
}

export function stripInvisible(s: string): string {
  return s.replace(INVISIBLE_RE, '');
}

export function countInvisible(s: string): number {
  let n = 0;
  for (const _ of s.matchAll(INVISIBLE_RE)) n++;
  return n;
}

const BASE64_RE = /[A-Za-z0-9+/]{40,}={0,2}|[A-Za-z0-9_-]{40,}/g;
const PCT_RE = /(?:%[0-9A-Fa-f]{2}){6,}/g;
const ENTITY_RE = /&#x?[0-9a-fA-F]{2,6};/;
const HTML_COMMENT_RE = /<!--([\s\S]*?)-->/g;
const HIDDEN_TAG_RE =
  /<(important|system|instructions?|hidden|secret|admin|override|note[_ -]?to[_ -]?(ai|assistant|agent|model)|ai|assistant|agent|developer|sys|prompt|directive|internal|confidential)\b[^>]*>([\s\S]*?)<\/\1\s*>/gi;
const HIDDEN_STYLE_RE =
  /<([a-z]+)[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0(?:\.0+)?\b|color\s*:\s*(?:#fff(?:fff)?|white|transparent)|\bhidden\b)[^>]*>([\s\S]*?)<\/\1\s*>/gi;
const MD_HIDDEN_RE = /!?\[\s*\]\(([^)]{12,})\)/g;

function decodeTagChars(raw: string): string | null {
  if (!TAG_RE.test(raw)) {
    TAG_RE.lastIndex = 0;
    return null;
  }
  TAG_RE.lastIndex = 0;
  let out = '';
  for (const ch of raw) {
    const cp = ch.codePointAt(0)!;
    if (cp >= 0xe0020 && cp <= 0xe007e) out += String.fromCharCode(cp - 0xe0000);
  }
  return out.length >= 4 ? out : null;
}

function printableRatio(s: string): number {
  if (!s.length) return 0;
  let ok = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if ((c >= 0x20 && c < 0x7f) || c === 0x0a || c === 0x0d || c === 0x09) ok++;
  }
  return ok / s.length;
}

function decodeBase64Blobs(raw: string): string[] {
  const out: string[] = [];
  let count = 0;
  for (const m of raw.matchAll(BASE64_RE)) {
    if (++count > 8) break;
    const blob = m[0];
    // skip hex-only (hashes) and tokens with no mixed case (unlikely to be base64 text)
    if (/^[0-9a-f]+$/i.test(blob)) continue;
    if (!/[a-z]/.test(blob) || !/[A-Z]/.test(blob)) continue;
    try {
      const buf = Buffer.from(blob.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
      if (buf.length < 12) continue;
      const text = buf.toString('utf8');
      if (printableRatio(text) >= 0.9 && /[a-z]{3,}\s+[a-z]{2,}/i.test(text)) out.push(text);
    } catch {
      /* not base64 */
    }
  }
  return out;
}

function decodePercent(raw: string): string | null {
  if (!PCT_RE.test(raw)) {
    PCT_RE.lastIndex = 0;
    return null;
  }
  PCT_RE.lastIndex = 0;
  try {
    const d = decodeURIComponent(raw);
    return d !== raw ? d : null;
  } catch {
    return null;
  }
}

function decodeEntities(raw: string): string | null {
  if (!ENTITY_RE.test(raw)) return null;
  const d = raw.replace(/&#x([0-9a-fA-F]{2,6});/g, (_m, h: string) => safeChar(parseInt(h, 16)))
    .replace(/&#([0-9]{2,7});/g, (_m, n: string) => safeChar(parseInt(n, 10)));
  return d !== raw ? d : null;
}

function safeChar(cp: number): string {
  if (!Number.isFinite(cp) || cp < 0 || cp > 0x10ffff) return '';
  try {
    return String.fromCodePoint(cp);
  } catch {
    return '';
  }
}

function normalizeCore(raw: string): { normalized: string; folded: number } {
  const { text, folded } = foldConfusables(stripInvisible(raw));
  const normalized = text.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, ' ').replace(/\s+/g, ' ').trim();
  return { normalized, folded };
}

const NORMALIZE_CACHE = new Map<string, NormalizedText>();
const NORMALIZE_CACHE_MAX = 256;

/** Full de-obfuscating normalization of a text. Cached (LRU-ish) because the gate and rules share views. */
export function normalizeText(raw: string): NormalizedText {
  const cached = NORMALIZE_CACHE.get(raw);
  if (cached) return cached;
  const zeroWidthCount = countInvisible(raw);
  const { normalized, folded } = normalizeCore(raw);
  const squeezed = normalized.replace(/[^a-z0-9]+/g, '');

  const decoded: string[] = [];
  const tag = decodeTagChars(raw);
  if (tag) decoded.push(normalizeCore(tag).normalized);
  const pct = decodePercent(raw);
  if (pct) decoded.push(normalizeCore(pct).normalized);
  const ent = decodeEntities(raw);
  if (ent) decoded.push(normalizeCore(ent).normalized);
  for (const b of decodeBase64Blobs(raw)) decoded.push(normalizeCore(b).normalized);

  const hiddenBlocks: string[] = [];
  for (const m of raw.matchAll(HTML_COMMENT_RE)) hiddenBlocks.push(normalizeCore(m[1] ?? '').normalized);
  for (const m of raw.matchAll(HIDDEN_TAG_RE)) hiddenBlocks.push(normalizeCore(m[3] ?? '').normalized);
  for (const m of raw.matchAll(HIDDEN_STYLE_RE)) hiddenBlocks.push(normalizeCore(m[2] ?? '').normalized);
  for (const m of raw.matchAll(MD_HIDDEN_RE)) hiddenBlocks.push(normalizeCore(m[1] ?? '').normalized);

  const out: NormalizedText = {
    raw,
    normalized,
    squeezed,
    decoded,
    zeroWidthCount,
    confusableCount: folded,
    hiddenBlocks: hiddenBlocks.filter((b) => b.length > 0),
  };
  if (NORMALIZE_CACHE.size >= NORMALIZE_CACHE_MAX) {
    const first = NORMALIZE_CACHE.keys().next().value;
    if (first !== undefined) NORMALIZE_CACHE.delete(first);
  }
  NORMALIZE_CACHE.set(raw, out);
  return out;
}

/** All textual views a pattern should be tested against: raw, normalized, decoded layers, hidden blocks. */
export function textViews(n: NormalizedText): string[] {
  const views = [n.normalized];
  if (n.raw !== n.normalized) views.push(n.raw);
  for (const d of n.decoded) views.push(d);
  for (const h of n.hiddenBlocks) views.push(h);
  return views;
}

/* ------------------------------------------------------------------------------------------------
 * Evidence helpers
 * ---------------------------------------------------------------------------------------------- */

/** Make a string safe for UI display: strip invisibles/control chars, collapse whitespace, cap length. */
export function clean(s: string, max = 200): string {
  const t = stripInvisible(s).replace(/[\u0000-\u001f]+/g, ' ').replace(/\s+/g, ' ').trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

/** Excerpt around a match: ±radius chars, cleaned. */
export function excerpt(text: string, index: number, length: number, radius = 48): string {
  const start = Math.max(0, index - radius);
  const end = Math.min(text.length, index + length + radius);
  const prefix = start > 0 ? '…' : '';
  const suffix = end < text.length ? '…' : '';
  return clean(`${prefix}${text.slice(start, end)}${suffix}`, 2 * radius + length + 4);
}

/** First match of `re` in any of the views; returns the excerpt. */
export function firstMatch(re: RegExp, views: string[]): { view: string; match: RegExpExecArray } | null {
  for (const view of views) {
    re.lastIndex = 0;
    const m = re.exec(view);
    if (m) return { view, match: m };
  }
  return null;
}

/** Weighted signal accumulator used by the heuristic detectors. */
export class SignalSheet {
  score = 0;
  readonly hits: { name: string; weight: number; evidence: string }[] = [];

  add(name: string, weight: number, evidence: string): this {
    this.score += weight;
    this.hits.push({ name, weight, evidence: clean(evidence, 160) });
    return this;
  }

  /** Test a regex against views; on first hit, add signal with excerpt evidence. Returns hit boolean. */
  test(name: string, weight: number, re: RegExp, views: string[]): boolean {
    const hit = firstMatch(re, views);
    if (!hit) return false;
    this.add(name, weight, excerpt(hit.view, hit.match.index, hit.match[0].length));
    return true;
  }

  get names(): string[] {
    return this.hits.map((h) => h.name);
  }

  /** Strongest evidence first (by weight, then order). */
  get evidence(): string {
    const top = [...this.hits].sort((a, b) => b.weight - a.weight)[0];
    return top ? top.evidence : '';
  }
}

export function severityForScore(score: number, thresholds: { critical: number; high: number; medium: number }): Severity {
  if (score >= thresholds.critical) return 'critical';
  if (score >= thresholds.high) return 'high';
  if (score >= thresholds.medium) return 'medium';
  return 'low';
}

/** Flatten an args object into one string for pattern matching (values only, stable key order). */
export function argsText(args: Record<string, unknown> | undefined): string {
  if (!args) return '';
  try {
    return JSON.stringify(args);
  } catch {
    return String(args);
  }
}

/** Walk a JSON-ish value and visit every string leaf with its dotted path. */
export function walkStrings(value: unknown, visit: (path: string, s: string) => void, path = '', depth = 0): void {
  if (depth > 8 || value === null || value === undefined) return;
  if (typeof value === 'string') {
    visit(path, value);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((v, i) => walkStrings(v, visit, `${path}[${i}]`, depth + 1));
    return;
  }
  if (typeof value === 'object') {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      walkStrings(v, visit, path ? `${path}.${k}` : k, depth + 1);
    }
  }
}
