/**
 * secret_exfil — a tool call whose arguments carry a secret-looking value (or a registered secret)
 * through a network / exec / write capability.
 */
import type { Capability, Finding } from '../types.js';
import { type DetectorInput, makeFinding, walkStrings } from './common.js';

export const DETECTOR_SECRET_EXFIL = 'secret_exfil';

export interface SecretHit {
  /** 'aws_access_key' | 'openai_key' | 'github_token' | 'jwt' | 'pem' | 'registered' | 'high_entropy' | ... */
  kind: string;
  /** redacted value, safe for UI */
  redacted: string;
  /** arg path when found by walking args */
  path?: string;
}

/** Registered secret values (Gate.registerSecret). Matches raw, base64, base64url, %-encoded and hex forms. */
export class SecretRegistry {
  private readonly entries = new Map<string, { name: string; variants: string[] }>();

  register(value: string, name = 'registered'): boolean {
    const v = String(value ?? '');
    if (v.length < 6) return false;
    const variants = new Set<string>([
      v,
      Buffer.from(v, 'utf8').toString('base64'),
      Buffer.from(v, 'utf8').toString('base64url'),
      encodeURIComponent(v),
      Buffer.from(v, 'utf8').toString('hex'),
    ]);
    this.entries.set(v, { name, variants: [...variants].filter((x) => x.length >= 6) });
    return true;
  }

  unregister(value: string): boolean {
    return this.entries.delete(value);
  }

  clear(): void {
    this.entries.clear();
  }

  get size(): number {
    return this.entries.size;
  }

  values(): string[] {
    return [...this.entries.keys()];
  }

  /** Find registered secrets (any variant) inside a text. */
  findIn(text: string): SecretHit[] {
    if (!this.entries.size || !text) return [];
    const hits: SecretHit[] = [];
    const lower = text.toLowerCase();
    for (const [value, { name, variants }] of this.entries) {
      for (const variant of variants) {
        if (text.includes(variant) || (variant === value && lower.includes(variant.toLowerCase()))) {
          hits.push({ kind: `registered:${name}`, redacted: redactSecret(value) });
          break;
        }
      }
    }
    return hits;
  }
}

const SECRET_PATTERNS: { kind: string; re: RegExp }[] = [
  { kind: 'aws_access_key', re: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{16}\b/ },
  { kind: 'openai_key', re: /\bsk-(?:proj-|ant-|live-|test-)?[A-Za-z0-9_-]{20,}\b/ },
  { kind: 'anthropic_key', re: /\bsk-ant-[A-Za-z0-9_-]{20,}/ },
  { kind: 'github_token', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b/ },
  { kind: 'slack_token', re: /\bxox[baprse]-[A-Za-z0-9-]{10,}\b/ },
  { kind: 'stripe_key', re: /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b/ },
  { kind: 'google_api_key', re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { kind: 'sendgrid_key', re: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/ },
  { kind: 'twilio_key', re: /\bSK[0-9a-fA-F]{32}\b/ },
  { kind: 'npm_token', re: /\bnpm_[A-Za-z0-9]{36}\b/ },
  { kind: 'jwt', re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/ },
  { kind: 'pem_private_key', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { kind: 'bearer_token', re: /\bBearer\s+[A-Za-z0-9._~+/=-]{20,}/i },
  { kind: 'basic_auth_url', re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:@/]+:[^\s@/]{6,}@[^\s/]+/i },
  { kind: 'db_connection_string', re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s:@/]+:[^\s@/]{4,}@/i },
  {
    kind: 'contextual_secret',
    re: /\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|private[_-]?key|client[_-]?secret|access[_-]?key|secret[_-]?key|auth[_-]?token|refresh[_-]?token|access[_-]?token)\b["']?\s*[:=]\s*["']?(?!\$\{|<|\*\*\*|xxx|your[_-]|example|changeme|placeholder|redacted|null|undefined|true|false)([^\s"',;&}{)]{12,})/i,
  },
  { kind: 'env_dump', re: /(?:^|\n)\s*[A-Z][A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|ACCESS_KEY)[A-Z0-9_]*\s*=\s*["']?([^\s"']{8,})/ },
];

/** Shannon entropy in bits per character. */
export function shannonEntropy(s: string): number {
  if (!s.length) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of counts.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function charClasses(s: string): number {
  let n = 0;
  if (/[a-z]/.test(s)) n++;
  if (/[A-Z]/.test(s)) n++;
  if (/[0-9]/.test(s)) n++;
  if (/[^A-Za-z0-9]/.test(s)) n++;
  return n;
}

const TOKEN_RE = /[A-Za-z0-9_\-+=]{32,}/g;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** High-entropy opaque tokens (32+ chars, ≥3 character classes, entropy ≥ 4.2 bits/char), excluding hashes/UUIDs. */
export function findHighEntropyTokens(text: string): string[] {
  const out: string[] = [];
  let n = 0;
  for (const m of text.matchAll(TOKEN_RE)) {
    if (++n > 64) break;
    const tok = m[0];
    if (UUID_RE.test(tok)) continue;
    if (/^[0-9a-f]+$/i.test(tok)) continue; // hex hash
    if (/^[0-9]+$/.test(tok)) continue;
    if (/^[a-z]+(?:[_-][a-z]+)+$/i.test(tok)) continue; // snake/kebab words
    if (charClasses(tok) < 3) continue;
    if (shannonEntropy(tok) < 4.2) continue;
    out.push(tok);
  }
  return out;
}

/** Redact a secret for display: first 4 + … + last 2 chars, plus length. */
export function redactSecret(token: string): string {
  const t = String(token);
  if (t.length <= 8) return `${t.slice(0, 2)}…(${t.length} chars)`;
  return `${t.slice(0, 4)}…${t.slice(-2)} (${t.length} chars)`;
}

/** Raw secret-looking token values in a text (pattern hits + high-entropy tokens). Used to auto-register secrets. */
export function extractSecretTokens(text: string): { kind: string; value: string }[] {
  if (!text) return [];
  const out: { kind: string; value: string }[] = [];
  const seen = new Set<string>();
  for (const p of SECRET_PATTERNS) {
    const re = new RegExp(p.re.source, p.re.flags.includes('g') ? p.re.flags : `${p.re.flags}g`);
    let n = 0;
    for (const m of text.matchAll(re)) {
      if (++n > 16) break;
      const v = m[1] ?? m[0];
      if (v.length >= 8 && !seen.has(v)) {
        seen.add(v);
        out.push({ kind: p.kind, value: v });
      }
    }
  }
  for (const tok of findHighEntropyTokens(text)) {
    if (!seen.has(tok)) {
      seen.add(tok);
      out.push({ kind: 'high_entropy_token', value: tok });
    }
  }
  return out;
}

/** Find secret-looking values in a text. Pattern hits + registered secrets + high-entropy tokens. */
export function findSecrets(text: string, registry?: SecretRegistry): SecretHit[] {
  if (!text) return [];
  const hits: SecretHit[] = [];
  const seen = new Set<string>();
  const push = (kind: string, value: string) => {
    const key = `${kind}:${value}`;
    if (seen.has(key)) return;
    seen.add(key);
    hits.push({ kind, redacted: redactSecret(value) });
  };
  for (const p of SECRET_PATTERNS) {
    p.re.lastIndex = 0;
    const m = p.re.exec(text);
    if (m) push(p.kind, m[1] ?? m[0]);
  }
  if (registry) for (const h of registry.findIn(text)) push(h.kind, h.redacted);
  for (const tok of findHighEntropyTokens(text)) push('high_entropy_token', tok);
  return hits;
}

/** Walk args and find secrets per string leaf (keeps the arg path for evidence). */
export function findSecretsInArgs(args: Record<string, unknown> | undefined, registry?: SecretRegistry): SecretHit[] {
  if (!args) return [];
  const hits: SecretHit[] = [];
  walkStrings(args, (path, s) => {
    for (const h of findSecrets(s, registry)) hits.push({ ...h, path });
  });
  // Secrets split across keys (e.g. {"k1": "AKIA...", "k2": "..."}) are covered by the leaf walk; also
  // scan the whole serialized args once for registered secrets that span structure (JSON-encoded, etc.).
  if (registry && !hits.length) {
    try {
      for (const h of registry.findIn(JSON.stringify(args))) hits.push({ ...h, path: '*' });
    } catch {
      /* ignore */
    }
  }
  return hits;
}

/* ------------------------------------------------------------------------------------------------
 * Transformed registered secrets (chunked / reversed / split) — used by the synthesizer and for display.
 * The runtime registry check deliberately only covers raw/base64/url/hex forms; antibodies cover transforms.
 * ---------------------------------------------------------------------------------------------- */

export type SecretTransform = 'raw' | 'chunked' | 'reversed' | 'split' | null;

export interface TransformedSecretHit {
  /** the registered secret that was found (raw value — use `redacted` for display) */
  secret: string | null;
  redacted: string | null;
  transform: SecretTransform;
  /** regex source catching this transform; case-sensitive when the secret has uppercase letters */
  pattern: string | null;
  /** alphanumeric pieces of the secret the pattern was built from */
  pieces: string[];
}

export function stripToAlnum(s: string): string {
  return s.replace(/[^A-Za-z0-9]/g, '');
}

export function reverseString(s: string): string {
  return [...s].reverse().join('');
}

/** Separator-tolerant sequence: 'AKIA' → 'A[\W_]{0,3}K[\W_]{0,3}I[\W_]{0,3}A' */
export function tolerantSequence(alnum: string, gap = '[\\W_]{0,3}'): string {
  return [...alnum].map((ch) => (/[A-Za-z0-9]/.test(ch) ? ch : `\\${ch}`)).join(gap);
}

export const SECRET_PATTERN_PREFIX_MAX = 16;
export const SECRET_PATTERN_PREFIX_MIN = 8;

/** Pattern from the first 12–16 alphanumerics of a secret (or of its reverse), separator-tolerant. */
export function secretPrefixPattern(secret: string, opts: { reversed?: boolean; maxLen?: number } = {}): string | null {
  const core = stripToAlnum(secret);
  if (core.length < SECRET_PATTERN_PREFIX_MIN) return null;
  const seq = opts.reversed ? reverseString(core) : core;
  return tolerantSequence(seq.slice(0, Math.min(opts.maxLen ?? SECRET_PATTERN_PREFIX_MAX, seq.length)));
}

const NO_HIT: TransformedSecretHit = { secret: null, redacted: null, transform: null, pattern: null, pieces: [] };

/**
 * Find a registered secret inside a text (e.g. JSON.stringify(args)) under a transform, case-sensitively:
 *  - raw: literal occurrence
 *  - chunked: present after stripping every non-alphanumeric ("AKIA IOSF ODNN", "AKIA-IOSF.ODNN", zero-width)
 *  - reversed: the reversed secret is present in the stripped text
 *  - split: the longest present prefix (>= 4 chars) and the remainder (>= 4 chars) are both present, non-contiguously
 * Returns the pattern that catches the transform (`<p1>[\s\S]{0,160}<p2>` in either order for split).
 */
export function findTransformedSecret(text: string, secrets: Iterable<string>): TransformedSecretHit {
  if (!text) return NO_HIT;
  const list = [...new Set([...secrets].filter((s) => typeof s === 'string' && stripToAlnum(s).length >= SECRET_PATTERN_PREFIX_MIN))].sort((a, b) => b.length - a.length);
  if (!list.length) return NO_HIT;
  const stripped = stripToAlnum(text);
  for (const secret of list) {
    const core = stripToAlnum(secret);
    const prefixLen = Math.min(SECRET_PATTERN_PREFIX_MAX, core.length);
    if (text.includes(secret)) {
      return { secret, redacted: redactSecret(secret), transform: 'raw', pattern: tolerantSequence(core.slice(0, prefixLen)), pieces: [core.slice(0, prefixLen)] };
    }
    if (stripped.includes(core)) {
      return { secret, redacted: redactSecret(secret), transform: 'chunked', pattern: tolerantSequence(core.slice(0, prefixLen)), pieces: [core.slice(0, prefixLen)] };
    }
    const rev = reverseString(core);
    if (stripped.includes(rev)) {
      return { secret, redacted: redactSecret(secret), transform: 'reversed', pattern: tolerantSequence(rev.slice(0, prefixLen)), pieces: [rev.slice(0, prefixLen)] };
    }
    // split: binary-search the longest present prefix (presence is monotone in prefix length)
    let lo = 0;
    let hi = core.length;
    while (lo < hi) {
      const mid = Math.ceil((lo + hi) / 2);
      if (stripped.includes(core.slice(0, mid))) lo = mid;
      else hi = mid - 1;
    }
    const k = lo;
    if (k >= 4 && core.length - k >= 4) {
      const p1 = core.slice(0, k);
      const p2 = core.slice(k);
      if (stripped.includes(p2)) {
        const a = tolerantSequence(p1.slice(0, SECRET_PATTERN_PREFIX_MAX));
        const b = tolerantSequence(p2.slice(0, SECRET_PATTERN_PREFIX_MAX));
        return { secret, redacted: redactSecret(secret), transform: 'split', pattern: `(?:${a}[\\s\\S]{0,160}${b}|${b}[\\s\\S]{0,160}${a})`, pieces: [p1, p2] };
      }
    }
  }
  return NO_HIT;
}

export const EXFIL_CAPABILITIES: readonly Capability[] = ['network', 'exec', 'write'];

/** Detector: tool_call phase. */
export function secretExfil(input: DetectorInput): Finding[] {
  if (input.phase !== 'tool_call' || !input.call) return [];
  const call = input.call;
  const hits = findSecretsInArgs(call.args, input.secrets);
  if (!hits.length) return [];
  const caps = call.capabilities ?? [];
  const outbound = caps.some((c) => EXFIL_CAPABILITIES.includes(c));
  const kinds = [...new Set(hits.map((h) => h.kind))].join(', ');
  const evidence = hits
    .slice(0, 3)
    .map((h) => `${h.path ?? 'args'}=${h.redacted}`)
    .join('; ');
  const registered = hits.some((h) => h.kind.startsWith('registered'));
  const severity = outbound ? 'critical' : registered ? 'high' : 'medium';
  return [
    makeFinding(
      DETECTOR_SECRET_EXFIL,
      severity,
      outbound
        ? `Outbound ${caps.join('/')} call ${call.server}/${call.tool} carries ${hits.length} secret-looking value(s) (${kinds})`
        : `Call ${call.server}/${call.tool} carries ${hits.length} secret-looking value(s) (${kinds}) in its arguments`,
      evidence,
    ),
  ];
}
