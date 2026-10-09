/**
 * destination — a network/exec call whose arguments reference a host outside the allowlist.
 */
import type { Capability, Finding } from '../types.js';
import { type DetectorInput, makeFinding, walkStrings } from './common.js';

export const DETECTOR_DESTINATION = 'destination';

export interface HostRef {
  host: string;
  /** full URL when one was found */
  url?: string;
  /** dotted arg path */
  path: string;
  source: 'url' | 'field';
}

const URL_RE = /\b(?:https?|wss?|ftp|sftp|ssh|smb|ldap|gopher|dict|file):\/\/[^\s"'<>\\)\]},|`]+/gi;
const PROTO_RELATIVE_RE = /(?:^|\s)\/\/((?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?)\b/i;
const HOST_FIELD_RE =
  /^(?:url|uri|href|host|hostname|domain|endpoint|server|webhook|webhook_?url|callback|callback_?url|target|destination|dest|address|addr|origin|base_?url|api_?url|remote|upstream|proxy|redirect|redirect_?uri|link|site|website|to_?url|post_?to|send_?to|sink|collector|relay)$/i;
const BARE_HOST_RE = /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}(?::\d{1,5})?(?:\/.*)?$/i;
const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?:\/.*)?$/;

export function normalizeHost(host: string): string {
  let h = host.trim().toLowerCase();
  if (h.startsWith('[') && h.includes(']')) return h.slice(0, h.indexOf(']') + 1);
  h = h.replace(/\.+$/, '');
  // strip :port
  const idx = h.lastIndexOf(':');
  if (idx > 0 && /^\d+$/.test(h.slice(idx + 1))) h = h.slice(0, idx);
  return h;
}

function hostFromUrl(url: string): string | null {
  try {
    const u = new URL(url);
    return u.hostname ? normalizeHost(u.hostname) : null;
  } catch {
    const m = /^[a-z][a-z0-9+.-]*:\/\/(?:[^@/\s]+@)?([^/:?#\s]+)/i.exec(url);
    return m ? normalizeHost(m[1]!) : null;
  }
}

/** Extract every host referenced in args: URLs anywhere in string leaves, bare hosts in URL-ish fields. */
export function extractHosts(args: unknown): HostRef[] {
  const out: HostRef[] = [];
  const seen = new Set<string>();
  const push = (ref: HostRef) => {
    const key = `${ref.host}|${ref.path}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push(ref);
  };
  walkStrings(args, (path, s) => {
    if (s.length > 20_000) s = s.slice(0, 20_000);
    URL_RE.lastIndex = 0;
    let n = 0;
    for (const m of s.matchAll(URL_RE)) {
      if (++n > 32) break;
      const host = hostFromUrl(m[0]);
      if (host) push({ host, url: m[0], path, source: 'url' });
    }
    const pr = PROTO_RELATIVE_RE.exec(s);
    if (pr) push({ host: normalizeHost(pr[1]!), url: `//${pr[1]}`, path, source: 'url' });
    const key = path.split('.').pop()?.replace(/\[\d+\]$/, '') ?? '';
    if (HOST_FIELD_RE.test(key)) {
      const v = s.trim();
      if ((BARE_HOST_RE.test(v) || IPV4_RE.test(v)) && !/\s/.test(v)) {
        const hostPart = v.split('/')[0]!;
        push({ host: normalizeHost(hostPart), path, source: 'field' });
      }
    }
  });
  return out;
}

/** Normalize an allowlist entry (may be a host, host:port, wildcard or full URL) to a host pattern. */
export function normalizeAllowlistEntry(entry: string): string {
  let e = entry.trim().toLowerCase();
  if (!e) return e;
  if (/^[a-z][a-z0-9+.-]*:\/\//.test(e)) {
    const h = hostFromUrl(e);
    if (h) return h;
  }
  if (e.startsWith('*.')) return `*.${normalizeHost(e.slice(2))}`;
  if (e.startsWith('.')) return `*${normalizeHost(e)}`;
  e = normalizeHost(e.split('/')[0]!);
  return e;
}

/** Exact host or `*.domain` wildcard (which also matches the apex). */
export function hostAllowed(host: string, allowlist: readonly string[]): boolean {
  const h = normalizeHost(host);
  for (const raw of allowlist) {
    const e = normalizeAllowlistEntry(raw);
    if (!e) continue;
    if (e === '*') return true;
    if (e.startsWith('*.')) {
      const base = e.slice(2);
      if (h === base || h.endsWith(`.${base}`)) return true;
    } else if (h === e) {
      return true;
    }
  }
  return false;
}

/** localhost / loopback / RFC1918 / link-local (cloud metadata) / .local / .internal */
export function isPrivateHost(host: string): boolean {
  const h = normalizeHost(host);
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') || h.endsWith('.internal') || h === '[::1]' || h === '0.0.0.0') return true;
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (!m) return false;
  const a = Number(m[1]);
  const b = Number(m[2]);
  return a === 10 || a === 127 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31) || (a === 169 && b === 254) || a === 0;
}

export const DESTINATION_CAPABILITIES: readonly Capability[] = ['network', 'exec'];

/** Detector: tool_call phase; needs a non-empty `input.allowlist`. */
export function destination(input: DetectorInput): Finding[] {
  if (input.phase !== 'tool_call' || !input.call) return [];
  const allowlist = input.allowlist ?? [];
  if (!allowlist.length) return [];
  const call = input.call;
  const caps = call.capabilities ?? [];
  if (!caps.some((c) => DESTINATION_CAPABILITIES.includes(c))) return [];
  const refs = extractHosts(call.args);
  if (!refs.length) return [];
  const bad = refs.filter((r) => !hostAllowed(r.host, allowlist));
  if (!bad.length) return [];
  const hosts = [...new Set(bad.map((b) => b.host))];
  const dangerous = hosts.some((h) => isPrivateHost(h) || h.startsWith('xn--') || h.includes('.xn--'));
  const shown = allowlist.slice(0, 4).join(', ') + (allowlist.length > 4 ? ', …' : '');
  return [
    makeFinding(
      DETECTOR_DESTINATION,
      dangerous ? 'critical' : 'high',
      `${caps.includes('network') ? 'Network' : 'Exec'} call ${call.server}/${call.tool} targets non-allowlisted host${hosts.length > 1 ? 's' : ''} ${hosts.join(', ')} (allowlist: ${shown})`,
      bad.slice(0, 3).map((b) => `${b.path}: ${b.url ?? b.host}`).join('; '),
    ),
  ];
}
