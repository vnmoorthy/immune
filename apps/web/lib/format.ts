import type { AttackFamily, Decision, RemediationStepName, Severity } from '@immune/core';

export function fmtMs(ms: number | null | undefined, opts: { precision?: number } = {}): string {
  if (ms === null || ms === undefined || Number.isNaN(ms)) return '—';
  if (ms < 1) return `${ms.toFixed(opts.precision ?? 2)} ms`;
  if (ms < 1000) return `${Math.round(ms)} ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(opts.precision ?? 2)} s`;
  const m = Math.floor(ms / 60_000);
  const s = Math.round((ms % 60_000) / 1000);
  return `${m}m ${s}s`;
}

export function fmtPct(x: number | null | undefined, digits = 1): string {
  if (x === null || x === undefined || Number.isNaN(x)) return '—';
  return `${(x * 100).toFixed(digits)}%`;
}

export function fmtInt(n: number | null | undefined): string {
  if (n === null || n === undefined || Number.isNaN(n)) return '—';
  return new Intl.NumberFormat('en-US').format(n);
}

export function shortId(id: string | undefined, keep = 6): string {
  if (!id) return '—';
  const [prefix, rest] = id.split('_');
  if (!rest) return id.length > keep + 2 ? `${id.slice(0, keep)}…` : id;
  return `${prefix}_${rest.slice(0, keep)}`;
}

export function fmtTime(ts: number | undefined): string {
  if (!ts) return '—';
  const d = new Date(ts);
  const hh = String(d.getHours()).padStart(2, '0');
  const mm = String(d.getMinutes()).padStart(2, '0');
  const ss = String(d.getSeconds()).padStart(2, '0');
  const ms = String(d.getMilliseconds()).padStart(3, '0');
  return `${hh}:${mm}:${ss}.${ms}`;
}

export function fmtDateTime(ts: number | undefined): string {
  if (!ts) return '—';
  const d = new Date(ts);
  return d.toLocaleString('en-US', {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

export function timeAgo(ts: number | undefined, now = Date.now()): string {
  if (!ts) return '—';
  const diff = Math.max(0, now - ts);
  if (diff < 5_000) return 'just now';
  if (diff < 60_000) return `${Math.floor(diff / 1000)}s ago`;
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
}

export interface FamilyMeta {
  label: string;
  short: string;
  description: string;
  /** what the gullible agent is asked to do in this scenario */
  scenario: string;
}

export const ATTACK_FAMILIES: Exclude<AttackFamily, 'benign'>[] = [
  'poisoned_description',
  'result_injection',
  'secret_exfil',
  'rug_pull',
  'homoglyph_spoof',
  'indirect_fetch',
];

export const FAMILY_META: Record<AttackFamily, FamilyMeta> = {
  poisoned_description: {
    label: 'Poisoned description',
    short: 'Tool poisoning',
    description: 'Hidden instructions inside a tool description steer the agent before it ever calls anything.',
    scenario: 'Agent lists tools on a freshly installed MCP server.',
  },
  result_injection: {
    label: 'Result injection',
    short: 'Result hijack',
    description: 'A tool result carries instructions that the agent obediently follows on the next step.',
    scenario: 'Agent reads a shared document and acts on what it says.',
  },
  secret_exfil: {
    label: 'Secret exfiltration',
    short: 'Secret exfil',
    description: 'The agent is coaxed into posting credentials to an attacker-controlled destination.',
    scenario: 'Agent fetches API credentials, then is told where to send them.',
  },
  rug_pull: {
    label: 'Rug pull',
    short: 'Rug pull',
    description: 'A trusted tool definition silently changes after it was pinned and approved.',
    scenario: 'Agent re-lists tools; a known tool now has a different description.',
  },
  homoglyph_spoof: {
    label: 'Homoglyph spoof',
    short: 'Look-alike tool',
    description: 'A look-alike tool name (Cyrillic, zero-width) shadows a trusted one.',
    scenario: 'Agent picks a tool by name — the wrong one answers.',
  },
  indirect_fetch: {
    label: 'Indirect fetch',
    short: 'Indirect injection',
    description: 'Fetched web content carries an injection that redirects the agent downstream.',
    scenario: 'Agent fetches a URL for a summary and obeys what the page says.',
  },
  benign: {
    label: 'Benign traffic',
    short: 'Benign',
    description: 'Legitimate sessions: customer lookups, reports, webhooks to allowed hosts.',
    scenario: 'Normal operations.',
  },
};

export function familyLabel(f: AttackFamily | string): string {
  return (FAMILY_META as Record<string, FamilyMeta>)[f]?.label ?? f;
}

export type Tone = 'immune' | 'breach' | 'flag' | 'quarantine' | 'neutral' | 'info';

export function decisionTone(decision: Decision, breached?: boolean): Tone {
  if (breached) return 'breach';
  switch (decision) {
    case 'allow':
      return 'immune';
    case 'flag':
      return 'flag';
    case 'block':
      return 'breach';
    case 'quarantine':
      return 'quarantine';
    default:
      return 'neutral';
  }
}

export function severityTone(s: Severity): Tone {
  switch (s) {
    case 'critical':
    case 'high':
      return 'breach';
    case 'medium':
      return 'flag';
    default:
      return 'neutral';
  }
}

export const STEP_META: Record<RemediationStepName, { label: string; verb: string; metaphor: string }> = {
  trace_captured: { label: 'Trace captured', verb: 'Capturing antigen', metaphor: 'Antigen' },
  antibody_drafted: { label: 'Antibody drafted', verb: 'Synthesizing antibody', metaphor: 'Antibody' },
  replay_proven: { label: 'Replay proven', verb: 'Replaying against corpus', metaphor: 'Proof' },
  semgrep_rescan: { label: 'Semgrep rescan', verb: 'Scanning server source', metaphor: 'Proof' },
  receipt_signed: { label: 'Receipt signed', verb: 'Signing receipt', metaphor: 'Receipt' },
  ruling_published: { label: 'Ruling published', verb: 'Publishing precedent', metaphor: 'Ruling' },
  immunity_verified: { label: 'Immunity verified', verb: 'Replaying the identical attack', metaphor: 'Immunity' },
};

export const STEP_ORDER: RemediationStepName[] = [
  'trace_captured',
  'antibody_drafted',
  'replay_proven',
  'semgrep_rescan',
  'receipt_signed',
  'ruling_published',
  'immunity_verified',
];

export function stepDuration(s: { startedAt?: number; finishedAt?: number }, now = Date.now()): number | null {
  if (!s.startedAt) return null;
  return (s.finishedAt ?? now) - s.startedAt;
}

export function clamp(n: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, n));
}

export function hostOf(url: unknown): string | null {
  if (typeof url !== 'string') return null;
  try {
    return new URL(url).host;
  } catch {
    return null;
  }
}

/** Pull any URL-looking string out of a call's args for display. */
export function firstUrlInArgs(args: Record<string, unknown> | undefined): string | null {
  if (!args) return null;
  for (const v of Object.values(args)) {
    if (typeof v === 'string' && /^https?:\/\//i.test(v)) return v;
  }
  return null;
}

export function phaseOfTrace(t: { toolDef?: unknown; result?: unknown; attemptedCall?: unknown }): 'tool_def' | 'tool_result' | 'tool_call' | '—' {
  if (t.attemptedCall) return 'tool_call';
  if (t.result) return 'tool_result';
  if (t.toolDef) return 'tool_def';
  return '—';
}

export function traceSubject(t: {
  toolDef?: { server: string; name: string };
  result?: { server: string; tool: string };
  attemptedCall?: { server: string; tool: string };
}): { server: string; tool: string } {
  if (t.attemptedCall) return { server: t.attemptedCall.server, tool: t.attemptedCall.tool };
  if (t.result) return { server: t.result.server, tool: t.result.tool };
  if (t.toolDef) return { server: t.toolDef.server, tool: t.toolDef.name };
  return { server: '—', tool: '—' };
}
