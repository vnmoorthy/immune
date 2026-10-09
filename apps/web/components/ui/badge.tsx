import clsx from 'clsx';
import type { ReactNode } from 'react';
import type { Decision, Rule, Remediation, Severity } from '@immune/core';
import { decisionTone, severityTone, type Tone } from '@/lib/format';

export const TONE_TEXT: Record<Tone, string> = {
  immune: 'text-immune',
  breach: 'text-breach',
  flag: 'text-flag',
  quarantine: 'text-breach',
  info: 'text-info',
  neutral: 'text-fg-2',
};

export const TONE_BG: Record<Tone, string> = {
  immune: 'bg-immune',
  breach: 'bg-breach',
  flag: 'bg-flag',
  quarantine: 'bg-breach',
  info: 'bg-info',
  neutral: 'bg-fg-3',
};

export const TONE_HEX: Record<Tone, string> = {
  immune: '#3ecf8e',
  breach: '#e5484d',
  flag: '#d9a21b',
  quarantine: '#e5484d',
  info: '#4c8dff',
  neutral: '#6b7075',
};

/** 6px status dot. */
export function Dot({ state, pulse, className }: { state: 'on' | 'off' | 'warn' | 'bad' | Tone; pulse?: boolean; className?: string }) {
  const color =
    state === 'on' ? 'bg-immune' : state === 'warn' ? 'bg-flag' : state === 'bad' ? 'bg-breach' : state === 'off' ? 'bg-fg-3' : TONE_BG[state as Tone];
  return <span className={clsx('inline-block h-1.5 w-1.5 shrink-0 rounded-full', color, pulse && 'animate-live-dot', className)} />;
}

/**
 * Semantic text tag: mono, uppercase, coloured text only (no fills).
 * `boxed` adds a hairline border for table cells.
 */
export function Tag({
  tone = 'neutral',
  children,
  dot,
  boxed,
  bold,
  className,
  title,
}: {
  tone?: Tone;
  children: ReactNode;
  dot?: boolean;
  boxed?: boolean;
  bold?: boolean;
  className?: string;
  title?: string;
}) {
  return (
    <span
      title={title}
      className={clsx(
        'inline-flex items-center gap-1.5 whitespace-nowrap font-mono text-[10.5px] uppercase leading-4 tracking-[0.06em]',
        bold ? 'font-semibold' : 'font-medium',
        TONE_TEXT[tone],
        boxed && 'border border-line px-1.5',
        className,
      )}
    >
      {dot ? <Dot state={tone} /> : null}
      {children}
    </span>
  );
}

export function DecisionTag({ decision, breached, boxed, className }: { decision: Decision; breached?: boolean; boxed?: boolean; className?: string }) {
  const tone = decisionTone(decision, breached);
  return (
    <Tag tone={tone} boxed={boxed} bold={!!breached} className={className} title={breached ? 'attack allowed — oracle says this must be blocked' : decision}>
      {breached ? 'BREACH' : decision}
    </Tag>
  );
}

export function SeverityTag({ severity }: { severity: Severity }) {
  return <Tag tone={severityTone(severity)}>{severity}</Tag>;
}

export function RuleStatusTag({ status }: { status: Rule['status'] }) {
  const tone: Tone = status === 'promoted' ? 'immune' : status === 'candidate' ? 'flag' : 'neutral';
  return (
    <Tag tone={tone} dot>
      {status}
    </Tag>
  );
}

export function OriginTag({ origin }: { origin: Rule['origin'] }) {
  return <Tag tone={origin === 'llm' ? 'info' : 'neutral'}>{origin}</Tag>;
}

export function RemediationStatusTag({ status }: { status: Remediation['status'] }) {
  const tone: Tone = status === 'immune' ? 'immune' : status === 'failed' ? 'breach' : 'flag';
  return (
    <Tag tone={tone} dot bold={status !== 'running'}>
      {status === 'running' ? 'remediating' : status}
    </Tag>
  );
}

export function LabelTag({ label }: { label: 'attack' | 'benign' }) {
  return <Tag tone="neutral">{label}</Tag>;
}
