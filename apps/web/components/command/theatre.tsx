'use client';

import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import clsx from 'clsx';
import { motion } from 'framer-motion';
import { ChevronLeft, ChevronRight } from 'lucide-react';
import type { Remediation, RemediationStep } from '@immune/core';
import { api } from '@/lib/api';
import { useImmuneEvents } from '@/lib/events';
import { usePoll, useNow } from '@/lib/use-poll';
import { FAMILY_META, fmtMs, fmtTime, STEP_META, STEP_ORDER } from '@/lib/format';
import { Panel } from '@/components/ui/panel';
import { RemediationStatusTag, Tag } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Empty } from '@/components/ui/misc';
import { NumberTicker } from '@/components/ui/number-ticker';

function upsert(list: Remediation[], r: Remediation): Remediation[] {
  const i = list.findIndex((x) => x.id === r.id);
  if (i === -1) return [r, ...list];
  const next = list.slice();
  next[i] = r;
  return next;
}

function orderedSteps(r: Remediation): RemediationStep[] {
  const byName = new Map(r.steps.map((s) => [s.name, s]));
  return STEP_ORDER.map((name) => byName.get(name) ?? { name, status: 'pending' as const });
}

export function Theatre() {
  const poll = usePoll(() => api.remediations(), 10_000);
  const [list, setList] = useState<Remediation[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [follow, setFollow] = useState(true);
  const known = useRef(new Set<string>());

  useEffect(() => {
    if (!poll.data) return;
    setList((prev) => {
      let next = prev;
      for (const r of poll.data!) {
        const local = prev.find((x) => x.id === r.id);
        // keep the fresher of the two (SSE may be ahead of the poll)
        if (local && (local.finishedAt ?? 0) >= (r.finishedAt ?? 0) && local.steps.filter((s) => s.status !== 'pending').length >= r.steps.filter((s) => s.status !== 'pending').length) continue;
        next = upsert(next, r);
      }
      return next.slice().sort((a, b) => b.startedAt - a.startedAt);
    });
  }, [poll.data]);

  useImmuneEvents((e) => {
    const r = e.payload as Remediation;
    if (!r || typeof r !== 'object' || !('steps' in r)) return;
    setList((prev) => upsert(prev, r).sort((a, b) => b.startedAt - a.startedAt));
  }, ['remediation']);

  // auto-follow the newest remediation
  useEffect(() => {
    if (!list.length) return;
    const newest = list[0]!;
    const isNew = !known.current.has(newest.id);
    list.forEach((r) => known.current.add(r.id));
    if (follow || isNew) setSelectedId(newest.id);
  }, [list, follow]);

  const idx = Math.max(0, list.findIndex((r) => r.id === selectedId));
  const rem = list[idx];
  const running = rem?.status === 'running';
  const now = useNow(running ? 100 : 60_000);

  const nav = (delta: number) => {
    const target = list[idx + delta];
    if (!target) return;
    setFollow(false);
    setSelectedId(target.id);
  };

  return (
    <Panel
      title="Remediation theatre"
      meta={rem ? `${rem.id} · ${FAMILY_META[rem.family]?.label ?? rem.family}` : 'breach → immunity, step by step'}
      className="col-span-12 border-0 lg:col-span-5"
      flush
      actions={
        list.length > 1 ? (
          <>
            <Button size="xs" variant="ghost" onClick={() => nav(1)} disabled={idx >= list.length - 1} aria-label="Older">
              <ChevronLeft className="h-3.5 w-3.5" />
            </Button>
            <span className="mono-num text-[11px] text-fg-3">
              {list.length - idx}/{list.length}
            </span>
            <Button size="xs" variant="ghost" onClick={() => nav(-1)} disabled={idx <= 0} aria-label="Newer">
              <ChevronRight className="h-3.5 w-3.5" />
            </Button>
            {!follow ? (
              <Button size="xs" mono variant="ghost" onClick={() => { setFollow(true); setSelectedId(list[0]!.id); }}>
                latest
              </Button>
            ) : null}
          </>
        ) : null
      }
    >
      {!rem ? (
        <Empty
          className="h-full"
          title={poll.loading ? 'Loading…' : 'No remediation has run yet'}
          hint={poll.loading ? '/api/remediations' : 'mutate any family in the arena — the first breach starts the loop'}
        />
      ) : (
        <TheatreBody rem={rem} now={now} />
      )}
    </Panel>
  );
}

function TheatreBody({ rem, now }: { rem: Remediation; now: number }) {
  const steps = orderedSteps(rem);
  const finished = steps.filter((s) => s.status === 'done' || s.status === 'skipped' || s.status === 'failed').length;
  const runningIdx = steps.findIndex((s) => s.status === 'running');
  const progress = Math.min(1, (finished + (runningIdx >= 0 ? 0.5 : 0)) / steps.length);
  const elapsed = (rem.finishedAt ?? now) - rem.startedAt;
  const failedStep = steps.find((s) => s.status === 'failed');

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-3 border-b border-line px-3 py-2 font-mono text-[11px] text-fg-3">
        <RemediationStatusTag status={rem.status} />
        <span>
          breach{' '}
          <Link href={`/traces?id=${encodeURIComponent(rem.breachTraceId)}`} className="text-info hover:underline">
            {rem.breachTraceId}
          </Link>
        </span>
        <span>started {fmtTime(rem.startedAt)}</span>
        <span className="ml-auto tabular text-fg-2">{fmtMs(elapsed)}</span>
      </div>

      <ol className="relative my-2 ml-[18px] mr-3 flex-1 border-l border-line pl-4">
        <motion.span
          aria-hidden
          className={clsx('absolute -left-px top-0 w-px', rem.status === 'failed' ? 'bg-breach' : 'bg-immune')}
          initial={false}
          animate={{ height: `${progress * 100}%` }}
          transition={{ duration: 0.18, ease: [0, 0, 0.2, 1] }}
        />
        {steps.map((s, i) => (
          <StepRow key={s.name} step={s} index={i} now={now} />
        ))}
      </ol>

      <div className="border-t border-line px-3 py-2">
        {rem.status === 'immune' ? (
          <div className="flex items-end justify-between gap-3">
            <div>
              <Tag tone="immune" bold dot>
                immune
              </Tag>
              <div className="mono-num mt-1 text-[28px] font-light leading-none text-immune">
                <NumberTicker value={(rem.timeToImmunityMs ?? elapsed) / 1000} format={(v) => v.toFixed(3)} /> <span className="text-[14px] text-fg-3">s</span>
              </div>
            </div>
            <div className="flex flex-col items-end gap-0.5 font-mono text-[10.5px] text-fg-3">
              {rem.ruleId ? (
                <Link href={`/antibodies?rule=${encodeURIComponent(rem.ruleId)}`} className="hover:text-fg">
                  antibody {rem.ruleId}
                </Link>
              ) : null}
              {rem.receiptId ? (
                <Link href={`/receipts?id=${encodeURIComponent(rem.receiptId)}`} className="hover:text-fg">
                  receipt {rem.receiptId}
                </Link>
              ) : null}
              {rem.rulingId ? (
                <Link href={`/rulings?id=${encodeURIComponent(rem.rulingId)}`} className="hover:text-fg">
                  ruling {rem.rulingId}
                </Link>
              ) : null}
            </div>
          </div>
        ) : rem.status === 'failed' ? (
          <div className="flex items-center justify-between gap-3">
            <Tag tone="breach" bold dot>
              failed{failedStep ? ` at ${failedStep.name}` : ''}
            </Tag>
            <span className="truncate font-mono text-[11px] text-fg-3" title={failedStep?.detail}>
              {failedStep?.detail ?? 'see step detail'}
            </span>
          </div>
        ) : (
          <div className="flex items-center justify-between gap-3 font-mono text-[11px] text-fg-3">
            <span className="flex items-center gap-2">
              <span className="h-1.5 w-1.5 animate-live-dot rounded-full bg-info" />
              {runningIdx >= 0 ? STEP_META[steps[runningIdx]!.name].verb : 'queued'}
            </span>
            <span className="tabular">{fmtMs(elapsed)} elapsed</span>
          </div>
        )}
      </div>
    </div>
  );
}

function StepRow({ step, index, now }: { step: RemediationStep; index: number; now: number }) {
  const meta = STEP_META[step.name];
  const dur = step.startedAt ? (step.finishedAt ?? now) - step.startedAt : null;
  const marker =
    step.status === 'done'
      ? 'bg-immune border-immune'
      : step.status === 'running'
        ? 'bg-info border-info animate-live-dot'
        : step.status === 'failed'
          ? 'bg-breach border-breach'
          : step.status === 'skipped'
            ? 'border-flag bg-surface-1'
            : 'border-fg-3 bg-surface-1';
  const active = step.status !== 'pending';
  return (
    <motion.li
      className="relative py-1.5"
      initial={false}
      animate={{ opacity: active ? 1 : 0.45 }}
      transition={{ duration: 0.15, ease: [0, 0, 0.2, 1] }}
    >
      <span className={clsx('absolute -left-[21px] top-[11px] h-2 w-2 rounded-full border', marker)} />
      <div className="flex items-baseline justify-between gap-3">
        <div className="flex items-baseline gap-2">
          <span className="mono-num text-[10px] text-fg-3">{String(index + 1).padStart(2, '0')}</span>
          <span className={clsx('text-[12.5px]', active ? 'text-fg' : 'text-fg-2')}>{meta.label}</span>
          <span className="hidden font-mono text-[10px] uppercase tracking-[0.08em] text-fg-3 2xl:inline">{meta.metaphor}</span>
        </div>
        <span className={clsx('mono-num shrink-0 text-[11px]', step.status === 'failed' ? 'text-breach' : step.status === 'skipped' ? 'text-flag' : 'text-fg-3')}>
          {step.status === 'skipped' ? 'skipped' : step.status === 'pending' ? '' : dur !== null ? fmtMs(dur) : ''}
        </span>
      </div>
      {step.status === 'running' && !step.detail ? (
        <div className="font-mono text-[11px] text-info">{meta.verb}…</div>
      ) : step.detail ? (
        <div className={clsx('break-words font-mono text-[11px] leading-snug', step.status === 'failed' ? 'text-breach' : 'text-fg-3')}>{step.detail}</div>
      ) : null}
    </motion.li>
  );
}
