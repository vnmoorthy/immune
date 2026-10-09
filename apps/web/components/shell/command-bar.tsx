'use client';

import { useEffect, useRef, useState } from 'react';
import clsx from 'clsx';
import { RotateCcw } from 'lucide-react';
import { api, isFixtureMode, subscribeFixtureMode, type StatusResponse } from '@/lib/api';
import { fmtMs } from '@/lib/format';
import { useEventsConnection, useImmuneEvents } from '@/lib/events';
import { usePoll } from '@/lib/use-poll';
import { Dot } from '@/components/ui/badge';
import { useToast } from '@/components/ui/toast';

type DotState = 'on' | 'off' | 'warn';

function Readout({ state, label, value, title, valueClass }: { state: DotState; label: string; value: string; title?: string; valueClass?: string }) {
  return (
    <div className="flex h-10 shrink-0 items-center gap-2 whitespace-nowrap" title={title}>
      <Dot state={state} />
      <span className="text-fg-3">{label}</span>
      <span className={clsx('text-fg', valueClass)}>{value}</span>
    </div>
  );
}

function readouts(s: StatusResponse | undefined) {
  if (!s) {
    return [
      { state: 'off' as DotState, label: 'STORE', value: '…' },
      { state: 'off' as DotState, label: 'SEMGREP', value: '…' },
      { state: 'off' as DotState, label: 'LLM', value: '…' },
      { state: 'off' as DotState, label: 'GUILD', value: '…' },
      { state: 'off' as DotState, label: 'SENSO', value: '…' },
      { state: 'off' as DotState, label: 'RECEIPT KEY', value: '…' },
    ];
  }
  const storeVal =
    s.store.kind === 'clickhouse'
      ? `clickhouse ${s.store.latencyMs !== null ? fmtMs(s.store.latencyMs) : ''}`.trim()
      : 'memory';
  return [
    {
      state: (s.store.kind === 'clickhouse' ? 'on' : 'warn') as DotState,
      label: 'STORE',
      value: storeVal,
      title: s.clickhouse.connected
        ? `ClickHouse ${s.clickhouse.version ?? ''} at ${s.clickhouse.url ?? ''} · ${s.clickhouse.rows ?? s.store.rows} rows`
        : `ClickHouse unreachable (${s.clickhouse.detail ?? 'no ping'}) — in-memory store, ${s.store.rows} rows`,
    },
    {
      state: (s.semgrep.installed ? 'on' : 'off') as DotState,
      label: 'SEMGREP',
      value: s.semgrep.installed ? (s.semgrep.version ?? 'installed') : 'absent',
      title: s.semgrep.detail ?? (s.semgrep.installed ? 'semgrep on PATH — rescans run' : 'semgrep not on PATH — rescans skipped'),
    },
    {
      state: (s.llm.provider !== 'none' ? 'on' : 'off') as DotState,
      label: 'LLM',
      value: s.llm.provider === 'none' ? 'none' : `${s.llm.provider}${s.llm.model ? ` ${s.llm.model}` : ''}`,
      title: s.llm.detail ?? 'LLM refiner is optional — synthesis is deterministic without it',
    },
    { state: (s.guild.configured ? 'on' : 'off') as DotState, label: 'GUILD', value: s.guild.configured ? 'configured' : 'local', title: s.guild.detail },
    {
      state: (s.senso.authenticated ?? s.senso.configured ? 'on' : 'off') as DotState,
      label: 'SENSO',
      value: s.senso.authenticated ?? s.senso.configured ? `senso ${s.senso.org ?? 'authenticated'}` : s.senso.installed ? 'senso not logged in' : 'senso not installed',
      title: s.senso.detail,
    },
    {
      state: (s.receiptSecretIsDefault ? 'warn' : 'on') as DotState,
      label: 'RECEIPT KEY',
      value: s.receiptSecretIsDefault ? 'default!' : 'custom',
      title: s.receiptSecretIsDefault ? 'IMMUNE_RECEIPT_SECRET not set — receipts are signed with the dev secret' : 'IMMUNE_RECEIPT_SECRET is set',
      valueClass: s.receiptSecretIsDefault ? '!text-flag' : undefined,
    },
  ];
}

function Clock() {
  const [t, setT] = useState<string | null>(null);
  useEffect(() => {
    const tick = () => setT(new Date().toISOString().slice(11, 19));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);
  return (
    <span className="tabular text-fg-2" suppressHydrationWarning>
      {t ?? '--:--:--'} <span className="text-fg-3">UTC</span>
    </span>
  );
}

export function CommandBar() {
  const status = usePoll(() => api.status(), 15_000);
  const { connected, eventsPerSec } = useEventsConnection();
  const { toast } = useToast();
  const [fixtures, setFixtures] = useState(false);
  useEffect(() => {
    setFixtures(isFixtureMode());
    return subscribeFixtureMode(setFixtures);
  }, []);
  const [arm, setArm] = useState(false);
  const [resetting, setResetting] = useState(false);
  const armTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // metrics events carry store latency changes; refresh status cheaply after remediations
  useImmuneEvents(() => void status.refresh(), ['remediation']);

  const onReset = async () => {
    if (!arm) {
      setArm(true);
      if (armTimer.current) clearTimeout(armTimer.current);
      armTimer.current = setTimeout(() => setArm(false), 3000);
      return;
    }
    setArm(false);
    setResetting(true);
    try {
      const r = await api.reset();
      toast({
        title: 'Engine reset',
        description: r.seeded ? `store cleared · re-seeded ${r.seeded.benign.toLocaleString()} benign + ${r.seeded.attacks} attacks in ${fmtMs(r.ms)}` : `store cleared in ${fmtMs(r.ms)}`,
        tone: 'info',
      });
      void status.refresh();
    } catch (e) {
      toast({ title: 'Reset failed', description: e instanceof Error ? e.message : String(e), tone: 'breach' });
    } finally {
      setResetting(false);
    }
  };

  return (
    <header className="sticky top-0 z-40 flex h-10 items-center gap-5 overflow-x-auto border-b border-line bg-surface-1 px-3 font-mono text-[11px]">
      {readouts(status.data).map((r) => (
        <Readout key={r.label} {...r} />
      ))}
      {status.error ? <span className="text-breach">status: {status.error.message}</span> : null}
      <div className="ml-auto flex shrink-0 items-center gap-5">
        {fixtures ? (
          <div className="flex items-center gap-2 text-breach" title="The API did not answer — showing fixture data until it does">
            <Dot state="bad" pulse />
            <span className="font-semibold">OFFLINE · FIXTURES</span>
          </div>
        ) : (
          <div className="flex items-center gap-2" title={connected ? 'SSE connected — /api/events' : 'SSE reconnecting'}>
            <Dot state={connected ? 'on' : 'off'} pulse={connected} />
            <span className="text-fg-3">LIVE</span>
            <span className="tabular text-fg">{connected ? `${eventsPerSec.toFixed(1)}/s` : 'offline'}</span>
          </div>
        )}
        <Clock />
        <span className="text-fg-3">v{status.data?.version ?? '…'}</span>
        <button
          onClick={onReset}
          disabled={resetting}
          className={clsx(
            'focus-ring flex h-6 items-center gap-1.5 border px-2 text-[10.5px] uppercase tracking-[0.06em] transition-colors duration-150 ease-out disabled:opacity-50',
            arm ? 'border-breach/60 bg-breach/10 text-breach' : 'border-line text-fg-2 hover:border-line-strong hover:text-fg',
          )}
          title="Clear the store, rules, receipts and rulings; re-seed the corpus"
        >
          <RotateCcw className={clsx('h-3 w-3', resetting && 'animate-spin')} />
          {resetting ? 'resetting' : arm ? 'confirm reset' : 'reset'}
        </button>
      </div>
    </header>
  );
}
