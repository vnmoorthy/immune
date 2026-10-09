'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import clsx from 'clsx';
import { Pause, Play } from 'lucide-react';
import type { Trace } from '@immune/core';
import { api } from '@/lib/api';
import { useImmuneEvents } from '@/lib/events';
import { FAMILY_META, fmtMs, fmtTime, phaseOfTrace, traceSubject } from '@/lib/format';
import { Panel } from '@/components/ui/panel';
import { DecisionTag } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Empty } from '@/components/ui/misc';
import { TraceDrawer } from '@/components/trace-drawer';
import { ToolName } from '@/components/ui/tool-name';

type Filter = 'all' | 'attack' | 'benign' | 'breach';
const FILTERS: { id: Filter; label: string }[] = [
  { id: 'all', label: 'all' },
  { id: 'attack', label: 'attacks' },
  { id: 'benign', label: 'benign' },
  { id: 'breach', label: 'breaches' },
];
const CAP = 400;

export function LiveWire() {
  const [rows, setRows] = useState<Trace[]>([]);
  const [filter, setFilter] = useState<Filter>('all');
  const [paused, setPaused] = useState(false);
  const [buffered, setBuffered] = useState(0);
  const [selected, setSelected] = useState<Trace | null>(null);
  const [loaded, setLoaded] = useState(false);
  const pausedRef = useRef(false);
  const bufferRef = useRef<Trace[]>([]);

  // pure updater (StrictMode double-invokes it) — dedupe against prev only
  const push = useCallback((incoming: Trace[]) => {
    setRows((prev) => {
      const ids = new Set(prev.map((t) => t.id));
      const fresh = incoming.filter((t) => !ids.has(t.id));
      if (!fresh.length) return prev;
      const next = [...fresh.slice().sort((a, b) => b.ts - a.ts), ...prev];
      return next.length > CAP ? next.slice(0, CAP) : next;
    });
  }, []);

  useEffect(() => {
    let cancelled = false;
    api
      .traces({ limit: 120 })
      .then((r) => {
        if (!cancelled) push(r.traces);
      })
      .catch(() => undefined)
      .finally(() => {
        if (!cancelled) setLoaded(true);
      });
    return () => {
      cancelled = true;
    };
  }, [push]);

  useImmuneEvents((e) => {
    const t = e.payload as Trace;
    if (!t || typeof t !== 'object' || !('id' in t)) return;
    if (pausedRef.current) {
      bufferRef.current.unshift(t);
      setBuffered(bufferRef.current.length);
      return;
    }
    push([t]);
  }, ['trace']);

  const togglePause = () => {
    const next = !paused;
    pausedRef.current = next;
    setPaused(next);
    if (!next && bufferRef.current.length) {
      push(bufferRef.current);
      bufferRef.current = [];
      setBuffered(0);
    }
  };

  const visible = rows.filter((t) => {
    if (filter === 'all') return true;
    if (filter === 'breach') return t.breached;
    return t.label === filter;
  });

  return (
    <Panel
      title="Live wire"
      meta={`${visible.length} shown · newest first${paused && buffered ? ` · +${buffered} buffered` : ''}`}
      className="col-span-12 border-0 lg:col-span-8"
      flush
      actions={
        <>
          <div className="flex items-center border border-line">
            {FILTERS.map((f) => (
              <button
                key={f.id}
                onClick={() => setFilter(f.id)}
                className={clsx(
                  'focus-ring h-6 px-2 font-mono text-[10.5px] uppercase tracking-[0.06em] transition-colors duration-150 ease-out',
                  filter === f.id ? 'bg-surface-3 text-fg' : 'text-fg-3 hover:text-fg-2',
                )}
              >
                {f.label}
              </button>
            ))}
          </div>
          <Button size="xs" mono variant={paused ? 'flag' : 'ghost'} icon={paused ? <Play className="h-3 w-3" /> : <Pause className="h-3 w-3" />} onClick={togglePause}>
            {paused ? 'resume' : 'pause'}
          </Button>
        </>
      }
    >
      <div className="h-[420px] overflow-y-auto">
        {visible.length === 0 ? (
          <Empty
            title={loaded ? 'No events on the wire' : 'Connecting…'}
            hint={loaded ? 'launch an attack in the arena or send a benign burst' : '/api/traces'}
          />
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th className="w-[92px]">time</th>
                <th className="w-[96px]">decision</th>
                <th className="w-[140px]">family</th>
                <th className="w-[80px]">phase</th>
                <th>server · tool</th>
                <th className="w-[150px]">blocked by</th>
                <th>citation</th>
                <th className="num w-[64px]">ms</th>
              </tr>
            </thead>
            <tbody>
              {visible.map((t) => {
                const subj = traceSubject(t);
                return (
                  <tr
                    key={t.id}
                    onClick={() => setSelected(t)}
                    className={clsx('h-7 cursor-pointer animate-row-in', t.breached && 'rail-breach bg-breach/[0.06] hover:!bg-breach/[0.1]')}
                  >
                    <td className="mono-num text-fg-3">{fmtTime(t.ts)}</td>
                    <td>
                      <DecisionTag decision={t.decision} breached={t.breached} />
                    </td>
                    <td className={clsx('truncate text-[12px]', t.label === 'benign' ? 'text-fg-3' : 'text-fg-2')}>{FAMILY_META[t.family]?.short ?? t.family}</td>
                    <td className="font-mono text-[11px] text-fg-3">{phaseOfTrace(t)}</td>
                    <td className="max-w-[220px] truncate font-mono text-[11.5px] text-fg" title={`${subj.server} · ${subj.tool}`}>
                      <span className="text-fg-3">{subj.server}</span> · <ToolName name={subj.tool} />
                    </td>
                    <td className="max-w-[150px] truncate font-mono text-[11px] text-fg-3" title={t.blockedBy}>
                      {t.blockedBy ?? ''}
                    </td>
                    <td className="max-w-[260px] truncate text-[11.5px] text-fg-2" title={t.citation}>
                      {t.citation ?? ''}
                    </td>
                    <td className="num text-fg-3">{t.latencyMs < 10 ? t.latencyMs.toFixed(2) : fmtMs(t.latencyMs)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
      <TraceDrawer trace={selected} onClose={() => setSelected(null)} />
    </Panel>
  );
}
