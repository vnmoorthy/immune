'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import clsx from 'clsx';
import { RefreshCw, Search } from 'lucide-react';
import type { AttackFamily, Decision, Trace } from '@immune/core';
import { api, type TracesQuery } from '@/lib/api';
import { useImmuneEvents } from '@/lib/events';
import { ATTACK_FAMILIES, FAMILY_META, fmtMs, fmtTime, phaseOfTrace, traceSubject } from '@/lib/format';
import { PageHeader, Panel } from '@/components/ui/panel';
import { DecisionTag, LabelTag } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Empty } from '@/components/ui/misc';
import { TraceDrawer } from '@/components/trace-drawer';
import { ToolName } from '@/components/ui/tool-name';

const DECISIONS: Decision[] = ['allow', 'flag', 'block', 'quarantine'];
const LIMITS = [100, 200, 500, 1000];

const selectCls = 'focus-ring h-6 border border-line bg-surface-2 px-1.5 font-mono text-[11px] text-fg';

export function TracesExplorer() {
  const params = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();

  const [label, setLabel] = useState<TracesQuery['label']>((params.get('label') as TracesQuery['label']) ?? '');
  const [family, setFamily] = useState<AttackFamily | ''>((params.get('family') as AttackFamily | null) ?? '');
  const [decision, setDecision] = useState<Decision | ''>((params.get('decision') as Decision | null) ?? '');
  const [breached, setBreached] = useState(params.get('breached') === '1');
  const [q, setQ] = useState(params.get('q') ?? '');
  const [limit, setLimit] = useState(Number(params.get('limit')) || 200);
  const [auto, setAuto] = useState(false);

  const [rows, setRows] = useState<Trace[]>([]);
  const [total, setTotal] = useState(0);
  const [ms, setMs] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Trace | null>(null);
  const [newSince, setNewSince] = useState(0);
  const reqId = useRef(0);

  const load = useCallback(async () => {
    const id = ++reqId.current;
    setLoading(true);
    try {
      const r = await api.traces({ limit, label, family, decision, breached: breached || undefined, q: q || undefined });
      if (id !== reqId.current) return;
      setRows(r.traces);
      setTotal(r.total);
      setMs(r.ms);
      setError(null);
      setNewSince(0);
    } catch (e) {
      if (id !== reqId.current) return;
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      if (id === reqId.current) setLoading(false);
    }
  }, [limit, label, family, decision, breached, q]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (!auto) return;
    const id = setInterval(() => void load(), 4000);
    return () => clearInterval(id);
  }, [auto, load]);

  useImmuneEvents(() => setNewSince((n) => n + 1), ['trace']);

  // deep link: ?id= opens the drawer with that exact trace
  const focusId = params.get('id');
  useEffect(() => {
    if (!focusId) return;
    let cancelled = false;
    const local = rows.find((t) => t.id === focusId);
    if (local) {
      setSelected(local);
      return;
    }
    api
      .traces({ id: focusId, limit: 1 })
      .then((r) => {
        if (!cancelled && r.traces[0]) setSelected(r.traces[0]);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focusId]);

  const closeDrawer = () => {
    setSelected(null);
    if (focusId) router.replace(pathname);
  };

  return (
    <>
      <PageHeader
        title="Traces"
        meta={
          <>
            {total.toLocaleString()} match{total === 1 ? '' : 'es'} · showing {rows.length}
            {ms !== null ? ` · ${fmtMs(ms)}` : ''}
            {newSince ? <span className="text-flag"> · +{newSince} new on the wire</span> : null}
          </>
        }
        actions={
          <>
            <label className="flex items-center gap-1.5 font-mono text-[11px] text-fg-3">
              <input type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} className="accent-[#4c8dff]" /> auto 4s
            </label>
            <Button size="xs" mono variant={newSince ? 'primary' : 'default'} icon={<RefreshCw className={clsx('h-3 w-3', loading && 'animate-spin')} />} onClick={() => void load()}>
              refresh
            </Button>
          </>
        }
      />
      <Panel className="panel" flush>
        <div className="flex flex-wrap items-center gap-2 border-b border-line px-3 py-2">
          <div className="flex items-center border border-line">
            {(['', 'attack', 'benign'] as const).map((l) => (
              <button key={l} onClick={() => setLabel(l)} className={clsx('focus-ring h-6 px-2 font-mono text-[10.5px] uppercase tracking-[0.06em] transition-colors duration-150 ease-out', label === l ? 'bg-surface-3 text-fg' : 'text-fg-3 hover:text-fg-2')}>
                {l || 'all'}
              </button>
            ))}
          </div>
          <select value={family} onChange={(e) => setFamily(e.target.value as AttackFamily | '')} className={selectCls} aria-label="Family">
            <option value="">any family</option>
            {[...ATTACK_FAMILIES, 'benign' as const].map((f) => (
              <option key={f} value={f}>
                {FAMILY_META[f].label}
              </option>
            ))}
          </select>
          <select value={decision} onChange={(e) => setDecision(e.target.value as Decision | '')} className={selectCls} aria-label="Decision">
            <option value="">any decision</option>
            {DECISIONS.map((d) => (
              <option key={d} value={d}>
                {d}
              </option>
            ))}
          </select>
          <label className="flex items-center gap-1.5 font-mono text-[11px] text-fg-2">
            <input type="checkbox" checked={breached} onChange={(e) => setBreached(e.target.checked)} className="accent-[#e5484d]" /> breaches only
          </label>
          <div className="relative">
            <Search className="pointer-events-none absolute left-1.5 top-1/2 h-3 w-3 -translate-y-1/2 text-fg-3" />
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="search id · host · tool · text" className="focus-ring h-6 w-64 border border-line bg-surface-2 pl-6 pr-2 font-mono text-[11px] text-fg placeholder:text-fg-3" />
          </div>
          <select value={limit} onChange={(e) => setLimit(Number(e.target.value))} className={clsx(selectCls, 'ml-auto')} aria-label="Limit">
            {LIMITS.map((n) => (
              <option key={n} value={n}>
                limit {n}
              </option>
            ))}
          </select>
        </div>
        <div className={clsx('h-[calc(100vh-176px)] overflow-auto transition-opacity duration-150', loading && rows.length > 0 && 'opacity-60')}>
          {error ? (
            <Empty title="Query failed" hint={error} action={<Button size="xs" mono onClick={() => void load()}>retry</Button>} />
          ) : rows.length === 0 ? (
            <Empty title={loading ? 'Loading…' : 'No traces match'} hint={loading ? '/api/traces' : 'relax a filter, or flood the store from the command center'} />
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th className="w-[96px]">time</th>
                  <th className="w-[96px]">decision</th>
                  <th className="w-[70px]">label</th>
                  <th className="w-[150px]">family</th>
                  <th className="w-[96px]">variant</th>
                  <th className="w-[84px]">phase</th>
                  <th>server · tool</th>
                  <th className="num w-[72px]">findings</th>
                  <th className="w-[160px]">blocked by</th>
                  <th className="w-[150px]">id</th>
                  <th className="num w-[64px]">ms</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((t) => {
                  const subj = traceSubject(t);
                  return (
                    <tr key={t.id} onClick={() => setSelected(t)} className={clsx('h-7 cursor-pointer', t.breached && 'rail-breach bg-breach/[0.06] hover:!bg-breach/[0.1]', selected?.id === t.id && 'bg-surface-3')}>
                      <td className="mono-num text-fg-3">{fmtTime(t.ts)}</td>
                      <td>
                        <DecisionTag decision={t.decision} breached={t.breached} />
                      </td>
                      <td>
                        <LabelTag label={t.label} />
                      </td>
                      <td className={clsx('text-[12px]', t.label === 'benign' ? 'text-fg-3' : 'text-fg-2')}>{FAMILY_META[t.family]?.label ?? t.family}</td>
                      <td className="font-mono text-[11px] text-fg-3">{t.variant}</td>
                      <td className="font-mono text-[11px] text-fg-3">{phaseOfTrace(t)}</td>
                      <td className="max-w-[260px] truncate font-mono text-[11.5px] text-fg" title={`${subj.server} · ${subj.tool}`}>
                        <span className="text-fg-3">{subj.server}</span> · <ToolName name={subj.tool} />
                      </td>
                      <td className={clsx('num', t.findings.length ? 'text-fg-2' : 'text-fg-3')}>{t.findings.length}</td>
                      <td className="max-w-[160px] truncate font-mono text-[11px] text-fg-3" title={t.blockedBy}>
                        {t.blockedBy ?? ''}
                      </td>
                      <td className="font-mono text-[11px] text-fg-3">{t.id}</td>
                      <td className="num text-fg-3">{t.latencyMs < 10 ? t.latencyMs.toFixed(2) : fmtMs(t.latencyMs)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </Panel>
      <TraceDrawer trace={selected} onClose={closeDrawer} showExplorerLink={false} />
    </>
  );
}
