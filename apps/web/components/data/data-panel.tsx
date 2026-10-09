'use client';

import { useEffect, useState } from 'react';
import clsx from 'clsx';
import { Play, RefreshCw } from 'lucide-react';
import { api, type NamedQueryResult } from '@/lib/api';
import { usePoll } from '@/lib/use-poll';
import { fmtInt, fmtMs } from '@/lib/format';
import { PageHeader, Panel } from '@/components/ui/panel';
import { Dot, Tag } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { CodeBlock } from '@/components/ui/code-block';
import { Empty } from '@/components/ui/misc';
import { FamilyChart, TimelineChart } from './charts';

function latencyState(ms: number): 'on' | 'warn' | 'bad' {
  return ms < 50 ? 'on' : ms < 250 ? 'warn' : 'bad';
}

function fmtCell(v: unknown): string {
  if (v === null || v === undefined) return '';
  if (typeof v === 'number') {
    if (Number.isInteger(v)) return Math.abs(v) >= 1e11 ? String(v) : v.toLocaleString('en-US'); // epoch-ish values stay raw
    return v.toLocaleString('en-US', { maximumFractionDigits: 3 });
  }
  if (typeof v === 'string') return v;
  return JSON.stringify(v);
}

function QueryCard({ q }: { q: NamedQueryResult }) {
  const cols = q.rows.length ? Object.keys(q.rows[0]!) : [];
  const numeric = new Set(cols.filter((c) => q.rows.every((r) => typeof r[c] === 'number' || r[c] === null)));
  return (
    <Panel
      title={q.name}
      meta={`${q.rows.length} row${q.rows.length === 1 ? '' : 's'}`}
      className="border-0"
      flush
      actions={
        <span className="flex items-center gap-1.5 font-mono text-[11px]">
          <Dot state={q.error ? 'bad' : latencyState(q.ms)} />
          <span className={clsx('tabular', q.error ? 'text-breach' : 'text-fg')}>{q.error ? 'error' : fmtMs(q.ms)}</span>
        </span>
      }
    >
      <div className="border-b border-line p-2">
        <CodeBlock code={q.sql} language="sql" title="sql" maxHeight={160} />
      </div>
      <div className="max-h-[260px] overflow-auto">
        {q.error ? (
          <Empty title="Query failed" hint={q.error} />
        ) : q.rows.length === 0 ? (
          <Empty title="No rows" hint="flood the store from the command center" />
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                {cols.map((c) => (
                  <th key={c} className={clsx(numeric.has(c) && 'num')}>
                    {c}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {q.rows.map((r, i) => (
                <tr key={i} className="h-7">
                  {cols.map((c) => (
                    <td key={c} className={clsx(numeric.has(c) ? 'num text-fg' : 'font-mono text-[11.5px] text-fg-2')}>
                      {fmtCell(r[c])}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </Panel>
  );
}

export function DataPanel() {
  const [auto, setAuto] = useState(false);
  const poll = usePoll(() => api.clickhouseQueries(), auto ? 10_000 : 0, [auto]);
  const d = poll.data;
  const [ranAt, setRanAt] = useState<number | null>(null);
  useEffect(() => {
    if (poll.lastUpdated) setRanAt(poll.lastUpdated);
  }, [poll.lastUpdated]);

  const bucketSec = d && d.timeline.length > 1 ? Math.max(1, Math.round((d.timeline[1]!.bucket - d.timeline[0]!.bucket) / 1000)) : 60;

  return (
    <>
      <PageHeader
        title="Data"
        meta={
          d ? (
            <>
              {d.store === 'clickhouse' ? (
                <>
                  clickhouse {d.version ?? ''} · {d.url ?? ''} · {fmtInt(d.rows)} rows
                </>
              ) : (
                <>
                  memory store · {fmtInt(d.rows)} rows · <span className="text-flag">clickhouse unreachable — SQL shown is what ClickHouse would run</span>
                </>
              )}
              {' · '}
              {d.queries.length} queries in {fmtMs(d.totalMs)}
              {ranAt ? ` · ran ${new Date(ranAt).toISOString().slice(11, 19)}Z` : ''}
            </>
          ) : undefined
        }
        actions={
          <>
            <label className="flex items-center gap-1.5 font-mono text-[11px] text-fg-3">
              <input type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} className="accent-[#4c8dff]" /> auto 10s
            </label>
            <Button size="xs" mono variant="primary" icon={poll.loading ? <RefreshCw className="h-3 w-3 animate-spin" /> : <Play className="h-3 w-3" />} onClick={() => void poll.refresh()} disabled={poll.loading}>
              run queries
            </Button>
          </>
        }
      />
      {poll.error && !d ? (
        <Panel className="panel">
          <Empty title="Queries failed" hint={poll.error.message} action={<Button size="xs" mono onClick={() => void poll.refresh()}>retry</Button>} />
        </Panel>
      ) : !d ? (
        <Panel className="panel">
          <Empty title="Running named queries…" hint="/api/clickhouse/queries" />
        </Panel>
      ) : (
        <div className={clsx('flex flex-col gap-3 transition-opacity duration-150', poll.loading && 'opacity-60')}>
          <div className="hairline-grid grid-cols-1 xl:grid-cols-2">
            <Panel
              title="Timeline"
              meta={`${bucketSec}s buckets · ${d.timeline.length} buckets`}
              className="border-0"
              actions={
                <Tag tone={d.store === 'clickhouse' ? 'immune' : 'flag'} dot>
                  {d.store}
                </Tag>
              }
            >
              <TimelineChart buckets={d.timeline} bucketSec={bucketSec} />
            </Panel>
            <Panel title="Family breakdown" meta="attack rows by outcome" className="border-0">
              <FamilyChart families={d.families} />
            </Panel>
          </div>
          <div className="hairline-grid grid-cols-1 xl:grid-cols-2">
            {d.queries.map((q) => (
              <QueryCard key={q.name} q={q} />
            ))}
          </div>
        </div>
      )}
    </>
  );
}
