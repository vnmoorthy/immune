'use client';

import { Fragment, useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import clsx from 'clsx';
import { ArrowRight, ChevronDown, ChevronRight, RefreshCw } from 'lucide-react';
import type { ProofReport, Rule } from '@immune/core';
import { api } from '@/lib/api';
import { useImmuneEvents } from '@/lib/events';
import { usePoll } from '@/lib/use-poll';
import { fmtDateTime, fmtInt, fmtMs, fmtPct } from '@/lib/format';
import { PageHeader, Panel } from '@/components/ui/panel';
import { OriginTag, RuleStatusTag, SeverityTag, Tag } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { CodeBlock, JsonBlock } from '@/components/ui/code-block';
import { Empty, KV } from '@/components/ui/misc';
import { useToast } from '@/components/ui/toast';

type StatusFilter = 'all' | Rule['status'];
type OriginFilter = 'all' | Rule['origin'];

function matchSummary(r: Rule): string[] {
  const m = r.match;
  const out: string[] = [m.phase];
  if (m.server) out.push(`server=${m.server}`);
  if (m.tool) out.push(`tool=${m.tool}`);
  if (m.patterns?.length) out.push(`${m.patterns.length} pattern${m.patterns.length === 1 ? '' : 's'}`);
  if (m.capabilities?.length) out.push(`caps:${m.capabilities.join('|')}`);
  if (m.afterTainted) out.push('after-taint');
  if (m.destinationNotIn) out.push(`dest∉${m.destinationNotIn.length}`);
  if (m.carriesSecret) out.push('carries-secret');
  return out;
}

function Delta({ before, after, invert, digits = 1 }: { before: number; after: number; invert?: boolean; digits?: number }) {
  const better = invert ? after <= before : after >= before;
  const same = Math.abs(after - before) < 1e-9;
  return (
    <span className="mono-num inline-flex items-center gap-1 text-[11.5px]">
      <span className="text-fg-3">{fmtPct(before, digits)}</span>
      <ArrowRight className="h-3 w-3 text-fg-3" />
      <span className={clsx(same ? 'text-fg-2' : better ? 'text-immune' : 'text-breach')}>{fmtPct(after, digits)}</span>
    </span>
  );
}

function ProofCell({ proof }: { proof?: ProofReport }) {
  if (!proof) return <span className="font-mono text-[11px] text-fg-3">no proof — builtin or unproven</span>;
  return (
    <div className="flex flex-col gap-0.5">
      <div className="flex items-center gap-2">
        <span className="w-9 font-mono text-[10px] uppercase text-fg-3">catch</span>
        <Delta before={proof.catchRateBefore} after={proof.catchRateAfter} />
      </div>
      <div className="flex items-center gap-2">
        <span className="w-9 font-mono text-[10px] uppercase text-fg-3">fp</span>
        <Delta before={proof.fpRateBefore} after={proof.fpRateAfter} invert digits={2} />
      </div>
      <div className="font-mono text-[10px] text-fg-3">
        corpus {fmtInt(proof.corpusSize)} · {proof.targetCaught ? <span className="text-immune">target caught</span> : <span className="text-breach">target missed</span>}
      </div>
    </div>
  );
}

export function RulesTable() {
  const params = useSearchParams();
  const focus = params.get('rule');
  const poll = usePoll(() => api.rules(), 10_000);
  const { toast } = useToast();
  const [status, setStatus] = useState<StatusFilter>('all');
  const [origin, setOrigin] = useState<OriginFilter>('all');
  const [q, setQ] = useState('');
  const [open, setOpen] = useState<Set<string>>(() => new Set(focus ? [focus] : []));
  const [busy, setBusy] = useState<string | null>(null);

  useImmuneEvents(() => void poll.refresh(), ['rule', 'remediation']);

  useEffect(() => {
    if (focus) {
      setOpen((s) => new Set(s).add(focus));
      const el = document.getElementById(`rule-${focus}`);
      el?.scrollIntoView({ block: 'center' });
    }
  }, [focus, poll.data]);

  const rules = useMemo(() => {
    const list = (poll.data ?? []).slice().sort((a, b) => b.createdAt - a.createdAt);
    const needle = q.trim().toLowerCase();
    return list.filter((r) => (status === 'all' || r.status === status) && (origin === 'all' || r.origin === origin) && (!needle || r.name.toLowerCase().includes(needle) || r.id.toLowerCase().includes(needle)));
  }, [poll.data, status, origin, q]);

  const counts = useMemo(() => {
    const all = poll.data ?? [];
    return { promoted: all.filter((r) => r.status === 'promoted').length, candidate: all.filter((r) => r.status === 'candidate').length, revoked: all.filter((r) => r.status === 'revoked').length };
  }, [poll.data]);

  const toggle = (id: string) =>
    setOpen((s) => {
      const n = new Set(s);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });

  const act = async (r: Rule, action: 'promote' | 'revoke') => {
    setBusy(r.id);
    try {
      const updated = action === 'promote' ? await api.promoteRule(r.id) : await api.revokeRule(r.id);
      poll.setData((prev) => prev?.map((x) => (x.id === updated.id ? updated : x)));
      toast({ title: action === 'promote' ? 'Antibody promoted' : 'Antibody revoked', description: `${r.id} · ${r.name}`, tone: action === 'promote' ? 'immune' : 'flag' });
      void poll.refresh();
    } catch (e) {
      toast({ title: `${action} failed`, description: e instanceof Error ? e.message : String(e), tone: 'breach' });
    } finally {
      setBusy(null);
    }
  };

  const Seg = <T extends string>({ value, options, onChange }: { value: T; options: { id: T; label: string }[]; onChange: (v: T) => void }) => (
    <div className="flex items-center border border-line">
      {options.map((o) => (
        <button key={o.id} onClick={() => onChange(o.id)} className={clsx('focus-ring h-6 px-2 font-mono text-[10.5px] uppercase tracking-[0.06em] transition-colors duration-150 ease-out', value === o.id ? 'bg-surface-3 text-fg' : 'text-fg-3 hover:text-fg-2')}>
          {o.label}
        </button>
      ))}
    </div>
  );

  return (
    <>
      <PageHeader
        title="Antibodies"
        meta={poll.data ? `${poll.data.length} rules · ${counts.promoted} promoted · ${counts.candidate} candidate · ${counts.revoked} revoked` : undefined}
        actions={
          <>
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="search name / id" className="focus-ring h-6 w-44 border border-line bg-surface-2 px-2 font-mono text-[11px] text-fg placeholder:text-fg-3" />
            <Seg value={status} onChange={setStatus} options={[{ id: 'all', label: 'all' }, { id: 'promoted', label: 'promoted' }, { id: 'candidate', label: 'candidate' }, { id: 'revoked', label: 'revoked' }]} />
            <Seg value={origin} onChange={setOrigin} options={[{ id: 'all', label: 'any origin' }, { id: 'builtin', label: 'builtin' }, { id: 'synthesized', label: 'synth' }, { id: 'llm', label: 'llm' }]} />
            <Button size="xs" variant="ghost" icon={<RefreshCw className={clsx('h-3 w-3', poll.loading && 'animate-spin')} />} onClick={() => void poll.refresh()} aria-label="Refresh" />
          </>
        }
      />
      <Panel flush className="panel">
        {poll.error ? (
          <Empty title="Could not load rules" hint={poll.error.message} action={<Button size="xs" mono onClick={() => void poll.refresh()}>retry</Button>} />
        ) : rules.length === 0 ? (
          <Empty title={poll.loading ? 'Loading…' : 'No antibodies match'} hint={poll.loading ? '/api/rules' : 'synthesized antibodies appear here after a breach is remediated'} />
        ) : (
          <div className="max-h-[calc(100vh-140px)] overflow-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th className="w-6" />
                  <th>antibody</th>
                  <th className="w-[100px]">status</th>
                  <th>match</th>
                  <th className="w-[112px]">action</th>
                  <th className="w-[124px]">derived from</th>
                  <th className="w-[196px]">proof · before → after</th>
                  <th className="w-[56px]">semgrep</th>
                  <th className="w-[128px]" />
                </tr>
              </thead>
              <tbody>
                {rules.map((r) => {
                  const isOpen = open.has(r.id);
                  return (
                    <Fragment key={r.id}>
                      <tr id={`rule-${r.id}`} onClick={() => toggle(r.id)} className={clsx('cursor-pointer', focus === r.id && 'rail-info', isOpen && 'bg-surface-2')}>
                        <td className="text-fg-3">{isOpen ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}</td>
                        <td className="max-w-[280px]">
                          <div className="truncate text-[12.5px] text-fg" title={r.name}>
                            {r.name}
                          </div>
                          <div className="flex items-center gap-2 font-mono text-[10.5px] text-fg-3">
                            {r.id} · v{r.version} <OriginTag origin={r.origin} />
                          </div>
                        </td>
                        <td>
                          <RuleStatusTag status={r.status} />
                        </td>
                        <td className="max-w-[230px]">
                          <div className="flex flex-wrap gap-1">
                            {matchSummary(r).map((s, i) => (
                              <span key={i} className={clsx('border border-line px-1 font-mono text-[10px]', i === 0 ? 'text-fg' : 'text-fg-2')}>
                                {s}
                              </span>
                            ))}
                          </div>
                        </td>
                        <td>
                          <div className="flex items-center gap-2">
                            <Tag tone={r.action === 'allow' ? 'immune' : r.action === 'flag' ? 'flag' : 'breach'} bold>
                              {r.action}
                            </Tag>
                            <SeverityTag severity={r.severity} />
                          </div>
                        </td>
                        <td className="font-mono text-[10.5px]">
                          {r.derivedFrom.length ? (
                            r.derivedFrom.slice(0, 2).map((t) => (
                              <Link key={t} href={`/traces?id=${encodeURIComponent(t)}`} onClick={(e) => e.stopPropagation()} className="block text-info hover:underline">
                                {t}
                              </Link>
                            ))
                          ) : (
                            <span className="text-fg-3">—</span>
                          )}
                          {r.derivedFrom.length > 2 ? <span className="text-fg-3">+{r.derivedFrom.length - 2}</span> : null}
                        </td>
                        <td>
                          <ProofCell proof={r.proof} />
                        </td>
                        <td className="font-mono text-[11px]">{r.semgrep ? <span className="text-fg">yaml</span> : <span className="text-fg-3">—</span>}</td>
                        <td onClick={(e) => e.stopPropagation()}>
                          <div className="flex justify-end gap-1">
                            {r.status !== 'promoted' ? (
                              <Button size="xs" mono variant="immune" loading={busy === r.id} onClick={() => act(r, 'promote')}>
                                promote
                              </Button>
                            ) : null}
                            {r.status !== 'revoked' ? (
                              <Button size="xs" mono variant="danger" loading={busy === r.id} onClick={() => act(r, 'revoke')}>
                                revoke
                              </Button>
                            ) : null}
                          </div>
                        </td>
                      </tr>
                      {isOpen ? (
                        <tr className="!bg-surface-2">
                          <td colSpan={9} className="!whitespace-normal !p-0">
                            <RuleDetail rule={r} />
                          </td>
                        </tr>
                      ) : null}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </>
  );
}

function RuleDetail({ rule: r }: { rule: Rule }) {
  const p = r.proof;
  return (
    <div className="grid grid-cols-1 gap-px bg-line xl:grid-cols-3">
      <div className="bg-surface-2 p-3">
        <h3 className="label mb-2">Match</h3>
        <JsonBlock title="rule.match" value={r.match} maxHeight={260} />
        <KV
          className="mt-3"
          rows={[
            { k: 'created', v: fmtDateTime(r.createdAt) },
            { k: 'receipt', v: r.receiptId ? <Link href={`/receipts?id=${encodeURIComponent(r.receiptId)}`} className="text-info hover:underline">{r.receiptId}</Link> : '—' },
            { k: 'ruling', v: r.rulingId ? <Link href={`/rulings?id=${encodeURIComponent(r.rulingId)}`} className="text-info hover:underline">{r.rulingId}</Link> : '—' },
          ]}
        />
      </div>
      <div className="bg-surface-2 p-3">
        <h3 className="label mb-2">Proof</h3>
        {p ? (
          <KV
            rows={[
              { k: 'promoted', v: p.promoted ? <span className="text-immune">yes</span> : <span className="text-breach">no</span> },
              { k: 'reason', v: <span className="font-sans text-[12px] text-fg-2">{p.reason}</span> },
              { k: 'attacks', v: `${p.before.attacksCaught}/${p.before.attacksTotal} → ${p.after.attacksCaught}/${p.after.attacksTotal}` },
              { k: 'benign blocked', v: `${p.before.benignBlocked}/${p.before.benignTotal} → ${p.after.benignBlocked}/${p.after.benignTotal}` },
              { k: 'corpus hash', v: `${p.corpusHash.slice(0, 24)}…` },
              { k: 'replay', v: `${fmtMs(p.replayMs)}${p.storeMs !== undefined ? ` · store ${fmtMs(p.storeMs)}` : ''}` },
              { k: 'semgrep', v: p.semgrep ? <span className={p.semgrep.ran ? 'text-fg' : 'text-fg-3'}>{p.semgrep.summary}</span> : '—' },
              { k: 'proved at', v: fmtDateTime(p.ts) },
            ]}
          />
        ) : (
          <p className="font-mono text-[11px] text-fg-3">builtin antibodies ship without a proof; synthesized ones are promoted only when catch rate rises and FP does not.</p>
        )}
      </div>
      <div className="bg-surface-2 p-3">
        <h3 className="label mb-2">Semgrep rule</h3>
        {r.semgrep ? <CodeBlock code={r.semgrep} language="yaml" title="semgrep.yaml" maxHeight={300} /> : <p className="font-mono text-[11px] text-fg-3">no source-level sink identified for this antibody</p>}
      </div>
    </div>
  );
}
