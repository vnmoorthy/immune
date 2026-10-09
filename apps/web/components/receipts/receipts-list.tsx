'use client';

import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import clsx from 'clsx';
import { BadgeCheck, RefreshCw, ShieldX } from 'lucide-react';
import type { Receipt } from '@immune/core';
import { api, type VerifyResponse } from '@/lib/api';
import { useImmuneEvents } from '@/lib/events';
import { usePoll } from '@/lib/use-poll';
import { fmtDateTime, fmtInt, fmtMs, fmtPct } from '@/lib/format';
import { PageHeader, Panel } from '@/components/ui/panel';
import { Tag } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { JsonBlock } from '@/components/ui/code-block';
import { Empty, KV } from '@/components/ui/misc';
import { useToast } from '@/components/ui/toast';

/** Client-side tamper: bump the claimed catch-rate so the proof looks better than it was. */
function tamper(r: Receipt): { receipt: Receipt; field: string; before: string; after: string } {
  const after = Math.min(1, Math.max(r.proof.catchRateAfter + 0.01, 1));
  return {
    receipt: { ...r, proof: { ...r.proof, catchRateAfter: after } },
    field: 'proof.catchRateAfter',
    before: r.proof.catchRateAfter.toFixed(4),
    after: after.toFixed(4),
  };
}

type Verdict = { state: 'idle' } | { state: 'verifying' } | { state: 'done'; result: VerifyResponse; tampered: boolean; at: number };

export function ReceiptsList() {
  const params = useSearchParams();
  const focus = params.get('id');
  const poll = usePoll(() => api.receipts(), 15_000);
  const { toast } = useToast();
  const [tampered, setTampered] = useState<Set<string>>(new Set());
  const [verdicts, setVerdicts] = useState<Record<string, Verdict>>({});
  const [showPayload, setShowPayload] = useState<Set<string>>(new Set());
  const [allBusy, setAllBusy] = useState(false);

  useImmuneEvents(() => void poll.refresh(), ['receipt']);

  useEffect(() => {
    if (focus && poll.data) document.getElementById(`receipt-${focus}`)?.scrollIntoView({ block: 'center' });
  }, [focus, poll.data]);

  const receipts = useMemo(() => (poll.data ?? []).slice().sort((a, b) => b.createdAt - a.createdAt), [poll.data]);

  const verify = async (r: Receipt, isTampered: boolean) => {
    setVerdicts((v) => ({ ...v, [r.id]: { state: 'verifying' } }));
    const payload = isTampered ? tamper(r).receipt : r;
    try {
      const result = await api.verifyReceipt(payload);
      setVerdicts((v) => ({ ...v, [r.id]: { state: 'done', result, tampered: isTampered, at: Date.now() } }));
      return result;
    } catch (e) {
      const result = { ok: false, reason: e instanceof Error ? e.message : String(e) };
      setVerdicts((v) => ({ ...v, [r.id]: { state: 'done', result, tampered: isTampered, at: Date.now() } }));
      return result;
    }
  };

  const toggleTamper = async (r: Receipt) => {
    const next = new Set(tampered);
    const on = !next.has(r.id);
    if (on) next.add(r.id);
    else next.delete(r.id);
    setTampered(next);
    const res = await verify(r, on);
    toast({
      title: on ? 'Tampered copy re-verified' : 'Original re-verified',
      description: `${r.id} → ${res.ok ? 'VALID' : 'INVALID'} · ${res.reason}`,
      tone: res.ok ? 'immune' : 'breach',
    });
  };

  const verifyAll = async () => {
    setAllBusy(true);
    try {
      const results = await Promise.all(receipts.map((r) => verify(r, tampered.has(r.id))));
      const ok = results.filter((x) => x.ok).length;
      toast({ title: `Verified ${results.length} receipt${results.length === 1 ? '' : 's'}`, description: `${ok} valid · ${results.length - ok} invalid`, tone: ok === results.length ? 'immune' : 'breach' });
    } finally {
      setAllBusy(false);
    }
  };

  return (
    <>
      <PageHeader
        title="Receipts"
        meta={poll.data ? `${poll.data.length} signed proofs · HMAC-SHA256 over sha256(canonicalJson({ruleId, proof}))` : undefined}
        actions={
          <>
            <Button size="xs" mono variant="primary" loading={allBusy} disabled={!receipts.length} onClick={verifyAll}>
              verify all
            </Button>
            <Button size="xs" variant="ghost" icon={<RefreshCw className={clsx('h-3 w-3', poll.loading && 'animate-spin')} />} onClick={() => void poll.refresh()} aria-label="Refresh" />
          </>
        }
      />
      {poll.error ? (
        <Panel className="panel">
          <Empty title="Could not load receipts" hint={poll.error.message} action={<Button size="xs" mono onClick={() => void poll.refresh()}>retry</Button>} />
        </Panel>
      ) : receipts.length === 0 ? (
        <Panel className="panel">
          <Empty title={poll.loading ? 'Loading…' : 'No receipts yet'} hint={poll.loading ? '/api/receipts' : 'a receipt is signed when a synthesized antibody passes replay proof'} action={!poll.loading ? <Link href="/" className="font-mono text-[11px] text-info hover:underline">go to the arena →</Link> : undefined} />
        </Panel>
      ) : (
        <div className="flex flex-col gap-2">
          {receipts.map((r) => {
            const isT = tampered.has(r.id);
            const v = verdicts[r.id] ?? { state: 'idle' };
            const t = isT ? tamper(r) : null;
            const shown = showPayload.has(r.id);
            return (
              <Panel
                key={r.id}
                className={clsx('panel', focus === r.id && 'rail-info', v.state === 'done' && (v.result.ok ? 'rail-immune' : 'rail-breach'))}
                title={<span id={`receipt-${r.id}`} className="font-mono normal-case tracking-normal text-fg">{r.id}</span>}
                meta={
                  <>
                    antibody{' '}
                    <Link href={`/antibodies?rule=${encodeURIComponent(r.ruleId)}`} className="text-info hover:underline">
                      {r.ruleId}
                    </Link>{' '}
                    · {fmtDateTime(r.createdAt)}
                  </>
                }
                actions={
                  <>
                    <button
                      onClick={() => void toggleTamper(r)}
                      className={clsx('focus-ring flex h-6 items-center gap-1.5 border px-2 font-mono text-[10.5px] uppercase tracking-[0.06em] transition-colors duration-150 ease-out', isT ? 'border-breach/60 bg-breach/10 text-breach' : 'border-line text-fg-2 hover:text-fg')}
                      title="Edit one field client-side and re-verify — the signature must fail"
                      aria-pressed={isT}
                    >
                      <span className={clsx('h-1.5 w-1.5 rounded-full', isT ? 'bg-breach' : 'bg-fg-3')} />
                      tamper {isT ? 'on' : 'off'}
                    </button>
                    <Button size="xs" mono variant="primary" loading={v.state === 'verifying'} onClick={() => void verify(r, isT)}>
                      verify
                    </Button>
                  </>
                }
              >
                <div className="grid grid-cols-1 gap-4 xl:grid-cols-[1fr_1fr_320px]">
                  <KV
                    rows={[
                      { k: 'algorithm', v: r.algorithm },
                      { k: 'payload hash', v: <span className="break-all">{r.payloadHash}</span> },
                      { k: 'signature', v: <span className="break-all">{r.signature}</span> },
                    ]}
                  />
                  <KV
                    rows={[
                      { k: 'corpus', v: `${fmtInt(r.proof.corpusSize)} traces · ${r.proof.corpusHash.slice(0, 16)}…` },
                      { k: 'catch rate', v: <span>{fmtPct(r.proof.catchRateBefore)} → <span className={clsx(isT ? 'text-breach line-through' : 'text-fg')}>{fmtPct(r.proof.catchRateAfter)}</span>{isT && t ? <span className="text-breach"> {fmtPct(Number(t.after))}</span> : null}</span> },
                      { k: 'false positives', v: `${fmtPct(r.proof.fpRateBefore, 2)} → ${fmtPct(r.proof.fpRateAfter, 2)}` },
                      { k: 'replay', v: `${fmtMs(r.proof.replayMs)}${r.proof.storeMs !== undefined ? ` · store ${fmtMs(r.proof.storeMs)}` : ''}` },
                      { k: 'promoted', v: r.proof.promoted ? <span className="text-immune">yes</span> : <span className="text-breach">no</span> },
                    ]}
                  />
                  <div className="flex flex-col gap-2">
                    <div className={clsx('inset flex min-h-[64px] flex-col justify-center px-3 py-2', v.state === 'done' && (v.result.ok ? 'border-immune/50' : 'border-breach/50'))}>
                      {v.state === 'idle' ? (
                        <span className="font-mono text-[11px] text-fg-3">not verified in this session</span>
                      ) : v.state === 'verifying' ? (
                        <span className="font-mono text-[11px] text-fg-2">verifying…</span>
                      ) : (
                        <>
                          <div className="flex items-center gap-2">
                            {v.result.ok ? <BadgeCheck className="h-4 w-4 text-immune" strokeWidth={1.75} /> : <ShieldX className="h-4 w-4 text-breach" strokeWidth={1.75} />}
                            <Tag tone={v.result.ok ? 'immune' : 'breach'} bold>
                              {v.result.ok ? 'valid' : 'invalid'}
                            </Tag>
                            {v.tampered ? <Tag tone="breach">tampered copy</Tag> : null}
                          </div>
                          <div className="mt-1 font-mono text-[11px] leading-snug text-fg-2">{v.result.reason}</div>
                        </>
                      )}
                    </div>
                    {isT && t ? (
                      <div className="font-mono text-[10.5px] text-fg-3">
                        edited <span className="text-fg">{t.field}</span>: <span className="line-through">{t.before}</span> → <span className="text-breach">{t.after}</span>
                      </div>
                    ) : null}
                    <button onClick={() => setShowPayload((s) => { const n = new Set(s); if (n.has(r.id)) n.delete(r.id); else n.add(r.id); return n; })} className="focus-ring self-start font-mono text-[10.5px] uppercase tracking-[0.06em] text-fg-3 hover:text-fg">
                      {shown ? 'hide' : 'show'} signed payload
                    </button>
                  </div>
                </div>
                {shown ? (
                  <div className="mt-3">
                    <JsonBlock title={isT ? 'receipt.json (tampered copy)' : 'receipt.json'} value={isT && t ? t.receipt : r} maxHeight={360} />
                  </div>
                ) : null}
              </Panel>
            );
          })}
        </div>
      )}
    </>
  );
}
