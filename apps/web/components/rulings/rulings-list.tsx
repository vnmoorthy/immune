'use client';

import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import clsx from 'clsx';
import { Check, Copy, RefreshCw, Search } from 'lucide-react';
import { api, type SensoAskResponse } from '@/lib/api';
import { citationText } from '@/lib/citation';
import { useImmuneEvents } from '@/lib/events';
import { usePoll } from '@/lib/use-poll';
import { fmtDateTime } from '@/lib/format';
import { PageHeader, Panel } from '@/components/ui/panel';
import { Tag } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Empty } from '@/components/ui/misc';

function CopyButton({ text }: { text: string }) {
  const [ok, setOk] = useState(false);
  return (
    <button
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setOk(true);
          setTimeout(() => setOk(false), 1200);
        } catch {
          /* clipboard unavailable */
        }
      }}
      className="focus-ring flex h-6 items-center gap-1 border border-line px-2 font-mono text-[10.5px] uppercase tracking-[0.06em] text-fg-2 transition-colors hover:text-fg"
    >
      {ok ? <Check className="h-3 w-3 text-immune" /> : <Copy className="h-3 w-3" />}
      {ok ? 'copied' : 'copy citation'}
    </button>
  );
}

function AskPrecedent() {
  const [q, setQ] = useState('');
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState<SensoAskResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const ask = async () => {
    const question = q.trim();
    if (!question || busy) return;
    setBusy(true);
    setError(null);
    try {
      setRes(await api.askPrecedent(question));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Panel
      title="Ask the precedent base"
      meta="senso · semantic search over published rulings"
      className="panel mb-2"
      actions={res ? <Tag tone={res.authenticated ? (res.ok ? 'immune' : 'flag') : 'neutral'} dot>{res.authenticated ? `senso${res.org ? ` · ${res.org}` : ''} · ${res.ms ? `${Math.round(res.ms)} ms` : 'ok'}` : 'not logged in'}</Tag> : null}
    >
      <form
        className="flex items-center gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          void ask();
        }}
      >
        <div className="relative flex-1">
          <Search className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-fg-3" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="is an agent allowed to post customer records to hooks.slack.com after reading a shared doc?"
            className="focus-ring h-7 w-full border border-line bg-surface-2 pl-7 pr-2 font-mono text-[11.5px] text-fg placeholder:text-fg-3"
            aria-label="Question for the precedent base"
          />
        </div>
        <Button type="submit" size="sm" mono variant="primary" loading={busy} disabled={!q.trim()}>
          ask
        </Button>
      </form>
      {error ? <div className="mt-2 font-mono text-[11px] text-breach">{error}</div> : null}
      {res ? (
        res.authenticated ? (
          <div className="mt-3 grid grid-cols-1 gap-3 xl:grid-cols-[1.2fr_1fr]">
            <div>
              <div className="label mb-1">Answer</div>
              {res.answer ? <p className="max-w-[80ch] text-[12.5px] leading-relaxed text-fg">{res.answer}</p> : <p className="font-mono text-[11px] text-fg-3">{res.ok ? 'no synthesized answer — see sources' : res.detail}</p>}
            </div>
            <div>
              <div className="label mb-1">Sources · {res.hits.length}</div>
              {res.hits.length === 0 ? (
                <p className="font-mono text-[11px] text-fg-3">no matching rulings in the knowledge base yet</p>
              ) : (
                <ul className="divide-y divide-line border border-line">
                  {res.hits.map((h, i) => (
                    <li key={i} className="px-2.5 py-2">
                      <div className="text-[12px] text-fg">{h.title ?? 'untitled'}</div>
                      <div className="mt-0.5 font-mono text-[10.5px] text-fg-3">
                        {h.kbNodeId ? `kb node ${h.kbNodeId}` : ''}
                        {h.kbNodeId && h.contentId ? ' · ' : ''}
                        {h.contentId ? `content ${h.contentId}` : ''}
                      </div>
                      {h.chunk ? <div className="mt-1 line-clamp-3 text-[11.5px] leading-snug text-fg-2">{h.chunk}</div> : null}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        ) : (
          <div className="mt-3 font-mono text-[11px] text-fg-2">
            <div>{res.detail}</div>
            {res.command ? (
              <div className="mt-1.5 flex items-center gap-2">
                <span className="text-fg-3">run</span>
                <code className="inset px-2 py-1 text-fg">{res.command}</code>
              </div>
            ) : null}
          </div>
        )
      ) : null}
    </Panel>
  );
}

export function RulingsList() {
  const params = useSearchParams();
  const focus = params.get('id');
  const poll = usePoll(() => api.rulings(), 15_000);
  useImmuneEvents(() => void poll.refresh(), ['ruling']);

  useEffect(() => {
    if (focus && poll.data) document.getElementById(`ruling-${focus}`)?.scrollIntoView({ block: 'center' });
  }, [focus, poll.data]);

  const rulings = useMemo(() => (poll.data ?? []).slice().sort((a, b) => b.createdAt - a.createdAt), [poll.data]);
  const senso = rulings.filter((r) => r.publishedTo === 'senso').length;

  return (
    <>
      <PageHeader
        title="Rulings"
        meta={poll.data ? `${rulings.length} precedents · ${senso} on senso · ${rulings.length - senso} local` : undefined}
        actions={<Button size="xs" variant="ghost" icon={<RefreshCw className={clsx('h-3 w-3', poll.loading && 'animate-spin')} />} onClick={() => void poll.refresh()} aria-label="Refresh" />}
      />
      <AskPrecedent />
      {poll.error ? (
        <Panel className="panel">
          <Empty title="Could not load rulings" hint={poll.error.message} action={<Button size="xs" mono onClick={() => void poll.refresh()}>retry</Button>} />
        </Panel>
      ) : rulings.length === 0 ? (
        <Panel className="panel">
          <Empty
            title={poll.loading ? 'Loading…' : 'No rulings published yet'}
            hint={poll.loading ? '/api/rulings' : 'a ruling is published after a receipt is signed; the next agent is denied with its citation'}
            action={!poll.loading ? <Link href="/" className="font-mono text-[11px] text-info hover:underline">go to the arena →</Link> : undefined}
          />
        </Panel>
      ) : (
        <div className="flex flex-col gap-2">
          {rulings.map((r) => {
            const cite = citationText(r);
            return (
              <Panel
                key={r.id}
                className={clsx('panel', focus === r.id && 'rail-info')}
                title={<span id={`ruling-${r.id}`} className="font-mono normal-case tracking-normal text-fg">{r.id}</span>}
                meta={
                  <>
                    {fmtDateTime(r.createdAt)} · antibody{' '}
                    <Link href={`/antibodies?rule=${encodeURIComponent(r.ruleId)}`} className="text-info hover:underline">
                      {r.ruleId}
                    </Link>{' '}
                    · receipt{' '}
                    <Link href={`/receipts?id=${encodeURIComponent(r.receiptId)}`} className="text-info hover:underline">
                      {r.receiptId}
                    </Link>
                  </>
                }
                actions={
                  <>
                    <Tag tone={r.publishedTo === 'senso' ? 'info' : 'neutral'} dot boxed title={r.externalId ? `senso kb node ${r.externalId}` : 'stored under .immune/rulings'}>
                      {r.publishedTo === 'senso' ? `senso · node ${(r.externalId ?? '').slice(0, 8) || '—'}` : 'local'}
                    </Tag>
                    <CopyButton text={cite} />
                  </>
                }
              >
                <div className="grid grid-cols-1 gap-4 xl:grid-cols-[1.4fr_1fr]">
                  <div>
                    <h3 className="text-[14px] font-medium leading-snug text-fg">{r.title}</h3>
                    <p className="mt-2 max-w-[72ch] text-[12.5px] leading-relaxed text-fg-2">{r.summary}</p>
                  </div>
                  <div className="flex flex-col gap-3">
                    <div>
                      <div className="label mb-1">Citation · as delivered in the denial</div>
                      <pre className="inset whitespace-pre-wrap break-words px-2.5 py-2 font-mono text-[11.5px] leading-relaxed text-fg">{cite}</pre>
                    </div>
                    <div>
                      <div className="label mb-1">Evidence · {r.evidenceTraceIds.length} trace{r.evidenceTraceIds.length === 1 ? '' : 's'}</div>
                      <div className="flex flex-wrap gap-1">
                        {r.evidenceTraceIds.map((t) => (
                          <Link key={t} href={`/traces?id=${encodeURIComponent(t)}`} className="focus-ring border border-line px-1.5 py-0.5 font-mono text-[10.5px] text-info transition-colors hover:border-line-strong hover:bg-surface-2">
                            {t}
                          </Link>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              </Panel>
            );
          })}
        </div>
      )}
    </>
  );
}
