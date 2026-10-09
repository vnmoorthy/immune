'use client';

import { useState } from 'react';
import clsx from 'clsx';
import { Crosshair, Dna, Layers, RotateCcw, Waves, Zap } from 'lucide-react';
import type { AttackFamily } from '@immune/core';
import { api, type AttackResponse } from '@/lib/api';
import { ATTACK_FAMILIES, FAMILY_META, fmtInt, fmtMs, type Tone } from '@/lib/format';
import { useMetrics } from './metrics-context';
import { Button } from '@/components/ui/button';
import { Panel } from '@/components/ui/panel';
import { Tag } from '@/components/ui/badge';
import { useToast } from '@/components/ui/toast';

type Mode = 'launch' | 'mutate' | 'x10' | 'replay';

interface LastResult {
  text: string;
  tone: Tone;
}

function summarize(r: AttackResponse): LastResult {
  if (r.breaches > 0) {
    return {
      tone: 'breach',
      text: `BREACH ×${r.breaches} → ${r.remediationId ?? 'remediation queued'}`,
    };
  }
  const decisive = r.traces.filter((t) => t.decision !== 'allow');
  const by = decisive.find((t) => t.blockedBy)?.blockedBy;
  const d = decisive[0]?.decision ?? 'allow';
  return {
    tone: d === 'allow' ? 'immune' : d === 'flag' ? 'flag' : 'breach',
    text: `${d.toUpperCase()}${by ? ` · ${by}` : ''} · ${r.sessions} session${r.sessions === 1 ? '' : 's'} · ${fmtMs(r.ms)}`,
  };
}

export function Arena() {
  const { metrics, refresh } = useMetrics();
  const { toast } = useToast();
  const [pending, setPending] = useState<Partial<Record<AttackFamily, Mode>>>({});
  const [last, setLast] = useState<Partial<Record<AttackFamily, LastResult>>>({});
  const [stormBusy, setStormBusy] = useState(false);
  const [seeds, setSeeds] = useState<Partial<Record<AttackFamily, number>>>({});

  const famStats = (f: AttackFamily) => metrics?.families.find((x) => x.family === f);
  const lastSeed = (f: AttackFamily): number | undefined => seeds[f] ?? metrics?.lastSeeds?.[f];

  const run = async (family: Exclude<AttackFamily, 'benign'>, mode: Mode) => {
    const replaySeed = mode === 'replay' ? lastSeed(family) : undefined;
    if (mode === 'replay' && replaySeed === undefined) return;
    setPending((p) => ({ ...p, [family]: mode }));
    try {
      const r = await api.attack({ family, mutate: mode !== 'launch', count: mode === 'x10' ? 10 : 1, seed: replaySeed });
      const s = summarize(r);
      setLast((l) => ({ ...l, [family]: s }));
      if (r.seed !== undefined && mode !== 'launch') setSeeds((x) => ({ ...x, [family]: r.seed }));
      const what = mode === 'launch' ? `known variant ${r.variant ?? ''}` : mode === 'mutate' ? `novel mutation · seed ${r.seed}` : mode === 'x10' ? `10 novel mutations · last seed ${r.seed}` : `replay · seed ${r.seed} (${r.variant ?? ''})`;
      toast({
        title: `${FAMILY_META[family].label} · ${what}`,
        description: s.text,
        tone: s.tone,
      });
      void refresh();
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setLast((l) => ({ ...l, [family]: { text: `ERROR · ${msg}`, tone: 'breach' } }));
      toast({ title: 'Attack failed to run', description: msg, tone: 'breach' });
    } finally {
      setPending((p) => ({ ...p, [family]: undefined }));
    }
  };

  const storm = async () => {
    setStormBusy(true);
    try {
      await Promise.allSettled(ATTACK_FAMILIES.map((f) => run(f, 'mutate')));
    } finally {
      setStormBusy(false);
    }
  };

  return (
    <Panel
      title="Arena"
      meta="gullible agent × acme mcp server · one session per launch"
      className="col-span-12 border-0 lg:col-span-7"
      flush
      actions={
        <Button size="xs" mono variant="danger" icon={<Zap className="h-3 w-3" />} loading={stormBusy} onClick={storm} title="Launch one novel mutation of every family">
          mutate all
        </Button>
      }
    >
      <div className="grid grid-cols-2 xl:grid-cols-3 [&>*]:border-b [&>*]:border-r [&>*]:border-line [&>*:nth-child(2n)]:border-r-0 xl:[&>*:nth-child(2n)]:border-r xl:[&>*:nth-child(3n)]:border-r-0">
        {ATTACK_FAMILIES.map((family) => {
          const meta = FAMILY_META[family];
          const st = famStats(family);
          const p = pending[family];
          const lr = last[family];
          return (
            <div key={family} className="flex min-w-0 flex-col gap-2 px-3 py-2.5">
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <div className="text-[12.5px] font-medium text-fg">{meta.label}</div>
                  <div className="mt-0.5 line-clamp-2 text-[11px] leading-snug text-fg-3">{meta.description}</div>
                </div>
                <span className="font-mono text-[10px] text-fg-3">{family}</span>
              </div>
              <div className="mono-num flex items-center gap-3 text-[11px] text-fg-3">
                <span>
                  n <span className="text-fg-2">{fmtInt(st?.total ?? 0)}</span>
                </span>
                <span>
                  blocked <span className="text-fg-2">{fmtInt(st?.blocked ?? 0)}</span>
                </span>
                <span>
                  breached <span className={clsx((st?.breached ?? 0) > 0 ? 'text-breach' : 'text-fg-2')}>{fmtInt(st?.breached ?? 0)}</span>
                </span>
              </div>
              <div className="flex items-center gap-1">
                <Button size="xs" mono icon={<Crosshair className="h-3 w-3" />} loading={p === 'launch'} disabled={!!p && p !== 'launch'} onClick={() => run(family, 'launch')} title="Known variant — should be caught by builtin antibodies">
                  launch
                </Button>
                <Button size="xs" mono variant="flag" icon={<Dna className="h-3 w-3" />} loading={p === 'mutate'} disabled={!!p && p !== 'mutate'} onClick={() => run(family, 'mutate')} title="Novel variant designed to evade current rules">
                  mutate
                </Button>
                <Button size="xs" mono variant="flag" icon={<Layers className="h-3 w-3" />} loading={p === 'x10'} disabled={!!p && p !== 'x10'} onClick={() => run(family, 'x10')} title="Ten novel variants, back to back">
                  ×10
                </Button>
                <Button
                  size="xs"
                  mono
                  variant="ghost"
                  icon={<RotateCcw className="h-3 w-3" />}
                  loading={p === 'replay'}
                  disabled={(!!p && p !== 'replay') || lastSeed(family) === undefined}
                  onClick={() => run(family, 'replay')}
                  title={lastSeed(family) !== undefined ? `Replay the identical mutation (seed ${lastSeed(family)}) — after immunity it must bounce with a citation` : 'Mutate first — replay re-runs the exact last mutation'}
                >
                  replay{lastSeed(family) !== undefined ? ` #${lastSeed(family)}` : ''}
                </Button>
              </div>
              <div className="h-4 truncate font-mono text-[10.5px]" title={lr?.text}>
                {lr ? <Tag tone={lr.tone} className="normal-case tracking-normal">{lr.text}</Tag> : <span className="text-fg-3">—</span>}
              </div>
            </div>
          );
        })}
      </div>
      <Flood />
    </Panel>
  );
}

function Flood() {
  const { refresh } = useMetrics();
  const { toast } = useToast();
  const [attacks, setAttacks] = useState(400);
  const [benign, setBenign] = useState(2000);
  const [busy, setBusy] = useState<'flood' | 'burst' | null>(null);
  const [result, setResult] = useState<string | null>(null);

  const flood = async () => {
    setBusy('flood');
    try {
      const r = await api.flood(attacks, benign);
      const text = `inserted ${fmtInt(r.inserted)} in ${fmtMs(r.ms)}`;
      setResult(text);
      toast({ title: 'Flood complete', description: `${fmtInt(r.benign)} benign + ${fmtInt(r.attacks)} attacks → store · ${fmtMs(r.ms)}`, tone: 'info' });
      void refresh();
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setResult(`error · ${msg}`);
      toast({ title: 'Flood failed', description: msg, tone: 'breach' });
    } finally {
      setBusy(null);
    }
  };

  const burst = async () => {
    setBusy('burst');
    try {
      const r = await api.attack({ family: 'benign', count: 10 });
      const fp = r.traces.filter((t) => t.decision === 'block' || t.decision === 'quarantine').length;
      const text = `${r.sessions} benign sessions · ${fp} false positive${fp === 1 ? '' : 's'} · ${fmtMs(r.ms)}`;
      setResult(text);
      toast({ title: 'Benign burst', description: text, tone: fp ? 'flag' : 'immune' });
      void refresh();
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setResult(`error · ${msg}`);
      toast({ title: 'Benign burst failed', description: msg, tone: 'breach' });
    } finally {
      setBusy(null);
    }
  };

  const Num = ({ value, onChange, label }: { value: number; onChange: (n: number) => void; label: string }) => (
    <label className="flex items-center gap-1.5 font-mono text-[11px] text-fg-3">
      {label}
      <input
        type="number"
        min={0}
        max={200000}
        step={100}
        value={value}
        onChange={(e) => onChange(Math.max(0, Math.min(200000, Number(e.target.value) || 0)))}
        className="focus-ring h-6 w-[76px] border border-line bg-surface-2 px-1.5 text-right font-mono text-[11px] tabular text-fg"
      />
    </label>
  );

  return (
    <div className="flex flex-wrap items-center gap-3 px-3 py-2">
      <span className="label flex items-center gap-1.5">
        <Waves className="h-3 w-3" /> Flood
      </span>
      <Num label="attacks" value={attacks} onChange={setAttacks} />
      <Num label="benign" value={benign} onChange={setBenign} />
      <Button size="xs" mono loading={busy === 'flood'} disabled={busy === 'burst'} onClick={flood} title="generateCorpus → batched insert into the store (no agent)">
        flood store
      </Button>
      <Button size="xs" mono variant="immune" loading={busy === 'burst'} disabled={busy === 'flood'} onClick={burst} title="10 legitimate sessions through the live gate — watch for false positives">
        benign burst ×10
      </Button>
      <span className="ml-auto truncate font-mono text-[10.5px] text-fg-3">{result ?? 'corpus = replay set for every proof'}</span>
    </div>
  );
}
