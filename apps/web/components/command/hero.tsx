'use client';

import Link from 'next/link';
import clsx from 'clsx';
import { useMetrics } from './metrics-context';
import { NumberTicker } from '@/components/ui/number-ticker';
import { Gauge } from '@/components/ui/gauge';
import { Panel } from '@/components/ui/panel';
import { Readout, Sparkline } from '@/components/ui/misc';
import { fmtInt, fmtMs, fmtPct, FAMILY_META, timeAgo, type Tone } from '@/lib/format';
import { useNow } from '@/lib/use-poll';

function ttiTone(ms: number | undefined): Tone {
  if (ms === undefined) return 'neutral';
  if (ms < 5000) return 'immune';
  if (ms < 20000) return 'flag';
  return 'breach';
}

export function TtiHero() {
  const { metrics } = useMetrics();
  const now = useNow(5000);
  const tti = metrics?.lastTimeToImmunityMs;
  const history = metrics?.ttiHistory ?? [];
  const last = history[history.length - 1];
  const tone = ttiTone(tti);
  const seconds = tti !== undefined ? tti / 1000 : undefined;

  return (
    <Panel title="Time to immunity" meta={last ? `${last.remediationId} · ${FAMILY_META[last.family]?.label ?? last.family} · ${timeAgo(last.ts, now)}` : 'no verified remediation yet'} className="col-span-12 border-0 lg:col-span-5">
      <div className="flex items-end justify-between gap-6">
        <div className="min-w-0">
          <div className="flex items-baseline gap-2">
            <span className={clsx('mono-num text-[72px] font-light leading-[0.9] tracking-[-0.02em]', tone === 'immune' && 'text-immune', tone === 'flag' && 'text-flag', tone === 'breach' && 'text-breach', tone === 'neutral' && 'text-fg-3')}>
              {seconds !== undefined ? <NumberTicker value={seconds} format={(v) => v.toFixed(3)} /> : <span className="text-[56px]">—</span>}
            </span>
            <span className="mono-num text-[20px] font-light text-fg-3">s</span>
          </div>
          <div className="mt-3 font-mono text-[11px] text-fg-3">
            {tti !== undefined ? (
              <>
                breach → antibody → proof → receipt → ruling → <span className="text-fg-2">verified immune</span> in {fmtMs(tti)}
              </>
            ) : (
              <>
                launch a <span className="text-fg-2">mutated</span> attack in the arena — the first breach starts the loop
              </>
            )}
          </div>
        </div>
        <div className="flex shrink-0 flex-col items-end gap-1">
          <Sparkline values={history.map((h) => h.ms)} width={160} height={36} stroke="#6b7075" accent={tone === 'neutral' ? '#6b7075' : tone === 'immune' ? '#3ecf8e' : tone === 'flag' ? '#d9a21b' : '#e5484d'} />
          <div className="font-mono text-[10.5px] text-fg-3">
            {history.length ? `${history.length} verified · median ${fmtMs(median(history.map((h) => h.ms)))}` : 'history'}
          </div>
        </div>
      </div>
      <div className="mt-4 grid grid-cols-4 border-t border-line pt-1 [&>*]:border-r [&>*]:border-line [&>*:last-child]:border-r-0">
        <Readout label="Gate p50" value={fmtMs(metrics?.gateP50Ms)} size="sm" className="!px-0 pr-3" />
        <Readout label="Gate p95" value={fmtMs(metrics?.gateP95Ms)} size="sm" className="pl-3" />
        <Readout label="Store" value={!metrics ? '…' : metrics.storeKind === 'clickhouse' ? fmtMs(metrics.storeLatencyMs) : 'memory'} sub={!metrics ? undefined : metrics.storeKind === 'clickhouse' ? 'clickhouse query' : 'no clickhouse'} size="sm" className="pl-3" />
        <Readout label="Antibodies" value={fmtInt(metrics?.rulesPromoted)} sub={metrics ? `${metrics.rulesCandidate} candidate · ${metrics.rulings} rulings` : undefined} size="sm" className="pl-3" />
      </div>
    </Panel>
  );
}

function median(xs: number[]): number {
  if (!xs.length) return 0;
  const s = xs.slice().sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m]! : (s[m - 1]! + s[m]!) / 2;
}

export function Gauges() {
  const { metrics } = useMetrics();
  const catchRate = metrics?.catchRate ?? 0;
  const fp = metrics?.fpRate ?? 0;
  // catch rate is a neutral meter; it turns green only at >= 99%. Red is reserved for breaches / false positives.
  const catchTone: Tone = metrics && catchRate >= 0.99 ? 'immune' : 'neutral';
  const fpTone: Tone = !metrics ? 'neutral' : fp === 0 ? 'immune' : 'breach';
  return (
    <Panel title="Gate accuracy" meta="corpus-wide" className="col-span-6 border-0 lg:col-span-3">
      <div className="flex h-full items-center justify-around gap-4">
        <Gauge value={catchRate} label="Catch rate" display={metrics ? fmtPct(catchRate, 1) : '—'} sub={metrics ? `${fmtInt(metrics.attacksBlocked)} / ${fmtInt(metrics.attacksTotal)}` : undefined} tone={catchTone} />
        <Gauge value={Math.min(1, fp * 20)} label="False positives" display={metrics ? fmtPct(fp, 2) : '—'} sub={metrics ? `${fmtInt(metrics.benignBlocked)} / ${fmtInt(metrics.benignTotal)}` : undefined} tone={fpTone} />
      </div>
    </Panel>
  );
}

export function Counters() {
  const { metrics: m } = useMetrics();
  return (
    <Panel title="Corpus" meta={m ? `${fmtInt(m.tracesTotal)} traces` : undefined} className="col-span-6 border-0 lg:col-span-4" flush>
      <div className="grid h-full grid-cols-3 grid-rows-2 [&>*]:border-b [&>*]:border-r [&>*]:border-line [&>*:nth-child(3n)]:border-r-0 [&>*:nth-child(n+4)]:border-b-0">
        <Readout label="Traces" value={<NumberTicker value={m?.tracesTotal ?? 0} />} />
        <Readout label="Attacks" value={<NumberTicker value={m?.attacksTotal ?? 0} />} />
        <Readout label="Blocked" value={<NumberTicker value={m?.attacksBlocked ?? 0} />} />
        <Readout label="Breaches" value={<NumberTicker value={m?.breaches ?? 0} />} tone={m && m.breaches > 0 ? 'breach' : 'neutral'} />
        <Readout label="Benign" value={<NumberTicker value={m?.benignTotal ?? 0} />} sub={m ? `${m.benignBlocked} blocked` : undefined} />
        <Readout label="Quarantined" value={<NumberTicker value={m?.quarantined ?? 0} />} tone={m && m.quarantined > 0 ? 'flag' : 'neutral'} sub={<Link href="/antibodies" className="hover:text-fg">{m ? `${m.rulesTotal} rules` : ''}</Link>} />
      </div>
    </Panel>
  );
}
