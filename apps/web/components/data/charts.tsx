'use client';

import { Area, Bar, BarChart, CartesianGrid, ComposedChart, Line, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import type { FamilyStat, TimelineBucket } from '@/lib/api';
import { FAMILY_META } from '@/lib/format';

/*
  Chart register: monochrome marks (fg-2 / fg-3) with one semantic colour (breach red) reserved
  for the thing that must be noticed. Hairline solid grid, mono axis ticks, crosshair tooltip.
*/
const INK = '#9aa0a6';
const INK_DIM = '#6b7075';
const INK_HI = '#e8e9eb';
const RED = '#e5484d';
const GRID = 'rgba(255,255,255,0.06)';
const TICK = { fill: INK_DIM, fontSize: 10, fontFamily: 'var(--font-jb-mono)' } as const;

interface TooltipRow {
  name?: string;
  value?: number | string;
  color?: string;
  dataKey?: string | number;
  stroke?: string;
  fill?: string;
}

function ChartTooltip({ active, payload, label, labelFormatter }: { active?: boolean; payload?: TooltipRow[]; label?: string | number; labelFormatter?: (l: string | number) => string }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="inset min-w-[150px] px-2.5 py-2 font-mono text-[11px]">
      <div className="mb-1 text-fg-3">{labelFormatter && label !== undefined ? labelFormatter(label) : String(label ?? '')}</div>
      {payload.map((p, i) => (
        <div key={i} className="flex items-center justify-between gap-4">
          <span className="flex items-center gap-1.5 text-fg-2">
            <span className="inline-block h-px w-3" style={{ background: p.stroke ?? p.color ?? p.fill ?? INK }} />
            {String(p.name ?? p.dataKey ?? '')}
          </span>
          <span className="tabular text-fg">{typeof p.value === 'number' ? p.value.toLocaleString('en-US', { maximumFractionDigits: 2 }) : String(p.value ?? '')}</span>
        </div>
      ))}
    </div>
  );
}

function Legend({ items }: { items: { label: string; color: string; kind: 'line' | 'rect' }[] }) {
  return (
    <div className="flex flex-wrap items-center gap-4 px-1 font-mono text-[10.5px] text-fg-2">
      {items.map((it) => (
        <span key={it.label} className="flex items-center gap-1.5">
          {it.kind === 'line' ? <span className="inline-block h-[2px] w-3" style={{ background: it.color }} /> : <span className="inline-block h-2 w-2" style={{ background: it.color }} />}
          {it.label}
        </span>
      ))}
    </div>
  );
}

const hhmm = (ts: number) => {
  const d = new Date(ts);
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
};

export function TimelineChart({ buckets, bucketSec }: { buckets: TimelineBucket[]; bucketSec: number }) {
  const data = buckets.map((b) => ({
    t: b.bucket,
    'events/s': Math.round(((b.attacks + b.benign) / bucketSec) * 100) / 100,
    'blocked/s': Math.round((b.blocked / bucketSec) * 100) / 100,
    'fp/s': Math.round((b.fp / bucketSec) * 100) / 100,
  }));
  if (!data.length) return <div className="flex h-[220px] items-center justify-center font-mono text-[11px] text-fg-3">no buckets in range</div>;
  return (
    <div>
      <Legend
        items={[
          { label: 'events/s', color: INK, kind: 'rect' },
          { label: 'blocked/s', color: INK_HI, kind: 'line' },
          { label: 'false positives/s', color: RED, kind: 'line' },
        ]}
      />
      <div className="mt-2 h-[220px]">
        <ResponsiveContainer width="100%" height="100%">
          <ComposedChart data={data} margin={{ top: 8, right: 12, bottom: 0, left: -12 }}>
            <CartesianGrid stroke={GRID} vertical={false} />
            <XAxis dataKey="t" tickFormatter={hhmm} tick={TICK} axisLine={{ stroke: GRID }} tickLine={false} minTickGap={32} />
            <YAxis tick={TICK} axisLine={false} tickLine={false} width={48} />
            <Tooltip content={<ChartTooltip labelFormatter={(l) => hhmm(Number(l))} />} cursor={{ stroke: 'rgba(255,255,255,0.28)', strokeWidth: 1 }} />
            <Area type="monotone" dataKey="events/s" stroke={INK} strokeWidth={1.5} fill={INK} fillOpacity={0.1} isAnimationActive={false} />
            <Line type="monotone" dataKey="blocked/s" stroke={INK_HI} strokeWidth={2} dot={false} isAnimationActive={false} />
            <Line type="monotone" dataKey="fp/s" stroke={RED} strokeWidth={2} dot={false} isAnimationActive={false} />
          </ComposedChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

export function FamilyChart({ families }: { families: FamilyStat[] }) {
  const data = families
    .filter((f) => f.family !== 'benign')
    .map((f) => ({
      family: FAMILY_META[f.family]?.short ?? f.family,
      blocked: f.blocked,
      flagged: Math.max(0, f.total - f.blocked - f.breached),
      breached: f.breached,
    }));
  const benign = families.find((f) => f.family === 'benign');
  if (!data.length) return <div className="flex h-[220px] items-center justify-center font-mono text-[11px] text-fg-3">no attack rows</div>;
  return (
    <div>
      <div className="flex items-center justify-between">
        <Legend
          items={[
            { label: 'blocked', color: INK, kind: 'rect' },
            { label: 'flagged / allowed', color: INK_DIM, kind: 'rect' },
            { label: 'breached', color: RED, kind: 'rect' },
          ]}
        />
        {benign ? (
          <span className="font-mono text-[10.5px] text-fg-3">
            benign {benign.total.toLocaleString()} · {benign.blocked} fp
          </span>
        ) : null}
      </div>
      <div className="mt-2 h-[220px]">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} layout="vertical" margin={{ top: 4, right: 16, bottom: 0, left: 8 }} barSize={14} barCategoryGap={8}>
            <CartesianGrid stroke={GRID} horizontal={false} />
            <XAxis type="number" tick={TICK} axisLine={{ stroke: GRID }} tickLine={false} />
            <YAxis type="category" dataKey="family" tick={{ ...TICK, fill: INK }} axisLine={false} tickLine={false} width={104} />
            <Tooltip content={<ChartTooltip />} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
            <Bar dataKey="blocked" stackId="a" fill={INK} isAnimationActive={false} stroke="#111214" strokeWidth={1} />
            <Bar dataKey="flagged" stackId="a" fill={INK_DIM} isAnimationActive={false} stroke="#111214" strokeWidth={1} />
            <Bar dataKey="breached" stackId="a" fill={RED} isAnimationActive={false} stroke="#111214" strokeWidth={1} radius={[0, 2, 2, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
