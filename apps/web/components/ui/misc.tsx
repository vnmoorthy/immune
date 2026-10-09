import clsx from 'clsx';
import { Loader2 } from 'lucide-react';
import type { ReactNode } from 'react';

export function KV({ rows, className }: { rows: { k: ReactNode; v: ReactNode; mono?: boolean }[]; className?: string }) {
  return (
    <dl className={clsx('grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-[12px]', className)}>
      {rows.map((r, i) => (
        <div key={i} className="contents">
          <dt className="text-fg-3">{r.k}</dt>
          <dd className={clsx('min-w-0 break-words text-fg', r.mono !== false && 'font-mono text-[11.5px]')}>{r.v}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Empty({ title, hint, action, className }: { title: ReactNode; hint?: ReactNode; action?: ReactNode; className?: string }) {
  return (
    <div className={clsx('flex flex-col items-center justify-center gap-1.5 py-8 text-center', className)}>
      <div className="text-[12.5px] text-fg-2">{title}</div>
      {hint ? <div className="max-w-sm font-mono text-[11px] text-fg-3">{hint}</div> : null}
      {action ? <div className="mt-2">{action}</div> : null}
    </div>
  );
}

export function Spinner({ className }: { className?: string }) {
  return <Loader2 className={clsx('h-3.5 w-3.5 animate-spin text-fg-3', className)} />;
}

/** label + large thin mono value */
export function Readout({ label, value, sub, tone, size = 'md', className }: { label: ReactNode; value: ReactNode; sub?: ReactNode; tone?: 'immune' | 'breach' | 'flag' | 'info' | 'neutral'; size?: 'sm' | 'md' | 'lg'; className?: string }) {
  return (
    <div className={clsx('min-w-0 px-3 py-2', className)}>
      <div className="label truncate">{label}</div>
      <div
        className={clsx(
          'mono-num mt-1 font-light leading-none',
          size === 'sm' && 'text-[18px]',
          size === 'md' && 'text-[22px]',
          size === 'lg' && 'text-[28px]',
          tone === 'immune' && 'text-immune',
          tone === 'breach' && 'text-breach',
          tone === 'flag' && 'text-flag',
          tone === 'info' && 'text-info',
          (!tone || tone === 'neutral') && 'text-fg',
        )}
      >
        {value}
      </div>
      {sub ? <div className="mono-num mt-1 truncate text-[10.5px] text-fg-3">{sub}</div> : null}
    </div>
  );
}

export function Mono({ children, className, dim }: { children: ReactNode; className?: string; dim?: boolean }) {
  return <span className={clsx('font-mono', dim ? 'text-fg-3' : 'text-fg-2', className)}>{children}</span>;
}

export function Sparkline({ values, width = 120, height = 24, stroke = '#9aa0a6', accent, className }: { values: number[]; width?: number; height?: number; stroke?: string; accent?: string; className?: string }) {
  if (values.length < 2) return <svg width={width} height={height} className={className} />;
  const max = Math.max(...values, 1);
  const min = Math.min(...values, 0);
  const span = max - min || 1;
  const pts = values.map((v, i) => {
    const x = (i / (values.length - 1)) * (width - 4) + 2;
    const y = height - 3 - ((v - min) / span) * (height - 6);
    return [x, y] as const;
  });
  const last = pts[pts.length - 1]!;
  return (
    <svg width={width} height={height} className={className} aria-hidden>
      <polyline points={pts.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(' ')} fill="none" stroke={stroke} strokeWidth={1.5} strokeLinejoin="round" strokeLinecap="round" />
      <circle cx={last[0]} cy={last[1]} r={2.5} fill={accent ?? stroke} stroke="#111214" strokeWidth={1.5} />
    </svg>
  );
}

export function Hairline({ className }: { className?: string }) {
  return <div className={clsx('h-px w-full bg-line', className)} />;
}

/** Inline keyboard/ID chip */
export function Id({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={clsx('font-mono text-[11px] text-fg-2', className)}>{children}</span>;
}
