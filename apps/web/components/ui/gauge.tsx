'use client';

import { motion } from 'framer-motion';
import clsx from 'clsx';
import { TONE_HEX } from '@/components/ui/badge';
import type { Tone } from '@/lib/format';

/** Thin 270° meter. value in [0,1]. Fill carries severity; the track is the same hue, faded. */
export function Gauge({
  value,
  label,
  display,
  sub,
  tone = 'immune',
  size = 128,
  className,
}: {
  value: number;
  label: string;
  display: string;
  sub?: string;
  tone?: Tone;
  size?: number;
  className?: string;
}) {
  const v = Math.max(0, Math.min(1, Number.isFinite(value) ? value : 0));
  const stroke = 3;
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const arc = c * 0.75;
  const color = tone === 'neutral' ? '#e8e9eb' : TONE_HEX[tone];
  const track = tone === 'neutral' ? '#2a2c30' : color;
  const trackOpacity = tone === 'neutral' ? 1 : 0.18;
  return (
    <div className={clsx('relative flex flex-col items-center', className)} style={{ width: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="-rotate-[135deg]">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={track} strokeOpacity={trackOpacity} strokeWidth={stroke} strokeDasharray={`${arc} ${c}`} />
        <motion.circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeDasharray={`${arc} ${c}`}
          initial={{ strokeDashoffset: arc }}
          animate={{ strokeDashoffset: arc - arc * v }}
          transition={{ duration: 0.6, ease: [0, 0, 0.2, 1] }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <div className="mono-num text-[24px] font-light leading-none text-fg">{display}</div>
        {sub ? <div className="mono-num mt-1.5 text-[10.5px] text-fg-3">{sub}</div> : null}
      </div>
      <div className="label -mt-2">{label}</div>
    </div>
  );
}
