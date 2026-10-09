'use client';

import { useEffect, useRef, useState } from 'react';
import { animate, useMotionValue } from 'framer-motion';

/**
 * Animates between numeric values. `format` renders the live value.
 * Uses a motion value so re-renders are cheap and interruptions are smooth.
 */
export function NumberTicker({
  value,
  format = (v) => Math.round(v).toLocaleString('en-US'),
  durationS = 0.5,
  className,
}: {
  value: number;
  format?: (v: number) => string;
  durationS?: number;
  className?: string;
}) {
  const mv = useMotionValue(value);
  const [display, setDisplay] = useState(() => format(value));
  const first = useRef(true);
  const formatRef = useRef(format);
  formatRef.current = format;

  useEffect(() => {
    if (first.current) {
      first.current = false;
      mv.set(value);
      setDisplay(formatRef.current(value));
      return;
    }
    const controls = animate(mv, value, {
      duration: durationS,
      ease: [0, 0, 0.2, 1],
      onUpdate: (v) => setDisplay(formatRef.current(v)),
    });
    return () => controls.stop();
  }, [value, durationS, mv]);

  return (
    <span className={className} suppressHydrationWarning>
      {display}
    </span>
  );
}
