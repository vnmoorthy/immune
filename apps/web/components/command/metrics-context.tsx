'use client';

import { createContext, useContext, useEffect, useMemo, useRef } from 'react';
import type { Metrics } from '@immune/core';
import { api, type MetricsResponse } from '@/lib/api';
import { useImmuneEvents } from '@/lib/events';
import { usePoll } from '@/lib/use-poll';

interface MetricsCtx {
  metrics: MetricsResponse | undefined;
  loading: boolean;
  error: Error | undefined;
  refresh: () => Promise<void>;
}

const Ctx = createContext<MetricsCtx | null>(null);

export function MetricsProvider({ children }: { children: React.ReactNode }) {
  const poll = usePoll(() => api.metrics(), 6000);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useImmuneEvents((e) => {
    if (e.type === 'metrics') {
      const m = e.payload as Metrics;
      poll.setData((prev) => (prev ? { ...prev, ...m } : prev));
    }
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => void poll.refresh(), 400);
  }, ['metrics', 'remediation', 'rule', 'quarantine', 'breach']);

  useEffect(() => () => {
    if (timer.current) clearTimeout(timer.current);
  }, []);

  const value = useMemo<MetricsCtx>(() => ({ metrics: poll.data, loading: poll.loading, error: poll.error, refresh: poll.refresh }), [poll.data, poll.loading, poll.error, poll.refresh]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useMetrics(): MetricsCtx {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error('useMetrics must be used inside <MetricsProvider>');
  return ctx;
}
