'use client';

import { useCallback, useEffect, useRef, useState } from 'react';

export interface PollState<T> {
  data: T | undefined;
  error: Error | undefined;
  loading: boolean;
  /** re-fetch now (de-duplicated while a request is in flight) */
  refresh: () => Promise<void>;
  /** optimistic local update */
  setData: (updater: (prev: T | undefined) => T | undefined) => void;
  lastUpdated: number | undefined;
}

/**
 * Minimal polling hook. `fetcher` must be stable (wrap with useCallback) or pass deps.
 * Interval 0 disables polling (fetch once).
 */
export function usePoll<T>(fetcher: () => Promise<T>, intervalMs = 0, deps: unknown[] = []): PollState<T> {
  const [data, setDataState] = useState<T | undefined>(undefined);
  const [error, setError] = useState<Error | undefined>(undefined);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<number | undefined>(undefined);
  const inflight = useRef<Promise<void> | null>(null);
  const mounted = useRef(true);
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;

  const refresh = useCallback(async () => {
    if (inflight.current) return inflight.current;
    const p = (async () => {
      try {
        const d = await fetcherRef.current();
        if (!mounted.current) return;
        setDataState(d);
        setError(undefined);
        setLastUpdated(Date.now());
      } catch (e) {
        if (!mounted.current) return;
        setError(e instanceof Error ? e : new Error(String(e)));
      } finally {
        if (mounted.current) setLoading(false);
        inflight.current = null;
      }
    })();
    inflight.current = p;
    return p;
  }, []);

  useEffect(() => {
    mounted.current = true;
    void refresh();
    if (!intervalMs) return () => { mounted.current = false; };
    const id = setInterval(() => {
      if (document.visibilityState === 'visible') void refresh();
    }, intervalMs);
    return () => {
      mounted.current = false;
      clearInterval(id);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [intervalMs, refresh, ...deps]);

  const setData = useCallback((updater: (prev: T | undefined) => T | undefined) => {
    setDataState((prev) => updater(prev));
  }, []);

  return { data, error, loading, refresh, setData, lastUpdated };
}

/** Ticks every `ms` so relative timestamps / running durations re-render. */
export function useNow(ms = 1000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), ms);
    return () => clearInterval(id);
  }, [ms]);
  return now;
}
