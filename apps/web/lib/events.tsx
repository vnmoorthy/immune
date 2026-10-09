'use client';

/**
 * One EventSource for the whole app (/api/events). Components subscribe with useImmuneEvents().
 * Keeps a bounded ring buffer of recent events so late-mounting panels can hydrate.
 */
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import type { ImmuneEvent, ImmuneEventType } from '@immune/core';
import { MOCK } from './api';

type Handler = (e: ImmuneEvent) => void;

interface EventsContextValue {
  connected: boolean;
  subscribe: (h: Handler) => () => void;
  recent: () => ImmuneEvent[];
  eventsPerSec: number;
  lastEventAt: number | undefined;
  reconnects: number;
}

const EventsContext = createContext<EventsContextValue | null>(null);

const RING = 400;

export function EventsProvider({ children }: { children: React.ReactNode }) {
  const [connected, setConnected] = useState(false);
  const [eventsPerSec, setEps] = useState(0);
  const [lastEventAt, setLastEventAt] = useState<number | undefined>(undefined);
  const [reconnects, setReconnects] = useState(0);
  const handlers = useRef(new Set<Handler>());
  const ring = useRef<ImmuneEvent[]>([]);
  const stamps = useRef<number[]>([]);

  const dispatch = useCallback((e: ImmuneEvent) => {
    ring.current.push(e);
    if (ring.current.length > RING) ring.current.splice(0, ring.current.length - RING);
    stamps.current.push(Date.now());
    setLastEventAt(e.ts);
    handlers.current.forEach((h) => {
      try {
        h(e);
      } catch (err) {
        console.error('[immune] event handler failed', err);
      }
    });
  }, []);

  useEffect(() => {
    const id = setInterval(() => {
      const cutoff = Date.now() - 5000;
      stamps.current = stamps.current.filter((t) => t >= cutoff);
      setEps(Math.round((stamps.current.length / 5) * 10) / 10);
    }, 1000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    if (MOCK) {
      let stop: (() => void) | undefined;
      setConnected(true);
      void import('./fixtures').then((m) => {
        stop = m.startMockEvents(dispatch);
      });
      return () => stop?.();
    }
    let es: EventSource | null = null;
    let closed = false;
    let attempt = 0;
    let retryTimer: ReturnType<typeof setTimeout> | undefined;

    const open = () => {
      if (closed) return;
      es = new EventSource('/api/events');
      es.onopen = () => {
        setConnected(true);
        if (attempt > 0) setReconnects((n) => n + 1);
        attempt = 0;
      };
      es.onmessage = (msg) => {
        try {
          const parsed = JSON.parse(msg.data) as ImmuneEvent;
          if (parsed && typeof parsed === 'object' && 'type' in parsed) dispatch(parsed);
        } catch {
          /* ignore malformed frames */
        }
      };
      es.onerror = () => {
        setConnected(false);
        es?.close();
        es = null;
        attempt += 1;
        const backoff = Math.min(8000, 500 * 2 ** Math.min(attempt, 4));
        retryTimer = setTimeout(open, backoff);
      };
    };
    open();
    return () => {
      closed = true;
      if (retryTimer) clearTimeout(retryTimer);
      es?.close();
    };
  }, [dispatch]);

  const value = useMemo<EventsContextValue>(
    () => ({
      connected,
      eventsPerSec,
      lastEventAt,
      reconnects,
      subscribe: (h) => {
        handlers.current.add(h);
        return () => {
          handlers.current.delete(h);
        };
      },
      recent: () => ring.current.slice(),
    }),
    [connected, eventsPerSec, lastEventAt, reconnects],
  );

  return <EventsContext.Provider value={value}>{children}</EventsContext.Provider>;
}

export function useEventsConnection() {
  const ctx = useContext(EventsContext);
  if (!ctx) throw new Error('useEventsConnection must be used inside <EventsProvider>');
  return ctx;
}

/**
 * Subscribe to live events. `handler` is kept in a ref so callers do not need useCallback.
 * Pass `types` to filter.
 */
export function useImmuneEvents(handler: Handler, types?: ImmuneEventType[]) {
  const ctx = useContext(EventsContext);
  if (!ctx) throw new Error('useImmuneEvents must be used inside <EventsProvider>');
  const ref = useRef(handler);
  ref.current = handler;
  const key = types?.join('|') ?? '*';
  useEffect(() => {
    const allowed = key === '*' ? null : new Set(key.split('|'));
    return ctx.subscribe((e) => {
      if (allowed && !allowed.has(e.type)) return;
      ref.current(e);
    });
  }, [ctx, key]);
}

/** Recent events of the given types, kept in state so the list re-renders live. */
export function useRecentEvents(types: ImmuneEventType[], limit = 200, paused = false): ImmuneEvent[] {
  const ctx = useContext(EventsContext);
  if (!ctx) throw new Error('useRecentEvents must be used inside <EventsProvider>');
  const allowed = useMemo(() => new Set(types), [types]);
  const [events, setEvents] = useState<ImmuneEvent[]>(() => ctx.recent().filter((e) => allowed.has(e.type)).slice(-limit).reverse());
  const pausedRef = useRef(paused);
  pausedRef.current = paused;
  useEffect(() => {
    return ctx.subscribe((e) => {
      if (!allowed.has(e.type) || pausedRef.current) return;
      setEvents((prev) => {
        const next = [e, ...prev];
        return next.length > limit ? next.slice(0, limit) : next;
      });
    });
  }, [ctx, allowed, limit]);
  return events;
}
