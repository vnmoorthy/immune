/**
 * MemoryStore — in-process Store with the same semantics (and displayed SQL) as the ClickHouse store.
 */
import { performance } from 'node:perf_hooks';
import type { Trace } from '../types.js';
import { extractHosts } from '../detectors/destination.js';
import { namedQuerySql, resolveQueryOptions } from './sql.js';
import type {
  FamilyCount,
  LatencyStats,
  NamedQuery,
  NamedQueryOptions,
  NamedQueryResult,
  QueryLogEntry,
  Store,
  StoreStatus,
  TimelineBucket,
  TraceFilter,
} from './types.js';

export const QUERY_LOG_MAX = 200;

export function percentileOf(sorted: number[], p: number): number {
  if (!sorted.length) return 0;
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[idx]!;
}

export function matchesFilter(t: Trace, f?: TraceFilter): boolean {
  if (!f) return true;
  if (f.label && t.label !== f.label) return false;
  if (f.family && t.family !== f.family) return false;
  if (f.sessionId && t.sessionId !== f.sessionId) return false;
  if (f.decision && t.decision !== f.decision) return false;
  if (f.breached !== undefined && t.breached !== f.breached) return false;
  return true;
}

/** Shared in-JS implementations of the aggregate queries (used by MemoryStore and by tests). */
export function aggregateFamilies(traces: Iterable<Trace>): FamilyCount[] {
  const map = new Map<string, FamilyCount>();
  for (const t of traces) {
    const key = `${t.family}|${t.label}`;
    let row = map.get(key);
    if (!row) {
      row = { family: t.family, label: t.label, total: 0, blocked: 0, breached: 0 };
      map.set(key, row);
    }
    row.total++;
    if (t.decision !== 'allow') row.blocked++;
    if (t.breached) row.breached++;
  }
  return [...map.values()].sort((a, b) => b.total - a.total || a.family.localeCompare(b.family) || a.label.localeCompare(b.label));
}

export function aggregateTimeline(traces: Iterable<Trace>, bucketSec: number, since: number): TimelineBucket[] {
  const bucketMs = Math.max(1, Math.floor(bucketSec)) * 1000;
  const map = new Map<number, TimelineBucket>();
  for (const t of traces) {
    if (t.ts < since) continue;
    const bucket = Math.floor(t.ts / bucketMs) * bucketMs;
    let row = map.get(bucket);
    if (!row) {
      row = { bucket, attacks: 0, blocked: 0, benign: 0, fp: 0 };
      map.set(bucket, row);
    }
    if (t.label === 'attack') {
      row.attacks++;
      if (t.decision !== 'allow') row.blocked++;
    } else {
      row.benign++;
      if (t.decision !== 'allow') row.fp++;
    }
  }
  return [...map.values()].sort((a, b) => a.bucket - b.bucket);
}

export function aggregateLatency(traces: Iterable<Trace>): Omit<LatencyStats, 'ms'> {
  const values: number[] = [];
  for (const t of traces) values.push(t.latencyMs ?? 0);
  values.sort((a, b) => a - b);
  const count = values.length;
  const sum = values.reduce((a, b) => a + b, 0);
  return { p50: percentileOf(values, 50), p95: percentileOf(values, 95), avg: count ? sum / count : 0, max: count ? values[count - 1]! : 0, count };
}

export function aggregateDestinations(traces: Iterable<Trace>, limit: number): Record<string, unknown>[] {
  const map = new Map<string, { host: string; calls: number; blocked: number; allowed: number }>();
  for (const t of traces) {
    if (!t.attemptedCall) continue;
    const hosts = new Set(extractHosts(t.attemptedCall.args).filter((h) => h.source === 'url').map((h) => h.host));
    for (const host of hosts) {
      let row = map.get(host);
      if (!row) {
        row = { host, calls: 0, blocked: 0, allowed: 0 };
        map.set(host, row);
      }
      row.calls++;
      if (t.decision === 'block' || t.decision === 'quarantine') row.blocked++;
      if (t.decision === 'allow') row.allowed++;
    }
  }
  return [...map.values()].sort((a, b) => b.calls - a.calls || a.host.localeCompare(b.host)).slice(0, limit);
}

export class MemoryStore implements Store {
  readonly kind = 'memory' as const;
  lastQueryMs: number | null = null;
  readonly queryLog: QueryLogEntry[] = [];
  private traces: Trace[] = [];
  private readonly maxRows: number;

  constructor(opts: { maxRows?: number } = {}) {
    this.maxRows = opts.maxRows ?? 250_000;
  }

  async init(): Promise<void> {
    /* nothing to do */
  }

  async insertTraces(traces: Trace[]): Promise<{ inserted: number; ms: number }> {
    const t0 = performance.now();
    for (const t of traces) this.traces.push(t);
    if (this.traces.length > this.maxRows) this.traces.splice(0, this.traces.length - this.maxRows);
    const ms = this.done('insertTraces', t0, traces.length);
    return { inserted: traces.length, ms };
  }

  async corpus(limit = 100_000): Promise<{ traces: Trace[]; ms: number }> {
    const t0 = performance.now();
    const sorted = [...this.traces].sort((a, b) => a.ts - b.ts || a.id.localeCompare(b.id));
    const traces = sorted.length > limit ? sorted.slice(sorted.length - limit) : sorted;
    const ms = this.done('corpus', t0, traces.length);
    return { traces, ms };
  }

  async recent(limit: number, filter?: TraceFilter): Promise<{ traces: Trace[]; ms: number }> {
    const t0 = performance.now();
    const traces = this.traces
      .filter((t) => matchesFilter(t, filter))
      .sort((a, b) => b.ts - a.ts || b.id.localeCompare(a.id))
      .slice(0, Math.max(0, limit));
    const ms = this.done('recent', t0, traces.length);
    return { traces, ms };
  }

  async countByFamily(): Promise<FamilyCount[]> {
    const t0 = performance.now();
    const rows = aggregateFamilies(this.traces);
    this.done('countByFamily', t0, rows.length);
    return rows;
  }

  async timeline(bucketSec: number, since: number): Promise<TimelineBucket[]> {
    const t0 = performance.now();
    const rows = aggregateTimeline(this.traces, bucketSec, since);
    this.done('timeline', t0, rows.length);
    return rows;
  }

  async count(): Promise<number> {
    const t0 = performance.now();
    const n = this.traces.length;
    this.done('count', t0, 1);
    return n;
  }

  async latency(): Promise<LatencyStats> {
    const t0 = performance.now();
    const stats = aggregateLatency(this.traces);
    const ms = this.done('latency', t0, 1);
    return { ...stats, ms };
  }

  async reset(): Promise<void> {
    const t0 = performance.now();
    this.traces = [];
    this.done('reset', t0, 0);
  }

  async runNamedQuery(name: NamedQuery, opts: NamedQueryOptions = {}): Promise<NamedQueryResult> {
    const t0 = performance.now();
    const o = resolveQueryOptions(name, opts);
    const sql = namedQuerySql(name, o);
    let rows: Record<string, unknown>[];
    switch (name) {
      case 'families':
        rows = aggregateFamilies(this.traces) as unknown as Record<string, unknown>[];
        break;
      case 'timeline':
        rows = aggregateTimeline(this.traces, o.bucketMs / 1000, o.since) as unknown as Record<string, unknown>[];
        break;
      case 'top_destinations':
        rows = aggregateDestinations(this.traces, o.limit);
        break;
      case 'latency':
        rows = [aggregateLatency(this.traces) as unknown as Record<string, unknown>];
        break;
      case 'breaches':
        rows = this.traces
          .filter((t) => t.breached)
          .sort((a, b) => b.ts - a.ts)
          .slice(0, o.limit)
          .map((t) => ({ id: t.id, ts: t.ts, session_id: t.sessionId, family: t.family, variant: t.variant, decision: t.decision, blocked_by: t.blockedBy ?? '', latency_ms: t.latencyMs }));
        break;
      default:
        throw new Error(`unknown named query: ${String(name)}`);
    }
    const ms = this.done(`query:${name}`, t0, rows.length);
    return { name, sql, rows, ms };
  }

  async status(): Promise<StoreStatus> {
    return { kind: 'memory', connected: true, rows: this.traces.length, detail: 'in-process memory store (ClickHouse not reachable or disabled)' };
  }

  async close(): Promise<void> {
    /* nothing to do */
  }

  private done(name: string, t0: number, rows?: number): number {
    const ms = Math.round((performance.now() - t0) * 1000) / 1000;
    this.lastQueryMs = ms;
    this.queryLog.push({ name, ms, ts: Date.now(), rows });
    if (this.queryLog.length > QUERY_LOG_MAX) this.queryLog.splice(0, this.queryLog.length - QUERY_LOG_MAX);
    return ms;
  }
}
