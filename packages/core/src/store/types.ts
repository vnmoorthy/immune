import type { AttackFamily, Decision, Trace } from '../types.js';

export type StoreKind = 'clickhouse' | 'memory';

export interface FamilyCount {
  family: string;
  label: string;
  total: number;
  /** decision != 'allow' */
  blocked: number;
  breached: number;
}

export interface TimelineBucket {
  /** bucket start, epoch ms */
  bucket: number;
  attacks: number;
  /** attacks with decision != 'allow' */
  blocked: number;
  benign: number;
  /** benign with decision != 'allow' (false positives) */
  fp: number;
}

export interface LatencyStats {
  p50: number;
  p95: number;
  avg: number;
  max: number;
  count: number;
  /** query time */
  ms: number;
}

export interface TraceFilter {
  label?: 'attack' | 'benign';
  family?: AttackFamily;
  sessionId?: string;
  decision?: Decision;
  breached?: boolean;
}

export const NAMED_QUERIES = ['families', 'timeline', 'top_destinations', 'latency', 'breaches'] as const;
export type NamedQuery = (typeof NAMED_QUERIES)[number];

export interface NamedQueryOptions {
  /** timeline bucket (default 60s) */
  bucketSec?: number;
  /** timeline lower bound, epoch ms (default now - 1h) */
  since?: number;
  /** row limit for top_destinations / breaches (default 20 / 50) */
  limit?: number;
}

export interface NamedQueryResult {
  name: NamedQuery;
  sql: string;
  rows: Record<string, unknown>[];
  ms: number;
}

export interface StoreStatus {
  kind: StoreKind;
  connected: boolean;
  url?: string;
  version?: string;
  rows?: number;
  detail?: string;
}

export interface QueryLogEntry {
  name: string;
  ms: number;
  ts: number;
  rows?: number;
}

/** Trace store. Every method measures its own latency (ms) and records it in `lastQueryMs` / `queryLog`. */
export interface Store {
  readonly kind: StoreKind;
  /** ms of the most recent query, null before any */
  readonly lastQueryMs: number | null;
  /** most recent queries, newest last (capped) */
  readonly queryLog: readonly QueryLogEntry[];
  init(): Promise<void>;
  insertTraces(traces: Trace[]): Promise<{ inserted: number; ms: number }>;
  /** the replay corpus: up to `limit` most recent traces (default 100k), ascending by ts */
  corpus(limit?: number): Promise<{ traces: Trace[]; ms: number }>;
  /** newest first */
  recent(limit: number, filter?: TraceFilter): Promise<{ traces: Trace[]; ms: number }>;
  countByFamily(): Promise<FamilyCount[]>;
  timeline(bucketSec: number, since: number): Promise<TimelineBucket[]>;
  count(): Promise<number>;
  latency(): Promise<LatencyStats>;
  reset(): Promise<void>;
  runNamedQuery(name: NamedQuery, opts?: NamedQueryOptions): Promise<NamedQueryResult>;
  status(): Promise<StoreStatus>;
  close(): Promise<void>;
}
