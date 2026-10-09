/**
 * ClickHouse DDL + named-query SQL. The memory store displays the same SQL it emulates.
 */
import type { NamedQuery, NamedQueryOptions } from './types.js';

export const CLICKHOUSE_DATABASE = 'immune';
export const TRACES_TABLE = 'traces';
export const TRACES_FQN = `${CLICKHOUSE_DATABASE}.${TRACES_TABLE}`;

export const CREATE_DATABASE_SQL = `CREATE DATABASE IF NOT EXISTS ${CLICKHOUSE_DATABASE}`;

export const CREATE_TABLE_SQL = `CREATE TABLE IF NOT EXISTS ${TRACES_FQN} (
  id String,
  session_id String,
  ts DateTime64(3, 'UTC'),
  family LowCardinality(String),
  variant String,
  label LowCardinality(String),
  decision LowCardinality(String),
  breached UInt8,
  tainted UInt8,
  blocked_by String,
  citation String,
  latency_ms Float64,
  findings String,
  tool_def String,
  result String,
  attempted_call String
) ENGINE = MergeTree
ORDER BY (ts, id)`;

export const SELECT_TRACE_COLUMNS = `id, session_id, toUnixTimestamp64Milli(ts) AS ts, family, variant, label, decision, breached, tainted, blocked_by, citation, latency_ms, findings, tool_def, result, attempted_call`;

export interface ResolvedQueryOptions {
  bucketMs: number;
  since: number;
  limit: number;
}

export function resolveQueryOptions(name: NamedQuery, opts: NamedQueryOptions = {}, now = Date.now()): ResolvedQueryOptions {
  const bucketSec = Math.max(1, Math.floor(opts.bucketSec ?? 60));
  return {
    bucketMs: bucketSec * 1000,
    since: Math.max(0, Math.floor(opts.since ?? now - 3_600_000)),
    limit: Math.max(1, Math.floor(opts.limit ?? (name === 'breaches' ? 50 : 20))),
  };
}

/** The SQL for a named query with literal parameters substituted (numbers only — safe to interpolate). */
export function namedQuerySql(name: NamedQuery, o: ResolvedQueryOptions): string {
  switch (name) {
    case 'families':
      return `SELECT family, label, count() AS total, countIf(decision != 'allow') AS blocked, countIf(breached = 1) AS breached
FROM ${TRACES_FQN}
GROUP BY family, label
ORDER BY total DESC, family, label`;
    case 'timeline':
      return `SELECT intDiv(toUnixTimestamp64Milli(ts), ${o.bucketMs}) * ${o.bucketMs} AS bucket,
       countIf(label = 'attack') AS attacks,
       countIf(label = 'attack' AND decision != 'allow') AS blocked,
       countIf(label = 'benign') AS benign,
       countIf(label = 'benign' AND decision != 'allow') AS fp
FROM ${TRACES_FQN}
WHERE ts >= fromUnixTimestamp64Milli(toInt64(${o.since}))
GROUP BY bucket
ORDER BY bucket`;
    case 'top_destinations':
      return `SELECT host, count() AS calls, countIf(decision IN ('block', 'quarantine')) AS blocked, countIf(decision = 'allow') AS allowed
FROM (
  SELECT decision, arrayJoin(extractAll(attempted_call, '(?i)https?://([a-z0-9.-]+)')) AS host
  FROM ${TRACES_FQN}
  WHERE attempted_call != ''
)
GROUP BY host
ORDER BY calls DESC, host
LIMIT ${o.limit}`;
    case 'latency':
      return `SELECT quantile(0.5)(latency_ms) AS p50, quantile(0.95)(latency_ms) AS p95, avg(latency_ms) AS avg, max(latency_ms) AS max, count() AS count
FROM ${TRACES_FQN}`;
    case 'breaches':
      return `SELECT id, toUnixTimestamp64Milli(ts) AS ts, session_id, family, variant, decision, blocked_by, latency_ms
FROM ${TRACES_FQN}
WHERE breached = 1
ORDER BY ts DESC
LIMIT ${o.limit}`;
    default:
      throw new Error(`unknown named query: ${String(name)}`);
  }
}
