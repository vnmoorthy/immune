/**
 * ClickHouseStore — traces in `immune.traces` (MergeTree ORDER BY (ts, id), JSON columns as String).
 * HTTP client (@clickhouse/client), batched JSONEachRow inserts, every query measured.
 * createStore() picks ClickHouse when GET /ping answers within 1500ms, else MemoryStore.
 */
import { performance } from 'node:perf_hooks';
import { createClient, type ClickHouseClient } from '@clickhouse/client';
import type { AttackFamily, Capability, Decision, Finding, Trace } from '../types.js';
import { MemoryStore, QUERY_LOG_MAX } from './memory.js';
import { CREATE_DATABASE_SQL, CREATE_TABLE_SQL, SELECT_TRACE_COLUMNS, TRACES_FQN, namedQuerySql, resolveQueryOptions } from './sql.js';
import type {
  FamilyCount,
  LatencyStats,
  NamedQuery,
  NamedQueryOptions,
  NamedQueryResult,
  QueryLogEntry,
  Store,
  StoreKind,
  StoreStatus,
  TimelineBucket,
  TraceFilter,
} from './types.js';

export const DEFAULT_CLICKHOUSE_URL = 'http://localhost:8123';
export const CLICKHOUSE_PING_TIMEOUT_MS = 1500;

export interface ClickHouseStoreOptions {
  /** HTTP url (default env CLICKHOUSE_URL or http://localhost:8123) */
  url?: string;
  username?: string;
  password?: string;
  requestTimeoutMs?: number;
  /** rows per INSERT (default 5000) */
  batchSize?: number;
}

export interface TraceRow {
  id: string;
  session_id: string;
  ts: string | number;
  family: string;
  variant: string;
  label: string;
  decision: string;
  breached: number;
  tainted: number;
  blocked_by: string;
  citation: string;
  latency_ms: number;
  findings: string;
  tool_def: string;
  result: string;
  attempted_call: string;
}

export function clickhouseUrl(env: NodeJS.ProcessEnv = process.env): string {
  return (env.CLICKHOUSE_URL && env.CLICKHOUSE_URL.trim()) || DEFAULT_CLICKHOUSE_URL;
}

/** 'YYYY-MM-DD HH:mm:ss.SSS' in UTC — what DateTime64(3, 'UTC') expects in JSONEachRow. */
export function formatDateTime64(ms: number): string {
  const d = new Date(Number.isFinite(ms) ? ms : 0);
  const p = (n: number, w = 2) => String(n).padStart(w, '0');
  return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}.${p(d.getUTCMilliseconds(), 3)}`;
}

function json(value: unknown): string {
  if (value === undefined || value === null) return '';
  try {
    return JSON.stringify(value);
  } catch {
    return '';
  }
}

function parseJson<T>(s: unknown, fallback: T): T {
  if (typeof s !== 'string' || !s) return fallback;
  try {
    return JSON.parse(s) as T;
  } catch {
    return fallback;
  }
}

export function traceToRow(t: Trace): TraceRow {
  return {
    id: t.id,
    session_id: t.sessionId,
    ts: formatDateTime64(t.ts),
    family: t.family,
    variant: t.variant,
    label: t.label,
    decision: t.decision,
    breached: t.breached ? 1 : 0,
    tainted: t.tainted ? 1 : 0,
    blocked_by: t.blockedBy ?? '',
    citation: t.citation ?? '',
    latency_ms: Number.isFinite(t.latencyMs) ? t.latencyMs : 0,
    findings: json(t.findings ?? []),
    tool_def: t.toolDef ? json(t.toolDef) : '',
    result: t.result ? json(t.result) : '',
    attempted_call: t.attemptedCall ? json(t.attemptedCall) : '',
  };
}

export function rowToTrace(r: Record<string, unknown>): Trace {
  const trace: Trace = {
    id: String(r.id ?? ''),
    sessionId: String(r.session_id ?? ''),
    ts: Number(r.ts ?? 0),
    family: String(r.family ?? 'benign') as AttackFamily,
    variant: String(r.variant ?? ''),
    label: (String(r.label ?? 'benign') === 'attack' ? 'attack' : 'benign'),
    tainted: Number(r.tainted ?? 0) === 1,
    findings: parseJson<Finding[]>(r.findings, []),
    decision: String(r.decision ?? 'allow') as Decision,
    breached: Number(r.breached ?? 0) === 1,
    latencyMs: Number(r.latency_ms ?? 0),
  };
  const blockedBy = String(r.blocked_by ?? '');
  if (blockedBy) trace.blockedBy = blockedBy;
  const citation = String(r.citation ?? '');
  if (citation) trace.citation = citation;
  const toolDef = parseJson<Trace['toolDef'] | undefined>(r.tool_def, undefined);
  if (toolDef) trace.toolDef = toolDef;
  const result = parseJson<Trace['result'] | undefined>(r.result, undefined);
  if (result) trace.result = result;
  const call = parseJson<Trace['attemptedCall'] | undefined>(r.attempted_call, undefined);
  if (call) trace.attemptedCall = { ...call, capabilities: (call.capabilities ?? []) as Capability[] };
  return trace;
}

export class ClickHouseStore implements Store {
  readonly kind = 'clickhouse' as const;
  readonly url: string;
  lastQueryMs: number | null = null;
  readonly queryLog: QueryLogEntry[] = [];
  version?: string;
  private readonly client: ClickHouseClient;
  private readonly batchSize: number;
  private initialized = false;

  constructor(opts: ClickHouseStoreOptions = {}) {
    this.url = opts.url ?? clickhouseUrl();
    this.batchSize = Math.max(1, opts.batchSize ?? 5000);
    this.client = createClient({
      url: this.url,
      username: opts.username ?? process.env.CLICKHOUSE_USER ?? 'default',
      password: opts.password ?? process.env.CLICKHOUSE_PASSWORD ?? '',
      request_timeout: opts.requestTimeoutMs ?? 30_000,
      clickhouse_settings: { output_format_json_quote_64bit_integers: 0, date_time_input_format: 'best_effort' },
      application: 'immune',
    });
  }

  async init(): Promise<void> {
    const t0 = performance.now();
    await this.client.command({ query: CREATE_DATABASE_SQL });
    await this.client.command({ query: CREATE_TABLE_SQL });
    try {
      const rs = await this.client.query({ query: 'SELECT version() AS v', format: 'JSONEachRow' });
      const rows = await rs.json<{ v: string }>();
      this.version = rows[0]?.v;
    } catch {
      /* version is informational */
    }
    this.initialized = true;
    this.done('init', t0);
  }

  async insertTraces(traces: Trace[]): Promise<{ inserted: number; ms: number }> {
    const t0 = performance.now();
    let inserted = 0;
    for (let i = 0; i < traces.length; i += this.batchSize) {
      const chunk = traces.slice(i, i + this.batchSize).map(traceToRow);
      await this.client.insert({ table: TRACES_FQN, values: chunk, format: 'JSONEachRow' });
      inserted += chunk.length;
    }
    const ms = this.done('insertTraces', t0, inserted);
    return { inserted, ms };
  }

  async corpus(limit = 100_000): Promise<{ traces: Trace[]; ms: number }> {
    const t0 = performance.now();
    const rows = await this.rows(`SELECT ${SELECT_TRACE_COLUMNS} FROM ${TRACES_FQN} ORDER BY ts DESC, id DESC LIMIT {limit:UInt32}`, { limit: Math.max(0, Math.floor(limit)) });
    const traces = rows.map(rowToTrace).reverse();
    const ms = this.done('corpus', t0, traces.length);
    return { traces, ms };
  }

  async recent(limit: number, filter: TraceFilter = {}): Promise<{ traces: Trace[]; ms: number }> {
    const t0 = performance.now();
    const where: string[] = [];
    const params: Record<string, unknown> = { limit: Math.max(0, Math.floor(limit)) };
    if (filter.label) {
      where.push('label = {label:String}');
      params.label = filter.label;
    }
    if (filter.family) {
      where.push('family = {family:String}');
      params.family = filter.family;
    }
    if (filter.sessionId) {
      where.push('session_id = {sessionId:String}');
      params.sessionId = filter.sessionId;
    }
    if (filter.decision) {
      where.push('decision = {decision:String}');
      params.decision = filter.decision;
    }
    if (filter.breached !== undefined) {
      where.push('breached = {breached:UInt8}');
      params.breached = filter.breached ? 1 : 0;
    }
    const sql = `SELECT ${SELECT_TRACE_COLUMNS} FROM ${TRACES_FQN}${where.length ? ` WHERE ${where.join(' AND ')}` : ''} ORDER BY ts DESC, id DESC LIMIT {limit:UInt32}`;
    const rows = await this.rows(sql, params);
    const traces = rows.map(rowToTrace);
    const ms = this.done('recent', t0, traces.length);
    return { traces, ms };
  }

  async countByFamily(): Promise<FamilyCount[]> {
    const t0 = performance.now();
    const rows = await this.rows(namedQuerySql('families', resolveQueryOptions('families')));
    const out = rows.map((r) => ({ family: String(r.family), label: String(r.label), total: Number(r.total), blocked: Number(r.blocked), breached: Number(r.breached) }));
    this.done('countByFamily', t0, out.length);
    return out;
  }

  async timeline(bucketSec: number, since: number): Promise<TimelineBucket[]> {
    const t0 = performance.now();
    const rows = await this.rows(namedQuerySql('timeline', resolveQueryOptions('timeline', { bucketSec, since })));
    const out = rows.map((r) => ({ bucket: Number(r.bucket), attacks: Number(r.attacks), blocked: Number(r.blocked), benign: Number(r.benign), fp: Number(r.fp) }));
    this.done('timeline', t0, out.length);
    return out;
  }

  async count(): Promise<number> {
    const t0 = performance.now();
    const rows = await this.rows(`SELECT count() AS c FROM ${TRACES_FQN}`);
    const n = Number(rows[0]?.c ?? 0);
    this.done('count', t0, 1);
    return n;
  }

  async latency(): Promise<LatencyStats> {
    const t0 = performance.now();
    const rows = await this.rows(namedQuerySql('latency', resolveQueryOptions('latency')));
    const r = rows[0] ?? {};
    const ms = this.done('latency', t0, 1);
    return { p50: num(r.p50), p95: num(r.p95), avg: num(r.avg), max: num(r.max), count: num(r.count), ms };
  }

  async reset(): Promise<void> {
    const t0 = performance.now();
    await this.client.command({ query: `TRUNCATE TABLE IF EXISTS ${TRACES_FQN}` });
    this.done('reset', t0, 0);
  }

  async runNamedQuery(name: NamedQuery, opts: NamedQueryOptions = {}): Promise<NamedQueryResult> {
    const t0 = performance.now();
    const sql = namedQuerySql(name, resolveQueryOptions(name, opts));
    const rows = (await this.rows(sql)).map((r) => {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(r)) out[k] = typeof v === 'string' && /^-?\d+(\.\d+)?$/.test(v) && k !== 'id' && k !== 'session_id' && k !== 'variant' ? Number(v) : v;
      return out;
    });
    const ms = this.done(`query:${name}`, t0, rows.length);
    return { name, sql, rows, ms };
  }

  async status(): Promise<StoreStatus> {
    try {
      const ping = await this.client.ping();
      if (!ping.success) return { kind: 'clickhouse', connected: false, url: this.url, detail: `ping failed: ${ping.error?.message ?? 'unknown'}` };
      const rows = this.initialized ? await this.count() : undefined;
      return { kind: 'clickhouse', connected: true, url: this.url, version: this.version, rows, detail: `ClickHouse ${this.version ?? ''} at ${this.url} (${TRACES_FQN})`.replace(/\s+/g, ' ') };
    } catch (err) {
      return { kind: 'clickhouse', connected: false, url: this.url, detail: (err as Error)?.message ?? String(err) };
    }
  }

  async close(): Promise<void> {
    await this.client.close();
  }

  /** Run a raw SELECT (JSONEachRow). Exposed for the /data panel's ad-hoc display; measured. */
  async rawQuery(sql: string, params?: Record<string, unknown>): Promise<{ rows: Record<string, unknown>[]; ms: number }> {
    const t0 = performance.now();
    const rows = await this.rows(sql, params);
    const ms = this.done('rawQuery', t0, rows.length);
    return { rows, ms };
  }

  /** Run a statement without a result set (DDL / ALTER … DELETE, synchronous mutations). Measured. */
  async rawCommand(query: string, params?: Record<string, unknown>): Promise<{ ms: number }> {
    const t0 = performance.now();
    await this.client.command({ query, query_params: params, clickhouse_settings: { mutations_sync: '1' } });
    return { ms: this.done('rawCommand', t0) };
  }

  private async rows(query: string, query_params?: Record<string, unknown>): Promise<Record<string, unknown>[]> {
    const rs = await this.client.query({ query, query_params, format: 'JSONEachRow' });
    return rs.json<Record<string, unknown>>();
  }

  private done(name: string, t0: number, rows?: number): number {
    const ms = Math.round((performance.now() - t0) * 1000) / 1000;
    this.lastQueryMs = ms;
    this.queryLog.push({ name, ms, ts: Date.now(), rows });
    if (this.queryLog.length > QUERY_LOG_MAX) this.queryLog.splice(0, this.queryLog.length - QUERY_LOG_MAX);
    return ms;
  }
}

function num(v: unknown): number {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

/** GET {url}/ping with a timeout. */
export async function pingClickHouse(url: string = clickhouseUrl(), timeoutMs: number = CLICKHOUSE_PING_TIMEOUT_MS): Promise<{ ok: boolean; detail: string; ms: number }> {
  const t0 = performance.now();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(`${url.replace(/\/+$/, '')}/ping`, { signal: ctrl.signal });
    const text = (await res.text()).trim();
    const ms = Math.round((performance.now() - t0) * 1000) / 1000;
    if (res.ok && /^ok\.?$/i.test(text)) return { ok: true, detail: `ClickHouse at ${url} answered /ping in ${ms}ms`, ms };
    return { ok: false, detail: `unexpected /ping response ${res.status}: ${text.slice(0, 80)}`, ms };
  } catch (err) {
    const ms = Math.round((performance.now() - t0) * 1000) / 1000;
    const e = err as Error & { cause?: { code?: string } };
    const why = e?.name === 'AbortError' ? `timeout after ${timeoutMs}ms` : e?.cause?.code ?? e?.message ?? String(err);
    return { ok: false, detail: `ClickHouse not reachable at ${url} (${why})`, ms };
  } finally {
    clearTimeout(timer);
  }
}

export interface CreateStoreOptions extends ClickHouseStoreOptions {
  /** ping timeout (default 1500ms) */
  pingTimeoutMs?: number;
  /** force a kind (also env IMMUNE_STORE=memory|clickhouse) */
  force?: StoreKind;
  /** memory store cap */
  maxRows?: number;
}

export interface CreateStoreResult {
  store: Store;
  kind: StoreKind;
  url?: string;
  version?: string;
  detail: string;
}

/** ClickHouse if it pings (and initializes), else MemoryStore. Always resolves; never throws. */
export async function createStore(opts: CreateStoreOptions = {}): Promise<CreateStoreResult> {
  const url = opts.url ?? clickhouseUrl();
  const force = opts.force ?? (process.env.IMMUNE_STORE === 'memory' || process.env.IMMUNE_STORE === 'clickhouse' ? (process.env.IMMUNE_STORE as StoreKind) : undefined);
  if (force === 'memory') {
    return { store: new MemoryStore({ maxRows: opts.maxRows }), kind: 'memory', detail: 'memory store forced (IMMUNE_STORE=memory)' };
  }
  const ping = await pingClickHouse(url, opts.pingTimeoutMs ?? CLICKHOUSE_PING_TIMEOUT_MS);
  if (!ping.ok) {
    return { store: new MemoryStore({ maxRows: opts.maxRows }), kind: 'memory', url, detail: `${ping.detail}; using in-memory store` };
  }
  const ch = new ClickHouseStore({ ...opts, url });
  try {
    await ch.init();
    return { store: ch, kind: 'clickhouse', url, version: ch.version, detail: `ClickHouse ${ch.version ?? ''} at ${url}, table ${TRACES_FQN} ready (ping ${ping.ms}ms)`.replace(/\s+/g, ' ') };
  } catch (err) {
    await ch.close().catch(() => undefined);
    return { store: new MemoryStore({ maxRows: opts.maxRows }), kind: 'memory', url, detail: `ClickHouse at ${url} pinged but init failed (${(err as Error)?.message ?? String(err)}); using in-memory store` };
  }
}
