/**
 * Typed client for the Immune web API. Every UI control goes through here.
 * Shapes mirror CONTRACTS.md; a few responses are supersets (extra fields) and are typed as such.
 *
 * Fixtures (lib/fixtures.ts) are served only when the API is unreachable, or when NEXT_PUBLIC_IMMUNE_MOCK=1
 * forces them for visual iteration. Never used by the server.
 */
import type {
  AdapterStatus,
  AttackFamily,
  Decision,
  Metrics,
  Receipt,
  Remediation,
  Rule,
  Ruling,
  Trace,
} from '@immune/core';

export type StoreKind = 'clickhouse' | 'memory';

export type StatusResponse = AdapterStatus & {
  senso: AdapterStatus['senso'] & { installed?: boolean; authenticated?: boolean; org?: string; version?: string; command?: string };
  receiptSecretIsDefault: boolean;
  version: string;
  store: { kind: StoreKind; latencyMs: number | null; rows: number };
  uptimeMs: number;
  seeded: boolean;
  seeding: boolean;
  bootedAt: number;
};

export interface FamilyStat {
  family: AttackFamily;
  label: string;
  total: number;
  blocked: number;
  breached: number;
}

export interface TtiPoint {
  ts: number;
  ms: number;
  remediationId: string;
  family: AttackFamily;
}

export type MetricsResponse = Metrics & {
  families: FamilyStat[];
  /** last mutation seed used per family — pass back with mutate:true to replay the identical attack */
  lastSeeds: Partial<Record<AttackFamily, number>>;
  ttiHistory: TtiPoint[];
  rulesTotal: number;
  rulesCandidate: number;
  receipts: number;
  rulings: number;
  remediationsRunning: number;
};

export interface AttackRequest {
  family: AttackFamily;
  /** hand-written variant key ('v1'..'v6'); ignored when mutate is true */
  variant?: string;
  /** novel evasive variant (deterministic per seed) */
  mutate?: boolean;
  /** replay an exact earlier mutation; omitted → the engine allocates the next seed for the family */
  seed?: number;
  count?: number;
}

export interface AttackResponse {
  traces: Trace[];
  breach?: Trace;
  remediationId?: string;
  remediationIds?: string[];
  sessions: number;
  blocked: number;
  breaches: number;
  ms: number;
  family: AttackFamily;
  /** seed used for the (last) session — pass it back with mutate:true to replay the identical attack */
  seed?: number;
  variant?: string;
}

export interface FloodResponse {
  inserted: number;
  ms: number;
  attacks: number;
  benign: number;
}

export interface TracesQuery {
  limit?: number;
  label?: 'attack' | 'benign' | '';
  family?: AttackFamily | '';
  decision?: Decision | '';
  breached?: boolean;
  q?: string;
  id?: string;
}

export interface TracesResponse {
  traces: Trace[];
  total: number;
  ms: number;
}

export interface QuarantineEntry {
  server: string;
  tool: string;
  reason: string;
  since: number;
  traceId?: string;
  family?: AttackFamily;
}

export interface VerifyResponse {
  ok: boolean;
  reason: string;
  expectedPayloadHash?: string;
}

export interface NamedQueryResult {
  name: string;
  sql: string;
  rows: Record<string, unknown>[];
  ms: number;
  error?: string;
}

export interface TimelineBucket {
  bucket: number;
  attacks: number;
  blocked: number;
  benign: number;
  fp: number;
}

export interface ClickhouseQueriesResponse {
  store: StoreKind;
  connected: boolean;
  url?: string;
  version?: string;
  rows: number;
  queries: NamedQueryResult[];
  timeline: TimelineBucket[];
  families: FamilyStat[];
  totalMs: number;
}

export interface ResetResponse {
  ok: boolean;
  seeded: { attacks: number; benign: number } | null;
  ms: number;
}

export interface IngestResponse {
  ok: boolean;
  traceId: string;
  breached: boolean;
  remediationId?: string;
}

export interface RulesResponse {
  rules: Rule[];
}

export interface SensoHit {
  title?: string;
  kbNodeId?: string;
  contentId?: string;
  chunk?: string;
}

export interface SensoAskResponse {
  ok: boolean;
  question: string;
  answer?: string;
  hits: SensoHit[];
  ms: number;
  detail: string;
  authenticated: boolean;
  installed?: boolean;
  org?: string;
  /** the one command to run when not authenticated */
  command?: string;
}

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
    public readonly body?: unknown,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

export const MOCK = typeof process !== 'undefined' && process.env.NEXT_PUBLIC_IMMUNE_MOCK === '1';

async function request<T>(path: string, init?: RequestInit & { json?: unknown }): Promise<T> {
  const headers = new Headers(init?.headers);
  let body = init?.body;
  if (init && 'json' in init && init.json !== undefined) {
    headers.set('content-type', 'application/json');
    body = JSON.stringify(init.json);
  }
  const res = await fetch(path, { ...init, headers, body, cache: 'no-store' });
  const text = await res.text();
  let parsed: unknown = undefined;
  if (text) {
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = text;
    }
  }
  if (!res.ok) {
    const msg =
      parsed && typeof parsed === 'object' && 'error' in parsed && typeof (parsed as { error: unknown }).error === 'string'
        ? (parsed as { error: string }).error
        : `${res.status} ${res.statusText}`;
    throw new ApiError(res.status, msg, parsed);
  }
  return parsed as T;
}

function qs(params: Record<string, string | number | boolean | undefined | null>): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '') continue;
    sp.set(k, String(v));
  }
  const s = sp.toString();
  return s ? `?${s}` : '';
}

export interface ImmuneApi {
  status(): Promise<StatusResponse>;
  metrics(): Promise<MetricsResponse>;
  attack(req: AttackRequest): Promise<AttackResponse>;
  flood(attacks: number, benign: number): Promise<FloodResponse>;
  traces(q?: TracesQuery): Promise<TracesResponse>;
  rules(): Promise<Rule[]>;
  promoteRule(id: string): Promise<Rule>;
  revokeRule(id: string): Promise<Rule>;
  remediations(): Promise<Remediation[]>;
  remediation(id: string): Promise<Remediation>;
  remediate(traceId: string): Promise<{ remediationId: string; remediation: Remediation }>;
  receipts(): Promise<Receipt[]>;
  verifyReceipt(receipt: Receipt): Promise<VerifyResponse>;
  rulings(): Promise<Ruling[]>;
  quarantine(): Promise<QuarantineEntry[]>;
  release(server: string, tool: string): Promise<{ ok: boolean; released: boolean }>;
  clickhouseQueries(): Promise<ClickhouseQueriesResponse>;
  reset(): Promise<ResetResponse>;
  ingest(trace: Trace): Promise<IngestResponse>;
  askPrecedent(question: string): Promise<SensoAskResponse>;
}

const liveApi: ImmuneApi = {
  status: () => request('/api/status'),
  metrics: () => request('/api/metrics'),
  attack: (req) => request('/api/attack', { method: 'POST', json: req }),
  flood: (attacks, benign) => request('/api/flood', { method: 'POST', json: { attacks, benign } }),
  traces: (q = {}) => request(`/api/traces${qs({ ...q })}`),
  rules: async () => {
    const r = await request<RulesResponse | Rule[]>('/api/rules');
    return Array.isArray(r) ? r : r.rules;
  },
  promoteRule: (id) => request(`/api/rules/${encodeURIComponent(id)}/promote`, { method: 'POST' }),
  revokeRule: (id) => request(`/api/rules/${encodeURIComponent(id)}/revoke`, { method: 'POST' }),
  remediations: async () => {
    const r = await request<{ remediations: Remediation[] } | Remediation[]>('/api/remediations');
    return Array.isArray(r) ? r : r.remediations;
  },
  remediation: (id) => request(`/api/remediations/${encodeURIComponent(id)}`),
  remediate: (traceId) => request('/api/remediate', { method: 'POST', json: { traceId } }),
  receipts: async () => {
    const r = await request<{ receipts: Receipt[] } | Receipt[]>('/api/receipts');
    return Array.isArray(r) ? r : r.receipts;
  },
  verifyReceipt: (receipt) => request('/api/receipts/verify', { method: 'POST', json: { receipt } }),
  rulings: async () => {
    const r = await request<{ rulings: Ruling[] } | Ruling[]>('/api/rulings');
    return Array.isArray(r) ? r : r.rulings;
  },
  quarantine: async () => {
    const r = await request<{ quarantine: QuarantineEntry[] } | QuarantineEntry[]>('/api/quarantine');
    return Array.isArray(r) ? r : r.quarantine;
  },
  release: (server, tool) => request('/api/quarantine/release', { method: 'POST', json: { server, tool } }),
  clickhouseQueries: () => request('/api/clickhouse/queries'),
  reset: () => request('/api/reset', { method: 'POST' }),
  ingest: (trace) => request('/api/ingest', { method: 'POST', json: { trace } }),
  askPrecedent: (question) => request('/api/senso/ask', { method: 'POST', json: { question } }),
};

/* ------------------------------------------------------------------------------------------------
 * Fixture fallback. Fixtures are served ONLY when the API is unreachable (network failure / 502-504),
 * or when NEXT_PUBLIC_IMMUNE_MOCK=1 forces them. The shell shows "OFFLINE · FIXTURES" while active, and
 * every call keeps trying the live API first so the UI snaps back as soon as the engine answers.
 * ---------------------------------------------------------------------------------------------- */

type FixtureListener = (on: boolean) => void;
let fixtureMode = MOCK;
const fixtureListeners = new Set<FixtureListener>();

export function isFixtureMode(): boolean {
  return fixtureMode;
}

export function subscribeFixtureMode(l: FixtureListener): () => void {
  fixtureListeners.add(l);
  return () => {
    fixtureListeners.delete(l);
  };
}

function setFixtureMode(on: boolean): void {
  if (fixtureMode === on) return;
  fixtureMode = on;
  fixtureListeners.forEach((l) => l(on));
}

function unreachable(err: unknown): boolean {
  if (err instanceof ApiError) return err.status === 502 || err.status === 503 || err.status === 504;
  return err instanceof TypeError; // fetch() network failure
}

let mockPromise: Promise<ImmuneApi> | null = null;
function mock(): Promise<ImmuneApi> {
  mockPromise ??= import('./fixtures').then((m) => m.mockApi);
  return mockPromise;
}

function withFallback<K extends keyof ImmuneApi>(name: K): ImmuneApi[K] {
  const live = liveApi[name] as (...args: unknown[]) => Promise<unknown>;
  const wrapped = async (...args: unknown[]) => {
    if (MOCK) return ((await mock())[name] as (...a: unknown[]) => Promise<unknown>)(...args);
    try {
      const r = await live(...args);
      setFixtureMode(false);
      return r;
    } catch (err) {
      if (!unreachable(err)) throw err;
      setFixtureMode(true);
      return ((await mock())[name] as (...a: unknown[]) => Promise<unknown>)(...args);
    }
  };
  return wrapped as unknown as ImmuneApi[K];
}

export const api: ImmuneApi = {
  status: withFallback('status'),
  metrics: withFallback('metrics'),
  attack: withFallback('attack'),
  flood: withFallback('flood'),
  traces: withFallback('traces'),
  rules: withFallback('rules'),
  promoteRule: withFallback('promoteRule'),
  revokeRule: withFallback('revokeRule'),
  remediations: withFallback('remediations'),
  remediation: withFallback('remediation'),
  remediate: withFallback('remediate'),
  receipts: withFallback('receipts'),
  verifyReceipt: withFallback('verifyReceipt'),
  rulings: withFallback('rulings'),
  quarantine: withFallback('quarantine'),
  release: withFallback('release'),
  clickhouseQueries: withFallback('clickhouseQueries'),
  reset: withFallback('reset'),
  ingest: withFallback('ingest'),
  askPrecedent: withFallback('askPrecedent'),
};
