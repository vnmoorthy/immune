/**
 * Immune engine — one per process, cached on globalThis across HMR.
 * Owns: Store (ClickHouse → Memory fallback), the long-lived Gate (proxy/ingest path, quarantine registry),
 * the rule set, receipts, rulings, remediation history/queue, metrics counters and the EventBus (SSE).
 *
 * Scenario runs (arena, immunity verification) each get a FRESH Gate built from the current rule set so
 * pins / trust / taint never leak between sessions; what they quarantine is absorbed into the registry
 * and the long-lived gate.
 */
import { performance } from 'node:perf_hooks';
import {
  Gate,
  builtinRules,
  createStore,
  detectLlm,
  newId,
  receiptSecret,
  semgrepAvailable,
  verifyReceipt as coreVerifyReceipt,
  type AttackFamily,
  type CreateStoreResult,
  type Finding,
  type NamedQuery,
  type Receipt,
  type Remediation,
  type Rule,
  type Ruling,
  type Store,
  type StoreStatus,
  type Trace,
} from '@immune/core';
import type { GateLike } from '@immune/demo';
import { BENIGN_ALLOWLIST, generateCorpus, registeredSecrets, runScenario } from '@immune/demo';
import type {
  AttackRequest,
  AttackResponse,
  ClickhouseQueriesResponse,
  FamilyStat,
  FloodResponse,
  IngestResponse,
  MetricsResponse,
  NamedQueryResult,
  QuarantineEntry,
  ResetResponse,
  StatusResponse,
  TracesQuery,
  TracesResponse,
  TtiPoint,
  VerifyResponse,
} from '@/lib/api';
import { citationText } from '@/lib/citation';
import { ATTACK_FAMILIES, FAMILY_META, STEP_ORDER } from '@/lib/format';
import { EventBus } from './event-bus';
import { HttpError } from './http';
import { runRemediation } from './remediator';
import { revokeRuling, sensoAdapterStatus } from './senso';

export const ALLOWLIST: string[] = [...BENIGN_ALLOWLIST];
export const SEED_ATTACKS = 400;
export const SEED_BENIGN = 2000;
const VERSION = process.env.IMMUNE_WEB_VERSION ?? '0.1.0';
const MAX_SESSIONS = 2000;
const MAX_TRACE_INDEX = 20_000;
const MAX_LATENCY_SAMPLES = 5000;
const FAMILY_KEYS: AttackFamily[] = [...ATTACK_FAMILIES, 'benign'];

export interface ScenarioRef {
  family: AttackFamily;
  variant: string;
  mutate: boolean;
  seed: number;
  sessionId: string;
}

interface FamilyCounter {
  total: number;
  blocked: number;
  breached: number;
}

export interface RunGate {
  /** what runScenario drives */
  gate: GateLike;
  /** the underlying core Gate (quarantine, sessions, secrets) */
  inner: Gate;
}

const clamp = (n: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, n));

export class Engine {
  readonly bootedAt = Date.now();
  readonly bus = new EventBus(600);
  store!: Store;
  storeInfo!: CreateStoreResult;
  /** long-lived gate: /api/ingest traffic, quarantine registry, latency samples */
  gate!: Gate;
  rules: Rule[] = [];
  readonly receipts: Receipt[] = [];
  readonly rulings: Ruling[] = [];
  readonly remediations: Remediation[] = [];
  readonly quarantine = new Map<string, QuarantineEntry>();
  readonly scenarioIndex = new Map<string, ScenarioRef>();
  readonly sessions = new Map<string, Trace[]>();
  readonly traceById = new Map<string, Trace>();
  readonly ttiHistory: TtiPoint[] = [];
  readonly lastSeed = new Map<string, number>();
  seeded = false;
  seeding = false;
  runningRemediations = 0;

  private counters = { tracesTotal: 0, benignTotal: 0, benignBlocked: 0, families: new Map<string, FamilyCounter>() };
  private latencies: number[] = [];
  private readonly seedCounter = new Map<string, number>();
  private readonly launchCounter = new Map<string, number>();
  private queue: Promise<void> = Promise.resolve();
  private metricsTimer: ReturnType<typeof setTimeout> | null = null;

  /* ---------------------------------------------------------------- boot */

  async init(): Promise<void> {
    this.storeInfo = await createStore();
    this.store = this.storeInfo.store;
    this.rules = builtinRules(ALLOWLIST);
    this.gate = this.newGate();
    let rows = 0;
    try {
      await this.loadCounters();
      rows = await this.store.count();
    } catch (err) {
      this.emitLog('warn', `could not read store counts: ${(err as Error).message}`);
    }
    this.emitLog('info', `engine up · ${this.storeInfo.kind} store · ${this.storeInfo.detail} · ${rows} traces · ${this.rules.length} builtin antibodies`);
    if (rows === 0) {
      void this.seed();
    } else {
      this.seeded = true;
    }
  }

  async seed(): Promise<void> {
    if (this.seeding) return;
    this.seeding = true;
    try {
      const r = await this.flood(SEED_ATTACKS, SEED_BENIGN);
      this.seeded = true;
      this.emitLog('info', `seeded corpus: ${r.benign} benign + ${r.attacks} attacks in ${Math.round(r.ms)} ms`);
    } catch (err) {
      this.emitLog('error', `seed failed: ${(err as Error).message}`);
    } finally {
      this.seeding = false;
    }
  }

  /* ---------------------------------------------------------------- gates */

  newGate(): Gate {
    const g = new Gate({ rules: this.rules, allowlist: ALLOWLIST, citationFor: (r) => this.citationFor(r) });
    for (const s of registeredSecrets()) g.registerSecret(s, 'acme');
    return g;
  }

  citationFor(rule: Rule): string | undefined {
    if (!rule.rulingId) return undefined;
    const ru = this.rulings.find((x) => x.id === rule.rulingId);
    return ru ? citationText(ru) : undefined;
  }

  /** The gate's rule list is a copy — re-sync after every rule change. */
  syncGate(): void {
    this.gate.setRules(this.rules);
  }

  activeRules(): Rule[] {
    return this.rules.filter((r) => r.status === 'promoted');
  }

  replaceRule(rule: Rule): Rule {
    const i = this.rules.findIndex((r) => r.id === rule.id);
    if (i >= 0) this.rules[i] = rule;
    else this.rules.push(rule);
    this.syncGate();
    return rule;
  }

  /**
   * A fresh gate for one scenario run. The wrapper adds two engine policies on top of core:
   *  - a definition that is quarantined/blocked taints the session that was served it (so the hijack that
   *    follows a poisoned definition is denied even though the agent then calls a different tool);
   *  - a denial without a citation of its own inherits the ruling citation of the antibody that tainted the session.
   */
  runGate(): RunGate {
    const inner = this.newGate();
    const citationFromSession = (sid: string): string | undefined => {
      const s = inner.session(sid);
      if (!s) return undefined;
      for (const f of s.findings) {
        if (!f.ruleId) continue;
        const rule = this.rules.find((r) => r.id === f.ruleId);
        const c = rule ? this.citationFor(rule) : undefined;
        if (c) return c;
      }
      return undefined;
    };
    const gate: GateLike = {
      inspectToolDef: (def, sid) => {
        const v = inner.inspectToolDef(def, sid);
        if (v.decision === 'quarantine' || v.decision === 'block') {
          inner.taintSession(sid, `definition ${def.server}/${def.name} was ${v.decision === 'quarantine' ? 'quarantined' : 'blocked'} (${v.blockedBy ?? 'policy'})`, v.findings);
          return { ...v, tainted: true };
        }
        return v;
      },
      inspectResult: (result, sid) => inner.inspectResult(result, sid),
      inspectCall: (call, def, sid) => {
        const v = inner.inspectCall(call, def, sid);
        if (v.decision !== 'allow' && !v.citation) {
          const c = citationFromSession(sid);
          if (c) return { ...v, citation: c };
        }
        return v;
      },
      registerSecret: (value) => {
        inner.registerSecret(value, 'acme');
      },
    };
    return { gate, inner };
  }

  /** Fresh ids + real timestamps for scenario traces (the demo seeds ids/ts deterministically). */
  normalize(raw: Trace[], sessionId: string): Trace[] {
    const base = Date.now();
    return raw.map((t, i) => ({ ...t, id: newId('tr'), sessionId, ts: base + i }));
  }

  /** Copy what a run gate quarantined into the registry and the long-lived gate. */
  absorbQuarantine(inner: Gate, traces: Trace[]): void {
    for (const q of inner.listQuarantine()) {
      const key = `${q.server}::${q.tool}`;
      if (this.quarantine.has(key)) continue;
      const evidence = traces.find((t) => t.toolDef?.name === q.tool || t.attemptedCall?.tool === q.tool || t.result?.tool === q.tool);
      const entry: QuarantineEntry = { server: q.server, tool: q.tool, reason: q.reason, since: q.since, traceId: evidence?.id, family: evidence?.family };
      this.quarantine.set(key, entry);
      if (!this.gate.isQuarantined(q.server, q.tool)) this.gate.quarantineTool(q.server, q.tool, q.reason, q.findings, q.hash);
      this.bus.emit('quarantine', { ...entry, active: true });
    }
  }

  /* ---------------------------------------------------------------- traces */

  private async loadCounters(): Promise<void> {
    const fams = await this.store.countByFamily();
    const c = { tracesTotal: 0, benignTotal: 0, benignBlocked: 0, families: new Map<string, FamilyCounter>() };
    for (const f of fams) {
      c.tracesTotal += f.total;
      if (f.label === 'benign' || f.family === 'benign') {
        c.benignTotal += f.total;
        c.benignBlocked += f.blocked;
      } else {
        const cur = c.families.get(f.family) ?? { total: 0, blocked: 0, breached: 0 };
        cur.blocked += f.blocked;
        cur.breached += f.breached;
        cur.total = cur.blocked + cur.breached;
        c.families.set(f.family, cur);
      }
    }
    this.counters = c;
    try {
      const lat = await this.store.latency();
      if (lat.count > 0) this.latencies = [lat.p50, lat.p95];
    } catch {
      /* optional */
    }
  }

  private count(t: Trace): void {
    const c = this.counters;
    c.tracesTotal++;
    if (t.label === 'benign') {
      c.benignTotal++;
      if (t.decision !== 'allow') c.benignBlocked++;
      return;
    }
    // attack steps are "decisive" when the gate stopped them or they got through; context steps are not counted
    if (t.decision === 'allow' && !t.breached) return;
    const cur = c.families.get(t.family) ?? { total: 0, blocked: 0, breached: 0 };
    if (t.decision !== 'allow') cur.blocked++;
    else cur.breached++;
    cur.total = cur.blocked + cur.breached;
    c.families.set(t.family, cur);
  }

  private index(t: Trace): void {
    this.traceById.set(t.id, t);
    if (this.traceById.size > MAX_TRACE_INDEX) {
      const first = this.traceById.keys().next().value;
      if (first) this.traceById.delete(first);
    }
    const s = this.sessions.get(t.sessionId);
    if (s) s.push(t);
    else {
      this.sessions.set(t.sessionId, [t]);
      if (this.sessions.size > MAX_SESSIONS) {
        const first = this.sessions.keys().next().value;
        if (first) this.sessions.delete(first);
      }
    }
    this.latencies.push(t.latencyMs);
    if (this.latencies.length > MAX_LATENCY_SAMPLES) this.latencies.splice(0, this.latencies.length - MAX_LATENCY_SAMPLES);
  }

  /** Persist traces, update counters, emit events. `emit:false` for bulk floods. */
  async recordTraces(traces: Trace[], opts: { emit: boolean; source: 'scenario' | 'flood' | 'ingest' | 'verify' }): Promise<{ inserted: number; ms: number }> {
    if (!traces.length) return { inserted: 0, ms: 0 };
    const r = await this.store.insertTraces(traces);
    for (const t of traces) {
      this.count(t);
      if (opts.source !== 'flood') this.index(t);
    }
    if (opts.emit) {
      for (const t of traces) {
        this.bus.emit('trace', t);
        if (t.breached) {
          this.bus.emit('breach', t);
          void this.notifyGuild(t);
        }
      }
    }
    this.scheduleMetrics();
    return r;
  }

  private async notifyGuild(breach: Trace): Promise<void> {
    const url = process.env.GUILD_WEBHOOK_URL;
    if (!url) return;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 3000);
    try {
      await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ event: 'breach', trace: breach }), signal: ctrl.signal });
    } catch (err) {
      this.emitLog('warn', `guild webhook failed: ${(err as Error).message}`);
    } finally {
      clearTimeout(timer);
    }
  }

  /* ---------------------------------------------------------------- arena */

  private nextSeed(family: string): number {
    const n = (this.seedCounter.get(family) ?? 0) + 1;
    this.seedCounter.set(family, n);
    return n;
  }

  private nextVariant(family: string): string {
    const n = this.launchCounter.get(family) ?? 0;
    this.launchCounter.set(family, n + 1);
    return `v${(n % 6) + 1}`;
  }

  async attack(req: AttackRequest): Promise<AttackResponse> {
    if (!FAMILY_KEYS.includes(req.family)) throw new HttpError(400, `unknown family ${String(req.family)}`);
    const count = clamp(Math.floor(req.count ?? 1), 1, 50);
    const t0 = performance.now();
    const all: Trace[] = [];
    const remIds: string[] = [];
    let firstBreach: Trace | undefined;
    let seedUsed: number | undefined;
    let variantUsed: string | undefined;

    for (let i = 0; i < count; i++) {
      const sessionId = newId('ses');
      const benign = req.family === 'benign';
      const mutate = !benign && !!req.mutate;
      const seed = benign ? this.nextSeed('benign') : req.seed !== undefined ? Math.floor(req.seed) : this.nextSeed(mutate ? req.family : `${req.family}:launch`);
      const variant = benign || mutate ? undefined : req.variant ?? this.nextVariant(req.family);
      const { gate, inner } = this.runGate();
      const raw = runScenario({ family: req.family, variant, mutate, seed, gate, sessionId, allowlist: ALLOWLIST });
      const traces = this.normalize(raw, sessionId);
      const ref: ScenarioRef = { family: req.family, variant: traces[0]?.variant ?? variant ?? '', mutate, seed, sessionId };
      for (const t of traces) this.scenarioIndex.set(t.id, ref);
      this.absorbQuarantine(inner, traces);
      await this.recordTraces(traces, { emit: true, source: 'scenario' });
      if (!benign) this.lastSeed.set(req.family, seed);
      seedUsed = seed;
      variantUsed = ref.variant;
      const breach = traces.find((t) => t.breached);
      if (breach) {
        firstBreach ??= breach;
        const rem = this.queueRemediation(breach, ref, 'auto');
        if (rem && !remIds.includes(rem.id)) remIds.push(rem.id);
      }
      all.push(...traces);
    }
    const ms = Math.round((performance.now() - t0) * 100) / 100;
    this.emitLog(
      'info',
      `${req.family} × ${count} ${req.family === 'benign' ? '' : req.mutate ? `mutated (seed ${seedUsed})` : `variant ${variantUsed}`} → ${all.filter((t) => t.breached).length} breach · ${all.filter((t) => t.decision !== 'allow').length} denied · ${ms} ms`,
    );
    return {
      traces: all,
      breach: firstBreach,
      remediationId: remIds[0],
      remediationIds: remIds,
      sessions: count,
      blocked: all.filter((t) => t.decision !== 'allow').length,
      breaches: all.filter((t) => t.breached).length,
      ms,
      family: req.family,
      seed: seedUsed,
      variant: variantUsed,
    };
  }

  async flood(attacks: number, benign: number): Promise<FloodResponse> {
    const a = clamp(Math.floor(attacks) || 0, 0, 100_000);
    const b = clamp(Math.floor(benign) || 0, 0, 100_000);
    const t0 = performance.now();
    const seed = (Date.now() ^ Math.floor(Math.random() * 0x7fffffff)) >>> 0;
    const traces = generateCorpus({ attacks: a, benign: b, seed, allowlist: ALLOWLIST });
    let inserted = 0;
    for (let i = 0; i < traces.length; i += 1000) {
      const r = await this.recordTraces(traces.slice(i, i + 1000), { emit: false, source: 'flood' });
      inserted += r.inserted;
    }
    const ms = Math.round((performance.now() - t0) * 100) / 100;
    if (a + b > 0) this.emitLog('info', `flood: ${b} benign + ${a} attacks → ${this.storeInfo.kind} in ${ms} ms`);
    this.scheduleMetrics();
    return { inserted, ms, attacks: a, benign: b };
  }

  /* ---------------------------------------------------------------- remediation */

  queueRemediation(breach: Trace, ref: ScenarioRef | undefined, mode: 'auto' | 'manual'): Remediation | undefined {
    if (mode === 'auto') {
      const dup = this.remediations.find((r) => r.status === 'running' && r.family === breach.family && ref && this.scenarioIndex.get(r.breachTraceId)?.variant === ref.variant);
      if (dup) {
        this.emitLog('info', `breach ${breach.id} (${breach.family}/${ref?.variant}) coalesced into ${dup.id}`);
        return dup;
      }
    }
    const rem: Remediation = {
      id: newId('rm'),
      breachTraceId: breach.id,
      family: breach.family,
      startedAt: Date.now(),
      steps: STEP_ORDER.map((name) => ({ name, status: 'pending' as const })),
      status: 'running',
    };
    this.remediations.unshift(rem);
    if (this.remediations.length > 200) this.remediations.length = 200;
    this.runningRemediations++;
    this.bus.emit('remediation', structuredClone(rem));
    this.queue = this.queue
      .then(() => runRemediation(this, rem, breach, ref, { skipIfCovered: mode === 'auto' }))
      .catch((err) => this.emitLog('error', `remediation ${rem.id} crashed: ${(err as Error).message}`))
      .finally(() => {
        this.runningRemediations--;
        this.scheduleMetrics();
      });
    return rem;
  }

  async remediate(traceId: string): Promise<Remediation> {
    const trace = await this.findTrace(traceId);
    if (!trace) throw new HttpError(404, `trace ${traceId} not found`);
    if (trace.label !== 'attack') throw new HttpError(400, 'only attack traces can be remediated');
    const ref = this.scenarioIndex.get(trace.id) ?? this.sessions.get(trace.sessionId)?.map((t) => this.scenarioIndex.get(t.id)).find(Boolean);
    const rem = this.queueRemediation(trace, ref, 'manual');
    if (!rem) throw new HttpError(409, 'remediation already running for this attack');
    return rem;
  }

  async findTrace(id: string): Promise<Trace | undefined> {
    const local = this.traceById.get(id);
    if (local) return local;
    const r = await this.store.recent(5000);
    return r.traces.find((t) => t.id === id);
  }

  /* ---------------------------------------------------------------- rules */

  promoteRule(id: string): Rule {
    const r = this.rules.find((x) => x.id === id);
    if (!r) throw new HttpError(404, `rule ${id} not found`);
    r.status = 'promoted';
    this.syncGate();
    this.bus.emit('rule', r);
    this.emitLog('info', `antibody ${r.id} promoted by operator`);
    this.scheduleMetrics();
    return r;
  }

  revokeRule(id: string): Rule {
    const r = this.rules.find((x) => x.id === id);
    if (!r) throw new HttpError(404, `rule ${id} not found`);
    r.status = 'revoked';
    this.syncGate();
    this.bus.emit('rule', r);
    this.emitLog('warn', `antibody ${r.id} revoked by operator`);
    const ruling = r.rulingId ? this.rulings.find((x) => x.id === r.rulingId) : undefined;
    if (ruling?.publishedTo === 'senso') {
      void revokeRuling(ruling).then((res) => this.emitLog(res.ok ? 'info' : 'warn', `ruling ${ruling.id} ${res.ok ? 'marked revoked in senso' : 'senso revoke skipped'}: ${res.detail}`));
    }
    this.scheduleMetrics();
    return r;
  }

  release(server: string, tool: string): { ok: boolean; released: boolean } {
    const key = `${server}::${tool}`;
    const had = this.quarantine.delete(key);
    const released = this.gate.release(server, tool) || had;
    this.bus.emit('quarantine', { server, tool, reason: 'released by operator', active: false });
    if (released) this.emitLog('info', `released ${server}/${tool} from quarantine`);
    this.scheduleMetrics();
    return { ok: true, released };
  }

  listQuarantine(): QuarantineEntry[] {
    // registry ∪ whatever the long-lived (proxy) gate holds
    const out = new Map(this.quarantine);
    for (const q of this.gate.listQuarantine()) {
      const key = `${q.server}::${q.tool}`;
      if (!out.has(key)) out.set(key, { server: q.server, tool: q.tool, reason: q.reason, since: q.since });
    }
    return [...out.values()].sort((a, b) => b.since - a.since);
  }

  verifyReceipt(receipt: Receipt): VerifyResponse {
    const r = coreVerifyReceipt(receipt, receiptSecret().secret);
    return { ok: r.ok, reason: r.reason };
  }

  /* ---------------------------------------------------------------- ingest (proxy) */

  async ingest(input: unknown): Promise<IngestResponse> {
    if (!input || typeof input !== 'object') throw new HttpError(400, 'trace must be an object');
    const t = input as Partial<Trace>;
    if (!t.family || !FAMILY_KEYS.includes(t.family)) throw new HttpError(400, 'trace.family is required');
    const trace: Trace = {
      id: typeof t.id === 'string' && t.id ? t.id : newId('tr'),
      sessionId: typeof t.sessionId === 'string' && t.sessionId ? t.sessionId : newId('ses'),
      ts: typeof t.ts === 'number' ? t.ts : Date.now(),
      family: t.family,
      variant: typeof t.variant === 'string' ? t.variant : 'proxy',
      label: t.label === 'benign' ? 'benign' : t.label === 'attack' ? 'attack' : t.family === 'benign' ? 'benign' : 'attack',
      toolDef: t.toolDef,
      result: t.result,
      attemptedCall: t.attemptedCall,
      tainted: !!t.tainted,
      findings: Array.isArray(t.findings) ? (t.findings as Finding[]) : [],
      decision: t.decision ?? 'allow',
      breached: !!t.breached,
      blockedBy: t.blockedBy,
      citation: t.citation,
      latencyMs: typeof t.latencyMs === 'number' ? t.latencyMs : 0,
    };
    await this.recordTraces([trace], { emit: true, source: 'ingest' });
    let remediationId: string | undefined;
    if (trace.breached) remediationId = this.queueRemediation(trace, undefined, 'auto')?.id;
    return { ok: true, traceId: trace.id, breached: trace.breached, remediationId };
  }

  /* ---------------------------------------------------------------- reads */

  async traces(q: TracesQuery): Promise<TracesResponse> {
    if (q.id) {
      const local = this.traceById.get(q.id);
      if (local) return { traces: [local], total: 1, ms: 0 };
      const r = await this.store.recent(5000);
      const hit = r.traces.filter((t) => t.id === q.id);
      return { traces: hit, total: hit.length, ms: r.ms };
    }
    const limit = clamp(Math.floor(q.limit ?? 200), 1, 5000);
    const needle = q.q?.trim().toLowerCase();
    const filter = {
      label: q.label || undefined,
      family: q.family || undefined,
      decision: q.decision || undefined,
      breached: q.breached ? true : undefined,
    };
    const r = await this.store.recent(needle ? Math.max(limit * 10, 2000) : limit, filter);
    let traces = r.traces;
    if (needle) traces = traces.filter((t) => JSON.stringify(t).toLowerCase().includes(needle));
    return { traces: traces.slice(0, limit), total: traces.length, ms: r.ms };
  }

  metrics(): MetricsResponse {
    const c = this.counters;
    let attacksTotal = 0;
    let attacksBlocked = 0;
    let breaches = 0;
    for (const f of c.families.values()) {
      attacksTotal += f.total;
      attacksBlocked += f.blocked;
      breaches += f.breached;
    }
    const sorted = this.latencies.slice().sort((a, b) => a - b);
    const pct = (p: number) => (sorted.length ? sorted[Math.min(sorted.length - 1, Math.max(0, Math.ceil(p * sorted.length) - 1))]! : 0);
    const families: FamilyStat[] = FAMILY_KEYS.map((family) => {
      if (family === 'benign') return { family, label: FAMILY_META.benign.label, total: c.benignTotal, blocked: c.benignBlocked, breached: 0 };
      const f = c.families.get(family) ?? { total: 0, blocked: 0, breached: 0 };
      return { family, label: FAMILY_META[family].label, ...f };
    });
    return {
      ts: Date.now(),
      tracesTotal: c.tracesTotal,
      attacksTotal,
      attacksBlocked,
      breaches,
      benignTotal: c.benignTotal,
      benignBlocked: c.benignBlocked,
      catchRate: attacksTotal ? attacksBlocked / attacksTotal : 0,
      fpRate: c.benignTotal ? c.benignBlocked / c.benignTotal : 0,
      rulesPromoted: this.rules.filter((r) => r.status === 'promoted').length,
      quarantined: this.listQuarantine().length,
      gateP50Ms: Math.round(pct(0.5) * 1000) / 1000,
      gateP95Ms: Math.round(pct(0.95) * 1000) / 1000,
      storeLatencyMs: this.storeInfo.kind === 'clickhouse' ? this.store.lastQueryMs : null,
      storeKind: this.storeInfo.kind,
      lastTimeToImmunityMs: this.ttiHistory[this.ttiHistory.length - 1]?.ms,
      families,
      lastSeeds: Object.fromEntries(this.lastSeed) as Partial<Record<AttackFamily, number>>,
      ttiHistory: this.ttiHistory.slice(-50),
      rulesTotal: this.rules.length,
      rulesCandidate: this.rules.filter((r) => r.status === 'candidate').length,
      receipts: this.receipts.length,
      rulings: this.rulings.length,
      remediationsRunning: this.runningRemediations,
    };
  }

  async status(): Promise<StatusResponse> {
    const fallback: StoreStatus = { kind: this.storeInfo.kind, connected: false, detail: 'status unavailable' };
    const [st, sg, senso] = await Promise.all([this.store.status().catch((): StoreStatus => fallback), semgrepAvailable(), sensoAdapterStatus()]);
    const llm = detectLlm();
    const guildKey = process.env.GUILD_API_KEY?.trim();
    const guildHook = process.env.GUILD_WEBHOOK_URL?.trim();
    return {
      clickhouse: {
        connected: this.storeInfo.kind === 'clickhouse' && st.connected !== false,
        url: st.url ?? this.storeInfo.url,
        version: st.version ?? this.storeInfo.version,
        rows: st.rows ?? this.counters.tracesTotal,
        detail: st.detail ?? this.storeInfo.detail,
      },
      semgrep: { installed: sg.installed, version: sg.version, detail: sg.detail },
      llm,
      guild: {
        configured: !!(guildKey || guildHook),
        detail: guildHook ? `breaches POSTed to ${guildHook}` : guildKey ? 'GUILD_API_KEY set' : 'GUILD_API_KEY / GUILD_WEBHOOK_URL not set — remediation runs locally',
      },
      senso,
      receiptSecretIsDefault: receiptSecret().isDefault,
      version: VERSION,
      store: { kind: this.storeInfo.kind, latencyMs: this.storeInfo.kind === 'clickhouse' ? this.store.lastQueryMs : null, rows: st.rows ?? this.counters.tracesTotal },
      uptimeMs: Date.now() - this.bootedAt,
      seeded: this.seeded,
      seeding: this.seeding,
      bootedAt: this.bootedAt,
    };
  }

  async clickhouseQueries(): Promise<ClickhouseQueriesResponse> {
    const t0 = performance.now();
    const names: NamedQuery[] = ['families', 'timeline', 'top_destinations', 'latency'];
    const since = Date.now() - 3_600_000;
    const queries: NamedQueryResult[] = await Promise.all(
      names.map(async (name) => {
        try {
          const r = await this.store.runNamedQuery(name, { bucketSec: 60, since, limit: 20 });
          return { name: r.name, sql: r.sql, rows: r.rows, ms: Math.round(r.ms * 100) / 100 };
        } catch (err) {
          return { name, sql: '', rows: [], ms: 0, error: (err as Error).message };
        }
      }),
    );
    const [timeline, fams, st] = await Promise.all([
      this.store.timeline(60, since).catch(() => []),
      this.store.countByFamily().catch(() => []),
      this.store.status().catch((): StoreStatus => ({ kind: this.storeInfo.kind, connected: false })),
    ]);
    const families: FamilyStat[] = fams.map((f) => ({
      family: f.family as AttackFamily,
      label: (FAMILY_META as Record<string, { label: string }>)[f.family]?.label ?? f.family,
      total: f.total,
      blocked: f.blocked,
      breached: f.breached,
    }));
    return {
      store: this.storeInfo.kind,
      connected: this.storeInfo.kind === 'clickhouse' && st.connected !== false,
      url: st.url ?? this.storeInfo.url,
      version: st.version ?? this.storeInfo.version,
      rows: st.rows ?? this.counters.tracesTotal,
      queries,
      timeline,
      families,
      totalMs: Math.round((performance.now() - t0) * 100) / 100,
    };
  }

  /* ---------------------------------------------------------------- reset */

  async reset(): Promise<ResetResponse> {
    if (this.runningRemediations > 0) throw new HttpError(409, 'a remediation is running — wait for it to finish');
    const t0 = performance.now();
    await this.store.reset();
    this.rules = builtinRules(ALLOWLIST);
    this.gate = this.newGate();
    this.receipts.length = 0;
    this.rulings.length = 0;
    this.remediations.length = 0;
    this.quarantine.clear();
    this.scenarioIndex.clear();
    this.sessions.clear();
    this.traceById.clear();
    this.ttiHistory.length = 0;
    this.lastSeed.clear();
    this.seedCounter.clear();
    this.launchCounter.clear();
    this.latencies = [];
    this.counters = { tracesTotal: 0, benignTotal: 0, benignBlocked: 0, families: new Map() };
    this.seeded = false;
    this.emitLog('warn', 'engine reset: store cleared, builtin antibodies restored');
    await this.seed();
    this.bus.emit('rule', this.rules[0]);
    this.scheduleMetrics();
    return { ok: true, seeded: { attacks: SEED_ATTACKS, benign: SEED_BENIGN }, ms: Math.round((performance.now() - t0) * 100) / 100 };
  }

  /* ---------------------------------------------------------------- events */

  emitLog(level: 'info' | 'warn' | 'error', message: string): void {
    const line = `[immune] ${message}`;
    if (level === 'error') console.error(line);
    else if (level === 'warn') console.warn(line);
    else console.log(line);
    this.bus.emit('log', { level, message });
  }

  scheduleMetrics(): void {
    if (this.metricsTimer) return;
    this.metricsTimer = setTimeout(() => {
      this.metricsTimer = null;
      try {
        this.bus.emit('metrics', this.metrics());
      } catch (err) {
        console.error('[immune] metrics emit failed', err);
      }
    }, 250);
  }
}

declare global {
  // eslint-disable-next-line no-var
  var __immuneEngine: Promise<Engine> | undefined;
}

/** Singleton engine (survives Next.js HMR). */
export function getEngine(): Promise<Engine> {
  if (!globalThis.__immuneEngine) {
    const engine = new Engine();
    globalThis.__immuneEngine = engine.init().then(() => engine);
    globalThis.__immuneEngine.catch((err) => {
      console.error('[immune] engine init failed', err);
      globalThis.__immuneEngine = undefined;
    });
  }
  return globalThis.__immuneEngine;
}
