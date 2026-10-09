/**
 * Immune — end-to-end HTTP smoke test against a running command center.
 *
 *   pnpm demo            # in one terminal
 *   pnpm e2e             # in another  (or: npx tsx scripts/e2e.ts http://localhost:3000)
 *
 * Exercises every API route the UI uses, and the full loop for every attack family:
 * launch (blocked) → mutate (breach) → remediation reaches IMMUNE → identical replay is blocked with a citation.
 * Exits non-zero on the first failed check.
 */

const BASE = process.argv[2] ?? process.env.IMMUNE_API ?? 'http://localhost:3000';
const FAMILIES = ['secret_exfil', 'result_injection', 'poisoned_description', 'indirect_fetch', 'homoglyph_spoof', 'rug_pull'];

let passed = 0;
const failures: string[] = [];

function ok(cond: unknown, label: string, detail?: unknown): void {
  if (cond) {
    passed++;
    console.log(`  ✓ ${label}`);
  } else {
    failures.push(label);
    console.log(`  ✗ ${label}${detail !== undefined ? `  → ${JSON.stringify(detail).slice(0, 300)}` : ''}`);
  }
}

async function http(method: string, path: string, body?: unknown): Promise<{ status: number; json: any; ms: number }> {
  const t0 = performance.now();
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: body !== undefined ? { 'content-type': 'application/json' } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json: any = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = text;
  }
  return { status: res.status, json, ms: Math.round(performance.now() - t0) };
}

/** Accept either a bare array or an object wrapping one. */
function list(json: any, ...keys: string[]): any[] {
  if (Array.isArray(json)) return json;
  for (const k of keys) if (json && Array.isArray(json[k])) return json[k];
  return [];
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function waitForRemediation(id: string, timeoutMs = 90_000): Promise<any> {
  const t0 = Date.now();
  for (;;) {
    const r = await http('GET', `/api/remediations/${id}`);
    const rem = r.json?.remediation ?? r.json;
    if (rem && (rem.status === 'immune' || rem.status === 'failed')) return rem;
    if (Date.now() - t0 > timeoutMs) return rem;
    await sleep(400);
  }
}

async function readSse(path: string, ms: number): Promise<string[]> {
  const ctrl = new AbortController();
  const events: string[] = [];
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    const res = await fetch(`${BASE}${path}`, { signal: ctrl.signal, headers: { accept: 'text/event-stream' } });
    const reader = res.body!.getReader();
    const dec = new TextDecoder();
    let buf = '';
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let i: number;
      while ((i = buf.indexOf('\n\n')) >= 0) {
        events.push(buf.slice(0, i));
        buf = buf.slice(i + 2);
      }
    }
  } catch {
    /* aborted on purpose */
  } finally {
    clearTimeout(timer);
  }
  return events;
}

async function main(): Promise<void> {
  console.log(`Immune e2e against ${BASE}\n`);

  console.log('status');
  const status = await http('GET', '/api/status');
  ok(status.status === 200, 'GET /api/status 200', status.json);
  ok(status.json?.clickhouse && status.json?.semgrep, 'status reports clickhouse + semgrep adapters', status.json);
  console.log(`    store=${status.json?.clickhouse?.connected ? 'clickhouse' : 'memory'} semgrep=${status.json?.semgrep?.installed ? status.json?.semgrep?.version : 'missing'}`);

  console.log('reset');
  const reset = await http('POST', '/api/reset');
  ok(reset.status === 200, 'POST /api/reset 200', reset.json);

  console.log('events (SSE, concurrent with an attack)');
  const ssePromise = readSse('/api/events', 6000);
  await sleep(500);

  console.log('gate: hand-written variants are blocked');
  for (const family of FAMILIES) {
    const r = await http('POST', '/api/attack', { family, variant: 'v1' });
    const traces = list(r.json, 'traces');
    ok(r.status === 200 && traces.length > 0, `launch ${family}/v1 returns traces`, r.json);
    ok(!traces.some((t: any) => t.breached), `launch ${family}/v1 does not breach`, traces.filter((t: any) => t.breached).map((t: any) => t.attemptedCall));
  }

  const sse = await ssePromise;
  ok(sse.length > 0, `GET /api/events streamed ${sse.length} event(s)`);

  console.log('loop: mutate → breach → immune → identical replay bounces (fresh state per family)');
  for (const family of FAMILIES) {
    await http('POST', '/api/reset'); // each family independently drives the whole loop
    const t0 = Date.now();
    const m = await http('POST', '/api/attack', { family, mutate: true });
    const seed = m.json?.seed;
    const remId = m.json?.remediationId;
    ok(m.status === 200 && m.json?.breach, `mutate ${family} breaches (seed ${seed})`, m.json?.error ?? m.json);
    ok(typeof remId === 'string', `mutate ${family} starts a remediation`, m.json);
    if (typeof remId !== 'string') continue;
    const rem = await waitForRemediation(remId);
    ok(rem?.status === 'immune', `remediation ${family} reaches IMMUNE`, rem?.steps?.map((s: any) => `${s.name}:${s.status}:${s.detail ?? ''}`));
    const steps: any[] = rem?.steps ?? [];
    ok(steps.length === 7 && steps.every((s) => s.status === 'done' || s.status === 'skipped'), `remediation ${family} completes all 7 steps`, steps.map((s) => `${s.name}:${s.status}`));
    ok(typeof rem?.timeToImmunityMs === 'number', `time-to-immunity ${rem?.timeToImmunityMs}ms (wall ${Date.now() - t0}ms)`);
    const replay = await http('POST', '/api/attack', { family, mutate: true, seed });
    const rt = list(replay.json, 'traces');
    const exfil = rt.filter((t: any) => t.attemptedCall && t.label === 'attack').at(-1);
    ok(!rt.some((t: any) => t.breached), `replay ${family} seed ${seed} no longer breaches`, rt.filter((t: any) => t.breached).map((t: any) => t.attemptedCall?.tool));
    ok(exfil && exfil.decision !== 'allow' && (exfil.blockedBy || exfil.citation), `replay ${family} blocked with rule/citation`, exfil && { decision: exfil.decision, blockedBy: exfil.blockedBy, citation: exfil.citation });
  }

  console.log('generalization: one antibody immunizes the whole class');
  {
    await http('POST', '/api/reset');
    const first = await http('POST', '/api/attack', { family: 'secret_exfil', mutate: true, seed: 1 });
    ok(first.json?.breach, 'first evasive variant breaches', first.json);
    if (first.json?.remediationId) await waitForRemediation(first.json.remediationId);
    const coveredFamilies: string[] = [];
    for (const family of FAMILIES.filter((f) => f !== 'secret_exfil')) {
      const r = await http('POST', '/api/attack', { family, mutate: true, seed: 1 });
      if (!r.json?.breach) coveredFamilies.push(family);
    }
    ok(coveredFamilies.length === FAMILIES.length - 1, `one antibody now blocks every other family (${coveredFamilies.length}/${FAMILIES.length - 1})`, coveredFamilies);
    // ...but a genuinely different attack vector should still be able to breach after reset
    await http('POST', '/api/reset');
    const afterReset = await http('POST', '/api/attack', { family: 'result_injection', mutate: true, seed: 1 });
    ok(afterReset.json?.breach, 'after reset the system has no memory and breaches again', afterReset.json);
    if (afterReset.json?.remediationId) await waitForRemediation(afterReset.json.remediationId);
  }

  console.log('antibodies');
  const rules = list((await http('GET', '/api/rules')).json, 'rules');
  const synthesized = rules.filter((r: any) => r.origin !== 'builtin');
  ok(synthesized.length > 0, `GET /api/rules has ${synthesized.length} synthesized rule(s)`);
  const promoted = synthesized.find((r: any) => r.status === 'promoted');
  ok(promoted?.proof && promoted.proof.catchRateAfter > promoted.proof.catchRateBefore, 'promoted rule carries a proof with catch rate up', promoted?.proof);
  ok(promoted?.proof && promoted.proof.fpRateAfter <= promoted.proof.fpRateBefore, 'promoted rule did not raise false positives', promoted?.proof);
  if (promoted) {
    const rv = await http('POST', `/api/rules/${promoted.id}/revoke`);
    ok(rv.status === 200, `POST /api/rules/${promoted.id}/revoke`, rv.json);
    const pr = await http('POST', `/api/rules/${promoted.id}/promote`);
    ok(pr.status === 200, `POST /api/rules/${promoted.id}/promote`, pr.json);
  }

  console.log('receipts');
  const receipts = list((await http('GET', '/api/receipts')).json, 'receipts');
  ok(receipts.length > 0, `GET /api/receipts has ${receipts.length}`);
  if (receipts[0]) {
    const v = await http('POST', '/api/receipts/verify', { receipt: receipts[0] });
    ok(v.json?.ok === true, 'receipt verifies', v.json);
    const tampered = JSON.parse(JSON.stringify(receipts[0]));
    tampered.proof.after.benignBlocked = (tampered.proof.after.benignBlocked ?? 0) + 1;
    const t = await http('POST', '/api/receipts/verify', { receipt: tampered });
    ok(t.json?.ok === false, 'tampered receipt fails verification', t.json);
  }

  console.log('rulings');
  const rulings = list((await http('GET', '/api/rulings')).json, 'rulings');
  ok(rulings.length > 0, `GET /api/rulings has ${rulings.length}`);

  console.log('traces');
  const traces = list((await http('GET', '/api/traces?limit=50')).json, 'traces');
  ok(traces.length > 0, `GET /api/traces returns ${traces.length}`);
  const attacksOnly = list((await http('GET', '/api/traces?limit=20&label=attack')).json, 'traces');
  ok(attacksOnly.every((t: any) => t.label === 'attack'), 'GET /api/traces label filter works');

  console.log('quarantine');
  const q = list((await http('GET', '/api/quarantine')).json, 'quarantine', 'entries', 'items');
  ok(Array.isArray(q), `GET /api/quarantine (${q.length} entries)`);
  const active = q.find((e: any) => e.active !== false);
  if (active) {
    const rel = await http('POST', '/api/quarantine/release', { server: active.server, tool: active.tool });
    ok(rel.status === 200, `release ${active.server}/${active.tool}`, rel.json);
  }

  console.log('data (ClickHouse)');
  const flood = await http('POST', '/api/flood', { attacks: 2000, benign: 8000 });
  ok(flood.status === 200 && (flood.json?.inserted ?? 0) >= 10_000, `POST /api/flood inserted ${flood.json?.inserted} in ${flood.json?.ms}ms`, flood.json);
  const queries = await http('GET', '/api/clickhouse/queries');
  const qs = list(queries.json, 'queries', 'results');
  ok(qs.length >= 4 && qs.every((x: any) => typeof x.ms === 'number' && x.sql), `GET /api/clickhouse/queries → ${qs.map((x: any) => `${x.name} ${x.ms}ms`).join(', ')}`, queries.json);
  const metrics = await http('GET', '/api/metrics');
  ok(metrics.status === 200 && typeof metrics.json?.catchRate === 'number', 'GET /api/metrics', metrics.json);

  console.log('ingest (external proxy path)');
  const sample = traces[0];
  if (sample) {
    const ing = await http('POST', '/api/ingest', { trace: { ...sample, id: `${sample.id}_ing` } });
    ok(ing.status === 200 || ing.status === 202, 'POST /api/ingest accepts a trace', ing.json);
  }

  console.log(`\n${passed} passed, ${failures.length} failed`);
  if (failures.length) {
    for (const f of failures) console.log(`  - ${f}`);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
