/**
 * Puts the command center into a rich, realistic state for screenshots and live demos:
 * reset → launch every family (blocked) → mutate one family (breach → remediation → IMMUNE)
 * → flood ClickHouse → a few benign bursts. Leaves one completed remediation in the theatre.
 *
 *   npx tsx scripts/seed-demo.ts [base_url]
 */
const BASE = process.argv[2] ?? 'http://localhost:3000';
const FAMILIES = ['poisoned_description', 'result_injection', 'secret_exfil', 'rug_pull', 'homoglyph_spoof', 'indirect_fetch'];
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function post(path: string, body?: unknown): Promise<any> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: body !== undefined ? { 'content-type': 'application/json' } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  return res.json();
}

async function waitFor(id: string): Promise<any> {
  for (let i = 0; i < 120; i++) {
    const r = await (await fetch(`${BASE}/api/remediations/${id}`)).json();
    const rem = r.remediation ?? r;
    if (rem?.status === 'immune' || rem?.status === 'failed') return rem;
    await sleep(400);
  }
}

async function main(): Promise<void> {
  console.log('reset');
  await post('/api/reset');
  console.log('flood ClickHouse: 6,000 attacks + 24,000 benign');
  console.log(' ', await post('/api/flood', { attacks: 6000, benign: 24000 }));
  console.log('launch every family (hand-written → blocked)');
  for (const family of FAMILIES) {
    for (const variant of ['v1', 'v2', 'v3']) await post('/api/attack', { family, variant });
  }
  console.log('benign bursts');
  for (let i = 0; i < 4; i++) await post('/api/attack', { family: 'benign', count: 10 });
  console.log('mutate secret_exfil → breach → remediation');
  const m = await post('/api/attack', { family: 'secret_exfil', mutate: true });
  console.log(`  breach=${!!m.breach} seed=${m.seed}`);
  if (m.remediationId) {
    const rem = await waitFor(m.remediationId);
    console.log(`  remediation ${rem?.status} in ${rem?.timeToImmunityMs} ms`);
  }
  console.log('replay the identical attack (must bounce)');
  const r = await post('/api/attack', { family: 'secret_exfil', mutate: true, seed: m.seed });
  console.log(`  breach=${!!r.breach}`);
  console.log('mutate two other families (generalization: blocked by the same antibody)');
  for (const family of ['indirect_fetch', 'rug_pull']) {
    const x = await post('/api/attack', { family, mutate: true });
    console.log(`  ${family}: breach=${!!x.breach}`);
  }
  console.log('done');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
