/**
 * Records the product footage for the product video, one file per scene, against the running command center.
 *
 *   node scripts/video/record-scenes.mjs <outDir> [base]
 *
 * Produces: s2-gate.webm · loop.webm (scenes 3–5, with cuts.json giving the cut times) · s6-proof.webm · s7-data.webm
 * Needs playwright-core resolvable from cwd (scripts/video/package.json installs it) and Google Chrome.
 */
import { chromium } from 'playwright-core';
import fs from 'node:fs';
import path from 'node:path';

const out = process.argv[2];
const base = process.argv[3] ?? 'http://localhost:3000';
fs.mkdirSync(out, { recursive: true });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function until(page, re, ms) {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) {
    const t = await page.evaluate(() => document.body.innerText);
    if (re.test(t)) return true;
    await sleep(400);
  }
  return false;
}

async function post(p, body) {
  await fetch(base + p, { method: 'POST', headers: body ? { 'content-type': 'application/json' } : undefined, body: body ? JSON.stringify(body) : undefined });
}

const browser = await chromium.launch({ channel: 'chrome', headless: true });

async function scene(name, fn) {
  const ctx = await browser.newContext({ viewport: { width: 1600, height: 1000 }, colorScheme: 'dark', recordVideo: { dir: out, size: { width: 1600, height: 1000 } } });
  const page = await ctx.newPage();
  const started = Date.now();
  const marks = {};
  const mark = (k) => { marks[k] = (Date.now() - started) / 1000; };
  const warm = async (p) => { await page.goto(base + p, { waitUntil: 'load', timeout: 120000 }); await until(page, /LIVE\s+\d/, 40000); };
  await fn({ page, warm, mark });
  const video = page.video();
  await ctx.close();
  const src = await video.path();
  const dst = path.join(out, `${name}.webm`);
  fs.renameSync(src, dst);
  console.log('✓', name, JSON.stringify(marks));
  return marks;
}

// fresh, well-populated state
await post('/api/reset');
await post('/api/flood', { attacks: 3000, benign: 12000 });

const launchBtn = (page) => page.getByRole('button', { name: /^launch$/i });
const mutateBtn = (page) => page.getByRole('button', { name: /^mutate$/i });

// Scene 2 — the gate: two known attacks, blocked
await scene('s2-gate', async ({ page, warm }) => {
  await warm('/'); await sleep(2500);
  await launchBtn(page).nth(0).click(); await sleep(3000);
  await launchBtn(page).nth(2).click(); await sleep(4000);
});

// Scenes 3–5 — breach → loop → replay bounces → other families immune (one continuous context; cut times recorded)
const cuts = await scene('loop', async ({ page, warm, mark }) => {
  await warm('/'); await sleep(2000);
  mark('t3');
  await mutateBtn(page).nth(2).click();
  await until(page, /BREACH\s*[×x]/i, 30000); await sleep(2500);
  mark('t4');
  // wait for the remediation to actually reach IMMUNE (the theatre lists step labels even while pending, so ask the API)
  const t0 = Date.now();
  while (Date.now() - t0 < 180000) {
    const r = await (await fetch(base + '/api/remediations')).json();
    const list = Array.isArray(r) ? r : r.remediations ?? [];
    if (list.some((x) => x.status === 'immune')) break;
    await sleep(500);
  }
  await sleep(5000);
  mark('t5');
  const replay = page.getByRole('button', { name: /replay\s*#/i });
  if (await replay.count()) { await replay.first().click(); await sleep(3500); }
  await mutateBtn(page).nth(5).click(); await sleep(3000);
  await mutateBtn(page).nth(3).click(); await sleep(3000);
  await mutateBtn(page).nth(4).click(); await sleep(3500);
  mark('end');
});
fs.writeFileSync(path.join(out, 'cuts.json'), JSON.stringify(cuts, null, 2));

// Scene 6 — proof: antibodies, receipts tamper → verify
await scene('s6-proof', async ({ page, warm }) => {
  await warm('/antibodies'); await sleep(6000);
  await warm('/receipts'); await sleep(2500);
  const verify = page.getByRole('button', { name: /^verify$/i });
  if (await verify.count()) { await verify.first().click(); await sleep(2500); }
  const tamper = page.getByRole('button', { name: /tamper/i });
  if (await tamper.count()) { await tamper.first().click(); await sleep(1500); }
  if (await verify.count()) { await verify.first().click(); await sleep(4000); }
});

// Scene 7 — data: the ClickHouse panel
await scene('s7-data', async ({ page, warm }) => {
  await warm('/data'); await sleep(5000);
  await page.mouse.wheel(0, 500); await sleep(4000);
  await page.mouse.wheel(0, 500); await sleep(4000);
});

await browser.close();
console.log('done');
