/**
 * Records the footage for the professional product video: animated intro/outro cards plus six product scenes
 * with slow, human-paced interaction. One file per scene (webm) + cuts.json for the continuous loop scene.
 *
 *   node scripts/video/record-pro.mjs <outDir> [base]
 *
 * Scenes: intro.webm · s2-gate.webm · loop.webm (s3 breach → s4 loop → s5 replay+families; cuts.json has t4/t5) ·
 *         s6-proof.webm · s7-stack.webm · outro.webm
 */
import { chromium } from 'playwright-core';
import fs from 'node:fs';
import path from 'node:path';

const out = process.argv[2];
const base = process.argv[3] ?? 'http://localhost:3000';
fs.mkdirSync(out, { recursive: true });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const W = 1600, H = 1000;

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
async function remediationDone() {
  const t0 = Date.now();
  while (Date.now() - t0 < 180000) {
    const r = await (await fetch(base + '/api/remediations')).json();
    const list = Array.isArray(r) ? r : r.remediations ?? [];
    if (list.length && list.every((x) => x.status !== 'running')) return list.some((x) => x.status === 'immune');
    await sleep(500);
  }
  return false;
}

// human-like cursor
async function glideTo(page, locator, opts = {}) {
  const box = await locator.boundingBox();
  if (!box) return null;
  const x = box.x + box.width * (opts.fx ?? 0.5), y = box.y + box.height * (opts.fy ?? 0.5);
  await page.mouse.move(x, y, { steps: opts.steps ?? 36 });
  return { x, y };
}
async function clickSlow(page, locator) {
  const p = await glideTo(page, locator);
  await sleep(450);
  if (p) await page.mouse.down(), await sleep(90), await page.mouse.up();
  else await locator.click();
}

const browser = await chromium.launch({ channel: 'chrome', headless: true });

async function scene(name, fn) {
  const ctx = await browser.newContext({ viewport: { width: W, height: H }, colorScheme: 'dark', recordVideo: { dir: out, size: { width: W, height: H } } });
  const page = await ctx.newPage();
  const started = Date.now();
  const marks = {};
  const mark = (k) => { marks[k] = (Date.now() - started) / 1000; };
  const warm = async (p) => { await page.goto(base + p, { waitUntil: 'load', timeout: 120000 }); await until(page, /LIVE\s+\d/, 40000); };
  try { await fn({ page, warm, mark }); } catch (e) { console.error('scene error', name, e.message); }
  const video = page.video();
  await ctx.close();
  fs.renameSync(await video.path(), path.join(out, `${name}.webm`));
  console.log('✓', name, JSON.stringify(marks));
  return marks;
}

const card = (body) => `<!doctype html><html><head><meta charset="utf-8">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  html,body{margin:0;height:100%;background:#000;color:#e8e9eb;font-family:Inter,system-ui,sans-serif;overflow:hidden}
  .grid{position:absolute;inset:0;background-image:linear-gradient(rgba(255,255,255,.045) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.045) 1px,transparent 1px);background-size:80px 80px;opacity:0;animation:fade 1.6s .2s forwards}
  .mono{font-family:'JetBrains Mono',ui-monospace,Menlo,monospace;letter-spacing:.14em;text-transform:uppercase;font-size:14px;color:#9aa0a6}
  .wrap{position:absolute;left:120px;top:0;bottom:0;right:120px;display:flex;flex-direction:column;justify-content:center}
  .word{font-weight:500;font-size:168px;letter-spacing:-.02em;line-height:1;display:flex}
  .word span{opacity:0;transform:translateY(24px);animation:up .7s cubic-bezier(.2,.7,.2,1) forwards}
  .rule{height:1px;background:rgba(255,255,255,.18);width:0;animation:grow 1.2s 1.2s cubic-bezier(.2,.7,.2,1) forwards;margin:28px 0}
  .tag{font-weight:300;font-size:46px;opacity:0;animation:fade 1s 1.8s forwards}
  .sub{margin-top:26px;opacity:0;animation:fade 1s 2.6s forwards}
  .rail{position:absolute;left:120px;right:120px;bottom:120px;display:flex;gap:18px;align-items:center}
  .rail .mono{color:#6b7075;font-size:13px;opacity:0;animation:fade .5s forwards}
  .rail .mono.on{color:#e8e9eb}
  .dot{width:6px;height:6px;background:#3ecf8e;border-radius:50%;display:inline-block;margin-right:10px;vertical-align:middle}
  .top{position:absolute;top:56px;left:120px;right:120px;display:flex;justify-content:space-between;opacity:0;animation:fade 1s .4s forwards}
  .pulse{animation:pulse 2.4s 3.4s ease-in-out infinite}
  @keyframes up{to{opacity:1;transform:none}} @keyframes fade{to{opacity:1}} @keyframes grow{to{width:100%}}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.55}}
</style></head><body>${body}</body></html>`;

const letters = (s, delay = 0.35) => [...s].map((c, i) => `<span style="animation-delay:${(delay + i * 0.07).toFixed(2)}s">${c}</span>`).join('');
const steps = ['01 ANTIGEN', '02 ANTIBODY', '03 PROOF', '04 SEMGREP', '05 RECEIPT', '06 RULING', '07 IMMUNITY'];
const rail = (start) => steps.map((s, i) => `<span class="mono ${i === 6 ? 'on' : ''}" style="animation-delay:${(start + i * 0.22).toFixed(2)}s">${s}${i < 6 ? '<span style="margin-left:18px;color:#3a3d42">→</span>' : ''}</span>`).join('');

const introHTML = card(`
  <div class="grid"></div>
  <div class="top"><span class="mono">Immune · agent security loop</span><span class="mono">Cyberdefense Hackathon · SF Tech Week 2026</span></div>
  <div class="wrap">
    <div class="word">${letters('IMMUNE')}</div>
    <div class="rule"></div>
    <div class="tag">every attack becomes an antibody<span class="pulse" style="color:#3ecf8e">.</span></div>
    <div class="sub mono">MCP firewall · replay-proven countermeasures · signed receipts · the next agent is immune</div>
  </div>
  <div class="rail">${rail(3.0)}</div>`);

const outroHTML = card(`
  <div class="grid"></div>
  <div class="top"><span class="mono">Immune · open source · MIT</span><span class="mono">built in one afternoon · October 9, 2026</span></div>
  <div class="wrap" style="right:120px">
    <div class="mono" style="opacity:0;animation:fade .8s .3s forwards"><span class="dot"></span>Time to immunity: seconds, not days</div>
    <div class="word" style="font-size:132px;margin-top:22px">${letters('IMMUNE', 0.6)}</div>
    <div class="rule"></div>
    <div class="tag" style="font-size:40px">github.com/vnmoorthy/immune</div>
    <div class="sub mono">catch it · prove it · sign it · publish it · verify it</div>
  </div>
  <div class="rail">${rail(2.4)}</div>`);

// ----- fresh, populated state -----
await post('/api/reset');
await post('/api/flood', { attacks: 3000, benign: 12000 });

const launchBtn = (page) => page.getByRole('button', { name: /^launch$/i });
const mutateBtn = (page) => page.getByRole('button', { name: /^mutate$/i });

await scene('intro', async ({ page }) => {
  await page.setContent(introHTML, { waitUntil: 'load' });
  await sleep(600); // fonts
  await sleep(26000);
});

await scene('s2-gate', async ({ page, warm }) => {
  await warm('/'); await sleep(3500);
  await clickSlow(page, launchBtn(page).nth(0)); await sleep(5200);
  await clickSlow(page, launchBtn(page).nth(2)); await sleep(5200);
  await clickSlow(page, launchBtn(page).nth(4)); await sleep(4500);
  const wire = page.getByText(/LIVE WIRE/i).first();
  await glideTo(page, wire); await sleep(1200);
  await page.mouse.wheel(0, 260); await sleep(5000);
  const rows = page.locator('table tbody tr, [role=row]');
  if (await rows.count()) { await glideTo(page, rows.nth(0)); await sleep(2500); await glideTo(page, rows.nth(2)); await sleep(2500); }
  await sleep(4000);
});

const cuts = await scene('loop', async ({ page, warm, mark }) => {
  await warm('/'); await sleep(2500);
  mark('t3');
  await clickSlow(page, mutateBtn(page).nth(2));
  await until(page, /BREACH\s*[×x]/i, 30000);
  await sleep(1500);
  const breachRow = page.getByText(/BREACH/).last();
  await glideTo(page, breachRow); await sleep(3500);
  mark('t4');
  const immune = await remediationDone();
  await sleep(1200);
  // walk the seven steps of the theatre with the cursor
  const stepRe = [/Trace captured/i, /Antibody drafted/i, /Replay proven/i, /Semgrep rescan/i, /Receipt signed/i, /Ruling published/i, /Immunity verified/i];
  for (const re of stepRe) { const el = page.getByText(re).first(); if (await el.count()) { await glideTo(page, el, { fx: 0.2 }); await sleep(3200); } }
  const tti = page.getByText(/TIME TO IMMUNITY/i).first();
  if (await tti.count()) { await glideTo(page, tti); await sleep(3500); }
  mark('t5');
  const replay = page.getByRole('button', { name: /replay\s*#/i });
  if (await replay.count()) { await clickSlow(page, replay.first()); await sleep(5000); }
  for (const n of [5, 3, 4]) { await clickSlow(page, mutateBtn(page).nth(n)); await sleep(4200); }
  await glideTo(page, page.getByText(/LIVE WIRE/i).first()); await sleep(4000);
  mark('end');
  console.error('immune:', immune);
});
fs.writeFileSync(path.join(out, 'cuts.json'), JSON.stringify(cuts, null, 2));

await scene('s6-proof', async ({ page, warm }) => {
  await warm('/antibodies'); await sleep(3500);
  const expander = page.locator('table tbody tr').first().locator('button').first();
  if (await expander.count()) { await clickSlow(page, expander); await sleep(6000); await page.mouse.wheel(0, 240); await sleep(4000); }
  await warm('/receipts'); await sleep(3000);
  const verify = page.getByRole('button', { name: /^verify$/i });
  if (await verify.count()) { await clickSlow(page, verify.first()); await sleep(4500); }
  const tamper = page.getByRole('button', { name: /tamper/i });
  if (await tamper.count()) { await clickSlow(page, tamper.first()); await sleep(2500); }
  if (await verify.count()) { await clickSlow(page, verify.first()); await sleep(7000); }
});

await scene('s7-stack', async ({ page, warm }) => {
  await warm('/data'); await sleep(6000);
  await page.mouse.move(800, 500, { steps: 20 });
  await page.mouse.wheel(0, 420); await sleep(6000);
  await page.mouse.wheel(0, 420); await sleep(6000);
  await warm('/rulings'); await sleep(7000);
  await warm('/'); await sleep(6000);
});

await scene('outro', async ({ page }) => {
  await page.setContent(outroHTML, { waitUntil: 'load' });
  await sleep(600);
  await sleep(24000);
});

await browser.close();
console.log('done');
