/**
 * Renders the lower-third caption overlays (transparent PNGs, 1600×1000) for the product video.
 *
 *   node scripts/video/render-cards.mjs <outDir>
 *
 * One PNG per section (caption-1..8.png). Captions sit bottom-right, clear of the presenter circle (bottom-left).
 */
import { chromium } from 'playwright-core';
import fs from 'node:fs';
import path from 'node:path';

const out = process.argv[2];
fs.mkdirSync(out, { recursive: true });

export const CAPTIONS = [
  { k: '00', label: 'Immune', title: 'Every attack becomes an antibody', sub: 'MCP firewall · replay-proven countermeasures · signed receipts' },
  { k: '01', label: 'The gate', title: 'Six detector families. 0.06 ms per decision.', sub: '36 / 36 known variants blocked' },
  { k: '02', label: 'The breach', title: 'A novel variant gets through.', sub: 'allowlisted host · credentials in four-character groups' },
  { k: '03', label: 'The loop', title: 'Antigen → antibody → proof → receipt → ruling → immune', sub: 'replayed over 32,589 traces in ClickHouse · catch 76.7% → 98.1% · FP 0 → 0' },
  { k: '04', label: 'One breach, whole class', title: 'Same antibody. Every family blocked.', sub: 'denials cite the ruling' },
  { k: '05', label: 'Proof, not claims', title: 'HMAC-signed receipts. Tamper and it fails.', sub: 'no receipt, no "done"' },
  { k: '06', label: 'The stack', title: 'ClickHouse · Semgrep · Guild · Senso · AkashML', sub: 'drop-in MCP proxy for Claude Code · zero API keys' },
  { k: '07', label: 'Open source', title: 'github.com/vnmoorthy/immune', sub: 'MIT · 186 tests · 77 end-to-end checks' },
];

const html = (c) => `<!doctype html><html><head><meta charset="utf-8">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  html,body{margin:0;width:1600px;height:1000px;background:transparent;overflow:hidden;font-family:Inter,system-ui,sans-serif}
  .lt{position:absolute;right:40px;bottom:40px;max-width:760px;padding:22px 28px 24px;background:rgba(8,9,11,.82);border:1px solid rgba(255,255,255,.12);border-left:3px solid #3ecf8e;backdrop-filter:blur(6px);color:#e8e9eb}
  .label{font-family:'JetBrains Mono',Menlo,monospace;font-size:13px;letter-spacing:.16em;text-transform:uppercase;color:#9aa0a6;margin-bottom:10px}
  .label b{color:#3ecf8e;font-weight:500;margin-right:14px}
  .title{font-size:30px;font-weight:400;letter-spacing:-.01em;line-height:1.2}
  .sub{font-family:'JetBrains Mono',Menlo,monospace;font-size:14px;color:#9aa0a6;margin-top:10px;letter-spacing:.02em}
</style></head><body>
<div class="lt"><div class="label"><b>${c.k}</b>${c.label}</div><div class="title">${c.title}</div><div class="sub">${c.sub}</div></div>
</body></html>`;

const browser = await chromium.launch({ channel: 'chrome', headless: true });
const page = await (await browser.newContext({ viewport: { width: 1600, height: 1000 }, deviceScaleFactor: 1 })).newPage();
for (let i = 0; i < CAPTIONS.length; i++) {
  await page.setContent(html(CAPTIONS[i]), { waitUntil: 'load' });
  await page.waitForTimeout(700);
  await page.screenshot({ path: path.join(out, `caption-${i + 1}.png`), omitBackground: true });
  console.log('✓ caption', i + 1);
}
await browser.close();
