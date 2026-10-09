import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { signReceipt } from '@immune/core';
import type { ProofReport, Rule } from '@immune/core';
import { describe, expect, it } from 'vitest';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../../..');
const CLI = resolve(HERE, '../src/cli.ts');
const TSX = resolve(ROOT, 'node_modules/.bin/tsx');
const SECRET = 'e2e-test-secret';

const rule: Rule = {
  id: 'rl_e2e000000001',
  name: 'block tainted webhook to attacker host',
  version: 1,
  createdAt: 1_700_000_000_000,
  origin: 'synthesized',
  derivedFrom: ['tr_e2e000000001'],
  match: { phase: 'tool_call', capabilities: ['network'], afterTainted: true, destinationNotIn: ['hooks.acme.example'] },
  action: 'block',
  severity: 'critical',
  status: 'promoted',
};

const proof: ProofReport = {
  ruleId: rule.id,
  corpusSize: 2400,
  corpusHash: 'a'.repeat(64),
  before: { attacksTotal: 400, attacksCaught: 390, benignTotal: 2000, benignBlocked: 0 },
  after: { attacksTotal: 400, attacksCaught: 400, benignTotal: 2000, benignBlocked: 0 },
  catchRateBefore: 0.975,
  catchRateAfter: 1,
  fpRateBefore: 0,
  fpRateAfter: 0,
  targetCaught: true,
  replayMs: 12,
  promoted: true,
  reason: 'target caught, catch rate up, no new false positives',
  ts: 1_700_000_000_500,
};

function runVerify(file: string): { code: number; out: string } {
  const res = spawnSync(TSX, [CLI, 'verify', file], {
    encoding: 'utf8',
    env: { ...process.env, IMMUNE_RECEIPT_SECRET: SECRET },
  });
  return { code: res.status ?? -1, out: `${res.stdout}${res.stderr}` };
}

describe('immune verify', () => {
  const dir = mkdtempSync(join(tmpdir(), 'immune-verify-'));
  const receipt = signReceipt(rule, proof, SECRET);

  it('prints OK and exits 0 for a genuine receipt', () => {
    const file = join(dir, 'ok.json');
    writeFileSync(file, JSON.stringify(receipt, null, 2));
    const { code, out } = runVerify(file);
    expect(out).toMatch(/^OK\s+receipt rc_/m);
    expect(code).toBe(0);
  });

  it('prints FAIL and exits 1 when the proof was tampered with', () => {
    const file = join(dir, 'tampered.json');
    const tampered = { ...receipt, proof: { ...receipt.proof, fpRateAfter: 0.5, promoted: true } };
    writeFileSync(file, JSON.stringify(tampered, null, 2));
    const { code, out } = runVerify(file);
    expect(out).toMatch(/^FAIL\s+receipt rc_/m);
    expect(code).toBe(1);
  });

  it('fails cleanly on a file that is not a receipt', () => {
    const file = join(dir, 'garbage.json');
    writeFileSync(file, '{"hello":"world"}');
    const { code, out } = runVerify(file);
    expect(out).toMatch(/^FAIL/m);
    expect(code).toBe(1);
  });
});
