import { readFileSync } from 'node:fs';
import { receiptSecret, verifyReceipt } from '@immune/core';
import type { Receipt } from '@immune/core';
import { ImmuneApi } from './api.js';
import { errorMessage } from './log.js';

function unwrapReceipt(parsed: unknown): Receipt | null {
  const candidate =
    parsed && typeof parsed === 'object' && 'receipt' in parsed ? (parsed as { receipt: unknown }).receipt : parsed;
  if (!candidate || typeof candidate !== 'object') return null;
  const r = candidate as Partial<Receipt>;
  if (typeof r.id !== 'string' || typeof r.ruleId !== 'string' || typeof r.signature !== 'string' || !r.proof) return null;
  return r as Receipt;
}

/** Returns the process exit code: 0 = OK, 1 = FAIL. */
export async function runVerify(file: string, opts: { api: string; remote?: boolean }): Promise<number> {
  let receipt: Receipt | null;
  try {
    receipt = unwrapReceipt(JSON.parse(readFileSync(file, 'utf8')));
  } catch (err) {
    console.log(`FAIL  ${file}: ${errorMessage(err)}`);
    return 1;
  }
  if (!receipt) {
    console.log(`FAIL  ${file}: not a receipt (expected {id, ruleId, proof, signature} or {receipt: ...})`);
    return 1;
  }

  let ok: boolean;
  let reason: string;
  try {
    if (opts.remote) {
      ({ ok, reason } = await new ImmuneApi(opts.api).verifyReceipt(receipt));
    } else {
      const { secret, isDefault } = receiptSecret();
      if (isDefault) process.stderr.write('[immune] verifying with the default dev secret (set IMMUNE_RECEIPT_SECRET)\n');
      ({ ok, reason } = verifyReceipt(receipt, secret));
    }
  } catch (err) {
    console.log(`FAIL  receipt ${receipt.id}: ${errorMessage(err)}`);
    return 1;
  }

  const proof = receipt.proof;
  const summary = `rule ${receipt.ruleId}; catch ${pct(proof.catchRateBefore)} -> ${pct(proof.catchRateAfter)}, fp ${pct(proof.fpRateBefore)} -> ${pct(proof.fpRateAfter)} over ${proof.corpusSize} traces`;
  console.log(`${ok ? 'OK  ' : 'FAIL'}  receipt ${receipt.id}: ${reason || (ok ? 'signature valid' : 'invalid')} (${summary})`);
  return ok ? 0 : 1;
}

function pct(n: number | undefined): string {
  return typeof n === 'number' && Number.isFinite(n) ? `${(n * 100).toFixed(1)}%` : '?';
}
