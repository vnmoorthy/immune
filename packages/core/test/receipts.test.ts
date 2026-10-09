import { describe, expect, it } from 'vitest';
import { DEFAULT_RECEIPT_SECRET, receiptPayloadHash, receiptSecret, signReceipt, verifyReceipt, type ProofReport, type Receipt } from '../src/index.js';

const proof: ProofReport = {
  ruleId: 'rl_abc',
  corpusSize: 10,
  corpusHash: 'a'.repeat(64),
  before: { attacksTotal: 2, attacksCaught: 1, benignTotal: 8, benignBlocked: 0 },
  after: { attacksTotal: 2, attacksCaught: 2, benignTotal: 8, benignBlocked: 0 },
  catchRateBefore: 0.5,
  catchRateAfter: 1,
  fpRateBefore: 0,
  fpRateAfter: 0,
  targetCaught: true,
  replayMs: 3,
  promoted: true,
  reason: 'ok',
  ts: 1,
};

describe('receipts', () => {
  it('signs and verifies with the default dev secret (flagged as default)', () => {
    const rc = signReceipt({ id: 'rl_abc' }, proof);
    expect(rc.id).toMatch(/^rc_[0-9a-f]{12}$/);
    expect(rc.algorithm).toBe('HMAC-SHA256');
    expect(rc.payloadHash).toBe(receiptPayloadHash('rl_abc', proof));
    expect(rc.signature).toMatch(/^[0-9a-f]{64}$/);
    const v = verifyReceipt(rc);
    expect(v.ok).toBe(true);
    expect(v.reason).toContain('valid');
    expect(receiptSecret({})).toEqual({ secret: DEFAULT_RECEIPT_SECRET, isDefault: true });
    expect(receiptSecret({ IMMUNE_RECEIPT_SECRET: 'prod' })).toEqual({ secret: 'prod', isDefault: false });
  });

  it('is deterministic for the same payload and key-order independent', () => {
    const a = signReceipt({ id: 'rl_abc' }, proof, 's', { id: 'rc_1', now: 5 });
    const b = signReceipt({ id: 'rl_abc' }, { ...proof, after: { benignBlocked: 0, benignTotal: 8, attacksCaught: 2, attacksTotal: 2 } }, 's', { id: 'rc_1', now: 5 });
    expect(a).toEqual(b);
  });

  it('fails on tampered proof, tampered ruleId, tampered signature and wrong secret', () => {
    const rc = signReceipt({ id: 'rl_abc' }, proof, 'secret-1');
    expect(verifyReceipt(rc, 'secret-1').ok).toBe(true);
    const tamperedProof: Receipt = { ...rc, proof: { ...rc.proof, fpRateAfter: 0.4 } };
    expect(verifyReceipt(tamperedProof, 'secret-1')).toMatchObject({ ok: false, reason: expect.stringContaining('payload hash mismatch') });
    const tamperedRule: Receipt = { ...rc, ruleId: 'rl_other' };
    expect(verifyReceipt(tamperedRule, 'secret-1').ok).toBe(false);
    const tamperedSig: Receipt = { ...rc, signature: rc.signature.replace(/^./, rc.signature.startsWith('0') ? '1' : '0') };
    expect(verifyReceipt(tamperedSig, 'secret-1')).toMatchObject({ ok: false, reason: expect.stringContaining('signature mismatch') });
    expect(verifyReceipt(rc, 'secret-2')).toMatchObject({ ok: false, reason: expect.stringContaining('signature mismatch') });
    const rehashed: Receipt = { ...tamperedProof, payloadHash: receiptPayloadHash('rl_abc', tamperedProof.proof) };
    expect(verifyReceipt(rehashed, 'secret-1')).toMatchObject({ ok: false, reason: expect.stringContaining('signature mismatch') });
    expect(verifyReceipt({ ...rc, algorithm: 'MD5' as unknown as 'HMAC-SHA256' }, 'secret-1').reason).toContain('unsupported algorithm');
    expect(verifyReceipt({} as Receipt, 'secret-1').ok).toBe(false);
  });
});
