/**
 * Receipts — HMAC-SHA256 signed records of a proof. "Done" is refused without one.
 * signature = HMAC-SHA256(secret, payloadHash) where payloadHash = sha256(canonicalJson({ ruleId, proof })).
 */
import { createHmac, timingSafeEqual } from 'node:crypto';
import type { ProofReport, Receipt, Rule } from './types.js';
import { canonicalJson, newId, sha256 } from './ids.js';

export const DEFAULT_RECEIPT_SECRET = 'immune-dev-secret';
export const RECEIPT_SECRET_ENV = 'IMMUNE_RECEIPT_SECRET';

/** The signing secret from IMMUNE_RECEIPT_SECRET, or the dev default (flagged so status can warn). */
export function receiptSecret(env: NodeJS.ProcessEnv = process.env): { secret: string; isDefault: boolean } {
  const fromEnv = env[RECEIPT_SECRET_ENV];
  if (fromEnv && fromEnv.length > 0) return { secret: fromEnv, isDefault: false };
  return { secret: DEFAULT_RECEIPT_SECRET, isDefault: true };
}

export function receiptPayloadHash(ruleId: string, proof: ProofReport): string {
  return sha256(canonicalJson({ ruleId, proof }));
}

export function receiptSignature(payloadHash: string, secret: string): string {
  return createHmac('sha256', secret).update(payloadHash, 'utf8').digest('hex');
}

export interface SignOptions {
  id?: string;
  now?: number;
}

/** Sign a proof for a rule. `secret` defaults to receiptSecret(). */
export function signReceipt(rule: Rule | { id: string }, proof: ProofReport, secret: string = receiptSecret().secret, opts: SignOptions = {}): Receipt {
  const ruleId = rule.id;
  const payloadHash = receiptPayloadHash(ruleId, proof);
  return {
    id: opts.id ?? newId('rc'),
    ruleId,
    proof,
    createdAt: opts.now ?? Date.now(),
    algorithm: 'HMAC-SHA256',
    payloadHash,
    signature: receiptSignature(payloadHash, secret),
  };
}

export interface VerifyResult {
  ok: boolean;
  reason: string;
}

/** Verify a receipt: shape, algorithm, payload hash (tamper of ruleId/proof) and HMAC signature (secret). */
export function verifyReceipt(receipt: Receipt, secret: string = receiptSecret().secret): VerifyResult {
  if (!receipt || typeof receipt !== 'object') return { ok: false, reason: 'malformed receipt' };
  const { ruleId, proof, payloadHash, signature, algorithm } = receipt as Partial<Receipt>;
  if (typeof ruleId !== 'string' || !ruleId) return { ok: false, reason: 'malformed receipt: missing ruleId' };
  if (!proof || typeof proof !== 'object') return { ok: false, reason: 'malformed receipt: missing proof' };
  if (typeof payloadHash !== 'string' || !/^[0-9a-f]{64}$/.test(payloadHash)) return { ok: false, reason: 'malformed receipt: payloadHash is not a sha256 hex digest' };
  if (typeof signature !== 'string' || !/^[0-9a-f]{64}$/.test(signature)) return { ok: false, reason: 'malformed receipt: signature is not an HMAC-SHA256 hex digest' };
  if (algorithm !== 'HMAC-SHA256') return { ok: false, reason: `unsupported algorithm ${String(algorithm)}` };
  if (proof.ruleId !== ruleId) return { ok: false, reason: `ruleId mismatch: receipt is for ${ruleId} but proof is for ${String(proof.ruleId)}` };

  const expectedHash = receiptPayloadHash(ruleId, proof);
  if (!safeEqualHex(expectedHash, payloadHash)) return { ok: false, reason: 'payload hash mismatch: the proof or ruleId was modified after signing' };

  const expectedSig = receiptSignature(payloadHash, secret);
  if (!safeEqualHex(expectedSig, signature)) return { ok: false, reason: 'signature mismatch: wrong secret or tampered signature' };

  return { ok: true, reason: `valid: HMAC-SHA256 signature matches payload ${payloadHash.slice(0, 12)}… (proof ${proof.promoted ? 'promoted' : 'not promoted'}, corpus ${proof.corpusSize})` };
}

function safeEqualHex(a: string, b: string): boolean {
  const ba = Buffer.from(a, 'hex');
  const bb = Buffer.from(b, 'hex');
  if (ba.length !== bb.length || ba.length === 0) return false;
  return timingSafeEqual(ba, bb);
}
