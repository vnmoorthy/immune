import type { Receipt } from '@immune/core';
import { getEngine } from '@/server/engine';
import { HttpError, handler, json, readJson } from '@/server/http';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

export const POST = handler(async (req: Request) => {
  const body = await readJson<{ receipt?: Receipt } | Receipt>(req);
  const receipt = (body && typeof body === 'object' && 'receipt' in body ? body.receipt : (body as Receipt)) as Receipt | undefined;
  if (!receipt || typeof receipt !== 'object') throw new HttpError(400, 'receipt is required');
  const engine = await getEngine();
  return json(engine.verifyReceipt(receipt));
});
