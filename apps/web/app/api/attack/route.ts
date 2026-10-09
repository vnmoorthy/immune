import type { AttackRequest } from '@/lib/api';
import { getEngine } from '@/server/engine';
import { HttpError, handler, json, readJson } from '@/server/http';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

export const POST = handler(async (req: Request) => {
  const body = await readJson<Partial<AttackRequest>>(req);
  if (!body.family || typeof body.family !== 'string') throw new HttpError(400, 'family is required');
  const engine = await getEngine();
  const res = await engine.attack({
    family: body.family,
    variant: typeof body.variant === 'string' ? body.variant : undefined,
    mutate: body.mutate === true,
    seed: typeof body.seed === 'number' && Number.isFinite(body.seed) ? body.seed : undefined,
    count: typeof body.count === 'number' ? body.count : undefined,
  });
  return json(res);
});
