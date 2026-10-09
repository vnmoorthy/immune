import { getEngine } from '@/server/engine';
import { handler, json, readJson } from '@/server/http';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

export const POST = handler(async (req: Request) => {
  const body = await readJson<{ attacks?: number; benign?: number }>(req);
  const engine = await getEngine();
  return json(await engine.flood(Number(body.attacks ?? 0), Number(body.benign ?? 0)));
});
