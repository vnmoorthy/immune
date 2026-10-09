import { getEngine } from '@/server/engine';
import { HttpError, handler, json, readJson } from '@/server/http';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

export const POST = handler(async (req: Request) => {
  const body = await readJson<{ server?: string; tool?: string }>(req);
  if (!body.server || !body.tool) throw new HttpError(400, 'server and tool are required');
  const engine = await getEngine();
  return json(engine.release(body.server, body.tool));
});
