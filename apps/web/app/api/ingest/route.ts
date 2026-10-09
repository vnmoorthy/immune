import { getEngine } from '@/server/engine';
import { HttpError, handler, json, readJson } from '@/server/http';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

/** External proxy → engine. Body: { trace } (or a bare Trace). */
export const POST = handler(async (req: Request) => {
  const body = await readJson<{ trace?: unknown } | Record<string, unknown>>(req);
  const trace = body && typeof body === 'object' && 'trace' in body ? (body as { trace: unknown }).trace : body;
  if (!trace || typeof trace !== 'object') throw new HttpError(400, 'trace is required');
  const engine = await getEngine();
  return json(await engine.ingest(trace));
});
