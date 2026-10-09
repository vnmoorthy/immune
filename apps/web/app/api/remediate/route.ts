import { getEngine } from '@/server/engine';
import { HttpError, handler, json, readJson } from '@/server/http';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

export const POST = handler(async (req: Request) => {
  const body = await readJson<{ traceId?: string }>(req);
  if (!body.traceId || typeof body.traceId !== 'string') throw new HttpError(400, 'traceId is required');
  const engine = await getEngine();
  const remediation = await engine.remediate(body.traceId);
  return json({ remediationId: remediation.id, remediation });
});
