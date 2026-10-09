import { getEngine } from '@/server/engine';
import { HttpError, handler, json } from '@/server/http';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

export const GET = handler(async (_req: Request, ctx: { params: Promise<{ id: string }> }) => {
  const { id } = await ctx.params;
  const engine = await getEngine();
  const rem = engine.remediations.find((r) => r.id === decodeURIComponent(id));
  if (!rem) throw new HttpError(404, `remediation ${id} not found`);
  return json(rem);
});
