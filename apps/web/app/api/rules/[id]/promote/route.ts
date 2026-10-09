import { getEngine } from '@/server/engine';
import { handler, json } from '@/server/http';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

export const POST = handler(async (_req: Request, ctx: { params: Promise<{ id: string }> }) => {
  const { id } = await ctx.params;
  const engine = await getEngine();
  return json(engine.promoteRule(decodeURIComponent(id)));
});
