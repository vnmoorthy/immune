import { getEngine } from '@/server/engine';
import { handler, json } from '@/server/http';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

export const GET = handler(async () => {
  const engine = await getEngine();
  return json(await engine.clickhouseQueries());
});
