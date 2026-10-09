import type { AttackFamily, Decision } from '@immune/core';
import { getEngine } from '@/server/engine';
import { handler, json } from '@/server/http';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

export const GET = handler(async (req: Request) => {
  const u = new URL(req.url);
  const p = u.searchParams;
  const engine = await getEngine();
  const label = p.get('label');
  const res = await engine.traces({
    limit: p.get('limit') ? Number(p.get('limit')) : undefined,
    label: label === 'attack' || label === 'benign' ? label : undefined,
    family: (p.get('family') as AttackFamily | null) ?? undefined,
    decision: (p.get('decision') as Decision | null) ?? undefined,
    breached: p.get('breached') === '1' || p.get('breached') === 'true',
    q: p.get('q') ?? undefined,
    id: p.get('id') ?? undefined,
  });
  return json(res);
});
