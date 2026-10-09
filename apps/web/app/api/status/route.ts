import type { StatusResponse } from '@/lib/api';
import { getEngine } from '@/server/engine';
import { handler, json } from '@/server/http';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

// Adapter probes (semgrep / senso CLIs, store ping) are cached briefly so the command bar is never
// starved by the burst of requests the command center fires on load.
const TTL_MS = 4000;
let cache: { at: number; value: StatusResponse } | null = null;
let inflight: Promise<StatusResponse> | null = null;

async function status(): Promise<StatusResponse> {
  if (cache && Date.now() - cache.at < TTL_MS) return cache.value;
  if (!inflight) {
    inflight = (async () => {
      try {
        const engine = await getEngine();
        const value = await engine.status();
        cache = { at: Date.now(), value };
        return value;
      } finally {
        inflight = null;
      }
    })();
  }
  return inflight;
}

// warm the adapter probes as soon as the route module loads
void status().catch(() => undefined);

export const GET = handler(async () => json(await status()));
