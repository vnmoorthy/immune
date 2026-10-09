import type { ImmuneEvent } from '@immune/core';
import { getEngine } from '@/server/engine';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

/** Server-sent events: every ImmuneEvent as `data: <json>`; heartbeat comment every 10s. */
export async function GET(req: Request): Promise<Response> {
  const engine = await getEngine();
  const encoder = new TextEncoder();
  let unsubscribe: (() => void) | null = null;
  let heartbeat: ReturnType<typeof setInterval> | null = null;

  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      let closed = false;
      const write = (chunk: string) => {
        if (closed) return;
        try {
          controller.enqueue(encoder.encode(chunk));
        } catch {
          cleanup();
        }
      };
      const send = (e: ImmuneEvent) => write(`id: ${e.id}\ndata: ${JSON.stringify(e)}\n\n`);
      const cleanup = () => {
        if (closed) return;
        closed = true;
        unsubscribe?.();
        if (heartbeat) clearInterval(heartbeat);
        try {
          controller.close();
        } catch {
          /* already closed */
        }
      };
      write(`: immune events · ${new Date().toISOString()}\nretry: 1000\n\n`);
      for (const e of engine.bus.recent(40)) send(e);
      unsubscribe = engine.bus.subscribe(send);
      heartbeat = setInterval(() => write(`: heartbeat ${Date.now()}\n\n`), 10_000);
      req.signal.addEventListener('abort', cleanup);
    },
    cancel() {
      unsubscribe?.();
      if (heartbeat) clearInterval(heartbeat);
    },
  });

  return new Response(stream, {
    headers: {
      'content-type': 'text/event-stream; charset=utf-8',
      'cache-control': 'no-cache, no-transform',
      connection: 'keep-alive',
      'x-accel-buffering': 'no',
    },
  });
}
