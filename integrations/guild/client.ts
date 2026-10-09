/**
 * Engine-side Guild client — how the Immune engine hands a breach to the hosted
 * `immune-remediator` agent, and how it reports Guild in AdapterStatus.
 *
 * Zero-key rule: `guildStatus().configured` is true only when BOTH GUILD_TRIGGER_URL and
 * GUILD_TRIGGER_KEY are set. When it is false the engine runs the identical remediation loop
 * in-process (see README). Nothing here throws for operational failures.
 *
 * Guild API facts (docs.guild.ai/platform/api-triggers, read 2026-10-09):
 *   start   POST https://api.guild.ai/v1/workspaces/{owner}/{workspace}/sessions
 *           Basic auth  user = api_key_id, pass = api_key_secret   (the trigger API key "<id>:<secret>")
 *           body { "session_type": "api_trigger", "agent_input": {...}, "agent_id"?: "owner~agent" }
 *           -> 201 { id, session_type: "api", session_url, root_task: { id, status: "CREATED" }, token_usage }
 *   status  GET  https://api.guild.ai/v1/sessions/{id}   -> root_task.status ∈ CREATED|DISPATCHED|STARTED|WAITING|DONE|ERROR|INTERRUPTED
 *   output  GET  https://api.guild.ai/v1/sessions/{id}/events?types=runtime_done&limit=5
 *           -> items[].type === "runtime_done", content.text carries the agent's reply (output JSON expected there — inferred)
 */

import type { AdapterStatus, Trace } from '../../packages/core/src/types.js';

export const GUILD_API = 'https://api.guild.ai/v1';

export interface GuildOptions {
  triggerUrl?: string; // default process.env.GUILD_TRIGGER_URL
  triggerKey?: string; // default process.env.GUILD_TRIGGER_KEY  ("<api_key_id>:<api_key_secret>")
  immuneApi?: string; // the Immune API as reachable FROM Guild — default process.env.IMMUNE_PUBLIC_API
  timeoutMs?: number; // overall wait for the session, default 240_000
  pollMs?: number; // default 3_000
  fetchImpl?: typeof fetch;
}

export interface GuildSession {
  id: string;
  sessionUrl?: string;
  status: string;
}

export interface GuildTriggerResult {
  ok: boolean;
  session?: GuildSession;
  /** the agent's parsed output (immune-remediator Output) when it could be read from the runtime_done event */
  output?: Record<string, unknown>;
  detail: string;
  ms: number;
}

function resolvedOpts(o: GuildOptions) {
  return {
    triggerUrl: (o.triggerUrl ?? process.env.GUILD_TRIGGER_URL ?? '').trim(),
    triggerKey: (o.triggerKey ?? process.env.GUILD_TRIGGER_KEY ?? '').trim(),
    immuneApi: (o.immuneApi ?? process.env.IMMUNE_PUBLIC_API ?? '').trim(),
    timeoutMs: o.timeoutMs ?? 240_000,
    pollMs: o.pollMs ?? 3_000,
    fetchImpl: o.fetchImpl ?? fetch,
  };
}

export function guildStatus(o: GuildOptions = {}): AdapterStatus['guild'] {
  const c = resolvedOpts(o);
  if (c.triggerUrl && c.triggerKey) {
    const ws = c.triggerUrl.match(/\/workspaces\/([^/]+)\/([^/]+)\/sessions/);
    return {
      configured: true,
      detail: `API trigger ${ws ? `${ws[1]}/${ws[2]}` : c.triggerUrl} (key ${c.triggerKey.split(':')[0]?.slice(0, 8)}…)${c.immuneApi ? `; agent calls back ${c.immuneApi}` : '; IMMUNE_PUBLIC_API not set — hosted agent cannot reach localhost'}`,
    };
  }
  return { configured: false, detail: 'GUILD_TRIGGER_URL / GUILD_TRIGGER_KEY not set — remediation loop runs in-process' };
}

/** Start a hosted remediation for a breach and wait for the agent's report. */
export async function triggerRemediation(trace: Trace, o: GuildOptions = {}): Promise<GuildTriggerResult> {
  const c = resolvedOpts(o);
  const t0 = performance.now();
  const ms = () => Math.round(performance.now() - t0);
  if (!c.triggerUrl || !c.triggerKey) return { ok: false, detail: 'Guild not configured', ms: 0 };

  const auth = 'Basic ' + Buffer.from(c.triggerKey, 'utf8').toString('base64');
  const headers = { Authorization: auth, 'Content-Type': 'application/json', Accept: 'application/json' };
  const agentInput: Record<string, unknown> = { traceId: trace.id, trace };
  if (c.immuneApi) agentInput.immune_api = c.immuneApi;

  let session: GuildSession;
  try {
    const res = await c.fetchImpl(c.triggerUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify({ session_type: 'api_trigger', agent_input: agentInput }),
      signal: AbortSignal.timeout(20_000),
    });
    const body = (await res.json().catch(() => ({}))) as { id?: string; session_url?: string; root_task?: { status?: string }; error?: string; message?: string };
    if (!res.ok || !body.id) {
      return { ok: false, detail: `POST sessions -> ${res.status} ${body.error ?? ''} ${body.message ?? ''}`.trim(), ms: ms() };
    }
    session = { id: body.id, sessionUrl: body.session_url, status: body.root_task?.status ?? 'CREATED' };
  } catch (err) {
    return { ok: false, detail: `POST sessions -> ${err instanceof Error ? err.message : String(err)}`, ms: ms() };
  }

  const base = c.triggerUrl.replace(/\/workspaces\/.*$/, '') || GUILD_API;
  const terminal = new Set(['DONE', 'ERROR', 'INTERRUPTED']);
  const deadline = Date.now() + c.timeoutMs;
  while (Date.now() < deadline && !terminal.has(session.status)) {
    await new Promise((r) => setTimeout(r, c.pollMs));
    try {
      const res = await c.fetchImpl(`${base}/sessions/${session.id}`, { headers, signal: AbortSignal.timeout(15_000) });
      const body = (await res.json().catch(() => ({}))) as { root_task?: { status?: string } };
      if (res.ok && body.root_task?.status) session.status = body.root_task.status;
    } catch {
      /* transient; keep polling */
    }
  }

  if (!terminal.has(session.status)) return { ok: false, session, detail: `session still ${session.status} after ${c.timeoutMs}ms`, ms: ms() };

  // Read the agent's final output from the runtime_done event.
  let output: Record<string, unknown> | undefined;
  try {
    const res = await c.fetchImpl(`${base}/sessions/${session.id}/events?types=runtime_done&limit=5`, { headers, signal: AbortSignal.timeout(15_000) });
    const body = (await res.json().catch(() => ({}))) as { items?: Array<{ type?: string; content?: { text?: string; data?: unknown } }> };
    for (const ev of body.items ?? []) {
      const raw = ev.content?.text ?? (typeof ev.content?.data === 'string' ? ev.content.data : undefined);
      if (typeof raw === 'string') {
        const m = raw.match(/\{[\s\S]*\}/);
        if (m) {
          try {
            output = JSON.parse(m[0]) as Record<string, unknown>;
            break;
          } catch {
            /* not JSON */
          }
        }
      } else if (ev.content && typeof ev.content === 'object' && 'ok' in ev.content) {
        output = ev.content as Record<string, unknown>;
        break;
      }
    }
  } catch {
    /* output stays undefined */
  }

  const ok = session.status === 'DONE' && (output === undefined || output.ok === true);
  return {
    ok,
    session,
    output,
    detail: `session ${session.status}${output ? ` — agent: ${String(output.detail ?? output.status ?? '')}` : ' (no runtime_done output parsed)'}`,
    ms: ms(),
  };
}
