/**
 * local-run.ts — run the immune-remediator agent's `run()` WITHOUT a Guild account.
 *
 * It builds a fake Guild `Task` whose `experimental_fetch_fetch` tool is Node's fetch and whose
 * `guild.sleep` is setTimeout, then calls the exact same `run` function that Guild hosts. This is
 * how the engine behaves when GUILD_TRIGGER_URL is unset: the same loop, in-process.
 *
 *   IMMUNE_API=http://localhost:3000 npx tsx integrations/guild/immune-remediator/local-run.ts tr_0123456789ab
 *   npx tsx integrations/guild/immune-remediator/local-run.ts path/to/breach-trace.json
 *
 * Requires `tsconfig.json` paths (tsx honours them) so the @guildai shims resolve.
 */

import { readFileSync } from "node:fs"
import type { Task } from "@guildai/agents-sdk"
import type { ExperimentalFetchInput, ExperimentalFetchOutput } from "@guildai-services/guildai~experimental-fetch"
import { run } from "./agent.js"

type Tools = Parameters<typeof run>[1] extends Task<infer T> ? T : never

async function nodeFetchTool(input: ExperimentalFetchInput): Promise<ExperimentalFetchOutput> {
  const headers: Record<string, string> = { ...(input.headers ?? {}) }
  let body: string | undefined
  if (input.data !== undefined) {
    body = typeof input.data === "string" ? input.data : JSON.stringify(input.data)
    if (!Object.keys(headers).some((h) => h.toLowerCase() === "content-type")) headers["content-type"] = "application/json"
  }
  const res = await fetch(input.url, {
    method: input.method,
    headers,
    body,
    redirect: input.follow_redirects === false ? "manual" : "follow",
    signal: AbortSignal.timeout((input.timeout_seconds ?? 5) * 1000),
  })
  const text = await res.text()
  const resHeaders: Record<string, string> = {}
  res.headers.forEach((v, k) => {
    resHeaders[k] = v
  })
  const out: ExperimentalFetchOutput = {
    status_code: res.status,
    url: res.url || input.url,
    headers: resHeaders,
  }
  if ((res.headers.get("content-type") ?? "").includes("application/json")) {
    try {
      out.json = JSON.parse(text)
    } catch {
      out.text = text
    }
  } else {
    out.text = input.max_bytes && text.length > input.max_bytes ? text.slice(0, input.max_bytes) + `[Response truncated to ${input.max_bytes} bytes]` : text
  }
  return out
}

export function makeLocalTask(env: Record<string, string>, log = (...a: unknown[]) => console.error("[remediator]", ...a)): Task<Tools> {
  const sleep = async (p: { seconds: number }) => {
    await new Promise((r) => setTimeout(r, p.seconds * 1000))
  }
  const task = {
    sessionId: `local_${Date.now().toString(36)}`,
    console: { debug: log, info: log, warn: log, error: log, log },
    tools: {
      experimental_fetch_fetch: nodeFetchTool,
      ui_notify: async (e: { text?: string }) => log(e.text),
      ui_prompt: async () => ({ text: "" }),
      guild_get_workspace: async () => ({ name: "local" }),
    },
    env: new Proxy(env, {
      get(target, key: string) {
        if (!(key in target)) throw new Error(`workspace variable ${key} is not set`)
        return target[key]
      },
    }),
    llm: { generateText: async () => ({ text: "" }) },
    ui: { notify: async (e: { text?: string }) => log(e.text), prompt: async () => ({ text: "" }), ping: async () => {} },
    guild: { sleep, get_workspace: async () => ({ name: "local" }) },
    gather: async (calls: readonly unknown[]) => Promise.all(calls as Promise<unknown>[]),
    gatherSettled: async (calls: readonly unknown[]) => Promise.allSettled(calls as Promise<unknown>[]),
  }
  return task as unknown as Task<Tools>
}

async function main() {
  const arg = process.argv[2]
  if (!arg) {
    console.error("usage: tsx local-run.ts <traceId | path/to/trace.json> [immuneApi]")
    process.exit(2)
  }
  const input: Parameters<typeof run>[0] = arg.endsWith(".json")
    ? { trace: JSON.parse(readFileSync(arg, "utf8")) as Record<string, unknown> }
    : { traceId: arg }
  if (process.argv[3]) input.immune_api = process.argv[3]
  const env: Record<string, string> = {}
  if (process.env.IMMUNE_API) env.IMMUNE_API = process.env.IMMUNE_API
  const out = await run(input, makeLocalTask(env))
  console.log(JSON.stringify(out, null, 2))
  process.exit(out.ok ? 0 : 1)
}

if (process.argv[1] && /local-run\.(ts|js)$/.test(process.argv[1])) {
  main().catch((err) => {
    console.error(err)
    process.exit(1)
  })
}
