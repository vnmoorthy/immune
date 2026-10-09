"use agent"

/**
 * immune-remediator — a Guild auto-managed-state (deterministic) TypeScript agent.
 *
 * Input:  a breach Trace (JSON) — or just its id — from the Immune proxy/engine.
 * Does:   POST {IMMUNE_API}/api/remediate {traceId}, then polls GET /api/remediations/:id until the
 *         remediation is `immune` or `failed`, reporting each loop step as Guild progress events.
 * Output: the ProofReport that justified the antibody, the receipt id (HMAC-signed proof), the
 *         ruling id, the time-to-immunity, and the step timeline.
 *
 * Why it looks the way it does (Guild SDK rules, docs.guild.ai/guide/coded-agents):
 *   - "use agent" at the top: the babel-plugin-agent-compiler turns `run` into a resumable state machine.
 *   - Only `@guildai/agents-sdk`, `zod` and `@guildai-services/*` may be imported. No `fetch`, no `node:*`.
 *   - Hosted agents have no direct internet: every HTTP call goes through the
 *     `guildai~experimental-fetch` integration (`task.tools.experimental_fetch_fetch`).
 *   - No Promise.all; every await is sequential; nothing non-serialisable crosses an await.
 *   - task.env.<KEY> THROWS when a workspace variable is unset, hence envOr().
 *   - Pure parsing lives in synchronous helpers (not compiled into the state machine).
 */

import {
  type Task,
  agent,
  guildTools,
  pick,
  progressLogNotifyEvent,
  userInterfaceTools,
} from "@guildai/agents-sdk"
import { ExperimentalFetchTools } from "@guildai-services/guildai~experimental-fetch"
import { z } from "zod"

// ---------------------------------------------------------------------------------------------
// Schemas (root must be z.object — Guild registers the agent as a typed tool)
// ---------------------------------------------------------------------------------------------

const inputSchema = z.object({
  trace: z
    .record(z.string(), z.unknown())
    .optional()
    .describe("The breach Trace object from Immune (packages/core/src/types.ts Trace). Its `id` is used as traceId."),
  traceId: z.string().optional().describe("Alternative to `trace`: the id (tr_...) of a trace the Immune engine already stored."),
  immune_api: z
    .string()
    .optional()
    .describe("Override of the Immune web API base URL. Defaults to workspace variable IMMUNE_API, then http://localhost:3000."),
  poll_interval_seconds: z.number().optional().describe("Seconds between status polls (default 2)."),
  timeout_seconds: z.number().optional().describe("Give up after this many seconds (default 180)."),
})
type Input = z.infer<typeof inputSchema>

const stepSchema = z.object({
  name: z.string(),
  status: z.string(),
  detail: z.string().optional(),
  ms: z.number().optional(),
})

const proofSchema = z.object({
  ruleId: z.string(),
  corpusSize: z.number(),
  corpusHash: z.string(),
  catchRateBefore: z.number(),
  catchRateAfter: z.number(),
  fpRateBefore: z.number(),
  fpRateAfter: z.number(),
  targetCaught: z.boolean(),
  promoted: z.boolean(),
  reason: z.string(),
  replayMs: z.number(),
  storeMs: z.number().optional(),
  semgrep: z.record(z.string(), z.unknown()).optional(),
  ts: z.number(),
})

const outputSchema = z.object({
  ok: z.boolean(),
  status: z.enum(["immune", "failed", "timeout", "error"]),
  traceId: z.string(),
  immuneApi: z.string(),
  remediationId: z.string().optional(),
  family: z.string().optional(),
  ruleId: z.string().optional(),
  receiptId: z.string().optional(),
  rulingId: z.string().optional(),
  timeToImmunityMs: z.number().optional(),
  proof: proofSchema.optional(),
  steps: z.array(stepSchema),
  detail: z.string().optional(),
})
type Output = z.infer<typeof outputSchema>

// ---------------------------------------------------------------------------------------------
// Tools: outbound HTTP via Guild's fetch integration; UI progress; guild.sleep for polling
// ---------------------------------------------------------------------------------------------

const tools = {
  ...userInterfaceTools,
  ...guildTools,
  ...pick(ExperimentalFetchTools, ["experimental_fetch_fetch"]),
}
type Tools = typeof tools

// ---------------------------------------------------------------------------------------------
// Synchronous helpers (not compiled; safe to keep here or move to another file)
// ---------------------------------------------------------------------------------------------

type Json = Record<string, unknown>

/** task.env throws on a missing key — turn that into a default. */
function envOr(task: Task<Tools>, key: string, fallback: string): string {
  try {
    const v = task.env[key]
    return typeof v === "string" && v.trim() ? v.trim() : fallback
  } catch {
    return fallback
  }
}

/** experimental_fetch_fetch returns the body under `json` for application/json, else `text`. */
function bodyOf(res: { status_code: number; json?: unknown; text?: string }): Json {
  if (res.json && typeof res.json === "object") return res.json as Json
  if (typeof res.text === "string" && res.text.trim().startsWith("{")) {
    try {
      return JSON.parse(res.text) as Json
    } catch {
      return {}
    }
  }
  return {}
}

function str(v: unknown): string | undefined {
  return typeof v === "string" && v ? v : undefined
}

function num(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? v : undefined
}

function stepsOf(remediation: Json): z.infer<typeof stepSchema>[] {
  const raw = Array.isArray(remediation.steps) ? (remediation.steps as Json[]) : []
  return raw.map((s) => {
    const started = num(s.startedAt)
    const finished = num(s.finishedAt)
    return {
      name: str(s.name) ?? "?",
      status: str(s.status) ?? "pending",
      detail: str(s.detail),
      ms: started !== undefined && finished !== undefined ? Math.max(0, finished - started) : undefined,
    }
  })
}

/** The proof lives on the promoted rule (GET /api/rules) and is mirrored on the replay_proven step. */
function proofOf(remediation: Json, rules: unknown): z.infer<typeof proofSchema> | undefined {
  const ruleId = str(remediation.ruleId)
  const list = Array.isArray(rules) ? (rules as Json[]) : Array.isArray((rules as Json | undefined)?.rules) ? ((rules as Json).rules as Json[]) : []
  const rule = ruleId ? list.find((r) => r.id === ruleId) : undefined
  const candidates: unknown[] = [rule?.proof]
  for (const s of Array.isArray(remediation.steps) ? (remediation.steps as Json[]) : []) {
    if (s.name === "replay_proven") candidates.push(s.data, (s.data as Json | undefined)?.proof)
  }
  for (const c of candidates) {
    if (c && typeof c === "object" && "catchRateAfter" in (c as Json) && "corpusHash" in (c as Json)) {
      const p = c as Json
      return {
        ruleId: str(p.ruleId) ?? ruleId ?? "?",
        corpusSize: num(p.corpusSize) ?? 0,
        corpusHash: str(p.corpusHash) ?? "",
        catchRateBefore: num(p.catchRateBefore) ?? 0,
        catchRateAfter: num(p.catchRateAfter) ?? 0,
        fpRateBefore: num(p.fpRateBefore) ?? 0,
        fpRateAfter: num(p.fpRateAfter) ?? 0,
        targetCaught: p.targetCaught === true,
        promoted: p.promoted === true,
        reason: str(p.reason) ?? "",
        replayMs: num(p.replayMs) ?? 0,
        storeMs: num(p.storeMs),
        semgrep: p.semgrep && typeof p.semgrep === "object" ? (p.semgrep as Json) : undefined,
        ts: num(p.ts) ?? 0,
      }
    }
  }
  return undefined
}

function describe(remediation: Json): string {
  const done = stepsOf(remediation)
    .filter((s) => s.status === "done")
    .map((s) => s.name)
  return done.length ? done.join(" → ") : "no steps completed yet"
}

// ---------------------------------------------------------------------------------------------
// run — the orchestrator (compiled into a state machine)
// ---------------------------------------------------------------------------------------------

async function run(input: Input, task: Task<Tools>): Promise<Output> {
  const immuneApi = (input.immune_api ?? envOr(task, "IMMUNE_API", "http://localhost:3000")).replace(/\/+$/, "")
  const pollEvery = Math.min(Math.max(input.poll_interval_seconds ?? 2, 1), 30)
  const timeoutS = Math.min(Math.max(input.timeout_seconds ?? 180, 5), 1800)
  const traceId = input.traceId ?? str(input.trace?.id)

  const fail = (status: "failed" | "timeout" | "error", detail: string, extra: Partial<Output> = {}): Output => ({
    ok: false,
    status,
    traceId: traceId ?? "?",
    immuneApi,
    steps: [],
    detail,
    ...extra,
  })

  if (!traceId) return fail("error", "input must carry `trace.id` or `traceId`")

  task.console.info({ traceId, immuneApi }, "immune-remediator: starting")
  await task.ui?.notify(progressLogNotifyEvent(`Posting breach ${traceId} to Immune (${immuneApi})...`))

  // 1. Kick off the remediation loop in the Immune engine.
  const started = await task.tools.experimental_fetch_fetch({
    url: `${immuneApi}/api/remediate`,
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    data: input.trace ? { traceId, trace: input.trace } : { traceId },
    timeout_seconds: 30,
  })
  if (started.status_code < 200 || started.status_code >= 300) {
    return fail("error", `POST /api/remediate -> ${started.status_code} ${(started.text ?? "").slice(0, 200)}`)
  }
  const kicked = bodyOf(started)
  const remediationId =
    str(kicked.remediationId) ?? str(kicked.id) ?? str((kicked.remediation as Json | undefined)?.id)
  if (!remediationId) return fail("error", `POST /api/remediate returned no remediation id: ${JSON.stringify(kicked).slice(0, 200)}`)

  // 2. Poll until terminal. Each iteration is one metered step + one suspension — fine for ≤ 900 polls.
  const maxPolls = Math.ceil(timeoutS / pollEvery)
  let remediation: Json = {}
  let lastProgress = ""
  let terminal = false
  for (let i = 0; i < maxPolls; i++) {
    const res = await task.tools.experimental_fetch_fetch({
      url: `${immuneApi}/api/remediations/${encodeURIComponent(remediationId)}`,
      method: "GET",
      headers: { accept: "application/json" },
      timeout_seconds: 15,
    })
    if (res.status_code >= 200 && res.status_code < 300) {
      remediation = bodyOf(res)
      const status = str(remediation.status)
      const progress = describe(remediation)
      if (progress !== lastProgress) {
        lastProgress = progress
        await task.ui?.notify(progressLogNotifyEvent(`Remediation ${remediationId}: ${progress}`))
      }
      if (status === "immune" || status === "failed") {
        terminal = true
        break
      }
    } else {
      task.console.warn({ status: res.status_code }, "poll failed; retrying")
    }
    await task.guild!.sleep({ seconds: pollEvery })
  }

  if (!terminal) {
    return fail("timeout", `remediation ${remediationId} still ${str(remediation.status) ?? "running"} after ${timeoutS}s`, {
      remediationId,
      steps: stepsOf(remediation),
    })
  }

  // 3. Collect the proof (promoted rule) for the receipt-bearing report.
  const rulesRes = await task.tools.experimental_fetch_fetch({
    url: `${immuneApi}/api/rules`,
    method: "GET",
    headers: { accept: "application/json" },
    timeout_seconds: 15,
  })
  const rules = rulesRes.status_code >= 200 && rulesRes.status_code < 300 ? (rulesRes.json ?? bodyOf(rulesRes)) : undefined
  const proof = proofOf(remediation, rules)

  const status = str(remediation.status) === "immune" ? "immune" : "failed"
  const out: Output = {
    ok: status === "immune",
    status,
    traceId,
    immuneApi,
    remediationId,
    family: str(remediation.family),
    ruleId: str(remediation.ruleId),
    receiptId: str(remediation.receiptId),
    rulingId: str(remediation.rulingId),
    timeToImmunityMs: num(remediation.timeToImmunityMs),
    proof,
    steps: stepsOf(remediation),
    detail:
      status === "immune"
        ? `immune in ${num(remediation.timeToImmunityMs) ?? "?"}ms — receipt ${str(remediation.receiptId) ?? "?"}, ruling ${str(remediation.rulingId) ?? "?"}`
        : `remediation failed: ${
            stepsOf(remediation)
              .filter((s) => s.status === "failed")
              .map((s) => `${s.name}: ${s.detail ?? "no detail"}`)
              .join("; ") || "no failed step reported"
          }`,
  }

  await task.ui?.notify(progressLogNotifyEvent(out.ok ? `Immune. ${out.detail}` : `Not immune. ${out.detail}`))
  task.console.info({ remediationId, status, receiptId: out.receiptId }, "immune-remediator: done")
  return out
}

export { inputSchema, outputSchema, run, envOr, bodyOf, proofOf, stepsOf }

export default agent({
  inputSchema,
  outputSchema,
  tools,
  run,
})
