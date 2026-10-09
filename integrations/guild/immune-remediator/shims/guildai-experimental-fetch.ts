/**
 * LOCAL SHIM for `@guildai-services/guildai~experimental-fetch` (type-check + local-run only).
 *
 * Parameters are from docs.guild.ai/guide/sdk-introduction#fetching-an-arbitrary-url:
 *   url, method (GET|POST|PUT|DELETE|PATCH), optional data, headers, follow_redirects (true),
 *   verify_certificate (true), timeout_seconds (5), max_bytes.
 * Response: status_code, the final url, headers, and a body parsed under `json` when the content
 * type is application/json, otherwise under `text`. The `json`/`text` field names are inferred from
 * that prose — verify with `guild agent capabilities --mode json` after `guild auth login`.
 */

import type { ToolDef } from "./guildai-agents-sdk.js"

export interface ExperimentalFetchInput {
  url: string
  method: "GET" | "POST" | "PUT" | "DELETE" | "PATCH"
  data?: unknown
  headers?: Record<string, string>
  follow_redirects?: boolean
  verify_certificate?: boolean
  timeout_seconds?: number
  max_bytes?: number
}

export interface ExperimentalFetchOutput {
  status_code: number
  url: string
  headers: Record<string, string>
  json?: unknown
  text?: string
}

export const ExperimentalFetchTools: {
  experimental_fetch_fetch: ToolDef<ExperimentalFetchInput, ExperimentalFetchOutput>
  experimental_fetch_fetch_async: ToolDef<ExperimentalFetchInput, ExperimentalFetchOutput>
} = {
  experimental_fetch_fetch: { name: "experimental_fetch_fetch", description: "HTTP request through Guild's fetch integration" },
  experimental_fetch_fetch_async: { name: "experimental_fetch_fetch_async" },
}
