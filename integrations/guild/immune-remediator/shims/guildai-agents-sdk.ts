/**
 * LOCAL SHIM for `@guildai/agents-sdk` — used only for `tsc` type-checking and `local-run.ts`
 * outside Guild's runtime (this repo must not run `pnpm add`, and the real package lives on
 * Guild's registry configured by `guild auth login`). Inside Guild the real SDK is used; this
 * file is never bundled there because `guild agent save` resolves the real package.
 *
 * Shapes follow docs.guild.ai/sdk/task-object and /packages/agents-sdk (SDK 0.6.0).
 */

export interface ToolDef<I = unknown, O = unknown> {
  readonly __input?: I
  readonly __output?: O
  name: string
  description?: string
}

export type ToolProxy<T> = {
  [K in keyof T]: T[K] extends ToolDef<infer I, infer O> ? (args: I) => Promise<O> : never
}

export interface NotifyEvent {
  type: "progress" | "message" | "error"
  text?: string
}

export interface UserInterfaceService {
  notify(event: NotifyEvent): Promise<void>
  prompt(p: { type: "text"; text: string }): Promise<{ text: string }>
  ping(p: { message: string }): Promise<void>
}

export interface GuildService {
  /** Flow control: suspend the agent for N seconds (param name inferred — docs only say "N seconds"). */
  sleep(params: { seconds: number }): Promise<void>
  get_workspace(params: { workspace_id: string }): Promise<{ name: string }>
  /** the real service exposes 46 endpoints (docs.guild.ai/sdk/task-object); only the two above are typed here */
}

export interface ConsoleService {
  debug(...args: unknown[]): void
  info(...args: unknown[]): void
  warn(...args: unknown[]): void
  error(...args: unknown[]): void
  log(...args: unknown[]): void
}

export interface LLMService {
  generateText(params: { prompt?: string; system?: string; messages?: unknown[] }): Promise<{ text: string }>
}

export interface Task<Tools> {
  sessionId: string
  console: ConsoleService
  tools: ToolProxy<Tools>
  env: Record<string, string>
  llm: LLMService
  ui?: UserInterfaceService
  guild?: GuildService
  gather<T extends readonly unknown[]>(calls: readonly [...T]): Promise<{ [K in keyof T]: Awaited<T[K]> }>
  gatherSettled<T extends readonly unknown[]>(calls: readonly [...T]): Promise<{ [K in keyof T]: PromiseSettledResult<Awaited<T[K]>> }>
}

export interface AgentDefinition<I, O, Tools> {
  description?: string
  inputSchema: { _output: I }
  outputSchema: { _output: O }
  tools: Tools
  run: (input: I, task: Task<Tools>) => Promise<O>
}

export function agent<I, O, Tools>(def: AgentDefinition<I, O, Tools>): AgentDefinition<I, O, Tools> {
  return def
}

export function pick<T extends object, K extends keyof T>(set: T, names: readonly K[]): Pick<T, K> {
  const out = {} as Pick<T, K>
  for (const n of names) out[n] = set[n]
  return out
}

export function omit<T extends object, K extends keyof T>(set: T, names: readonly K[]): Omit<T, K> {
  const out = { ...set } as T
  for (const n of names) delete out[n]
  return out as Omit<T, K>
}

export function progressLogNotifyEvent(text: string): NotifyEvent {
  return { type: "progress", text }
}

export function textPromptNotifyEvent(p: { type: "text"; text: string }): NotifyEvent {
  return { type: "message", text: p.text }
}

export function errorNotifyEvent(error: unknown): NotifyEvent {
  return { type: "error", text: error instanceof Error ? error.message : String(error) }
}

/** Marker tool sets. The real SDK exports concrete tool definitions; the keys are what matters for typing. */
export const userInterfaceTools: { ui_notify: ToolDef<NotifyEvent, void>; ui_prompt: ToolDef<{ type: "text"; text: string }, { text: string }> } = {
  ui_notify: { name: "ui_notify" },
  ui_prompt: { name: "ui_prompt" },
}

export const guildTools: { guild_get_workspace: ToolDef<{ workspace_id: string }, { name: string }> } = {
  guild_get_workspace: { name: "guild_get_workspace" },
}

export const consoleTools: { console_log: ToolDef<{ level: string; message: string }, void> } = {
  console_log: { name: "console_log" },
}

export const noTools: Record<string, never> = {}
