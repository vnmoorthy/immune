/**
 * Optional LLM adapter. Providers, in order:
 *   1. OPENAI_BASE_URL (+ OPENAI_API_KEY or AKASHML_API_KEY) — any OpenAI-compatible endpoint
 *   2. AKASHML_API_KEY — AkashML at https://api.akashml.com/v1
 *   3. OPENAI_API_KEY — api.openai.com
 *   4. `claude -p` CLI when IMMUNE_USE_CLAUDE_CLI=1 and `claude` is on PATH
 * Always optional: detectLlm() reports 'none' and complete() returns null when nothing is configured. 20s timeout.
 */
import { execFile } from 'node:child_process';
import { accessSync, constants } from 'node:fs';
import { delimiter, join } from 'node:path';
import type { AdapterStatus } from './types.js';

export type LlmStatus = AdapterStatus['llm'];
export type LlmProvider = LlmStatus['provider'];

export const AKASHML_BASE_URL = 'https://api.akashml.com/v1';
export const OPENAI_DEFAULT_BASE_URL = 'https://api.openai.com/v1';
export const DEFAULT_LLM_TIMEOUT_MS = 20_000;
export const DEFAULT_MODELS: Record<Exclude<LlmProvider, 'none'>, string | undefined> = {
  akashml: 'Meta-Llama-3-3-70B-Instruct',
  'openai-compatible': 'gpt-4o-mini',
  'claude-code': undefined, // CLI default
};

export interface LlmConfig {
  provider: LlmProvider;
  baseUrl?: string;
  apiKey?: string;
  model?: string;
  cliPath?: string;
  detail: string;
}

export interface CompleteOptions {
  /** ask for a JSON object; the returned string is the extracted JSON when possible */
  json?: boolean;
  system?: string;
  timeoutMs?: number;
  maxTokens?: number;
  temperature?: number;
  model?: string;
}

/** Find an executable on PATH (sync, no spawn). */
export function findOnPath(name: string, env: NodeJS.ProcessEnv = process.env): string | undefined {
  const path = env.PATH ?? '';
  for (const dir of path.split(delimiter)) {
    if (!dir) continue;
    const full = join(dir, name);
    try {
      accessSync(full, constants.X_OK);
      return full;
    } catch {
      /* keep looking */
    }
  }
  return undefined;
}

export function resolveLlmConfig(env: NodeJS.ProcessEnv = process.env): LlmConfig {
  const model = env.IMMUNE_LLM_MODEL || env.OPENAI_MODEL || env.AKASHML_MODEL || undefined;
  const baseUrl = env.OPENAI_BASE_URL?.trim();
  if (baseUrl) {
    const provider: LlmProvider = /akashml/i.test(baseUrl) ? 'akashml' : 'openai-compatible';
    const apiKey = env.OPENAI_API_KEY || env.AKASHML_API_KEY || '';
    return { provider, baseUrl: baseUrl.replace(/\/+$/, ''), apiKey, model: model ?? DEFAULT_MODELS[provider], detail: `${provider} via OPENAI_BASE_URL ${baseUrl}${apiKey ? '' : ' (no API key)'}` };
  }
  if (env.AKASHML_API_KEY) {
    return { provider: 'akashml', baseUrl: AKASHML_BASE_URL, apiKey: env.AKASHML_API_KEY, model: model ?? DEFAULT_MODELS.akashml, detail: `AkashML ${AKASHML_BASE_URL}` };
  }
  if (env.OPENAI_API_KEY) {
    return { provider: 'openai-compatible', baseUrl: OPENAI_DEFAULT_BASE_URL, apiKey: env.OPENAI_API_KEY, model: model ?? DEFAULT_MODELS['openai-compatible'], detail: `OpenAI ${OPENAI_DEFAULT_BASE_URL}` };
  }
  if (env.IMMUNE_USE_CLAUDE_CLI === '1' || env.IMMUNE_USE_CLAUDE_CLI === 'true') {
    const cli = findOnPath('claude', env);
    if (cli) return { provider: 'claude-code', cliPath: cli, model: env.IMMUNE_CLAUDE_MODEL || model, detail: `claude -p (${cli})` };
    return { provider: 'none', detail: 'IMMUNE_USE_CLAUDE_CLI=1 but `claude` is not on PATH' };
  }
  return { provider: 'none', detail: 'no LLM configured (set OPENAI_BASE_URL/OPENAI_API_KEY, AKASHML_API_KEY, or IMMUNE_USE_CLAUDE_CLI=1)' };
}

/** AdapterStatus['llm'] for /api/status. Does no network I/O. */
export function detectLlm(env: NodeJS.ProcessEnv = process.env): LlmStatus {
  const cfg = resolveLlmConfig(env);
  const status: LlmStatus = { provider: cfg.provider, detail: cfg.detail };
  if (cfg.model) status.model = cfg.model;
  return status;
}

/** Extract the first JSON object/array from free text. */
export function extractJson(text: string): unknown | undefined {
  if (!text) return undefined;
  const fenced = /```(?:json)?\s*([\s\S]*?)```/i.exec(text);
  const body = fenced ? fenced[1]! : text;
  const candidates = [body.trim()];
  const objStart = body.indexOf('{');
  const objEnd = body.lastIndexOf('}');
  if (objStart >= 0 && objEnd > objStart) candidates.push(body.slice(objStart, objEnd + 1));
  const arrStart = body.indexOf('[');
  const arrEnd = body.lastIndexOf(']');
  if (arrStart >= 0 && arrEnd > arrStart) candidates.push(body.slice(arrStart, arrEnd + 1));
  for (const c of candidates) {
    try {
      return JSON.parse(c);
    } catch {
      /* next */
    }
  }
  return undefined;
}

async function completeOpenAi(cfg: LlmConfig, prompt: string, opts: CompleteOptions): Promise<string | null> {
  const url = `${cfg.baseUrl}/chat/completions`;
  const messages: { role: string; content: string }[] = [];
  if (opts.system) messages.push({ role: 'system', content: opts.system });
  messages.push({ role: 'user', content: opts.json ? `${prompt}\n\nRespond with a single JSON object and nothing else.` : prompt });
  const body: Record<string, unknown> = {
    model: opts.model ?? cfg.model,
    messages,
    temperature: opts.temperature ?? 0,
    max_tokens: opts.maxTokens ?? 1024,
  };
  if (opts.json) body.response_format = { type: 'json_object' };
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (cfg.apiKey) headers.authorization = `Bearer ${cfg.apiKey}`;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_LLM_TIMEOUT_MS;

  const attempt = async (payload: Record<string, unknown>): Promise<{ status: number; text: string } | null> => {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const res = await fetch(url, { method: 'POST', headers, body: JSON.stringify(payload), signal: ctrl.signal });
      return { status: res.status, text: await res.text() };
    } catch {
      return null;
    } finally {
      clearTimeout(timer);
    }
  };

  let res = await attempt(body);
  if (res && res.status === 400 && opts.json && body.response_format) {
    const { response_format: _drop, ...rest } = body;
    res = await attempt(rest);
  }
  if (!res || res.status < 200 || res.status >= 300) return null;
  try {
    const data = JSON.parse(res.text) as { choices?: { message?: { content?: string | { text?: string }[] } }[] };
    const content = data.choices?.[0]?.message?.content;
    const text = typeof content === 'string' ? content : Array.isArray(content) ? content.map((c) => c?.text ?? '').join('') : '';
    return text ? text : null;
  } catch {
    return null;
  }
}

function completeClaudeCli(cfg: LlmConfig, prompt: string, opts: CompleteOptions): Promise<string | null> {
  return new Promise((resolve) => {
    const args = ['-p', '--output-format', 'text'];
    const model = opts.model ?? cfg.model;
    if (model) args.push('--model', model);
    const full = `${opts.system ? `${opts.system}\n\n` : ''}${prompt}${opts.json ? '\n\nRespond with a single JSON object and nothing else.' : ''}`;
    // strip nesting markers so the CLI does not refuse to start inside another Claude Code session
    const env = { ...process.env };
    delete env.CLAUDECODE;
    delete env.CLAUDE_CODE_ENTRYPOINT;
    try {
      const child = execFile(cfg.cliPath ?? 'claude', args, { timeout: opts.timeoutMs ?? DEFAULT_LLM_TIMEOUT_MS, maxBuffer: 8 * 1024 * 1024, env }, (error, stdout) => {
        if (error) return resolve(null);
        const text = String(stdout ?? '').trim();
        resolve(text ? text : null);
      });
      child.stdin?.on('error', () => undefined);
      child.stdin?.end(full);
    } catch {
      resolve(null);
    }
  });
}

/** Complete a prompt with the configured provider. Returns null when no provider, on error, or on timeout. */
export async function complete(prompt: string, opts: CompleteOptions = {}): Promise<string | null> {
  const cfg = resolveLlmConfig();
  if (cfg.provider === 'none') return null;
  let text: string | null = null;
  try {
    text = cfg.provider === 'claude-code' ? await completeClaudeCli(cfg, prompt, opts) : await completeOpenAi(cfg, prompt, opts);
  } catch {
    text = null;
  }
  if (text && opts.json) {
    const parsed = extractJson(text);
    if (parsed !== undefined) return JSON.stringify(parsed);
  }
  return text;
}
