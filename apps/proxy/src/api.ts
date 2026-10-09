import { z } from 'zod';
import type { Rule, Ruling, Trace } from '@immune/core';
import { errorMessage, log, warn } from './log.js';

export const DEFAULT_API = process.env.IMMUNE_API ?? 'http://localhost:3000';

const RuleWire = z
  .object({
    id: z.string(),
    name: z.string(),
    version: z.number().optional(),
    createdAt: z.number().optional(),
    origin: z.enum(['builtin', 'synthesized', 'llm']).optional(),
    derivedFrom: z.array(z.string()).optional(),
    match: z.object({ phase: z.enum(['tool_def', 'tool_call', 'tool_result']) }).passthrough(),
    action: z.enum(['allow', 'flag', 'block', 'quarantine']),
    severity: z.enum(['low', 'medium', 'high', 'critical']).optional(),
    status: z.enum(['candidate', 'promoted', 'revoked']),
  })
  .passthrough();

function toRule(wire: z.infer<typeof RuleWire>): Rule {
  return {
    version: 1,
    createdAt: Date.now(),
    origin: 'synthesized',
    derivedFrom: [],
    severity: 'high',
    ...wire,
    match: wire.match as Rule['match'],
  } as Rule;
}

export function parseRules(payload: unknown): Rule[] {
  const list: unknown = Array.isArray(payload)
    ? payload
    : payload && typeof payload === 'object' && Array.isArray((payload as { rules?: unknown }).rules)
      ? (payload as { rules: unknown[] }).rules
      : [];
  const rules: Rule[] = [];
  for (const item of list as unknown[]) {
    const parsed = RuleWire.safeParse(item);
    if (parsed.success) rules.push(toRule(parsed.data));
  }
  return rules;
}

const RulingWire = z
  .object({
    id: z.string(),
    ruleId: z.string(),
    title: z.string(),
    summary: z.string().optional(),
    evidenceTraceIds: z.array(z.string()).optional(),
    receiptId: z.string().optional(),
    publishedTo: z.enum(['local', 'senso']).optional(),
    createdAt: z.number().optional(),
  })
  .passthrough();

export function parseRulings(payload: unknown): Ruling[] {
  const list: unknown = Array.isArray(payload)
    ? payload
    : payload && typeof payload === 'object' && Array.isArray((payload as { rulings?: unknown }).rulings)
      ? (payload as { rulings: unknown[] }).rulings
      : [];
  const rulings: Ruling[] = [];
  for (const item of list as unknown[]) {
    const parsed = RulingWire.safeParse(item);
    if (!parsed.success) continue;
    const r = parsed.data;
    rulings.push({
      summary: '',
      evidenceTraceIds: [],
      receiptId: '',
      publishedTo: 'local',
      createdAt: Date.now(),
      ...r,
    } as Ruling);
  }
  return rulings;
}

/**
 * Thin client for the Immune web API. Everything here is best-effort: the proxy
 * must keep gating traffic with builtin rules when the API is down.
 */
export class ImmuneApi {
  private offline = false;
  readonly baseUrl: string;

  constructor(baseUrl: string, private readonly timeoutMs = 2000) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
  }

  /** Fire-and-forget. Never awaited on the call path. */
  ingest(trace: Trace): void {
    void fetch(`${this.baseUrl}/api/ingest`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ trace }),
      signal: AbortSignal.timeout(this.timeoutMs),
    })
      .then((res) => {
        if (res.ok) this.markOnline();
        else this.markOffline(`ingest -> HTTP ${res.status}`);
      })
      .catch((err: unknown) => this.markOffline(`ingest failed: ${errorMessage(err)}`));
  }

  /** All rules the API knows about, or null when unreachable. */
  async fetchRules(): Promise<Rule[] | null> {
    try {
      const res = await fetch(`${this.baseUrl}/api/rules`, {
        headers: { accept: 'application/json' },
        signal: AbortSignal.timeout(this.timeoutMs),
      });
      if (!res.ok) {
        this.markOffline(`rules -> HTTP ${res.status}`);
        return null;
      }
      const rules = parseRules(await res.json());
      this.markOnline();
      return rules;
    } catch (err) {
      this.markOffline(`rules failed: ${errorMessage(err)}`);
      return null;
    }
  }

  /** Published rulings (precedents cited in denials), or null when unreachable. */
  async fetchRulings(): Promise<Ruling[] | null> {
    try {
      const res = await fetch(`${this.baseUrl}/api/rulings`, {
        headers: { accept: 'application/json' },
        signal: AbortSignal.timeout(this.timeoutMs),
      });
      if (!res.ok) return null;
      return parseRulings(await res.json());
    } catch {
      return null;
    }
  }

  async verifyReceipt(receipt: unknown): Promise<{ ok: boolean; reason: string }> {
    const res = await fetch(`${this.baseUrl}/api/receipts/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ receipt }),
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status} from ${this.baseUrl}/api/receipts/verify`);
    const body = (await res.json()) as { ok?: unknown; reason?: unknown };
    return { ok: body.ok === true, reason: typeof body.reason === 'string' ? body.reason : '' };
  }

  get isOffline(): boolean {
    return this.offline;
  }

  private markOffline(detail: string): void {
    if (!this.offline) warn(`api ${this.baseUrl} unreachable (${detail}); running offline with local rules`);
    this.offline = true;
  }

  private markOnline(): void {
    if (this.offline) log(`api ${this.baseUrl} reachable again`);
    this.offline = false;
  }
}
