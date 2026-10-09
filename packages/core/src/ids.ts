import { createHash, randomBytes } from 'node:crypto';
import type { ToolDef } from './types.js';

/** Id prefixes used across the system (see CONTRACTS.md → Conventions). */
export type IdPrefix = 'tr' | 'rl' | 'rc' | 'ru' | 'rm' | 'ev' | (string & {});

/** `${prefix}_${12 hex chars}` from crypto.randomBytes. */
export function newId(prefix: IdPrefix): string {
  return `${prefix}_${randomBytes(6).toString('hex')}`;
}

/** Deterministic id: `${prefix}_${first 12 hex of sha256(seed)}`. Used where re-running must yield the same id. */
export function deterministicId(prefix: IdPrefix, seed: string): string {
  return `${prefix}_${sha256(seed).slice(0, 12)}`;
}

/** Hex sha256 of a UTF-8 string. */
export function sha256(str: string): string {
  return createHash('sha256').update(str, 'utf8').digest('hex');
}

/**
 * Canonical JSON: object keys sorted recursively, `undefined` members dropped, arrays kept in order,
 * Dates as ISO strings. Two structurally-equal values always serialize to the same string.
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function canonicalize(value: unknown): unknown {
  if (value === null || value === undefined) return value ?? null;
  if (value instanceof Date) return value.toISOString();
  if (Array.isArray(value)) return value.map((v) => (v === undefined ? null : canonicalize(v)));
  if (typeof value === 'object') {
    const src = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(src).sort()) {
      const v = src[key];
      if (v === undefined) continue;
      out[key] = canonicalize(v);
    }
    return out;
  }
  if (typeof value === 'bigint') return value.toString();
  return value;
}

/** sha256 of (name + description + inputSchema) — the rug-pull pin for a tool definition. */
export function toolDefHash(def: Pick<ToolDef, 'name' | 'description' | 'inputSchema'>): string {
  return sha256(`${def.name}\n${def.description}\n${canonicalJson(def.inputSchema ?? {})}`);
}

/** Stable key for a (server, tool) pair. */
export function toolKey(server: string, tool: string): string {
  return `${server}::${tool}`;
}
