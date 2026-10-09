/**
 * rug_pull — a tool definition that silently changes after it was trusted (hash pin mismatch).
 */
import type { Finding, ToolDef } from '../types.js';
import { canonicalJson, sha256, toolDefHash, toolKey } from '../ids.js';
import { type DetectorInput, clean, makeFinding } from './common.js';

export const DETECTOR_RUG_PULL = 'rug_pull';

export interface PinRecord {
  server: string;
  tool: string;
  hash: string;
  description: string;
  schemaHash: string;
  pinnedAt: number;
  /** how many times the identical definition has been observed since pinning */
  seen: number;
}

export type ChangedPart = 'description' | 'schema' | 'name';

export interface PinCheck {
  hash: string;
  pinned: boolean;
  changed: boolean;
  previous?: PinRecord;
  what: ChangedPart[];
}

/** Hash-pin registry for tool definitions. The Gate pins on first trusted sight; it never auto re-pins. */
export class HashPinRegistry {
  private readonly pins = new Map<string, PinRecord>();

  pin(def: ToolDef, now: number = Date.now()): PinRecord {
    const rec: PinRecord = {
      server: def.server,
      tool: def.name,
      hash: toolDefHash(def),
      description: def.description ?? '',
      schemaHash: sha256(canonicalJson(def.inputSchema ?? {})),
      pinnedAt: now,
      seen: 1,
    };
    this.pins.set(toolKey(def.server, def.name), rec);
    return rec;
  }

  get(server: string, tool: string): PinRecord | undefined {
    return this.pins.get(toolKey(server, tool));
  }

  has(server: string, tool: string): boolean {
    return this.pins.has(toolKey(server, tool));
  }

  unpin(server: string, tool: string): boolean {
    return this.pins.delete(toolKey(server, tool));
  }

  clear(): void {
    this.pins.clear();
  }

  get size(): number {
    return this.pins.size;
  }

  entries(): PinRecord[] {
    return [...this.pins.values()];
  }

  /** key → hash, for persistence / display */
  snapshot(): Record<string, string> {
    const out: Record<string, string> = {};
    for (const [k, v] of this.pins) out[k] = v.hash;
    return out;
  }

  /** Compare a definition against its pin without mutating. */
  check(def: ToolDef): PinCheck {
    const hash = toolDefHash(def);
    const previous = this.get(def.server, def.name);
    if (!previous) return { hash, pinned: false, changed: false, what: [] };
    if (previous.hash === hash) {
      previous.seen++;
      return { hash, pinned: true, changed: false, previous, what: [] };
    }
    const what: ChangedPart[] = [];
    if ((def.description ?? '') !== previous.description) what.push('description');
    if (sha256(canonicalJson(def.inputSchema ?? {})) !== previous.schemaHash) what.push('schema');
    if (!what.length) what.push('name');
    return { hash, pinned: true, changed: true, previous, what };
  }
}

/** Human-readable excerpt of what changed between the pinned description and the new one. */
export function describeChange(previous: PinRecord, def: ToolDef): string {
  const a = previous.description;
  const b = def.description ?? '';
  if (a === b) return `schema changed (${previous.schemaHash.slice(0, 8)} → ${sha256(canonicalJson(def.inputSchema ?? {})).slice(0, 8)})`;
  let i = 0;
  while (i < a.length && i < b.length && a[i] === b[i]) i++;
  const added = b.slice(i);
  const removed = a.slice(i);
  const parts: string[] = [];
  if (added.trim()) parts.push(`+ "${clean(added, 120)}"`);
  if (removed.trim()) parts.push(`- "${clean(removed, 80)}"`);
  return parts.join(' ') || `description changed at offset ${i}`;
}

/** Detector: tool_def phase; needs `input.pins`. */
export function rugPull(input: DetectorInput): Finding[] {
  if (input.phase !== 'tool_def' || !input.toolDef || !input.pins) return [];
  const def = input.toolDef;
  const check = input.pins.check(def);
  if (!check.changed || !check.previous) return [];
  const prev = check.previous;
  return [
    makeFinding(
      DETECTOR_RUG_PULL,
      'critical',
      `Tool ${def.server}/${def.name} changed after being pinned (${check.what.join(' + ')}; ${prev.hash.slice(0, 10)}… → ${check.hash.slice(0, 10)}…)`,
      describeChange(prev, def),
    ),
  ];
}
