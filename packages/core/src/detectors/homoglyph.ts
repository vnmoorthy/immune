/**
 * homoglyph — look-alike tool names shadowing a trusted tool: Unicode confusables, invisible
 * characters, or edit-distance 1–2 from a trusted name on a different server.
 */
import type { Finding, Severity } from '../types.js';
import { toolKey } from '../ids.js';
import { type DetectorInput, countInvisible, foldConfusables, makeFinding, stripInvisible } from './common.js';

export const DETECTOR_HOMOGLYPH = 'homoglyph';

export interface TrustedTool {
  server: string;
  name: string;
}

/** Trusted (server, tool) identities — populated by the Gate from pinned, allowed definitions. */
export class TrustedTools {
  private readonly map = new Map<string, TrustedTool>();

  add(server: string, name: string): void {
    this.map.set(toolKey(server, name), { server, name });
  }

  remove(server: string, name: string): boolean {
    return this.map.delete(toolKey(server, name));
  }

  has(server: string, name: string): boolean {
    return this.map.has(toolKey(server, name));
  }

  list(): TrustedTool[] {
    return [...this.map.values()];
  }

  clear(): void {
    this.map.clear();
  }

  get size(): number {
    return this.map.size;
  }
}

/** Visual skeleton of a tool name: confusables folded, invisibles stripped, l/1/I and 0/o unified, rn→m, vv→w. */
export function nameSkeleton(name: string): string {
  return foldConfusables(stripInvisible(name))
    .text.replace(/[|1!]/g, 'l')
    .replace(/0/g, 'o')
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w')
    .replace(/[-.\s]/g, '_');
}

/** Optimal-string-alignment (Damerau–Levenshtein with adjacent transpositions). Early-exits past `max`. */
export function editDistance(a: string, b: string, max = Infinity): number {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const n = a.length;
  const m = b.length;
  if (!n) return m;
  if (!m) return n;
  let prev2: number[] = [];
  let prev: number[] = Array.from({ length: m + 1 }, (_, j) => j);
  for (let i = 1; i <= n; i++) {
    const cur: number[] = new Array<number>(m + 1);
    cur[0] = i;
    let rowMin = cur[0];
    for (let j = 1; j <= m; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let v = Math.min(prev[j]! + 1, cur[j - 1]! + 1, prev[j - 1]! + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) v = Math.min(v, prev2[j - 2]! + 1);
      cur[j] = v;
      if (v < rowMin) rowMin = v;
    }
    if (rowMin > max) return max + 1;
    prev2 = prev;
    prev = cur;
  }
  return prev[m]!;
}

export type LookAlikeKind = 'invisible' | 'confusable' | 'edit_distance' | 'shadow';

export interface LookAlike {
  trusted: TrustedTool;
  kind: LookAlikeKind;
  distance: number;
  severity: Severity;
  detail: string;
}

/** Compare a candidate (server, name) against trusted identities. */
export function findLookAlikes(server: string, name: string, trusted: TrustedTools): LookAlike[] {
  const out: LookAlike[] = [];
  const invisible = countInvisible(name);
  const skeleton = nameSkeleton(name);
  const nonAscii = /[^\x20-\x7e]/.test(name);

  for (const t of trusted.list()) {
    if (t.server === server && t.name === name) continue; // itself
    const tSkeleton = nameSkeleton(t.name);
    if (skeleton === tSkeleton) {
      if (t.name === name) {
        if (t.server !== server) out.push({ trusted: t, kind: 'shadow', distance: 0, severity: 'medium', detail: `same name as trusted ${t.server}/${t.name} on a different server` });
        continue;
      }
      out.push({
        trusted: t,
        kind: invisible ? 'invisible' : 'confusable',
        distance: 0,
        severity: 'critical',
        detail: invisible
          ? `"${stripInvisible(name)}" contains ${invisible} invisible character(s) and renders like trusted ${t.server}/${t.name}`
          : `"${name}" is visually identical to trusted ${t.server}/${t.name} (${nonAscii ? 'Unicode confusables' : 'l/1/0/o/rn/m confusion'})`,
      });
      continue;
    }
    if (t.server === server) continue; // same server, distinct names → legit tool family (get_user / get_users)
    const len = Math.min(skeleton.length, tSkeleton.length);
    const maxDist = len >= 8 ? 2 : len >= 5 ? 1 : 0;
    if (!maxDist) continue;
    const d = editDistance(skeleton, tSkeleton, maxDist);
    if (d >= 1 && d <= maxDist) {
      out.push({ trusted: t, kind: 'edit_distance', distance: d, severity: 'high', detail: `"${name}" is ${d} edit(s) from trusted ${t.server}/${t.name}` });
    }
  }
  if (invisible && !out.length) {
    out.push({ trusted: { server, name }, kind: 'invisible', distance: 0, severity: 'critical', detail: `tool name contains ${invisible} invisible character(s)` });
  }
  const order: Record<LookAlikeKind, number> = { invisible: 0, confusable: 1, edit_distance: 2, shadow: 3 };
  return out.sort((a, b) => order[a.kind] - order[b.kind] || a.distance - b.distance);
}

/** Detector: tool_def phase; needs `input.trusted`. */
export function homoglyph(input: DetectorInput): Finding[] {
  if (input.phase !== 'tool_def' || !input.toolDef) return [];
  const def = input.toolDef;
  const trusted = input.trusted ?? new TrustedTools();
  const hits = findLookAlikes(def.server, def.name, trusted);
  if (!hits.length) return [];
  const top = hits[0]!;
  return [
    makeFinding(
      DETECTOR_HOMOGLYPH,
      top.severity,
      top.kind === 'shadow'
        ? `Tool ${def.server}/${def.name} shadows trusted ${top.trusted.server}/${top.trusted.name}`
        : `Tool ${def.server}/${stripInvisible(def.name)} is a look-alike of trusted ${top.trusted.server}/${top.trusted.name} (${top.kind.replace('_', ' ')})`,
      top.detail,
    ),
  ];
}
