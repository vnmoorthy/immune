import { builtinRules } from '@immune/core';
import type { Rule } from '@immune/core';
import { ImmuneApi } from './api.js';

export interface RulesOptions {
  api: string;
  json?: boolean;
  all?: boolean;
}

export function summarizeMatch(rule: Rule): string {
  const m = rule.match;
  const bits: string[] = [m.phase];
  if (m.server) bits.push(`server=${m.server}`);
  if (m.tool) bits.push(`tool=${m.tool}`);
  if (m.patterns?.length) bits.push(`${m.patterns.length} pattern${m.patterns.length === 1 ? '' : 's'}`);
  if (m.capabilities?.length) bits.push(`caps=${m.capabilities.join('|')}`);
  if (m.afterTainted) bits.push('after-taint');
  if (m.destinationNotIn) bits.push(`dest∉[${m.destinationNotIn.join(',')}]`);
  if (m.carriesSecret) bits.push('carries-secret');
  return bits.join(' ');
}

export async function runRules(opts: RulesOptions): Promise<void> {
  const api = new ImmuneApi(opts.api);
  const remote = await api.fetchRules();
  const source = remote ? `${api.baseUrl}/api/rules` : `builtin (API ${api.baseUrl} unreachable)`;
  const all = remote ?? builtinRules();
  const rules = opts.all ? all : all.filter((r) => r.status === 'promoted');

  if (opts.json) {
    console.log(JSON.stringify({ source, rules }, null, 2));
    return;
  }
  console.log(`# ${rules.length} rule${rules.length === 1 ? '' : 's'} from ${source}${opts.all ? '' : ' (promoted only; --all for candidates/revoked)'}`);
  const rows = rules.map((r) => [r.id, r.status, r.action, r.origin, r.severity, r.name, summarizeMatch(r)]);
  const header = ['ID', 'STATUS', 'ACTION', 'ORIGIN', 'SEVERITY', 'NAME', 'MATCH'];
  const widths = header.map((h, i) => Math.max(h.length, ...rows.map((row) => row[i].length)));
  const fmt = (row: string[]): string => row.map((cell, i) => (i === row.length - 1 ? cell : cell.padEnd(widths[i]))).join('  ');
  console.log(fmt(header));
  for (const row of rows) console.log(fmt(row));
}
