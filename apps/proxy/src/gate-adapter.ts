import { Gate, builtinRules } from '@immune/core';
import type { GateVerdict, Rule, Ruling } from '@immune/core';

export type Verdict = GateVerdict;

export interface GateHandle {
  gate: Gate;
  builtin: Rule[];
  /** rulings by id, used to cite the published precedent in denials */
  rulings: Map<string, Ruling>;
}

export function createGate(allowlist: string[]): GateHandle {
  const builtin = builtinRules(allowlist);
  const rulings = new Map<string, Ruling>();
  const gate = new Gate({
    rules: builtin,
    allowlist,
    citationFor: (rule) => {
      if (!rule.rulingId) return undefined;
      const ruling = rulings.get(rule.rulingId);
      return ruling ? `${ruling.id}: ${ruling.title} — ${ruling.summary}` : `${rule.rulingId}: ${rule.name}`;
    },
  });
  return { gate, builtin, rulings };
}

/** builtin + promoted from the API; API revocations win over builtin copies. */
export function mergeRules(builtin: Rule[], remote: Rule[]): Rule[] {
  const byId = new Map<string, Rule>();
  for (const rule of builtin) byId.set(rule.id, rule);
  for (const rule of remote) {
    if (rule.status === 'promoted') byId.set(rule.id, rule);
    else if (rule.status === 'revoked') byId.delete(rule.id);
  }
  return [...byId.values()];
}

export function ruleSetKey(rules: Rule[]): string {
  return rules
    .map((r) => `${r.id}@${r.version}:${r.status}:${r.rulingId ?? ''}`)
    .sort()
    .join('|');
}
