import type { Ruling } from '@immune/core';

/**
 * The sentence an agent receives in a denial. Shared by the engine (server) and the UI so the
 * citation shown on /rulings is byte-for-byte what the gate says.
 */
export function citationText(r: Pick<Ruling, 'id' | 'title' | 'receiptId'>): string {
  return `Immune ruling ${r.id}: ${r.title} (receipt ${r.receiptId})`;
}
