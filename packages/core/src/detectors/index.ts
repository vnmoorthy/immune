import type { Finding, Phase } from '../types.js';
import { type Detector, type DetectorInput, makeFinding } from './common.js';
import { poisonedDescription } from './poisonedDescription.js';
import { resultInjection } from './resultInjection.js';
import { secretExfil } from './secretExfil.js';
import { rugPull } from './rugPull.js';
import { homoglyph } from './homoglyph.js';
import { destination } from './destination.js';
import { taintGate } from './taintGate.js';

export * from './common.js';
export * from './poisonedDescription.js';
export * from './resultInjection.js';
export * from './secretExfil.js';
export * from './rugPull.js';
export * from './homoglyph.js';
export * from './destination.js';
export * from './taintGate.js';

/** Detectors per phase, in execution order. */
export const DETECTORS: Record<Phase, Detector[]> = {
  tool_def: [poisonedDescription, rugPull, homoglyph],
  tool_result: [resultInjection],
  tool_call: [secretExfil, destination, taintGate],
};

/** All detector ids that have a builtin rule mapping. */
export const DETECTOR_IDS = [
  'poisoned_description',
  'result_injection',
  'secret_exfil',
  'rug_pull',
  'homoglyph',
  'destination',
  'taint_gate',
] as const;
export type DetectorId = (typeof DETECTOR_IDS)[number];

/** Run every detector for the input's phase. Detectors never throw past this boundary. */
export function runDetectors(input: DetectorInput): Finding[] {
  const out: Finding[] = [];
  for (const detector of DETECTORS[input.phase] ?? []) {
    try {
      out.push(...detector(input));
    } catch (err) {
      out.push(makeFinding('detector_error', 'low', `Detector ${detector.name || 'anonymous'} failed: ${(err as Error)?.message ?? String(err)}`, ''));
    }
  }
  return out;
}
