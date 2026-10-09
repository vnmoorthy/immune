/**
 * taint_gate — once a session has read a flagged result, any call with a sensitive capability
 * (network / exec / write / secret) is blocked until the session is cleared.
 */
import type { Finding } from '../types.js';
import { type DetectorInput, SENSITIVE_CAPABILITIES, makeFinding } from './common.js';

export const DETECTOR_TAINT_GATE = 'taint_gate';

export function taintGate(input: DetectorInput): Finding[] {
  if (input.phase !== 'tool_call' || !input.call || !input.tainted) return [];
  const caps = (input.call.capabilities ?? []).filter((c) => SENSITIVE_CAPABILITIES.includes(c));
  if (!caps.length) return [];
  return [
    makeFinding(
      DETECTOR_TAINT_GATE,
      caps.includes('network') || caps.includes('exec') || caps.includes('secret') ? 'high' : 'medium',
      `Session is tainted by an earlier flagged result; ${caps.join('/')} call ${input.call.server}/${input.call.tool} is held`,
      input.taintReason ?? 'earlier tool result in this session was flagged',
    ),
  ];
}
