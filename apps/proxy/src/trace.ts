import type { AttackFamily, Capability, GateVerdict, Phase, ToolDef, Trace } from '@immune/core';
import { newId } from '@immune/core';

export type Verdict = GateVerdict;

export interface TaintSource {
  tool: string;
  capabilities: Capability[];
}

export interface TraceContext {
  sessionId: string;
  variant: string;
  taintSource?: TaintSource;
}

const RESULT_MAX_CHARS = 16_000;

/** Detector -> family, in priority order (most specific first). */
const FAMILY_BY_DETECTOR: Array<[string, AttackFamily]> = [
  ['secret_exfil', 'secret_exfil'],
  ['rug_pull', 'rug_pull'],
  ['homoglyph', 'homoglyph_spoof'],
  ['poisoned_description', 'poisoned_description'],
  ['result_injection', 'result_injection'],
];

/**
 * The proxy has no oracle, so family is inferred from the detectors that fired.
 * Rule-only findings fall back to the phase and taint source.
 */
export function inferFamily(phase: Phase, verdict: Verdict, ctx: TraceContext, capabilities: Capability[] = []): AttackFamily {
  const detectors = new Set(verdict.findings.map((f) => f.detector));
  for (const [detector, family] of FAMILY_BY_DETECTOR) if (detectors.has(detector)) return family;
  if (detectors.has('taint_gate') || detectors.has('destination') || verdict.tainted) {
    return ctx.taintSource?.capabilities.includes('network') ? 'indirect_fetch' : 'result_injection';
  }
  if (phase === 'tool_def') return 'poisoned_description';
  if (phase === 'tool_result') return 'result_injection';
  return capabilities.includes('network') ? 'secret_exfil' : 'result_injection';
}

export function isAttackVerdict(verdict: Verdict): boolean {
  if (verdict.decision === 'block' || verdict.decision === 'quarantine') return true;
  return verdict.findings.some((f) => f.severity === 'high' || f.severity === 'critical');
}

function base(ctx: TraceContext, phase: Phase, verdict: Verdict, capabilities: Capability[]): Trace {
  const attack = isAttackVerdict(verdict);
  const label = attack ? 'attack' : 'benign';
  return {
    id: newId('tr'),
    sessionId: ctx.sessionId,
    ts: Date.now(),
    family: attack ? inferFamily(phase, verdict, ctx, capabilities) : 'benign',
    variant: ctx.variant,
    label,
    tainted: verdict.tainted,
    findings: verdict.findings,
    decision: verdict.decision,
    breached: label === 'attack' && verdict.decision === 'allow',
    blockedBy: verdict.blockedBy,
    citation: verdict.citation,
    latencyMs: verdict.latencyMs,
  };
}

export function traceForToolDef(ctx: TraceContext, def: ToolDef, verdict: Verdict): Trace {
  return { ...base(ctx, 'tool_def', verdict, def.capabilities), toolDef: def };
}

export function traceForCall(
  ctx: TraceContext,
  call: { server: string; tool: string; args: Record<string, unknown>; capabilities: Capability[] },
  verdict: Verdict,
): Trace {
  return { ...base(ctx, 'tool_call', verdict, call.capabilities), attemptedCall: call };
}

export function traceForResult(
  ctx: TraceContext,
  result: { server: string; tool: string; content: string },
  capabilities: Capability[],
  verdict: Verdict,
): Trace {
  const content = result.content.length > RESULT_MAX_CHARS ? result.content.slice(0, RESULT_MAX_CHARS) : result.content;
  return { ...base(ctx, 'tool_result', verdict, capabilities), result: { ...result, content } };
}

export function formatDecision(phase: Phase, server: string, tool: string, verdict: Verdict): string {
  const findings = verdict.findings
    .map((f) => `${f.detector}${f.ruleId && !f.detector.includes(f.ruleId) ? `(${f.ruleId})` : ''}`)
    .join(',');
  const parts = [
    verdict.decision.toUpperCase().padEnd(10),
    phase.padEnd(11),
    `${server}/${tool}`,
    `${verdict.latencyMs.toFixed(2)}ms`,
  ];
  if (verdict.tainted) parts.push('tainted');
  if (verdict.blockedBy) parts.push(`rule=${verdict.blockedBy}`);
  if (verdict.citation) parts.push(`ruling=${verdict.citation}`);
  if (findings) parts.push(`findings=${findings}`);
  return parts.join('  ');
}
