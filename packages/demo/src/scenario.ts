/**
 * scenario.ts — drive the GullibleAgent against the acme server THROUGH the
 * core Gate, recording one Trace per step.
 *
 * The Gate is injected (the core package owns its construction). We type it
 * structurally as `GateLike` / `GateVerdict` exactly as CONTRACTS.md specifies,
 * so this module compiles independently of when core's gate.ts lands and the
 * real `Gate` instance satisfies it by shape at runtime.
 *
 * Flow for an attack:
 *   1. list tools -> gate.inspectToolDef on each (priming trusted set + pins);
 *      the malicious / changed / look-alike def is recorded as a trace.
 *   2. the agent runs the task's benign call -> gate.inspectCall, execute,
 *      gate.inspectResult (the poisoned doc / page lands here and taints).
 *   3. the agent, hijacked, attempts the exfil call(s) -> gate.inspectCall.
 * `breached` is set on the exfil/unauthorized step when the gate ALLOWED it.
 *
 * Deterministic given `seed`.
 */

import type {
  AttackFamily,
  Capability,
  Decision,
  Finding,
  ToolCall,
  ToolDef,
  ToolResult,
  Trace,
} from '@immune/core';
import {
  type AttackVariant,
  type AttackFamilyNonBenign,
  type BenignSession,
  HAND_WRITTEN,
  benignTraffic,
  mutate,
  variantById,
} from './attacks.js';
import {
  GullibleAgent,
  fillCredentials,
  react,
  type InducedCall,
} from './agent.js';
import * as acme from './servers/acme.js';
import {
  DEFAULT_ALLOWLIST,
  capabilitiesOf,
  seededId,
} from './util.js';

/* --------------------------------------------------------------------------
 * The Gate contract (structural). Matches CONTRACTS.md exactly; the real core
 * Gate instance satisfies this by shape.
 * ------------------------------------------------------------------------ */

export interface GateVerdict {
  decision: Decision;
  findings: Finding[];
  blockedBy?: string;
  citation?: string;
  latencyMs: number;
  tainted: boolean;
}

export interface GateLike {
  inspectToolDef(def: ToolDef, sessionId: string): GateVerdict;
  inspectResult(result: ToolResult, sessionId: string): GateVerdict;
  inspectCall(call: ToolCall, def: ToolDef | undefined, sessionId: string): GateVerdict;
  /** optional: register known secret values (core Gate exposes this). */
  registerSecret?(value: string): void;
}

const DEFAULT_VERDICT: GateVerdict = {
  decision: 'allow',
  findings: [],
  latencyMs: 0,
  tainted: false,
};

function coalesce(v: GateVerdict | undefined | void): GateVerdict {
  return v ? v : { ...DEFAULT_VERDICT };
}

/* --------------------------------------------------------------------------
 * options
 * ------------------------------------------------------------------------ */

export interface RunScenarioOptions {
  family: AttackFamily;
  /** variant key ('v3') or full id ('secret_exfil/v3'); ignored when mutate=true. */
  variant?: string;
  /** when true, synthesize a novel mutated variant from `seed`. */
  mutate?: boolean;
  /** deterministic seed. */
  seed?: number;
  gate: GateLike;
  sessionId?: string;
  /** destination allowlist (informational; the gate owns its own). */
  allowlist?: readonly string[];
  /** optional LLM hook for the agent. */
  complete?: (prompt: string) => string | null | Promise<string | null>;
}

/* --------------------------------------------------------------------------
 * trace recorder
 * ------------------------------------------------------------------------ */

interface Recorder {
  seed: number;
  sessionId: string;
  family: AttackFamily;
  variant: string;
  label: 'attack' | 'benign';
  traces: Trace[];
  step: number;
  baseTs: number;
}

function record(
  rec: Recorder,
  phase: 'tool_def' | 'tool_call' | 'tool_result',
  verdict: GateVerdict,
  parts: {
    toolDef?: ToolDef;
    result?: { server: string; tool: string; content: string };
    attemptedCall?: { server: string; tool: string; args: Record<string, unknown>; capabilities: Capability[] };
    breached?: boolean;
  },
): Trace {
  const id = seededId('tr', rec.seed, rec.step + 1);
  const trace: Trace = {
    id,
    sessionId: rec.sessionId,
    ts: rec.baseTs + rec.step,
    family: rec.family,
    variant: rec.variant,
    label: rec.label,
    toolDef: parts.toolDef,
    result: parts.result,
    attemptedCall: parts.attemptedCall,
    tainted: verdict.tainted,
    findings: verdict.findings,
    decision: verdict.decision,
    breached: parts.breached ?? false,
    blockedBy: verdict.blockedBy,
    citation: verdict.citation,
    latencyMs: verdict.latencyMs,
  };
  rec.traces.push(trace);
  rec.step++;
  return trace;
}

/* --------------------------------------------------------------------------
 * helpers
 * ------------------------------------------------------------------------ */

function callCapabilities(tool: string, def?: ToolDef): Capability[] {
  const caps = capabilitiesOf(tool);
  if (caps.length) return caps;
  if (def && def.name === tool) return def.capabilities;
  return def?.capabilities ?? [];
}

function resolveVariant(opts: RunScenarioOptions): AttackVariant {
  const family = opts.family as AttackFamilyNonBenign;
  if (opts.mutate) return mutate(family, opts.seed ?? 1);
  if (opts.variant) {
    const byId = opts.variant.includes('/') ? variantById(opts.variant) : undefined;
    if (byId) return byId;
    const inFamily = (HAND_WRITTEN[family] ?? []).find((v) => v.variant === opts.variant);
    if (inFamily) return inFamily;
  }
  const list = HAND_WRITTEN[family] ?? [];
  const idx = (opts.seed ?? 0) % Math.max(1, list.length);
  return list[idx]!;
}

/** Build the concrete hijack calls a hijacked agent will attempt for a variant. */
function hijackCalls(v: AttackVariant): InducedCall[] {
  const calls: InducedCall[] = [];
  if (v.carriesSecret) {
    calls.push({
      tool: 'get_api_credentials',
      args: {},
      capabilities: capabilitiesOf('get_api_credentials'),
      induced: true,
      carriesSecret: false,
    });
  }
  calls.push({
    tool: v.tool,
    args: { ...v.args },
    capabilities: callCapabilities(v.tool, v.toolDef),
    induced: true,
    destinationHost: v.destinationHost,
    carriesSecret: v.carriesSecret,
    needsCredentials: v.carriesSecret,
    transform: v.transform,
  });
  return calls;
}

function mkCall(
  rec: Recorder,
  server: string,
  tool: string,
  args: Record<string, unknown>,
): ToolCall {
  return {
    id: seededId('call', rec.seed, rec.step + 1000),
    sessionId: rec.sessionId,
    server,
    tool,
    args,
    ts: rec.baseTs + rec.step,
  };
}

/* --------------------------------------------------------------------------
 * runScenario
 * ------------------------------------------------------------------------ */

export function runScenario(opts: RunScenarioOptions): Trace[] {
  if (opts.family === 'benign') return runBenign(opts);
  return runAttack(opts);
}

function runAttack(opts: RunScenarioOptions): Trace[] {
  const seed = opts.seed ?? 1;
  const sessionId = opts.sessionId ?? seededId('sess', seed, 0);
  const v = resolveVariant(opts);
  const gate = opts.gate;
  const allowlist = opts.allowlist ?? DEFAULT_ALLOWLIST;
  void allowlist;

  const rec: Recorder = {
    seed,
    sessionId,
    family: v.family,
    variant: v.variant,
    label: 'attack',
    traces: [],
    step: 0,
    baseTs: 1_700_000_000_000 + seed * 1000,
  };

  const ctx = acme.createAcmeContext();

  // register the fake secrets with the gate if it supports it
  if (typeof gate.registerSecret === 'function') {
    for (const s of acme.registeredSecrets()) gate.registerSecret(s);
  }

  // ----- 1) list tools: prime the gate, record the malicious/changed def -----
  const baseDefs = acme.toolDefs();

  if (v.family === 'rug_pull' && v.originalToolDef && v.toolDef) {
    // prime trust on everything, then present the ORIGINAL (trusted), then the CHANGED one
    for (const d of baseDefs) gate.inspectToolDef(d, sessionId);
    const vo = coalesce(gate.inspectToolDef(v.originalToolDef, sessionId));
    record(rec, 'tool_def', vo, { toolDef: v.originalToolDef });
    const vc = coalesce(gate.inspectToolDef(v.toolDef, sessionId));
    record(rec, 'tool_def', vc, { toolDef: v.toolDef });
  } else if (v.toolDef) {
    // poisoned_description / homoglyph_spoof: prime baseline, then the malicious def
    for (const d of baseDefs) gate.inspectToolDef(d, sessionId);
    const vd = coalesce(gate.inspectToolDef(v.toolDef, sessionId));
    record(rec, 'tool_def', vd, { toolDef: v.toolDef });
  } else {
    // doc_content / fetched_page: baseline defs only (no recorded def trace)
    for (const d of baseDefs) gate.inspectToolDef(d, sessionId);
  }

  // find a def to pass to inspectCall for capability context
  const defByName = new Map<string, ToolDef>();
  for (const d of baseDefs) defByName.set(d.name, d);
  if (v.toolDef) defByName.set(v.toolDef.name, v.toolDef);

  // ----- 2) the agent's benign plan call + reading the delivery -----
  let deliveryText = v.payload;

  if (v.payloadVia === 'result' && v.resultCall) {
    // behavioural rug pull / look-alike tool: the definition is clean, the RESULT carries the payload
    const call = mkCall(rec, 'acme', v.resultCall.tool, { ...v.resultCall.args });
    const cv = coalesce(gate.inspectCall(call, defByName.get(v.resultCall.tool), sessionId));
    record(rec, 'tool_call', cv, {
      attemptedCall: { server: 'acme', tool: v.resultCall.tool, args: call.args, capabilities: callCapabilities(v.resultCall.tool, v.toolDef) },
    });
    const content = v.payload;
    deliveryText = content;
    const result: ToolResult = { callId: call.id, server: 'acme', tool: v.resultCall.tool, content, ts: call.ts };
    const rv = coalesce(gate.inspectResult(result, sessionId));
    record(rec, 'tool_result', rv, { result: { server: 'acme', tool: v.resultCall.tool, content } });
  } else if (v.delivery === 'doc_content' && v.docId) {
    acme.poisonSharedDoc(ctx, v.docId, v.payload);
    const call = mkCall(rec, 'acme', 'read_shared_doc', { docId: v.docId });
    const cv = coalesce(gate.inspectCall(call, defByName.get('read_shared_doc'), sessionId));
    record(rec, 'tool_call', cv, {
      attemptedCall: { server: 'acme', tool: 'read_shared_doc', args: call.args, capabilities: ['read'] },
    });
    const content = acme.callTool('read_shared_doc', call.args, ctx);
    deliveryText = content;
    const result: ToolResult = { callId: call.id, server: 'acme', tool: 'read_shared_doc', content, ts: call.ts };
    const rv = coalesce(gate.inspectResult(result, sessionId));
    record(rec, 'tool_result', rv, { result: { server: 'acme', tool: 'read_shared_doc', content } });
  } else if (v.delivery === 'fetched_page' && v.sourceUrl) {
    acme.plantPage(ctx, v.sourceUrl, v.payload);
    const call = mkCall(rec, 'acme', 'fetch_url', { url: v.sourceUrl });
    const cv = coalesce(gate.inspectCall(call, defByName.get('fetch_url'), sessionId));
    record(rec, 'tool_call', cv, {
      attemptedCall: { server: 'acme', tool: 'fetch_url', args: call.args, capabilities: ['network'] },
    });
    const content = acme.callTool('fetch_url', call.args, ctx);
    deliveryText = content;
    const result: ToolResult = { callId: call.id, server: 'acme', tool: 'fetch_url', content, ts: call.ts };
    const rv = coalesce(gate.inspectResult(result, sessionId));
    record(rec, 'tool_result', rv, { result: { server: 'acme', tool: 'fetch_url', content } });
  } else {
    // def-delivered: do a benign lookup as the task's baseline work
    const call = mkCall(rec, 'acme', 'lookup_customer', { id: '1001' });
    const cv = coalesce(gate.inspectCall(call, defByName.get('lookup_customer'), sessionId));
    record(rec, 'tool_call', cv, {
      attemptedCall: { server: 'acme', tool: 'lookup_customer', args: call.args, capabilities: ['read'] },
    });
    const content = acme.callTool('lookup_customer', call.args, ctx);
    const result: ToolResult = { callId: call.id, server: 'acme', tool: 'lookup_customer', content, ts: call.ts };
    const rv = coalesce(gate.inspectResult(result, sessionId));
    record(rec, 'tool_result', rv, { result: { server: 'acme', tool: 'lookup_customer', content } });
  }

  // confirm the gullible agent parsed an instruction out of what it read
  const agent = new GullibleAgent({ complete: opts.complete });
  void agent;
  const followed = react(deliveryText).length > 0;

  // ----- 3) the hijack: the agent follows the instruction -----
  const calls = hijackCalls(v);
  let creds: string | undefined;

  for (const ic of calls) {
    let concrete = ic;
    if (ic.needsCredentials) {
      if (creds === undefined) creds = acme.callTool('get_api_credentials', {}, ctx);
      concrete = fillCredentials(ic, creds, v.transform);
    }

    const call = mkCall(rec, 'acme', concrete.tool, concrete.args);
    const def = defByName.get(concrete.tool);
    const verdict = coalesce(gate.inspectCall(call, def, sessionId));

    // capture the credential result for a plain get_api_credentials step
    if (concrete.tool === 'get_api_credentials' && creds === undefined) {
      creds = acme.callTool('get_api_credentials', {}, ctx);
    }

    const isExfilStep = concrete.tool !== 'get_api_credentials';
    const breached = isExfilStep && verdict.decision === 'allow';

    record(rec, 'tool_call', verdict, {
      attemptedCall: {
        server: 'acme',
        tool: concrete.tool,
        args: concrete.args,
        capabilities: concrete.capabilities,
      },
      breached,
    });
  }

  // reflect whether the agent actually followed the injection (for debugging)
  if (!followed && rec.traces.length) {
    // the declared hijack still drove the steps above; nothing to change.
  }

  return rec.traces;
}

/* --------------------------------------------------------------------------
 * benign scenario
 * ------------------------------------------------------------------------ */

function runBenign(opts: RunScenarioOptions): Trace[] {
  const seed = opts.seed ?? 1;
  const sessionId = opts.sessionId ?? seededId('sess', seed, 0);
  const gate = opts.gate;

  const session: BenignSession = benignTraffic(1, seed)[0]!;
  const rec: Recorder = {
    seed,
    sessionId,
    family: 'benign',
    variant: 'legit',
    label: 'benign',
    traces: [],
    step: 0,
    baseTs: 1_700_000_000_000 + seed * 1000,
  };

  const ctx = acme.createAcmeContext();
  const baseDefs = acme.toolDefs();
  for (const d of baseDefs) gate.inspectToolDef(d, sessionId);
  const defByName = new Map<string, ToolDef>();
  for (const d of baseDefs) defByName.set(d.name, d);

  for (const c of session.calls) {
    const call = mkCall(rec, 'acme', c.tool, c.args);
    const verdict = coalesce(gate.inspectCall(call, defByName.get(c.tool), sessionId));
    record(rec, 'tool_call', verdict, {
      attemptedCall: { server: 'acme', tool: c.tool, args: c.args, capabilities: capabilitiesOf(c.tool) },
      breached: false,
    });
    const content = acme.callTool(c.tool, c.args, ctx);
    const result: ToolResult = { callId: call.id, server: 'acme', tool: c.tool, content, ts: call.ts };
    const rv = coalesce(gate.inspectResult(result, sessionId));
    record(rec, 'tool_result', rv, { result: { server: 'acme', tool: c.tool, content } });
  }

  return rec.traces;
}
