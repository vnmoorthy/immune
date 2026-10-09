import { describe, it, expect } from 'vitest';
import type { ToolCall, ToolDef, ToolResult } from '@immune/core';
import {
  runScenario,
  type GateLike,
  type GateVerdict,
  DEFAULT_ALLOWLIST,
  foldHomoglyphs,
  firstHost,
  isAllowedHost,
  looksLikeSecret,
} from '../src/index.js';

/**
 * A minimal, robust stand-in for the core Gate — enough to prove scenario.ts
 * wiring and the breach computation. It is NOT the real gate; core owns that.
 */
class StubGate implements GateLike {
  private tainted = new Set<string>();
  private pins = new Map<string, string>();
  constructor(private allowlist: readonly string[] = DEFAULT_ALLOWLIST) {}

  private v(decision: GateVerdict['decision'], sessionId: string, findings: GateVerdict['findings'] = [], blockedBy?: string): GateVerdict {
    return { decision, findings, latencyMs: 0.5, tainted: this.tainted.has(sessionId), blockedBy };
  }

  inspectToolDef(def: ToolDef, sessionId: string): GateVerdict {
    // homoglyph look-alike
    if (foldHomoglyphs(def.name) !== def.name) {
      this.tainted.add(sessionId);
      return this.v('quarantine', sessionId, [{ detector: 'homoglyph', severity: 'high', message: 'look-alike', evidence: def.name }]);
    }
    // rug pull: same (server,name) seen with a different hash
    const key = `${def.server}::${def.name}`;
    const prev = this.pins.get(key);
    const hash = def.hash ?? '';
    if (prev && prev !== hash) {
      this.tainted.add(sessionId);
      return this.v('quarantine', sessionId, [{ detector: 'rug_pull', severity: 'high', message: 'changed def', evidence: def.name }]);
    }
    if (!prev) this.pins.set(key, hash);
    // poisoned description
    if (/\b(call|post|send|fetch|run|curl|credential)\b/i.test(def.description)) {
      this.tainted.add(sessionId);
      return this.v('flag', sessionId, [{ detector: 'poisoned_description', severity: 'medium', message: 'imperative in desc', evidence: def.name }]);
    }
    return this.v('allow', sessionId);
  }

  inspectResult(result: ToolResult, sessionId: string): GateVerdict {
    const host = firstHost(result.content);
    const imperative = /\b(call|post|send|fetch|run|curl|credential|ignore previous)\b/i.test(result.content);
    if (imperative || (host && !isAllowedHost(host, this.allowlist))) {
      this.tainted.add(sessionId);
      return this.v('flag', sessionId, [{ detector: 'result_injection', severity: 'medium', message: 'instructions in result', evidence: result.tool }]);
    }
    return this.v('allow', sessionId);
  }

  inspectCall(call: ToolCall, def: ToolDef | undefined, sessionId: string): GateVerdict {
    const caps = def?.capabilities ?? [];
    const argsText = JSON.stringify(call.args);
    const host = firstHost(argsText);
    if (looksLikeSecret(argsText)) {
      return this.v('block', sessionId, [{ detector: 'secret_exfil', severity: 'critical', message: 'secret in args', evidence: 'secret' }], 'builtin:secret_exfil');
    }
    if ((caps.includes('network') || caps.includes('exec')) && host && !isAllowedHost(host, this.allowlist)) {
      return this.v('block', sessionId, [{ detector: 'destination', severity: 'high', message: `host ${host} not allowed`, evidence: host }], 'builtin:destination');
    }
    return this.v('allow', sessionId);
  }
}

/** A gate that allows everything — to demonstrate a breach. */
class AllowAllGate implements GateLike {
  inspectToolDef(): GateVerdict { return { decision: 'allow', findings: [], latencyMs: 0.1, tainted: false }; }
  inspectResult(): GateVerdict { return { decision: 'allow', findings: [], latencyMs: 0.1, tainted: true }; }
  inspectCall(): GateVerdict { return { decision: 'allow', findings: [], latencyMs: 0.1, tainted: true }; }
}

const FAMILIES = [
  'poisoned_description',
  'result_injection',
  'secret_exfil',
  'rug_pull',
  'homoglyph_spoof',
  'indirect_fetch',
] as const;

describe('runScenario', () => {
  it('drives every family through the gate and records traces, no breach under a robust gate', () => {
    for (const family of FAMILIES) {
      const gate = new StubGate();
      const traces = runScenario({ family, gate, seed: 1, sessionId: `s-${family}` });
      expect(traces.length, `${family} produced traces`).toBeGreaterThan(0);
      for (const t of traces) {
        expect(t.family).toBe(family);
        expect(t.sessionId).toBe(`s-${family}`);
      }
      // a robust gate catches the attack: at least one non-allow decision, no breach
      expect(traces.some((t) => t.decision !== 'allow'), `${family} caught`).toBe(true);
      expect(traces.some((t) => t.breached), `${family} should not breach`).toBe(false);
    }
  });

  it('records a BREACH when the gate allows the exfil step', () => {
    for (const family of FAMILIES) {
      const traces = runScenario({ family, gate: new AllowAllGate(), seed: 3, sessionId: `b-${family}` });
      const breached = traces.filter((t) => t.breached);
      expect(breached.length, `${family} should breach under allow-all`).toBeGreaterThan(0);
      // the breached step is an attempted call that was allowed
      for (const b of breached) {
        expect(b.decision).toBe('allow');
        expect(b.label).toBe('attack');
        expect(b.attemptedCall).toBeDefined();
      }
    }
  });

  it('is deterministic given a seed', () => {
    const a = runScenario({ family: 'secret_exfil', gate: new StubGate(), seed: 11, sessionId: 'd1' });
    const b = runScenario({ family: 'secret_exfil', gate: new StubGate(), seed: 11, sessionId: 'd1' });
    expect(a.map((t) => `${t.variant}:${t.decision}:${t.breached}`)).toEqual(
      b.map((t) => `${t.variant}:${t.decision}:${t.breached}`),
    );
  });

  it('runs mutated variants too', () => {
    const traces = runScenario({ family: 'result_injection', mutate: true, gate: new StubGate(), seed: 8, sessionId: 'm1' });
    expect(traces.length).toBeGreaterThan(0);
    expect(traces[0]!.variant.startsWith('mutated-')).toBe(true);
  });

  it('a benign scenario produces only allowed, non-breaching traces', () => {
    const traces = runScenario({ family: 'benign', gate: new StubGate(), seed: 4, sessionId: 'ok1' });
    expect(traces.length).toBeGreaterThan(0);
    for (const t of traces) {
      expect(t.label).toBe('benign');
      expect(t.decision).toBe('allow');
      expect(t.breached).toBe(false);
    }
  });
});
