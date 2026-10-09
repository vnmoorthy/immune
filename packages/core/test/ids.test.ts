import { describe, expect, it } from 'vitest';
import { canonicalJson, deterministicId, newId, sha256, toolDefHash, toolKey } from '../src/index.js';

describe('ids', () => {
  it('newId is prefix + 12 hex and unique', () => {
    const a = newId('tr');
    const b = newId('tr');
    expect(a).toMatch(/^tr_[0-9a-f]{12}$/);
    expect(a).not.toBe(b);
    expect(newId('rl')).toMatch(/^rl_[0-9a-f]{12}$/);
  });

  it('deterministicId is stable', () => {
    expect(deterministicId('rl', 'x')).toBe(deterministicId('rl', 'x'));
    expect(deterministicId('rl', 'x')).not.toBe(deterministicId('rl', 'y'));
    expect(deterministicId('rl', 'x')).toMatch(/^rl_[0-9a-f]{12}$/);
  });

  it('sha256 matches a known vector', () => {
    expect(sha256('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });

  it('canonicalJson sorts keys recursively and drops undefined', () => {
    const a = canonicalJson({ b: 1, a: { d: [3, { z: 1, y: 2 }], c: undefined }, e: undefined });
    const b = canonicalJson({ a: { d: [3, { y: 2, z: 1 }] }, b: 1 });
    expect(a).toBe(b);
    expect(a).toBe('{"a":{"d":[3,{"y":2,"z":1}]},"b":1}');
  });

  it('toolDefHash depends on name, description and schema only', () => {
    const def = { server: 'acme', name: 'fetch_url', description: 'Fetch', inputSchema: { type: 'object', properties: { url: { type: 'string' } } }, capabilities: ['network' as const] };
    const h1 = toolDefHash(def);
    const elsewhere = { ...def, server: 'other', capabilities: [] };
    expect(h1).toBe(toolDefHash(elsewhere));
    expect(h1).not.toBe(toolDefHash({ ...def, description: 'Fetch!' }));
    expect(h1).not.toBe(toolDefHash({ ...def, inputSchema: { type: 'object' } }));
    expect(toolKey('a', 'b')).toBe('a::b');
  });
});
