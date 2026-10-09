import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { toolDefHash } from '@immune/core';
import type { ToolDef } from '@immune/core';
import { inferCapabilities } from './capabilities.js';
import { safeStringify } from './log.js';

/** Convert a downstream MCP tool into the Immune ToolDef the Gate inspects (hash pinned for rug-pull detection). */
export function toToolDef(server: string, tool: Tool): ToolDef {
  const description = tool.description ?? '';
  const inputSchema = (tool.inputSchema ?? { type: 'object' }) as Record<string, unknown>;
  const capabilities = inferCapabilities(tool.name, description, inputSchema, tool.annotations);
  const def: ToolDef = { server, name: tool.name, description, inputSchema, capabilities };
  def.hash = toolDefHash(def);
  return def;
}

/** Flatten an MCP tool result (current or legacy `toolResult` shape) into the text the agent will read. */
export function extractText(raw: object): string {
  const result = raw as Record<string, unknown>;
  const parts: string[] = [];
  if (Array.isArray(result.content)) {
    for (const block of result.content) {
      if (!block || typeof block !== 'object') continue;
      const b = block as Record<string, unknown>;
      if (b.type === 'text' && typeof b.text === 'string') parts.push(b.text);
      else if (b.type === 'resource' && b.resource && typeof b.resource === 'object') {
        const r = b.resource as Record<string, unknown>;
        if (typeof r.text === 'string') parts.push(r.text);
      } else if (b.type === 'resource_link' && typeof b.uri === 'string') {
        parts.push(`${typeof b.name === 'string' ? b.name : ''} ${b.uri}`.trim());
      }
    }
  }
  if (result.structuredContent !== undefined) parts.push(safeStringify(result.structuredContent));
  if (result.toolResult !== undefined) parts.push(typeof result.toolResult === 'string' ? result.toolResult : safeStringify(result.toolResult));
  return parts.join('\n');
}

/** MCP requires `inputSchema.type === 'object'`. */
export function ensureObjectSchema(schema: Record<string, unknown> | undefined): Tool['inputSchema'] {
  const base = schema && typeof schema === 'object' ? schema : {};
  return { ...base, type: 'object' } as Tool['inputSchema'];
}

export function envStrings(env: NodeJS.ProcessEnv): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(env)) if (typeof v === 'string') out[k] = v;
  return out;
}
