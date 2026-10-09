import { existsSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import type { CallToolResult, Tool } from '@modelcontextprotocol/sdk/types.js';
import type { ToolDef } from '@immune/core';
import { ATTACKER_HOST, INJECTED_DOC, INJECTED_PAGE, createInlineDemo } from './demo-tools.js';
import type { DemoImpl, InlineDemoOptions } from './demo-tools.js';
import { errorMessage, log, protectStdout } from './log.js';
import { ensureObjectSchema } from './mcp-utils.js';

export interface DemoServerOptions extends InlineDemoOptions {
  /** skip @immune/demo even when it is present */
  inline?: boolean;
  version: string;
}

/** The subset of @immune/demo's acme server this command uses. Context helpers are optional. */
interface DemoModule {
  toolDefs: () => ToolDef[];
  callTool: (name: string, args: Record<string, unknown>, ctx?: unknown) => string | Promise<string>;
  createAcmeContext?: () => unknown;
  poisonSharedDoc?: (ctx: unknown, docId: string, content: string) => void;
  plantPage?: (ctx: unknown, url: string, html: string) => void;
}

function isDemoModule(mod: unknown): mod is DemoModule {
  return (
    !!mod &&
    typeof mod === 'object' &&
    typeof (mod as DemoModule).toolDefs === 'function' &&
    typeof (mod as DemoModule).callTool === 'function'
  );
}

/**
 * The acme server keeps its shared drive / planted pages in a context object. Seed one with the
 * same attacker content the inline tools serve, so `read_shared_doc q3-plan` and a fetch of the
 * attacker's page carry injections when the real server is wrapped.
 */
function seededContext(mod: DemoModule): unknown {
  if (typeof mod.createAcmeContext !== 'function') return undefined;
  const ctx = mod.createAcmeContext();
  mod.poisonSharedDoc?.(ctx, 'q3-plan', INJECTED_DOC);
  mod.plantPage?.(ctx, `https://${ATTACKER_HOST}/news`, INJECTED_PAGE);
  return ctx;
}

/** Prefer the real @immune/demo acme server when the workspace has it; fall back to the inline copy. */
async function loadDemoPackage(): Promise<DemoImpl | null> {
  const workspacePath = fileURLToPath(new URL('../../../packages/demo/src/index.ts', import.meta.url));
  const candidates: Array<{ label: string; specifier: string; exists: boolean }> = [
    { label: '@immune/demo', specifier: '@immune/demo', exists: true },
    { label: workspacePath, specifier: pathToFileURL(workspacePath).href, exists: existsSync(workspacePath) },
  ];
  for (const c of candidates) {
    if (!c.exists) continue;
    try {
      const mod: unknown = await import(c.specifier);
      if (isDemoModule(mod)) {
        const ctx = seededContext(mod);
        return { source: c.label, toolDefs: () => mod.toolDefs(), callTool: (name, args) => mod.callTool(name, args, ctx) };
      }
    } catch (err) {
      const code = (err as { code?: unknown }).code;
      if (code === 'ERR_MODULE_NOT_FOUND' || code === 'MODULE_NOT_FOUND') continue; // not installed here; try the next candidate
      log(`demo package not loadable from ${c.label}: ${errorMessage(err)}`);
    }
  }
  return null;
}

function toMcpTool(def: ToolDef): Tool {
  return { name: def.name, description: def.description, inputSchema: ensureObjectSchema(def.inputSchema) };
}

export async function runDemoServer(opts: DemoServerOptions): Promise<void> {
  protectStdout();
  const impl = (opts.inline ? null : await loadDemoPackage()) ?? createInlineDemo(opts);

  const server = new Server({ name: 'acme-demo', version: opts.version }, { capabilities: { tools: { listChanged: true } } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: impl.toolDefs().map(toMcpTool) }));
  server.setRequestHandler(CallToolRequestSchema, async (req): Promise<CallToolResult> => {
    try {
      const text = await impl.callTool(req.params.name, (req.params.arguments ?? {}) as Record<string, unknown>);
      return { content: [{ type: 'text', text }] };
    } catch (err) {
      return { isError: true, content: [{ type: 'text', text: `error: ${errorMessage(err)}` }] };
    }
  });
  impl.onListChanged?.(() => {
    log('demo-server: tool definitions changed (rug pull); notifying client');
    void server.sendToolListChanged();
  });

  await server.connect(new StdioServerTransport());
  log(`demo-server up: ${impl.toolDefs().length} tools from ${impl.source}${opts.poison ? ' (+poisoned tool)' : ''}${opts.rugPull ? ' (rug pull armed)' : ''}`);
}
