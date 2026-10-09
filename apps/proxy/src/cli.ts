#!/usr/bin/env -S npx tsx
import { readFileSync } from 'node:fs';
import { Command } from 'commander';
import { DEFAULT_API } from './api.js';

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string };
export const VERSION = pkg.version;

function splitList(value: string | undefined): string[] {
  return (value ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

const program = new Command();
program
  .name('immune')
  .description('Immune — MCP firewall proxy. Wraps any stdio MCP server, gates every tool definition, call and result.')
  .version(VERSION)
  .enablePositionalOptions();

program
  .command('wrap')
  .description('wrap a stdio MCP server:  immune wrap --name acme [--api URL] [--allow host,host] -- <cmd> [args...]')
  .requiredOption('--name <server>', 'logical server name used in traces and rules')
  .option('--api <url>', 'Immune web API base URL', DEFAULT_API)
  .option('--allow <hosts>', 'comma-separated destination hosts allowed for network tools', '')
  .argument('<command...>', 'downstream MCP server command (place it after --)')
  .passThroughOptions()
  .action(async (command: string[], o: { name: string; api: string; allow: string }) => {
    const { runWrap } = await import('./wrap.js');
    await runWrap({
      name: o.name,
      api: o.api,
      allow: splitList(o.allow),
      command: command[0],
      args: command.slice(1),
      version: VERSION,
    });
  });

program
  .command('demo-server')
  .description('run the acme demo server as a real MCP stdio server (uses @immune/demo when present)')
  .option('--inline', 'use the inline demo tools even when @immune/demo is present', process.env.IMMUNE_DEMO_INLINE === '1')
  .option('--poison', 'add a tool with hidden instructions in its description', process.env.IMMUNE_DEMO_POISON === '1')
  .option('--rug-pull', 'rewrite a trusted tool definition after start-up (tools/list_changed)', process.env.IMMUNE_DEMO_RUGPULL === '1')
  .option('--rug-pull-after <ms>', 'delay before the rug pull', process.env.IMMUNE_DEMO_RUGPULL_AFTER_MS ?? '15000')
  .action(async (o: { inline?: boolean; poison?: boolean; rugPull?: boolean; rugPullAfter: string }) => {
    const { runDemoServer } = await import('./demo-server.js');
    await runDemoServer({
      version: VERSION,
      inline: o.inline,
      poison: o.poison,
      rugPull: o.rugPull,
      rugPullAfterMs: Number(o.rugPullAfter) || 15_000,
    });
  });

program
  .command('verify')
  .description('verify a signed receipt: prints OK/FAIL with the reason; exit code 0/1')
  .argument('<receipt.json>', 'receipt file ({id, ruleId, proof, signature} or {receipt: ...})')
  .option('--api <url>', 'Immune web API base URL (used with --remote)', DEFAULT_API)
  .option('--remote', 'verify through POST /api/receipts/verify instead of the local secret', false)
  .action(async (file: string, o: { api: string; remote: boolean }) => {
    const { runVerify } = await import('./verify.js');
    process.exitCode = await runVerify(file, o);
  });

program
  .command('rules')
  .description('list promoted rules from the API (fallback: builtin rules)')
  .option('--api <url>', 'Immune web API base URL', DEFAULT_API)
  .option('--all', 'include candidate and revoked rules', false)
  .option('--json', 'print JSON', false)
  .action(async (o: { api: string; all: boolean; json: boolean }) => {
    const { runRules } = await import('./rules.js');
    await runRules(o);
  });

program
  .command('mcp-config')
  .description('print the JSON snippet for .mcp.json / claude_desktop_config.json that routes a server through the proxy')
  .option('--name <server>', 'server name', 'acme')
  .option('--api <url>', 'Immune web API base URL', DEFAULT_API)
  .option('--allow <hosts>', 'comma-separated allowlisted destination hosts', '')
  .argument('[command...]', 'downstream server command (default: the bundled demo server)')
  .passThroughOptions()
  .action(async (command: string[], o: { name: string; api: string; allow: string }) => {
    const { printMcpConfig } = await import('./mcp-config.js');
    printMcpConfig({ name: o.name, api: o.api, allow: splitList(o.allow), command });
  });

program.parseAsync(process.argv).catch((err: unknown) => {
  process.stderr.write(`[immune] fatal: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}\n`);
  process.exit(1);
});
