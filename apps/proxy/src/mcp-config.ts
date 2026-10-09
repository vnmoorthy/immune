import { fileURLToPath } from 'node:url';

export interface McpConfigOptions {
  name: string;
  api: string;
  allow: string[];
  /** downstream command; defaults to the bundled demo server */
  command: string[];
}

export function buildMcpConfig(opts: McpConfigOptions): Record<string, unknown> {
  const cli = fileURLToPath(new URL('./cli.ts', import.meta.url));
  const downstream = opts.command.length > 0 ? opts.command : ['npx', 'tsx', cli, 'demo-server'];
  const args = ['tsx', cli, 'wrap', '--name', opts.name, '--api', opts.api];
  if (opts.allow.length > 0) args.push('--allow', opts.allow.join(','));
  args.push('--', ...downstream);
  return { mcpServers: { [opts.name]: { command: 'npx', args } } };
}

export function printMcpConfig(opts: McpConfigOptions): void {
  console.log(JSON.stringify(buildMcpConfig(opts), null, 2));
  process.stderr.write(
    [
      '',
      `# Paste the "${opts.name}" entry into:`,
      '#   Claude Code:    .mcp.json at your project root (or ~/.claude.json for user scope)',
      '#   Claude Desktop: claude_desktop_config.json under "mcpServers"',
      '# Every tool call then flows through the Immune gate; decisions are logged on stderr',
      `# and traces are posted to ${opts.api}/api/ingest when the dashboard is running.`,
      '',
    ].join('\n'),
  );
}
