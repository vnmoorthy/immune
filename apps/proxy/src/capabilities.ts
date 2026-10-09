import type { Capability } from '@immune/core';

/**
 * Capability inference for MCP tools that do not declare one. Heuristic by design:
 * tool name tokens and input-schema property names are authoritative; description
 * tokens only contribute the strong network/exec verbs. Anything unmatched is 'read'.
 */
const NETWORK_NAME = new Set([
  'fetch', 'http', 'https', 'url', 'urls', 'uri', 'webhook', 'webhooks', 'download', 'upload', 'request',
  'curl', 'post', 'crawl', 'browse', 'scrape', 'send', 'email', 'mail', 'notify', 'slack', 'endpoint', 'ping',
]);
const NETWORK_PROPS = new Set(['url', 'urls', 'uri', 'endpoint', 'webhook', 'href', 'host', 'hostname', 'callback', 'callback_url']);
const NETWORK_DESC = new Set(['fetch', 'fetches', 'download', 'downloads', 'http', 'https', 'url', 'urls', 'webhook', 'webhooks', 'curl']);

const EXEC_NAME = new Set([
  'run', 'exec', 'execute', 'shell', 'command', 'cmd', 'bash', 'sh', 'zsh', 'powershell', 'script', 'spawn',
  'eval', 'process', 'terminal', 'subprocess',
]);
const EXEC_PROPS = new Set(['command', 'cmd', 'script', 'shell']);
const EXEC_DESC = new Set(['exec', 'execute', 'executes', 'shell', 'subprocess', 'spawn', 'spawns']);

const SECRET_NAME = new Set([
  'secret', 'secrets', 'credential', 'credentials', 'token', 'tokens', 'apikey', 'key', 'keys', 'password',
  'passwords', 'passwd', 'private', 'auth', 'oauth', 'ssh',
]);
const SECRET_PROPS = new Set(['token', 'secret', 'password', 'apikey', 'api_key', 'credential', 'credentials']);

const WRITE_NAME = new Set([
  'write', 'update', 'delete', 'create', 'insert', 'remove', 'modify', 'set', 'put', 'patch', 'edit', 'save',
  'rename', 'move', 'drop', 'truncate', 'append', 'add', 'upsert', 'publish', 'commit', 'push', 'deploy', 'mkdir', 'rm',
]);

const ORDER: Capability[] = ['read', 'write', 'network', 'exec', 'secret'];

export function tokenize(text: string): string[] {
  return text
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

function hasAny(tokens: string[], set: Set<string>): boolean {
  return tokens.some((t) => set.has(t));
}

function propertyNames(inputSchema: Record<string, unknown> | undefined): string[] {
  const props = inputSchema?.properties;
  return props && typeof props === 'object' ? Object.keys(props as Record<string, unknown>) : [];
}

export interface ToolAnnotationsLike {
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
}

export function inferCapabilities(
  name: string,
  description: string,
  inputSchema?: Record<string, unknown>,
  annotations?: ToolAnnotationsLike,
): Capability[] {
  const caps = new Set<Capability>();
  const nameTokens = tokenize(name);
  const propTokens = propertyNames(inputSchema).map((p) => p.toLowerCase());
  const descTokens = tokenize(description);

  if (hasAny(nameTokens, NETWORK_NAME) || hasAny(propTokens, NETWORK_PROPS) || hasAny(descTokens, NETWORK_DESC)) caps.add('network');
  if (hasAny(nameTokens, EXEC_NAME) || hasAny(propTokens, EXEC_PROPS) || hasAny(descTokens, EXEC_DESC)) caps.add('exec');
  if (hasAny(nameTokens, SECRET_NAME) || hasAny(propTokens, SECRET_PROPS)) caps.add('secret');
  if (hasAny(nameTokens, WRITE_NAME) || annotations?.destructiveHint === true) caps.add('write');
  if (annotations?.readOnlyHint === true) caps.delete('write');

  if (caps.size === 0) caps.add('read');
  return ORDER.filter((c) => caps.has(c));
}
