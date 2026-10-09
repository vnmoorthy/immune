/**
 * All proxy diagnostics go to stderr. stdout is the MCP channel and must never
 * receive anything but JSON-RPC frames.
 */
const PREFIX = '[immune]';

export function log(message: string): void {
  process.stderr.write(`${PREFIX} ${message}\n`);
}

export function warn(message: string): void {
  process.stderr.write(`${PREFIX} warn: ${message}\n`);
}

/** Route every console.* call to stderr so a stray console.log can never corrupt the MCP stream. */
export function protectStdout(): void {
  const toStderr = (...args: unknown[]): void => {
    process.stderr.write(args.map((a) => (typeof a === 'string' ? a : safeStringify(a))).join(' ') + '\n');
  };
  console.log = toStderr;
  console.info = toStderr;
  console.debug = toStderr;
  console.warn = toStderr;
}

export function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value) ?? String(value);
  } catch {
    return String(value);
  }
}

export function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export function truncate(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, max)}…`;
}
