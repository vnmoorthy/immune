/**
 * Semgrep adapter — `semgrep --config <tmp.yaml> --json --quiet <paths>` via child_process.
 * Never throws: every failure is reported as { ran: false, ... } with a detail in `summary`.
 */
import { execFile } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { parse as yamlParse } from 'yaml';

export interface SemgrepStatus {
  installed: boolean;
  version?: string;
  detail?: string;
  /** binary used (env SEMGREP_BIN or 'semgrep' on PATH) */
  path?: string;
}

export interface SemgrepFinding {
  checkId: string;
  path: string;
  line: number;
  endLine?: number;
  message: string;
  severity: string;
  snippet?: string;
}

export interface SemgrepResult {
  /** semgrep actually executed and produced parseable JSON */
  ran: boolean;
  /** number of matches */
  findings: number;
  /** ran without errors (parse failures etc. make ok=false even if it ran) */
  ok: boolean;
  summary: string;
  raw?: unknown;
  results: SemgrepFinding[];
  errors: string[];
  ms: number;
  command?: string;
}

export interface RunSemgrepOptions {
  timeoutMs?: number;
  cwd?: string;
  /** extra CLI args */
  extraArgs?: string[];
}

export function semgrepBinary(env: NodeJS.ProcessEnv = process.env): string {
  return (env.SEMGREP_BIN && env.SEMGREP_BIN.trim()) || 'semgrep';
}

interface ExecOutcome {
  code: number | null;
  stdout: string;
  stderr: string;
  error?: NodeJS.ErrnoException & { killed?: boolean; signal?: string };
}

function run(bin: string, args: string[], opts: { timeoutMs: number; cwd?: string }): Promise<ExecOutcome> {
  return new Promise((resolve) => {
    try {
      execFile(
        bin,
        args,
        { timeout: opts.timeoutMs, cwd: opts.cwd, maxBuffer: 64 * 1024 * 1024, env: { ...process.env, SEMGREP_SEND_METRICS: 'off', SEMGREP_ENABLE_VERSION_CHECK: '0', NO_COLOR: '1' } },
        (error, stdout, stderr) => {
          const err = error as (NodeJS.ErrnoException & { code?: number | string; killed?: boolean; signal?: string }) | null;
          resolve({
            code: err ? (typeof err.code === 'number' ? err.code : null) : 0,
            stdout: String(stdout ?? ''),
            stderr: String(stderr ?? ''),
            error: err ?? undefined,
          });
        },
      );
    } catch (err) {
      resolve({ code: null, stdout: '', stderr: '', error: err as NodeJS.ErrnoException });
    }
  });
}

let statusCache: { at: number; status: SemgrepStatus } | undefined;
const STATUS_TTL_MS = 60_000;

/** Is semgrep installed? (`semgrep --version`, cached for 60s). */
export async function semgrepAvailable(opts: { force?: boolean; timeoutMs?: number } = {}): Promise<SemgrepStatus> {
  if (!opts.force && statusCache && Date.now() - statusCache.at < STATUS_TTL_MS) return statusCache.status;
  const bin = semgrepBinary();
  const out = await run(bin, ['--version'], { timeoutMs: opts.timeoutMs ?? 10_000 });
  let status: SemgrepStatus;
  if (out.error && (out.error.code === 'ENOENT' || /ENOENT|not found/i.test(out.error.message ?? ''))) {
    status = { installed: false, path: bin, detail: `semgrep not found on PATH (install: pip install semgrep, or brew install semgrep)` };
  } else if (out.error && out.error.killed) {
    // A slow probe under load must not flip a known-good install to "absent": keep the last good status.
    if (lastGood) {
      status = { ...lastGood, detail: `${lastGood.detail} (version probe timed out; last known good)` };
      statusCache = { at: Date.now() - STATUS_TTL_MS + 5_000, status }; // re-probe in 5 s
      return status;
    }
    status = { installed: false, path: bin, detail: 'semgrep --version timed out' };
  } else {
    const version = (out.stdout.trim().split(/\s+/).pop() ?? '').replace(/^v/, '') || undefined;
    if (version && /^\d+\.\d+/.test(version)) status = { installed: true, version, path: bin, detail: `semgrep ${version}` };
    else status = { installed: false, path: bin, detail: `unexpected semgrep --version output: ${(out.stdout || out.stderr).trim().slice(0, 120)}` };
  }
  if (status.installed) lastGood = status;
  statusCache = { at: Date.now(), status };
  return status;
}

let lastGood: SemgrepStatus | undefined;

function failure(summary: string, ms: number, extra: Partial<SemgrepResult> = {}): SemgrepResult {
  return { ran: false, findings: 0, ok: false, summary, results: [], errors: [], ms, ...extra };
}

/** Run a rule YAML against paths. Returns ran:false (never throws) when semgrep is missing, the YAML is invalid, paths are missing, or it times out. */
export async function runSemgrep(ruleYaml: string, paths: string[], opts: RunSemgrepOptions = {}): Promise<SemgrepResult> {
  const t0 = performance.now();
  const elapsed = () => Math.round((performance.now() - t0) * 1000) / 1000;

  if (!ruleYaml || !ruleYaml.trim()) return failure('no rule YAML provided', elapsed());
  try {
    const doc = yamlParse(ruleYaml) as { rules?: unknown };
    if (!doc || typeof doc !== 'object' || !Array.isArray(doc.rules) || !doc.rules.length) return failure('rule YAML has no `rules` list', elapsed());
  } catch (err) {
    return failure(`invalid rule YAML: ${(err as Error)?.message ?? String(err)}`, elapsed());
  }
  const existing = (paths ?? []).filter((p) => typeof p === 'string' && p.length > 0 && existsSync(p));
  if (!existing.length) return failure(`no scan targets exist (${(paths ?? []).join(', ') || 'none given'})`, elapsed());

  const status = await semgrepAvailable();
  if (!status.installed) return failure(`semgrep not installed: ${status.detail ?? ''}`.trim(), elapsed());

  let dir: string | undefined;
  try {
    dir = mkdtempSync(join(tmpdir(), 'immune-semgrep-'));
    const rulePath = join(dir, 'antibody.yaml');
    writeFileSync(rulePath, ruleYaml, 'utf8');
    const args = ['--config', rulePath, '--json', '--quiet', '--metrics=off', '--disable-version-check', ...(opts.extraArgs ?? []), ...existing];
    const command = `${status.path ?? 'semgrep'} ${args.map((a) => (a.includes(' ') ? JSON.stringify(a) : a)).join(' ')}`;
    const out = await run(status.path ?? semgrepBinary(), args, { timeoutMs: opts.timeoutMs ?? 120_000, cwd: opts.cwd });

    if (out.error?.killed) return failure(`semgrep timed out after ${opts.timeoutMs ?? 120_000}ms`, elapsed(), { command });
    if (out.error && (out.error.code === 'ENOENT' || /ENOENT/.test(out.error.message ?? ''))) return failure('semgrep binary disappeared (ENOENT)', elapsed(), { command });

    let parsed: { results?: unknown[]; errors?: unknown[]; version?: string } | undefined;
    try {
      parsed = JSON.parse(out.stdout) as typeof parsed;
    } catch {
      parsed = undefined;
    }
    if (!parsed || typeof parsed !== 'object') {
      const detail = (out.stderr || out.stdout).trim().split('\n').slice(-3).join(' | ').slice(0, 300);
      return failure(`semgrep exited ${out.code ?? 'unknown'} without JSON output${detail ? `: ${detail}` : ''}`, elapsed(), { command });
    }
    const lineCache = new Map<string, string[]>();
    const snippetFor = (path: string, line: number, endLine?: number): string | undefined => {
      try {
        let lines = lineCache.get(path);
        if (!lines) {
          lines = readFileSync(path, 'utf8').split('\n');
          lineCache.set(path, lines);
        }
        if (!line || line > lines.length) return undefined;
        return lines.slice(line - 1, Math.max(line, endLine ?? line)).join('\n').slice(0, 400);
      } catch {
        return undefined;
      }
    };
    const results: SemgrepFinding[] = (parsed.results ?? []).map((r) => {
      const x = r as { check_id?: string; path?: string; start?: { line?: number }; end?: { line?: number }; extra?: { message?: string; severity?: string; lines?: string } };
      const path = String(x.path ?? '');
      const line = Number(x.start?.line ?? 0);
      const endLine = x.end?.line !== undefined ? Number(x.end.line) : undefined;
      // semgrep prints "requires login" instead of source lines when logged out — read them ourselves
      const fromSemgrep = typeof x.extra?.lines === 'string' && !/^requires login$/i.test(x.extra.lines.trim()) ? x.extra.lines.slice(0, 400) : undefined;
      return {
        checkId: String(x.check_id ?? ''),
        path,
        line,
        endLine,
        message: String(x.extra?.message ?? ''),
        severity: String(x.extra?.severity ?? ''),
        snippet: fromSemgrep ?? snippetFor(path, line, endLine),
      };
    });
    const errors = (parsed.errors ?? [])
      .map((e) => {
        const x = e as { level?: string; message?: string; short_msg?: string; long_msg?: string; type?: string };
        return { level: String(x.level ?? 'error'), text: String(x.message ?? x.long_msg ?? x.short_msg ?? x.type ?? 'error') };
      })
      .filter((e) => e.level !== 'warn' && e.level !== 'warning' && e.level !== 'info')
      .map((e) => e.text.slice(0, 300));
    const ms = elapsed();
    const files = existing.length;
    const summary = `semgrep ${status.version ?? ''}: ${results.length} finding${results.length === 1 ? '' : 's'} in ${files} target${files === 1 ? '' : 's'} (${ms}ms)${errors.length ? `; ${errors.length} error${errors.length === 1 ? '' : 's'}` : ''}`.replace(/\s+/g, ' ');
    return { ran: true, findings: results.length, ok: errors.length === 0, summary, raw: parsed, results, errors, ms, command };
  } catch (err) {
    return failure(`semgrep failed: ${(err as Error)?.message ?? String(err)}`, elapsed());
  } finally {
    if (dir) {
      try {
        rmSync(dir, { recursive: true, force: true });
      } catch {
        /* ignore */
      }
    }
  }
}
