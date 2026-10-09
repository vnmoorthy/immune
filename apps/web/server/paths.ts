import fs from 'node:fs';
import path from 'node:path';

let cachedRoot: string | undefined;

/** The pnpm workspace root (walks up from cwd until pnpm-workspace.yaml). */
export function repoRoot(): string {
  if (cachedRoot) return cachedRoot;
  let dir = process.cwd();
  for (let i = 0; i < 6; i++) {
    if (fs.existsSync(path.join(dir, 'pnpm-workspace.yaml'))) {
      cachedRoot = dir;
      return dir;
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  cachedRoot = path.resolve(process.cwd(), '../..');
  return cachedRoot;
}

export function semgrepTargetsDir(): string {
  return path.join(repoRoot(), 'integrations', 'semgrep', 'targets');
}

export function rulingsDir(): string {
  return path.join(repoRoot(), '.immune', 'rulings');
}
