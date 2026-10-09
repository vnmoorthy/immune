#!/usr/bin/env bash
# One command to run the whole Immune demo: ClickHouse (if installed) + the command center on http://localhost:3000
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="$ROOT/.tools/semgrep-venv/bin:$PATH"
if command -v clickhouse >/dev/null 2>&1; then
  if ! curl -s --max-time 1 http://localhost:8123/ping >/dev/null 2>&1; then
    echo "▸ starting local ClickHouse"; (nohup bash scripts/clickhouse.sh > .immune/clickhouse.log 2>&1 &) ; sleep 5
  fi
  curl -s --max-time 2 http://localhost:8123/ping >/dev/null 2>&1 && echo "▸ ClickHouse up on :8123" || echo "▸ ClickHouse not reachable — falling back to in-memory store"
else
  echo "▸ clickhouse binary not found (brew install --cask clickhouse) — using in-memory store"
fi
command -v semgrep >/dev/null 2>&1 && echo "▸ Semgrep $(semgrep --version 2>/dev/null | head -1)" || echo "▸ Semgrep not installed — rescan step will be skipped"
echo "▸ Immune command center → http://localhost:3000"
exec pnpm --filter @immune/web dev
