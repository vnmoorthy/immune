#!/usr/bin/env bash
# Headless-Chrome screenshots of the running command center → docs/screenshots/*.png
# usage: scripts/screenshot.sh [base_url]   (default http://localhost:3000)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASE="${1:-http://localhost:3000}"
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
OUT="$ROOT/docs/screenshots"; mkdir -p "$OUT"
shot() { # name path
  "$CHROME" --headless=new --disable-gpu --hide-scrollbars --force-dark-mode --window-size=1600,1000 \
    --virtual-time-budget=6000 --screenshot="$OUT/$1.png" "$BASE$2" >/dev/null 2>&1 && echo "✓ $1.png" || echo "✗ $1"
}
shot command-center /
shot antibodies /antibodies
shot receipts /receipts
shot rulings /rulings
shot traces /traces
shot data /data
