#!/usr/bin/env bash
# Rebuild docs/deck/immune.pptx (+ immune.pdf) from scratch.
#   PPTXGENJS_DIR=<node_modules dir that contains pptxgenjs@3.12.0>  bash build.sh [out.pptx]
# e.g.  npm i --prefix /tmp/immune-deck pptxgenjs@3.12.0 && PPTXGENJS_DIR=/tmp/immune-deck/node_modules bash build.sh
# Needs: node, python3 + lxml; optional: LibreOffice (soffice) for the PDF, Google Chrome for docs/architecture.svg.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$HERE/../immune.pptx}"
: "${PPTXGENJS_DIR:?set PPTXGENJS_DIR to a node_modules folder containing pptxgenjs}"

NODE_PATH="$PPTXGENJS_DIR" node "$HERE/build_deck.js" "$OUT"
python3 "$HERE/postprocess.py" "$OUT"

if command -v soffice >/dev/null 2>&1; then
  PROFILE="$(mktemp -d)"
  soffice "-env:UserInstallation=file://$PROFILE" --headless --convert-to pdf --outdir "$(dirname "$OUT")" "$OUT" >/dev/null 2>&1 || echo "PDF export failed"
  rm -rf "$PROFILE"
fi
echo "built $OUT"
