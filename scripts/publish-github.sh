#!/usr/bin/env bash
# Create/update the public GitHub repo for Immune with description, homepage, topics and GitHub Pages (docs/ folder).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
OWNER=vnmoorthy; NAME=immune
DESC="Immune — the agent security loop that turns every attack into an antibody. MCP firewall → replayable breach trace in ClickHouse → synthesized countermeasure → replay-proven → Semgrep rescan → signed receipt → ruling → the next agent is immune. Built at the Cyberdefense Hackathon, SF Tech Week 2026."
HOME_URL="https://$OWNER.github.io/$NAME/"
if ! gh repo view $OWNER/$NAME >/dev/null 2>&1; then
  gh repo create $OWNER/$NAME --public --description "$DESC" --homepage "$HOME_URL" --source . --remote origin --push
else
  gh repo edit $OWNER/$NAME --description "$DESC" --homepage "$HOME_URL"
  git push -u origin HEAD
fi
gh repo edit $OWNER/$NAME --add-topic ai-security --add-topic mcp --add-topic model-context-protocol --add-topic prompt-injection --add-topic agent-security --add-topic llm-security --add-topic clickhouse --add-topic semgrep --add-topic autonomous-remediation --add-topic cyberdefense --add-topic hackathon --add-topic typescript --add-topic nextjs --add-topic claude-code --add-topic guardrails --add-topic firewall
# GitHub Pages from /docs on the default branch
BR=$(git rev-parse --abbrev-ref HEAD)
gh api -X POST repos/$OWNER/$NAME/pages -f "source[branch]=$BR" -f "source[path]=/docs" >/dev/null 2>&1 || gh api -X PUT repos/$OWNER/$NAME/pages -f "source[branch]=$BR" -f "source[path]=/docs" >/dev/null 2>&1 || true
echo "repo: https://github.com/$OWNER/$NAME   site: $HOME_URL"
