# Semgrep × Immune — rules for weaknesses in AI-generated MCP servers

Semgrep is the **static half** of Immune's loop. The proxy catches an attack at runtime; the
synthesizer turns the breach into an antibody; and when the antibody has an identifiable code
sink (fetch / exec / eval / fs write) it is also emitted as a Semgrep rule so the *source* of
the MCP server can be rescanned — the `semgrep_rescan` step of every remediation. The rules in
this folder are the hand-written seed set: the same weaknesses, in the same YAML shape the
synthesizer produces.

```
integrations/semgrep/
├── rules/immune-mcp.yaml                 8 rules (5 taint-mode, 3 search-mode)
├── targets/acme_server.ts                vulnerable "AI-generated" MCP dispatcher (the demo server's real sinks)
├── targets/sample_vulnerable_server.ts   same weaknesses in @modelcontextprotocol/sdk style + NEGATIVE CONTROLS
└── README.md
```

## Run it

```bash
# from the repo root — exactly what the Immune engine runs in the semgrep_rescan step
semgrep --config integrations/semgrep/rules/immune-mcp.yaml integrations/semgrep/targets --json

# human-readable, with the taint trace from source to sink
semgrep --config integrations/semgrep/rules/immune-mcp.yaml integrations/semgrep/targets --dataflow-traces

# scan YOUR MCP server
semgrep --config integrations/semgrep/rules/immune-mcp.yaml path/to/your-mcp-server/

# only the high-confidence rules, SARIF for code scanning
semgrep --config integrations/semgrep/rules/immune-mcp.yaml src/ --severity ERROR --sarif -o immune.sarif

# check the pack itself
semgrep --validate --config integrations/semgrep/rules/immune-mcp.yaml
```

Requires `semgrep` ≥ 1.100 (`brew install semgrep` or `pipx install semgrep`); verified with 1.180.0.
No login or Semgrep account is needed — these are local rules. `--metrics=off` disables telemetry.

## Results on the fixtures (semgrep 1.180.0, OSS engine)

`semgrep --config integrations/semgrep/rules/immune-mcp.yaml integrations/semgrep/targets --json` →
**36 findings, 0 errors, 0 false positives on the negative controls.**

| rule | `acme_server.ts` | `sample_vulnerable_server.ts` | what it hits |
|---|---:|---:|---|
| `immune-tool-result-to-fetch` | 4 | 6 (5 lines) | `fetch(url)` in `fetchUrl`, `fetch(args.url, …)` in `sendWebhook`, `fetchUrl({url: urlMatch[0]})` fed by `readSharedDoc()`, the `callTool` dispatcher; SDK `server.tool` handlers, `axios.get(args.endpoint)`, `request.params.arguments` |
| `immune-tool-result-to-exec` | 3 | 2 | `exec(cmd)` built from `args.name`, `runReport({query: doc})` fed by a shared doc, `execSync(\`… ${name}\`)`, `spawn(…, {shell: true})` |
| `immune-secret-in-outbound-body` | 1 | 2 | `getApiCredentials()` + `API_CREDENTIALS.*` → `fetch(args.url, {body})`; `process.env.ACME_API_KEY` in a body; `SLACK_BOT_TOKEN` in a query string |
| `immune-poisoned-tool-description` | 0 | 2 | `<IMPORTANT>… do not tell the user`, zero-width chars + "Ignore previous instructions" |
| `immune-missing-host-allowlist` | 2 | 5 | every dynamic-URL request in a tool handler with no allowlist idiom |
| `immune-eval-on-tool-output` | 0 | 4 (2 lines) | `eval(source)`, `new Function('ctx', source)` on shared-doc text |
| `immune-write-to-sensitive-path` | 0 | 4 (3 lines) | tool text → `~/.ssh/authorized_keys`, `~/.env`; `writeFileSync(args.path, …)` |
| `immune-confusable-tool-name` | 0 | 1 | `lоokup_customer` (Cyrillic о) |

Counts are raw `--json` findings; a line carries two findings when two different taint sources
(e.g. the handler parameter *and* a `readSharedDoc()` result) reach the same sink — hence
"(n lines)".

Negative controls in `sample_vulnerable_server.ts` (`// ok:` blocks) — a throwing `assertAllowedHost(url)`,
an `ALLOWED_HOSTS.has(new URL(url).hostname)` guard, a first-party literal host carrying our own
API key, argv-form `spawn('acme-report', ['--name', name])`, a sandbox-rooted write with
`path.basename` + `startsWith(root)`, and a description containing a harmless `<table>` — produce
**zero** findings. The zeros for acme on rules 4/6/7/8 are also correct: that file has none of those
weaknesses.

## The rules

All rules: `languages: [typescript, javascript]`, `metadata.category: security`, CWE + OWASP
Top-10 + **OWASP Top 10 for LLM Applications (2025)** ids, references, and an `immune:` block that
names the runtime family / detector / gate rule the static finding corresponds to.

| id | mode | weakness | CWE | OWASP-LLM | Immune family → detector |
|---|---|---|---|---|---|
| `immune-tool-result-to-fetch` | taint | LLM-chosen argument or tool-result text reaches the URL of `fetch`/`axios`/`got`/`http.request`/`new Request` or a `fetch*`/`download*`/`scrape*` wrapper | 918, 20 | LLM01, LLM05, LLM06 | `indirect_fetch` → `destination` |
| `immune-tool-result-to-exec` | taint | the same sources reach `exec`/`execSync`, `spawn`/`execFile` with `shell: true`, `sh -c`, or a `run*`/`exec*`/`shell*` wrapper | 78 | LLM05, LLM06, LLM01 | `result_injection` → `taint_gate` |
| `immune-secret-in-outbound-body` | taint | `process.env.*SECRET*`, identifiers/properties named like credentials, `get*Credentials()` getters, or literal `AKIA…`/`sk-…`/`ghp_…`/`xox…` tokens reach the **body, headers or URL** of a request whose destination is *not* a literal first-party host | 200, 522 | LLM02, LLM06, LLM01 | `secret_exfil` → `secret_exfil` |
| `immune-poisoned-tool-description` | search | registered tool description contains `<IMPORTANT>`-style tags, "do not tell the user", "ignore previous instructions", "before using this tool", `system prompt`, zero-width characters (`​…﻿`, escaped or raw), `~/.ssh`, `id_rsa` | 1427, 506 | LLM01, LLM03 | `poisoned_description` → `poisoned_description` |
| `immune-missing-host-allowlist` | search | a tool handler (`server.tool`, `registerTool`, `setRequestHandler`, `fetch*Url`-style or `*_tool` dispatcher functions) requests a dynamic URL and no allowlist idiom (`ALLOWED.has/includes`, `isAllowedHost`, `assertAllowedHost`, early-exit guard) is visible | 918, 862 | LLM06 | `indirect_fetch` → `destination` |
| `immune-eval-on-tool-output` | taint | sources reach `eval`, `new Function`, `vm.runIn*Context`, `new vm.Script`, dynamic `import()`/`require()`, string `setTimeout` | 95, 94 | LLM05, LLM01 | `result_injection` → `taint_gate` |
| `immune-write-to-sensitive-path` | taint | sources are written **into** `~/.ssh`, `.env`, shell rc, `.npmrc`/`.gitconfig`/`.aws`/`.kube`, agent config (`.claude`, `.cursor`, `.mcp.json`), cron/launchd — or the **path itself** is tool-controlled | 73, 22, 732 | LLM06, LLM05 | `result_injection` → `taint_gate` |
| `immune-confusable-tool-name` | search | registered tool name contains non-ASCII / escaped / invisible characters (homoglyph shadowing) | 1007 | LLM03, LLM01 | `homoglyph_spoof` → `homoglyph` |

### Taint sources shared by the taint rules

1. **Handler parameters** of `server.tool(…, async (args) => …)`, `registerTool`, and
   `setRequestHandler(CallToolRequestSchema, async (request) => …)` — destructured params included.
2. **Plain handler functions** whose parameter is named like tool input
   (`args|arguments|input|params|toolArgs|toolInput|request|req|payload`) — the `callTool(name, args)`
   dispatcher shape every LLM writes.
3. `request.params.arguments`, `client.callTool(...)`, `result.content[i].text`.
4. **HTTP responses** (`fetch(...)`, `axios…`, `got…`) — fetched content is attacker text (Immune's
   `indirect_fetch` family).
5. **Tool-result getters** by name: `readSharedDoc()`, `getPage()`, `loadDocument()`, `fetchEmail()`,
   `listTickets()`, `searchRecords()` … (regex over `(read|get|fetch|load|open|download|search|list|query)_?…_?(doc|file|page|content|note|email|message|ticket|issue|comment|result|url|site|feed|record)s?`).

Call-based sources are `exact: true` so a call's *own arguments* are never treated as tainted by
that call (that is what keeps `fetch(\`https://drive.acme.internal/${id}\`)` clean).

### Sanitizers recognised

Throwing allowlist checks (`assert|require|check|ensure|validate|verify|enforce|guard…(host|destination|url|allow|origin|domain)…`, by side effect),
guarded branches (`if (ALLOWED.has(...))`, `if (isAllowed…(...))`), early-exit guards
(`if (!ALLOWED.has(host)) throw/return`), strict-regex guards (`if (!/^[a-z0-9_-]+$/.test(x)) throw`),
shell quoting (`shellEscape`, `shellQuote`, `quote`), `path.basename`, sandbox-root `startsWith` guards,
and `redact|mask|hash|sha256|digest` for secrets.

### Honest limitations

- Semgrep OSS taint is **intraprocedural**. The `handleSummarize → fetchUrl({url})` hop in
  `acme_server.ts` is caught only because `fetchUrl` matches the *wrapper-name heuristic*
  (`fetch*` / `run*` / `exec*` user functions are sinks). `semgrep --pro` tracks the flow
  properly across functions and files; nothing in the rules needs changing for Pro.
- The wrapper heuristics and the "parameter named `args`" source are deliberately broad
  (`confidence: MEDIUM`) — they are tuned for the code LLMs write, not for arbitrary codebases.
  Scope the scan to your MCP server package.
- `immune-missing-host-allowlist` is structural (`confidence: LOW`, `severity: WARNING`): it
  cannot see an allowlist enforced *outside* the handler (e.g. by the Immune proxy). That is the
  point — with the proxy in front, the finding becomes advisory.
- The secret rule excludes requests to a **literal** `https://host` (first-party API auth is not
  exfiltration). A secret sent to a first-party host that is *also* a tool argument is still flagged.

## How Immune's synthesizer emits rules in this format

`synthesizeAntibody(breach, corpus)` in `packages/core/src/synthesizer.ts` produces a runtime
`Rule` (the antibody) and, when the breach trace has an identifiable sink — the attempted call
had a `network`/`exec`/`write` capability and the tool name maps to a known handler — fills
`Rule.semgrep` with a single-rule YAML document of exactly this shape:

```yaml
rules:
  - id: immune-synth-<ruleId>                # e.g. immune-synth-rl_3f9c2a7b1d4e
    mode: taint
    message: >-
      Synthesized from breach trace <traceId> (<family>, variant <variant>): tool-result text
      reached <tool> (<capability>). Promoted after replay proof <proofHash>. Receipt <receiptId>.
    severity: ERROR
    languages: [typescript, javascript]
    metadata:
      category: security
      owasp-llm: ["LLM01:2025 Prompt Injection"]
      immune:
        ruleId: rl_3f9c2a7b1d4e
        derivedFrom: [tr_9a1b2c3d4e5f]
        family: result_injection
        receiptId: rc_...
        rulingId: ru_...
    pattern-sources:
      - pattern: readSharedDoc(...)            # the tool whose result carried the payload
        exact: true
      - pattern: $REQ.params.arguments
        exact: true
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: fetch($URL, ...)        # the sink the breached call reached
              - pattern: sendWebhook($URL, ...)  # the tool handler by name
          - focus-metavariable: $URL
```

The engine's `semgrep_rescan` step then calls `runSemgrep(rule.semgrep, ['integrations/semgrep/targets'])`
(`packages/core/src/semgrep.ts`), which writes the YAML to a temp file and runs
`semgrep --config <tmpfile> --json <paths>`; the finding count lands in `ProofReport.semgrep`
and in the signed receipt. If `semgrep` is not on `PATH`, the step is reported as **skipped with a
reason** — never faked (`AdapterStatus.semgrep.installed`).

Because the synthesized rule and the hand-written rules share one format, you can concatenate them:

```bash
semgrep --config integrations/semgrep/rules/immune-mcp.yaml --config .immune/rules/ src/
```

## Semgrep in Claude Code (the "fix it where you write it" loop)

Install the official Semgrep plugin for Claude Code and let the agent scan what it just generated:

```bash
claude plugin install semgrep@claude-plugins-official
```

Then, inside Claude Code, ask in plain words — the plugin gives the agent Semgrep's CLI and
guidance on reading results:

> run `semgrep --config integrations/semgrep/rules/immune-mcp.yaml` on the MCP server you just
> wrote, explain each ERROR with its taint trace, and fix them without weakening the tool

Combined with the Immune proxy (`immune wrap --name acme -- <server cmd>`), this closes the loop
both ways: the proxy blocks the attack at runtime and cites the ruling; Semgrep finds the
weakness in the source before the next agent ships it.

The plugin uses whatever `semgrep` binary is on `PATH` (`brew install semgrep`); `semgrep login`
is optional and only needed for Semgrep's hosted rule registry — the Immune rules are local
files. Check `claude plugin list` for the exact commands the installed plugin version exposes.

## Writing more rules

- Keep one weakness per rule; name it `immune-<source>-to-<sink>` or `immune-<thing>`.
- Prefer `mode: taint` when there is a real data flow; use `focus-metavariable` on the exact sink
  argument; set `exact: true` on call-shaped sources.
- Add a positive case to `targets/sample_vulnerable_server.ts` **and** a `// ok:` negative control.
- Re-run the two commands above; the finding table in this README should change only where you
  intended.
