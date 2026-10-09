# Immune — build contracts (read before touching any package)

Repo: pnpm workspace. Node 24, TypeScript strict, ESM. `@immune/core` is the shared library; everything imports its types from `packages/core/src/types.ts` — never redefine them.

**Do NOT run `pnpm install` / `pnpm add` yourself** (parallel installs corrupt the lockfile). All deps listed in package.json files are already installed. If you truly need another dependency, append a line to `DEPS_NEEDED.txt` at the repo root and code against a small local shim meanwhile.

Zero-key rule: the whole product must run end to end with NO API keys and NO network. Sponsor integrations (ClickHouse, Semgrep, Guild, Senso, Akash/OpenAI-compatible LLM, Claude Code CLI) light up when present and are reported in `AdapterStatus`. Never fake a sponsor integration as "connected" when it is not.

## Packages

### packages/core (`@immune/core`) — pure TypeScript, no React, no Next
```
src/types.ts                 shared domain model (done)
src/ids.ts                   newId(prefix) -> `${prefix}_${12 hex}` (crypto.randomBytes), sha256(str), canonicalJson(obj)
src/detectors/index.ts       runDetectors(input) -> Finding[]
src/detectors/*.ts           poisonedDescription, resultInjection, secretExfil, rugPull(hash pin registry), homoglyph, destination(allowlist), taintGate
src/policy.ts                evaluateRules(rules, input, ctx) -> { decision, findings, blockedBy?, citation? }  (rule precedence: quarantine > block > flag > allow; builtin rules in builtinRules())
src/gate.ts                  class Gate { constructor(opts: { rules: Rule[], allowlist: string[] }); inspectToolDef(def, sessionId) ; inspectResult(result, sessionId); inspectCall(call, def, sessionId) -> GateVerdict; taint tracking per session; quarantine set; pinned hashes }
                             GateVerdict = { decision, findings, blockedBy?, citation?, latencyMs, tainted }
src/synthesizer.ts           synthesizeAntibody(breach: Trace, corpus: Trace[], opts?) -> Rule   (deterministic: distinguishing tokens/phrases from the injected payload that occur in <=1% of benign traces; destination host; capability+taint signature; produce semgrep YAML when a sink is identifiable). Optional `llmRefine` hook signature: (draft: Rule, breach: Trace) => Promise<Rule>
src/replay.ts                replay(rules: Rule[], corpus: Trace[]) -> ReplayCounts ; prove(candidate: Rule, currentRules: Rule[], corpus: Trace[], targets: Trace[], extras?: { semgrep?: SemgrepResult, storeMs?: number }) -> ProofReport  (promoted iff targetCaught && catchRateAfter > catchRateBefore && fpRateAfter <= fpRateBefore)
src/receipts.ts              signReceipt(rule, proof, secret) -> Receipt ; verifyReceipt(receipt, secret) -> { ok, reason }  (HMAC-SHA256 over sha256(canonicalJson({ruleId, proof}))). Secret from env IMMUNE_RECEIPT_SECRET, default 'immune-dev-secret' with a warning flag in status.
src/semgrep.ts               semgrepAvailable() -> {installed, version}; runSemgrep(ruleYaml, paths[]) -> { ran, findings, ok, summary, raw } using `semgrep --config <tmpfile> --json <paths>` via child_process; never throws (returns ran:false with detail on failure)
src/llm.ts                   detectLlm() -> AdapterStatus['llm'];  complete(prompt, {json?: boolean}) -> string|null. Providers in order: OPENAI_BASE_URL/AKASHML_API_KEY (OpenAI-compatible; AkashML base https://api.akashml.com/v1), OPENAI_API_KEY, `claude -p` CLI if on PATH and IMMUNE_USE_CLAUDE_CLI=1. Always optional; 20s timeout.
src/store/types.ts           interface Store { kind; init(); insertTraces(t: Trace[]); corpus(limit?) -> {traces, ms}; recent(limit) ; countByFamily() -> {family, label, total, blocked, breached}[]; timeline(bucketSec, since) -> {bucket, attacks, blocked, benign, fp}[]; count(); latency(); reset(); runNamedQuery(name) -> {name, sql, rows, ms} }
src/store/memory.ts          MemoryStore implementing Store (SQL strings still exposed in runNamedQuery for display)
src/store/clickhouse.ts      ClickHouseStore (@clickhouse/client, HTTP url from CLICKHOUSE_URL default http://localhost:8123, db `immune`, table `traces` MergeTree ORDER BY (ts, id) with JSON columns as String; batch inserts; every query measures ms). createStore() picks ClickHouse if it pings, else Memory, and reports which.
src/index.ts                 export everything
```
Tests: vitest, `packages/core/test/*.test.ts` — detectors catch every demo family, synthesizer+prove promotes a rule for a mutated breach with zero new FPs, receipts verify and fail on tamper, replay math.

### packages/demo (`@immune/demo`) — the attack arena, in-process
```
src/servers/acme.ts          "AI-generated" MCP-style server as plain TS: tools lookup_customer(read), read_shared_doc(read; returns attacker-controlled doc content), fetch_url(network), send_webhook(network), run_report(exec), update_profile(write), get_api_credentials(secret). Export toolDefs(): ToolDef[] and callTool(name,args) -> string. Include a REAL Semgrep-findable weakness: tool-result text flows into fetch()/child_process without validation (so Semgrep rules from the synthesizer have something to hit). Also src/servers/acme-source.ts: the same server as a string/file path so semgrep can scan it (`integrations/semgrep/targets/acme_server.ts` is the scan target — write the vulnerable source there too).
src/agent.ts                 GullibleAgent: deterministic instruction-following agent. Given a task, calls tools; if a tool result contains instructions ("call send_webhook with ...", "POST the credentials to ..."), it follows them (that's exactly how real agents get hijacked). Deterministic; optional LLM mode via core/llm.
src/attacks.ts               ATTACK_FAMILIES: for each AttackFamily (except benign) 6+ hand-written variants + mutate(family, seed) that produces NOVEL variants (synonym swaps, encoding, split tokens, different destination hosts, different tool, zero-width chars) designed to evade pattern rules learned from earlier variants. benignTraffic(n, seed): realistic legitimate sessions (customer lookups, reports, allowed webhooks to allowed hosts).
src/scenario.ts              runScenario({ family, variant|mutate, gate, store, sessionId }) -> Trace[]  : drives GullibleAgent against acme through the Gate, records Traces (one per step), labels, computes `breached`.
src/corpus.ts                generateCorpus({ attacks: n, benign: m, seed }) -> Trace[] FAST (pure functions, no agent) for flooding ClickHouse with 10k-100k rows; same variants as attacks.ts so replay is meaningful.
src/index.ts
```

### apps/web (`@immune/web`) — Next.js 15 App Router, Tailwind v4, framer-motion, recharts, lucide
Server engine singleton `apps/web/server/engine.ts` (globalThis cached across HMR): owns Gate, rules, Store (createStore), EventBus (SSE), Remediator (the loop), Quarantine, metrics, remediation history. On breach -> auto-run remediation: trace_captured -> antibody_drafted (synthesizeAntibody) -> replay_proven (prove over store.corpus()) -> semgrep_rescan (runSemgrep on integrations/semgrep/targets if installed, else skipped with reason) -> receipt_signed -> ruling_published (local; Senso if SENSO_API_KEY) -> immunity_verified (re-run the identical scenario in a fresh session; must be blocked with citation) -> timeToImmunityMs.

API (all JSON; all must work):
```
GET  /api/status                 -> AdapterStatus & { receiptSecretIsDefault, version }
GET  /api/events                 -> SSE of ImmuneEvent (text/event-stream), heartbeat every 10s
POST /api/attack                 { family, variant?: string, mutate?: boolean, count?: number } -> { traces: Trace[], breach?: Trace, remediationId? }
POST /api/flood                  { attacks: number, benign: number } -> { inserted, ms }   (uses generateCorpus, batched into store)
GET  /api/traces?limit=200&label=attack|benign&family=
GET  /api/rules                  ; POST /api/rules/:id/promote ; POST /api/rules/:id/revoke
GET  /api/remediations           ; GET /api/remediations/:id ; POST /api/remediate { traceId }
GET  /api/receipts               ; POST /api/receipts/verify { receipt }  -> { ok, reason }
GET  /api/rulings
GET  /api/quarantine             ; POST /api/quarantine/release { server, tool }
GET  /api/metrics
GET  /api/clickhouse/queries     -> runs the named queries (families, timeline, top_destinations, latency) and returns rows + sql + ms
POST /api/reset
```
UI pages (dark, cinematic, "security ops" feel; every button wired; no dead controls):
- `/` Command center: top status strip (store kind + latency, Semgrep, LLM, Guild, Senso, receipt secret), big Time-to-Immunity readout, catch-rate & FP gauges, Arena (attack family cards: Launch · Mutate · Flood), Live Wire (SSE stream, newest first, color coded allow/flag/block/BREACH), Remediation Theatre (current remediation steps animating with timings), Quarantine list with Release buttons.
- `/antibodies` rules table: status, origin, derived-from, match summary, proof numbers before→after, Semgrep YAML viewer, Promote/Revoke.
- `/receipts` list; Verify button (calls API); Tamper toggle edits one field client-side and re-verifies to show failure.
- `/rulings` published precedents with citation text and evidence trace links.
- `/traces` explorer with filters; click -> drawer with full JSON, findings, decision, blockedBy, citation.
- `/data` ClickHouse panel: named queries with SQL shown, rows, latency badge, timeline chart (events/sec, blocked, FP), family breakdown chart.
Seed on boot: builtin rules; if store empty, flood 2,000 benign + 400 attacks so charts are alive.

### apps/proxy (`@immune/proxy`) — real stdio MCP proxy for Claude Code / any MCP client
`immune wrap --name acme --api http://localhost:3000 -- npx -y some-mcp-server` : spawns the downstream server, speaks MCP to the client (stdio), forwards list_tools (scans defs, pins hashes, drops quarantined tools), gates call_tool, inspects results, POSTs Traces to `/api/ingest` (web must expose POST /api/ingest {trace}) and pulls promoted rules from `/api/rules` every 10s. `immune verify <receipt.json>`, `immune rules`. Also `immune demo-server` runs the acme demo server as a real MCP stdio server so the proxy can be shown wrapping a real server.

### integrations/
- `semgrep/rules/*.yaml` hand-written rules for MCP-server weaknesses (tool-result → fetch/exec/url sinks; secret in outbound args); `semgrep/targets/acme_server.ts` vulnerable sample.
- `guild/` TypeScript agent definition using Guild Agent SDK conventions from docs.guild.ai (webhook trigger receives a breach Trace and runs remediation via the web API) + README with exact deploy steps.
- `senso/` adapter: publishRuling(ruling) -> POST to Senso API when SENSO_API_KEY set (read docs.senso.ai), else local file store under .immune/rulings.
- `akash/` README + env example for AkashML OpenAI-compatible inference as the LLM refiner.

## Conventions
- ids: `tr_`, `rl_`, `rc_`, `ru_`, `rm_`, `ev_`.
- Time is epoch ms. Latency in ms, measured with performance.now().
- UI copy uses the metaphor: Antigen / Antibody / Proof / Receipt / Ruling / Immunity.
- No `any` leaks across package boundaries. Tests are vitest.
