# Guild × Immune — hosting the remediator loop

When the Immune proxy records a **breach** (an attack the gate allowed), something has to run the
seven-step loop — *Antigen → Antibody → Proof → Semgrep rescan → Receipt → Ruling → Immunity
check* — and come back with evidence. `immune-remediator` is that loop as a **Guild agent**: a
deterministic TypeScript agent (no LLM drives it) that takes a breach `Trace`, calls the Immune
web API, and returns the replay-proven `ProofReport`, the receipt id and the ruling id.

```
integrations/guild/
├── immune-remediator/
│   ├── agent.ts                 the agent ("use agent", @guildai/agents-sdk `agent({...})`)
│   ├── package.json             deps: @guildai/agents-sdk ^0.6.0, @guildai-services/guildai~experimental-fetch
│   ├── tsconfig.json            local type-check (maps the SDK to ./shims — see below)
│   ├── shims/                   minimal local stand-ins for the SDK, the fetch tool set and zod
│   ├── local-run.ts             run the SAME run() in-process with Node fetch — no Guild account needed
│   └── trigger.example.json     the API trigger + the exact request the engine sends
├── client.ts                    engine side: guildStatus(), triggerRemediation(trace) → session + agent output
└── README.md
```

## Honest framing first

- **Hosting on Guild requires a Guild account** (`guild auth login` opens app.guild.ai; publishing
  needs an organisation/workspace). None of the Immune demo depends on it.
- **The engine runs the same loop in-process when `GUILD_TRIGGER_URL` is not set.** Every step,
  every artefact (rule, proof, receipt, ruling) and the dashboard are identical. Guild adds a
  *hosted, observable, triggerable* copy of the loop — sessions with logs, progress events, token
  usage, and an API trigger any system can POST a breach to.
- Hosted Guild agents **cannot reach `localhost`** and may import only `@guildai/agents-sdk`,
  `zod` and `@guildai-services/*`; all HTTP goes through the `guildai~experimental-fetch`
  integration. So the Immune web API must be reachable from Guild's runtime: expose it with a
  tunnel (`cloudflared tunnel --url http://localhost:3000`, or `ngrok http 3000`) and give the
  agent that URL (`IMMUNE_API` workspace variable or `immune_api` input).
- `AdapterStatus.guild.configured` is `true` only when both `GUILD_TRIGGER_URL` and
  `GUILD_TRIGGER_KEY` are set — never "connected" by assumption.

## What the agent does (agent.ts)

| | |
|---|---|
| type | Guild **auto-managed state** TypeScript agent (`"use agent"` directive; compiled to a resumable state machine; deterministic, no LLM in the control flow) |
| input (`inputSchema`) | `{ trace?: Trace-as-JSON, traceId?: "tr_…", immune_api?: string, poll_interval_seconds?: number, timeout_seconds?: number }` — `trace.id` or `traceId` is required |
| tools | `experimental_fetch_fetch` (HTTP via Guild), `userInterfaceTools` (progress events), `guildTools` (`task.guild.sleep` between polls) |
| flow | `POST {IMMUNE_API}/api/remediate {traceId, trace}` → `remediationId` → poll `GET /api/remediations/:id` every `poll_interval_seconds` (default 2 s) until `status ∈ immune | failed` (default timeout 180 s), emitting a progress event each time a new loop step completes → `GET /api/rules` to pick up the promoted rule's `ProofReport` |
| output (`outputSchema`) | `{ ok, status: immune|failed|timeout|error, traceId, remediationId, family, ruleId, receiptId, rulingId, timeToImmunityMs, proof: ProofReport, steps: [{name, status, detail, ms}], detail }` |
| env | `IMMUNE_API` workspace variable (default `http://localhost:3000` — only meaningful for `local-run.ts`). `task.env.X` throws when unset, so the agent reads it through `envOr()`. |

The agent file is written against the SDK rules verbatim from the docs: no `Promise.all`, every
`await` sequential, nothing non-serialisable held across an `await`, heavy parsing in synchronous
helpers (`bodyOf`, `proofOf`, `stepsOf`), `task.ui?.notify(progressLogNotifyEvent(...))` for
milestones only.

## Exact `guild` CLI steps

Prerequisite: Node 22+. All commands are from [docs.guild.ai/quickstart](https://docs.guild.ai/quickstart),
[cli/commands/agent](https://docs.guild.ai/cli/commands/agent), [cli/commands/trigger](https://docs.guild.ai/cli/commands/trigger),
[cli/commands/workspace](https://docs.guild.ai/cli/commands/workspace) and [platform/api-triggers](https://docs.guild.ai/platform/api-triggers).

### 1. Install and sign in

```bash
npm install -g @guildai/cli
guild auth login          # browser sign-in at app.guild.ai; also configures npm for Guild's registry
guild auth status         # ✓ Authenticated
guild doctor              # if anything is off
# if your account belongs to an organisation, set the default owner once:
guild config set default_owner <org-name-or-id>
```

### 2. Scaffold the agent and drop in this code

```bash
guild agent init --name immune-remediator --template AUTO_MANAGED_STATE --category development
cd immune-remediator
# replace the starter with this repo's files:
cp /path/to/immune/integrations/guild/immune-remediator/agent.ts ./agent.ts
# keep the generated package.json/tsconfig.json/guild.json (the CLI manages guild.json);
# add the fetch integration to dependencies if the template did not:
#   "@guildai-services/guildai~experimental-fetch": "latest"
git add -A                 # ephemeral test builds include only git-tracked files
```

`guild agent init` creates the agent in your Guild account, initialises a git repo and pulls the
starter files (`agent.ts`, `package.json`, `tsconfig.json`, `guild.json`, `.gitignore`).

### 3. Run it locally (against a reachable Immune API)

```bash
# in another terminal: pnpm dev  (Immune web on :3000) and expose it
cloudflared tunnel --url http://localhost:3000      # prints https://<random>.trycloudflare.com

guild workspace select                                # pick the workspace to test in
guild workspace variable set IMMUNE_API=https://<random>.trycloudflare.com

# interactive session built from your working tree:
guild agent test
# scripted / non-interactive — feed the agent input as JSON:
echo '{"traceId":"tr_0123456789ab","immune_api":"https://<random>.trycloudflare.com"}' | guild agent test --mode json
# or pass a whole breach trace:
curl -s http://localhost:3000/api/traces?limit=1\&label=attack | jq '{trace: .traces[0]}' | guild agent test --mode json
```

### 4. Save, validate and publish

```bash
guild agent save --message "immune-remediator v0.1" --wait --publish
#   --wait blocks until validation (TypeScript build) passes; --publish makes it Internal (installable by your org's workspaces)
guild agent capabilities --mode json       # confirm experimental_fetch_fetch, ui_*, guild_* are resolved
guild agent logs                           # build/validation output if something failed
```

Public Agent Hub listing is a separate, **permanent** step in the web UI (agent settings → Public).

### 5. Install into a workspace and create the trigger

```bash
guild workspace agent add <owner>~immune-remediator
guild trigger create --type api --agent <owner>~immune-remediator --name immune-breach
guild trigger list
guild trigger get <trigger-id>
```

**Trigger API key:** the `<api_key_id>:<api_key_secret>` pair is generated when the API trigger
is created and shown **once** — in the web UI (workspace → *Run* → *Triggers* → *Add Trigger* →
*API*). Key management is web-UI only (no CLI/API). Copy it into the engine's env:

```bash
GUILD_TRIGGER_URL=https://api.guild.ai/v1/workspaces/<owner_name>/<workspace_name>/sessions
GUILD_TRIGGER_KEY=<api_key_id>:<api_key_secret>
IMMUNE_PUBLIC_API=https://<random>.trycloudflare.com     # what the hosted agent will call back
```

`trigger.example.json` holds the exact request/response shapes.

## How the engine hands off a breach (client.ts)

```ts
import { guildStatus, triggerRemediation } from '../../../integrations/guild/client.js';

// AdapterStatus
status.guild = guildStatus();     // { configured: false, detail: 'GUILD_TRIGGER_URL / GUILD_TRIGGER_KEY not set — remediation loop runs in-process' }

// on breach
if (guildStatus().configured) {
  const r = await triggerRemediation(breachTrace);   // POST sessions (Basic auth) → poll GET /v1/sessions/:id → read runtime_done event
  // r.session.sessionUrl is a link to the hosted run; r.output is the agent's Output (proof, receiptId, rulingId)
} else {
  await remediator.run(breachTrace);                 // identical loop, in-process
}
```

What `triggerRemediation` sends — straight from the API-triggers doc:

```http
POST https://api.guild.ai/v1/workspaces/{owner_name}/{workspace_name}/sessions
Authorization: Basic base64(api_key_id:api_key_secret)
Content-Type: application/json

{ "session_type": "api_trigger",
  "agent_input": { "traceId": "tr_…", "trace": { …Trace… }, "immune_api": "https://<tunnel>" } }
```

→ `201 { id, session_type: "api", session_url, root_task: { status: "CREATED" } }`, then
`GET /v1/sessions/{id}` until `root_task.status ∈ DONE | ERROR | INTERRUPTED`, then
`GET /v1/sessions/{id}/events?types=runtime_done&limit=5`.

Even when Guild hosts the loop, the engine still runs it in-process: the hosted session is
additional evidence (and the demo's "autonomous remediation" surface), not a dependency.

## Run the agent without Guild at all

```bash
# --tsconfig is required: tsx only reads the cwd's tsconfig, and the shim `paths` live in the agent's
IMMUNE_API=http://localhost:3000 node_modules/.bin/tsx --tsconfig integrations/guild/immune-remediator/tsconfig.json \
  integrations/guild/immune-remediator/local-run.ts tr_0123456789ab
node_modules/.bin/tsx --tsconfig integrations/guild/immune-remediator/tsconfig.json \
  integrations/guild/immune-remediator/local-run.ts path/to/breach.json http://localhost:3000
```

Verified against a mock of the Immune API (POST /api/remediate → 3 polls → `immune`): the agent returns
`ok: true, status: "immune"` with the proof, `receiptId`, `rulingId`, `timeToImmunityMs` and all seven steps.

`local-run.ts` builds a fake `Task` (Node `fetch` for `experimental_fetch_fetch`, `setTimeout` for
`guild.sleep`, stderr for progress) and calls the very same `run()`.

## Confirmed from docs vs. inferred

| detail | status |
|---|---|
| `"use agent"`, `agent({inputSchema, outputSchema, tools, run})`, `Task` API (`tools`, `env`, `ui.notify`, `console`, `guild`), root `z.object` requirement, import restrictions, no `Promise.all`, serialisation rules | confirmed — docs.guild.ai/guide/coded-agents, /sdk/task-object |
| `ExperimentalFetchTools` import, `experimental_fetch_fetch` params (`url`, `method`, `data`, `headers`, `follow_redirects`, `verify_certificate`, `timeout_seconds`, `max_bytes`), response = `status_code`, `url`, `headers`, body under `json` (application/json) or `text` | confirmed — docs.guild.ai/guide/sdk-introduction (field names `json`/`text` are taken from the prose; the shim mirrors it) |
| `task.guild.sleep` exists ("suspend the agent for N seconds") | confirmed; **the parameter name `{ seconds }` is inferred** |
| `task.env.KEY` throws when unset; workspace variables via `guild workspace variable set` | confirmed |
| CLI: `guild agent init --template AUTO_MANAGED_STATE`, `guild agent test --mode json`, `guild agent save --wait --publish`, `guild workspace agent add`, `guild trigger create --type api --agent …` | confirmed |
| API trigger: `POST /v1/workspaces/{owner}/{workspace}/sessions` with Basic auth, body `{session_type:"api_trigger", agent_input}`, `201` session, poll `root_task.status`, terminal states | confirmed — docs.guild.ai/platform/api-triggers |
| final agent output readable from the `runtime_done` event's `content.text` | the events doc says the agent's *reply* arrives there; for a typed-output agent the JSON is expected in that text — **verify once against a real session** (`client.ts` also accepts `content` as an object) |
| `guild agent test --mode json` reads the agent input from stdin as JSON | inferred from the quickstart's `echo '{"prompt":"Hello!"}' \| guild agent test --mode json` example |
| `@guildai-services/guildai~experimental-fetch` package version | not published in the docs; `latest` — `guild agent init` pins what the registry serves |

## Type-check locally

```bash
node_modules/.bin/tsc -p integrations/guild/immune-remediator/tsconfig.json   # agent + local runner (via shims)
node_modules/.bin/tsc -p integrations/guild/tsconfig.json                      # client.ts
```

The `shims/` directory exists only because this monorepo must not run `pnpm add` and the real
SDK is served from Guild's registry after `guild auth login`; inside Guild the real packages are
resolved and the shims are never bundled.
