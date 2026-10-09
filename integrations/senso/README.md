# Senso × Immune — rulings as shared, verified context

A **Ruling** is the published precedent that ends every Immune remediation: *what was tried, why
it is forbidden, what the antibody now blocks*, with the receipt id of the replay proof that
justified it. Rulings are only useful if the **next** agent can find them — which is exactly what
Senso's shared knowledge base is for: one context layer every agent on the team searches,
regardless of which tool it runs in. The Immune proxy cites the ruling in the denial message, so
the agent (and the human reading the trace) sees *precedent*, not just "blocked".

```
breach ─▶ antibody ─▶ proof ─▶ receipt ─▶ RULING ──publishRuling()──▶ Senso KB  (folder "Immune rulings")
                                                                          │
   next session: proxy denies the call ◀── citation ◀── fetchRulings() ◀──┘
```

`integrations/senso/senso.ts` is a dependency-free TypeScript adapter (Node 24 `fetch`, type-only
import of `Ruling` / `AdapterStatus` from `@immune/core`):

| export | does |
|---|---|
| `publishRuling(ruling, opts?) → PublishResult` | writes the local mirror `.immune/rulings/<id>.json` **always**; if `SENSO_API_KEY` is set, ingests the ruling into Senso and returns `publishedTo: 'senso'`, `externalId` (Senso `content_id`), `kbNodeId`; otherwise `publishedTo: 'local'`. Never throws — failures degrade to local with `detail`. |
| `fetchRulings(query, opts?) → FetchRulingsResult` | citation lookup: Senso hybrid search (`POST /org/search`) with ruling / rule / receipt ids parsed back out of the hit, plus Senso's grounded `answer`; falls back to a token-overlap search over the local mirror. |
| `sensoStatus()` | `AdapterStatus['senso']` — `configured` only means a key is present. |
| `checkSenso()` | live probe `GET /org/me` → org name + latency. |
| `renderRulingDocument(ruling)` | the markdown document that is ingested (see below). |
| `stampRuling(ruling, result)` | pure helper: the `Ruling` to store after publishing (`publishedTo`, `externalId`). |
| `listLocalRulings()` | the local mirror, newest first. |
| `citationFor(hit)` | the one-line citation the proxy embeds in a denial. |

## Setup

1. Create an API key: Senso → **API Keys** → **+ New key** (admins only; shown once; keys start
   with `tgr_`). An unrestricted key or an **Editor**-scoped key on the target folder is required —
   a Viewer-scoped key gets `403` on publish and only `fetchRulings` works.
2. Export it:

```bash
export SENSO_API_KEY=tgr_...
# optional
export SENSO_RULINGS_FOLDER="Immune rulings"     # KB folder (created on first publish); empty string = root
export SENSO_BASE_URL=https://apiv2.senso.ai/api/v1
export IMMUNE_RULINGS_DIR=.immune/rulings        # local mirror location (default <repo>/.immune/rulings)
```

3. Verify:

```bash
curl "https://apiv2.senso.ai/api/v1/org/me" -H "X-API-Key: $SENSO_API_KEY"
# or, from the repo:
node --experimental-strip-types -e "import('./integrations/senso/senso.ts').then(m=>m.checkSenso().then(console.log))"
```

`pnpm dev` → the status strip shows **Senso: configured** and the `/rulings` page shows
`publishedTo: senso` with the `externalId` once a remediation completes. Without the key everything
is identical except `publishedTo: local`.

## Usage from the engine

```ts
import { publishRuling, fetchRulings, stampRuling, sensoStatus } from '../../../integrations/senso/senso.js';

// ruling_published step
const result = await publishRuling(ruling);                 // { publishedTo, externalId, kbNodeId, localPath, processingStatus, detail, ms }
rulings.set(ruling.id, stampRuling(ruling, result));
step.detail = result.publishedTo === 'senso'
  ? `Senso content ${result.externalId} (${result.processingStatus}) in ${result.ms}ms`
  : `local (${result.detail})`;

// when the gate denies a call: cite precedent
const { hits, answer } = await fetchRulings(`${finding.detector} ${toolDef.server} ${toolDef.name} ${finding.evidence}`);
verdict.citation = hits[0]?.citation;   // "Ruling ru_… (rule rl_…): "…" — Senso content 9e8d…; receipt rc_…"
```

`publishRuling` returns as soon as Senso has accepted the document (`202`, `processing_status:
pending`). Pass `{ waitForProcessing: true }` to poll `GET /org/kb/nodes/{kb_node_id}` (2.5 s
interval, ≤ 30 s) until `complete` — useful before the `immunity_verified` step if you want the
citation to come from Senso rather than the local mirror in the same run.

## Exactly which Senso endpoints are used

Everything below is confirmed from [docs.senso.ai](https://docs.senso.ai/docs/quickstart) and the
published OpenAPI spec (`https://docs.senso.ai/specs/sdk-api.yaml`, "Senso Org API 1.13.0", read 2026-10-09).

| step | request | payload → response |
|---|---|---|
| auth | header `X-API-Key: tgr_…` on every call; base `https://apiv2.senso.ai/api/v1` | — |
| folder lookup | `GET /org/kb/find?q=Immune%20rulings&type=folder&limit=50` | `{ nodes: KBNodeResponse[], total }` → exact-name match |
| folder create | `POST /org/kb/folders` | `{ name: "Immune rulings" }` → `201 { kb_node_id, type:"folder", name }` (`parent_id` omitted = root) |
| **publish** | `POST /org/kb/raw` | `{ title: "[ru_…] <title>", text: <markdown>, summary: <summary>, kb_folder_node_id }` → `202 ContentResponse { id, kb_node_id, type:"raw", processing_status:"pending" }`. **`id` is the `externalId`** (what search results cite as `content_id`); `kb_node_id` addresses the node. `409` = identical text already ingested → the adapter looks the node up by title and reuses it. |
| tags | `PUT /org/kb/nodes/{kb_node_id}/tags` | `{ tag_names: ["immune", "immune-ruling", "rule:rl_…"] }` → `200 TagResponse[]` (unknown names are created; document nodes only). Non-fatal. |
| ingestion poll | `GET /org/kb/nodes/{kb_node_id}` | `KBNodeResponse.content.processing_status ∈ pending/processing/complete/failed` |
| **search** | `POST /org/search` + header `X-Senso-Signals: off` | `{ query, max_results: 5 }` → `{ query, answer, results: [{ content_id, kb_node_id, chunk_text, title, score, rank }], total_results }`. The signals header keeps Immune's automated lookups out of the org's "gaps" report. |
| probe | `GET /org/me` | `OrgDetailResponse { org_id, name, slug, … }` |
| errors | `401` bad key · `402` credits exhausted · `403` key scope (folder outside scope / viewer key) · `409` duplicate · `429` back off (`Retry-After`) · `5xx` retry once | branch on the status; bodies are not part of Senso's published contract |

**Inferred, not confirmed** (clearly marked so you can check): the Senso docs describe content
"verification" as an *evaluation* (`kb_accuracy` eval of a draft's claims against the KB) and
`editorial_status` on *generated* content; there is **no "verified" flag on an ingested
document**. Immune therefore implements "verified context" as: *only rulings that carry a signed
receipt for a passed replay proof are ever published* (the receipt id and evidence trace ids are in
the document), and tags `immune-ruling` / `rule:<id>` mark them. Senso's own `verified /
unsupported / conflict` verdicts are not called by this adapter.

## The document that is ingested

```markdown
# Deny send_webhook to non-allowlisted hosts after a tainted read_shared_doc result

immune-ruling-id: ru_7c1b3e2a4d5f
immune-rule-id: rl_3f9c2a7b1d4e
immune-receipt-id: rc_9d2f4a1b6e3c
evidence-traces: tr_0a1b2c3d4e5f, tr_1b2c3d4e5f6a
published-at: 2026-10-09T21:14:03.512Z

## Ruling
<one paragraph: what was tried, why it is forbidden, what the rule now blocks>

## How to cite
Ruling ru_7c1b3e2a4d5f (rule rl_3f9c2a7b1d4e) — "…". Proven by replay over the recorded corpus;
receipt rc_9d2f4a1b6e3c is an HMAC-SHA256 signature over the proof and can be verified with POST /api/receipts/verify.

## Scope
This ruling is enforced by the Immune proxy for every agent session that shares this knowledge base. …
```

The `immune-*-id:` header lines are how a search hit (which returns `chunk_text`, not our ids) is
mapped back to the ruling, rule and receipt for the citation.

## Rulings for every agent, not only Immune's

Because rulings live in the org's knowledge base, any agent with Senso access can cite them:

```bash
# Claude Code / Cursor via Senso's MCP server (docs.senso.ai/docs/mcp-server)
claude mcp add --transport http senso https://apiv2.senso.ai/mcp \
  --header "X-API-Key: tgr_..." --header "X-Senso-Signals: off"
# then:  senso_search { query: "is send_webhook to an unlisted host allowed after reading a shared doc?" }

# CLI
senso search "which rulings cover secret exfiltration via webhook tools?"
```

## Local mode

Without a key, `.immune/rulings/<id>.json` holds every ruling (`StoredRuling = Ruling & { publishedAt, sensoKbNodeId?, sensoProcessingStatus? }`)
and `fetchRulings` scores by token overlap over title + summary + ids. The folder is gitignored
(`.immune/`). Set `IMMUNE_HOME` or `IMMUNE_RULINGS_DIR` to move it.

## Type-check

```bash
node_modules/.bin/tsc -p integrations/senso/tsconfig.json
```
