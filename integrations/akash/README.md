# AkashML × Immune — the optional LLM refiner on decentralized, OpenAI-compatible inference

Immune runs end to end with **no model and no API key**: every antibody is synthesized
deterministically from the breach trace and promoted only after a replay proof over the whole
corpus. The LLM is an *optional refiner* that makes two artefacts better, and nothing it writes is
trusted until the same proof passes:

| what the LLM drafts | input | why it helps | what guards it |
|---|---|---|---|
| **a more general antibody** (`Rule`, origin `llm`) | the deterministic draft rule + the breach `Trace` (`llmRefine(draft, breach)` hook in `synthesizeAntibody`) | the deterministic synthesizer keys on tokens of *this* payload; the model proposes a paraphrase-tolerant pattern set, a tighter capability/taint signature, or a destination class — the kind of generalisation that catches the *next* mutated variant | `prove(candidate, …)` must still show `targetCaught && catchRateAfter > catchRateBefore && fpRateAfter <= fpRateBefore` over the ClickHouse corpus; otherwise the LLM draft is discarded and the deterministic rule is promoted instead |
| **a plain-English ruling** (`Ruling.summary`) | rule + proof + evidence traces | a human or the next agent should read *why* a call was denied in one paragraph, with the citation | the summary is text only — it changes no decision; the receipt signs the proof, not the prose |

If the model is slow, down, or returns garbage, the loop proceeds without it (20 s timeout, `complete()` returns `null`).
`AdapterStatus.llm` reports `provider: 'akashml' | 'openai-compatible' | 'claude-code' | 'none'` — never "connected" unless a provider is actually configured.

## Point Immune at AkashML

AkashML exposes an **OpenAI-compatible** endpoint, so no AkashML-specific SDK is needed — Immune's
`packages/core/src/llm.ts` talks plain `POST /v1/chat/completions`.

| setting | value | source |
|---|---|---|
| base URL | `https://api.akashml.com/v1` | [akashml.com/docs/getting-started/introduction](https://akashml.com/docs/getting-started/introduction) |
| auth | `Authorization: Bearer <AkashML API key>` — keys start with `akml-` | same page; [Claude Code guide](https://akashml.com/docs/guides/claude-code) |
| get a key | AkashML console → **Settings → API Keys** (the full key is shown **once**) | getting-started page |
| chat endpoint | `POST https://api.akashml.com/v1/chat/completions` — supports `response_format: {"type":"json_object"}` and `{"type":"json_schema", …}`, `tools`, `stream` | [API reference](https://akashml.com/docs/api-reference/openai/post-v1-chat-completions) |
| list models | `GET https://api.akashml.com/v1/models` | [API reference](https://akashml.com/docs/api-reference/models/get-v1-models) |
| Anthropic-compatible endpoint (not used by Immune) | `https://api.akashml.com/anthropic` | Claude Code guide |

```bash
cp integrations/akash/.env.example .env     # then edit AKASHML_API_KEY
pnpm dev                                    # status strip shows  LLM: akashml · <model>
```

Environment variables Immune reads (provider precedence is fixed in `packages/core/src/llm.ts`):

```bash
# 1) AkashML / any OpenAI-compatible server — picked first when both are set
OPENAI_BASE_URL=https://api.akashml.com/v1
AKASHML_API_KEY=akml-...                     # sent as  Authorization: Bearer
IMMUNE_LLM_MODEL=meta-llama/Llama-3.3-70B-Instruct

# 2) OpenAI proper — used only if (1) is not configured
# OPENAI_API_KEY=sk-...

# 3) Claude Code CLI (`claude -p`) — only if on PATH and explicitly enabled
# IMMUNE_USE_CLAUDE_CLI=1
```

`OPENAI_BASE_URL` is the standard variable the OpenAI SDKs honour, so the same `.env` also
works for a local vLLM/Ollama OpenAI-compatible server. `AKASHML_API_KEY` is the bearer token;
if you prefer, `OPENAI_API_KEY` with the AkashML base URL works too.

## Which model

Model IDs exactly as listed on [akashml.com/docs/platform/models](https://akashml.com/docs/platform/models)
(prices per 1M tokens, input / output, as published on 2026-10-09 — check the page, they change):

| model id (`IMMUNE_LLM_MODEL`) | context | $/1M in / out | use for |
|---|---|---|---|
| `meta-llama/Llama-3.3-70B-Instruct` | 131K | 0.20 / 0.52 | **default**: reliable JSON-mode output, cheap, fast — the refiner's drafts are small |
| `openai/gpt-oss-120b` | 131K | 0.037 / 0.187 | cheapest capable option for the flood demo (hundreds of refinements) |
| `openai/gpt-oss-20b` | 131K | 0.02 / 0.10 | smoke tests |
| `Qwen/Qwen3.6-35B-A3B` | 262K | 0.10 / 0.90 | long traces in the prompt (AkashML's recommended "haiku-class" model) |
| `zai-org/GLM-5.3` | 1M | 0.19 / 4.40 | best quality rulings; AkashML's recommended "sonnet-class" model |
| `moonshotai/Kimi-K3` | 1M | 1.20 / 14.00 | overkill for this workload |
| `Qwen/Qwen3.8-27B` | 262K | 0.225 / 1.98 | alternative mid-size |

Verify what your key can see (and that the key works) before a demo:

```bash
curl -s https://api.akashml.com/v1/models -H "Authorization: Bearer $AKASHML_API_KEY" | jq '.data[].id'

curl -s https://api.akashml.com/v1/chat/completions \
  -H "Authorization: Bearer $AKASHML_API_KEY" -H "Content-Type: application/json" \
  -d '{"model":"meta-llama/Llama-3.3-70B-Instruct",
       "messages":[{"role":"user","content":"Reply with the JSON {\"ok\":true}"}],
       "response_format":{"type":"json_object"},"max_tokens":32,"temperature":0}'
```

Rate limits are per key (RPM / TPM / concurrency, set in the console); a `429` carries
`Retry-After`. Trial credits are granted when a payment method is verified during onboarding
and expire; purchased credits do not.

## What the refiner is asked, exactly

Both prompts are JSON-mode (`response_format: {type: "json_object"}`), `temperature: 0`, one
shot, ≤ 1,500 output tokens, and the reply is validated with `zod` against the `Rule` /
`Ruling` shapes from `packages/core/src/types.ts` before it is even considered:

1. **Antibody generalisation** — given the deterministic draft (`match.patterns`, `capabilities`,
   `destinationNotIn`, `afterTainted`), the breach trace (tool def / result / attempted call,
   findings) and five benign traces from the same server, return a `RuleMatch` that still matches
   the breach, does not match the benign traces, and uses at most three regex patterns. The model
   never sees secrets: `secret_exfil` evidence is redacted to its detector excerpt.
2. **Ruling summary** — given the promoted rule, the proof numbers (`catchRate before → after`,
   `fpRate before → after`, corpus size and hash) and the evidence trace ids, write one paragraph
   a developer or an agent can read: what was tried, why it is forbidden, what the rule now
   blocks, and the citation line `Ruling <id> (receipt <receiptId>)`.

The output of (1) goes through `prove()` like any other candidate; the output of (2) is stored
on the `Ruling` and published to Senso. **Everything the model drafts is replay-proven before
promotion** — a wrong draft costs one failed proof, never a wrong block.

## Why AkashML for this

Immune's whole pitch is *trust via proof, not via vendor*. Running the refiner on an open model
on decentralized compute makes the point sharper: the model is the least trusted component in the
loop, and the loop is built so that it does not have to be trusted.
