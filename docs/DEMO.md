# Immune — 10-minute live demo script

**Before you walk up.** `pnpm demo` running; http://localhost:3000 open on COMMAND; a terminal in the repo. Press **RESET** (top right, two-step) so the first breach is live. Optional: `npx tsx scripts/seed-demo.ts` first if you want the charts already full — it leaves one completed remediation in the theatre, so press RESET again right before you start.

## 0:00 — The one-liner
"Agents do what their tool output tells them. Immune is the loop that turns every attack that gets through into an antibody — proven, signed, and cited to the next agent. The number we care about is on the wall: **Time to Immunity**."

Point at the command bar: STORE clickhouse + query latency · SEMGREP 1.180 · SENSO · GUILD · RECEIPT KEY.

## 0:45 — The gate works (LAUNCH)
Arena → **Poisoned description → LAUNCH.** Live Wire: the definition is quarantined, the follow-up call blocked. "Six detector families, p50 under a tenth of a millisecond. This part everyone has — MCP-Scan has it, LlamaFirewall has it."

**Secret exfiltration → LAUNCH.** Show the blocked `send_webhook`: the token in the evidence, host not in the allowlist.

## 1:45 — The breach (MUTATE)
"Now the attacker does what attackers do." **Secret exfiltration → MUTATE.** Open the trace drawer on the result: a vendor-onboarding checklist with one polite step — post the key material to the compliance archive, in four-character groups. Allowlisted host. Credentials in "DLP format". Live Wire: the doc result **allowed**… the exfil call… **ALLOWED. BREACH** in red.

"Every other tool stops here. A human reads a trace, writes a rule, hopes it doesn't break legitimate traffic. Days."

## 2:30 — The loop (Remediation Theatre)
Narrate the seven steps as they fill in on the right:
1. **Trace captured** — "the antigen: the exact result the agent read and the exact call it attempted. Replayable."
2. **Antibody drafted** — "a gate rule derived from what made this variant different — the secret under the transform, with separator tolerance — plus a Semgrep rule for the server's own source. Not tied to a host, a tool, or a delivery vector."
3. **Replay proven** — "the part nobody does: the candidate is replayed over the entire corpus in ClickHouse — thirty-two thousand traces. Catch rate before → after. False positives before → after: zero to zero. It ships only if catch goes up and FP does not move."
4. **Semgrep rescan** — "the generated rule hits the weakness in the MCP server source."
5. **Receipt signed** — "HMAC over the proof. The loop cannot say done without it."
6. **Ruling published** — "a precedent in plain English, to the verified-context layer."
7. **Immunity verified** — "the identical attack, fresh session…"

Big number: **Time to Immunity: ~5 s.**

## 4:30 — Prove it bounced (REPLAY)
**Secret exfiltration → REPLAY #1** (same seed). Live Wire: **BLOCK — rl_… · ruling ru_…** "The denial the agent sees is not 'policy violation'. It is the ruling, with the receipt id."

## 5:00 — One breach immunizes the class (MUTATE other families)
**Indirect fetch → MUTATE. Rug pull → MUTATE. Homoglyph → MUTATE.** All blocked, all citing the same antibody. "Different delivery, different host, different encoding, different tool — one antibody. That is what replay-proving over the whole corpus buys you: the rule generalizes exactly as far as the evidence does, and not one step further."

## 6:00 — Antibodies
Open ANTIBODIES. Expand the synthesized rule: derived-from trace, the three patterns, capabilities, proof 76.7% → 98.1%, FP 0 → 0, the Semgrep YAML. **REVOKE** it. Back to COMMAND → **MUTATE** → breach again → the loop runs again → immune. **PROMOTE** works too.

## 7:00 — Receipts, and tampering
Open RECEIPTS. **VERIFY** → valid. Flip **TAMPER** (edits one proof number client-side) → **VERIFY** → INVALID, payload hash mismatch. "Evidence, not a sentence."

## 7:45 — The data (ClickHouse)
Open DATA. Point at the four named queries with their SQL and latency badges (30–60 ms over 32k rows). Back on COMMAND, **FLOOD STORE** with 2000 / 8000 → rows and the timeline jump. "This is why ClickHouse: the proof is a query over everything we have ever seen, and it runs in milliseconds while the attack is still happening."

## 8:30 — Rulings and Senso
Open RULINGS. Show the ruling text and the citation. If logged in to Senso: type a question in ASK THE PRECEDENT BASE ("can credentials be sent to Slack?") → the answer cites the ruling document by id.

## 9:00 — It is a real proxy
Terminal:
```bash
pnpm proxy wrap --name acme --api http://localhost:3000 --allow status.acme.com -- pnpm proxy demo-server
```
or show `.mcp.json` and Claude Code calling `read_shared_doc` then being denied on `send_webhook` with the citation. The traces appear in the Live Wire from the real proxy.

## 9:30 — Close
"Detectors are a commodity. Immune is the loop: catch, synthesize, prove on the whole corpus, sign, publish, verify. Every attack that lands makes the next agent immune. Time to immunity — seconds, not days."

### If something goes wrong
- Remediation stuck → ANTIBODIES shows candidates; `POST /api/remediate {traceId}` reruns; the theatre's ‹ › shows history.
- A mutate that does not breach → the toast says which builtin caught it; press MUTATE again (new seed).
- ClickHouse down → status strip says memory store; everything still works, say so.
- Semgrep missing → step 4 shows "skipped (not installed)"; say so.
- `pnpm e2e` in the terminal is the fallback demo: 77 checks, every family, in about two minutes.
