# Cyberdefense Hackathon — submission answers (paste-ready)

**Project name**
Immune

**Tagline (one line)**
The agent security loop that turns every attack into an antibody.

**GitHub repository**
https://github.com/vnmoorthy/immune

**Demo video**
https://github.com/vnmoorthy/immune/raw/main/docs/demo/immune-product-video.mp4

**Website (optional)**
https://vnmoorthy.github.io/immune/

**Screenshot (optional)**
https://raw.githubusercontent.com/vnmoorthy/immune/main/docs/screenshots/command-center.png

**Tracks**
Threat discovery · Autonomous remediation · Continuous defense (attack intelligence via the ClickHouse corpus)

**Sponsor tools used (3+)**
ClickHouse, Semgrep, Guild.ai, Senso.ai, AkashML

**Team**
Moorthy — vnarasingamoorthy@gmail.com (solo)

---

**What you built (short, ~60 words)**
Immune is an MCP firewall with a memory. It sits between any agent and its tool servers and catches poisoned tool descriptions, injected results and secret exfiltration. When a novel variant gets through, it synthesizes a countermeasure, proves it by replaying the whole corpus in ClickHouse, rescans with Semgrep, signs a receipt, publishes a ruling, and verifies that the same attack now bounces. Headline metric: Time to Immunity, in seconds.

**What you built (long)**
Agents do what their tool output tells them. A poisoned tool description, a shared doc with a polite "compliance note", a fetched page — and the agent that was looking up a customer is posting your API credentials to a webhook. Detectors alone are a commodity (MCP-Scan, LlamaFirewall): they catch the attacks they already know, and the next variant gets through. When it does, a human reads the trace, writes a rule, hopes it doesn't break legitimate traffic, and ships it days later. Nobody proves the fix.

Immune closes that loop. A stdio MCP proxy (drop-in for Claude Code or any MCP client) runs six detector families and a typed capability gate on every tool definition, result and call, at a measured p50 of 0.06 ms. Every step is a replayable trace in ClickHouse. When something gets through, the remediator (a) captures the exact antigen, (b) synthesizes an antibody — a gate rule plus a Semgrep rule for the MCP server's own source, (c) proves it by replaying the entire corpus of attacks and benign sessions, promoting only if catch rate rises and false positives do not, (d) rescans the source with Semgrep, (e) signs an HMAC-SHA256 receipt — no receipt, no "done", (f) publishes a plain-English ruling to Senso's verified-context layer, and (g) verifies immunity by replaying the identical attack against a fresh session. The denial the next agent sees cites the ruling and the receipt.

Measured on the live run: the builtin gate blocks 36/36 hand-written variants; 180/180 evasive mutations (compliance-phrased instruction, allowlisted destination, credentials transformed into four-character groups) breach a fresh gate; one synthesized antibody raises corpus catch rate from 76.7% to 98.1% with 0 → 0 false positives over 32,589 ClickHouse traces; time to verified immunity is 4–8 seconds; and after that one antibody, every other attack family's evasive variant is blocked citing the same ruling. 186 unit tests and 77 end-to-end checks. Runs end to end with zero API keys.

**How each sponsor tool is used**
- ClickHouse — every trace is a row; the replay corpus is one query; named queries power the data panel (30–60 ms over 32k rows; 10k-row flood in 0.7 s). The proof is literally a ClickHouse replay.
- Semgrep — synthesized antibodies carry a Semgrep rule; the rescan step runs it against the MCP server source; a taint-mode rule pack for AI-generated MCP servers ships in the repo (36 findings, 0 false positives on negative controls).
- Guild.ai — the remediator is packaged as a Guild agent (Agent SDK, typed input/output, API trigger); breaches are dispatched to it when configured.
- Senso.ai — rulings are published as versioned documents through the Senso CLI; the precedent base is searched scoped to Immune's own documents, and the citation is what the next agent sees in its denial.
- AkashML — optional OpenAI-compatible refiner that drafts a more general antibody and the ruling text; everything it drafts is still replay-proven before promotion.

**Semgrep "best vulnerability found" entry**
AI-generated MCP servers routinely pipe tool-result text straight into fetch() URLs and child_process.exec, and echo credentials into outbound request bodies. Immune's synthesized rule and the shipped pack catch exactly this class in the demo server (integrations/semgrep/targets/acme_server.ts: tool-result → fetch, tool-result → exec, secret → outbound body), and the rule is generated from a live breach trace rather than written by hand.

**How to run**
git clone https://github.com/vnmoorthy/immune && cd immune && pnpm install && pnpm demo → http://localhost:3000. No keys required. `pnpm e2e` runs the 77 end-to-end checks.

**What's real vs. configured**
Detection, gate, synthesis, replay proof, receipts, rulings and immunity check are real and tested; ClickHouse and Semgrep are live; Senso and Guild adapters are built against their docs and light up after login; the LLM refiner is optional.

**License**
MIT
