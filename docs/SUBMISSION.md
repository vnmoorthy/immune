# Submission — Cyberdefense Hackathon (tokens& × AWS Builder Loft, SF Tech Week, Oct 9 2026)

**Project:** Immune — the agent security loop that turns every attack into an antibody.
**Repo:** https://github.com/vnmoorthy/immune · **Site:** https://vnmoorthy.github.io/immune/ · **Demo video:** https://github.com/vnmoorthy/immune/raw/main/docs/demo/immune-demo.mp4 · **Deck:** https://github.com/vnmoorthy/immune/blob/main/docs/deck/immune.pdf
**Measured on the live run:** builtin gate blocks 36/36 hand-written variants; 180/180 evasive mutations breach a fresh gate; one synthesized antibody raises corpus catch rate 76.7% → 98.1% with 0 → 0 false positives over 32,589 ClickHouse traces; time to verified immunity 4–8 s; after that one antibody, all five other families' evasive variants are blocked citing the same ruling. 186 unit tests + 77 end-to-end checks.
**Tracks:** Threat discovery · Autonomous remediation · Continuous defense (and attack intelligence via the ClickHouse corpus).

## What we built
An MCP firewall (stdio proxy, drop-in for Claude Code or any MCP client) that detects poisoned tool descriptions, result injections, secret exfiltration, rug pulls, homoglyph tools and taint-flow violations with a typed capability gate. Every step is a replayable trace in ClickHouse. When a novel variant gets through, the remediator synthesizes a countermeasure (a gate rule and a Semgrep rule for the MCP server's source), **proves** it by replaying the entire corpus (attacks and benign) — promoted only if catch rate rises and false positives do not — rescans with Semgrep, signs an HMAC receipt (no receipt, no "done"), publishes a ruling to the verified-context layer, and verifies immunity by replaying the identical attack against a fresh session. Headline metric: **Time to Immunity**.

## Sponsor tools used
- **ClickHouse** — trace store and replay corpus; named queries with measured latency drive the proof and the data panel (local server or Cloud).
- **Semgrep** — synthesized antibodies carry a Semgrep rule; the rescan step runs it on the MCP server source; a rule pack for AI-generated MCP servers ships in `integrations/semgrep`.
- **Guild.ai** — the remediator is packaged as a Guild agent with a webhook trigger (`integrations/guild`).
- **Senso.ai** — rulings are published as versioned documents through the official Senso CLI; the precedent base is searched scoped to Immune's own documents and the citation is what the next agent sees in its denial (`integrations/senso/senso-cli.ts`, `/rulings`).
- **AkashML** — optional OpenAI-compatible LLM refiner for antibody generalisation and ruling text; everything it drafts is replay-proven before promotion.

## Semgrep "best vulnerability" entry
The demo MCP server (`integrations/semgrep/targets/acme_server.ts`) is written the way coding agents write MCP servers today: tool-result text flows straight into `fetch()` URLs and `child_process.exec`, and credentials are echoed into outbound bodies. Immune's generated rules and the shipped pack catch these; see `integrations/semgrep/README.md`.

## Team
Moorthy — vnarasingamoorthy@gmail.com
