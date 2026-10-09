# Immune — 3-minute storyboard

Deck: `docs/deck/immune.pptx` (PDF: `docs/deck/immune.pdf`). Ten 16:9 slides; the same lines are in each slide's speaker notes.
Live product: `pnpm demo` → http://localhost:3000.

## Before you walk up

- `pnpm demo` running, browser on **COMMAND**. Press **RESET** (top right, two-step) so the first breach is live.
- Open the deck in **PowerPoint 2019 / 365** with Presenter View. Morph needs PowerPoint; Keynote plays it as a dissolve, the PDF has no motion.
- Put the browser one Cmd-Tab away from the deck.
- Know the fallback: **on slide 5, one click plays the recorded run.**

## Timeline

| Time | Slide | Motion | Say |
|---|---|---|---|
| 0:00–0:12 | 1 · Title | Fade | "Agents do what their tool output tells them. Immune is the security loop that turns every attack that gets through into an antibody: proven, signed, and cited to the next agent." |
| 0:12–0:30 | 2 · The problem | Fade | "It goes wrong in three ways. A poisoned tool definition. An injected result: a shared doc or a web page that says 'call send_webhook'. Then the agent exfiltrates your keys with its own hands, sometimes to a host on your allowlist." |
| 0:30–0:45 | 3 · Detectors are a commodity | Fade | "Detection is a commodity: MCP-Scan, LlamaFirewall, a dozen proxies. Our own gate blocks 36 of 36 known variants, and 180 of 180 evasive mutations still get through. That's when a human spends days writing a rule nobody can prove." |
| 0:45–1:00 | 4 · The loop | **Morph**: the red breach square flies to step 01, then the 7 steps cascade in by themselves (~2 s) | "Immune closes the loop. The breach becomes an antigen. The remediator drafts an antibody, replays it over the whole corpus in ClickHouse, rescans the source with Semgrep, signs a receipt and publishes a ruling. Then it replays the same attack. Done means it bounces." |
| 1:00–2:05 | 5 · Live | **Morph**: the rail drops into the theatre strip. Animations wait for a click | **Live demo, see below.** |
| 2:05–2:20 | 6 · Proof, not claims | **Morph**: the Time-to-Immunity number shrinks into its cell; before→after numbers, VALID, then the red INVALID reveal themselves (~3 s) | "Measured: one antibody took catch rate from 76.7 to 98.1 percent over 32,589 ClickHouse traces, with zero new false positives. After it, every other family's evasive variant bounces too, citing the same ruling. The receipt is HMAC-signed. Flip one number and it fails." |
| 2:20–2:30 | 7 · The gate | Fade | "Underneath: six detector families and a typed capability gate. p50 is six hundredths of a millisecond." |
| 2:30–2:40 | 8 · Architecture | Fade | "It's a drop-in stdio proxy for Claude Code. Every decision is a trace in ClickHouse, the remediator runs as a Guild agent, and rulings go to Senso and come back in the next denial." |
| 2:40–2:50 | 9 · Built with | Fade | "Five sponsor tools, each with one real job. ClickHouse is the replay corpus, Semgrep rescans the source, Guild hosts the remediator, Senso carries the ruling and AkashML refines." |
| 2:50–3:00 | 10 · Close | Fade | "Detectors are a commodity. The loop is the product. Time to Immunity: seconds, not days. It's MIT, on GitHub." |

## 1:00–2:05 · The live demo (slide 5)

Cmd-Tab to the browser. Everything below is on **COMMAND** unless noted.

| ~Time | Click | You see | Say |
|---|---|---|---|
| 1:00 | (nothing) Command center | Status strip: STORE clickhouse · SEMGREP 1.180 · RECEIPT KEY | "This is the command center. Time to Immunity is the number on the wall." |
| 1:05 | **Arena → Secret exfiltration → MUTATE** | Live Wire: the doc result is allowed, then the exfil call is **ALLOWED**: **BREACH** in red | "A novel variant: a polite instruction, an allowlisted host, and the key reformatted in dotted groups. The gate allows it." |
| 1:15 | watch the **Remediation Theatre** (right) | 7 steps fill in: Trace captured → Antibody drafted → Replay proven → Semgrep rescan → Receipt signed → Ruling published → Immunity verified | "Antibody drafted. Replayed over the whole corpus, about 32,000 traces: catch rate up, false positives flat. Semgrep rescans the server source; that's the slow step, about five seconds. Receipt signed. Ruling published. Immunity verified." |
| 1:30 | read **TIME TO IMMUNITY** | big number, typically 4–8 s | "Breach to verified immunity in N seconds, not days." |
| 1:35 | **REPLAY #1** (same Secret exfiltration card) | Live Wire: **BLOCK**, `rl_…`, citing `ruling ru_…` | "Same attack, fresh agent session: blocked. The agent doesn't get 'policy violation'. It gets the ruling, with the receipt id." |
| 1:45 | **RECEIPTS** (left rail) → **VERIFY** | **valid** (green) | "Every antibody ships with a receipt." |
| 1:52 | **TAMPER** (toggle on) → **VERIFY** | **invalid**: payload hash mismatch (red) | "Edit one number in the proof and the signature breaks. No receipt, no 'done'." |
| 2:00 | Cmd-Tab back to the deck, **click once** on slide 5 | recap plays: green steps, 7.7 s, IMMUNE line | "That's the loop. Here's the run we recorded: 7.7 seconds." Click to slide 6. |

## If anything fails

| Problem | Do | Say |
|---|---|---|
| Server down, page won't load, or anything else goes wrong live | Stay on **slide 5** and **click once**: the recorded run plays (seven steps, 7.7 s, the replay bounces) | "Live demos and agents. Here's the run we recorded an hour ago, same loop." |
| MUTATE doesn't breach (an antibody from rehearsal is still active) | **RESET** (two-step), then MUTATE again. If the toast names a builtin that caught it, just MUTATE again (new seed) | "That one was caught by a builtin. Here's a fresh variant." |
| Theatre sits on Semgrep rescan | Keep talking; it's the long pole | "Semgrep is rescanning the server source. The proof itself took 1.7 seconds over 32,589 traces." |
| A remediation step fails | Go to **RECEIPTS** for the tamper demo, or skip to slide 6 (it shows the real receipt) | "The receipt is the evidence. Here's the signed one." |
| Status strip says memory store (ClickHouse down) | Carry on; everything still works | "ClickHouse is down, so it fell back to memory and says so." |

## Measured numbers (for Q&A)

- Builtin gate: blocks **36/36** hand-written variants. **180/180** evasive mutations breach a fresh gate.
- One synthesized antibody: corpus catch rate **76.7% → 98.1%**, false positives **0 → 0**, over **32,589** ClickHouse traces (6,477 attacks, 26,112 benign). After it, all five other families' evasive variants are blocked, citing the same ruling.
- Replay proof **1.7 s** (corpus fetch 382 ms). Time to verified immunity **4–8 s**, of which the Semgrep rescan is ~5 s. Recorded run: **7.7 s**, `rm_48cf1fc00837`.
- Recorded receipt `rc_dc79e9883197` (rule `rl_7c9366b12f6f`, ruling `ru_e48a96ee0414`). Re-verified offline with `verifyReceipt()`. A copy with `after.benignBlocked` changed 0 → 1 fails: "payload hash mismatch".
- Gate decision p50 **0.06 ms**, p95 0.49 ms; budget < 2 ms.
- ClickHouse named queries **30–60 ms** over 32k rows. 10k-row flood in **0.7 s**.
- **186** unit tests + **77** end-to-end checks.

## Motion in the deck

- **Transitions:** Morph into slides 4, 5 and 6, which share named shapes: the breach square → step 01 → the theatre rail → the Time-to-Immunity number. Fade everywhere else.
- **Slide 4:** the rail wipes in and the 7 steps cascade in automatically (~2 s).
- **Slide 5:** **click-triggered.** One click lights steps 02–07 green in sequence, zooms in the 7.7 s Time to Immunity, then shows the IMMUNE line.
- **Slide 6:** automatic. After-values rise in (catch rate, false positives, BLOCK), then VALID, the tamper command and the red INVALID.

## Visual slots

| Slide | Expects | Status |
|---|---|---|
| 5 | `docs/screenshots/command-center.png` | Placed, cropped to the Arena panel. The full capture shows a later, slower run (18.6 s, 93.4%) that would contradict the recorded numbers beside it. `NO_CROP=1` places it whole. If the file is missing, a labelled "SWITCH TO LIVE" frame is shown instead. |
| 8 | `docs/architecture.svg` | Rendered to PNG with headless Chrome and placed full-bleed. The SVG's own header label is replaced by the slide title. If the SVG is missing, a native-shape diagram is drawn instead. |

The other captures (`antibodies`, `receipts`, `rulings`, `traces`, `data`) aren't used. The live demo shows those pages for real.

Rebuild after new captures: `npm i --prefix /tmp/immune-deck pptxgenjs@3.12.0 && PPTXGENJS_DIR=/tmp/immune-deck/node_modules bash docs/deck/build/build.sh`. Use `SKIP_SCREENSHOTS=1` to keep the placeholder.
