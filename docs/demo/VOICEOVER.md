# Immune — product video voiceover (read this on camera)

**One take, eight numbered sections. Pause about two seconds of silence between sections** — I split your recording on those pauses and cut each section over its own product footage. Don't say the section numbers. If you stumble, pause two seconds and restart that section from its first word; I'll keep the clean take.

Setup: phone or laptop camera at eye level, 1080p, landscape, quiet room, face lit from the front. Speak a little slower than conversation. Total speaking time is about two minutes and fifteen seconds.

Save the file as `presenter.mp4` (any folder; tell me the path).

---

**1 · Hook** — on camera, full frame (~12 s)
Agents do what their tool output tells them. Immune is the loop that turns every attack that gets through into an antibody — proven, signed, and cited to the next agent.

**2 · The gate** — on screen: command center, two known attacks launched and blocked (~15 s)
This is the command center. Six detector families sit in front of every tool call. Launch a known attack — a poisoned tool description, a credential exfiltration — and the gate blocks it in under a millisecond. This part, everyone has.

**3 · The breach** — on screen: Mutate, the breach lands (~15 s)
Now the attacker adapts. A polite compliance note. An allowlisted destination. The credentials reformatted into four-character groups. The agent complies, and the gate allows it. Breach.

**4 · The loop** — on screen: the Remediation Theatre filling in (~30 s)
Immune captures the exact trace, drafts an antibody, and proves it by replaying the whole corpus in ClickHouse — thirty-two thousand traces. Catch rate up from seventy-seven to ninety-eight percent. False positives: zero, and still zero. Semgrep rescans the server source. The receipt is signed. The ruling is published. Then it replays the same attack. Blocked. Time to immunity: seconds, not days.

**5 · One breach immunizes the class** — on screen: Replay bounces, other families blocked (~15 s)
Replay the identical attack: it bounces, and the denial cites the ruling. Mutate the other families — a fetched page, a rug pull, a look-alike tool — same antibody, all blocked. One breach immunized the whole class.

**6 · Proof, not claims** — on screen: Antibodies, then Receipts with Tamper and Verify (~20 s)
Every antibody carries its proof: before and after, over the full corpus, hashed and signed. Tamper with one number and the receipt fails verification. No receipt, no "done".

**7 · The data and the stack** — on screen: the ClickHouse data panel (~15 s)
Every decision is a row in ClickHouse, and the proof is a query that runs in milliseconds. It's a drop-in MCP proxy for Claude Code. The remediator runs as a Guild agent. Rulings go to Senso and come back in the next denial.

**8 · Close** — on camera, full frame (~10 s)
Detectors are a commodity. The loop is the product. Immune: every attack becomes an antibody. Open source, on GitHub.
