# Immune — 3-minute read-aloud (high energy)

One take. Pause two full seconds between sections (I cut on those pauses). Don't read the headers or timings. Smile while you talk; it comes through in the voice. About 440 words, roughly three minutes at an excited pace.

---

**1 · Hook** — on camera (~20 s)
Okay. Here's the thing nobody wants to say out loud. Agents do whatever their tool output tells them to. A poisoned tool description. A shared doc with one sneaky paragraph. A web page with a polite little "compliance note". And boom, the agent that was looking up a customer is now shipping your API keys to a webhook. We built the fix. It's called Immune, and it turns every attack that gets through into an antibody!

**2 · The gate** — on screen (~20 s)
This is the command center. Six detector families sit in front of every single tool call: poisoned descriptions, injected results, secret exfiltration, rug pulls, look-alike tools, and a taint gate. Launch a known attack, and watch it get blocked in a tenth of a millisecond. Thirty-six out of thirty-six known variants, blocked. Now, honestly? Everyone has this part. MCP-Scan has it. LlamaFirewall has it. This is where everyone else stops.

**3 · The breach** — on screen (~20 s)
But attackers adapt! Watch this. One click: Mutate. A polite compliance note. An allowlisted destination, hooks dot slack dot com. The credentials chopped into four-character groups. The agent happily complies, the gate allows it, and there it is: BREACH. One hundred and eighty out of one hundred and eighty of these evasive mutations get through a fresh gate. Every other tool on earth stops right here and pages a human. Days.

**4 · The loop** — on screen, the theatre (~45 s)
Not Immune. Watch the right side of the screen. Step one, the exact trace is captured: the antigen. Step two, an antibody is drafted: a gate rule that matches the transformed secret, plus a Semgrep rule for the server's own source code. Step three, and this is the part nobody else does: that antibody is proven by replaying the ENTIRE corpus in ClickHouse. Thirty-two thousand traces! Catch rate goes from seventy-seven percent to ninety-eight percent, and false positives? Zero. Still zero. Step four, Semgrep rescans the source. Step five, an HMAC receipt is signed: no receipt, no "done". Step six, a plain-English ruling is published to Senso. And step seven, the identical attack is replayed against a fresh session, and it bounces! Look at that number. Time to immunity: seconds. Not days. Seconds!

**5 · One breach, whole class** — on screen (~20 s)
And here's my favorite part. Hit Replay: same attack, fresh agent, blocked, and the denial cites the ruling by name. Now mutate the OTHER families: a fetched web page, a rug pull, a look-alike tool. Same antibody. All blocked. One breach immunized the entire class, with zero false positives. That is what proving against the whole corpus buys you.

**6 · Proof, not claims** — on screen (~25 s)
Every antibody carries its proof: before and after, over the full corpus, hashed and signed. Open Receipts. Verify: valid. Now flip Tamper, change one single number, verify again: invalid. Payload hash mismatch. "Patched" is a sentence an agent can say. A receipt is evidence. No receipt, no "done".

**7 · The stack** — on screen (~20 s)
Every decision is a row in ClickHouse, and the proof is literally a query that runs in milliseconds. It's a drop-in MCP proxy for Claude Code or any agent. The remediator runs as a Guild agent. Rulings live in Senso and come back in the next denial. And the whole thing runs end to end with zero API keys. One hundred eighty-six tests. Seventy-seven end-to-end checks. All green.

**8 · Close** — on camera (~15 s)
Detectors are a commodity. The loop is the product. Catch it, prove it, sign it, publish it, verify it. Every attack that lands makes the next agent immune. This is Immune. It's open source, it's on GitHub right now, and we built it today. Thank you!
