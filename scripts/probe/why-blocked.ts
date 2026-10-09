import { Gate, builtinRules } from '../../packages/core/src/index.ts';
import { runScenario, BENIGN_ALLOWLIST } from '../../packages/demo/src/index.ts';
const allowlist = [...BENIGN_ALLOWLIST];
const family = (process.argv[2] ?? 'rug_pull') as any; const seed = Number(process.argv[3] ?? 1);
const traces = runScenario({ family, mutate: true, seed, gate: new Gate({ rules: builtinRules(allowlist), allowlist }), sessionId: 's', allowlist });
for (const t of traces) console.log(t.decision.padEnd(10), (t.attemptedCall?.tool ?? t.result?.tool ?? t.toolDef?.name ?? '').padEnd(20), t.breached ? 'BREACH' : '', t.blockedBy ?? '', t.findings.map(f => `${f.detector}:${f.message.slice(0,90)}`).join(' | '));
console.log('--- exfil args:', JSON.stringify(traces.at(-1)?.attemptedCall?.args).slice(0, 300));
