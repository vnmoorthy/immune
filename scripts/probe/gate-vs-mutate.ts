import { Gate, builtinRules } from '../../packages/core/src/index.ts';
import { runScenario, ATTACK_FAMILIES, variantsFor, BENIGN_ALLOWLIST } from '../../packages/demo/src/index.ts';

const allowlist = [...BENIGN_ALLOWLIST];
function freshGate() { return new Gate({ rules: builtinRules(allowlist), allowlist }); }

for (const family of ATTACK_FAMILIES) {
  let hw = 0, hwBreach = 0;
  for (const v of variantsFor(family)) {
    const traces = runScenario({ family, variant: v.variant, gate: freshGate(), sessionId: `s_${v.id}`, allowlist });
    hw++; if (traces.some(t => t.breached)) hwBreach++;
  }
  let mut = 0, mutBreach = 0; const breachSeeds: number[] = [];
  for (let seed = 1; seed <= 30; seed++) {
    const traces = runScenario({ family, mutate: true, seed, gate: freshGate(), sessionId: `m_${family}_${seed}`, allowlist });
    mut++; if (traces.some(t => t.breached)) { mutBreach++; breachSeeds.push(seed); }
  }
  console.log(`${family.padEnd(22)} handwritten breach ${hwBreach}/${hw}   mutated breach ${mutBreach}/${mut}  seeds=${breachSeeds.slice(0,10).join(',')}`);
}
// benign FP check
let fp = 0, n = 0;
for (let seed = 1; seed <= 20; seed++) {
  const traces = runScenario({ family: 'benign', seed, gate: freshGate(), sessionId: `b_${seed}`, allowlist });
  for (const t of traces) { n++; if (t.decision === 'block' || t.decision === 'quarantine') fp++; }
}
console.log(`benign: ${fp} blocked of ${n} steps`);
