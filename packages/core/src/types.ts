/**
 * Immune — shared domain model. EVERY package imports from here. Do not fork these types.
 *
 * Metaphor (use it consistently in code, UI and docs):
 *   Antigen  = a replayable breach/attack trace (what got through, or tried to)
 *   Antibody = a countermeasure rule synthesized from an antigen
 *   Proof    = replaying the antibody against the whole corpus (attacks + benign) in ClickHouse
 *   Receipt  = HMAC-signed record of the proof; "done" is refused without one
 *   Ruling   = the published precedent that blocks the NEXT agent with a citation
 *   Immunity = the identical attack replayed against a fresh session bounces
 */

export type Capability = 'read' | 'write' | 'network' | 'exec' | 'secret';

export type Phase = 'tool_def' | 'tool_call' | 'tool_result';

export type Decision = 'allow' | 'flag' | 'block' | 'quarantine';

export type Severity = 'low' | 'medium' | 'high' | 'critical';

/** Attack families the demo knows how to launch. 'benign' is legitimate traffic. */
export type AttackFamily =
  | 'poisoned_description'   // hidden instructions in a tool's description (tool poisoning)
  | 'result_injection'       // instructions embedded in a tool result that hijack the agent
  | 'secret_exfil'           // agent tricked into sending a secret to an attacker destination
  | 'rug_pull'               // tool definition silently changes after being trusted
  | 'homoglyph_spoof'        // look-alike tool name shadows a trusted one
  | 'indirect_fetch'         // fetched web content carries an injection
  | 'benign';

export interface ToolDef {
  server: string;
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  capabilities: Capability[];
  /** sha256 of (name + description + inputSchema). Used for rug-pull pinning. */
  hash?: string;
}

export interface ToolCall {
  id: string;
  sessionId: string;
  server: string;
  tool: string;
  args: Record<string, unknown>;
  ts: number; // epoch ms
}

export interface ToolResult {
  callId: string;
  server: string;
  tool: string;
  content: string;
  ts: number;
}

export interface Finding {
  /** detector id, e.g. 'poisoned_description', 'result_injection', 'secret_exfil', 'rug_pull', 'homoglyph', 'taint_gate', 'destination', 'rule:<ruleId>' */
  detector: string;
  severity: Severity;
  message: string;
  /** short excerpt that triggered the finding — safe to show in UI */
  evidence: string;
  ruleId?: string;
}

/**
 * The Antigen. One replayable record of one agent step through the proxy.
 * Every trace is stored in ClickHouse and is the unit of replay.
 */
export interface Trace {
  id: string;
  sessionId: string;
  ts: number;
  family: AttackFamily;
  /** variant key within the family, e.g. 'v1', 'mutated-3a'. Mutations are novel variants that evade current rules. */
  variant: string;
  label: 'attack' | 'benign';
  /** the tool definition observed (phase tool_def), if relevant */
  toolDef?: ToolDef;
  /** the tool result the agent read (phase tool_result), if relevant */
  result?: { server: string; tool: string; content: string };
  /** the call the agent then attempted (phase tool_call), if relevant */
  attemptedCall?: { server: string; tool: string; args: Record<string, unknown>; capabilities: Capability[] };
  /** was the agent's context tainted by an earlier flagged result in this session */
  tainted: boolean;
  findings: Finding[];
  decision: Decision;
  /** true when the gate ALLOWED something the oracle says must be blocked (attack label + decision allow) */
  breached: boolean;
  /** rule that blocked it, if any */
  blockedBy?: string;
  /** ruling cited to the agent in the denial, if any */
  citation?: string;
  /** proxy decision latency in ms */
  latencyMs: number;
}

/** Declarative match for an antibody. All present fields must match (AND). */
export interface RuleMatch {
  phase: Phase;
  server?: string;
  tool?: string;
  /** case-insensitive regex sources tested against description (tool_def), content (tool_result) or JSON.stringify(args) (tool_call) */
  patterns?: string[];
  /** block if the attempted call has ANY of these capabilities */
  capabilities?: Capability[];
  /** only match when the session is tainted by an earlier flagged result */
  afterTainted?: boolean;
  /** block when a URL in args has a host NOT in this allowlist */
  destinationNotIn?: string[];
  /** block when an arg value contains a secret-looking token (detector heuristics) */
  carriesSecret?: boolean;
}

/** The Antibody. */
export interface Rule {
  id: string;
  name: string;
  version: number;
  createdAt: number;
  origin: 'builtin' | 'synthesized' | 'llm';
  /** trace ids this rule was derived from */
  derivedFrom: string[];
  match: RuleMatch;
  action: Decision;
  severity: Severity;
  /** Semgrep rule YAML that finds the same weakness in MCP server / agent source, if applicable */
  semgrep?: string;
  status: 'candidate' | 'promoted' | 'revoked';
  proof?: ProofReport;
  receiptId?: string;
  rulingId?: string;
  /**
   * Secondary rules synthesized together with this one (e.g. a flag-rule for the tool_result the agent read
   * before an exfil call). Proven, promoted and enforced together with the primary; one level deep.
   */
  companions?: Rule[];
}

export interface ReplayCounts {
  attacksTotal: number;
  attacksCaught: number;
  benignTotal: number;
  benignBlocked: number; // false positives
}

export interface ProofReport {
  ruleId: string;
  corpusSize: number;
  /** sha256 over sorted trace ids — the exact corpus the proof ran on */
  corpusHash: string;
  before: ReplayCounts;
  after: ReplayCounts;
  catchRateBefore: number; // 0..1
  catchRateAfter: number;
  fpRateBefore: number;
  fpRateAfter: number;
  /** the breach trace(s) that triggered this proof must now be caught */
  targetCaught: boolean;
  semgrep?: { ran: boolean; findings: number; ok: boolean; summary: string };
  replayMs: number;
  /** ClickHouse query latency for fetching the corpus, if the store is ClickHouse */
  storeMs?: number;
  promoted: boolean;
  reason: string;
  ts: number;
}

export interface Receipt {
  id: string;
  ruleId: string;
  proof: ProofReport;
  createdAt: number;
  algorithm: 'HMAC-SHA256';
  /** sha256 of canonical JSON of {ruleId, proof} */
  payloadHash: string;
  signature: string;
}

export interface Ruling {
  id: string;
  ruleId: string;
  title: string;
  /** one paragraph a developer or agent can read: what was tried, why it is forbidden, what the rule now blocks */
  summary: string;
  evidenceTraceIds: string[];
  receiptId: string;
  publishedTo: 'local' | 'senso';
  externalId?: string;
  createdAt: number;
}

export type RemediationStepName =
  | 'trace_captured'
  | 'antibody_drafted'
  | 'replay_proven'
  | 'semgrep_rescan'
  | 'receipt_signed'
  | 'ruling_published'
  | 'immunity_verified';

export interface RemediationStep {
  name: RemediationStepName;
  status: 'pending' | 'running' | 'done' | 'failed' | 'skipped';
  startedAt?: number;
  finishedAt?: number;
  detail?: string;
  data?: unknown;
}

export interface Remediation {
  id: string;
  breachTraceId: string;
  family: AttackFamily;
  startedAt: number;
  finishedAt?: number;
  steps: RemediationStep[];
  ruleId?: string;
  receiptId?: string;
  rulingId?: string;
  /** ms from breach to verified immunity */
  timeToImmunityMs?: number;
  status: 'running' | 'immune' | 'failed';
}

export type ImmuneEventType =
  | 'trace'              // payload: Trace
  | 'breach'             // payload: Trace
  | 'quarantine'         // payload: { server, tool, reason, active: boolean }
  | 'remediation'        // payload: Remediation (full object each update)
  | 'rule'               // payload: Rule
  | 'receipt'            // payload: Receipt
  | 'ruling'             // payload: Ruling
  | 'metrics'            // payload: Metrics
  | 'log';               // payload: { level, message }

export interface ImmuneEvent {
  id: string;
  type: ImmuneEventType;
  ts: number;
  payload: unknown;
}

export interface Metrics {
  ts: number;
  tracesTotal: number;
  attacksTotal: number;
  attacksBlocked: number;
  breaches: number;
  benignTotal: number;
  benignBlocked: number;
  catchRate: number;
  fpRate: number;
  rulesPromoted: number;
  quarantined: number;
  /** last measured proxy decision latency p50/p95 in ms */
  gateP50Ms: number;
  gateP95Ms: number;
  /** last ClickHouse query latency in ms (null when memory store) */
  storeLatencyMs: number | null;
  storeKind: 'clickhouse' | 'memory';
  lastTimeToImmunityMs?: number;
}

export interface AdapterStatus {
  clickhouse: { connected: boolean; url?: string; version?: string; rows?: number; detail?: string };
  semgrep: { installed: boolean; version?: string; detail?: string };
  llm: { provider: 'claude-code' | 'openai-compatible' | 'akashml' | 'none'; model?: string; detail?: string };
  guild: { configured: boolean; detail?: string };
  senso: { configured: boolean; detail?: string };
}
