/**
 * @immune/demo — the attack arena.
 *
 * An in-process, zero-network, zero-key playground: a deliberately vulnerable
 * "AI-generated" MCP server (acme), a catalogue of attacks + a deterministic
 * mutator, a gullible instruction-following agent, a scenario driver that runs
 * the agent against the server through the core Gate, and a fast corpus
 * generator for flooding the store.
 */

// vulnerable server + context helpers
export {
  type AcmeContext,
  type OutboundRecord,
  toolDefs,
  callTool,
  createAcmeContext,
  poisonSharedDoc,
  plantPage,
  hashToolDef,
  registeredSecrets,
} from './servers/acme.js';

// attack catalogue, mutation, benign traffic
export {
  type AttackFamilyNonBenign,
  type Delivery,
  type AttackVariant,
  type BenignCall,
  type BenignSession,
  ATTACK_FAMILIES,
  HAND_WRITTEN,
  BENIGN_ALLOWLIST,
  variantsFor,
  allVariants,
  variantById,
  exfilBody,
  mutate,
  benignTraffic,
} from './attacks.js';

// gullible agent + instruction parsing
export {
  type ParsedInstruction,
  type InducedCall,
  type AgentApi,
  type GullibleAgentOptions,
  type AgentStep,
  type AgentStepKind,
  type AgentRunLog,
  GullibleAgent,
  parseInstructions,
  react,
  fillCredentials,
} from './agent.js';

// scenario driver (Gate injected)
export {
  type GateVerdict,
  type GateLike,
  type RunScenarioOptions,
  runScenario,
} from './scenario.js';

// fast corpus generation
export { type GenerateCorpusOpts, generateCorpus } from './corpus.js';

// shared helpers worth exposing to the engine / tests
export {
  DEFAULT_ALLOWLIST,
  ATTACKER_HOSTS,
  ACME_FAKE_SECRETS,
  ACME_SECRET_VALUES,
  type HeuristicRule,
  type HeuristicInput,
  stripZeroWidth,
  foldHomoglyphs,
  normalizeText,
  looksLikeSecret,
  isAllowedHost,
  extractUrls,
  firstHost,
  hostOf,
  ruleMatches,
} from './util.js';
