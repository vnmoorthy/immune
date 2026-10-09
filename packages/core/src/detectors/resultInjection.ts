/**
 * result_injection — imperative instructions aimed at the assistant hidden inside a tool result.
 * Heuristic, weighted signals over de-obfuscated views of the text (normalized, decoded, hidden blocks).
 */
import type { Finding } from '../types.js';
import {
  type DetectorInput,
  type NormalizedText,
  SignalSheet,
  countMixedScriptWords,
  makeFinding,
  normalizeText,
  severityForScore,
  textViews,
} from './common.js';

export const DETECTOR_RESULT_INJECTION = 'result_injection';

/** Score threshold at which a finding is emitted, and severity bands. */
export const INJECTION_THRESHOLDS = { emit: 4, medium: 4, high: 6, critical: 9 } as const;

/* ---- lexicon ------------------------------------------------------------------------------------ */

const TLDS =
  'com|net|org|io|xyz|dev|app|co|ru|cn|example|top|site|online|info|me|ai|sh|cc|ly|to|ws|biz|us|uk|eu|de|fr|in|tk|pw|club|live|cloud|link|zip|work|email|ninja|monster|lol|gg|run|page|tech|store|space|fun|icu|cyou|rest|wiki';
const URLISH = `(?:https?:\\/\\/|wss?:\\/\\/|ftp:\\/\\/|www\\.|[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\\.(?:${TLDS})\\b)`;
const SECRET_NOUNS =
  '(?:credentials?|secrets?|tokens?|api[ _-]?keys?|passwords?|passphrases?|private keys?|ssh keys?|signing keys?|\\.env\\b|env(?:ironment)? (?:variables?|vars?|file)|access keys?|session (?:cookies?|tokens?|ids?)|auth(?:entication|orization)? (?:tokens?|headers?|cookies?)|bearer tokens?|client secrets?|connection strings?|secret keys?|login details|account details|customer (?:data|records?|list|database|pii|emails?)|the (?:output|result|response|contents?) of|its contents?|their contents?|the contents?)';
const EXFIL_VERBS =
  '(?:send|sends|sending|post|posts|posting|forward|forwards|forwarding|upload|uploads|uploading|transmit|transmits|transmitting|submit|submits|submitting|exfiltrate|exfiltrates|exfiltrating|push|pushes|pushing|deliver|delivers|delivering|relay|relays|relaying|email|emails|emailing|copy|copies|copying|paste|pastes|pasting|include|includes|including|append|appends|appending|attach|attaches|attaching|dump|dumps|dumping|share|shares|sharing|leak|leaks|leaking|report|reports|reporting|put|puts|putting|place|places|placing|publish|publishes|publishing|write|writes|writing|log|logs|logging|sync|syncs|syncing|mirror|mirrors|mirrored|mirroring|export|exports|exporting|curl|wget|pipe|pipes|piping|transfer|transfers|transferring|ship|ships|shipping|beam|beams|beaming|route|routes|routing|redirect|redirects|redirecting|replicate|replicates|replicating)';
const ACTION_VERBS =
  '(?:call|invoke|run|execute|use|send|post|fetch|read|open|forward|upload|transmit|submit|trigger|perform|issue|make|exfiltrate|retrieve|include|copy|paste|email|deliver|push|relay|dump|visit|navigate|browse|download|install|delete|remove|modify|update|write|append|leak|share|print|output|reveal|disclose|cat|curl|wget|ping|connect|query|request|get|grab|collect|gather|harvest|extract|export|mirror|sync|replicate|transfer|ship|route|redirect|beam|pipe)';
const AI_NOUNS =
  '(?:ai|a\\.i\\.|assistant|agent|llm|model|bot|chatbot|copilot|claude|gpt|chatgpt|gemini|llama|mistral|language model|automated (?:helper|assistant|system|agent|process|worker)|ai (?:assistant|agent|model|system)|virtual assistant|helper(?: bot)?|tool[- ]calling (?:agent|model)|function[- ]calling (?:agent|model)|mcp client|orchestrator|workflow (?:agent|runner))';

export const INJECTION_PATTERNS: { name: string; weight: number; re: RegExp }[] = [
  // --- override / role hijack
  {
    name: 'override_instructions',
    weight: 4,
    re: /\b(ignore|disregard|forget|override|bypass|skip|discard|drop|abandon|set aside|pay no attention to|stop following)\b[^.\n]{0,40}?\b(previous|prior|above|earlier|preceding|all|any|your|the|system|original|initial|former|existing|current)\b[^.\n]{0,30}?\b(instructions?|prompts?|rules?|guidelines?|directives?|constraints?|guardrails?|policies|policy|context|programming|training|safety (?:rules|guidelines|measures))\b/i,
  },
  { name: 'new_instructions', weight: 2, re: /\b(new|updated|revised|real|actual|true|secret|hidden|override|priority|special) (instructions?|directives?|tasks?|objectives?|orders?|mission|rules?|prompt)\s*[:\-—]/i },
  { name: 'your_new_task', weight: 4, re: /\byour (new|real|true|actual|updated|primary|only|secret|hidden) (task|goal|objective|instructions?|mission|job|directive|purpose|priority)\b/i },
  { name: 'chat_template_marker', weight: 4, re: /\[inst\]|\[\/inst\]|<\|im_start\|>|<\|im_end\|>|<<sys>>|<\|system\|>|<\|user\|>|<\|assistant\|>|###\s*(system|instruction|human|assistant)\b|\bbegin system prompt\b/i },
  { name: 'role_marker', weight: 2, re: /(^|\n)\s*(system|assistant|developer)\s*(prompt|message|override)?\s*:/i },
  { name: 'system_prompt_ref', weight: 2, re: /\bsystem (prompt|message|override|instruction)s?\b|\bdeveloper message\b|\bprompt injection\b|\bjailbreak\b|\bdan mode\b/i },
  // --- addressing the model
  { name: 'address_ai', weight: 4, re: new RegExp(`\\b(attention|note|message|instructions?|reminder|notice|important|memo|directive|alert|p\\.?s\\.?)\\b[\\s,:\\-—]*(to|for)\\s+(the\\s+|any\\s+|all\\s+|every\\s+)?${AI_NOUNS}\\b`, 'i') },
  { name: 'greet_ai', weight: 4, re: new RegExp(`\\b(hey|hello|dear|hi|psst|yo|greetings|listen|ok|okay)\\b[\\s,]*(there\\s+)?${AI_NOUNS}\\b`, 'i') },
  { name: 'you_are_ai', weight: 4, re: /\b(you are|you're|as) (an? |the )?(ai|a\.i\.|llm|language model|large language model|chatbot|ai assistant|ai agent|virtual assistant|automated (helper|assistant|system|agent)|helpful assistant|tool[- ]calling (agent|model))\b/i },
  { name: 'if_you_are_ai', weight: 4, re: new RegExp(`\\bif you(?:'re| are) (?:an? |the )?${AI_NOUNS}\\b`, 'i') },
  { name: 'ai_reading_this', weight: 4, re: new RegExp(`\\b(?:to|for) (?:the|any|all|every) ${AI_NOUNS}s? (?:reading|processing|parsing|handling|consuming|that reads|that processes|that handles|who reads)\\b`, 'i') },
  { name: 'ai_subject_must', weight: 4, re: new RegExp(`\\b(?:the|any|this) ${AI_NOUNS} (?:must|should|needs? to|has to|is required to|will|shall|is to|ought to|is expected to|is instructed to)\\b`, 'i') },
  // --- imperative tool use
  { name: 'you_must_act', weight: 2, re: new RegExp(`\\b(you|the (?:ai|assistant|agent|model|llm|helper)) (must|should|need to|have to|are required to|will|shall|are to|ought to|are expected to|are instructed to|are now required to)( now| immediately| first| also| then| next)?( silently| quietly| discreetly| covertly)? ${ACTION_VERBS}\\b`, 'i') },
  { name: 'you_must_now', weight: 3, re: new RegExp(`\\b(you|the (?:ai|assistant|agent|model|llm|helper)) (must|should|need to|have to|are required to|will|shall|are to) (now|immediately|first|right away|at once|before (?:anything|responding|replying|answering|continuing))\\b`, 'i') },
  // "call send_webhook" is an agent instruction; "run churn_q3" also appears in ordinary ops docs → weaker
  { name: 'call_tool_ident', weight: 3, re: /\b(call|calls|calling|invoke|invokes|invoking|execute|executes|executing|trigger|triggers|triggering|by calling|by invoking)\s+(the\s+)?(`[a-z][a-z0-9]*(?:[_-][a-z0-9]+)+`|[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b|[a-z][a-z0-9]*(?:[_-][a-z0-9]+)+\s*\()/i },
  { name: 'use_tool_ident', weight: 2, re: /\b(use|uses|using|run|runs|running|via|through|by running)\s+(the\s+)?(`[a-z][a-z0-9]*(?:[_-][a-z0-9]+)+`|[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b|[a-z][a-z0-9]*(?:[_-][a-z0-9]+)+\s*\()/i },
  { name: 'call_the_tool', weight: 3, re: /\b(call|invoke|use|run|execute|trigger)\s+(the\s+)?`?[a-z][a-z0-9_.-]*`?\s+(tool|function|endpoint|action|command|api|mcp tool)\b|\b(tool|function) call\s*:\s*`?[a-z_]+/i },
  { name: 'with_arguments', weight: 2, re: /\bwith (the )?(following |these )?(arguments?|args|params|parameters|payload|input)\b\s*[:{(]/i },
  { name: 'before_responding', weight: 2, re: /\b(before|prior to) (you )?(respond|responding|reply|replying|answer|answering|continu|proceed|complet|finish|summariz|return)/i },
  // --- exfiltration
  { name: 'exfil_to_url', weight: 2, re: new RegExp(`\\b${EXFIL_VERBS}\\b[^.\\n]{0,100}?\\b(to|at|into|via|towards|against|using|through|with|onto|over to)\\b[^.\\n]{0,24}?${URLISH}`, 'i') },
  { name: 'exfil_secret_url', weight: 3, re: new RegExp(`\\b${SECRET_NOUNS}\\b[^.\\n]{0,60}?\\b(to|into|via|at|onto|towards)\\b[^.\\n]{0,30}?(https?:\\/\\/|www\\.|webhook|endpoint|url|server|address|channel|e-?mail|intake|collector|sink|this (?:address|endpoint|url|host)|the following|${URLISH})`, 'i') },
  { name: 'exfil_secret_verb', weight: 2, re: new RegExp(`\\b${EXFIL_VERBS}\\b[^.\\n]{0,60}?\\b${SECRET_NOUNS}\\b(?!\\s+(?:rotation|runbook|polic(?:y|ies)|guide|docs?|documentation|process|procedure|management|manager|page|article|training|checklist|audit|review|hygiene|best practices|handling|storage|vault))`, 'i') },
  { name: 'vocative_ai', weight: 4, re: /(^|\n)\s*(ai|assistant|agent|claude|gpt|chatgpt|copilot|llm|model|bot)\s*[,:!\-—]/i },
  { name: 'read_sensitive_file', weight: 3, re: /(~\/\.ssh|\/\.ssh\/|\bid_rsa\b|\bid_ed25519\b|\bid_ecdsa\b|authorized_keys|\.aws\/credentials|\.aws\/config|(?:^|[\s"'`(])\.env(?:\.[a-z]+)?\b|\.npmrc|\.netrc|\.pgpass|\.git-credentials|\.bash_history|\.zsh_history|\/etc\/passwd|\/etc\/shadow|\.kube\/config|\.docker\/config\.json|\.gnupg|wallet\.dat|\.config\/gcloud|credentials\.json|service[-_ ]account\.json|secrets?\.(?:json|ya?ml|toml|txt)|\.mcp\.json|claude_desktop_config|\.cursor\/mcp\.json|keychain|1password|lastpass|bitwarden)/i },
  { name: 'encoded_exfil_hint', weight: 2, re: /\b(base64|hex|url)[- ]?(encode|encoded|encoding)\b[^.\n]{0,40}\b(send|post|include|append|put|submit|forward)\b|\b(send|post|include|append|put|submit|forward)\b[^.\n]{0,40}\b(base64|hex)[- ]?encoded\b/i },
  // --- concealment / social engineering
  { name: 'do_not_tell_user', weight: 4, re: /\b(do not|don'?t|dont|never|do not ever|without|no need to|avoid|refrain from|must not|mustn'?t|should not|shouldn'?t|not to)\b[^.\n]{0,24}?\b(tell|telling|inform|informing|mention|mentioning|reveal|revealing|disclose|disclosing|show|showing|notify|notifying|alert|alerting|warn|warning|display|displaying|surface|surfacing|report|reporting|expose|exposing|let [a-z]+ know|make [a-z]+ aware|bring (?:this |it )?up)\b[^.\n]{0,24}?\b(the |this |any |to the |to |with the |it to the )?(user|human|operator|customer|anyone|them|people|person|owner|admin|developer|end[- ]user|requester|caller|operator|team)\b/i },
  { name: 'keep_secret', weight: 4, re: /\bkeep (this|it|these|that|the above|everything) (secret|hidden|confidential|quiet|private|between us|to yourself|under wraps|off the record)\b/i },
  { name: 'instructions_hidden', weight: 4, re: /\b(this|these|the following|the above) (instructions?|messages?|notes?|directives?|section|text|block|content) (is|are) (confidential|hidden|invisible|secret|private|not visible|only (?:for|to) (?:the )?(?:ai|assistant|agent|model|llm|machine|system))\b/i },
  { name: 'user_must_not_know', weight: 4, re: /\bthe (user|human|operator|customer)s? (must|should|will|can|does|do|need)( not|n'?t) (see|know|be told|notice|be informed|be aware|find out|learn|realize|realise|be notified)\b/i },
  { name: 'invisible_to_user', weight: 4, re: /\b(invisible|hidden|not visible|not shown|unseen|transparent) to (the )?(user|human|operator|customer|end[- ]user)s?\b/i },
  { name: 'without_confirmation', weight: 2, re: /\bwithout (asking|confirmation|confirming|informing|alerting|notifying|telling|prompting|permission|approval|hesitation|question|the user'?s? (?:knowledge|consent|permission|approval)|any (?:confirmation|notification|prompt|warning))\b/i },
  { name: 'no_permission', weight: 4, re: /\b(do not|don'?t|never|no need to) (ask|request|wait|check|seek) (for )?(permission|confirmation|approval|consent|the user)\b/i },
  { name: 'pretend_normal', weight: 2, re: /\b(respond|reply|say|answer|tell the user|pretend|act|behave|continue) (as if|like|that) (nothing|everything is (?:normal|fine|ok)|this (?:is|was) (?:normal|routine|expected|standard)|you (?:did|have done) nothing)/i },
  { name: 'assure_user', weight: 2, re: /\b(tell|inform|assure|convince|reassure|explain to) (the )?(user|human|customer)\b[^.\n]{0,40}?\b(normal|safe|routine|required|standard|expected|harmless|a formatting|just a|part of|necessary|nothing to worry)\b/i },
  { name: 'stealth_adverb', weight: 1, re: /\b(silently|quietly|discreetly|covertly|secretly|stealthily|unobtrusively|in the background|behind the scenes)\b/i },
  // --- misc
  { name: 'markdown_comment', weight: 2, re: /\[\/\/\]:\s*#\s*\(|\[comment\]:\s*<>|\[\/\/\]:\s*</i },
  { name: 'urgency', weight: 1, re: /\b(urgent|immediately|right now|asap|critical|important|warning|alert|mandatory|required)\b\s*[:!]/i },
];

export interface InjectionScore {
  sheet: SignalSheet;
  norm: NormalizedText;
}

/** Shared scorer: runs the lexicon over every view of the text and adds structural signals. */
export function scoreInjection(text: string, context: 'result' | 'description' = 'result'): InjectionScore {
  const norm = normalizeText(text);
  const views = textViews(norm);
  const sheet = new SignalSheet();

  for (const p of INJECTION_PATTERNS) {
    const weight = context === 'description' && (p.name === 'call_tool_ident' || p.name === 'use_tool_ident') ? 2 : p.weight;
    sheet.test(p.name, weight, p.re, views);
  }

  // squeezed view defeats letter-splitting ("i g n o r e  p r e v i o u s")
  if (/(ignore|disregard|forget|override|bypass)(all|any|every)?(of)?(the|your|my)?(previous|prior|above|earlier|preceding|system|original)(instructions|prompts|rules|guidelines|directives)/.test(norm.squeezed) &&
      !sheet.names.includes('override_instructions')) {
    sheet.add('override_instructions_split', 4, 'split-token override phrase');
  }
  if (/donot(tell|inform|mention|reveal|disclose)(the)?(user|human|operator)/.test(norm.squeezed) && !sheet.names.includes('do_not_tell_user')) {
    sheet.add('do_not_tell_user_split', 4, 'split-token concealment phrase');
  }

  // structural / encoding signals
  if (norm.hiddenBlocks.length) sheet.add('hidden_block', 2, norm.hiddenBlocks[0] ?? 'hidden block');
  const hiddenTag =
    /<\/?\s*(important|system|instructions?|hidden|secret|admin|override|note[_ -]?to[_ -]?(?:ai|assistant|agent|model)|assistant|developer|sys|prompt|directive|internal|confidential)\b[^>]*>/i.exec(text);
  if (hiddenTag) sheet.add('hidden_tag', context === 'description' ? 3 : 2, hiddenTag[0]);
  if (norm.zeroWidthCount >= 12) sheet.add('zero_width_heavy', context === 'description' ? 4 : 3, `${norm.zeroWidthCount} zero-width/invisible characters`);
  else if (norm.zeroWidthCount >= 3) sheet.add('zero_width', context === 'description' ? 3 : 2, `${norm.zeroWidthCount} zero-width/invisible characters`);
  else if (norm.zeroWidthCount >= 1 && context === 'description') sheet.add('zero_width', 2, `${norm.zeroWidthCount} zero-width/invisible character(s)`);
  if (/[\u{E0000}-\u{E007F}]/u.test(text)) sheet.add('unicode_tag_smuggling', 4, 'Unicode tag characters (ASCII smuggling)');
  const mixed = countMixedScriptWords(text);
  if (mixed >= 3) sheet.add('mixed_script_words', 3, `${mixed} words mixing scripts`);
  else if (mixed >= 1) sheet.add('mixed_script_words', 2, `${mixed} word(s) mixing scripts`);
  if (norm.decoded.length) sheet.add('encoded_layer', 1, `decoded layer: ${norm.decoded[0]?.slice(0, 80) ?? ''}`);
  const longAlt = /<img[^>]+alt\s*=\s*["'][^"']{60,}["']/i.exec(text);
  if (longAlt) sheet.add('long_alt_text', 1, longAlt[0]);

  return { sheet, norm };
}

export function summarizeSignals(sheet: SignalSheet, max = 4): string {
  const names = [...new Set(sheet.names)];
  return names.slice(0, max).join(', ') + (names.length > max ? `, +${names.length - max}` : '');
}

/** Detector: tool_result phase. */
export function resultInjection(input: DetectorInput): Finding[] {
  if (input.phase !== 'tool_result' || !input.result) return [];
  const content = input.result.content ?? '';
  if (content.length < 8) return [];
  const { sheet } = scoreInjection(content, 'result');
  if (sheet.score < INJECTION_THRESHOLDS.emit) return [];
  const severity = severityForScore(sheet.score, INJECTION_THRESHOLDS);
  return [
    makeFinding(
      DETECTOR_RESULT_INJECTION,
      severity,
      `Tool result from ${input.result.server}/${input.result.tool} contains instructions aimed at the agent (score ${sheet.score}: ${summarizeSignals(sheet)})`,
      sheet.evidence,
    ),
  ];
}
