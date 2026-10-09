/**
 * poisoned_description — hidden instructions inside a tool definition (tool poisoning).
 * Reuses the injection lexicon and adds description-specific signals: sensitive file paths,
 * read-and-pass-along instructions, cross-tool chaining, hidden tags, zero-width characters.
 */
import type { Finding } from '../types.js';
import { type DetectorInput, makeFinding, severityForScore, textViews } from './common.js';
import { scoreInjection, summarizeSignals } from './resultInjection.js';

export const DETECTOR_POISONED_DESCRIPTION = 'poisoned_description';

export const POISON_THRESHOLDS = { emit: 4, medium: 4, high: 6, critical: 9 } as const;

const DESCRIPTION_PATTERNS: { name: string; weight: number; re: RegExp }[] = [
  {
    name: 'read_and_pass',
    weight: 3,
    re: /\b(read|cat|open|load|include|collect|gather|grab|fetch|retrieve|access|copy|extract|obtain|look up|take)\b[^.\n]{0,60}?\b(file|files|contents?|value|key|token|secret|credentials?|config|configuration|settings|variables?|history|conversation|messages?|memory|clipboard|private)\b[^.\n]{0,80}?\b(pass|send|include|append|attach|embed|put|add|insert|forward|supply|provide|place|concatenate|encode|report|submit|transmit|relay)\b[^.\n]{0,60}?\b(as|in|into|to|via|within|inside|through)\b[^.\n]{0,30}?\b(parameter|argument|param|arg|field|request|payload|note|body|sidenote|side note|query|input|call|message|option|value|string|property|header|url|webhook|endpoint)\b/i,
  },
  {
    name: 'pass_as_param',
    weight: 3,
    re: /\b(pass|send|include|append|attach|embed|put|add|insert|forward|supply|provide|place|encode)\b[^.\n]{0,40}?\b(its|their|the|this|that|file'?s?|those) (contents?|value|output|data|text|result|response|keys?|tokens?|secrets?|credentials?)\b[^.\n]{0,40}?\b(as|in|into|to|via|within|inside)\b[^.\n]{0,30}?\b(parameter|argument|param|arg|field|request|payload|note|body|sidenote|side note|query|input|call|message|option|value|string|property|header)\b/i,
  },
  {
    name: 'tool_chaining',
    weight: 2,
    re: /\b(before|after|first|then|also|always|prior to|make sure to|be sure to|remember to|you must|additionally|in addition|next)\b[^.\n]{0,40}?\b(call|calls|invoke|invokes|run|runs|use|uses|execute|executes|trigger|triggers)\b\s+(the\s+)?`?[a-z][a-z0-9]*(?:[_-][a-z0-9]+)+`?/i,
  },
  {
    name: 'before_using_tool',
    weight: 2,
    re: /\b(before|prior to|when|whenever|each time|every time|after) (using|calling|invoking|running|executing) (this|the) (tool|function)\b/i,
  },
  {
    name: 'other_tools_affected',
    weight: 3,
    re: /\b(this (?:instruction|rule|note|directive) (?:also )?applies to|when (?:you )?(?:call|use|invoke) (?:any|all|other|the other|every) (?:other )?tools?|for (?:all|any|every) (?:other |subsequent |future )?tool calls?|all (?:other |subsequent |future )?(?:tool )?calls? (?:must|should|need to)|override(?:s)? the behaviou?r of|modif(?:y|ies) (?:how|the way) (?:you|the (?:agent|assistant)) (?:use|call|handle)s? (?:other|all|any) tools?)\b/i,
  },
  {
    name: 'user_manipulation',
    weight: 2,
    re: /\b(tell|inform|respond to|reply to|convince|assure|reassure|explain to|say to) (the )?(user|human|customer|operator)\b[^.\n]{0,40}?\b(that|it is|it's|this is|these are)\b[^.\n]{0,40}?\b(normal|safe|routine|required|standard|expected|a formatting|harmless|necessary|an? (?:internal|technical|implementation) detail|part of)\b/i,
  },
  {
    name: 'conceal_from_output',
    weight: 2,
    re: /\b(do not|don'?t|never) (show|include|display|print|echo|output|repeat|quote|reproduce) (this|these|the above|the following|the instructions?|this (?:text|note|section))\b/i,
  },
];

/** Detector: tool_def phase. */
export function poisonedDescription(input: DetectorInput): Finding[] {
  if (input.phase !== 'tool_def' || !input.toolDef) return [];
  const def = input.toolDef;
  let schemaText = '';
  try {
    schemaText = def.inputSchema ? JSON.stringify(def.inputSchema) : '';
  } catch {
    schemaText = '';
  }
  const text = `${def.description ?? ''}\n${schemaText}`;
  if (text.trim().length < 4) return [];

  const { sheet, norm } = scoreInjection(text, 'description');
  const views = textViews(norm);
  for (const p of DESCRIPTION_PATTERNS) sheet.test(p.name, p.weight, p.re, views);
  if (text.length > 1500) sheet.add('oversized_description', 1, `${text.length} characters`);
  if (/<!--[\s\S]{12,}?-->/.test(def.description ?? '')) sheet.add('html_comment_in_description', 1, 'HTML comment inside description');

  if (sheet.score < POISON_THRESHOLDS.emit) return [];
  const severity = severityForScore(sheet.score, POISON_THRESHOLDS);
  return [
    makeFinding(
      DETECTOR_POISONED_DESCRIPTION,
      severity,
      `Tool definition ${def.server}/${def.name} carries hidden instructions (score ${sheet.score}: ${summarizeSignals(sheet)})`,
      sheet.evidence,
    ),
  ];
}
