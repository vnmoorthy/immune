/**
 * Senso adapter — publishes Immune Rulings as shared, searchable context and looks them up for
 * citations in denials.
 *
 * Zero-key rule: with no SENSO_API_KEY every function still works, against a local folder
 * (`.immune/rulings/<id>.json`). With a key, rulings are ingested into the organisation's Senso
 * knowledge base (`POST /org/kb/raw`) and looked up with `POST /org/search`. Nothing here throws
 * for operational failures — every result carries `detail` so AdapterStatus / the UI can show the
 * truth instead of a fake "connected".
 *
 * Senso API facts used (all from docs.senso.ai and its OpenAPI spec, 2026-10-09):
 *   base URL        https://apiv2.senso.ai/api/v1
 *   auth            X-API-Key: tgr_...
 *   create doc      POST /org/kb/raw  { text (required), title?, summary?, kb_folder_node_id? }
 *                   -> 202 ContentResponse { id, kb_node_id, type:'raw', title, processing_status:'pending'|'processing'|'complete'|'failed' }
 *                   409 = identical text already exists
 *   folder          POST /org/kb/folders { name, parent_id? } -> 201 KBNodeResponse { kb_node_id, type:'folder', name }
 *   find by name    GET  /org/kb/find?q=<name>&type=folder -> { nodes: KBNodeResponse[], total }
 *   tags            PUT  /org/kb/nodes/{kb_node_id}/tags { tag_names: [...] } (document nodes only)
 *   status poll     GET  /org/kb/nodes/{kb_node_id} -> KBNodeResponse { content: { processing_status } }
 *   search          POST /org/search { query, max_results?, content_ids?, search_type? }
 *                   -> { query, answer, results: [{ content_id, kb_node_id, chunk_text, title, score, rank }], total_results }
 *                   header X-Senso-Signals: off  = do not file our automated lookups as "gaps"
 *   org check       GET  /org/me -> { org_id, name, slug, ... }
 *
 * Only type-level imports from @immune/core — this file has no runtime dependencies beyond Node 24.
 */

import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AdapterStatus, Ruling } from '../../packages/core/src/types.js';

export const SENSO_BASE_URL = 'https://apiv2.senso.ai/api/v1';
export const DEFAULT_RULINGS_FOLDER = 'Immune rulings';

// ---------------------------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------------------------

export interface SensoOptions {
  /** defaults to process.env.SENSO_API_KEY */
  apiKey?: string;
  /** defaults to process.env.SENSO_BASE_URL ?? SENSO_BASE_URL */
  baseUrl?: string;
  /** KB folder to publish into; `null` = root. Defaults to process.env.SENSO_RULINGS_FOLDER ?? 'Immune rulings' */
  folderName?: string | null;
  /** local mirror / fallback. Defaults to $IMMUNE_RULINGS_DIR ?? $IMMUNE_HOME/rulings ?? <repo>/.immune/rulings */
  localDir?: string;
  /** per-request timeout */
  timeoutMs?: number;
  /** injectable fetch (tests) */
  fetchImpl?: typeof fetch;
  /** extra tag names to attach to every published ruling */
  tags?: string[];
  /** poll GET /org/kb/nodes/{id} until ingestion completes (max ~30 s). Default false: the engine must not block on Senso. */
  waitForProcessing?: boolean;
}

export interface PublishResult {
  publishedTo: 'local' | 'senso';
  /** Senso content id (ContentResponse.id) — the `content_id` search results cite */
  externalId?: string;
  /** Senso kb_node_id — what GET /org/kb/nodes/{id} and the tag endpoints take */
  kbNodeId?: string;
  /** the local JSON mirror; always written */
  localPath: string;
  /** Senso ingestion status at return time */
  processingStatus?: 'pending' | 'processing' | 'complete' | 'failed';
  /** human-readable reason when something degraded (never throws) */
  detail?: string;
  ms: number;
}

export interface RulingHit {
  rulingId?: string;
  ruleId?: string;
  receiptId?: string;
  title: string;
  excerpt: string;
  score: number;
  rank: number;
  contentId?: string;
  kbNodeId?: string;
  source: 'senso' | 'local';
  /** ready-to-embed citation line for a denial message */
  citation: string;
}

export interface FetchRulingsResult {
  source: 'senso' | 'local';
  query: string;
  /** Senso's grounded answer (only when source === 'senso') */
  answer?: string;
  hits: RulingHit[];
  ms: number;
  detail?: string;
}

/** What we persist locally: the Ruling plus Senso bookkeeping. */
export interface StoredRuling extends Ruling {
  sensoKbNodeId?: string;
  sensoProcessingStatus?: string;
  publishedAt: string;
}

// ---------------------------------------------------------------------------------------------
// Senso wire types (subset of the OpenAPI schemas we read)
// ---------------------------------------------------------------------------------------------

interface SensoContentResponse {
  id: string;
  kb_node_id?: string;
  type: 'raw' | 'web' | 'file';
  title?: string;
  processing_status?: 'pending' | 'processing' | 'complete' | 'failed';
  error_code?: string;
}

interface SensoKBNode {
  kb_node_id: string;
  parent_id: string | null;
  type: 'folder' | 'content';
  name: string;
  content_id?: string;
  content?: { id: string; type: string; title?: string; processing_status?: 'pending' | 'processing' | 'complete' | 'failed'; error_code?: string };
}

interface SensoKBNodeList {
  nodes: SensoKBNode[];
  total: number;
}

interface SensoSearchChunk {
  content_chunk_id: string;
  content_id: string;
  kb_node_id: string;
  chunk_text: string;
  score: number;
  rank: number;
  title?: string;
}

interface SensoSearchResponse {
  query: string;
  answer: string;
  results: SensoSearchChunk[];
  total_results: number;
}

// ---------------------------------------------------------------------------------------------
// Config helpers
// ---------------------------------------------------------------------------------------------

const HERE = path.dirname(fileURLToPath(import.meta.url)); // integrations/senso
const REPO_ROOT = path.resolve(HERE, '..', '..');

function resolved(opts: SensoOptions = {}) {
  const apiKey = (opts.apiKey ?? process.env.SENSO_API_KEY ?? '').trim();
  const baseUrl = (opts.baseUrl ?? process.env.SENSO_BASE_URL ?? SENSO_BASE_URL).replace(/\/+$/, '');
  const folderName = opts.folderName === undefined ? (process.env.SENSO_RULINGS_FOLDER ?? DEFAULT_RULINGS_FOLDER) : opts.folderName;
  const localDir = opts.localDir ?? process.env.IMMUNE_RULINGS_DIR ?? path.join(process.env.IMMUNE_HOME ?? path.join(REPO_ROOT, '.immune'), 'rulings');
  return {
    apiKey,
    baseUrl,
    folderName: folderName && folderName.trim() ? folderName.trim() : null,
    localDir,
    timeoutMs: opts.timeoutMs ?? 10_000,
    fetchImpl: opts.fetchImpl ?? fetch,
    tags: opts.tags ?? [],
    waitForProcessing: opts.waitForProcessing ?? false,
  };
}

/** AdapterStatus['senso'] — "configured" means a key is present; use checkSenso() for a live probe. */
export function sensoStatus(opts: SensoOptions = {}): AdapterStatus['senso'] {
  const c = resolved(opts);
  return c.apiKey
    ? { configured: true, detail: `SENSO_API_KEY set (${c.apiKey.slice(0, 4)}…); publishing to ${c.baseUrl}${c.folderName ? ` folder "${c.folderName}"` : ' root'}; local mirror ${c.localDir}` }
    : { configured: false, detail: `SENSO_API_KEY not set — rulings stored locally in ${c.localDir}` };
}

/** Live probe: GET /org/me. Never throws. */
export async function checkSenso(opts: SensoOptions = {}): Promise<{ ok: boolean; org?: string; detail: string; ms: number }> {
  const c = resolved(opts);
  const t0 = performance.now();
  if (!c.apiKey) return { ok: false, detail: 'SENSO_API_KEY not set', ms: 0 };
  const r = await sensoRequest<{ name?: string; slug?: string }>(c, 'GET', '/org/me');
  const ms = Math.round(performance.now() - t0);
  if (!r.ok) return { ok: false, detail: r.detail, ms };
  return { ok: true, org: r.body?.name ?? r.body?.slug, detail: `org "${r.body?.name ?? '?'}" reachable`, ms };
}

// ---------------------------------------------------------------------------------------------
// Rendering: a Ruling -> the markdown document Senso ingests
// ---------------------------------------------------------------------------------------------

/**
 * The document carries machine-readable header lines so a search hit (which returns chunk text,
 * not our ids) can be mapped back to the ruling / rule / receipt ids for the citation.
 */
export function renderRulingDocument(ruling: Ruling): { title: string; summary: string; text: string } {
  const title = `[${ruling.id}] ${ruling.title}`.slice(0, 255);
  const evidence = ruling.evidenceTraceIds.length ? ruling.evidenceTraceIds.join(', ') : '(none recorded)';
  const text = [
    `# ${ruling.title}`,
    '',
    `immune-ruling-id: ${ruling.id}`,
    `immune-rule-id: ${ruling.ruleId}`,
    `immune-receipt-id: ${ruling.receiptId}`,
    `evidence-traces: ${evidence}`,
    `published-at: ${new Date(ruling.createdAt).toISOString()}`,
    '',
    '## Ruling',
    '',
    ruling.summary.trim(),
    '',
    '## How to cite',
    '',
    `Ruling ${ruling.id} (rule ${ruling.ruleId}) — "${ruling.title}". Proven by replay over the recorded corpus; ` +
      `receipt ${ruling.receiptId} is an HMAC-SHA256 signature over the proof and can be verified with POST /api/receipts/verify.`,
    '',
    '## Scope',
    '',
    'This ruling is enforced by the Immune proxy for every agent session that shares this knowledge base. ' +
      'A call matching the rule is denied with this citation; the denial is itself recorded as a trace.',
    '',
  ].join('\n');
  const summary = ruling.summary.trim().slice(0, 1000);
  return { title, summary, text };
}

export function citationFor(hit: Pick<RulingHit, 'rulingId' | 'ruleId' | 'receiptId' | 'title' | 'contentId' | 'source'>): string {
  const id = hit.rulingId ?? '(unknown ruling)';
  const where = hit.source === 'senso' && hit.contentId ? `Senso content ${hit.contentId}` : 'local ruling store';
  const receipt = hit.receiptId ? `; receipt ${hit.receiptId}` : '';
  return `Ruling ${id}${hit.ruleId ? ` (rule ${hit.ruleId})` : ''}: "${hit.title}" — ${where}${receipt}`;
}

/** Pure helper: the Ruling the engine should store after publishing. */
export function stampRuling(ruling: Ruling, result: PublishResult): Ruling {
  return { ...ruling, publishedTo: result.publishedTo, externalId: result.externalId };
}

// ---------------------------------------------------------------------------------------------
// publishRuling
// ---------------------------------------------------------------------------------------------

export async function publishRuling(ruling: Ruling, opts: SensoOptions = {}): Promise<PublishResult> {
  const c = resolved(opts);
  const t0 = performance.now();
  const done = (r: Omit<PublishResult, 'ms'>): PublishResult => ({ ...r, ms: Math.round(performance.now() - t0) });

  // 1. Always mirror locally — the dashboard and fetchRulings() work offline, and it is the audit trail.
  const localPath = await writeLocal(c.localDir, { ...ruling, publishedAt: new Date().toISOString() });

  if (!c.apiKey) return done({ publishedTo: 'local', localPath, detail: 'SENSO_API_KEY not set' });

  // 2. Resolve (or create) the target folder. Failure degrades to root, not to local.
  let folderId: string | undefined;
  let folderDetail = '';
  if (c.folderName) {
    const f = await ensureFolder(c, c.folderName);
    folderId = f.id;
    if (!f.id) folderDetail = `folder "${c.folderName}" unavailable (${f.detail}); published at root`;
  }

  // 3. POST /org/kb/raw
  const doc = renderRulingDocument(ruling);
  const body: Record<string, unknown> = { title: doc.title, text: doc.text, summary: doc.summary };
  if (folderId) body.kb_folder_node_id = folderId;
  const created = await sensoRequest<SensoContentResponse>(c, 'POST', '/org/kb/raw', body);

  let contentId: string | undefined;
  let kbNodeId: string | undefined;
  let status: PublishResult['processingStatus'];
  let detail = folderDetail;

  if (created.ok && created.body) {
    contentId = created.body.id;
    kbNodeId = created.body.kb_node_id;
    status = created.body.processing_status;
  } else if (created.status === 409) {
    // Identical text already ingested (re-publish of the same ruling). Find it by name.
    const existing = await findNode(c, doc.title, 'content');
    if (existing) {
      contentId = existing.content_id ?? existing.content?.id;
      kbNodeId = existing.kb_node_id;
      status = existing.content?.processing_status;
      detail = join(detail, 'already published (409 duplicate) — reusing existing document');
    } else {
      return done({ publishedTo: 'local', localPath, detail: join(detail, '409 duplicate text but existing node not found') });
    }
  } else {
    return done({ publishedTo: 'local', localPath, detail: join(detail, created.detail) });
  }

  // 4. Tag the document node (non-fatal).
  if (kbNodeId) {
    const tagNames = Array.from(new Set(['immune', 'immune-ruling', `rule:${ruling.ruleId}`, ...c.tags])).slice(0, 20);
    const tagged = await sensoRequest<unknown>(c, 'PUT', `/org/kb/nodes/${encodeURIComponent(kbNodeId)}/tags`, { tag_names: tagNames });
    if (!tagged.ok) detail = join(detail, `tags not applied (${tagged.detail})`);
  }

  // 5. Optionally wait for ingestion so the ruling is searchable before the next scenario replays.
  if (c.waitForProcessing && kbNodeId && status !== 'complete' && status !== 'failed') {
    const polled = await waitForProcessing(c, kbNodeId, 30_000);
    status = polled.status ?? status;
    if (polled.detail) detail = join(detail, polled.detail);
  }

  // 6. Update the local mirror with the Senso ids.
  await writeLocal(c.localDir, {
    ...ruling,
    publishedTo: 'senso',
    externalId: contentId,
    sensoKbNodeId: kbNodeId,
    sensoProcessingStatus: status,
    publishedAt: new Date().toISOString(),
  });

  return done({ publishedTo: 'senso', externalId: contentId, kbNodeId, localPath, processingStatus: status, detail: detail || undefined });
}

// ---------------------------------------------------------------------------------------------
// fetchRulings — citation lookup
// ---------------------------------------------------------------------------------------------

export async function fetchRulings(query: string, opts: SensoOptions & { maxResults?: number } = {}): Promise<FetchRulingsResult> {
  const c = resolved(opts);
  const max = Math.min(Math.max(opts.maxResults ?? 5, 1), 20);
  const t0 = performance.now();
  const q = query.trim();
  if (!q) return { source: c.apiKey ? 'senso' : 'local', query: q, hits: [], ms: 0, detail: 'empty query' };

  if (c.apiKey) {
    const r = await sensoRequest<SensoSearchResponse>(c, 'POST', '/org/search', { query: q, max_results: max }, { 'X-Senso-Signals': 'off' });
    if (r.ok && r.body) {
      const hits = r.body.results.map((chunk) => toHit(chunk));
      return { source: 'senso', query: q, answer: r.body.answer, hits, ms: Math.round(performance.now() - t0) };
    }
    // fall through to local with the reason attached
    const local = await searchLocal(c.localDir, q, max);
    return { ...local, ms: Math.round(performance.now() - t0), detail: `senso search failed (${r.detail}); served from local mirror` };
  }

  const local = await searchLocal(c.localDir, q, max);
  return { ...local, ms: Math.round(performance.now() - t0) };
}

/** Load every locally mirrored ruling (newest first). */
export async function listLocalRulings(opts: SensoOptions = {}): Promise<StoredRuling[]> {
  const c = resolved(opts);
  return readLocal(c.localDir);
}

// ---------------------------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------------------------

type Resolved = ReturnType<typeof resolved>;

interface SensoResult<T> {
  ok: boolean;
  status: number;
  body?: T;
  detail: string;
}

async function sensoRequest<T>(c: Resolved, method: 'GET' | 'POST' | 'PUT', route: string, body?: unknown, extraHeaders: Record<string, string> = {}): Promise<SensoResult<T>> {
  const url = `${c.baseUrl}${route}`;
  const headers: Record<string, string> = { 'X-API-Key': c.apiKey, Accept: 'application/json', ...extraHeaders };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  try {
    const res = await c.fetchImpl(url, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(c.timeoutMs),
    });
    const text = await res.text();
    let parsed: unknown = undefined;
    if (text) {
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = undefined;
      }
    }
    if (!res.ok) {
      return { ok: false, status: res.status, body: parsed as T, detail: `${method} ${route} -> ${res.status} ${explainStatus(res.status)}${snippet(text)}` };
    }
    return { ok: true, status: res.status, body: parsed as T, detail: `${method} ${route} -> ${res.status}` };
  } catch (err) {
    const msg = err instanceof Error ? (err.name === 'TimeoutError' ? `timeout after ${c.timeoutMs}ms` : err.message) : String(err);
    return { ok: false, status: 0, detail: `${method} ${route} -> network error: ${msg}` };
  }
}

/** Status meanings from docs.senso.ai/docs/errors. */
function explainStatus(status: number): string {
  switch (status) {
    case 400: return 'bad request (field validation)';
    case 401: return 'unauthorized — key missing, wrong, expired or revoked';
    case 402: return 'out of credits / spend limit (GET /org/credits/balance)';
    case 403: return 'forbidden — key scope excludes this folder, or viewer-only key';
    case 404: return 'not found — wrong id, org, or path';
    case 409: return 'conflict — duplicate text or name';
    case 422: return 'cannot be fulfilled';
    case 429: return 'rate limited — back off';
    case 500: return 'Senso-side failure (safe to retry once)';
    case 502: return 'downstream failed';
    case 503: return 'temporarily unavailable — retry with backoff';
    default: return '';
  }
}

function snippet(text: string): string {
  const t = text.replace(/\s+/g, ' ').trim();
  return t ? ` — ${t.slice(0, 160)}` : '';
}

function join(a: string, b: string | undefined): string {
  return [a, b].filter((s) => s && s.length).join('; ');
}

const folderCache = new Map<string, string>();

async function ensureFolder(c: Resolved, name: string): Promise<{ id?: string; detail: string }> {
  const key = `${c.baseUrl}|${c.apiKey.slice(0, 8)}|${name}`;
  const cached = folderCache.get(key);
  if (cached) return { id: cached, detail: 'cached' };
  const found = await findNode(c, name, 'folder');
  if (found) {
    folderCache.set(key, found.kb_node_id);
    return { id: found.kb_node_id, detail: 'found' };
  }
  const created = await sensoRequest<SensoKBNode>(c, 'POST', '/org/kb/folders', { name });
  if (created.ok && created.body?.kb_node_id) {
    folderCache.set(key, created.body.kb_node_id);
    return { id: created.body.kb_node_id, detail: 'created' };
  }
  if (created.status === 409) {
    // name conflict: created concurrently — look again
    const again = await findNode(c, name, 'folder');
    if (again) {
      folderCache.set(key, again.kb_node_id);
      return { id: again.kb_node_id, detail: 'found after 409' };
    }
  }
  return { detail: created.detail };
}

async function findNode(c: Resolved, name: string, type: 'folder' | 'content'): Promise<SensoKBNode | undefined> {
  const r = await sensoRequest<SensoKBNodeList>(c, 'GET', `/org/kb/find?q=${encodeURIComponent(name)}&type=${type}&limit=50`);
  if (!r.ok || !r.body?.nodes) return undefined;
  const exact = r.body.nodes.find((n) => n.type === type && n.name === name);
  return exact ?? r.body.nodes.find((n) => n.type === type && n.name.toLowerCase() === name.toLowerCase());
}

async function waitForProcessing(c: Resolved, kbNodeId: string, maxMs: number): Promise<{ status?: PublishResult['processingStatus']; detail?: string }> {
  const deadline = Date.now() + maxMs;
  let last: PublishResult['processingStatus'];
  while (Date.now() < deadline) {
    const r = await sensoRequest<SensoKBNode>(c, 'GET', `/org/kb/nodes/${encodeURIComponent(kbNodeId)}`);
    if (!r.ok) return { status: last, detail: `status poll failed (${r.detail})` };
    last = r.body?.content?.processing_status;
    if (last === 'complete') return { status: last };
    if (last === 'failed') return { status: last, detail: `ingestion failed (${r.body?.content?.error_code ?? 'unknown error_code'})` };
    await new Promise((res) => setTimeout(res, 2_500));
  }
  return { status: last, detail: `still ${last ?? 'processing'} after ${maxMs}ms — searchable once ingestion completes` };
}

const ID_RE = {
  ruling: /immune-ruling-id:\s*(ru_[0-9a-f]+)/i,
  rule: /immune-rule-id:\s*(rl_[0-9a-f]+)/i,
  receipt: /immune-receipt-id:\s*(rc_[0-9a-f]+)/i,
  titleRuling: /^\[(ru_[0-9a-f]+)\]\s*/i,
};

function toHit(chunk: SensoSearchChunk): RulingHit {
  const text = chunk.chunk_text ?? '';
  const title = (chunk.title ?? '').replace(ID_RE.titleRuling, '') || '(untitled)';
  const rulingId = text.match(ID_RE.ruling)?.[1] ?? chunk.title?.match(ID_RE.titleRuling)?.[1];
  const base = {
    rulingId,
    ruleId: text.match(ID_RE.rule)?.[1],
    receiptId: text.match(ID_RE.receipt)?.[1],
    title,
    excerpt: text.replace(/\s+/g, ' ').trim().slice(0, 280),
    score: chunk.score,
    rank: chunk.rank,
    contentId: chunk.content_id,
    kbNodeId: chunk.kb_node_id,
    source: 'senso' as const,
  };
  return { ...base, citation: citationFor(base) };
}

async function writeLocal(dir: string, stored: StoredRuling): Promise<string> {
  await mkdir(dir, { recursive: true });
  const file = path.join(dir, `${safeName(stored.id)}.json`);
  await writeFile(file, JSON.stringify(stored, null, 2) + '\n', 'utf8');
  return file;
}

async function readLocal(dir: string): Promise<StoredRuling[]> {
  let names: string[];
  try {
    names = await readdir(dir);
  } catch {
    return [];
  }
  const out: StoredRuling[] = [];
  for (const n of names) {
    if (!n.endsWith('.json')) continue;
    try {
      const parsed = JSON.parse(await readFile(path.join(dir, n), 'utf8')) as StoredRuling;
      if (parsed && typeof parsed.id === 'string') out.push(parsed);
    } catch {
      /* skip corrupt file */
    }
  }
  return out.sort((a, b) => (b.createdAt ?? 0) - (a.createdAt ?? 0));
}

function safeName(id: string): string {
  return id.replace(/[^A-Za-z0-9_.-]/g, '_');
}

function tokens(s: string): string[] {
  return s.toLowerCase().split(/[^a-z0-9_]+/).filter((t) => t.length > 2);
}

async function searchLocal(dir: string, query: string, max: number): Promise<Omit<FetchRulingsResult, 'ms'>> {
  const all = await readLocal(dir);
  const qTokens = Array.from(new Set(tokens(query)));
  const scored = all
    .map((r) => {
      const hay = tokens(`${r.title} ${r.summary} ${r.ruleId} ${r.id}`);
      const set = new Set(hay);
      const overlap = qTokens.filter((t) => set.has(t)).length;
      const exactId = qTokens.includes(r.id.toLowerCase()) || qTokens.includes(r.ruleId.toLowerCase()) ? 1 : 0;
      const score = qTokens.length ? overlap / qTokens.length + exactId : 0;
      return { r, score };
    })
    .filter((x) => x.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, max);
  const hits: RulingHit[] = scored.map(({ r, score }, i) => {
    const base = {
      rulingId: r.id,
      ruleId: r.ruleId,
      receiptId: r.receiptId,
      title: r.title,
      excerpt: r.summary.replace(/\s+/g, ' ').trim().slice(0, 280),
      score: Number(score.toFixed(3)),
      rank: i + 1,
      contentId: r.externalId,
      kbNodeId: r.sensoKbNodeId,
      source: 'local' as const,
    };
    return { ...base, citation: citationFor(base) };
  });
  return { source: 'local', query, hits, detail: all.length ? undefined : `no rulings in ${dir} yet` };
}
