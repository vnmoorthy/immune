/**
 * Ruling publication + precedent search.
 * Every ruling is written locally (.immune/rulings/<id>.json). When the Senso CLI is installed and logged in
 * (integrations/senso/senso-cli.ts), the ruling is also published to the Senso knowledge base and the
 * node id is kept as `externalId`. Senso is never reported as connected unless the CLI is authenticated.
 */
import fs from 'node:fs/promises';
import path from 'node:path';
import type { ProofReport, Ruling } from '@immune/core';
import {
  askPrecedent as cliAskPrecedent,
  publishRulingToSenso,
  revokeRulingInSenso,
  sensoStatus,
  type PublishableRuling,
  type SensoSearchResult,
} from '../../../integrations/senso/senso-cli';
import { rulingsDir } from './paths';

export interface PublishResult {
  publishedTo: 'local' | 'senso';
  externalId?: string;
  detail: string;
}

export interface SensoAdapterStatus {
  configured: boolean;
  detail: string;
  installed: boolean;
  authenticated: boolean;
  org?: string;
  version?: string;
  /** the one command to run when not authenticated */
  command?: string;
}

function commandFor(detail: string, installed: boolean): string | undefined {
  const m = detail.match(/run:\s*(.+)$/);
  if (m) return m[1]!.trim();
  if (!installed) return 'see integrations/senso/README.md — install the senso CLI, then `senso login`';
  return 'senso login';
}

export async function sensoAdapterStatus(): Promise<SensoAdapterStatus> {
  try {
    const st = await sensoStatus();
    return {
      configured: st.authenticated,
      detail: st.detail,
      installed: st.installed,
      authenticated: st.authenticated,
      org: st.org,
      version: st.version,
      command: st.authenticated ? undefined : commandFor(st.detail, st.installed),
    };
  } catch (err) {
    const detail = `senso status failed: ${(err as Error)?.message ?? String(err)}`;
    return { configured: false, detail, installed: false, authenticated: false, command: commandFor(detail, false) };
  }
}

async function publishLocal(ruling: Ruling): Promise<PublishResult> {
  const dir = rulingsDir();
  await fs.mkdir(dir, { recursive: true });
  const file = path.join(dir, `${ruling.id}.json`);
  await fs.writeFile(file, JSON.stringify(ruling, null, 2), 'utf8');
  return { publishedTo: 'local', detail: `local · ${path.relative(process.cwd(), file)}` };
}

function publishable(ruling: Ruling, ctx?: { family?: string; match?: string; proof?: ProofReport }): PublishableRuling {
  const p = ctx?.proof;
  return {
    id: ruling.id,
    ruleId: ruling.ruleId,
    title: ruling.title,
    summary: ruling.summary,
    evidenceTraceIds: ruling.evidenceTraceIds,
    receiptId: ruling.receiptId,
    createdAt: ruling.createdAt,
    family: ctx?.family,
    match: ctx?.match,
    proof: p
      ? { corpusSize: p.corpusSize, corpusHash: p.corpusHash, catchRateBefore: p.catchRateBefore, catchRateAfter: p.catchRateAfter, fpRateBefore: p.fpRateBefore, fpRateAfter: p.fpRateAfter }
      : undefined,
  };
}

/** Local file always; Senso when the CLI is authenticated. Never throws. */
export async function publishRuling(ruling: Ruling, ctx?: { family?: string; match?: string; proof?: ProofReport }): Promise<PublishResult> {
  const local = await publishLocal(ruling);
  try {
    const res = await publishRulingToSenso(publishable(ruling, ctx));
    if (res.ok) {
      return { publishedTo: 'senso', externalId: res.nodeId ?? res.contentId, detail: `${res.detail} · ${local.detail}` };
    }
    return { ...local, detail: `${local.detail} · senso: ${res.detail}` };
  } catch (err) {
    return { ...local, detail: `${local.detail} · senso failed: ${(err as Error)?.message ?? String(err)}` };
  }
}

export async function revokeRuling(ruling: Ruling): Promise<{ ok: boolean; detail: string }> {
  try {
    const res = await revokeRulingInSenso(publishable(ruling));
    return { ok: res.ok, detail: res.detail };
  } catch (err) {
    return { ok: false, detail: `senso revoke failed: ${(err as Error)?.message ?? String(err)}` };
  }
}

export async function askPrecedent(question: string): Promise<SensoSearchResult> {
  try {
    return await cliAskPrecedent(question, { maxResults: 5 });
  } catch (err) {
    return { ok: false, hits: [], ms: 0, detail: `senso search failed: ${(err as Error)?.message ?? String(err)}` };
  }
}
