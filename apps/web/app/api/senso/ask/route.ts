import { HttpError, handler, json, readJson } from '@/server/http';
import { askPrecedent, sensoAdapterStatus } from '@/server/senso';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

/** Ask the Senso precedent base a question. Returns the answer + sources, or the auth status when not logged in. */
export const POST = handler(async (req: Request) => {
  const body = await readJson<{ question?: string }>(req);
  const question = typeof body.question === 'string' ? body.question.trim() : '';
  if (!question) throw new HttpError(400, 'question is required');
  const status = await sensoAdapterStatus();
  if (!status.authenticated) {
    return json({ ok: false, hits: [], ms: 0, detail: status.detail, authenticated: false, installed: status.installed, command: status.command, question });
  }
  const res = await askPrecedent(question);
  return json({ ...res, authenticated: true, installed: status.installed, org: status.org, question });
});
