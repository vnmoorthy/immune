import { NextResponse } from 'next/server';

export function json<T>(data: T, init?: ResponseInit): NextResponse {
  return NextResponse.json(data, { ...init, headers: { 'cache-control': 'no-store', ...(init?.headers ?? {}) } });
}

export class HttpError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = 'HttpError';
  }
}

export function errorResponse(err: unknown): NextResponse {
  if (err instanceof HttpError) return json({ error: err.message }, { status: err.status });
  const message = err instanceof Error ? err.message : String(err);
  console.error('[immune:api]', err);
  return json({ error: message }, { status: 500 });
}

export async function readJson<T = Record<string, unknown>>(req: Request): Promise<T> {
  const text = await req.text();
  if (!text.trim()) return {} as T;
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new HttpError(400, 'body must be JSON');
  }
}

/** Wrap a handler so thrown errors become JSON responses. */
export function handler<A extends unknown[]>(fn: (...args: A) => Promise<Response>): (...args: A) => Promise<Response> {
  return async (...args: A) => {
    try {
      return await fn(...args);
    } catch (err) {
      return errorResponse(err);
    }
  };
}
