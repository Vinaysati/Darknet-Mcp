import { AsyncLocalStorage } from "node:async_hooks";

const requestSignals = new AsyncLocalStorage<AbortSignal>();
export function getRequestSignal(): AbortSignal | undefined { return requestSignals.getStore(); }
export function withRequestSignal<T>(signal: AbortSignal, operation: () => Promise<T>): Promise<T> { return requestSignals.run(signal, operation); }

export interface HttpOptions {
  timeoutMs?: number; maxBodyBytes?: number; retries?: number; retryDelayMs?: number;
  beforeRetry?: (signal: AbortSignal) => Promise<void>;
}
function abortError(signal: AbortSignal): Error { return signal.reason instanceof Error ? signal.reason : new Error("Request cancelled"); }

async function pause(ms: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) throw abortError(signal);
  await new Promise<void>((resolve, reject) => {
    const finish = () => { signal.removeEventListener("abort", cancel); resolve(); };
    const timer = setTimeout(finish, ms);
    const cancel = () => { clearTimeout(timer); signal.removeEventListener("abort", cancel); reject(abortError(signal)); };
    signal.addEventListener("abort", cancel, { once: true });
  });
}

async function boundedBody(response: Response, maxBytes: number): Promise<Uint8Array | null> {
  if (!response.body) return null;
  if (Number(response.headers.get("content-length")) > maxBytes) {
    await response.body.cancel();
    throw new Error("Upstream response exceeded the configured size limit");
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) { await reader.cancel(); throw new Error("Upstream response exceeded the configured size limit"); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const body = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.byteLength; }
  return body;
}

/** Bounded read-only HTTP requests. GET/HEAD respect Retry-After; POST is not replayed. */
export async function apiFetch(input: string | URL, init: RequestInit = {}, options: HttpOptions = {}): Promise<Response> {
  const timeoutMs = options.timeoutMs ?? 15_000;
  const deadline = new AbortController();
  const timer = setTimeout(() => deadline.abort(new Error("Upstream request deadline exceeded")), timeoutMs);
  const signals = [deadline.signal, init.signal, getRequestSignal()].filter((s): s is AbortSignal => Boolean(s));
  const signal = AbortSignal.any(signals);
  const method = (init.method ?? "GET").toUpperCase();
  const retries = method === "GET" || method === "HEAD" ? options.retries ?? 2 : 0;
  const endAt = Date.now() + timeoutMs;
  try {
    for (let attempt = 0; ; attempt++) {
      if (signal.aborted) throw abortError(signal);
      let response: Response;
      // Provider endpoints are fixed. Refuse redirects so custom API-key headers cannot cross origins.
      try { response = await fetch(input, { ...init, signal, redirect: "error" }); }
      catch (error) {
        if (signal.aborted) throw abortError(signal);
        if (attempt >= retries) throw error;
        await pause((options.retryDelayMs ?? 250) * 2 ** attempt, signal);
        await options.beforeRetry?.(signal);
        continue;
      }
      if ([429, 502, 503, 504].includes(response.status) && attempt < retries) {
        const retryAfter = response.headers.get("retry-after");
        const seconds = retryAfter === null ? NaN : Number(retryAfter);
        const when = retryAfter === null || Number.isFinite(seconds) ? NaN : Date.parse(retryAfter);
        const wait = Number.isFinite(seconds) && seconds >= 0 ? seconds * 1000 : Number.isFinite(when) ? Math.max(0, when - Date.now()) : (options.retryDelayMs ?? 250) * 2 ** attempt;
        if (Date.now() + wait < endAt) { await response.body?.cancel(); await pause(wait, signal); await options.beforeRetry?.(signal); continue; }
      }
      const body = await boundedBody(response, options.maxBodyBytes ?? 10 * 1024 * 1024);
      const headers = new Headers(response.headers);
      headers.delete("content-encoding"); headers.delete("content-length");
      return new Response(body === null ? null : body.buffer as ArrayBuffer, { status: response.status, statusText: response.statusText, headers });
    }
  } finally { clearTimeout(timer); }
}
