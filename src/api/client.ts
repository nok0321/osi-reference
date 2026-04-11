import { createSignal } from "solid-js";
import type { ServerTrace, DbQuery, CryptoOp, SessionOp } from "../../shared/api-types";

/* ── Captured HTTP Exchange ── */
export interface CapturedExchange {
  id: string;
  timestamp: number;
  request: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: unknown;
  };
  response: {
    status: number;
    statusText: string;
    headers: Record<string, string>;
    body: unknown;
    durationMs: number;
  };
  trace?: ServerTrace;
}

/* ── Global exchange log (reactive) ── */
const [exchanges, setExchanges] = createSignal<CapturedExchange[]>([]);
const [latestExchange, setLatestExchange] = createSignal<CapturedExchange | null>(null);

export { exchanges, latestExchange };

export function clearExchanges() {
  setExchanges([]);
  setLatestExchange(null);
}

/* ── Scoped exchange stores (capped to prevent unbounded memory growth) ── */
const MAX_SCOPED_STORES = 32;
const scopedStores = new Map<string, ReturnType<typeof createSignal<CapturedExchange[]>>>();

export function getScopedExchanges(scopeId: string) {
  if (!scopedStores.has(scopeId)) {
    // Evict oldest entry if at capacity
    if (scopedStores.size >= MAX_SCOPED_STORES) {
      const oldest = scopedStores.keys().next().value!;
      scopedStores.delete(oldest);
    }
    scopedStores.set(scopeId, createSignal<CapturedExchange[]>([]));
  }
  return scopedStores.get(scopeId)![0];
}

export function clearScopedExchanges(scopeId: string) {
  const store = scopedStores.get(scopeId);
  if (store) store[1]([]);
}

let exchangeCounter = 0;

/* ── API fetch wrapper ── */
export async function apiFetch<T = unknown>(
  url: string,
  options: RequestInit = {},
  scopeId?: string,
  signal?: AbortSignal
): Promise<{ data?: T; error?: string; exchange: CapturedExchange }> {
  const startTime = performance.now();
  const id = `ex-${++exchangeCounter}`;

  const reqHeaders: Record<string, string> = {};
  if (options.headers) {
    const h = options.headers as Record<string, string>;
    Object.entries(h).forEach(([k, v]) => { reqHeaders[k] = v; });
  }
  if (options.body && !reqHeaders["Content-Type"]) {
    reqHeaders["Content-Type"] = "application/json";
  }

  let reqBody: unknown = undefined;
  if (options.body && typeof options.body === "string") {
    try { reqBody = JSON.parse(options.body); } catch { reqBody = options.body; }
  }

  const exchange: CapturedExchange = {
    id,
    timestamp: Date.now(),
    request: {
      method: options.method || "GET",
      url,
      headers: reqHeaders,
      body: reqBody,
    },
    response: { status: 0, statusText: "", headers: {}, body: null, durationMs: 0 },
  };

  try {
    const res = await fetch(url, {
      ...options,
      headers: reqHeaders,
      credentials: "include",
      signal,
    });

    const durationMs = performance.now() - startTime;
    const resHeaders: Record<string, string> = {};
    res.headers.forEach((v, k) => { resHeaders[k] = v; });

    let resBody: Record<string, unknown> | null;
    try { resBody = await res.json(); } catch { resBody = null; }

    // Extract _trace from response
    let trace: ServerTrace | undefined;
    if (resBody && "_trace" in resBody) {
      trace = resBody._trace as ServerTrace;
      delete resBody._trace;
    }

    exchange.response = { status: res.status, statusText: res.statusText, headers: resHeaders, body: resBody, durationMs };
    exchange.trace = trace;

    // Update stores
    setExchanges((prev) => [...prev.slice(-49), exchange]);
    setLatestExchange(exchange);
    if (scopeId) {
      const store = scopedStores.get(scopeId);
      if (store) {
        store[1]((prev: CapturedExchange[]) => [...prev.slice(-19), exchange]);
      } else {
        scopedStores.set(scopeId, createSignal<CapturedExchange[]>([exchange]));
      }
    }

    if (resBody && resBody.success === false) {
      return { error: (resBody.error as string) || "Request failed", exchange };
    }
    return { data: (resBody?.data ?? resBody) as T | undefined, exchange };
  } catch (err: unknown) {
    // Silently return for aborted requests
    if (err instanceof DOMException && err.name === "AbortError") {
      exchange.response = { status: 0, statusText: "Aborted", headers: {}, body: null, durationMs: performance.now() - startTime };
      return { error: "aborted", exchange };
    }
    const durationMs = performance.now() - startTime;
    exchange.response = {
      status: 0,
      statusText: "Network Error",
      headers: {},
      body: { error: err instanceof Error ? err.message : "Unknown error" },
      durationMs,
    };
    setExchanges((prev) => [...prev.slice(-49), exchange]);
    setLatestExchange(exchange);
    return { error: err instanceof Error ? err.message : "Unknown error", exchange };
  }
}

/* ── Convenience helpers ── */
export function apiGet<T = unknown>(url: string, scopeId?: string, signal?: AbortSignal) {
  return apiFetch<T>(url, { method: "GET" }, scopeId, signal);
}

export function apiPost<T = unknown>(url: string, body: unknown, scopeId?: string, extraHeaders?: Record<string, string>, signal?: AbortSignal) {
  return apiFetch<T>(url, {
    method: "POST",
    body: JSON.stringify(body),
    headers: { "Content-Type": "application/json", ...extraHeaders },
  }, scopeId, signal);
}

export function apiDelete<T = unknown>(url: string, scopeId?: string, signal?: AbortSignal) {
  return apiFetch<T>(url, { method: "DELETE" }, scopeId, signal);
}

/* ── Re-export trace types for convenience ── */
export type { ServerTrace, DbQuery, CryptoOp, SessionOp };
