import type { Context, Next } from "hono";
import type { ServerTrace, DbQuery, CryptoOp, SessionOp } from "../../shared/api-types.js";

/**
 * Per-request trace collector.
 * Routes call ctx.get("trace") to log DB queries, crypto ops, etc.
 * The middleware appends the collected trace to the JSON response as `_trace`.
 */

export interface TraceCollector {
  addDbQuery(q: DbQuery): void;
  addCryptoOp(op: CryptoOp): void;
  addSessionOp(op: SessionOp): void;
  getTrace(): ServerTrace;
}

function createTraceCollector(): TraceCollector {
  const dbQueries: DbQuery[] = [];
  const cryptoOps: CryptoOp[] = [];
  const sessionOps: SessionOp[] = [];

  return {
    addDbQuery(q) { dbQueries.push(q); },
    addCryptoOp(op) { cryptoOps.push(op); },
    addSessionOp(op) { sessionOps.push(op); },
    getTrace() {
      const trace: ServerTrace = {};
      if (dbQueries.length) trace.dbQueries = dbQueries;
      if (cryptoOps.length) trace.cryptoOps = cryptoOps;
      if (sessionOps.length) trace.sessionOps = sessionOps;
      return trace;
    },
  };
}

declare module "hono" {
  interface ContextVariableMap {
    trace: TraceCollector;
  }
}

export async function traceMiddleware(ctx: Context, next: Next) {
  const collector = createTraceCollector();
  ctx.set("trace", collector);
  await next();

  // Only attach trace to JSON responses
  const contentType = ctx.res.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    const body = await ctx.res.json();
    const trace = collector.getTrace();
    if (Object.keys(trace).length > 0) {
      body._trace = trace;
    }
    ctx.res = new Response(JSON.stringify(body), {
      status: ctx.res.status,
      headers: ctx.res.headers,
    });
  }
}
