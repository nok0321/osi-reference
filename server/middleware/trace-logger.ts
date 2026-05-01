import type { Context, Next } from "hono";
import type { ServerTrace, DbQuery, CryptoOp, SessionOp, AttackStep } from "../../shared/api-types.js";

/**
 * Per-request trace collector.
 * Routes call ctx.get("trace") to log DB queries, crypto ops, etc.
 * The middleware appends the collected trace to the JSON response as `_trace`.
 */

export interface TraceCollector {
  addDbQuery(q: DbQuery): void;
  addCryptoOp(op: CryptoOp): void;
  addSessionOp(op: SessionOp): void;
  /**
   * AttackStep を追加。timestamp が含まれていればそれを尊重し、なければ Date.now() で自動付与する。
   * これにより呼び出し側で timestamp を 1 度だけ計算して `_trace.attackSteps` と `data.steps` の
   * 両方に同一値を共有させることが可能 (ROB-FIND-009 対応)。
   */
  addAttackStep(step: AttackStep | Omit<AttackStep, "timestamp">): void;
  getTrace(): ServerTrace;
}

function createTraceCollector(): TraceCollector {
  const dbQueries: DbQuery[] = [];
  const cryptoOps: CryptoOp[] = [];
  const sessionOps: SessionOp[] = [];
  const attackSteps: AttackStep[] = [];

  return {
    addDbQuery(q) { dbQueries.push(q); },
    addCryptoOp(op) { cryptoOps.push(op); },
    addSessionOp(op) { sessionOps.push(op); },
    addAttackStep(step) {
      const ts = "timestamp" in step && typeof step.timestamp === "number"
        ? step.timestamp
        : Date.now();
      attackSteps.push({ ...step, timestamp: ts });
    },
    getTrace() {
      const trace: ServerTrace = {};
      if (dbQueries.length) trace.dbQueries = dbQueries;
      if (cryptoOps.length) trace.cryptoOps = cryptoOps;
      if (sessionOps.length) trace.sessionOps = sessionOps;
      if (attackSteps.length) trace.attackSteps = attackSteps;
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
    const isAttackPath = ctx.req.path.includes("/attack/");
    const hasAnyOps = Object.keys(trace).length > 0;
    if (hasAnyOps || isAttackPath) {
      if (isAttackPath) trace.isAttackMode = true;
      body._trace = trace;
    }
    ctx.res = new Response(JSON.stringify(body), {
      status: ctx.res.status,
      headers: ctx.res.headers,
    });
  }
}
