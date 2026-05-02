/**
 * Orchestrator route: POST /api/orchestrator/exec
 *
 * 【教育目的専用】
 * このファイルは OSI 参照アプリの教材機能として、
 * ブラウザの RawHttpComposer が組み立てた raw HTTP リクエストを
 * VICTIM_ALLOWLIST で限定された victim コンテナへ中継するプロキシです。
 *
 * - ブラウザは target キー文字列のみ送信可能 (URL 偽造防止)
 * - baseUrl は orchestrator が allowlist から取得 (環境変数による上書き禁止)
 * - Host ヘッダは強制上書き (DNS rebinding 予防)
 * - raw bytes は browser⇄orchestrator + orchestrator⇄victim の双方向で
 *   メモリ上のみ保持し、永続化しない
 *
 * 関連設計書: DESIGN/31, DESIGN/34
 */
import { Hono } from "hono";
import { z } from "zod";
import * as http from "node:http";
import * as https from "node:https";
import type {
  OrchestratorExecRequest,
  OrchestratorExecResponse,
  RawExchange,
  RawHttpRequest,
  RawHttpResponse,
  VictimEntry,
  VictimTarget,
  AttackStep,
} from "../../shared/api-types.js";

export const orchestratorExecRoutes = new Hono();

// ── VICTIM_ALLOWLIST (DESIGN/31 §5.1) ─────────────────────────────────
const VICTIM_ALLOWLIST: ReadonlyMap<VictimTarget, VictimEntry> = new Map([
  [
    "victim-web",
    {
      // docker compose 環境では `victim-web` の DNS、dev:no-docker 環境では localhost を解決する。
      // VICTIM_WEB_BASE_URL は test 用 override のみ許可 (本番デプロイ時は使われない)。
      baseUrl: process.env.VICTIM_WEB_BASE_URL ?? "http://localhost:4001",
      network: "victim-net",
      phaseAvailable: 1,
    },
  ],
  [
    "attacker-shell",
    {
      baseUrl: "exec://attacker-shell",
      network: "victim-net",
      phaseAvailable: 2, // Phase 1 では HTTP プロキシ未対応 (Phase 2 で docker exec 対応予定)
    },
  ],
] as const);

// ── Phase ガード ─────────────────────────────────────────────────────
const CURRENT_PHASE = (() => {
  const env = process.env.LIVE_ATTACK_PHASE;
  const parsed = env ? Number(env) : 1;
  if (![1, 2, 3, 4, 5].includes(parsed)) return 1;
  return parsed as 1 | 2 | 3 | 4 | 5;
})();

// ── zod スキーマ (DESIGN/31 §3.1) ─────────────────────────────────────
const HTTP_METHOD_VALUES = [
  "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS",
] as const;

const VICTIM_TARGET_VALUES: readonly VictimTarget[] = [
  "victim-web", "attacker-shell", "victim-tls-proxy", "victim-saml-idp",
] as const;

const orchestratorExecRequestSchema = z.object({
  scenarioId: z.string().min(1).max(64),
  target: z.enum(VICTIM_TARGET_VALUES as unknown as [VictimTarget, ...VictimTarget[]]),
  request: z.object({
    method: z.enum(HTTP_METHOD_VALUES),
    path: z.string().regex(/^\//, "path must start with /").max(1024),
    headers: z.record(z.string(), z.string()),
    body: z.union([z.string(), z.null()]).optional(),
  }),
  timeoutMs: z.number().int().min(100).max(10000).optional(),
});

// ── route handler ────────────────────────────────────────────────────
orchestratorExecRoutes.post("/exec", async (c) => {
  const trace = c.get("trace");
  trace.setLiveMode();

  // 1. Body parse + validation
  let json: unknown;
  try {
    json = await c.req.json();
  } catch {
    return c.json({ success: false, error: "invalid_json_body" }, 400);
  }

  const parsed = orchestratorExecRequestSchema.safeParse(json);
  if (!parsed.success) {
    return c.json(
      {
        success: false,
        error: "schema_validation_failed",
        validationErrors: parsed.error.issues,
      },
      400,
    );
  }
  const req: OrchestratorExecRequest = {
    scenarioId: parsed.data.scenarioId,
    target: parsed.data.target,
    request: {
      method: parsed.data.request.method,
      path: parsed.data.request.path,
      headers: parsed.data.request.headers,
      body: parsed.data.request.body ?? null,
    },
    timeoutMs: parsed.data.timeoutMs ?? 3000,
  };

  // 2. VICTIM_ALLOWLIST 検証
  const entry = VICTIM_ALLOWLIST.get(req.target);
  if (!entry) {
    // セキュリティログ: 不在キーは URL 偽造試行の可能性。target 値はレスポンスに含めない (情報漏洩防止)
    console.warn(
      `[orchestrator] target_not_in_allowlist scenarioId=${req.scenarioId}`,
    );
    return c.json(
      {
        success: false,
        error: "target_not_in_allowlist",
        _trace: {
          mode: "live",
          isAttackMode: true,
          victimNote: "不正な target 値の可能性あり",
        },
      },
      403,
    );
  }

  // 3. Phase ガード
  if (entry.phaseAvailable > CURRENT_PHASE) {
    return c.json(
      {
        success: false,
        error: "phase_not_reached",
        requiredPhase: entry.phaseAvailable,
        currentPhase: CURRENT_PHASE,
      },
      503,
    );
  }

  // 4. exec:// (docker exec) は Phase 2+ で実装。Phase 1 では未対応として 503 を返す
  if (entry.baseUrl.startsWith("exec://")) {
    return c.json(
      {
        success: false,
        error: "exec_target_not_implemented",
        detail: "attacker-shell exec routing arrives in Phase 2",
      },
      503,
    );
  }

  // 5. raw HTTP プロキシ
  const startedAt = Date.now();
  let proxyResult: ProxyResult;
  try {
    proxyResult = await proxyToVictim(entry, req.request, req.timeoutMs ?? 3000);
  } catch (err) {
    const code = err instanceof Error ? err.message : "unknown_error";
    if (code === "victim_timeout") {
      return c.json(
        { success: false, error: "victim_timeout", timeoutMs: req.timeoutMs ?? 3000 },
        504,
      );
    }
    return c.json(
      { success: false, error: "victim_unreachable", detail: code },
      502,
    );
  }
  const finishedAt = Date.now();

  // 6. AttackStep 生成 (probe → exploit/blocked → verify)
  const victimStatus = proxyResult.exchange.orchestratorToVictim.response.status;
  const attackSucceeded = victimStatus >= 200 && victimStatus < 300;

  const probeStep: AttackStep = {
    id: `${req.scenarioId}-probe`,
    kind: "probe",
    label: `Sent ${req.request.method} ${req.request.path} to ${req.target}`,
    labelJa: `${req.target} に ${req.request.method} ${req.request.path} を送信`,
    status: "success",
    payload: {
      type: "http",
      request: {
        method: req.request.method,
        url: `${entry.baseUrl}${req.request.path}`,
        headers: proxyResult.exchange.orchestratorToVictim.request.headers,
        body: req.request.body,
      },
    },
    timestamp: startedAt,
  };
  trace.addAttackStep(probeStep);

  const outcomeStep: AttackStep = {
    id: `${req.scenarioId}-${attackSucceeded ? "exploit" : "blocked"}`,
    kind: attackSucceeded ? "exploit" : "blocked",
    label: attackSucceeded
      ? `victim returned ${victimStatus} — attack condition met`
      : `victim returned ${victimStatus} — defense engaged`,
    labelJa: attackSucceeded
      ? `victim が ${victimStatus} を返却 — 攻撃成立条件を満たした`
      : `victim が ${victimStatus} を返却 — 防御が機能`,
    status: attackSucceeded ? "success" : "blocked",
    payload: {
      type: "http",
      response: {
        status: victimStatus,
        headers: proxyResult.exchange.orchestratorToVictim.response.headers,
        body: parseJsonOrString(
          proxyResult.exchange.orchestratorToVictim.response.body,
        ),
      },
    },
    timestamp: finishedAt - 1,
  };
  trace.addAttackStep(outcomeStep);

  const verifyStep: AttackStep = {
    id: `${req.scenarioId}-verify`,
    kind: "verify",
    label: attackSucceeded
      ? "Attack succeeded against vulnerable endpoint (defense recommendation in panel)"
      : "Defense correctly rejected the attack request",
    labelJa: attackSucceeded
      ? "脆弱エンドポイントに対し攻撃が成立 (防御策はパネル参照)"
      : "防御が攻撃リクエストを正しく拒否",
    status: attackSucceeded ? "success" : "blocked",
    timestamp: finishedAt,
  };
  trace.addAttackStep(verifyStep);

  // 7. レスポンス構築 (browserToOrchestrator は orchestrator-exec 自身のフレーム)
  const browserReqHeaders: Record<string, string> = {};
  c.req.raw.headers.forEach((v, k) => {
    browserReqHeaders[k] = v;
  });
  const browserToOrchestrator = {
    request: {
      line: `POST /api/orchestrator/exec HTTP/1.1`,
      headers: browserReqHeaders,
      body: JSON.stringify(json),
      bytesSent: estimateBytes(JSON.stringify(json)),
    } satisfies RawHttpRequest,
    // response は本ハンドラの戻り値 (下記で組み立てた後にメタ的に詰め直す形)
    response: {
      line: `HTTP/1.1 200 OK`,
      status: 200,
      headers: { "content-type": "application/json" },
      body: null, // 完全な応答は呼び出し側で持つので null とする (永続化しないポリシー)
      bytesReceived: 0,
    } satisfies RawHttpResponse,
  };

  const rawExchange: RawExchange = {
    browserToOrchestrator,
    orchestratorToVictim: proxyResult.exchange.orchestratorToVictim,
    elapsedMs: finishedAt - startedAt,
  };

  const result: OrchestratorExecResponse = {
    scenarioId: req.scenarioId,
    outcome: "succeeded",
    startedAt,
    finishedAt,
    steps: [probeStep, outcomeStep, verifyStep],
    summary: attackSucceeded
      ? `Live attack against ${req.target} returned ${victimStatus} — see DataFlowPanel for raw exchange.`
      : `Live attack request blocked by ${req.target} (HTTP ${victimStatus}).`,
    summaryJa: attackSucceeded
      ? `${req.target} への live 攻撃で ${victimStatus} が返却されました。raw exchange は DataFlowPanel を参照。`
      : `${req.target} が live 攻撃リクエストを拒否しました (HTTP ${victimStatus})。`,
    rawExchange,
    mode: "live",
  };

  return c.json({ success: true, data: result });
});

// ── helpers ──────────────────────────────────────────────────────────

interface ProxyResult {
  exchange: {
    orchestratorToVictim: RawExchange["orchestratorToVictim"];
  };
}

async function proxyToVictim(
  entry: VictimEntry,
  reqInput: OrchestratorExecRequest["request"],
  timeoutMs: number,
): Promise<ProxyResult> {
  const base = new URL(entry.baseUrl);
  const isHttps = base.protocol === "https:";
  const transport = isHttps ? https : http;

  // Host ヘッダ強制上書き (DNS rebinding 予防 — DESIGN/31 §6.3)
  const forcedHeaders: Record<string, string> = {};
  for (const [k, v] of Object.entries(reqInput.headers)) {
    if (k.toLowerCase() === "host") continue; // 破棄
    forcedHeaders[k] = v;
  }
  forcedHeaders["Host"] = base.host;
  forcedHeaders["Connection"] = "close";
  if (reqInput.body !== null && reqInput.body !== undefined) {
    forcedHeaders["Content-Length"] = String(Buffer.byteLength(reqInput.body, "utf8"));
  }

  return new Promise((resolve, reject) => {
    const clientReq = transport.request({
      hostname: base.hostname,
      port: base.port ? Number(base.port) : isHttps ? 443 : 80,
      path: reqInput.path,
      method: reqInput.method,
      headers: forcedHeaders,
    });

    clientReq.setTimeout(timeoutMs, () => {
      clientReq.destroy(new Error("victim_timeout"));
    });

    const responseChunks: Buffer[] = [];
    clientReq.on("response", (res) => {
      res.on("data", (chunk: Buffer) => responseChunks.push(chunk));
      res.on("end", () => {
        const rawBody = Buffer.concat(responseChunks);
        const respHeaders: Record<string, string> = {};
        for (const [k, v] of Object.entries(res.headers)) {
          if (typeof v === "string") respHeaders[k] = v;
          else if (Array.isArray(v)) respHeaders[k] = v.join(", ");
        }
        resolve({
          exchange: {
            orchestratorToVictim: {
              request: {
                line: `${reqInput.method} ${reqInput.path} HTTP/1.1`,
                headers: forcedHeaders,
                body: reqInput.body ?? null,
                bytesSent:
                  estimateBytes(
                    `${reqInput.method} ${reqInput.path} HTTP/1.1\r\n` +
                      headerString(forcedHeaders),
                  ) + (reqInput.body ? Buffer.byteLength(reqInput.body, "utf8") : 0),
              },
              response: {
                line: `HTTP/1.1 ${res.statusCode ?? 0} ${res.statusMessage ?? ""}`.trim(),
                status: res.statusCode ?? 0,
                headers: respHeaders,
                body: rawBody.toString("utf8"),
                bytesReceived: rawBody.length,
              },
              targetResolvedTo: entry.baseUrl,
            },
          },
        });
      });
    });

    clientReq.on("error", (err) => reject(err instanceof Error ? err : new Error(String(err))));
    if (reqInput.body !== null && reqInput.body !== undefined) {
      clientReq.write(reqInput.body);
    }
    clientReq.end();
  });
}

function estimateBytes(s: string): number {
  return Buffer.byteLength(s, "utf8");
}

function headerString(headers: Record<string, string>): string {
  return Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join("\r\n") + "\r\n\r\n";
}

function parseJsonOrString(s: string | null): unknown {
  if (s === null || s === "") return s;
  try {
    return JSON.parse(s);
  } catch {
    return s;
  }
}
