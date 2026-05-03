/**
 * orchestrator/exec エンドポイントの結合テスト (DESIGN/31 §11)。
 *
 * 10 項目チェックリスト:
 * 1. スキーマ違反 → 400 + validationErrors
 * 2. target が VICTIM_ALLOWLIST に不在 → 403 + _trace.victimNote
 * 3. ECONNREFUSED → 502
 * 4. timeoutMs 超過 → 504
 * 5. NODE_ENV=production → 503 live_attack_disabled_in_production
 * 6. 双方向 raw bytes (browserToOrchestrator + orchestratorToVictim) を独立キャプチャ
 * 7. Host ヘッダが victim baseUrl から計算した値に強制上書き
 * 8. attack_log には summary のみで raw bytes は含まれない (本テストでは attack_log 永続化は対象外、
 *    レスポンス内に raw bytes を含むこと自体は許容。orchestrator は永続化しないことを type で保証)
 * 9. _trace.mode === "live"
 * 10. _trace.victimNote が設定されている
 *
 * モック方針: DESIGN/31 §11.2 に従い in-process `http.createServer` で victim を立てる。
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { Hono } from "hono";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { traceMiddleware } from "../middleware/trace-logger.js";
import { productionGuard } from "../middleware/production-guard.js";
import { orchestratorExecRoutes } from "../routes/orchestrator-exec.js";

interface MockVictim {
  port: number;
  url: string;
  receivedRequests: Array<{
    method: string;
    url: string;
    headers: http.IncomingHttpHeaders;
    body: string;
  }>;
  close: () => Promise<void>;
}

type VictimResponder = (req: {
  method: string;
  url: string;
  headers: http.IncomingHttpHeaders;
  body: string;
}) => { status: number; headers?: Record<string, string>; body: string };

async function startMockVictim(responder: VictimResponder): Promise<MockVictim> {
  const received: MockVictim["receivedRequests"] = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (chunk: Buffer) => {
      body += chunk.toString("utf8");
    });
    req.on("end", () => {
      received.push({
        method: req.method ?? "GET",
        url: req.url ?? "/",
        headers: req.headers,
        body,
      });
      const reply = responder({
        method: req.method ?? "GET",
        url: req.url ?? "/",
        headers: req.headers,
        body,
      });
      const headers = reply.headers ?? { "content-type": "application/json" };
      res.writeHead(reply.status, headers);
      res.end(reply.body);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    port,
    url: `http://127.0.0.1:${port}`,
    receivedRequests: received,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

function createApp() {
  const app = new Hono();
  app.use("/api/*", traceMiddleware);
  app.use("/api/orchestrator/*", productionGuard);
  app.route("/api/orchestrator", orchestratorExecRoutes);
  return app;
}

function buildRequest(overrides?: Record<string, unknown>) {
  return {
    scenarioId: "jwt-alg-none-test",
    target: "victim-web",
    request: {
      method: "POST",
      path: "/jwt/verify",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: "TEST_FIXTURE_NOT_A_JWT" }),
    },
    ...overrides,
  };
}

let mockVictim: MockVictim | null = null;

beforeEach(() => {
  // 各テスト開始時にクリーンな環境を保証
  delete process.env.VICTIM_WEB_BASE_URL;
  delete process.env.LIVE_ATTACK_PHASE;
  delete process.env.NODE_ENV;
});

afterEach(async () => {
  if (mockVictim) {
    await mockVictim.close();
    mockVictim = null;
  }
  delete process.env.VICTIM_WEB_BASE_URL;
  delete process.env.LIVE_ATTACK_PHASE;
  delete process.env.NODE_ENV;
});

describe("POST /api/orchestrator/exec — schema validation (item 1)", () => {
  it("returns 400 + validationErrors when required field is missing", async () => {
    const app = createApp();
    const res = await app.request("/api/orchestrator/exec", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenarioId: "x" }), // target / request 欠如
    });
    expect(res.status).toBe(400);
    const json = (await res.json()) as { success: boolean; error: string; validationErrors?: unknown[] };
    expect(json.success).toBe(false);
    expect(json.error).toBe("schema_validation_failed");
    expect(Array.isArray(json.validationErrors)).toBe(true);
    expect(json.validationErrors!.length).toBeGreaterThan(0);
  });

  it("returns 400 invalid_json_body when body is not JSON", async () => {
    const app = createApp();
    const res = await app.request("/api/orchestrator/exec", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "not-json{",
    });
    expect(res.status).toBe(400);
    const json = (await res.json()) as { error: string };
    expect(json.error).toBe("invalid_json_body");
  });
});

describe("POST /api/orchestrator/exec — VICTIM_ALLOWLIST (item 2)", () => {
  it("returns 403 with _trace.victimNote when target is not in allowlist", async () => {
    const app = createApp();
    const res = await app.request("/api/orchestrator/exec", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(buildRequest({ target: "victim-tls-proxy" })),
    });
    expect(res.status).toBe(403);
    const json = (await res.json()) as {
      success: boolean;
      error: string;
      _trace?: { victimNote?: string };
    };
    expect(json.success).toBe(false);
    expect(json.error).toBe("target_not_in_allowlist");
    expect(json._trace?.victimNote).toBeDefined();
    expect(typeof json._trace!.victimNote).toBe("string");
  });
});

describe("POST /api/orchestrator/exec — connection failure (item 3)", () => {
  it("returns 502 victim_unreachable when victim cannot be reached", async () => {
    // 確実に閉じているポート (ephemeral 0 を一時的に開いて閉じる)
    const dead = await startMockVictim(() => ({ status: 200, body: "{}" }));
    const deadUrl = dead.url;
    await dead.close();
    process.env.VICTIM_WEB_BASE_URL = deadUrl;

    const app = createApp();
    const res = await app.request("/api/orchestrator/exec", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(buildRequest({ timeoutMs: 1000 })),
    });
    expect(res.status).toBe(502);
    const json = (await res.json()) as { success: boolean; error: string; detail?: string };
    expect(json.success).toBe(false);
    expect(json.error).toBe("victim_unreachable");
    expect(typeof json.detail).toBe("string");
  });
});

describe("POST /api/orchestrator/exec — timeout (item 4)", () => {
  it("returns 504 victim_timeout with timeoutMs echoed back", async () => {
    // 応答しない victim (response を保留)
    const stalled = http.createServer((_req, _res) => {
      // 応答しないまま接続維持
    });
    await new Promise<void>((resolve) => stalled.listen(0, "127.0.0.1", resolve));
    const port = (stalled.address() as AddressInfo).port;
    process.env.VICTIM_WEB_BASE_URL = `http://127.0.0.1:${port}`;

    try {
      const app = createApp();
      const res = await app.request("/api/orchestrator/exec", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(buildRequest({ timeoutMs: 200 })),
      });
      expect(res.status).toBe(504);
      const json = (await res.json()) as { error: string; timeoutMs: number };
      expect(json.error).toBe("victim_timeout");
      expect(json.timeoutMs).toBe(200);
    } finally {
      await new Promise<void>((resolve) => stalled.close(() => resolve()));
    }
  });
});

describe("POST /api/orchestrator/exec — production guard (item 5)", () => {
  it("returns 503 live_attack_disabled_in_production when NODE_ENV=production", async () => {
    process.env.NODE_ENV = "production";
    const app = createApp();
    const res = await app.request("/api/orchestrator/exec", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(buildRequest()),
    });
    expect(res.status).toBe(503);
    const json = (await res.json()) as { error: string };
    expect(json.error).toBe("live_attack_disabled_in_production");
  });
});

describe("POST /api/orchestrator/exec — successful proxy (items 6-10)", () => {
  beforeEach(async () => {
    mockVictim = await startMockVictim((req) => {
      // 受信リクエストを反射するシンプルな victim
      return {
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          ok: true,
          receivedMethod: req.method,
          receivedUrl: req.url,
          receivedBody: req.body,
        }),
      };
    });
    process.env.VICTIM_WEB_BASE_URL = mockVictim.url;
  });

  it("captures rawExchange.browserToOrchestrator and orchestratorToVictim independently (item 6)", async () => {
    const app = createApp();
    const res = await app.request("/api/orchestrator/exec", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(buildRequest()),
    });
    expect(res.status).toBe(200);
    const json = (await res.json()) as {
      success: boolean;
      data: {
        rawExchange: {
          browserToOrchestrator: { request: { line: string }; response: { line: string } };
          orchestratorToVictim: {
            request: { line: string; headers: Record<string, string>; body: string | null };
            response: { line: string; status: number };
            targetResolvedTo: string;
          };
          elapsedMs: number;
        };
      };
    };
    expect(json.success).toBe(true);
    const ex = json.data.rawExchange;
    expect(ex.browserToOrchestrator.request.line).toContain("/api/orchestrator/exec");
    expect(ex.orchestratorToVictim.request.line).toContain("/jwt/verify");
    expect(ex.orchestratorToVictim.response.status).toBe(200);
    expect(ex.orchestratorToVictim.targetResolvedTo).toBe(mockVictim!.url);
    expect(typeof ex.elapsedMs).toBe("number");
    expect(ex.elapsedMs).toBeGreaterThanOrEqual(0);
  });

  it("forces Host header to victim host (item 7)", async () => {
    const app = createApp();
    await app.request("/api/orchestrator/exec", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(
        buildRequest({
          request: {
            method: "POST",
            path: "/jwt/verify",
            // ブラウザ側が悪意ある Host を送っても orchestrator が上書きすべき
            headers: { "Content-Type": "application/json", Host: "evil.example.com" },
            body: JSON.stringify({ token: "TEST_FIXTURE_NOT_A_JWT" }),
          },
        }),
      ),
    });
    // victim 側が受信したヘッダで確認
    const received = mockVictim!.receivedRequests[0];
    const expectedHost = `127.0.0.1:${mockVictim!.port}`;
    expect(received.headers.host).toBe(expectedHost);
    expect(received.headers.host).not.toBe("evil.example.com");
  });

  it("does not include attack_log persistence (raw bytes are response-only, item 8)", async () => {
    // attack_log への永続化は本実装では未実装。レスポンス側に raw bytes が含まれるが、
    // 永続層には書き込まれていないことを契約として確認する。
    // (DESIGN/31 §6.4: in-memory のみ、永続化禁止)
    const app = createApp();
    const res = await app.request("/api/orchestrator/exec", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(buildRequest()),
    });
    const json = (await res.json()) as {
      data: {
        // raw bytes は応答に含まれて良い (browser が visualize するため)
        rawExchange: unknown;
        // ただし永続化向けの logId 等のフィールドを追加していないことを確認
        attackLogId?: number;
      };
    };
    expect(json.data.rawExchange).toBeDefined();
    expect("attackLogId" in json.data).toBe(false);
  });

  it("sets _trace.mode === \"live\" (item 9)", async () => {
    const app = createApp();
    const res = await app.request("/api/orchestrator/exec", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(buildRequest()),
    });
    const json = (await res.json()) as { _trace?: { mode?: string } };
    expect(json._trace?.mode).toBe("live");
  });

  it("sets _trace.victimNote (item 10)", async () => {
    const app = createApp();
    const res = await app.request("/api/orchestrator/exec", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(buildRequest()),
    });
    const json = (await res.json()) as { _trace?: { victimNote?: string } };
    expect(typeof json._trace?.victimNote).toBe("string");
    expect(json._trace!.victimNote!.length).toBeGreaterThan(0);
  });
});

describe("POST /api/orchestrator/exec — phase guard (additional)", () => {
  it("returns 503 phase_not_reached for attacker-shell at default phase 1", async () => {
    const app = createApp();
    const res = await app.request("/api/orchestrator/exec", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(buildRequest({ target: "attacker-shell" })),
    });
    expect(res.status).toBe(503);
    const json = (await res.json()) as {
      error: string;
      requiredPhase: number;
      currentPhase: number;
    };
    expect(json.error).toBe("phase_not_reached");
    expect(json.requiredPhase).toBe(2);
    expect(json.currentPhase).toBe(1);
  });
});
