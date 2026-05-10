/**
 * シナリオ固有 e2e テスト: mfa-otp-replay (Phase 2 PoC 第 5 号 = Phase 2 完結)
 *
 * orchestrator (server/routes/orchestrator-exec.ts) → 実 victim-web (services/victim-web)
 * の経路で TOTP リプレイ脆弱性 (CWE-294) が成立することを検証する。
 *
 * orchestrator 基盤の挙動 (schema validation / VICTIM_ALLOWLIST / Host 強制 / production guard 等)
 * は server/__tests__/orchestrator-live.test.ts でカバーされているため、本ファイルでは
 * シナリオ固有の挙動 (脆弱パス / leakedToAttacker フィールド観察 / blocked 経路) のみを対象とする。
 *
 * DESIGN/30 §5.3 / DESIGN/32 §4.7 に対応。
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Hono } from "hono";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { getRequestListener } from "@hono/node-server";
import { traceMiddleware } from "../../middleware/trace-logger.js";
import { productionGuard } from "../../middleware/production-guard.js";
import { orchestratorExecRoutes } from "../../routes/orchestrator-exec.js";
import { totpVulnRoutes } from "../../../services/victim-web/src/routes/totp-vuln.js";

interface VictimInstance {
  url: string;
  close: () => Promise<void>;
}

/** 実 victim-web の totp-vuln ルートを in-process で起動。 */
async function startVictimWeb(): Promise<VictimInstance> {
  const app = new Hono();
  app.route("/totp", totpVulnRoutes);
  const handler = getRequestListener(app.fetch);
  const server = http.createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      ),
  };
}

function createOrchestratorApp() {
  const app = new Hono();
  app.use("/api/*", traceMiddleware);
  app.use("/api/orchestrator/*", productionGuard);
  app.route("/api/orchestrator", orchestratorExecRoutes);
  return app;
}

let victim: VictimInstance | null = null;

beforeAll(async () => {
  victim = await startVictimWeb();
  process.env.VICTIM_WEB_BASE_URL = victim.url;
  delete process.env.LIVE_ATTACK_PHASE;
  delete process.env.NODE_ENV;
});

afterAll(async () => {
  if (victim) {
    await victim.close();
    victim = null;
  }
  delete process.env.VICTIM_WEB_BASE_URL;
});

describe("Phase 2 PoC: mfa-otp-replay (orchestrator → victim-web)", () => {
  it("既知 username で 200 + 同一 OTP の 2 連続認証 + leakedToAttacker が観察できる (脆弱性 e2e)", async () => {
    const app = createOrchestratorApp();
    const res = await app.request("/api/orchestrator/exec", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scenarioId: "mfa-otp-replay",
        target: "victim-web",
        request: {
          method: "POST",
          path: "/totp/login-replay",
          headers: {
            "Content-Type": "application/json",
            Accept: "application/json",
          },
          body: JSON.stringify({ username: "seed_alice" }),
        },
      }),
    });

    expect(res.status).toBe(200);
    const json = (await res.json()) as {
      success: boolean;
      data: {
        outcome: "succeeded" | "blocked" | "error";
        rawExchange: {
          orchestratorToVictim: {
            request: { line: string };
            response: { status: number; headers: Record<string, string>; body: string | null };
            targetResolvedTo: string;
          };
        };
        mode: string;
      };
    };

    expect(json.success).toBe(true);
    expect(json.data.outcome).toBe("succeeded");
    expect(json.data.mode).toBe("live");

    const ex = json.data.rawExchange.orchestratorToVictim;
    expect(ex.request.line).toContain("POST /totp/login-replay");
    expect(ex.response.status).toBe(200);
    expect(ex.targetResolvedTo).toBe(victim!.url);

    // 教材ヘッダ (storyboard が data-leak visual で参照する)
    expect(ex.response.headers["x-computed-otp"]).toMatch(/^\d{6}$/);
    expect(ex.response.headers["x-replay-detected"]).toBe("false");

    // body の漏えい想定データを検証
    const victimBody = JSON.parse(ex.response.body ?? "{}") as {
      ok: boolean;
      computedOtp: string;
      victimLogin: { authenticatedAs: string; counterMatched: number };
      attackerReplay: { authenticatedAs: string; counterMatched: number };
      leakedToAttacker: {
        userId: number;
        username: string;
        email: string;
        demoBalance: string;
        demoApiKey: string;
      };
      replayDetected: boolean;
      usedOtpTracking: string;
    };
    expect(victimBody.ok).toBe(true);
    expect(victimBody.computedOtp).toBe(ex.response.headers["x-computed-otp"]);
    expect(victimBody.victimLogin.authenticatedAs).toBe("seed_alice");
    expect(victimBody.attackerReplay.authenticatedAs).toBe("seed_alice");
    expect(victimBody.victimLogin.counterMatched).toBe(victimBody.attackerReplay.counterMatched);
    expect(victimBody.leakedToAttacker.userId).toBe(1);
    expect(victimBody.leakedToAttacker.email).toBe("alice@victim.local");
    expect(victimBody.leakedToAttacker.demoApiKey).toContain("REDACTED");
    expect(victimBody.replayDetected).toBe(false);
    expect(victimBody.usedOtpTracking).toBe("absent");
  });

  it("admin への昇格でも leakedToAttacker.demoBalance が $1,000,000.00 で漏えいする", async () => {
    const app = createOrchestratorApp();
    const res = await app.request("/api/orchestrator/exec", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scenarioId: "mfa-otp-replay",
        target: "victim-web",
        request: {
          method: "POST",
          path: "/totp/login-replay",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: "seed_admin" }),
        },
      }),
    });
    expect(res.status).toBe(200);
    const json = (await res.json()) as {
      data: {
        outcome: string;
        rawExchange: { orchestratorToVictim: { response: { body: string | null } } };
      };
    };
    expect(json.data.outcome).toBe("succeeded");
    const victimBody = JSON.parse(
      json.data.rawExchange.orchestratorToVictim.response.body ?? "{}",
    ) as { leakedToAttacker: { userId: number; demoBalance: string } };
    expect(victimBody.leakedToAttacker.userId).toBe(4);
    expect(victimBody.leakedToAttacker.demoBalance).toBe("$1,000,000.00");
  });

  it("AttackStep が probe / exploit / verify の 3 段で生成される", async () => {
    const app = createOrchestratorApp();
    const res = await app.request("/api/orchestrator/exec", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scenarioId: "mfa-otp-replay",
        target: "victim-web",
        request: {
          method: "POST",
          path: "/totp/login-replay",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: "seed_bob" }),
        },
      }),
    });
    expect(res.status).toBe(200);
    const json = (await res.json()) as {
      data: { steps: Array<{ id: string; kind: string; status: string }> };
    };
    const steps = json.data.steps;
    expect(steps).toHaveLength(3);
    expect(steps[0].kind).toBe("probe");
    expect(steps[1].kind).toBe("exploit");
    expect(steps[2].kind).toBe("verify");
    expect(steps[1].status).toBe("success");
    expect(steps[0].id).toBe("mfa-otp-replay-probe");
    expect(steps[1].id).toBe("mfa-otp-replay-exploit");
    expect(steps[2].id).toBe("mfa-otp-replay-verify");
  });

  it("不在 username では victim が 401 を返し、ステップは blocked になる", async () => {
    const app = createOrchestratorApp();
    const res = await app.request("/api/orchestrator/exec", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scenarioId: "mfa-otp-replay",
        target: "victim-web",
        request: {
          method: "POST",
          path: "/totp/login-replay",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: "ghost_user" }),
        },
      }),
    });
    expect(res.status).toBe(200);
    const json = (await res.json()) as {
      data: {
        outcome: string;
        rawExchange: { orchestratorToVictim: { response: { status: number } } };
        steps: Array<{ kind: string; status: string }>;
      };
    };
    // victim が 401 を返したので、orchestrator は blocked 系のステップを出す
    expect(json.data.rawExchange.orchestratorToVictim.response.status).toBe(401);
    expect(json.data.outcome).toBe("succeeded"); // OrchestratorExecResponse 側は常に succeeded
    const blockedStep = json.data.steps.find((s) => s.kind === "blocked");
    expect(blockedStep).toBeDefined();
    expect(blockedStep!.status).toBe("blocked");
  });
});
