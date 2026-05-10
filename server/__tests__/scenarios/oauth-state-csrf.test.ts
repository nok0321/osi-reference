/**
 * シナリオ固有 e2e テスト: oauth-state-csrf (Phase 2 PoC)
 *
 * orchestrator (server/routes/orchestrator-exec.ts) → 実 victim-web (services/victim-web)
 * の経路で state パラメータ未検証脆弱性が成立することを検証する。
 *
 * orchestrator 基盤の挙動 (schema validation / VICTIM_ALLOWLIST / Host 強制 / production guard 等)
 * は server/__tests__/orchestrator-live.test.ts でカバーされているため、本ファイルでは
 * シナリオ固有の挙動 (脆弱パス / mitigation 観察) のみを対象とする。
 *
 * DESIGN/30 §5.3 / DESIGN/32 §4.4 に対応。
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Hono } from "hono";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { getRequestListener } from "@hono/node-server";
import { traceMiddleware } from "../../middleware/trace-logger.js";
import { productionGuard } from "../../middleware/production-guard.js";
import { orchestratorExecRoutes } from "../../routes/orchestrator-exec.js";
import { oauthVulnRoutes } from "../../../services/victim-web/src/routes/oauth-vuln.js";

interface VictimInstance {
  url: string;
  close: () => Promise<void>;
}

/** 実 victim-web の oauth-vuln ルートを in-process で起動。 */
async function startVictimWeb(): Promise<VictimInstance> {
  const app = new Hono();
  app.route("/oauth", oauthVulnRoutes);
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

describe("Phase 2 PoC: oauth-state-csrf (orchestrator → victim-web)", () => {
  it("state パラメータ無しの GET /oauth/authorize で 200 + 認可コードが返る (脆弱性 e2e)", async () => {
    const app = createOrchestratorApp();
    const res = await app.request("/api/orchestrator/exec", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scenarioId: "oauth-state-csrf",
        target: "victim-web",
        request: {
          method: "GET",
          path: "/oauth/authorize?client_id=demo-app&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=read",
          headers: { Accept: "application/json" },
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
            response: { status: number; body: string | null };
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
    expect(ex.request.line).toContain("GET /oauth/authorize");
    expect(ex.response.status).toBe(200);
    expect(ex.targetResolvedTo).toBe(victim!.url);

    // victim 応答のボディに認可コードが含まれていることを確認 = 脆弱性が成立
    const victimBody = JSON.parse(ex.response.body ?? "{}") as {
      ok: boolean;
      code: string;
      state_received: string | null;
    };
    expect(victimBody.ok).toBe(true);
    expect(victimBody.code).toMatch(/^vuln-code-/);
    expect(victimBody.state_received).toBeNull();
  });

  it("state パラメータがあっても victim は同様に code を発行する (state 検証なし)", async () => {
    const app = createOrchestratorApp();
    const res = await app.request("/api/orchestrator/exec", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scenarioId: "oauth-state-csrf",
        target: "victim-web",
        request: {
          method: "GET",
          path: "/oauth/authorize?client_id=demo-app&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=read&state=learner_supplied_state",
          headers: { Accept: "application/json" },
        },
      }),
    });

    expect(res.status).toBe(200);
    const json = (await res.json()) as {
      success: boolean;
      data: {
        outcome: "succeeded" | "blocked" | "error";
        rawExchange: {
          orchestratorToVictim: { response: { status: number; body: string | null } };
        };
      };
    };
    expect(json.success).toBe(true);
    expect(json.data.outcome).toBe("succeeded");
    const victimBody = JSON.parse(
      json.data.rawExchange.orchestratorToVictim.response.body ?? "{}",
    ) as { code: string; state_received: string | null };
    expect(victimBody.code).toMatch(/^vuln-code-/);
    // state は echo されるが検証は行われない
    expect(victimBody.state_received).toBe("learner_supplied_state");
  });

  it("AttackStep が probe / exploit / verify の 3 段で生成される", async () => {
    const app = createOrchestratorApp();
    const res = await app.request("/api/orchestrator/exec", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scenarioId: "oauth-state-csrf",
        target: "victim-web",
        request: {
          method: "GET",
          path: "/oauth/authorize?client_id=demo-app&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback",
          headers: {},
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
    expect(steps[0].id).toBe("oauth-state-csrf-probe");
    expect(steps[1].id).toBe("oauth-state-csrf-exploit");
    expect(steps[2].id).toBe("oauth-state-csrf-verify");
  });

  it("victim 応答ボディに leakedToAttacker (token exchange 後の予定 profile) が含まれる", async () => {
    const app = createOrchestratorApp();
    const res = await app.request("/api/orchestrator/exec", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scenarioId: "oauth-state-csrf",
        target: "victim-web",
        request: {
          method: "GET",
          path: "/oauth/authorize?client_id=demo-app&redirect_uri=http%3A%2F%2Fattacker.example%2Fcb",
          headers: { Accept: "application/json" },
        },
      }),
    });
    expect(res.status).toBe(200);
    const json = (await res.json()) as {
      data: {
        rawExchange: {
          orchestratorToVictim: {
            response: { body: string | null; headers: Record<string, string> };
          };
        };
      };
    };
    const ex = json.data.rawExchange.orchestratorToVictim;
    const victimBody = JSON.parse(ex.response.body ?? "{}") as {
      code: string;
      leakedToAttacker: {
        username: string;
        email: string;
        futureAccessToken: string;
        authorizationCode: string;
        stateValidated: boolean;
        attackerControlledRedirect: string;
      };
    };
    expect(victimBody.leakedToAttacker.username).toBe("seed_alice");
    expect(victimBody.leakedToAttacker.email).toBe("alice@victim.local");
    expect(victimBody.leakedToAttacker.futureAccessToken).toMatch(
      /^VICTIM_AT_REDACTED_/,
    );
    expect(victimBody.leakedToAttacker.authorizationCode).toBe(victimBody.code);
    expect(victimBody.leakedToAttacker.stateValidated).toBe(false);
    expect(victimBody.leakedToAttacker.attackerControlledRedirect).toBe(
      "http://attacker.example/cb",
    );

    // 教材ヒントヘッダが victim → orchestrator 経路を抜けて raw exchange に保存される
    const headerKeys = Object.keys(ex.response.headers).map((k) => k.toLowerCase());
    expect(headerKeys).toContain("x-authorization-code");
    expect(headerKeys).toContain("x-csrf-risk");
  });

  it("client_id / redirect_uri 欠如時は victim が 400 を返し outcome は blocked", async () => {
    const app = createOrchestratorApp();
    const res = await app.request("/api/orchestrator/exec", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scenarioId: "oauth-state-csrf",
        target: "victim-web",
        request: {
          method: "GET",
          // client_id / redirect_uri を意図的に欠如
          path: "/oauth/authorize?scope=read",
          headers: {},
        },
      }),
    });
    expect(res.status).toBe(200);
    const json = (await res.json()) as {
      data: {
        outcome: "succeeded" | "blocked" | "error";
        rawExchange: {
          orchestratorToVictim: { response: { status: number } };
        };
        steps: Array<{ kind: string; status: string }>;
      };
    };
    // victim が 400 を返したので、orchestrator は blocked と判定する
    expect(json.data.rawExchange.orchestratorToVictim.response.status).toBe(400);
    expect(json.data.outcome).toBe("succeeded"); // OrchestratorExecResponse 側は常に succeeded
    // ステップ側で blocked が出ること
    const blockedStep = json.data.steps.find((s) => s.kind === "blocked");
    expect(blockedStep).toBeDefined();
    expect(blockedStep!.status).toBe("blocked");
  });
});
