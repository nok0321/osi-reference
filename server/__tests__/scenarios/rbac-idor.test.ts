/**
 * シナリオ固有 e2e テスト: rbac-idor (Phase 2 PoC 第 3 号)
 *
 * orchestrator (server/routes/orchestrator-exec.ts) → 実 victim-web (services/victim-web)
 * の経路で IDOR 脆弱性 (CWE-639) が成立することを検証する。
 *
 * orchestrator 基盤の挙動 (schema validation / VICTIM_ALLOWLIST / Host 強制 / production guard 等)
 * は server/__tests__/orchestrator-live.test.ts でカバーされているため、本ファイルでは
 * シナリオ固有の挙動 (脆弱パス / mitigation 観察) のみを対象とする。
 *
 * DESIGN/30 §5.3 / DESIGN/32 §4.5 に対応。
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Hono } from "hono";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { getRequestListener } from "@hono/node-server";
import { traceMiddleware } from "../../middleware/trace-logger.js";
import { productionGuard } from "../../middleware/production-guard.js";
import { orchestratorExecRoutes } from "../../routes/orchestrator-exec.js";
import { rbacVulnRoutes } from "../../../services/victim-web/src/routes/rbac-vuln.js";

interface VictimInstance {
  url: string;
  close: () => Promise<void>;
}

/** 実 victim-web の rbac-vuln ルートを in-process で起動。 */
async function startVictimWeb(): Promise<VictimInstance> {
  const app = new Hono();
  app.route("/rbac", rbacVulnRoutes);
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

describe("Phase 2 PoC: rbac-idor (orchestrator → victim-web)", () => {
  it("攻撃者 charlie (id=3) が victimId=1 (alice) を送ると 200 + alice のフルレコードが漏洩 (脆弱性 e2e)", async () => {
    const app = createOrchestratorApp();
    const res = await app.request("/api/orchestrator/exec", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scenarioId: "rbac-idor",
        target: "victim-web",
        request: {
          method: "POST",
          path: "/rbac/users/profile",
          headers: { "Content-Type": "application/json", Accept: "application/json" },
          body: JSON.stringify({ victimId: 1 }),
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
    expect(ex.request.line).toContain("POST /rbac/users/profile");
    expect(ex.response.status).toBe(200);
    expect(ex.targetResolvedTo).toBe(victim!.url);

    // victim 応答のボディに alice のフルレコードが含まれていることを確認 = 脆弱性が成立
    const victimBody = JSON.parse(ex.response.body ?? "{}") as {
      ok: boolean;
      user: { id: number; username: string; email: string; role: string; ownerId: number };
      leakedFields: string[];
    };
    expect(victimBody.ok).toBe(true);
    expect(victimBody.user.id).toBe(1);
    expect(victimBody.user.username).toBe("seed_alice");
    expect(victimBody.user.email).toBe("alice@example.com");
    expect(victimBody.user.ownerId).toBe(1);
    // 攻撃者 charlie の id=3 と ownerId=1 が一致しないにも関わらず、データが返却されている
    expect(victimBody.leakedFields).toEqual(
      expect.arrayContaining(["id", "username", "email", "role", "ownerId"]),
    );
  });

  it("victimId をどの id に書き換えても 200 が返る (admin=4 を含む — 所有権検証が無いことの確認)", async () => {
    const app = createOrchestratorApp();
    const res = await app.request("/api/orchestrator/exec", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scenarioId: "rbac-idor",
        target: "victim-web",
        request: {
          method: "POST",
          path: "/rbac/users/profile",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ victimId: 4 }),
        },
      }),
    });
    expect(res.status).toBe(200);
    const json = (await res.json()) as {
      data: {
        outcome: string;
        rawExchange: { orchestratorToVictim: { response: { status: number; body: string | null } } };
      };
    };
    expect(json.data.outcome).toBe("succeeded");
    const victimBody = JSON.parse(
      json.data.rawExchange.orchestratorToVictim.response.body ?? "{}",
    ) as { user: { id: number; role: string } };
    expect(victimBody.user.id).toBe(4);
    expect(victimBody.user.role).toBe("admin"); // 管理者ロールも漏洩する
  });

  it("AttackStep が probe / exploit / verify の 3 段で生成される", async () => {
    const app = createOrchestratorApp();
    const res = await app.request("/api/orchestrator/exec", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scenarioId: "rbac-idor",
        target: "victim-web",
        request: {
          method: "POST",
          path: "/rbac/users/profile",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ victimId: 2 }),
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
    expect(steps[0].id).toBe("rbac-idor-probe");
    expect(steps[1].id).toBe("rbac-idor-exploit");
    expect(steps[2].id).toBe("rbac-idor-verify");
  });

  it("victimId 欠如時は victim が 400 を返し、ステップは blocked になる", async () => {
    const app = createOrchestratorApp();
    const res = await app.request("/api/orchestrator/exec", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scenarioId: "rbac-idor",
        target: "victim-web",
        request: {
          method: "POST",
          path: "/rbac/users/profile",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({}),
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
    // victim が 400 を返したので、orchestrator は blocked 系のステップを出す
    expect(json.data.rawExchange.orchestratorToVictim.response.status).toBe(400);
    expect(json.data.outcome).toBe("succeeded"); // OrchestratorExecResponse 側は常に succeeded
    const blockedStep = json.data.steps.find((s) => s.kind === "blocked");
    expect(blockedStep).toBeDefined();
    expect(blockedStep!.status).toBe("blocked");
  });
});
