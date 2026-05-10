/**
 * シナリオ固有 e2e テスト: session-fixation (Phase 2 PoC 第 4 号)
 *
 * orchestrator (server/routes/orchestrator-exec.ts) → 実 victim-web (services/victim-web)
 * の経路で Session Fixation 脆弱性 (CWE-384) が成立することを検証する。
 *
 * orchestrator 基盤の挙動 (schema validation / VICTIM_ALLOWLIST / Host 強制 / production guard 等)
 * は server/__tests__/orchestrator-live.test.ts でカバーされているため、本ファイルでは
 * シナリオ固有の挙動 (脆弱パス / mitigation 観察) のみを対象とする。
 *
 * DESIGN/30 §5.3 / DESIGN/32 §4.6 に対応。
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Hono } from "hono";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { getRequestListener } from "@hono/node-server";
import { traceMiddleware } from "../../middleware/trace-logger.js";
import { productionGuard } from "../../middleware/production-guard.js";
import { orchestratorExecRoutes } from "../../routes/orchestrator-exec.js";
import { sessionVulnRoutes } from "../../../services/victim-web/src/routes/session-vuln.js";

interface VictimInstance {
  url: string;
  close: () => Promise<void>;
}

/** 実 victim-web の session-vuln ルートを in-process で起動。 */
async function startVictimWeb(): Promise<VictimInstance> {
  const app = new Hono();
  app.route("/session", sessionVulnRoutes);
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

describe("Phase 2 PoC: session-fixation (orchestrator → victim-web)", () => {
  it("攻撃者既知 SID を Cookie で送ると 200 + Set-Cookie / body.sessionId に同じ SID が echo される (脆弱性 e2e)", async () => {
    const app = createOrchestratorApp();
    const attackerKnownSid = "ATTACKER_KNOWN_SID_v1";
    const res = await app.request("/api/orchestrator/exec", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scenarioId: "session-fixation",
        target: "victim-web",
        request: {
          method: "POST",
          path: "/session/login",
          headers: {
            "Content-Type": "application/json",
            Accept: "application/json",
            Cookie: `session_id=${attackerKnownSid}`,
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
    expect(ex.request.line).toContain("POST /session/login");
    expect(ex.response.status).toBe(200);
    expect(ex.targetResolvedTo).toBe(victim!.url);

    // Set-Cookie に同じ SID が echo されている = 脆弱性が orchestrator 経路で成立
    const setCookie = ex.response.headers["set-cookie"] ?? "";
    expect(setCookie).toContain(`session_id=${attackerKnownSid}`);

    // body にも sessionId が echo され、sessionIdSource=reused-from-request-cookie を確認
    const victimBody = JSON.parse(ex.response.body ?? "{}") as {
      ok: boolean;
      user: { id: number; username: string };
      sessionId: string;
      sessionIdSource: string;
      sessionRegenerated: boolean;
    };
    expect(victimBody.ok).toBe(true);
    expect(victimBody.user.username).toBe("seed_alice");
    expect(victimBody.sessionId).toBe(attackerKnownSid);
    expect(victimBody.sessionIdSource).toBe("reused-from-request-cookie");
    expect(victimBody.sessionRegenerated).toBe(false);
  });

  it("どの username でも Cookie の SID が同じなら echo される (admin にも昇格可能であることの確認)", async () => {
    const app = createOrchestratorApp();
    const attackerKnownSid = "EVIL_SID_zzz";
    const res = await app.request("/api/orchestrator/exec", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scenarioId: "session-fixation",
        target: "victim-web",
        request: {
          method: "POST",
          path: "/session/login",
          headers: {
            "Content-Type": "application/json",
            Cookie: `session_id=${attackerKnownSid}`,
          },
          body: JSON.stringify({ username: "seed_admin" }),
        },
      }),
    });
    expect(res.status).toBe(200);
    const json = (await res.json()) as {
      data: {
        outcome: string;
        rawExchange: {
          orchestratorToVictim: {
            response: { status: number; body: string | null };
          };
        };
      };
    };
    expect(json.data.outcome).toBe("succeeded");
    const victimBody = JSON.parse(
      json.data.rawExchange.orchestratorToVictim.response.body ?? "{}",
    ) as { user: { id: number; username: string }; sessionId: string };
    expect(victimBody.user.id).toBe(4);
    expect(victimBody.user.username).toBe("seed_admin");
    expect(victimBody.sessionId).toBe(attackerKnownSid);
  });

  it("AttackStep が probe / exploit / verify の 3 段で生成される", async () => {
    const app = createOrchestratorApp();
    const res = await app.request("/api/orchestrator/exec", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scenarioId: "session-fixation",
        target: "victim-web",
        request: {
          method: "POST",
          path: "/session/login",
          headers: {
            "Content-Type": "application/json",
            Cookie: "session_id=ATTACKER_KNOWN_SID_v1",
          },
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
    expect(steps[0].id).toBe("session-fixation-probe");
    expect(steps[1].id).toBe("session-fixation-exploit");
    expect(steps[2].id).toBe("session-fixation-verify");
  });

  it("不在 username では victim が 401 を返し、ステップは blocked になる", async () => {
    const app = createOrchestratorApp();
    const res = await app.request("/api/orchestrator/exec", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scenarioId: "session-fixation",
        target: "victim-web",
        request: {
          method: "POST",
          path: "/session/login",
          headers: {
            "Content-Type": "application/json",
            Cookie: "session_id=ATTACKER_KNOWN_SID_v1",
          },
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
