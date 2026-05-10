/**
 * victim-web 単体テスト: POST /totp/login-replay (mfa-otp-replay 脆弱エンドポイント)
 *
 * orchestrator を介さずに victim-web 単体の脆弱性が成立することを直接確認する。
 * orchestrator 経由の e2e は server/__tests__/scenarios/mfa-otp-replay.test.ts で別途検証する。
 *
 * DESIGN/32 §4.7 / §8.1 (Phase 2 PR-4 で追記): "POST /totp/login-replay — victim が
 * 現在時刻 OTP を計算し、同じ OTP で 2 連続検証して両方 success を返すこと"
 */
import { describe, it, expect } from "vitest";
import { Hono } from "hono";
import { totpVulnRoutes } from "../src/routes/totp-vuln.js";
import {
  computeTotp,
  currentCounter,
} from "../src/utils/totp.js";

function createApp() {
  const app = new Hono();
  app.route("/totp", totpVulnRoutes);
  return app;
}

const DEMO_SECRET = "JBSWY3DPEHPK3PXP";

describe("victim-web: POST /totp/login-replay (CWE-294 OTP replay)", () => {
  it("既知 username + secret 省略で 200 + 同一 OTP の 2 連続認証が成立する (脆弱性の核心)", async () => {
    const app = createApp();
    const res = await app.request("/totp/login-replay", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "seed_alice" }),
    });
    expect(res.status).toBe(200);

    const json = (await res.json()) as {
      ok: boolean;
      computedOtp: string;
      totpCounter: number;
      victimLogin: { authenticatedAs: string; counterMatched: number; sessionId: string };
      attackerReplay: { authenticatedAs: string; counterMatched: number; sessionId: string };
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

    expect(json.ok).toBe(true);
    expect(json.computedOtp).toMatch(/^\d{6}$/);
    expect(json.victimLogin.authenticatedAs).toBe("seed_alice");
    expect(json.attackerReplay.authenticatedAs).toBe("seed_alice");
    // 脆弱性の核心: 同じ counter で 2 セッション発行
    expect(json.victimLogin.counterMatched).toBe(json.attackerReplay.counterMatched);
    // 漏えい想定データが揃っている
    expect(json.leakedToAttacker.userId).toBe(1);
    expect(json.leakedToAttacker.email).toBe("alice@victim.local");
    expect(json.leakedToAttacker.demoBalance).toBe("$12,345.67");
    expect(json.leakedToAttacker.demoApiKey).toContain("REDACTED");
    expect(json.replayDetected).toBe(false);
    expect(json.usedOtpTracking).toBe("absent");

    // 教材ヘッダ
    expect(res.headers.get("X-Computed-OTP")).toBe(json.computedOtp);
    expect(res.headers.get("X-Replay-Detected")).toBe("false");
    expect(res.headers.get("X-Counter")).toBe(String(json.totpCounter));
  });

  it("学習者が secret を明示的に渡すと secretUsed=<learner-provided> になる", async () => {
    const app = createApp();
    const res = await app.request("/totp/login-replay", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "seed_admin", secret: DEMO_SECRET }),
    });
    expect(res.status).toBe(200);
    const json = (await res.json()) as {
      ok: boolean;
      secretUsed: string;
      leakedToAttacker: { userId: number; demoBalance: string };
    };
    expect(json.ok).toBe(true);
    expect(json.secretUsed).toBe("<learner-provided>");
    expect(json.leakedToAttacker.userId).toBe(4);
    expect(json.leakedToAttacker.demoBalance).toBe("$1,000,000.00");
  });

  it("学習者が現在時刻の正しい OTP を code として送ってもリプレイが成立する", async () => {
    const app = createApp();
    const counter = currentCounter();
    const code = computeTotp(DEMO_SECRET, counter).code;
    const res = await app.request("/totp/login-replay", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "seed_bob", secret: DEMO_SECRET, code }),
    });
    expect(res.status).toBe(200);
    const json = (await res.json()) as {
      ok: boolean;
      computedOtp: string;
      victimLogin: { counterMatched: number };
      attackerReplay: { counterMatched: number };
    };
    expect(json.ok).toBe(true);
    expect(json.computedOtp).toBe(code);
    expect(json.victimLogin.counterMatched).toBe(json.attackerReplay.counterMatched);
  });

  it("シードに存在しないユーザー名は 401 を返す", async () => {
    const app = createApp();
    const res = await app.request("/totp/login-replay", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "ghost_user" }),
    });
    expect(res.status).toBe(401);
    const json = (await res.json()) as {
      ok: boolean;
      error: string;
      requestedUsername: string;
    };
    expect(json.ok).toBe(false);
    expect(json.error).toContain("invalid credentials");
    expect(json.requestedUsername).toBe("ghost_user");
  });

  it("username 欠如時は 400 を返す", async () => {
    const app = createApp();
    const res = await app.request("/totp/login-replay", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(400);
    const json = (await res.json()) as { ok: boolean; error: string };
    expect(json.ok).toBe(false);
    expect(json.error).toContain("username");
  });

  it("invalid JSON body は 400 を返す", async () => {
    const app = createApp();
    const res = await app.request("/totp/login-replay", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "not-json",
    });
    expect(res.status).toBe(400);
    const json = (await res.json()) as { ok: boolean; error: string };
    expect(json.ok).toBe(false);
    expect(json.error).toBe("invalid_json_body");
  });
});
