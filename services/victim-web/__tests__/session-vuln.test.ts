/**
 * victim-web 単体テスト: POST /session/login (session-fixation 脆弱エンドポイント)
 *
 * orchestrator を介さずに victim-web 単体の脆弱性が成立することを直接確認する。
 * orchestrator 経由の e2e は server/__tests__/scenarios/session-fixation.test.ts で別途検証する。
 *
 * DESIGN/32 §4.6 / §8.1 (Phase 2 PR-3 で追記): "POST /session/login — Cookie の session_id が
 * 認証成功後も再生成されず、Set-Cookie / body.sessionId に同じ値が echo されること"
 */
import { describe, it, expect } from "vitest";
import { Hono } from "hono";
import { sessionVulnRoutes } from "../src/routes/session-vuln.js";

function createApp() {
  const app = new Hono();
  app.route("/session", sessionVulnRoutes);
  return app;
}

describe("victim-web: POST /session/login (CWE-384 session-fixation)", () => {
  it("攻撃者既知 SID を Cookie で送ると 200 + Set-Cookie に同じ SID が echo される (脆弱性の核心)", async () => {
    const app = createApp();
    const attackerKnownSid = "ATTACKER_KNOWN_SID_v1";
    const res = await app.request("/session/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Cookie: `session_id=${attackerKnownSid}`,
      },
      body: JSON.stringify({ username: "seed_alice" }),
    });
    expect(res.status).toBe(200);

    // Set-Cookie ヘッダに同じ SID が echo されている = 脆弱性の核心
    const setCookie = res.headers.get("set-cookie") ?? "";
    expect(setCookie).toContain(`session_id=${attackerKnownSid}`);
    expect(setCookie.toLowerCase()).toContain("httponly");

    const json = (await res.json()) as {
      ok: boolean;
      user: { id: number; username: string };
      sessionId: string;
      sessionIdSource: string;
      sessionRegenerated: boolean;
      note?: string;
    };
    expect(json.ok).toBe(true);
    expect(json.user.id).toBe(1);
    expect(json.user.username).toBe("seed_alice");
    expect(json.sessionId).toBe(attackerKnownSid);
    expect(json.sessionIdSource).toBe("reused-from-request-cookie");
    expect(json.sessionRegenerated).toBe(false);
    expect(json.note).toContain("CWE-384");
  });

  it("Cookie の session_id をどの値に書き換えても 200 + Set-Cookie で echo される (SID 再生成欠如の確認)", async () => {
    const app = createApp();
    const sids = ["custom-sid-1", "evil-sid-abc", "FIXATION_ATTACKER_SID_v1"];
    for (const sid of sids) {
      const res = await app.request("/session/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: `session_id=${sid}`,
        },
        body: JSON.stringify({ username: "seed_bob" }),
      });
      expect(res.status).toBe(200);
      const json = (await res.json()) as { ok: boolean; sessionId: string; user: { id: number } };
      expect(json.ok).toBe(true);
      expect(json.sessionId).toBe(sid);
      expect(json.user.id).toBe(2);
    }
  });

  it("Cookie が無い場合は 200 + 新規 SID を発行する (生成パスも動く)", async () => {
    const app = createApp();
    const res = await app.request("/session/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "seed_alice" }),
    });
    expect(res.status).toBe(200);
    const json = (await res.json()) as {
      ok: boolean;
      sessionId: string;
      sessionIdSource: string;
    };
    expect(json.ok).toBe(true);
    expect(json.sessionIdSource).toBe("newly-generated");
    expect(json.sessionId).toMatch(/^VICTIM_FRESH_/);

    const setCookie = res.headers.get("set-cookie") ?? "";
    expect(setCookie).toContain(`session_id=${json.sessionId}`);
  });

  it("シードに存在しないユーザー名は 401 を返す", async () => {
    const app = createApp();
    const res = await app.request("/session/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Cookie: "session_id=does-not-matter",
      },
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

  it("username 欠如時は 400 を返す (最小バリデーション)", async () => {
    const app = createApp();
    const res = await app.request("/session/login", {
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
    const res = await app.request("/session/login", {
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
