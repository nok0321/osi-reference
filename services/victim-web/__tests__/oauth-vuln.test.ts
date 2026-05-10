/**
 * victim-web 単体テスト: GET /oauth/authorize (oauth-state-csrf 脆弱エンドポイント)
 *
 * orchestrator を介さずに victim-web 単体の脆弱性が成立することを直接確認する。
 * orchestrator 経由の e2e は server/__tests__/scenarios/oauth-state-csrf.test.ts で別途検証する。
 *
 * DESIGN/32 §4.4 / §8.1 (必須テスト): "GET /oauth/authorize — state なしで認可コードが発行されること"
 */
import { describe, it, expect } from "vitest";
import { Hono } from "hono";
import { oauthVulnRoutes } from "../src/routes/oauth-vuln.js";

function createApp() {
  const app = new Hono();
  app.route("/oauth", oauthVulnRoutes);
  return app;
}

describe("victim-web: GET /oauth/authorize (CWE-352 oauth-state-csrf)", () => {
  it("state パラメータ無しで 200 + 認可コードを発行する (脆弱性の核心)", async () => {
    const app = createApp();
    const res = await app.request(
      "/oauth/authorize?client_id=demo-app&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=read",
      { method: "GET" },
    );
    expect(res.status).toBe(200);
    const json = (await res.json()) as {
      ok: boolean;
      code: string;
      state_received: string | null;
      note?: string;
    };
    expect(json.ok).toBe(true);
    expect(typeof json.code).toBe("string");
    expect(json.code).toMatch(/^vuln-code-/);
    // state なしでも認可コードが発行される = 脆弱性が成立している
    expect(json.state_received).toBeNull();
    expect(json.note).toContain("CWE-352");
  });

  it("state パラメータあり/なし で挙動が変わらないこと (state は単に echo される)", async () => {
    const app = createApp();
    const resWith = await app.request(
      "/oauth/authorize?client_id=demo-app&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&state=abc123",
      { method: "GET" },
    );
    const resWithout = await app.request(
      "/oauth/authorize?client_id=demo-app&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback",
      { method: "GET" },
    );
    expect(resWith.status).toBe(200);
    expect(resWithout.status).toBe(200);
    const jsonWith = (await resWith.json()) as { code: string; state_received: string | null };
    const jsonWithout = (await resWithout.json()) as { code: string; state_received: string | null };
    // state 値を検証していないため、両方とも認可コードが発行される
    expect(typeof jsonWith.code).toBe("string");
    expect(typeof jsonWithout.code).toBe("string");
    expect(jsonWith.state_received).toBe("abc123");
    expect(jsonWithout.state_received).toBeNull();
  });

  it("client_id 欠如時は 400 を返す (最小バリデーション)", async () => {
    const app = createApp();
    const res = await app.request(
      "/oauth/authorize?redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback",
      { method: "GET" },
    );
    expect(res.status).toBe(400);
    const json = (await res.json()) as { ok: boolean; error: string };
    expect(json.ok).toBe(false);
    expect(json.error).toContain("client_id");
  });

  it("redirect_uri 欠如時は 400 を返す", async () => {
    const app = createApp();
    const res = await app.request(
      "/oauth/authorize?client_id=demo-app",
      { method: "GET" },
    );
    expect(res.status).toBe(400);
    const json = (await res.json()) as { ok: boolean; error: string };
    expect(json.ok).toBe(false);
    expect(json.error).toContain("redirect_uri");
  });
});
