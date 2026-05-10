/**
 * victim-web 単体テスト: POST /rbac/users/profile (rbac-idor 脆弱エンドポイント)
 *
 * orchestrator を介さずに victim-web 単体の脆弱性が成立することを直接確認する。
 * orchestrator 経由の e2e は server/__tests__/scenarios/rbac-idor.test.ts で別途検証する。
 *
 * DESIGN/32 §4.5 / §8.1 (Phase 2 PR-2 で追記): "POST /rbac/users/profile — owner_id チェックなしでフルレコードが返ること"
 */
import { describe, it, expect } from "vitest";
import { Hono } from "hono";
import { rbacVulnRoutes } from "../src/routes/rbac-vuln.js";

function createApp() {
  const app = new Hono();
  app.route("/rbac", rbacVulnRoutes);
  return app;
}

describe("victim-web: POST /rbac/users/profile (CWE-639 rbac-idor)", () => {
  it("攻撃者 (charlie=3) が他ユーザー (alice=1) の id を送ると 200 + フルレコードを返す (脆弱性の核心)", async () => {
    const app = createApp();
    const res = await app.request("/rbac/users/profile", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ victimId: 1 }),
    });
    expect(res.status).toBe(200);
    const json = (await res.json()) as {
      ok: boolean;
      user: { id: number; username: string; email: string; role: string; ownerId: number };
      leakedFields: string[];
      note?: string;
    };
    expect(json.ok).toBe(true);
    // owner_id チェックなしのため、攻撃者本人以外の全フィールドが漏洩する
    expect(json.user.id).toBe(1);
    expect(json.user.username).toBe("seed_alice");
    expect(json.user.email).toBe("alice@example.com");
    expect(json.user.role).toBe("viewer");
    expect(json.leakedFields).toEqual(
      expect.arrayContaining(["id", "username", "email", "role", "ownerId"]),
    );
    expect(json.note).toContain("CWE-639");
  });

  it("victimId をどの id に書き換えても 200 が返る (所有権検証が無いことの確認)", async () => {
    const app = createApp();
    const ids = [1, 2, 3, 4]; // alice / bob / charlie / admin
    for (const id of ids) {
      const res = await app.request("/rbac/users/profile", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ victimId: id }),
      });
      expect(res.status).toBe(200);
      const json = (await res.json()) as { ok: boolean; user: { id: number } };
      expect(json.ok).toBe(true);
      expect(json.user.id).toBe(id);
    }
  });

  it("シードに存在しない id (例: 99) は 404 を返す (脆弱性は変わらないが exploit パスは空振り)", async () => {
    const app = createApp();
    const res = await app.request("/rbac/users/profile", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ victimId: 99 }),
    });
    expect(res.status).toBe(404);
    const json = (await res.json()) as { ok: boolean; error: string; requestedVictimId: number };
    expect(json.ok).toBe(false);
    expect(json.error).toContain("not found");
    expect(json.requestedVictimId).toBe(99);
  });

  it("victimId 欠如時は 400 を返す (最小バリデーション)", async () => {
    const app = createApp();
    const res = await app.request("/rbac/users/profile", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(400);
    const json = (await res.json()) as { ok: boolean; error: string };
    expect(json.ok).toBe(false);
    expect(json.error).toContain("victimId");
  });

  it("victimId が文字列の場合も 400 を返す (型バリデーション)", async () => {
    const app = createApp();
    const res = await app.request("/rbac/users/profile", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ victimId: "1" }),
    });
    expect(res.status).toBe(400);
    const json = (await res.json()) as { ok: boolean; error: string };
    expect(json.ok).toBe(false);
    expect(json.error).toContain("integer");
  });

  it("invalid JSON body は 400 を返す", async () => {
    const app = createApp();
    const res = await app.request("/rbac/users/profile", {
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
