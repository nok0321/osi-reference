/**
 * 脆弱エンドポイント: RBAC IDOR (Insecure Direct Object Reference)
 *
 * 【教育目的専用】
 * このファイルは OSI 参照アプリの教材機能として、
 * victim-net 内の固定シードデータに対する概念実証を提供します。
 *
 * - 外部ネットワークへのリクエストは行いません
 * - 実 CVE のエクスプロイトコードは含みません
 * - victim-net 外での動作は想定していません
 *
 * 対応 CWE: CWE-639 (Authorization Bypass Through User-Controlled Key)
 * 対応 CAPEC: CAPEC-77
 * 堅牢実装: server/routes/rbac.ts (POST /api/rbac/attack/idor の defended パス: WHERE owner_id = ?)
 * 関連設計書: DESIGN/04-safety-guardrails.md, DESIGN/32-victim-web-spec.md §4.5 (Phase 2 PR-2 で追記)
 */
import { Hono } from "hono";

export const rbacVulnRoutes = new Hono();

/**
 * 教材用シードユーザー (server/routes/rbac.ts の SEED_USERS と意図的に整合させる)
 *
 * - charlie (id=3) が attacker、その他 3 ユーザー (alice / bob / admin) が victim 候補
 * - 全フィールドが固定文字列で、外部に漏洩しても無害
 */
const SEED_USERS: Readonly<
  Record<
    number,
    Readonly<{ id: number; username: string; email: string; role: string; ownerId: number }>
  >
> = {
  1: { id: 1, username: "seed_alice", email: "alice@example.com", role: "viewer", ownerId: 1 },
  2: { id: 2, username: "seed_bob", email: "bob@example.com", role: "editor", ownerId: 2 },
  3: { id: 3, username: "attacker_charlie", email: "charlie@example.com", role: "viewer", ownerId: 3 },
  4: { id: 4, username: "seed_admin", email: "admin@example.com", role: "admin", ownerId: 4 },
};

/**
 * 脆弱: ユーザー制御の victimId をそのまま使用し、所有権チェックを行わずユーザー全列を返却。
 * 学習者が POST /rbac/users/profile に他ユーザーの id を送ると 200 + フルレコードが返る (CWE-639)。
 *
 * 期待入力: POST /rbac/users/profile  body: { "victimId": <number> }
 * 期待挙動:
 *   - 既知シード id (1-4) → 200 + 当該ユーザーの全フィールド (脆弱性の核心)
 *   - 未知 id (例: 99) → 404 + ok:false (DB 上不在のためエクスプロイトパスが空振り)
 *   - victimId 欠如 / 数値以外 → 400
 *
 * 堅牢実装 (server/routes/rbac.ts の defended パス) では
 *   SELECT ... WHERE id = ? AND owner_id = ?
 * によって認証済みユーザー以外のレコードは 0 行となり 403 が返る。
 */
rbacVulnRoutes.post("/users/profile", async (c) => {
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ ok: false, error: "invalid_json_body" }, 400);
  }

  if (typeof body !== "object" || body === null) {
    return c.json({ ok: false, error: "request body must be a JSON object" }, 400);
  }

  const victimIdRaw = (body as { victimId?: unknown }).victimId;
  if (typeof victimIdRaw !== "number" || !Number.isInteger(victimIdRaw)) {
    return c.json({ ok: false, error: "victimId is required and must be an integer" }, 400);
  }

  // ── 脆弱性の核心 ─────────────────────────────────────────────────
  // owner_id チェックを一切行わず、victimId をそのまま id 検索のキーとして使用する。
  // 攻撃者が認証済みかどうか、リソースの所有者かどうかは問われない (CWE-639)。
  // ───────────────────────────────────────────────────────────────
  const user = SEED_USERS[victimIdRaw as keyof typeof SEED_USERS];
  if (!user) {
    return c.json(
      {
        ok: false,
        error: "user not found",
        requestedVictimId: victimIdRaw,
      },
      404,
    );
  }

  return c.json({
    ok: true,
    user,
    leakedFields: Object.keys(user),
    note: "user record returned without ownership check (CWE-639 vulnerable: missing WHERE owner_id check)",
  });
});
