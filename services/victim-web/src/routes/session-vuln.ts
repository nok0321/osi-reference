/**
 * 脆弱エンドポイント: Session Fixation (CWE-384)
 *
 * 【教育目的専用】
 * このファイルは OSI 参照アプリの教材機能として、
 * victim-net 内の固定シードデータに対する概念実証を提供します。
 *
 * - 外部ネットワークへのリクエストは行いません
 * - 実 CVE のエクスプロイトコードは含みません
 * - victim-net 外での動作は想定していません
 *
 * 対応 CWE: CWE-384 (Session Fixation)
 * 対応 CAPEC: CAPEC-61
 * 堅牢実装: server/routes/session-auth.ts (POST /api/session/login の uuidv4() 再生成パス)
 * 関連設計書: DESIGN/04-safety-guardrails.md, DESIGN/32-victim-web-spec.md §4.6 (Phase 2 PR-3 で追記)
 */
import { Hono } from "hono";
import { getCookie, setCookie } from "hono/cookie";

export const sessionVulnRoutes = new Hono();

/**
 * 教材用シードユーザー (server/db/schema.ts の seed と意図的に整合させる)
 *
 * - charlie (id=3) が attacker、その他 3 ユーザー (alice / bob / admin) が victim 候補
 * - パスワード検証は教材簡素化のため省略 (victim 単体で再現できる脆弱性核心は SID 再生成欠如)
 */
const SEED_USERS: Readonly<
  Record<string, Readonly<{ id: number; username: string }>>
> = {
  seed_alice: { id: 1, username: "seed_alice" },
  seed_bob: { id: 2, username: "seed_bob" },
  attacker_charlie: { id: 3, username: "attacker_charlie" },
  seed_admin: { id: 4, username: "seed_admin" },
};

/**
 * 脆弱: ログインリクエストに `Cookie: session_id=...` が含まれていれば、
 * 認証成功後もその SID をそのまま再利用 (Set-Cookie で同じ値を echo)。
 *
 * 学習者が事前既知 SID (例: ATTACKER_KNOWN_SID_v1) を Cookie で送ると、
 * レスポンスの Set-Cookie / body.sessionId に同じ値が入って返り、
 * 「ログイン後に SID が再生成されない = 攻撃者の事前知識がそのまま有効」を観察できる (CWE-384)。
 *
 * 期待入力: POST /session/login
 *           headers: { Cookie?: "session_id=<attacker-known-sid>" }
 *           body:    { "username": "<seed_alice|seed_bob|seed_admin|attacker_charlie>" }
 * 期待挙動:
 *   - 既知ユーザー + Cookie あり → 200 + Set-Cookie に同じ SID を echo (脆弱性の核心)
 *   - 既知ユーザー + Cookie なし → 200 + 新規 SID を Set-Cookie で発行 (生成パスも動く)
 *   - 未知ユーザー → 401
 *   - body 欠如 / 型違反 → 400
 *   - invalid JSON body → 400
 *
 * 堅牢実装 (server/routes/session-auth.ts) では認証成功時に必ず uuidv4() で
 * 新規 SID を発行するため、攻撃者の事前 SID は無効化される。
 */
sessionVulnRoutes.post("/login", async (c) => {
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ ok: false, error: "invalid_json_body" }, 400);
  }

  if (typeof body !== "object" || body === null) {
    return c.json({ ok: false, error: "request body must be a JSON object" }, 400);
  }

  const usernameRaw = (body as { username?: unknown }).username;
  if (typeof usernameRaw !== "string" || usernameRaw.length === 0) {
    return c.json(
      { ok: false, error: "username is required and must be a non-empty string" },
      400,
    );
  }

  const user = SEED_USERS[usernameRaw];
  if (!user) {
    return c.json(
      { ok: false, error: "invalid credentials", requestedUsername: usernameRaw },
      401,
    );
  }

  // ── 脆弱性の核心 ─────────────────────────────────────────────────
  // リクエスト Cookie の session_id が存在すれば、認証後もそれをそのまま再利用する。
  // 「ログイン後の SID 再生成」をスキップするため、攻撃者が事前に知っている SID が
  // 認証済みセッションに紐付き、Set-Cookie で echo される (CWE-384)。
  // ───────────────────────────────────────────────────────────────
  const reusedSid = getCookie(c, "session_id");
  const sessionId = reusedSid ?? `VICTIM_FRESH_${Date.now().toString(36)}`;
  const sessionIdSource: "reused-from-request-cookie" | "newly-generated" =
    reusedSid ? "reused-from-request-cookie" : "newly-generated";

  // Set-Cookie に同じ SID を載せる (HttpOnly のみ、Secure は教材なので付けない)
  setCookie(c, "session_id", sessionId, {
    httpOnly: true,
    path: "/",
  });

  return c.json({
    ok: true,
    user,
    sessionId,
    sessionIdSource,
    sessionRegenerated: false,
    note:
      sessionIdSource === "reused-from-request-cookie"
        ? "session ID NOT regenerated after authentication (CWE-384 vulnerable: pre-known SID reused)"
        : "session ID generated for the first time, but no rotation occurs on subsequent logins (CWE-384 vulnerable behavior)",
  });
});
