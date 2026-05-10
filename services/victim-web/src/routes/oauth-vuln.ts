/**
 * 脆弱エンドポイント: OAuth 2.0 (state CSRF)
 *
 * 【教育目的専用】
 * このファイルは OSI 参照アプリの教材機能として、
 * victim-net 内の固定シードデータに対する概念実証を提供します。
 *
 * - 外部ネットワークへのリクエストは行いません
 * - 実 CVE のエクスプロイトコードは含みません
 * - victim-net 外での動作は想定していません
 *
 * 対応 CWE: CWE-352 (state CSRF)
 * 堅牢実装: server/routes/oauth-sim.ts (state 必須検証)
 * 関連設計書: DESIGN/04-safety-guardrails.md, DESIGN/32-victim-web-spec.md §4.4
 */
import { Hono } from "hono";

export const oauthVulnRoutes = new Hono();

/**
 * 脆弱: state パラメータを一切検証せず認可コードを発行する。
 * 学習者が state なしで GET /oauth/authorize を送ると 200 + code が返る (CWE-352)。
 *
 * 期待入力: GET /oauth/authorize?client_id=<id>&redirect_uri=<uri>[&scope=<scope>][&state=<state>]
 * 期待挙動:
 *   - state なし → 200 + 認可コード発行 (脆弱性の核心)
 *   - state あり → 200 + 認可コード発行 (検証も無効化されているため state は単に echo)
 *   - client_id / redirect_uri 欠如 → 400
 *
 * 堅牢実装 (server/routes/oauth-sim.ts) では state パラメータが必須であり、
 * sessionStorage に保存した state と照合することで CSRF を防ぐ。
 */
oauthVulnRoutes.get("/authorize", (c) => {
  const clientId = c.req.query("client_id") ?? "";
  const redirectUri = c.req.query("redirect_uri") ?? "";
  const scope = c.req.query("scope") ?? "read";
  const state = c.req.query("state") ?? null;
  const responseType = c.req.query("response_type") ?? "code";

  if (!clientId || !redirectUri) {
    return c.json(
      { ok: false, error: "client_id and redirect_uri are required" },
      400,
    );
  }

  // ── 脆弱性の核心 ─────────────────────────────────────────────────
  // state の存在チェックも sessionStorage との照合も行わない。
  // state を完全に無視するため、攻撃者が被害者のコールバックに
  // 攻撃者制御の認可コードを注入できる (CWE-352)。
  // ───────────────────────────────────────────────────────────────

  // 教材用認可コード — 外部に漏洩しても無害な固定パターンの code 値
  const code = `vuln-code-${Date.now().toString(36)}-${Math.random()
    .toString(36)
    .slice(2, 10)}`;

  return c.json({
    ok: true,
    code,
    client_id: clientId,
    redirect_uri: redirectUri,
    scope,
    response_type: responseType,
    state_received: state, // null でも 200 を返す = 脆弱性
    note: "authorization code issued without verifying state (CWE-352 vulnerable: state parameter not enforced)",
  });
});
