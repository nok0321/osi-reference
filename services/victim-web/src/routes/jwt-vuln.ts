/**
 * 脆弱エンドポイント: JWT
 *
 * 【教育目的専用】
 * - victim-net 内のシードデータに対する概念実証のみ
 * - 実 CVE のエクスプロイトコードは含まない
 *
 * 対応 CWE: CWE-345 (alg=none), CWE-347 (signature stripping)
 * 堅牢実装: server/routes/jwt-ops.ts (algorithms allowlist 必須)
 * 関連設計書: DESIGN/04-safety-guardrails.md, DESIGN/32-victim-web-spec.md
 */
import { Hono } from "hono";
import jwt from "jsonwebtoken";

// 教材用弱秘密鍵 — victim-web は orchestrator の HS256_SECRET と独立した固定値を持つ
const WEAK_SECRET = "secret";

export const jwtVulnRoutes = new Hono();

/**
 * 脆弱: algorithms オプション未指定。
 * alg=none トークンおよび任意のアルゴリズムが受理される (CWE-345)。
 *
 * 期待入力: { "token": "<JWT>" }
 * 期待挙動: 200 + { valid: true, claims: {...} } を返す (alg=none でも通過)
 */
jwtVulnRoutes.post("/verify", async (c) => {
  let body: { token?: unknown };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ valid: false, error: "Invalid JSON body" }, 400);
  }

  const token = typeof body.token === "string" ? body.token : null;
  if (!token) {
    return c.json({ valid: false, error: "token (string) is required" }, 400);
  }

  // alg=none を受理する独自実装。jsonwebtoken は { algorithms: ["none"] } を渡しても
  // 署名なしトークンを受理しない実装になっているため、教育目的で簡略パーサを書く。
  const segments = token.split(".");
  if (segments.length === 3) {
    try {
      const headerJson = Buffer.from(segments[0], "base64url").toString("utf8");
      const header = JSON.parse(headerJson) as { alg?: string };
      if (header.alg === "none" && segments[2] === "") {
        // 署名検証を完全にスキップ — これが alg=none 脆弱性の本質
        const payloadJson = Buffer.from(segments[1], "base64url").toString("utf8");
        const claims = JSON.parse(payloadJson);
        return c.json({
          valid: true,
          claims,
          algorithm: "none",
          note: "signature verification skipped (vulnerable: alg=none accepted)",
        });
      }
    } catch {
      // base64/JSON エラーなら HMAC 経路へフォールバック
    }
  }

  // alg=none 以外は弱秘密鍵で HMAC 検証 (algorithms オプション未指定 = 脆弱)
  try {
    const decoded = jwt.verify(token, WEAK_SECRET);
    return c.json({ valid: true, claims: decoded, algorithm: "HS256" });
  } catch (err) {
    return c.json(
      {
        valid: false,
        error: err instanceof Error ? err.message : "verification failed",
      },
      401,
    );
  }
});
