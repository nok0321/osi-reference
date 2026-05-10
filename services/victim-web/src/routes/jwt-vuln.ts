/**
 * 脆弱エンドポイント: JWT
 *
 * 【教育目的専用】
 * - victim-net 内のシードデータに対する概念実証のみ
 * - 実 CVE のエクスプロイトコードは含まない
 *
 * 対応 CWE: CWE-345 (alg=none), CWE-347 (signature stripping)
 * 堅牢実装: server/routes/jwt-ops.ts (algorithms allowlist 必須)
 * 関連設計書: DESIGN/04-safety-guardrails.md, DESIGN/32-victim-web-spec.md,
 *             DESIGN/35-attack-storyboard.md (PR-A 波及で leakedToAttacker 追記)
 */
import { Hono } from "hono";
import jwt from "jsonwebtoken";

// 教材用弱秘密鍵 — victim-web は orchestrator の HS256_SECRET と独立した固定値を持つ
const WEAK_SECRET = "secret";

/**
 * 教材用シードユーザー + 漏えい想定データ。
 * alg=none で受理した偽造 claims の sub に対応するプロファイルを「攻撃者が
 * 認証バイパスで取得できるはずのデータ」として leakedToAttacker に詰める。
 * 全フィールドが _DEMO_ / @victim.local / REDACTED マーカー入りで本物の
 * secret は含まない (totp-vuln.ts と同パターン)。
 */
const SEED_USER_PROFILES: Readonly<
  Record<
    string,
    Readonly<{
      id: number;
      username: string;
      role: "user" | "admin";
      email: string;
      fullName: string;
      lastLogin: string;
      demoBalance: string;
      demoApiKey: string;
    }>
  >
> = {
  seed_alice: {
    id: 1,
    username: "seed_alice",
    role: "user",
    email: "alice@victim.local",
    fullName: "Alice Demo",
    lastLogin: "2026-05-09T22:14:03Z",
    demoBalance: "$12,345.67",
    demoApiKey: "sk_demo_alice_REDACTED_aXX1",
  },
  seed_bob: {
    id: 2,
    username: "seed_bob",
    role: "user",
    email: "bob@victim.local",
    fullName: "Bob Demo",
    lastLogin: "2026-05-09T18:02:11Z",
    demoBalance: "$987.65",
    demoApiKey: "sk_demo_bob_REDACTED_bYY2",
  },
  seed_admin: {
    id: 4,
    username: "seed_admin",
    role: "admin",
    email: "admin@victim.local",
    fullName: "Admin Demo",
    lastLogin: "2026-05-10T07:55:42Z",
    demoBalance: "$1,000,000.00",
    demoApiKey: "sk_demo_admin_REDACTED_dZZ4",
  },
};

export const jwtVulnRoutes = new Hono();

/**
 * 脆弱: algorithms オプション未指定。
 * alg=none トークンおよび任意のアルゴリズムが受理される (CWE-345)。
 *
 * 期待入力: { "token": "<JWT>" }
 * 期待挙動: 200 + { valid: true, claims: {...}, algorithm, leakedToAttacker?: {...} } を返す
 *           - 認証バイパスが成立した場合、claims.sub に対応する seed プロファイルを
 *             leakedToAttacker に詰めて「攻撃者がこの偽造 token で奪取できる範囲」を可視化
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
        const claims = JSON.parse(payloadJson) as Record<string, unknown>;
        const sub = typeof claims.sub === "string" ? claims.sub : null;
        const role = typeof claims.role === "string" ? claims.role : null;
        const profile = sub !== null ? SEED_USER_PROFILES[sub] ?? null : null;

        // 教材ヒント用ヘッダ (storyboard の data-leak visual で参照しやすい)
        c.header("X-Token-Alg", "none");
        if (sub !== null) c.header("X-Forged-Sub", sub);
        if (role !== null) c.header("X-Forged-Role", role);

        return c.json({
          valid: true,
          claims,
          algorithm: "none",
          note: "signature verification skipped (vulnerable: alg=none accepted)",
          leakedToAttacker: profile === null
            ? null
            : {
                userId: profile.id,
                username: profile.username,
                role: profile.role,
                email: profile.email,
                fullName: profile.fullName,
                lastLogin: profile.lastLogin,
                demoBalance: profile.demoBalance,
                demoApiKey: profile.demoApiKey,
              },
        });
      }
    } catch {
      // base64/JSON エラーなら HMAC 経路へフォールバック
    }
  }

  // alg=none 以外は弱秘密鍵で HMAC 検証 (algorithms オプション未指定 = 脆弱)
  try {
    const decoded = jwt.verify(token, WEAK_SECRET) as Record<string, unknown> | string;
    const claims = typeof decoded === "string" ? null : decoded;
    const sub = claims !== null && typeof claims.sub === "string" ? claims.sub : null;
    const role = claims !== null && typeof claims.role === "string" ? claims.role : null;
    const profile = sub !== null ? SEED_USER_PROFILES[sub] ?? null : null;

    c.header("X-Token-Alg", "HS256");
    if (sub !== null) c.header("X-Forged-Sub", sub);
    if (role !== null) c.header("X-Forged-Role", role);

    return c.json({
      valid: true,
      claims: decoded,
      algorithm: "HS256",
      leakedToAttacker: profile === null
        ? null
        : {
            userId: profile.id,
            username: profile.username,
            role: profile.role,
            email: profile.email,
            fullName: profile.fullName,
            lastLogin: profile.lastLogin,
            demoBalance: profile.demoBalance,
            demoApiKey: profile.demoApiKey,
          },
    });
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
