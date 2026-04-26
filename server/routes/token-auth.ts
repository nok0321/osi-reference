import { Hono } from "hono";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { v4 as uuidv4 } from "uuid";
import { getDb } from "../db/schema.js";
import { parseBody, tokenLoginSchema, tokenRefreshSchema, tokenAttackReplaySchema } from "../validation.js";
import type { UserRow, RefreshTokenRow } from "../../shared/api-types.js";
import { runAttackScenario, maskSecret } from "../utils/attack-runner.js";

const REFRESH_TTL_DAYS = 7;
const REFRESH_TTL_MS = REFRESH_TTL_DAYS * 24 * 60 * 60 * 1000;

export const tokenAuthRoutes = new Hono();

const JWT_SECRET = "osi-demo-token-auth-secret";
const REFRESH_SECRET = "osi-demo-refresh-secret";

tokenAuthRoutes.post("/login", async (c) => {
  const parsed = await parseBody(c, tokenLoginSchema);
  if ("error" in parsed) return parsed.error;
  const { username, password } = parsed.data;
  const trace = c.get("trace");
  const db = getDb();

  const user = db.prepare("SELECT id, username, password_hash FROM users WHERE username = ?").get(username) as UserRow | undefined;
  trace.addDbQuery({
    sql: "SELECT id, username, password_hash FROM users WHERE username = ?",
    params: [username],
    rows: user ? [{ id: user.id, username: user.username }] : [],
    ms: 0,
  });

  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return c.json({ success: false, error: "Invalid credentials" }, 401);
  }

  const accessToken = jwt.sign(
    { sub: user.id, username: user.username, type: "access" },
    JWT_SECRET,
    { expiresIn: "15m" }
  );
  trace.addCryptoOp({
    op: "jwt.sign(accessToken)",
    input: JSON.stringify({ sub: user.id, username: user.username, type: "access" }),
    output: accessToken.substring(0, 40) + "...",
    algo: "HS256",
    detail: `Secret: "${JWT_SECRET.substring(0, 15)}..." / Expires: 15 minutes`,
  });

  const jti = uuidv4();
  const refreshToken = jwt.sign(
    { sub: user.id, type: "refresh", jti },
    REFRESH_SECRET,
    { expiresIn: `${REFRESH_TTL_DAYS}d` }
  );
  const refreshExpiresAt = new Date(Date.now() + REFRESH_TTL_MS).toISOString();
  db.prepare(
    "INSERT INTO refresh_tokens (jti, user_id, expires_at) VALUES (?, ?, ?)"
  ).run(jti, user.id, refreshExpiresAt);
  trace.addDbQuery({
    sql: "INSERT INTO refresh_tokens (jti, user_id, expires_at) VALUES (?, ?, ?)",
    params: [jti, user.id, refreshExpiresAt],
    ms: 0,
  });
  trace.addCryptoOp({
    op: "jwt.sign(refreshToken)",
    input: JSON.stringify({ sub: user.id, type: "refresh", jti }),
    output: refreshToken.substring(0, 40) + "...",
    algo: "HS256",
    detail: `Secret: "${REFRESH_SECRET.substring(0, 15)}..." / Expires: ${REFRESH_TTL_DAYS} days / jti stored in DB for revocation & rotation`,
  });

  return c.json({
    success: true,
    data: {
      accessToken,
      refreshToken,
      expiresIn: 900,
      tokenType: "Bearer",
      user: { id: user.id, username: user.username },
    },
  });
});

tokenAuthRoutes.get("/profile", (c) => {
  const trace = c.get("trace");
  const authHeader = c.req.header("Authorization");

  trace.addSessionOp({
    action: "READ_HEADER",
    data: { name: "Authorization", value: authHeader || "(not found)" },
  });

  if (!authHeader?.startsWith("Bearer ")) {
    return c.json({ success: false, error: "No Bearer token" }, 401);
  }

  const token = authHeader.slice(7);
  if (!token) {
    return c.json({ success: false, error: "Empty Bearer token" }, 401);
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as unknown as { sub: number; username: string; type: string };

    // Reject refresh tokens used as access tokens
    if (decoded.type && decoded.type !== "access") {
      return c.json({ success: false, error: "Invalid token type — expected access token" }, 401);
    }

    trace.addCryptoOp({
      op: "jwt.verify(accessToken)",
      input: token.substring(0, 30) + "...",
      output: "VALID ✓",
      algo: "HS256",
    });
    return c.json({
      success: true,
      data: { user: { id: decoded.sub, username: decoded.username }, decoded },
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Unknown error";
    trace.addCryptoOp({
      op: "jwt.verify(accessToken)",
      input: token.substring(0, 30) + "...",
      output: `INVALID ✗ — ${message}`,
      algo: "HS256",
    });
    return c.json({ success: false, error: message }, 401);
  }
});

tokenAuthRoutes.post("/refresh", async (c) => {
  const parsed = await parseBody(c, tokenRefreshSchema);
  if ("error" in parsed) return parsed.error;
  const { refreshToken } = parsed.data;
  const trace = c.get("trace");

  try {
    const decoded = jwt.verify(refreshToken, REFRESH_SECRET) as unknown as { sub: number; type: string; jti: string };

    if (decoded.type !== "refresh") {
      return c.json({ success: false, error: "Invalid token type — expected refresh token" }, 401);
    }
    if (!decoded.jti) {
      return c.json({ success: false, error: "Refresh token missing jti" }, 401);
    }

    trace.addCryptoOp({
      op: "jwt.verify(refreshToken)",
      input: refreshToken.substring(0, 30) + "...",
      output: "VALID ✓",
      algo: "HS256",
    });

    const db = getDb();

    // Atomically consume the refresh token: only succeeds if jti exists, not revoked, not expired.
    // UPDATE ... WHERE prevents TOCTOU race between concurrent refresh requests using the same token.
    // SEC FINDING-6 (E-3 拡張): is_attack_sim = 0 で攻撃シミュレーション由来のトークンを正常系から除外。
    const consumeResult = db
      .prepare(
        "UPDATE refresh_tokens SET revoked = 1 WHERE jti = ? AND revoked = 0 AND expires_at > datetime('now') AND is_attack_sim = 0"
      )
      .run(decoded.jti);
    trace.addDbQuery({
      sql: "UPDATE refresh_tokens SET revoked = 1 WHERE jti = ? AND revoked = 0 AND expires_at > datetime('now') AND is_attack_sim = 0",
      params: [decoded.jti],
      rows: [{ changes: consumeResult.changes }],
      ms: 0,
    });
    if (consumeResult.changes === 0) {
      return c.json({ success: false, error: "Refresh token revoked, reused, or expired" }, 401);
    }

    const user = db.prepare("SELECT id, username FROM users WHERE id = ?").get(decoded.sub) as Pick<UserRow, "id" | "username"> | undefined;
    if (!user) {
      return c.json({ success: false, error: "User not found" }, 401);
    }

    const newAccessToken = jwt.sign(
      { sub: user.id, username: user.username, type: "access" },
      JWT_SECRET,
      { expiresIn: "15m" }
    );
    trace.addCryptoOp({
      op: "jwt.sign(newAccessToken)",
      input: JSON.stringify({ sub: user.id, username: user.username }),
      output: newAccessToken.substring(0, 40) + "...",
      algo: "HS256",
    });

    // Rotation: issue a new refresh token with a new jti
    const newJti = uuidv4();
    const newRefreshToken = jwt.sign(
      { sub: user.id, type: "refresh", jti: newJti },
      REFRESH_SECRET,
      { expiresIn: `${REFRESH_TTL_DAYS}d` }
    );
    const newRefreshExpiresAt = new Date(Date.now() + REFRESH_TTL_MS).toISOString();
    db.prepare(
      "INSERT INTO refresh_tokens (jti, user_id, expires_at) VALUES (?, ?, ?)"
    ).run(newJti, user.id, newRefreshExpiresAt);
    trace.addCryptoOp({
      op: "jwt.sign(rotatedRefreshToken)",
      input: JSON.stringify({ sub: user.id, type: "refresh", jti: newJti }),
      output: newRefreshToken.substring(0, 40) + "...",
      algo: "HS256",
      detail: "Rotation: old jti revoked, new jti issued",
    });

    return c.json({
      success: true,
      data: { accessToken: newAccessToken, refreshToken: newRefreshToken, expiresIn: 900, tokenType: "Bearer" },
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Unknown error";
    return c.json({ success: false, error: message }, 401);
  }
});

/**
 * 攻撃デモルート: session-vs-token タブ
 *
 * 【教育目的専用】
 * このコードは OSI 参照アプリの教材機能として、
 * ローカル環境の固定シードデータに対する攻撃シミュレーションを提供します。
 *
 * - 外部ネットワークへのリクエストは行いません
 * - 実 CVE のエクスプロイトコードは含みません
 * - 本番環境での使用は想定していません
 *
 * 対象 CWE: CWE-294
 * 対象 CAPEC: CAPEC-60
 * 関連設計書: DESIGN/13-attack-session-token.md
 * 安全装置: DESIGN/04-safety-guardrails.md
 */

// ── Scenario C: トークンリプレイ攻撃 ──
type TokenReplayExtra = {
  accessTokenPreview: string;
  victimUsername: string;
  issuedAtSec: number;
  expiresInSec: number;
  scenarioDelaySec: number;
  immediateReplayValid: boolean;
  delayedReplayValid: boolean;
  delayedReplayError: string;
  rotationNote: string;
  rotationNoteJa: string;
  /** ROB-N2: seed_alice が DB に存在しなかったため脆弱パスをスキップした場合 false。 */
  victimSeedFound: boolean;
};

tokenAuthRoutes.post("/attack/replay", (c) =>
  runAttackScenario<typeof tokenAttackReplaySchema, TokenReplayExtra>(c, {
    schema: tokenAttackReplaySchema,
    scenarioId: "token-replay",
    tabId: "session-vs-token",
    async handler({ body, trace, db, recordStep }) {
      const victimUsername = "seed_alice";
      const aliceUser = db
        .prepare("SELECT id, username FROM users WHERE username = ?")
        .get(victimUsername) as { id: number; username: string } | undefined;
      const expiresInSec = 900; // 15 minutes

      // ── ROB-N2: seed_alice 不在時の早期リターン ──
      // 実 DB INSERT を行わないため即座にはクラッシュしないが、`sub: 0` の偽トークンが
      // attack_log と extra に残ると教育価値が下がる。fixation と同じく
      // 5 ステップを "failed/blocked" で記録して outcome="succeeded" を保つ。
      if (!aliceUser) {
        for (const [stepIdx, kind] of [
          ["replay-1", "probe"],
          ["replay-2", "tamper"],
          ["replay-3", "forge"],
        ] as const) {
          recordStep({
            id: stepIdx,
            kind,
            label: `Skipped (${stepIdx}): seed user '${victimUsername}' not present in DB`,
            labelJa: `スキップ (${stepIdx}): シードユーザー '${victimUsername}' が DB に存在しません`,
            status: "failed",
            payload: {
              type: "generic",
              data: {
                reason: "seed_alice missing — cannot mint a victim access token for this scenario.",
              },
            },
            detailJa: "シード再投入 (POST /api/reset) を実行してください。",
            detail: "Run POST /api/reset to re-seed the database.",
          });
        }
        recordStep({
          id: "replay-4",
          kind: "exploit",
          label: "Vulnerable path skipped — no victim token to replay",
          labelJa: "脆弱パススキップ — リプレイ対象トークンがありません",
          status: "failed",
          payload: {
            type: "generic",
            data: { vulnerableReplaySkipped: true, reason: "seed_alice missing" },
          },
          detailJa: "被害者トークンが発行できないため、傍受/リプレイのシミュレーションを実行できません。",
          detail: "No victim token can be issued, so the interception/replay simulation cannot run.",
        });
        recordStep({
          id: "replay-5",
          kind: "verify",
          label: "Defended path also unaffected: expiry validation not exercised",
          labelJa: "堅牢パスも影響なし: 有効期限検証は未実行",
          status: "blocked",
          payload: {
            type: "generic",
            data: {
              blockedBy: "jwt_expiry_validation_enforced",
              note: "Defense (jwt expiry + refresh-token rotation) would still apply if seed were present.",
            },
          },
          detailJa: "堅牢実装は引き続き有効期限検証 + リフレッシュトークン回転で防御しますが、本実行ではトークン発行自体が空振りしました。",
          detail: "The defended implementation still enforces expiry + refresh-token rotation, but no token was minted in this run.",
        });
        return {
          blockedBy: "jwt_expiry_validation_enforced",
          summary:
            "Vulnerable path skipped because seed_alice is missing from the DB. Defense (JWT expiry + refresh-token rotation) would still apply if seed were present.",
          summaryJa:
            "このシナリオではシードユーザー seed_alice が DB に存在しないため脆弱パスを安全にスキップしました。堅牢実装 (JWT 有効期限検証 + リフレッシュトークン回転) は同攻撃を阻止する設計です。",
          extra: {
            accessTokenPreview: "(not issued)",
            victimUsername,
            issuedAtSec: 0,
            expiresInSec,
            scenarioDelaySec: body.scenarioDelay,
            immediateReplayValid: false,
            delayedReplayValid: false,
            delayedReplayError: "seed_alice missing",
            rotationNote:
              "Even if the access token were extended, the refresh_tokens.revoked flag (token-auth.ts) detects refresh-token reuse and forces re-authentication.",
            rotationNoteJa:
              "アクセストークンの寿命を延ばしても、refresh_tokens.revoked フラグ (token-auth.ts) が旧 jti の再使用を検出し、再認証を強制します。",
            victimSeedFound: false,
          } satisfies TokenReplayExtra,
          payload: {
            params: { scenarioDelay: body.scenarioDelay },
            result: {
              accessTokenMasked: null,
              immediateReplayValid: false,
              delayedReplayValid: false,
              delayedReplayError: "seed_alice missing",
            },
          },
        };
      }
      const aliceId = aliceUser.id;

      // ── Step 1: probe — seed_alice のアクセストークンを発行 (in-handler、実 jwt.sign)
      const issuedAtSec = Math.floor(Date.now() / 1000);
      const claims = { sub: aliceId, username: victimUsername, type: "access" };
      const accessToken = jwt.sign(claims, JWT_SECRET, { expiresIn: `${expiresInSec}s` });
      const accessTokenPreview = accessToken.substring(0, 40) + "...";
      trace.addCryptoOp({
        op: "jwt.sign(victim_access_token)",
        input: JSON.stringify(claims),
        output: accessTokenPreview,
        algo: "HS256",
        detail: `expiresIn: ${expiresInSec}s (15 minutes) / iat=${issuedAtSec}`,
      });
      recordStep({
        id: "replay-1",
        kind: "probe",
        label: "Victim logs in and obtains an access token",
        labelJa: "被害者がログインしてアクセストークンを取得",
        status: "success",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/token/login",
            body: { username: victimUsername, password: "(omitted)" },
          },
          response: {
            status: 200,
            body: {
              accessToken: accessTokenPreview,
              expiresIn: expiresInSec,
              tokenType: "Bearer",
            },
          },
        },
        detailJa: `${victimUsername} のアクセストークン (HS256, 15 分有効) が正常系として発行されました。`,
        detail: `${victimUsername}'s HS256 access token (15-minute lifetime) is issued through the legitimate flow.`,
      });

      // ── Step 2: tamper — 攻撃者が MitM/XSS でトークン傍受 (シミュレーション)
      recordStep({
        id: "replay-2",
        kind: "tamper",
        label: "Attacker intercepts the access token (simulated MitM/XSS)",
        labelJa: "攻撃者が MitM / XSS でアクセストークンを傍受 (シミュレーション)",
        status: "success",
        payload: {
          type: "generic",
          data: {
            interceptionVector: "MitM (HTTP) または XSS による Authorization ヘッダ漏洩",
            interceptedTokenPreview: accessTokenPreview,
            note: "本デモでは外部リクエストを送信せず、傍受された状態をシミュレーションします",
          },
        },
        detailJa:
          "攻撃者は本来非公開のアクセストークンを傍受したと仮定します。実際の傍受は本デモでは行いません。",
        detail:
          "Assume the attacker has captured the access token (no real network interception is performed in this demo).",
      });

      // ── Step 3: forge — リプレイ用に保存
      recordStep({
        id: "replay-3",
        kind: "forge",
        label: "Attacker stores the stolen token for replay",
        labelJa: "攻撃者が盗んだトークンをリプレイ用に保存",
        status: "success",
        payload: {
          type: "generic",
          data: {
            storedTokenPreview: accessTokenPreview,
            replayPlan: { immediate: true, delayedSec: body.scenarioDelay },
            note: "scenarioDelay = 0 は即時リプレイ、scenarioDelay > 900 は有効期限超過リプレイ",
          },
        },
        detailJa:
          "攻撃者は同じトークンを 2 度使い回してリプレイ攻撃を試みます。",
        detail:
          "The attacker reuses the same token to attempt replay attacks at multiple points in time.",
      });

      // ── Step 4: exploit — 即時リプレイ (脆弱: 有効期限内のため成立)
      let immediateReplayValid = false;
      try {
        jwt.verify(accessToken, JWT_SECRET);
        immediateReplayValid = true;
        trace.addCryptoOp({
          op: "jwt.verify(immediate_replay)",
          input: accessTokenPreview,
          output: "VALID ✓ (replay accepted within expiry)",
          algo: "HS256",
          detail: "Immediate replay succeeds because the token is still within its 15-minute lifetime.",
        });
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : "Unknown";
        trace.addCryptoOp({
          op: "jwt.verify(immediate_replay)",
          input: accessTokenPreview,
          output: `INVALID ✗ — ${message}`,
          algo: "HS256",
        });
      }
      recordStep({
        id: "replay-4",
        kind: "exploit",
        label: "Vulnerable: immediate replay succeeds while token is still valid",
        labelJa: "脆弱版: 即時リプレイは有効期限内のため成立",
        status: immediateReplayValid ? "success" : "failed",
        payload: {
          type: "http",
          request: {
            method: "GET",
            url: "/api/token/profile",
            headers: { Authorization: `Bearer ${accessTokenPreview}` },
          },
          response: {
            status: immediateReplayValid ? 200 : 401,
            body: immediateReplayValid
              ? {
                  user: { username: victimUsername },
                  note: "この実装は脆弱です: 短寿命設計でない場合、傍受されたトークンは有効期限内ずっと再使用可能",
                }
              : { error: "Token unexpectedly invalid" },
          },
        },
        detailJa: `この実装は脆弱です: アクセストークンは ${expiresInSec} 秒間有効なため、傍受された直後のリプレイは成立します。`,
        detail: `This implementation is vulnerable: because the access token is valid for ${expiresInSec} seconds, replay immediately after interception succeeds.`,
      });

      // ── Step 5: verify — 有効期限後リプレイ (堅牢: TokenExpiredError で拒否)
      // SEC-1/SEC-4: jsonwebtoken の clockTimestamp は「秒単位 (NOT ms) の現在時刻 (Unix epoch sec)」を上書きする。
      //              ライブラリは内部で Math.floor(Date.now()/1000) の代わりに渡された値を使い、
      //              RFC 7519 §4.1.4 準拠で `clockTimestamp >= exp` なら TokenExpiredError を投げる。
      // SEC-1: zod スキーマは scenarioDelay の min=0 (UI で「即時リプレイ」も指定可能にするため) を許容するが、
      //        本シナリオは「有効期限超過リプレイの拒否」が verify ステップの教育目的なので、
      //        scenarioDelay < expiresInSec+1 の場合は最低 expiresInSec+1 秒進めて確実に blocked を観測させる。
      //        scenarioDelay 自体はユーザー指定値として `extra.scenarioDelaySec` に保持し、
      //        実際に verify で進めた秒数は `verifyDelay` (Step 5 の payload `note` に明示) に分離する。
      const verifyDelay = Math.max(body.scenarioDelay, expiresInSec + 1);
      const fakeNow = issuedAtSec + verifyDelay;
      let delayedReplayValid = false;
      let delayedReplayError = "";
      try {
        jwt.verify(accessToken, JWT_SECRET, { clockTimestamp: fakeNow });
        delayedReplayValid = true;
        delayedReplayError = "";
      } catch (err: unknown) {
        delayedReplayError = err instanceof Error ? err.message : "Unknown";
      }
      trace.addCryptoOp({
        op: "jwt.verify(delayed_replay)",
        input: accessTokenPreview,
        output: delayedReplayValid
          ? "VALID ✓ (UNEXPECTED)"
          : `EXPIRED ✗ — ${delayedReplayError}`,
        algo: "HS256",
        detail: `Simulated time offset: +${verifyDelay}s from issuance (clockTimestamp=${fakeNow}). Token expires at iat+${expiresInSec}s.`,
      });
      recordStep({
        id: "replay-5",
        kind: "verify",
        label: "Defended: delayed replay rejected by JWT expiry validation",
        labelJa: "堅牢版: 有効期限超過リプレイが JWT 検証で拒否",
        status: delayedReplayValid ? "failed" : "blocked",
        payload: {
          type: "http",
          request: {
            method: "GET",
            url: "/api/token/profile",
            headers: { Authorization: `Bearer ${accessTokenPreview}` },
          },
          response: {
            status: 401,
            body: {
              error: delayedReplayError || "jwt expired",
              blockedBy: "jwt_expiry_validation_enforced",
              note: `clockTimestamp=${fakeNow} (+${verifyDelay}s from issuance) — token has expired (lifetime ${expiresInSec}s).`,
            },
          },
        },
        detailJa: `堅牢版: 短寿命 (${expiresInSec} 秒) のアクセストークンは有効期限を過ぎると jwt.verify が TokenExpiredError を投げて拒否します。さらに refresh_tokens.revoked による回転防御も有効です。`,
        detail: `Defended: short-lived (${expiresInSec}s) access tokens are rejected by jwt.verify after expiry (TokenExpiredError). Refresh-token rotation via refresh_tokens.revoked provides an additional defense layer.`,
      });

      return {
        blockedBy: "jwt_expiry_validation_enforced",
        summary:
          "The vulnerable replay succeeded within the token's 15-minute lifetime. The defended replay (after expiry) was rejected by JWT expiry validation, and refresh-token rotation provides a second defense layer.",
        summaryJa:
          "この実装は脆弱です: アクセストークンの有効期限内 (15 分) であれば、傍受されたトークンでリプレイ攻撃が成立します。堅牢版では 15 分後の検証で TokenExpiredError により拒否され、リフレッシュトークン回転 (refresh_tokens.revoked) によって追加の防御層が機能します。",
        extra: {
          accessTokenPreview,
          victimUsername,
          issuedAtSec,
          expiresInSec,
          scenarioDelaySec: body.scenarioDelay,
          immediateReplayValid,
          delayedReplayValid,
          delayedReplayError,
          rotationNote:
            "Even if the access token were extended, the refresh_tokens.revoked flag (token-auth.ts) detects refresh-token reuse and forces re-authentication.",
          rotationNoteJa:
            "アクセストークンの寿命を延ばしても、refresh_tokens.revoked フラグ (token-auth.ts) が旧 jti の再使用を検出し、再認証を強制します。",
          victimSeedFound: true,
        } satisfies TokenReplayExtra,
        payload: {
          params: { scenarioDelay: body.scenarioDelay },
          result: {
            accessTokenMasked: maskSecret(accessToken),
            immediateReplayValid,
            delayedReplayValid,
            delayedReplayError,
          },
        },
      };
    },
  })
);
