/**
 * 脆弱エンドポイント: TOTP Replay (CWE-294 / CAPEC-60)
 *
 * 【教育目的専用】
 * このファイルは OSI 参照アプリの教材機能として、
 * victim-net 内の固定シードデータに対する概念実証を提供します。
 *
 * - 外部ネットワークへのリクエストは行いません
 * - 実 CVE のエクスプロイトコードは含みません
 * - victim-net 外での動作は想定していません
 *
 * 対応 CWE: CWE-294 (Authentication Bypass by Capture-Replay)
 * 対応 CAPEC: CAPEC-60
 * 堅牢実装: server/routes/mfa-totp.ts (used_otps テーブルで再使用拒否)
 * 関連設計書: DESIGN/04-safety-guardrails.md, DESIGN/32-victim-web-spec.md §4.7,
 *             DESIGN/35-attack-storyboard.md (Phase 2 PR-4 で追記)
 */
import { Hono } from "hono";
import { computeTotp, currentCounter, verifyTotpWithDetail } from "../utils/totp.js";

export const totpVulnRoutes = new Hono();

/** 固定 demo secret (ASCII "Hi"+padding 等価の base32)。学習者が secret を省略した場合に使用。 */
const DEMO_TOTP_SECRET = "JBSWY3DPEHPK3PXP";

/**
 * 教材用シードユーザー + 漏えい想定データ。
 * 「攻撃者がアカウント乗っ取りで取得できるデータ」を 1 リクエストで可視化するため、
 * 各ユーザーに擬似個人情報 (email / 残高 / demoApiKey) を持たせる。
 * すべて _DEMO_ / @victim.local / REDACTED マーカー入りで、本物の secret は含まない。
 */
const SEED_USER_PROFILES: Readonly<
  Record<
    string,
    Readonly<{
      id: number;
      username: string;
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
    email: "alice@victim.local",
    fullName: "Alice Demo",
    lastLogin: "2026-05-09T22:14:03Z",
    demoBalance: "$12,345.67",
    demoApiKey: "sk_demo_alice_REDACTED_aXX1",
  },
  seed_bob: {
    id: 2,
    username: "seed_bob",
    email: "bob@victim.local",
    fullName: "Bob Demo",
    lastLogin: "2026-05-09T18:02:11Z",
    demoBalance: "$987.65",
    demoApiKey: "sk_demo_bob_REDACTED_bYY2",
  },
  seed_admin: {
    id: 4,
    username: "seed_admin",
    email: "admin@victim.local",
    fullName: "Admin Demo",
    lastLogin: "2026-05-10T07:55:42Z",
    demoBalance: "$1,000,000.00",
    demoApiKey: "sk_demo_admin_REDACTED_dZZ4",
  },
};

interface ParsedRequest {
  username: string;
  secret: string;
  /** true なら学習者が secret を明示的に送信した。false なら demo default 使用 */
  secretFromLearner: boolean;
  providedCode: string | null;
}

function parseRequest(body: unknown): { ok: true; data: ParsedRequest } | { ok: false; error: string } {
  if (typeof body !== "object" || body === null) {
    return { ok: false, error: "request body must be a JSON object" };
  }
  const obj = body as Record<string, unknown>;
  const usernameRaw = obj.username;
  if (typeof usernameRaw !== "string" || usernameRaw.length === 0) {
    return { ok: false, error: "username is required and must be a non-empty string" };
  }
  const secretRaw = obj.secret;
  const secretFromLearner = typeof secretRaw === "string" && secretRaw.length > 0;
  const secret = secretFromLearner ? (secretRaw as string) : DEMO_TOTP_SECRET;
  const codeRaw = obj.code;
  const providedCode = typeof codeRaw === "string" && codeRaw.length > 0 ? codeRaw : null;
  return { ok: true, data: { username: usernameRaw, secret, secretFromLearner, providedCode } };
}

/**
 * 脆弱: 学習者が送った username + secret を使い、victim が現在時刻 OTP を計算し、
 * 同じ OTP で 2 連続検証して両方 success を返す。
 * used_otps テーブルを持たない実装の脅威を 1 リクエストで体感させる (CWE-294)。
 *
 * 期待入力: POST /totp/login-replay
 *   body: { "username": "<seed_alice|seed_bob|seed_admin>", "secret"?: "<base32>", "code"?: "<6digits>" }
 * 期待挙動:
 *   - 既知 username + secret → 200 + computedOtp + victimLogin + attackerReplay + leakedToAttacker
 *   - 未知 username → 401
 *   - body 欠如 / 型違反 → 400
 *   - invalid JSON body → 400
 *
 * 堅牢実装 (server/routes/mfa-totp.ts) では (user_id, counter) を used_otps に記録し、
 * 同一 counter の再使用を拒否するため、第 2 回目の検証は failed になる。
 */
totpVulnRoutes.post("/login-replay", async (c) => {
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ ok: false, error: "invalid_json_body" }, 400);
  }

  const parsed = parseRequest(body);
  if (!parsed.ok) {
    return c.json({ ok: false, error: parsed.error }, 400);
  }
  const { username, secret, secretFromLearner, providedCode } = parsed.data;

  const profile = SEED_USER_PROFILES[username];
  if (!profile) {
    return c.json(
      { ok: false, error: "invalid credentials", requestedUsername: username },
      401,
    );
  }

  // ── 脆弱性の核心 ─────────────────────────────────────────────────
  // victim が「攻撃者が観測した OTP」のメタファーとして現在時刻 OTP を生成し、
  // 同じ OTP で 2 連続検証する。used_otps を記録しないため両方 success になる。
  // ───────────────────────────────────────────────────────────────
  const counter = currentCounter();
  const computed = computeTotp(secret, counter);
  const otpToReplay = providedCode ?? computed.code;

  const firstVerify = verifyTotpWithDetail(secret, otpToReplay);
  const secondVerify = verifyTotpWithDetail(secret, otpToReplay);

  // 両方検証成功 = 脆弱性が成立した
  const replaySucceeded =
    firstVerify.match !== null &&
    secondVerify.match !== null &&
    firstVerify.match.counter === secondVerify.match.counter;

  if (!replaySucceeded) {
    // providedCode が wrong などで一致しなかった場合のみ通る (教材的にはレア)
    return c.json(
      {
        ok: false,
        error: "otp_did_not_verify",
        computedOtp: computed.code,
        firstVerify: { match: firstVerify.match !== null },
        secondVerify: { match: secondVerify.match !== null },
        note: "Provided OTP did not match the current ±1 window. Try omitting `code` so victim computes the current OTP.",
      },
      400,
    );
  }

  const issuedAt = new Date().toISOString();
  const victimLogin = {
    authenticatedAs: profile.username,
    sessionId: `VICTIM_SESSION_${profile.username}_${counter.toString(36)}`,
    bearerToken: `VICTIM_TOKEN_${profile.username}_${Date.now().toString(36)}_a`,
    issuedAt,
    counterMatched: firstVerify.match!.counter,
  };
  const attackerReplay = {
    authenticatedAs: profile.username, // ← 攻撃者が被害者として認証された
    sessionId: `ATTACKER_SESSION_${profile.username}_${counter.toString(36)}`,
    bearerToken: `ATTACKER_TOKEN_${profile.username}_${Date.now().toString(36)}_b`,
    issuedAt,
    counterMatched: secondVerify.match!.counter,
  };

  const leakedToAttacker = {
    userId: profile.id,
    username: profile.username,
    email: profile.email,
    fullName: profile.fullName,
    lastLogin: profile.lastLogin,
    demoBalance: profile.demoBalance,
    demoApiKey: profile.demoApiKey,
  };

  // 教材ヒント用ヘッダ (storyboard の data-leak visual で参照しやすい)
  c.header("X-Computed-OTP", computed.code);
  c.header("X-Replay-Detected", "false");
  c.header("X-Counter", counter.toString());

  return c.json({
    ok: true,
    computedOtp: computed.code,
    totpCounter: counter,
    secretUsed: secretFromLearner ? "<learner-provided>" : "<demo-default>",
    victimLogin,
    attackerReplay,
    leakedToAttacker,
    replayDetected: false,
    usedOtpTracking: "absent",
    note:
      "CWE-294: Same OTP authenticated TWO independent sessions. The attacker now holds equivalent " +
      "account access as the victim. A defended server would record (user_id, counter) on first verify " +
      "and reject the second (see server/routes/mfa-totp.ts for the recommended implementation pattern).",
  });
});
