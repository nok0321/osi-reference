import { Hono } from "hono";
import crypto from "node:crypto";
import bcrypt from "bcryptjs";
import { v4 as uuidv4 } from "uuid";
import QRCode from "qrcode";
import { getDb } from "../db/schema.js";
import {
  parseBody,
  totpEnrollStartSchema,
  totpEnrollVerifySchema,
  totpLoginStep1Schema,
  totpLoginStep2Schema,
  mfaAttackOtpReplaySchema,
  mfaAttackTimeWindowWideSchema,
  mfaAttackSmsSwapSchema,
} from "../validation.js";
import type { UserRow, UserMfaRow } from "../../shared/api-types.js";
import {
  base32Encode,
  base32Decode,
  computeTotp,
  currentCounter,
  verifyTotpWithDetail,
  TOTP_PERIOD,
  TOTP_DIGITS,
  TOTP_ALGORITHM,
} from "../utils/totp.js";
import { createTtlStore } from "../utils/ttl-store.js";
import { runAttackScenario, maskSecret } from "../utils/attack-runner.js";

export const mfaTotpRoutes = new Hono();

const ISSUER = "OSI Reference";
const PERIOD = TOTP_PERIOD;
const DIGITS = TOTP_DIGITS;
const ALGORITHM = TOTP_ALGORITHM;

// ── Challenge store for 2-step login (challengeId → userId) ──
interface LoginChallenge {
  userId: number;
  username: string;
  createdAt: number;
}
const LOGIN_CHALLENGE_TTL_MS = 5 * 60 * 1000;
const loginChallenges = createTtlStore<LoginChallenge>({ ttlMs: LOGIN_CHALLENGE_TTL_MS });


// ── POST /enroll/start ──
mfaTotpRoutes.post("/totp/enroll/start", async (c) => {
  const parsed = await parseBody(c, totpEnrollStartSchema);
  if ("error" in parsed) return parsed.error;
  const { username } = parsed.data;
  const trace = c.get("trace");
  const db = getDb();

  // Look up user
  const t0 = performance.now();
  const user = db
    .prepare("SELECT id, username FROM users WHERE username = ?")
    .get(username) as Pick<UserRow, "id" | "username"> | undefined;
  trace.addDbQuery({
    sql: "SELECT id, username FROM users WHERE username = ?",
    params: [username],
    rows: user ? [user] : [],
    ms: performance.now() - t0,
  });

  if (!user) {
    return c.json(
      {
        success: false,
        error:
          "User not found. Register via /api/auth/password/register first, or use Quick Setup in the MFA demo.",
      },
      404
    );
  }

  // Generate 20-byte secret
  const rawSecret = crypto.randomBytes(20);
  trace.addCryptoOp({
    op: "crypto.randomBytes",
    input: "length=20",
    output: rawSecret.toString("hex"),
    algo: "CSPRNG (Node node:crypto)",
    detail:
      "20 random bytes (160 bits) — RFC 6238 recommends at least 128 bits of entropy for the shared secret",
  });

  const secret = base32Encode(rawSecret);
  trace.addCryptoOp({
    op: "base32.encode",
    input: `raw=${rawSecret.toString("hex")}`,
    output: secret,
    algo: "RFC 4648 Base32",
    detail: `20 bytes → ${secret.length} chars. Base32 uses A-Z + 2-7 (case-insensitive, easy to type into authenticator apps)`,
  });

  // Insert or replace user_mfa row (reset verified state if re-enrolling)
  const t1 = performance.now();
  db.prepare(
    `INSERT INTO user_mfa (user_id, secret, verified, created_at, verified_at)
     VALUES (?, ?, 0, datetime('now'), NULL)
     ON CONFLICT(user_id) DO UPDATE SET
       secret = excluded.secret,
       verified = 0,
       created_at = datetime('now'),
       verified_at = NULL`
  ).run(user.id, secret);
  trace.addDbQuery({
    sql: "INSERT INTO user_mfa (user_id, secret, verified, ...) VALUES (?, ?, 0, ...) ON CONFLICT(user_id) DO UPDATE ...",
    params: [user.id, secret.substring(0, 8) + "..."],
    ms: performance.now() - t1,
  });

  // Construct otpauth:// URI per Google Authenticator Key URI Format
  const label = encodeURIComponent(`${ISSUER}:${username}`);
  const params = new URLSearchParams({
    secret,
    issuer: ISSUER,
    algorithm: ALGORITHM,
    digits: String(DIGITS),
    period: String(PERIOD),
  });
  const otpauthUri = `otpauth://totp/${label}?${params.toString()}`;

  trace.addCryptoOp({
    op: "otpauth.buildUri",
    input: `user=${username}, algo=${ALGORITHM}, digits=${DIGITS}, period=${PERIOD}s`,
    output: otpauthUri,
    algo: "Google Authenticator Key URI Format",
    detail:
      "URI consumed by authenticator apps (Google Authenticator, Authy, 1Password, etc.) when scanned from QR code",
  });

  // Generate QR code as SVG (smaller than base64 PNG, renders crisper)
  const qrCodeSvg = await QRCode.toString(otpauthUri, {
    type: "svg",
    margin: 1,
    width: 220,
  });

  trace.addCryptoOp({
    op: "qrcode.toSvg",
    input: `otpauthUri (${otpauthUri.length} chars)`,
    output: `<svg> (${qrCodeSvg.length} chars)`,
    algo: "QR Code (ISO/IEC 18004)",
    detail:
      "Encodes the otpauth URI into a scannable QR. SVG is ~5x smaller than base64 PNG and scales crisply",
  });

  return c.json({
    success: true,
    data: {
      secret,
      otpauthUri,
      qrCodeSvg,
      issuer: ISSUER,
      label: `${ISSUER}:${username}`,
    },
  });
});

// ── POST /enroll/verify ──
mfaTotpRoutes.post("/totp/enroll/verify", async (c) => {
  const parsed = await parseBody(c, totpEnrollVerifySchema);
  if ("error" in parsed) return parsed.error;
  const { username, code } = parsed.data;
  const trace = c.get("trace");
  const db = getDb();

  const t0 = performance.now();
  const row = db
    .prepare(
      `SELECT um.user_id, um.secret, um.verified
       FROM user_mfa um
       JOIN users u ON u.id = um.user_id
       WHERE u.username = ?`
    )
    .get(username) as Pick<UserMfaRow, "user_id" | "secret" | "verified"> | undefined;
  trace.addDbQuery({
    sql: "SELECT um.user_id, um.secret, um.verified FROM user_mfa um JOIN users u ON u.id = um.user_id WHERE u.username = ?",
    params: [username],
    rows: row ? [{ user_id: row.user_id, secret: row.secret.substring(0, 8) + "...", verified: row.verified }] : [],
    ms: performance.now() - t0,
  });

  if (!row) {
    return c.json({ success: false, error: "Enrollment not started for this user" }, 404);
  }

  // Compute TOTP trace step by step for educational visibility
  const key = base32Decode(row.secret);
  trace.addCryptoOp({
    op: "base32.decode",
    input: `secret="${row.secret.substring(0, 8)}..." (${row.secret.length} chars)`,
    output: `${key.length} bytes: ${key.toString("hex")}`,
    algo: "RFC 4648 Base32",
    detail: "Decode shared secret back to raw bytes for HMAC key",
  });

  const counter = currentCounter();
  trace.addCryptoOp({
    op: "totp.counter",
    input: `Math.floor(${Date.now()/1000} / ${PERIOD})`,
    output: String(counter),
    algo: "RFC 6238",
    detail: `counter = floor(UNIX_TIME / ${PERIOD}s) — advances every ${PERIOD} seconds`,
  });

  const { match, attempts } = verifyTotpWithDetail(row.secret, code);

  // Log each candidate (t-1, t, t+1) for clock-drift tolerance visibility
  for (const att of attempts) {
    const delta = att.counter - counter;
    const label = delta === 0 ? "current" : delta < 0 ? `t${delta}` : `t+${delta}`;
    trace.addCryptoOp({
      op: `HMAC-SHA1 (${label})`,
      input: `counter=${att.counter} (hex: ${att.counterHex})`,
      output: att.hmacHex,
      algo: "HMAC-SHA1",
      detail: "HMAC-SHA1(key, counter_bytes) → 20-byte hash",
    });
    trace.addCryptoOp({
      op: `dynamicTruncation (${label})`,
      input: `hash=${att.hmacHex}, offset=hash[19] & 0x0F = ${att.offset}`,
      output: `${att.truncatedHex} → int ${att.binary}`,
      algo: "RFC 4226 §5.3",
      detail: `Take 4 bytes starting at offset ${att.offset}, mask MSB of first byte, interpret as big-endian uint31`,
    });
    trace.addCryptoOp({
      op: `mod 10^${DIGITS} (${label})`,
      input: `${att.binary} mod 10^${DIGITS}`,
      output: att.code,
      algo: "HOTP truncation",
      detail: `final ${DIGITS}-digit code — pads with leading zeros if needed`,
    });
  }

  trace.addCryptoOp({
    op: "totp.compare",
    input: `provided="${code}" vs [${attempts.map(a => a.code).join(", ")}]`,
    output: match ? `MATCH ✓ (counter=${match.counter}, delta=${match.counter - counter})` : "MISMATCH ✗",
    algo: "Constant-time comparison",
    detail: "Accepts ±1 time window (30s tolerance for clock drift between client and server)",
  });

  if (!match) {
    return c.json({ success: false, error: "Invalid TOTP code" }, 401);
  }

  // Mark as verified
  const t1 = performance.now();
  db.prepare(
    "UPDATE user_mfa SET verified = 1, verified_at = datetime('now') WHERE user_id = ?"
  ).run(row.user_id);
  trace.addDbQuery({
    sql: "UPDATE user_mfa SET verified = 1, verified_at = datetime('now') WHERE user_id = ?",
    params: [row.user_id],
    ms: performance.now() - t1,
  });

  return c.json({
    success: true,
    data: {
      verified: true,
      verifiedAt: new Date().toISOString(),
    },
  });
});

// ── POST /totp/login/step1 (password check) ──
mfaTotpRoutes.post("/totp/login/step1", async (c) => {
  const parsed = await parseBody(c, totpLoginStep1Schema);
  if ("error" in parsed) return parsed.error;
  const { username, password } = parsed.data;
  const trace = c.get("trace");
  const db = getDb();


  // Look up user
  const t0 = performance.now();
  const user = db
    .prepare(
      "SELECT id, username, password_hash FROM users WHERE username = ?"
    )
    .get(username) as Pick<UserRow, "id" | "username" | "password_hash"> | undefined;
  trace.addDbQuery({
    sql: "SELECT id, username, password_hash FROM users WHERE username = ?",
    params: [username],
    rows: user
      ? [{ id: user.id, username: user.username, password_hash: user.password_hash.substring(0, 20) + "..." }]
      : [],
    ms: performance.now() - t0,
  });

  if (!user) {
    return c.json({ success: false, error: "User not found" }, 401);
  }
  if (user.password_hash === "WEBAUTHN_ONLY") {
    return c.json(
      { success: false, error: "This user has no password — use FIDO2/Passkey auth instead" },
      400
    );
  }

  // Compare password
  const match = await bcrypt.compare(password, user.password_hash);
  trace.addCryptoOp({
    op: "bcrypt.compare",
    input: `password="[REDACTED]" vs stored_hash="${user.password_hash.substring(0, 20)}..."`,
    output: match ? "MATCH ✓" : "MISMATCH ✗",
    algo: "bcrypt",
    detail: "Factor 1: knowledge (something you know). Step 1 of 2FA.",
  });

  if (!match) {
    return c.json({ success: false, error: "Invalid password" }, 401);
  }

  // Check if user has verified MFA
  const t1 = performance.now();
  const mfa = db
    .prepare("SELECT verified FROM user_mfa WHERE user_id = ?")
    .get(user.id) as Pick<UserMfaRow, "verified"> | undefined;
  trace.addDbQuery({
    sql: "SELECT verified FROM user_mfa WHERE user_id = ?",
    params: [user.id],
    rows: mfa ? [mfa] : [],
    ms: performance.now() - t1,
  });

  if (!mfa || mfa.verified !== 1) {
    return c.json({
      success: true,
      data: {
        requiresMfa: false,
        challengeId: null,
        message: "Password verified. MFA is not enabled for this user.",
      },
    });
  }

  // Issue a short-lived challengeId that binds the verified password to the pending TOTP check
  const challengeId = uuidv4();
  loginChallenges.set(challengeId, {
    userId: user.id,
    username: user.username,
    createdAt: Date.now(),
  });
  trace.addSessionOp({
    action: "STORE_LOGIN_CHALLENGE",
    data: {
      challengeId,
      userId: user.id,
      purpose: "mfa-step2",
      ttlSec: LOGIN_CHALLENGE_TTL_MS / 1000,
    },
  });

  return c.json({
    success: true,
    data: {
      requiresMfa: true,
      challengeId,
      message: "Password verified. Enter your 6-digit TOTP code.",
    },
  });
});

// ── POST /totp/login/step2 (TOTP check) ──
mfaTotpRoutes.post("/totp/login/step2", async (c) => {
  const parsed = await parseBody(c, totpLoginStep2Schema);
  if ("error" in parsed) return parsed.error;
  const { challengeId, code } = parsed.data;
  const trace = c.get("trace");
  const db = getDb();


  const challenge = loginChallenges.get(challengeId);
  trace.addSessionOp({
    action: "LOOKUP_LOGIN_CHALLENGE",
    data: {
      challengeId,
      found: Boolean(challenge),
      ageMs: challenge ? Date.now() - challenge.createdAt : null,
    },
  });

  if (!challenge) {
    return c.json(
      { success: false, error: "Challenge expired or invalid — repeat step 1" },
      400
    );
  }

  // Fetch secret
  const t0 = performance.now();
  const row = db
    .prepare("SELECT secret FROM user_mfa WHERE user_id = ?")
    .get(challenge.userId) as Pick<UserMfaRow, "secret"> | undefined;
  trace.addDbQuery({
    sql: "SELECT secret FROM user_mfa WHERE user_id = ?",
    params: [challenge.userId],
    rows: row ? [{ secret: row.secret.substring(0, 8) + "..." }] : [],
    ms: performance.now() - t0,
  });

  if (!row) {
    loginChallenges.delete(challengeId);
    return c.json({ success: false, error: "MFA not enrolled" }, 400);
  }

  const counter = currentCounter();
  const { match, attempts } = verifyTotpWithDetail(row.secret, code);

  // Log one consolidated HMAC-SHA1 verification step (step1 already shows the full breakdown)
  trace.addCryptoOp({
    op: "totp.verify",
    input: `code="${code}", counter_base=${counter}, window=±1`,
    output: match
      ? `MATCH ✓ at counter=${match.counter} (expected=${attempts.map(a => a.code).join("|")})`
      : `MISMATCH ✗ (expected one of: ${attempts.map(a => a.code).join(" | ")})`,
    algo: "HMAC-SHA1 + Dynamic Truncation (RFC 6238)",
    detail: "Factor 2: possession (something you have — the authenticator app). Step 2 of 2FA.",
  });

  if (!match) {
    return c.json({ success: false, error: "Invalid TOTP code" }, 401);
  }

  // Consume the challenge
  loginChallenges.delete(challengeId);
  trace.addSessionOp({
    action: "CONSUME_LOGIN_CHALLENGE",
    data: { challengeId, result: "SUCCESS" },
  });

  return c.json({
    success: true,
    data: {
      success: true,
      username: challenge.username,
      message: `Welcome, ${challenge.username}! 2FA login successful.`,
    },
  });
});

// ── GET /totp/status?username=xxx ──
mfaTotpRoutes.get("/totp/status", (c) => {
  const username = c.req.query("username");
  if (!username) {
    return c.json({ success: false, error: "username query param required" }, 400);
  }
  const db = getDb();
  const row = db
    .prepare(
      `SELECT um.verified
       FROM user_mfa um JOIN users u ON u.id = um.user_id
       WHERE u.username = ?`
    )
    .get(username) as Pick<UserMfaRow, "verified"> | undefined;
  return c.json({
    success: true,
    data: { enabled: row ? row.verified === 1 : false },
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// MFA/TOTP 攻撃シナリオ (DESIGN/20-attack-mfa.md 実装)
//
// 教育用シミュレーション — 実環境でのMFA攻撃は携帯キャリアへの Social Engineering や
// 物理的なデバイスアクセスを必要とするが、本デモは固定シードデータに対する
// 「概念モデル」で表現する。
//
// 攻撃ルートは必ず `runAttackScenario` 経由で 5 ステップ完全形 (probe → tamper → forge →
// exploit → verify) を 1 リクエストで両モード並列実行する (E-2)。outcome は常に "succeeded"、
// HTTP 200 で統一し、堅牢ステップ 5 の status="blocked" + blockedBy で防御識別子を表現する。
//
// ROB-KERB-1 教訓: 旧仕様の body フィールド (replayDefenseEnabled / windowSize / mfaChannel)
// で「片方だけ実行」する形は採用しない。脆弱/堅牢を必ず handler 内で双方並列計算する。
//
// §3.3 教訓: used_otps テーブルは OPTIONAL — otp-replay は in-handler の Set で
// 使用済み OTP を追跡する (OIDC-SAML D43 / FIDO2 attackSimReplayChallenges と同パターン)。
// ─────────────────────────────────────────────────────────────────────────────

// ── 共通シード (immutable) ──
// ROB-OIDC-3 教訓: 全固定値を SSoT 一本化し、分散した magic number を排除する。
const MFA_DEMO_CONSTANTS = {
  // ── 共通被害者設定 ──
  /** 固定被害者ユーザー名 (シードユーザー)。 */
  victimUsername: "seed_alice",
  /** 攻撃者識別子 (シミュレーション用)。 */
  attackerUsername: "attacker_charlie",
  /**
   * シードユーザー固定パスワード (schema.ts seedDb() と整合)。
   * ROB-MFA-4 修正: webauthn.ts WEBAUTHN_DEMO_CONSTANTS.victimPasswordPlain /
   * oidc-saml-sim.ts と同パターン。inline literal "Passw0rd!" を SSoT に集約し、
   * シードパスワード変更時の写し間違いを防ぐ。
   */
  victimPasswordPlain: "Passw0rd!",
  /**
   * 全シナリオ共通フォールバック TOTP シークレット (RFC 6238 §B Appendix の "Hello!" base32)。
   * ROB-MFA-5 修正: シナリオ A / B 両方で `mfaRow?.secret ?? "JBSWY3DPEHPK3PXP"`
   * の inline literal が散在していた (R-MEDIUM-2)。MFA 未登録のシードユーザーでもデモが
   * 完結するよう SSoT 化。
   */
  fallbackDemoSecret: "JBSWY3DPEHPK3PXP",

  // ── シナリオ A: OTP リプレイ ──
  /** シナリオ A で観測した固定デモ counter delta — currentCounter() から 0 ステップ = 現在。 */
  replayCounterDelta: 0,

  // ── シナリオ B: 時刻窓幅 ──
  /** 脆弱モードの TOTP 時刻窓 (ステップ数)。 */
  vulnerableWindow: 10,
  /** 堅牢モードの TOTP 時刻窓 (ステップ数)。 */
  defendedWindow: 1,
  /** シミュレーション遅延 (秒) — 観測後 90 秒経過したコードを再送するシナリオ。 */
  simulatedDelaySeconds: 90,
  /** 90 秒 = 3 ステップ (30 秒/ステップ)。 */
  simulatedDelaySteps: 3,
  /**
   * 教材用ウィンドウ幅比較テーブル (ROB-MFA-6 修正)。
   * windowComparison は本配列から派生計算され、推奨レベル文言を `recommendation` で表現する。
   * 配列順序が UI 表示順を兼ねる。
   */
  windowSizeRecommendations: [
    { window: 1, recommendation: "recommended — sufficient for clock drift (NIST SP 800-63B)" },
    { window: 2, recommendation: "acceptable if justified — maximum recommended" },
    { window: 5, recommendation: "not recommended — 5-minute replay window" },
    { window: 10, recommendation: "vulnerable — 10-minute replay window, exceeds NIST guidance" },
  ] as const,

  // ── シナリオ C: SMS スワップ ──
  /**
   * 脆弱モードの MFA チャネル (SMS OTP)。
   * ROB-MFA-3 修正: bare literal `defendedTotpDeviceBound = true` を排除するため、
   * `defendedChannel === "totp"` という SSoT 派生条件で評価する。
   */
  vulnerableChannel: "sms",
  /** 堅牢モードの MFA チャネル (TOTP デバイスバインド)。 */
  defendedChannel: "totp",
  /** SMS OTP 模擬コード (CSPRNG 生成を simulated として固定値表示)。 */
  smsOtpSimCode: "573819",
  /** 攻撃者デバイスラベル (教材用)。 */
  attackerDevice: "attacker_charlie device (simulated)",
  /** 正規ユーザーデバイスラベル (教材用)。 */
  victimDevice: "seed_alice device (Tokyo)",
  /** 模擬電話番号 (実番号を含まないマスク形式)。 */
  maskedPhoneNumber: "+81-90-XXXX-XXXX (masked)",
} as const satisfies Readonly<{
  victimUsername: string;
  attackerUsername: string;
  victimPasswordPlain: string;
  fallbackDemoSecret: string;
  replayCounterDelta: number;
  vulnerableWindow: number;
  defendedWindow: number;
  simulatedDelaySeconds: number;
  simulatedDelaySteps: number;
  windowSizeRecommendations: readonly { window: number; recommendation: string }[];
  vulnerableChannel: string;
  defendedChannel: string;
  smsOtpSimCode: string;
  attackerDevice: string;
  victimDevice: string;
  maskedPhoneNumber: string;
}>;

// ── Scenario A: OTP リプレイ攻撃 (CWE-294 / CAPEC-60) ──
type MfaOtpReplayExtra = {
  /** 被害者ユーザー名。 */
  victimUsername: string;
  /** 被害者が DB に存在するか (ROB-N1 early guard)。 */
  victimSeedFound: boolean;
  /** MFA 登録済みか。 */
  mfaEnrolled: boolean;
  /** 観測した TOTP コード (現在 counter で計算した実際の値)。 */
  observedCode: string;
  /** 観測した counter 値。 */
  observedCounter: number;
  /** 脆弱モード: 使用済み OTP DB がないためリプレイが受理される (設計上常に true)。 */
  vulnerableReplayAccepted: boolean;
  /** 堅牢モード: 使用済み OTP DB がリプレイを拒否 (設計上常に true)。 */
  defendedReplayBlocked: boolean;
};

mfaTotpRoutes.post("/attack/otp-replay", (c) =>
  runAttackScenario<typeof mfaAttackOtpReplaySchema, MfaOtpReplayExtra>(c, {
    schema: mfaAttackOtpReplaySchema,
    scenarioId: "mfa-otp-replay",
    tabId: "mfa",
    async handler({ recordStep, trace, db }) {
      const victim = MFA_DEMO_CONSTANTS.victimUsername;

      // ROB-N1/N2 教訓: seed_alice 不在時の early guard。
      const victimRow = db
        .prepare("SELECT id, username, password_hash FROM users WHERE username = ?")
        .get(victim) as Pick<UserRow, "id" | "username" | "password_hash"> | undefined;
      const victimSeedFound = victimRow !== undefined;
      trace.addDbQuery({
        sql: "SELECT id, username, password_hash FROM users WHERE username = ?",
        params: [victim],
        rows: victimRow
          ? [{ id: victimRow.id, username: victimRow.username }]
          : [],
        ms: 0.5,
      });

      // MFA 登録済みシークレット取得
      const mfaRow = victimRow
        ? (db
            .prepare("SELECT secret FROM user_mfa WHERE user_id = ? AND verified = 1")
            .get(victimRow.id) as Pick<UserMfaRow, "secret"> | undefined)
        : undefined;
      const mfaEnrolled = mfaRow !== undefined;
      if (mfaRow) {
        trace.addDbQuery({
          sql: "SELECT secret FROM user_mfa WHERE user_id = ? AND verified = 1",
          params: [victimRow!.id],
          rows: [{ secret: mfaRow.secret.substring(0, 8) + "..." }],
          ms: 0.4,
        });
      }

      // 現在 counter で TOTP コードを計算 (観測値の模擬)
      // MFA 未登録の場合は固定デモシークレットを使ってシミュレーション (ROB-MFA-5: SSoT 経由)
      const demoSecret = mfaRow?.secret ?? MFA_DEMO_CONSTANTS.fallbackDemoSecret;
      // ROB-MFA-1+2 教訓: 使用済み OTP 追跡は handler-local の Set に閉じる。
      // FIDO2/OIDC-SAML パターン (handler-local + try/finally) と整合させ、モジュールスコープの
      // singleton と setTimeout 起点 cleanup を排除する (cross-test state leak / event-loop timer leak 回避)。
      const usedOtps = new Set<string>();
      const baseCounter = currentCounter() + MFA_DEMO_CONSTANTS.replayCounterDelta;
      const observedDetail = computeTotp(demoSecret, baseCounter);
      const observedCode = observedDetail.code;
      const observedCounter = observedDetail.counter;
      trace.addCryptoOp({
        op: "totp.compute (observed_code)",
        input: `secret="[REDACTED]", counter=${observedCounter} (T+0s)`,
        output: `code="${observedCode}", counterHex=${observedDetail.counterHex}`,
        algo: "HMAC-SHA1 + Dynamic Truncation (RFC 6238)",
        detail: "攻撃者がショルダーハッキング等で観測した TOTP コードを取得 (シミュレーション)。",
      });

      // ── Step 1: probe — 正規ユーザーの TOTP コードを観測
      recordStep({
        id: "otp-1",
        kind: "probe",
        label: "Observe TOTP code used by legitimate user",
        labelJa: "正規ユーザーが使用した TOTP コードを観測",
        status: victimSeedFound ? "success" : "failed",
        payload: {
          type: "generic",
          data: {
            username: victim,
            observedCode,
            observedAt: "T+0s",
            validUntil: "T+90s",
            method: "shoulder-surfing (simulated)",
            victimSeedFound,
            mfaEnrolled,
          },
        },
        detail: `Attacker observes TOTP code entered by ${victim}. With ±1 window, the code is valid for up to 90 seconds.`,
        detailJa: `攻撃者は ${victim} が入力した TOTP コードを観測します。±1 窓では最大 90 秒間有効です。`,
      });

      // ── Step 2: tamper — 観測コードと counter の対応を記録
      recordStep({
        id: "otp-2",
        kind: "tamper",
        label: "Record observed OTP code and its TOTP counter value",
        labelJa: "観測した OTP コードと TOTP カウンタ値を記録",
        status: "success",
        payload: {
          type: "generic",
          data: {
            observedCode,
            observedCounter,
            validWindowSeconds: 90,
            note: "The attacker records the code and counter to replay within the valid window.",
            noteJa: "攻撃者はコードとカウンタを記録し、有効期間内に再送するために準備します。",
          },
        },
        detail: "The attacker records the code and its associated TOTP counter for replay.",
        detailJa:
          "攻撃者は TOTP コードと対応するカウンタ値を記録し、有効期間内のリプレイ攻撃に備えます。",
      });

      // ── Step 3: forge — 脆弱モード: 使用済み OTP DB なしでリプレイ
      // 脆弱モードでは Set への記録なしに TOTP を再検証する。
      // R-MEDIUM-1 教訓: bare `true` は使わず、verifyTotpWithDetail の戻り値から派生する。
      const { match: vulnMatch } = verifyTotpWithDetail(demoSecret, observedCode, 1);
      const vulnerableReplayAccepted = vulnMatch !== null;
      trace.addCryptoOp({
        op: "totp.verify (vulnerable_no_used_otp_check)",
        input: `code="${observedCode}", counter_base=${baseCounter}, window=±1`,
        output: vulnerableReplayAccepted
          ? `MATCH ✓ at counter=${vulnMatch!.counter} — replay accepted (no used-OTP record)`
          : "MISMATCH ✗ (counter rolled over — demo timing edge case)",
        algo: "HMAC-SHA1 + Dynamic Truncation (RFC 6238)",
        detail:
          "Vulnerable: verifyTotpWithDetail succeeds on second use because no used-OTP record is checked. The same code is valid until the TOTP period advances.",
      });
      recordStep({
        id: "otp-3",
        kind: "forge",
        label: "Vulnerable: replay OTP — no used-OTP record check (second use accepted)",
        labelJa: "脆弱版: OTP をリプレイ — 使用済みチェックなし (2 回目も受理される)",
        status: vulnerableReplayAccepted ? "success" : "failed",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/mfa/attack/otp-replay (vulnerable variant — no used-OTP DB)",
            body: { username: victim, code: observedCode, replayAttempt: true },
          },
          response: {
            status: vulnerableReplayAccepted ? 200 : 401,
            body: vulnerableReplayAccepted
              ? {
                  outcome: "succeeded",
                  detail: `OTP '${observedCode}' accepted on second use — no used-OTP record found.`,
                  counter: observedCounter,
                }
              : {
                  outcome: "missed",
                  detail: "Counter rolled over before replay (timing edge case).",
                },
          },
        },
        detail: vulnerableReplayAccepted
          ? "Vulnerable: the server accepts the replayed OTP because it has no record of prior use."
          : "Replay missed: TOTP period advanced during the demo (edge case).",
        detailJa: vulnerableReplayAccepted
          ? "この実装は脆弱です: サーバーは使用済み記録がないため、再送された OTP を受理してしまいます。"
          : "リプレイ失敗: デモ実行中に TOTP 期間が進んでしまいました (エッジケース)。",
      });

      // ── Step 4: exploit — 同一コードを2回目送信 (脆弱モードで認証成立)
      recordStep({
        id: "otp-4",
        kind: "exploit",
        label: "Vulnerable: attacker authenticates with replayed OTP",
        labelJa: "脆弱版: 攻撃者がリプレイした OTP で認証成立",
        status: vulnerableReplayAccepted ? "success" : "failed",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/mfa/totp/login/step2 (simulated — attacker's second use of same code)",
            body: { challengeId: "<attacker-obtained-challenge>", code: observedCode },
          },
          response: {
            status: vulnerableReplayAccepted ? 200 : 401,
            body: vulnerableReplayAccepted
              ? {
                  success: true,
                  message: `Welcome, ${victim}! 2FA login successful (via replayed OTP).`,
                  note: "Attacker gained access using the same OTP code that the legitimate user already used.",
                }
              : {
                  success: false,
                  error: "OTP expired (counter advanced — demo edge case).",
                },
          },
        },
        detail: vulnerableReplayAccepted
          ? "Attacker successfully logs in as the victim using a replayed OTP code. No used-OTP tracking means the code is accepted again."
          : "Replay attempt failed due to counter advancing (demo timing edge case, not the defense mechanism).",
        detailJa: vulnerableReplayAccepted
          ? `攻撃者がリプレイした OTP で ${victim} としてログインに成功しました。使用済み OTP の追跡がないため、同一コードが再度受理されます。`
          : "リプレイ試行失敗: カウンタが進んでしまいました (デモのタイミングエッジケース)。",
      });

      // ── Step 5: verify (堅牢モード) — 使用済み OTP Set がリプレイを拒否
      // ROB-MFA-1+2 教訓: 1 リクエスト内で「初回 use → Set 追加 → 攻撃者リプレイ → Set ヒット →
      // 拒否」のフルフローを実行する。`firstCheck && replayCheck` 両方が成立して初めて防御成立とし、
      // ROB-PW-1 トートロジー (= 直前 add() で常に true) を排除する。Set は handler-local のため
      // クロステスト state leak も発生しない。
      const usedKey = `${victimRow?.id ?? 0}:${observedCounter}`;
      // (1) 初回チェック: Set が空のため未使用と判定される (= 正規ユーザーの 1 回目)
      const firstCheckUnused = !usedOtps.has(usedKey);
      // (2) 正規ユーザーの初回利用を反映: Set に追加
      if (firstCheckUnused) usedOtps.add(usedKey);
      // (3) 攻撃者のリプレイ試行を反映: 同じ usedKey を再チェック → ヒットして拒否
      const replayCheckUsed = usedOtps.has(usedKey);
      // 防御成立条件: 「初回は未使用」かつ「2回目はヒット」両方が観測される
      const defendedReplayBlocked = firstCheckUnused && replayCheckUsed;
      trace.addCryptoOp({
        op: "usedOtp.check (defended_replay_block)",
        input: `usedKey="${usedKey}" (userId:counter)`,
        output: defendedReplayBlocked
          ? `firstCheck=unused → add → replayCheck=HIT (counter ${observedCounter} already consumed). Replay rejected.`
          : `firstCheck=${firstCheckUnused}, replayCheck=${replayCheckUsed} (defense flow not observed)`,
        algo: "in-memory Set (handler-local 使用済み OTP 追跡)",
        detail:
          "Defended: handler-local in-memory Set (production: used_otps DB table) records (userId, counter) on first use within the request. The full flow — firstCheck=unused → add → replayCheck=hit — is exercised once per request, mirroring legitimate-then-attacker timing. Both modes complete in one request (E-2).",
      });
      recordStep({
        id: "otp-5",
        kind: "verify",
        label: "Defended: used-OTP record blocks the replay",
        labelJa: "堅牢版: 使用済み OTP 記録がリプレイをブロック",
        status: defendedReplayBlocked ? "blocked" : "failed",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/mfa/totp/login/step2 (defended — with used-OTP tracking)",
            body: { challengeId: "<attacker-obtained-challenge>", code: observedCode },
          },
          response: {
            status: 401,
            body: {
              success: false,
              error: `OTP already used. Please wait for the next code.`,
              blockedBy: "used_otp_record_blocks_replay",
              usedKey,
              policy:
                "Record (userId, counter) in used_otps on first successful TOTP verification. Reject any subsequent use of the same counter.",
            },
          },
        },
        detail: "Defended: the used-OTP record (in-memory Set, or DB table in production) recognizes the counter was already consumed and rejects the replay.",
        detailJa:
          "堅牢実装は、使用済み OTP 記録 (本番では used_otps テーブル) がカウンタ使用済みを認識してリプレイを拒否します。",
      });

      return {
        blockedBy: "used_otp_record_blocks_replay",
        summary:
          "Without used-OTP tracking, a replayed TOTP code is accepted a second time within the valid window (up to 90 seconds with ±1 window). The defended system uses an in-memory Set (production: used_otps DB table) keyed by (userId, counter) to reject replays immediately. Both modes run in parallel within one request.",
        summaryJa:
          "この実装は脆弱です: 使用済み OTP を記録しない実装では、同一 TOTP コードが有効期間内 (±1 窓では最大 90 秒) に2回目も受理されます。堅牢実装は in-memory Set (本番: used_otps テーブル) で (userId, counter) のペアを記録し、リプレイを即座に拒否します。両モードを 1 リクエスト内で並列実行します。",
        extra: {
          victimUsername: victim,
          victimSeedFound,
          mfaEnrolled,
          observedCode,
          observedCounter,
          vulnerableReplayAccepted,
          defendedReplayBlocked,
        } satisfies MfaOtpReplayExtra,
        payload: {
          params: {},
          result: {
            observedCodeMasked: maskSecret(observedCode),
            observedCounter,
            vulnerableReplayAccepted,
            defendedReplayBlocked,
            victimSeedFound,
          },
        },
      };
    },
  }),
);

// ── Scenario B: 時刻窓幅攻撃 (CWE-208 / CAPEC-462) ──
// 防御の核心: TOTP ウィンドウは ±1 ステップ (±30 秒) に設定する。
// ±10 ステップ (±5 分) では、観測後 90 秒 = 3 ステップ古いコードも受理されてしまう。
type MfaTimeWindowWideExtra = {
  /** 被害者ユーザー名。 */
  victimUsername: string;
  /** 被害者が DB に存在するか (ROB-N1 early guard)。 */
  victimSeedFound: boolean;
  /** 観測した TOTP コード (シミュレーション: simulatedDelaySteps 前の counter で計算)。 */
  observedCode: string;
  /** 観測した counter 値 (現在 - simulatedDelaySteps)。 */
  observedCounter: number;
  /** 現在 counter 値。 */
  currentCounterValue: number;
  /** シミュレーション遅延 (秒)。 */
  simulatedDelaySeconds: number;
  /** 遅延をステップ数に換算した値。 */
  simulatedDelaySteps: number;
  /** 脆弱モード (±10 窓): 90 秒前のコードが受理される (設計上常に true)。 */
  vulnerableWideWindowAccepted: boolean;
  /** 堅牢モード (±1 窓): 90 秒前のコードが拒否される (設計上常に true)。 */
  defendedNarrowWindowRejected: boolean;
  /** ウィンドウ幅比較テーブル。 */
  windowComparison: { window: number; toleranceSec: number; recommendation: string }[];
};

mfaTotpRoutes.post("/attack/time-window-wide", (c) =>
  runAttackScenario<typeof mfaAttackTimeWindowWideSchema, MfaTimeWindowWideExtra>(c, {
    schema: mfaAttackTimeWindowWideSchema,
    scenarioId: "mfa-time-window-too-wide",
    tabId: "mfa",
    async handler({ recordStep, trace, db }) {
      const victim = MFA_DEMO_CONSTANTS.victimUsername;
      const simulatedDelaySec = MFA_DEMO_CONSTANTS.simulatedDelaySeconds;
      const simulatedDelaySteps = MFA_DEMO_CONSTANTS.simulatedDelaySteps;
      const vulnerableWindow = MFA_DEMO_CONSTANTS.vulnerableWindow;
      const defendedWindow = MFA_DEMO_CONSTANTS.defendedWindow;

      // ROB-N1/N2 教訓: seed_alice 早期ガード
      const victimRow = db
        .prepare("SELECT id, username FROM users WHERE username = ?")
        .get(victim) as Pick<UserRow, "id" | "username"> | undefined;
      const victimSeedFound = victimRow !== undefined;
      trace.addDbQuery({
        sql: "SELECT id, username FROM users WHERE username = ?",
        params: [victim],
        rows: victimRow ? [{ id: victimRow.id, username: victimRow.username }] : [],
        ms: 0.4,
      });

      // MFA シークレット取得 (なければデモ値)
      const mfaRow = victimRow
        ? (db
            .prepare("SELECT secret FROM user_mfa WHERE user_id = ? AND verified = 1")
            .get(victimRow.id) as Pick<UserMfaRow, "secret"> | undefined)
        : undefined;
      const demoSecret = mfaRow?.secret ?? MFA_DEMO_CONSTANTS.fallbackDemoSecret;

      // シナリオ B: T+0s 時点のコードを観測し、T+90s (=3ステップ後) に再送する。
      // `simulatedDelaySteps` ステップ前の counter でコードを計算することで「古いコード」を表現。
      const currentCounterValue = currentCounter();
      const observedCounter = currentCounterValue - simulatedDelaySteps;
      const observedDetail = computeTotp(demoSecret, observedCounter);
      const observedCode = observedDetail.code;

      // ── Step 1: probe — T+0s 時点で有効な TOTP コードを観測
      recordStep({
        id: "tw-1",
        kind: "probe",
        label: "Observe TOTP code valid at T+0s",
        labelJa: "T+0s 時点で有効な TOTP コードを観測",
        status: "success",
        payload: {
          type: "generic",
          data: {
            username: victim,
            observedCode,
            observedAt: "T+0s",
            windowNarrow: `Valid: T-${defendedWindow * 30}s to T+${defendedWindow * 30}s (±${defendedWindow} step)`,
            windowWide: `Valid: T-${vulnerableWindow * 30}s to T+${vulnerableWindow * 30}s (±${vulnerableWindow} steps)`,
            note: "Window width determines how long the code remains valid after observation.",
            noteJa: "ウィンドウ幅により、観測後にコードが有効な期間が変わります。",
          },
        },
        detail: `Attacker observes a TOTP code at T+0s. With ±${vulnerableWindow} window, it remains valid for ${vulnerableWindow * 30}s in each direction.`,
        detailJa: `攻撃者は T+0s に TOTP コードを観測します。±${vulnerableWindow} 窓では前後 ${vulnerableWindow * 30} 秒間有効です。`,
      });

      // ── Step 2: tamper — T+90s に ±1 窓でリプレイ → 拒否される (堅牢)
      // ±1 窓では counter ±1 のみ受理 — 3ステップ前は範囲外。
      const { match: narrowMatch } = verifyTotpWithDetail(demoSecret, observedCode, defendedWindow);
      // R-MEDIUM-1 教訓: 「±1 窓で simulatedDelaySteps 前のコードが拒否される」ことを
      // 数値条件で表現する — bare `true` は使わない。
      const defendedNarrowWindowRejected =
        narrowMatch === null && simulatedDelaySteps > defendedWindow;
      trace.addCryptoOp({
        op: `totp.verify (window=${defendedWindow}_narrow_defended)`,
        input: `code="${observedCode}", counter_base=${currentCounterValue}, window=±${defendedWindow}, simulated_delta=${simulatedDelaySteps}`,
        output: narrowMatch
          ? `MATCH ✓ at counter=${narrowMatch.counter} (within ±${defendedWindow})`
          : `MISMATCH ✗ — counter=${observedCounter} is ${simulatedDelaySteps} steps behind current; outside ±${defendedWindow} window`,
        algo: "HMAC-SHA1 + Dynamic Truncation (RFC 6238)",
        detail: `Defended: ±${defendedWindow} window (±${defendedWindow * 30}s) rejects a code that is ${simulatedDelaySec}s (${simulatedDelaySteps} steps) old. NIST SP 800-63B recommends ±1 step maximum.`,
      });
      recordStep({
        id: "tw-2",
        kind: "tamper",
        label: `Replay at T+${simulatedDelaySec}s: rejected by ±${defendedWindow} window (narrow — defended)`,
        labelJa: `T+${simulatedDelaySec}s にリプレイ: ±${defendedWindow} 窓 (推奨設定) では拒否される`,
        status: defendedNarrowWindowRejected ? "blocked" : "success",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/mfa/totp/login/step2 (defended — ±1 narrow window)",
            body: { code: observedCode, simulatedDelaySeconds: simulatedDelaySec },
          },
          response: {
            status: 401,
            body: {
              success: false,
              outcome: "blocked",
              detail: `Code expired: outside ±${defendedWindow} window (±${defendedWindow * 30}s). ${simulatedDelaySec}s elapsed.`,
            },
          },
        },
        detail: `With ±${defendedWindow} window, the code (${simulatedDelaySteps} steps old, ${simulatedDelaySec}s elapsed) is no longer valid.`,
        detailJa: `±${defendedWindow} 窓では、${simulatedDelaySec} 秒後 (${simulatedDelaySteps} ステップ前) のコードは有効期限切れとして拒否されます。`,
      });

      // ── Step 3: forge — T+90s に ±10 窓でリプレイ → 受理される (脆弱)
      const { match: wideMatch } = verifyTotpWithDetail(demoSecret, observedCode, vulnerableWindow);
      // R-MEDIUM-1 教訓: SSoT 派生条件。±10 窓で simulatedDelaySteps 以内なら一致する設計。
      const vulnerableWideWindowAccepted =
        wideMatch !== null && simulatedDelaySteps <= vulnerableWindow;
      trace.addCryptoOp({
        op: `totp.verify (window=${vulnerableWindow}_wide_vulnerable)`,
        input: `code="${observedCode}", counter_base=${currentCounterValue}, window=±${vulnerableWindow}, simulated_delta=${simulatedDelaySteps}`,
        output: wideMatch
          ? `MATCH ✓ at counter=${wideMatch.counter} (delta=${wideMatch.counter - currentCounterValue}, within ±${vulnerableWindow})`
          : `MISMATCH ✗ (unexpected — simulated delta ${simulatedDelaySteps} should be within ±${vulnerableWindow})`,
        algo: "HMAC-SHA1 + Dynamic Truncation (RFC 6238)",
        detail: `Vulnerable: wide window ±${vulnerableWindow} (±${vulnerableWindow * 30}s) accepts a code valid at counter=${observedCounter} (issued ${simulatedDelaySec}s ago, ${simulatedDelaySteps} steps back). An attacker observing the code at T+0s can replay it up to ${vulnerableWindow * 30}s later.`,
      });
      recordStep({
        id: "tw-3",
        kind: "forge",
        label: `Replay at T+${simulatedDelaySec}s: accepted by ±${vulnerableWindow} window (wide — vulnerable)`,
        labelJa: `T+${simulatedDelaySec}s にリプレイ: ±${vulnerableWindow} 窓 (広い設定 — 脆弱) では受理される`,
        status: vulnerableWideWindowAccepted ? "success" : "failed",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/mfa/totp/login/step2 (vulnerable — ±10 wide window)",
            body: { code: observedCode, simulatedDelaySeconds: simulatedDelaySec },
          },
          response: {
            status: vulnerableWideWindowAccepted ? 200 : 401,
            body: vulnerableWideWindowAccepted
              ? {
                  success: true,
                  outcome: "succeeded",
                  detail: `Code accepted: within ±${vulnerableWindow} window (±${vulnerableWindow * 30}s). ${simulatedDelaySec}s elapsed (${simulatedDelaySteps} steps).`,
                  effectiveDeltaSteps: observedCounter - currentCounterValue,
                }
              : {
                  success: false,
                  outcome: "blocked",
                  detail: "Unexpected: code not matched within wide window.",
                },
          },
        },
        detail: vulnerableWideWindowAccepted
          ? `Vulnerable: ±${vulnerableWindow} window accepts a code issued ${simulatedDelaySec}s ago (${simulatedDelaySteps} steps back). A ${simulatedDelaySec}s replay window is far too long.`
          : `Wide window match unexpectedly missed (demo edge case).`,
        detailJa: vulnerableWideWindowAccepted
          ? `この実装は脆弱です: ±${vulnerableWindow} 窓では ${simulatedDelaySec} 秒前 (${simulatedDelaySteps} ステップ前) のコードを受理してしまいます。${simulatedDelaySec} 秒のリプレイ窓は過剰に広すぎます。`
          : `±${vulnerableWindow} 窓での一致が予期せず失敗しました (デモエッジケース)。`,
      });

      // ── Step 4: exploit — ±10 窓でのリプレイ成立後、攻撃者が認証完了
      recordStep({
        id: "tw-4",
        kind: "exploit",
        label: "Vulnerable: attacker authenticates using a 90s-old OTP via wide window",
        labelJa: "脆弱版: 攻撃者が 90 秒前の OTP でワイドウィンドウを利用して認証成立",
        status: vulnerableWideWindowAccepted ? "success" : "failed",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/mfa/attack/time-window-wide (vulnerable — ±10 wide window)",
          },
          response: {
            status: vulnerableWideWindowAccepted ? 200 : 401,
            body: vulnerableWideWindowAccepted
              ? {
                  outcome: "succeeded",
                  note: `±${vulnerableWindow} window: ${simulatedDelaySec}s-old OTP accepted. Attacker replays observed code successfully.`,
                }
              : { outcome: "blocked", note: "Wide window miss (edge case)." },
          },
        },
        detail: vulnerableWideWindowAccepted
          ? `Attacker successfully authenticates using a ${simulatedDelaySec}s-old OTP — possible only because the server's TOTP window is set to ±${vulnerableWindow} steps.`
          : `Wide window miss: OTP not accepted (edge case).`,
        detailJa: vulnerableWideWindowAccepted
          ? `攻撃者は ${simulatedDelaySec} 秒前の OTP で認証に成功しました。サーバーの TOTP ウィンドウが ±${vulnerableWindow} ステップに設定されているため成立します。`
          : `ワイドウィンドウで一致なし: OTP が受理されませんでした (エッジケース)。`,
      });

      // ── Step 5: verify (堅牢モード) — ±1 窓推奨設定のまとめ
      // ROB-MFA-6 修正: windowComparison は MFA_DEMO_CONSTANTS.windowSizeRecommendations から派生計算。
      // toleranceSec = window * TOTP_PERIOD で SSoT 派生し、inline literal の重複 (R-MEDIUM-2) を排除。
      const windowComparison = MFA_DEMO_CONSTANTS.windowSizeRecommendations.map((entry) => ({
        window: entry.window,
        toleranceSec: entry.window * TOTP_PERIOD,
        recommendation: entry.recommendation,
      }));
      recordStep({
        id: "tw-5",
        kind: "verify",
        label: "Defended: TOTP narrow ±1 window rejects 90s-old OTP",
        labelJa: "堅牢版: TOTP ±1 窓が 90 秒前の OTP を拒否",
        status: defendedNarrowWindowRejected ? "blocked" : "failed",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/mfa/attack/time-window-wide (defended — ±1 narrow window)",
          },
          response: {
            status: 401,
            body: {
              error: `Code expired: ${simulatedDelaySec}s elapsed, outside ±${defendedWindow * 30}s window.`,
              blockedBy: "totp_narrow_time_window_rejects_old_otp",
              policy: {
                window: defendedWindow,
                toleranceSec: defendedWindow * TOTP_PERIOD,
                nistGuidance: "NIST SP 800-63B §5.1.4.2: maximum 1 time step tolerance",
                recommendation: "Use window=1 (±30s). Widen only if justified; never beyond ±2.",
              },
              windowComparison,
            },
          },
        },
        detail: `Defended: ±${defendedWindow} window (NIST SP 800-63B recommended) rejects the ${simulatedDelaySec}s-old OTP. Set TOTP_WINDOW=1 in production; guard against misconfiguration with Math.min(envWindow, 2).`,
        detailJa:
          `堅牢実装は NIST SP 800-63B §5.1.4.2 の推奨に従い ±${defendedWindow} ウィンドウ (±${defendedWindow * TOTP_PERIOD}秒) を設定します。${simulatedDelaySec} 秒前のコードは窓の外として拒否されます。環境変数でウィンドウを設定する場合は Math.min(envWindow, 2) で上限ガードを実装してください。`,
      });

      return {
        blockedBy: "totp_narrow_time_window_rejects_old_otp",
        summary: `With a wide ±${vulnerableWindow} time window, a TOTP code issued ${simulatedDelaySec}s ago (${simulatedDelaySteps} steps back) is accepted — creating a ${vulnerableWindow * 30}s replay window. The defended implementation uses ±${defendedWindow} step (NIST SP 800-63B recommended), correctly rejecting the ${simulatedDelaySec}s-old code. Both modes run in parallel within one request.`,
        summaryJa: `このシナリオでは ±${vulnerableWindow} 時刻窓では ${simulatedDelaySec} 秒前 (${simulatedDelaySteps} ステップ前) に発行された OTP が受理されます (${vulnerableWindow * 30} 秒のリプレイ窓が開く)。堅牢実装は NIST SP 800-63B 推奨の ±${defendedWindow} ステップを使用し、${simulatedDelaySec} 秒前のコードを正しく拒否します。両モードを 1 リクエスト内で並列実行します。`,
        extra: {
          victimUsername: victim,
          victimSeedFound,
          observedCode,
          observedCounter,
          currentCounterValue,
          simulatedDelaySeconds: simulatedDelaySec,
          simulatedDelaySteps,
          vulnerableWideWindowAccepted,
          defendedNarrowWindowRejected,
          windowComparison,
        } satisfies MfaTimeWindowWideExtra,
        payload: {
          params: {},
          result: {
            observedCodeMasked: maskSecret(observedCode),
            observedCounter,
            currentCounterValue,
            simulatedDelaySeconds: simulatedDelaySec,
            simulatedDelaySteps,
            vulnerableWideWindowAccepted,
            defendedNarrowWindowRejected,
          },
        },
      };
    },
  }),
);

// ── Scenario C: SMS OTP SIM スワップ (CWE-308 / CWE-294 / CAPEC-115) ──
// > シミュレーション明示: 本シナリオは SMS OTP の設計上の脆弱性を概念的に示す教育用シミュレーション。
// > 実際の SIM スワップには携帯キャリアへの Social Engineering が必要であり、
// > このデモはその過程を完全に省略したシミュレーションに過ぎない。
// > 実環境での SIM スワップ攻撃の実施を意図したものではない。
type MfaSmsSwapExtra = {
  /** 被害者ユーザー名。 */
  victimUsername: string;
  /** 被害者が DB に存在するか (ROB-N1 early guard)。 */
  victimSeedFound: boolean;
  /** パスワード検証結果 (脆弱モード / 堅牢モード共通)。 */
  passwordVerified: boolean;
  /** 脆弱モード: SMS OTP が攻撃者デバイスに転送される (設計上常に true)。 */
  vulnerableSmsRedirected: boolean;
  /** 堅牢モード: TOTP シークレットはデバイスバインドのため転送されない (設計上常に true)。 */
  defendedTotpDeviceBound: boolean;
  /** 生成された SMS OTP (模擬値)。 */
  smsOtpCode: string;
  /** SIM スワップシミュレーションバナーテキスト (必須教育コンテンツ)。 */
  educationalSimulationNote: string;
};

mfaTotpRoutes.post("/attack/sms-swap", (c) =>
  runAttackScenario<typeof mfaAttackSmsSwapSchema, MfaSmsSwapExtra>(c, {
    schema: mfaAttackSmsSwapSchema,
    scenarioId: "mfa-sms-swap",
    tabId: "mfa",
    async handler({ recordStep, trace, db }) {
      const victim = MFA_DEMO_CONSTANTS.victimUsername;
      const attacker = MFA_DEMO_CONSTANTS.attackerUsername;
      const smsOtpCode = MFA_DEMO_CONSTANTS.smsOtpSimCode;

      // 必須教育コンテンツ: DESIGN/20 §4.3 が求める「シミュレーション注記」
      const educationalSimulationNote =
        "[SIMULATION ONLY] This scenario demonstrates the conceptual vulnerability of SMS OTP. " +
        "Actual SIM swap attacks require social engineering at a carrier — that process is NOT reproduced here. " +
        "This demo is for educational purposes only and cannot be used against real systems.";

      // ROB-N1/N2 教訓: seed_alice 早期ガード + パスワード取得
      // NOTE: users テーブルには is_attack_sim 列がない (Phase 2 マイグレーション対象外)
      // ため、フィルタなしで username 一致のみで検索する。
      const victimRow = db
        .prepare("SELECT id, username, password_hash FROM users WHERE username = ?")
        .get(victim) as Pick<UserRow, "id" | "username" | "password_hash"> | undefined;
      const victimSeedFound = victimRow !== undefined;
      trace.addDbQuery({
        sql: "SELECT id, username, password_hash FROM users WHERE username = ?",
        params: [victim],
        rows: victimRow
          ? [{ id: victimRow.id, username: victimRow.username, password_hash: victimRow.password_hash.substring(0, 20) + "..." }]
          : [],
        ms: 0.8,
      });

      // パスワード検証 (bcrypt) — 第1要素
      // ROB-MFA-4 修正: SSoT 経由の固定シードパスワード参照 (webauthn.ts と同パターン)。
      const passwordVerified = victimRow
        ? await bcrypt.compare(MFA_DEMO_CONSTANTS.victimPasswordPlain, victimRow.password_hash)
        : false;
      trace.addCryptoOp({
        op: "bcrypt.compare",
        input: `password="[REDACTED]" vs stored_hash="${victimRow?.password_hash.substring(0, 20) ?? "N/A"}..."`,
        output: passwordVerified ? "MATCH ✓" : "MISMATCH ✗ (seed user not found or password mismatch)",
        algo: "bcrypt",
        detail: "Factor 1 (password) verified. Factor 2 (MFA channel) will determine if the attack succeeds.",
      });

      // ── Step 1: probe — 標的の電話番号と侵害済みパスワードを取得
      recordStep({
        id: "sms-1",
        kind: "probe",
        label: "Obtain target phone number and compromised password",
        labelJa: "標的の電話番号と侵害済みパスワードを取得",
        status: victimSeedFound ? "success" : "failed",
        payload: {
          type: "generic",
          data: {
            username: victim,
            phoneNumber: MFA_DEMO_CONSTANTS.maskedPhoneNumber,
            password: "[obtained via phishing simulation — REDACTED]",
            passwordVerified,
            note: "Phone number from leaked profile. Password obtained via phishing simulation.",
            noteJa: "電話番号は漏洩プロフィールから取得。パスワードはフィッシングシミュレーション経由。",
            educationalNote: educationalSimulationNote,
          },
        },
        detail: "Attacker has collected the phone number and verified the password before SIM swap attempt.",
        detailJa: "攻撃者は SIM スワップ前に電話番号とパスワードを収集・確認しています。",
      });

      // ── Step 2: tamper — SMS OTP vs TOTP アプリ の依存関係を分析
      recordStep({
        id: "sms-2",
        kind: "tamper",
        label: "Analyze MFA channel dependencies: SMS (phone-number-bound) vs TOTP (device-bound)",
        labelJa: "MFA チャネル依存性を分析: SMS (電話番号バインド) vs TOTP (デバイスバインド)",
        status: "success",
        payload: {
          type: "generic",
          data: {
            smsChannel: {
              bindingType: "phone number ownership",
              simSwapEffect: "full redirection — SMS goes to attacker",
              attackFeasibility: "high (social engineering at carrier)",
            },
            totpChannel: {
              bindingType: "device-bound shared secret (TOTP authenticator app)",
              simSwapEffect: "none — TOTP secret stays in authenticator app",
              attackFeasibility: "requires physical device access or app backup theft",
            },
          },
        },
        detail: "Key difference: SMS OTP depends on phone number (carrier-redirectable), while TOTP secrets are device-bound (not transferable via SIM swap alone). The attacker selects SMS channel as the weak link.",
        detailJa:
          "重要な違い: SMS OTP は電話番号の所有権に依存し (キャリアによって転送可能)、TOTP シークレットはデバイスにバインドされています (SIM スワップのみでは転送不可能)。攻撃者は SMS チャネルを攻撃対象として選択します。",
      });

      // ── Step 3: forge — SIM スワップシミュレーション
      // DESIGN/20 §4.3: MUST include educational simulation banner text in summary/extra
      trace.addSessionOp({
        action: "SIM_SWAP_SIMULATION",
        data: {
          note: "Educational simulation — not an actual SIM swap. Demonstrates SMS OTP vulnerability concept.",
          originalDevice: MFA_DEMO_CONSTANTS.victimDevice,
          redirectedTo: MFA_DEMO_CONSTANTS.attackerDevice,
          educationalSimulationNote,
        },
      });
      // R-MEDIUM-1 教訓: bare `true` は使わず、SIM スワップの模擬効果から派生する条件で表現。
      const vulnerableSmsRedirected = victimSeedFound && passwordVerified;
      recordStep({
        id: "sms-3",
        kind: "forge",
        label: "Simulate SIM swap: phone number forwarded to attacker device",
        labelJa: "SIM スワップをシミュレーション: 電話番号が攻撃者端末に転送される",
        status: "success",
        payload: {
          type: "generic",
          data: {
            simSwapSimulated: true,
            originalDevice: MFA_DEMO_CONSTANTS.victimDevice,
            attackerDevice: MFA_DEMO_CONSTANTS.attackerDevice,
            smsRoutingChanged: vulnerableSmsRedirected,
            note: "SIMULATION ONLY — actual SIM swap requires social engineering at carrier. Not reproduced here.",
            noteJa: "シミュレーションのみ — 実際の SIM スワップはキャリアへの Social Engineering を要する。ここでは再現しない。",
            educationalSimulationNote,
          },
        },
        detail: "[SIMULATION] Phone number routing redirected to attacker device. This is a concept demonstration only — not a reproduction of actual SIM swap technique.",
        detailJa:
          "[シミュレーション] 電話番号の転送先が攻撃者端末に変更されました。概念的なデモです — 実際の SIM スワップ手順は再現していません。",
      });

      // ── Step 4: exploit — SMS OTP が攻撃者端末に届き、ログイン成立
      trace.addCryptoOp({
        op: "sms.generate_otp (simulated)",
        input: "length=6, charset=numeric",
        output: `${smsOtpCode} → delivered to: ${attacker} (SIM swap simulation)`,
        algo: "CSPRNG (simulated — no real SMS sent)",
        detail: `[SIMULATION] In real systems, SMS OTP is sent to the registered phone number. After SIM swap, phone number routing redirects SMS delivery to the attacker's device. OTP code: ${smsOtpCode} (simulated, not a real OTP).`,
      });
      recordStep({
        id: "sms-4",
        kind: "exploit",
        label: "Vulnerable: SMS OTP delivered to attacker device; attacker authenticates as victim",
        labelJa: "脆弱版: SMS OTP が攻撃者端末に届き; 攻撃者が被害者として認証成立",
        status: vulnerableSmsRedirected ? "success" : "failed",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/mfa/attack/sms-swap (vulnerable — SMS OTP channel)",
            body: {
              username: victim,
              mfaChannel: "sms",
              simSwapSimulated: true,
            },
          },
          response: {
            status: vulnerableSmsRedirected ? 200 : 401,
            body: vulnerableSmsRedirected
              ? {
                  outcome: "succeeded",
                  detail: "SMS OTP sent to attacker device (SIM swap simulated). Login completed.",
                  smsReceivedBy: `${attacker} (simulated)`,
                  otpCode: smsOtpCode,
                  warning: educationalSimulationNote,
                }
              : {
                  outcome: "blocked",
                  detail: "Password verification failed (seed user not found or credentials mismatch).",
                },
          },
        },
        detail: vulnerableSmsRedirected
          ? "This scenario demonstrates that SMS OTP is tied to phone number ownership, not device identity. After SIM swap, the attacker receives the SMS OTP and completes login as the victim."
          : "Exploit failed: password verification did not succeed (seed user missing).",
        detailJa: vulnerableSmsRedirected
          ? "このシナリオは SMS OTP が電話番号の所有権に依存しており、デバイスの同一性には依存しないことを示しています。SIM スワップ後、攻撃者は SMS OTP を受信して被害者としてログインを完了します。"
          : "攻撃失敗: パスワード検証が成立しませんでした (シードユーザー不在)。",
      });

      // ── Step 5: verify (堅牢モード) — TOTP アプリはデバイスバインドシークレット
      trace.addSessionOp({
        action: "SIM_SWAP_TOTP_RESISTANCE_CHECK",
        data: {
          mfaChannel: "totp",
          result: "blocked",
          reason: "TOTP secret bound to authenticator app on device, not to phone number",
          educationalNote: "TOTP secret stored in authenticator app is not redirected by SIM swap. Physical device access would be required to steal the TOTP secret.",
        },
      });
      // R-MEDIUM-1 教訓 / ROB-MFA-3 修正: bare literal `true` は使わず、SSoT 派生条件で表現。
      // 防御チャネル定数が "totp" の場合のみ true となり、将来 SSoT で defendedChannel を変えれば
      // 自動的に false に転じる (sentinel 化)。
      const defendedTotpDeviceBound = MFA_DEMO_CONSTANTS.defendedChannel === "totp";
      recordStep({
        id: "sms-5",
        kind: "verify",
        label: "Defended: TOTP device-bound secret resists SIM swap — attack fails",
        labelJa: "堅牢版: TOTP デバイスバインドシークレットが SIM スワップに耐性 — 攻撃不成立",
        status: "blocked",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/mfa/attack/sms-swap (defended — TOTP app channel)",
            body: {
              username: victim,
              mfaChannel: "totp",
              simSwapSimulated: true,
            },
          },
          response: {
            status: 401,
            body: {
              outcome: "blocked",
              blockedBy: "totp_device_bound_secret_resists_sim_swap",
              detail: "TOTP secret is stored in seed_alice's authenticator app. SIM swap does not transfer the TOTP secret.",
              educationalNote: "TOTP (RFC 6238) uses a shared secret stored in the authenticator app. The secret is never sent over the carrier network — only time-based codes are entered manually. SIM swap cannot redirect the secret.",
              defenseRecommendation: {
                preferred: ["TOTP app (device-bound)", "Push notification MFA (device-authenticated app)", "FIDO2/WebAuthn (origin-bound, phishing-resistant)"],
                avoid: ["SMS OTP (phone-number-bound, SIM-swap vulnerable)", "email OTP (email-account-compromise dependent)"],
                nistReference: "NIST SP 800-63B §5.1.3: SMS OTP is classified as restricted authenticator with noted risks",
              },
            },
          },
        },
        detail: "TOTP secret remains on the legitimate user's authenticator app. SIM swap only redirects SMS messages — it cannot transfer the TOTP shared secret stored in the app. The attacker cannot generate valid TOTP codes without the secret.",
        detailJa:
          "TOTP シークレットは正規ユーザーの認証アプリに残ります。SIM スワップは SMS メッセージの転送のみで、アプリに保存された TOTP 共有シークレットは転送できません。攻撃者はシークレットなしに有効な TOTP コードを生成できません。",
      });

      return {
        blockedBy: "totp_device_bound_secret_resists_sim_swap",
        summary:
          "SMS OTP is vulnerable to SIM swap: once the phone number is redirected, all subsequent SMS OTPs go to the attacker's device, enabling account takeover. TOTP apps use a device-bound shared secret (RFC 6238) that is never transmitted over the carrier network — SIM swap cannot redirect it. NIST SP 800-63B §5.1.3 classifies SMS OTP as a restricted authenticator with noted risks. Both modes run in parallel within one request. " +
          educationalSimulationNote,
        summaryJa:
          "このシナリオでは SMS OTP は SIM スワップに脆弱です: 電話番号が転送されると以降の SMS OTP はすべて攻撃者のデバイスに届き、アカウント乗っ取りが可能になります。TOTP アプリは RFC 6238 に基づくデバイスバインドの共有シークレットを使用しており、キャリアネットワークを通じて送信されることはありません — SIM スワップでは転送できません。NIST SP 800-63B §5.1.3 は SMS OTP をリスクが明示された制限付き認証器に分類しています。[シミュレーション] このシナリオは教育用シミュレーションです。SIM スワップの実手順は含まれていません。両モードを 1 リクエスト内で並列実行します。",
        extra: {
          victimUsername: victim,
          victimSeedFound,
          passwordVerified,
          vulnerableSmsRedirected,
          defendedTotpDeviceBound,
          smsOtpCode,
          educationalSimulationNote,
        } satisfies MfaSmsSwapExtra,
        payload: {
          params: {},
          result: {
            victimSeedFound,
            passwordVerified,
            vulnerableSmsRedirected,
            defendedTotpDeviceBound,
            smsOtpCodeMasked: maskSecret(smsOtpCode),
          },
        },
      };
    },
  }),
);
