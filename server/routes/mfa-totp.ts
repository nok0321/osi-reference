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

export const mfaTotpRoutes = new Hono();

const ISSUER = "OSI Reference";
const PERIOD = TOTP_PERIOD;
const DIGITS = TOTP_DIGITS;
const ALGORITHM = TOTP_ALGORITHM;

// ── Challenge store for 2-step login (challengeId → userId) ──
const LOGIN_CHALLENGE_TTL_MS = 5 * 60 * 1000;
interface LoginChallenge {
  userId: number;
  username: string;
  createdAt: number;
}
const loginChallenges = new Map<string, LoginChallenge>();

function cleanExpiredLoginChallenges() {
  const now = Date.now();
  for (const [key, c] of loginChallenges) {
    if (now - c.createdAt > LOGIN_CHALLENGE_TTL_MS) loginChallenges.delete(key);
  }
}


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

  cleanExpiredLoginChallenges();

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
  const match = bcrypt.compareSync(password, user.password_hash);
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

  cleanExpiredLoginChallenges();

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
