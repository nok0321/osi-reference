import { Hono } from "hono";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { v4 as uuidv4 } from "uuid";
import { getDb } from "../db/schema.js";
import { parseBody, tokenLoginSchema, tokenRefreshSchema } from "../validation.js";
import type { UserRow, RefreshTokenRow } from "../../shared/api-types.js";

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
