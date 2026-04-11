import { Hono } from "hono";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { v4 as uuidv4 } from "uuid";
import { getDb } from "../db/schema.js";
import { parseBody, tokenLoginSchema, tokenRefreshSchema } from "../validation.js";
import type { UserRow } from "../../shared/api-types.js";

export const tokenAuthRoutes = new Hono();

const JWT_SECRET = "osi-demo-token-auth-secret";
const REFRESH_SECRET = "osi-demo-refresh-secret";

tokenAuthRoutes.post("/login", async (c) => {
  const parsed = await parseBody(c, tokenLoginSchema);
  if ("error" in parsed) return parsed.error;
  const { username, password } = parsed.data;
  const trace = c.get("trace");
  const db = getDb();

  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username) as UserRow | undefined;
  trace.addDbQuery({
    sql: "SELECT * FROM users WHERE username = ?",
    params: [username],
    rows: user ? [{ id: user.id, username: user.username }] : [],
    ms: 0,
  });

  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
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

  const refreshToken = jwt.sign(
    { sub: user.id, type: "refresh", jti: uuidv4() },
    REFRESH_SECRET,
    { expiresIn: "7d" }
  );
  trace.addCryptoOp({
    op: "jwt.sign(refreshToken)",
    input: JSON.stringify({ sub: user.id, type: "refresh" }),
    output: refreshToken.substring(0, 40) + "...",
    algo: "HS256",
    detail: `Secret: "${REFRESH_SECRET.substring(0, 15)}..." / Expires: 7 days`,
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
    const decoded = jwt.verify(refreshToken, REFRESH_SECRET) as unknown as { sub: number; type: string };

    // Ensure this is actually a refresh token
    if (decoded.type !== "refresh") {
      return c.json({ success: false, error: "Invalid token type — expected refresh token" }, 401);
    }

    trace.addCryptoOp({
      op: "jwt.verify(refreshToken)",
      input: refreshToken.substring(0, 30) + "...",
      output: "VALID ✓",
      algo: "HS256",
    });

    const db = getDb();
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

    return c.json({
      success: true,
      data: { accessToken: newAccessToken, expiresIn: 900, tokenType: "Bearer" },
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Unknown error";
    return c.json({ success: false, error: message }, 401);
  }
});
