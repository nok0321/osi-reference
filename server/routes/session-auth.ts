import { Hono } from "hono";
import { setCookie, getCookie, deleteCookie } from "hono/cookie";
import { v4 as uuidv4 } from "uuid";
import bcrypt from "bcryptjs";
import { getDb } from "../db/schema.js";
import { parseBody, sessionLoginSchema } from "../validation.js";
import type { UserRow, SessionRow } from "../../shared/api-types.js";

export const sessionAuthRoutes = new Hono();

sessionAuthRoutes.post("/login", async (c) => {
  const parsed = await parseBody(c, sessionLoginSchema);
  if ("error" in parsed) return parsed.error;
  const { username, password } = parsed.data;
  const trace = c.get("trace");
  const db = getDb();

  const t0 = performance.now();
  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username) as UserRow | undefined;
  trace.addDbQuery({
    sql: "SELECT * FROM users WHERE username = ?",
    params: [username],
    rows: user ? [{ id: user.id, username: user.username }] : [],
    ms: performance.now() - t0,
  });

  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return c.json({ success: false, error: "Invalid credentials" }, 401);
  }

  // Create session
  const sessionId = uuidv4();
  const expiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString(); // 30 min

  const t1 = performance.now();
  db.prepare("INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)").run(
    sessionId, user.id, expiresAt
  );
  trace.addDbQuery({
    sql: "INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)",
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
  const session = db.prepare(
    "SELECT s.*, u.username FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.id = ? AND s.expires_at > datetime('now')"
  ).get(sessionId) as SessionRow | undefined;
  trace.addDbQuery({
    sql: "SELECT s.*, u.username FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.id = ? AND s.expires_at > datetime('now')",
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
    db.prepare("DELETE FROM sessions WHERE id = ?").run(sessionId);
    trace.addDbQuery({
      sql: "DELETE FROM sessions WHERE id = ?",
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
  const sessions = db.prepare(
    "SELECT s.id, s.user_id, u.username, s.created_at, s.expires_at FROM sessions s JOIN users u ON s.user_id = u.id"
  ).all();
  return c.json({ success: true, data: { sessions } });
});
