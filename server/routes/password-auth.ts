import { Hono } from "hono";
import bcrypt from "bcryptjs";
import { getDb } from "../db/schema.js";
import type { UserRow } from "../../shared/api-types.js";
import { parseBody, registerSchema, loginSchema } from "../validation.js";

export const passwordAuthRoutes = new Hono();

passwordAuthRoutes.post("/register", async (c) => {
  const parsed = await parseBody(c, registerSchema);
  if ("error" in parsed) return parsed.error;
  const { username, password } = parsed.data;
  const trace = c.get("trace");
  const db = getDb();

  // Check existing
  const t0 = performance.now();
  const existing = db.prepare("SELECT id FROM users WHERE username = ?").get(username);
  trace.addDbQuery({
    sql: "SELECT id FROM users WHERE username = ?",
    params: [username],
    rows: existing ? [existing] : [],
    ms: performance.now() - t0,
  });

  if (existing) {
    return c.json({ success: false, error: "Username already exists" }, 409);
  }

  // Generate salt
  const salt = await bcrypt.genSalt(10);
  trace.addCryptoOp({
    op: "bcrypt.genSalt",
    input: `rounds=10`,
    output: salt,
    algo: "bcrypt",
    detail: "Generate random salt with cost factor 10 (2^10 = 1024 iterations)",
  });

  // Hash password
  const hash = await bcrypt.hash(password, salt);
  trace.addCryptoOp({
    op: "bcrypt.hash",
    input: `password="[REDACTED]" + salt="${salt}"`,
    output: hash,
    algo: "bcrypt",
    detail: `Blowfish key schedule x1024 rounds. Output: $2a$10$... (60 chars)`,
  });

  // Insert user
  const t1 = performance.now();
  const result = db
    .prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)")
    .run(username, hash);
  trace.addDbQuery({
    sql: "INSERT INTO users (username, password_hash) VALUES (?, ?)",
    params: [username, "***"],
    rows: [{ lastInsertRowid: result.lastInsertRowid }],
    ms: performance.now() - t1,
  });

  const user = db
    .prepare("SELECT id, username, created_at FROM users WHERE id = ?")
    .get(result.lastInsertRowid) as Pick<UserRow, "id" | "username" | "created_at">;

  return c.json({ success: true, data: { user } });
});

passwordAuthRoutes.post("/login", async (c) => {
  const parsed = await parseBody(c, loginSchema);
  if ("error" in parsed) return parsed.error;
  const { username, password } = parsed.data;
  const trace = c.get("trace");
  const db = getDb();

  // Lookup user
  const t0 = performance.now();
  const user = db
    .prepare("SELECT id, username, password_hash, created_at FROM users WHERE username = ?")
    .get(username) as UserRow | undefined;
  trace.addDbQuery({
    sql: "SELECT id, username, password_hash, created_at FROM users WHERE username = ?",
    params: [username],
    rows: user ? [{ ...user, password_hash: user.password_hash.substring(0, 20) + "..." }] : [],
    ms: performance.now() - t0,
  });

  if (!user) {
    return c.json({ success: false, error: "User not found" }, 401);
  }

  // Compare password
  const match = await bcrypt.compare(password, user.password_hash);
  trace.addCryptoOp({
    op: "bcrypt.compare",
    input: `password="[REDACTED]" vs stored_hash="${user.password_hash.substring(0, 20)}..."`,
    output: match ? "MATCH ✓" : "MISMATCH ✗",
    algo: "bcrypt",
    detail: match
      ? "Extract salt from stored hash → re-hash input → compare result"
      : "Hash of provided password does not match stored hash",
  });

  if (!match) {
    return c.json({ success: false, error: "Invalid password" }, 401);
  }

  return c.json({
    success: true,
    data: {
      user: { id: user.id, username: user.username, created_at: user.created_at },
      message: "Login successful",
    },
  });
});

passwordAuthRoutes.get("/users", (c) => {
  if (process.env.NODE_ENV === "production") {
    return c.json({ success: false, error: "Not available in production" }, 403);
  }
  const db = getDb();
  const users = db
    .prepare("SELECT id, username, password_hash, created_at FROM users")
    .all() as UserRow[];
  // Mask password_hash — show algorithm/cost prefix + partial hash for educational display
  const masked = users.map((u) => ({
    id: u.id,
    username: u.username,
    password_hash: u.password_hash === "WEBAUTHN_ONLY"
      ? "WEBAUTHN_ONLY"
      : `${u.password_hash.substring(0, 29)}...` ,
    password_hash_full_length: u.password_hash.length,
    created_at: u.created_at,
  }));
  return c.json({ success: true, data: { users: masked } });
});
