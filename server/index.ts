import { Hono } from "hono";
import { cors } from "hono/cors";
import { serve } from "@hono/node-server";
import { traceMiddleware } from "./middleware/trace-logger.js";
import { getDb, seedDb } from "./db/schema.js";
import { passwordAuthRoutes } from "./routes/password-auth.js";
import { jwtOpsRoutes } from "./routes/jwt-ops.js";
import { sessionAuthRoutes } from "./routes/session-auth.js";
import { tokenAuthRoutes } from "./routes/token-auth.js";
import { oauthSimRoutes } from "./routes/oauth-sim.js";
import { rbacRoutes } from "./routes/rbac.js";
import { webauthnRoutes } from "./routes/webauthn.js";
import { kerberoSimRoutes } from "./routes/kerberos-sim.js";
import { oidcSamlSimRoutes } from "./routes/oidc-saml-sim.js";
import { ssoApikeyRoutes } from "./routes/sso-apikey.js";
import { tlsSimRoutes } from "./routes/tls-sim.js";
import { mfaTotpRoutes } from "./routes/mfa-totp.js";
import { passkeyRoutes } from "./routes/passkey.js";
import { cleanExpiredSessions } from "./db/queries.js";

const app = new Hono();

// ── Middleware ──
app.use("/api/*", cors({ origin: "http://localhost:3000", credentials: true }));
app.use("/api/*", traceMiddleware);

// ── Routes ──
app.route("/api/auth/password", passwordAuthRoutes);
app.route("/api/jwt", jwtOpsRoutes);
app.route("/api/session", sessionAuthRoutes);
app.route("/api/token", tokenAuthRoutes);
app.route("/api/oauth", oauthSimRoutes);
app.route("/api/rbac", rbacRoutes);
app.route("/api/webauthn", webauthnRoutes);
app.route("/api/kerberos", kerberoSimRoutes);
app.route("/api/oidc", oidcSamlSimRoutes);
app.route("/api/sso", ssoApikeyRoutes);
app.route("/api/tls", tlsSimRoutes);
app.route("/api/mfa", mfaTotpRoutes);
app.route("/api/passkey", passkeyRoutes);

// ── Debug: view DB tables (development only) ──
const ALLOWED_TABLES = [
  "users", "sessions", "oauth_clients", "oauth_codes", "oauth_tokens",
  "roles", "user_roles", "permissions", "role_permissions",
  "webauthn_credentials", "api_keys", "kerberos_tickets", "user_mfa",
] as const;
type AllowedTable = (typeof ALLOWED_TABLES)[number];

// Map of safe SELECT queries per table (prevents SQL injection entirely)
const TABLE_QUERIES: Record<AllowedTable, string> = {
  users: "SELECT id, username, created_at FROM users",
  sessions: "SELECT id, user_id, created_at, expires_at FROM sessions",
  oauth_clients: "SELECT * FROM oauth_clients",
  oauth_codes: "SELECT * FROM oauth_codes",
  oauth_tokens: "SELECT * FROM oauth_tokens",
  roles: "SELECT * FROM roles",
  user_roles: "SELECT * FROM user_roles",
  permissions: "SELECT * FROM permissions",
  role_permissions: "SELECT * FROM role_permissions",
  webauthn_credentials: "SELECT credential_id, user_id, counter, created_at FROM webauthn_credentials",
  api_keys: "SELECT key_id, key_prefix, name, created_at, last_used FROM api_keys",
  kerberos_tickets: "SELECT ticket_type, principal, realm, valid_until, created_at FROM kerberos_tickets",
  user_mfa: "SELECT user_id, verified, created_at, verified_at FROM user_mfa",
};

app.get("/api/debug/tables/:name", (c) => {
  if (process.env.NODE_ENV === "production") {
    return c.json({ success: false, error: "Debug endpoints disabled in production" }, 403);
  }
  const name = c.req.param("name");
  if (!ALLOWED_TABLES.includes(name as AllowedTable)) {
    return c.json({ success: false, error: "Table not allowed" }, 400);
  }
  const db = getDb();
  const query = TABLE_QUERIES[name as AllowedTable];
  const rows = db.prepare(query).all();
  return c.json({ success: true, data: { rows } });
});

// ── Reset (development only) ──
app.post("/api/reset", (c) => {
  if (process.env.NODE_ENV === "production") {
    return c.json({ success: false, error: "Reset disabled in production" }, 403);
  }
  seedDb();
  return c.json({ success: true, data: { message: "Database reset and seeded" } });
});

// ── Health check ──
app.get("/api/health", (c) => c.json({ status: "ok", time: new Date().toISOString() }));

// ── Init DB and start ──
getDb();
if (process.env.NODE_ENV !== "production") {
  seedDb();
}

// ── Periodic cleanup: expired sessions ──
setInterval(() => {
  const deleted = cleanExpiredSessions();
  if (deleted > 0) console.log(`🧹 Cleaned ${deleted} expired session(s)`);
}, 5 * 60 * 1000); // every 5 minutes

const PORT = 3001;
console.log(`🔧 Hono server running on http://localhost:${PORT}`);
serve({ fetch: app.fetch, port: PORT });
