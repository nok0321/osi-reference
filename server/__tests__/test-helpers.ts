/**
 * Test helpers for backend route integration tests.
 * Creates an isolated in-memory DB + Hono app per test suite.
 */
import { Hono } from "hono";
import { _createTestDb, _setDbForTest, seedDb } from "../db/schema.js";
import { traceMiddleware } from "../middleware/trace-logger.js";
import { ensureAttackEnabled } from "../middleware/attack-guard.js";
import { passwordAuthRoutes } from "../routes/password-auth.js";
import { jwtOpsRoutes } from "../routes/jwt-ops.js";
import { sessionAuthRoutes } from "../routes/session-auth.js";
import { tokenAuthRoutes } from "../routes/token-auth.js";
import { oauthSimRoutes } from "../routes/oauth-sim.js";
import { rbacRoutes } from "../routes/rbac.js";
import { kerberoSimRoutes } from "../routes/kerberos-sim.js";
import { tlsSimRoutes } from "../routes/tls-sim.js";
import { ssoApikeyRoutes } from "../routes/sso-apikey.js";
import { mfaTotpRoutes } from "../routes/mfa-totp.js";
import { webauthnRoutes } from "../routes/webauthn.js";
import { oidcSamlSimRoutes } from "../routes/oidc-saml-sim.js";

/** Create a fresh Hono app backed by an in-memory SQLite DB. */
export function createTestApp() {
  const db = _createTestDb();
  _setDbForTest(db);
  seedDb();

  const app = new Hono();
  app.use("/api/*", async (c, next) => {
    if (c.req.path.includes("/attack/")) {
      const blocked = ensureAttackEnabled(c);
      if (blocked) return blocked;
    }
    await next();
  });
  app.use("/api/*", traceMiddleware);
  app.route("/api/auth/password", passwordAuthRoutes);
  app.route("/api/jwt", jwtOpsRoutes);
  app.route("/api/session", sessionAuthRoutes);
  app.route("/api/token", tokenAuthRoutes);
  app.route("/api/oauth", oauthSimRoutes);
  app.route("/api/rbac", rbacRoutes);
  app.route("/api/kerberos", kerberoSimRoutes);
  app.route("/api/tls", tlsSimRoutes);
  app.route("/api/sso", ssoApikeyRoutes);
  app.route("/api/mfa", mfaTotpRoutes);
  app.route("/api/webauthn", webauthnRoutes);
  app.route("/api/oidc", oidcSamlSimRoutes);

  return { app, db };
}

/** Send a JSON request to the test app and parse the response. */
export async function testRequest(
  app: Hono,
  method: string,
  path: string,
  body?: unknown,
  headers?: Record<string, string>,
) {
  const init: RequestInit = { method, headers: { ...headers } };
  if (body !== undefined) {
    init.body = JSON.stringify(body);
    (init.headers as Record<string, string>)["Content-Type"] = "application/json";
  }
  const res = await app.request(path, init);
  const json = await res.json().catch(() => null);
  return { status: res.status, json, headers: res.headers };
}

/** Shorthand helpers */
export function get(app: Hono, path: string, headers?: Record<string, string>) {
  return testRequest(app, "GET", path, undefined, headers);
}
export function post(app: Hono, path: string, body?: unknown, headers?: Record<string, string>) {
  return testRequest(app, "POST", path, body, headers);
}
export function del(app: Hono, path: string, headers?: Record<string, string>) {
  return testRequest(app, "DELETE", path, undefined, headers);
}
