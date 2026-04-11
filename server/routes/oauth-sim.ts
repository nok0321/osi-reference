import { Hono } from "hono";
import { v4 as uuidv4 } from "uuid";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { getDb } from "../db/schema.js";
import { parseBody, oauthAuthorizeSchema, oauthTokenSchema } from "../validation.js";
import type { UserRow, OAuthClientRow, OAuthCodeRow, OAuthTokenRow } from "../../shared/api-types.js";

export const oauthSimRoutes = new Hono();

const OAUTH_SECRET = "osi-demo-oauth-secret";
const VALID_SCOPES = ["read", "write", "admin", "profile", "email"] as const;

// Step 1: Authorization request — returns what the auth server would show
oauthSimRoutes.get("/authorize", (c) => {
  const trace = c.get("trace");
  const clientId = c.req.query("client_id") || "";
  const redirectUri = c.req.query("redirect_uri") || "";
  const scope = c.req.query("scope") || "read";
  const state = c.req.query("state") || "";

  const db = getDb();
  const client = db.prepare("SELECT * FROM oauth_clients WHERE client_id = ?").get(clientId) as OAuthClientRow | undefined;
  trace.addDbQuery({
    sql: "SELECT * FROM oauth_clients WHERE client_id = ?",
    params: [clientId],
    rows: client ? [client] : [],
    ms: 0,
  });

  if (!client) {
    return c.json({ success: false, error: "Unknown client_id" }, 400);
  }

  // Validate redirect_uri against registered URIs
  const registeredUris: string[] = JSON.parse(client.redirect_uris || "[]");
  if (redirectUri && !registeredUris.includes(redirectUri)) {
    return c.json({
      success: false,
      error: `Invalid redirect_uri. Registered: ${registeredUris.join(", ")}`,
    }, 400);
  }

  return c.json({
    success: true,
    data: {
      step: "authorization_page",
      client: { id: client.client_id, name: client.name },
      requestedScope: scope,
      redirectUri,
      state,
      message: "User sees consent screen — approve or deny",
    },
  });
});

// Step 2: User approves → auth code generated
oauthSimRoutes.post("/authorize", async (c) => {
  const parsed = await parseBody(c, oauthAuthorizeSchema);
  if ("error" in parsed) return parsed.error;
  const { client_id, redirect_uri, scope, state, username, password } = parsed.data;
  const trace = c.get("trace");
  const db = getDb();

  // Validate client and redirect_uri
  const client = db.prepare("SELECT * FROM oauth_clients WHERE client_id = ?").get(client_id) as OAuthClientRow | undefined;
  if (!client) {
    return c.json({ success: false, error: "Unknown client_id" }, 400);
  }
  const registeredUris: string[] = JSON.parse(client.redirect_uris || "[]");
  if (redirect_uri && !registeredUris.includes(redirect_uri)) {
    return c.json({
      success: false,
      error: `Invalid redirect_uri. Registered: ${registeredUris.join(", ")}`,
    }, 400);
  }

  // Authenticate user
  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username) as UserRow | undefined;
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return c.json({ success: false, error: "Invalid credentials" }, 401);
  }

  // Generate authorization code
  const code = uuidv4();
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();

  db.prepare(
    "INSERT INTO oauth_codes (code, client_id, user_id, scope, redirect_uri, expires_at) VALUES (?, ?, ?, ?, ?, ?)"
  ).run(code, client_id, user.id, scope, redirect_uri, expiresAt);

  trace.addDbQuery({
    sql: "INSERT INTO oauth_codes (code, client_id, user_id, scope, redirect_uri, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
    params: [code, client_id, user.id, scope, redirect_uri, expiresAt],
    ms: 0,
  });

  trace.addCryptoOp({
    op: "generateAuthCode",
    input: `user=${username}, client=${client_id}, scope=${scope}`,
    output: code,
    algo: "UUIDv4",
    detail: "One-time authorization code, valid 10 minutes",
  });

  return c.json({
    success: true,
    data: {
      step: "authorization_code_issued",
      code,
      redirectUri: `${redirect_uri}?code=${code}&state=${state}`,
      expiresAt,
    },
  });
});

// Step 3: Exchange code for tokens
oauthSimRoutes.post("/token", async (c) => {
  const parsedBody = await parseBody(c, oauthTokenSchema);
  if ("error" in parsedBody) return parsedBody.error;
  const body = parsedBody.data;
  const trace = c.get("trace");
  const db = getDb();

  if (body.grant_type === "authorization_code") {
    const { code, client_id, client_secret } = body;

    // Verify client
    const client = db.prepare(
      "SELECT * FROM oauth_clients WHERE client_id = ? AND client_secret = ?"
    ).get(client_id, client_secret) as OAuthClientRow | undefined;
    trace.addDbQuery({
      sql: "SELECT * FROM oauth_clients WHERE client_id = ? AND client_secret = ?",
      params: [client_id, "***"],
      rows: client ? [{ client_id: client.client_id, name: client.name }] : [],
      ms: 0,
    });

    if (!client) {
      return c.json({ success: false, error: "Invalid client credentials" }, 401);
    }

    // Atomically mark code as used and verify in one step (prevents double-spend race condition)
    const t1 = performance.now();
    const codeUpdate = db.prepare(
      "UPDATE oauth_codes SET used = 1 WHERE code = ? AND client_id = ? AND used = 0 AND expires_at > datetime('now')"
    ).run(code, client_id);
    trace.addDbQuery({
      sql: "UPDATE oauth_codes SET used = 1 WHERE code = ? AND client_id = ? AND used = 0 AND expires_at > datetime('now')",
      params: [code, client_id],
      rows: [{ changes: codeUpdate.changes }],
      ms: performance.now() - t1,
    });

    if (codeUpdate.changes === 0) {
      return c.json({ success: false, error: "Invalid or expired authorization code" }, 400);
    }

    // Fetch the code details for token generation
    const authCode = db.prepare(
      "SELECT * FROM oauth_codes WHERE code = ? AND client_id = ?"
    ).get(code, client_id) as OAuthCodeRow | undefined;

    if (!authCode) {
      return c.json({ success: false, error: "Authorization code not found" }, 400);
    }

    // Validate redirect_uri matches the one used during authorization
    if (body.redirect_uri && body.redirect_uri !== authCode.redirect_uri) {
      return c.json({ success: false, error: "redirect_uri mismatch" }, 400);
    }

    // Generate tokens
    const user = db.prepare("SELECT id, username FROM users WHERE id = ?").get(authCode.user_id) as Pick<UserRow, "id" | "username"> | undefined;
    if (!user) {
      return c.json({ success: false, error: "User associated with authorization code not found" }, 500);
    }
    const accessToken = jwt.sign(
      { sub: user.id, username: user.username, scope: authCode.scope, type: "oauth_access" },
      OAUTH_SECRET,
      { expiresIn: "1h" }
    );
    const refreshToken = uuidv4();
    const expiresAt = new Date(Date.now() + 3600 * 1000).toISOString();

    db.prepare(
      "INSERT INTO oauth_tokens (access_token, refresh_token, client_id, user_id, scope, expires_at) VALUES (?, ?, ?, ?, ?, ?)"
    ).run(accessToken, refreshToken, client_id, user.id, authCode.scope, expiresAt);

    trace.addCryptoOp({
      op: "jwt.sign(oauth_access_token)",
      input: JSON.stringify({ sub: user.id, scope: authCode.scope }),
      output: accessToken.substring(0, 40) + "...",
      algo: "HS256",
    });

    return c.json({
      success: true,
      data: {
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: 3600,
        refresh_token: refreshToken,
        scope: authCode.scope,
      },
    });
  }

  if (body.grant_type === "refresh_token") {
    const { refresh_token, client_id } = body;
    const tokenRow = db.prepare(
      "SELECT * FROM oauth_tokens WHERE refresh_token = ? AND client_id = ?"
    ).get(refresh_token, client_id) as OAuthTokenRow | undefined;

    if (!tokenRow) {
      return c.json({ success: false, error: "Invalid refresh token" }, 400);
    }

    const user = db.prepare("SELECT id, username FROM users WHERE id = ?").get(tokenRow.user_id) as Pick<UserRow, "id" | "username"> | undefined;
    if (!user) {
      return c.json({ success: false, error: "User associated with token not found" }, 500);
    }
    const newAccessToken = jwt.sign(
      { sub: user.id, username: user.username, scope: tokenRow.scope, type: "oauth_access" },
      OAUTH_SECRET,
      { expiresIn: "1h" }
    );
    const newRefreshToken = uuidv4();
    const expiresAt = new Date(Date.now() + 3600 * 1000).toISOString();

    db.prepare("DELETE FROM oauth_tokens WHERE refresh_token = ?").run(refresh_token);
    db.prepare(
      "INSERT INTO oauth_tokens (access_token, refresh_token, client_id, user_id, scope, expires_at) VALUES (?, ?, ?, ?, ?, ?)"
    ).run(newAccessToken, newRefreshToken, client_id, user.id, tokenRow.scope, expiresAt);

    return c.json({
      success: true,
      data: {
        access_token: newAccessToken,
        token_type: "Bearer",
        expires_in: 3600,
        refresh_token: newRefreshToken,
        scope: tokenRow.scope,
      },
    });
  }

  return c.json({ success: false, error: "Unsupported grant_type" }, 400);
});

// Step 4: Access protected resource
oauthSimRoutes.get("/resource", (c) => {
  const trace = c.get("trace");
  const authHeader = c.req.header("Authorization");

  if (!authHeader?.startsWith("Bearer ")) {
    return c.json({ success: false, error: "No Bearer token" }, 401);
  }

  try {
    const decoded = jwt.verify(authHeader.slice(7), OAUTH_SECRET) as unknown as { sub: number; username: string; scope: string };
    trace.addCryptoOp({
      op: "jwt.verify(oauth_access_token)",
      input: authHeader.slice(7).substring(0, 30) + "...",
      output: "VALID ✓",
      algo: "HS256",
    });

    return c.json({
      success: true,
      data: {
        resource: {
          message: "Protected resource accessed successfully",
          user: decoded.username,
          scope: decoded.scope,
          data: [
            { id: 1, title: "Article 1", content: "OAuth-protected content" },
            { id: 2, title: "Article 2", content: "More protected content" },
          ],
        },
      },
    });
  } catch {
    return c.json({ success: false, error: "Invalid or expired token" }, 401);
  }
});
