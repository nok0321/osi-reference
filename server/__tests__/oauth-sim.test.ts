import { describe, it, expect, beforeEach } from "vitest";
import { createTestApp, post, get } from "./test-helpers.js";
import type { Hono } from "hono";

let app: Hono;

beforeEach(() => {
  ({ app } = createTestApp());
});

// Shared constants matching seeded data
const CLIENT_ID = "demo-app";
const CLIENT_SECRET = "demo-secret-12345";
const REDIRECT_URI = "http://localhost:3000/auth/oauth/callback";
const USERNAME = "oidc-user";
const PASSWORD = "demo123";

/** Run the authorization step and return the auth code. */
async function getAuthCode(
  testApp: Hono,
  overrides: Record<string, string> = {},
): Promise<string> {
  const res = await post(testApp, "/api/oauth/authorize", {
    client_id: overrides.client_id ?? CLIENT_ID,
    redirect_uri: overrides.redirect_uri ?? REDIRECT_URI,
    scope: overrides.scope ?? "read",
    state: overrides.state ?? "test-state",
    username: overrides.username ?? USERNAME,
    password: overrides.password ?? PASSWORD,
  });
  expect(res.status).toBe(200);
  return res.json.data.code;
}

/** Run the full auth code -> token exchange and return the token data. */
async function getTokens(testApp: Hono, code: string) {
  const res = await post(testApp, "/api/oauth/token", {
    grant_type: "authorization_code",
    code,
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
  });
  expect(res.status).toBe(200);
  return res.json.data;
}

describe("GET /api/oauth/authorize", () => {
  it("returns consent page info for a valid client", async () => {
    const res = await get(
      app,
      `/api/oauth/authorize?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&scope=read&state=xyz`,
    );
    expect(res.status).toBe(200);
    expect(res.json.success).toBe(true);
    expect(res.json.data.step).toBe("authorization_page");
    expect(res.json.data.client.id).toBe(CLIENT_ID);
    expect(res.json.data.requestedScope).toBe("read");
    expect(res.json.data.state).toBe("xyz");
  });

  it("rejects unknown client_id", async () => {
    const res = await get(
      app,
      `/api/oauth/authorize?client_id=unknown-app&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&scope=read`,
    );
    expect(res.status).toBe(400);
    expect(res.json.error).toContain("Unknown client_id");
  });

  it("rejects invalid redirect_uri", async () => {
    const res = await get(
      app,
      `/api/oauth/authorize?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent("http://evil.com/callback")}&scope=read`,
    );
    expect(res.status).toBe(400);
    expect(res.json.error).toContain("Invalid redirect_uri");
  });
});

describe("POST /api/oauth/authorize", () => {
  it("issues an authorization code for valid credentials", async () => {
    const res = await post(app, "/api/oauth/authorize", {
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: "read",
      state: "test-state",
      username: USERNAME,
      password: PASSWORD,
    });
    expect(res.status).toBe(200);
    expect(res.json.success).toBe(true);
    expect(res.json.data.step).toBe("authorization_code_issued");
    expect(res.json.data.code).toBeTruthy();
    expect(res.json.data.redirectUri).toContain("code=");
    expect(res.json.data.redirectUri).toContain("state=test-state");
  });

  it("rejects invalid user credentials", async () => {
    const res = await post(app, "/api/oauth/authorize", {
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: "read",
      state: "xyz",
      username: USERNAME,
      password: "wrong-password",
    });
    expect(res.status).toBe(401);
    expect(res.json.error).toContain("Invalid credentials");
  });

  it("rejects unknown client_id", async () => {
    const res = await post(app, "/api/oauth/authorize", {
      client_id: "fake-client",
      redirect_uri: REDIRECT_URI,
      scope: "read",
      state: "xyz",
      username: USERNAME,
      password: PASSWORD,
    });
    expect(res.status).toBe(400);
    expect(res.json.error).toContain("Unknown client_id");
  });
});

describe("POST /api/oauth/token (authorization_code)", () => {
  it("exchanges a valid code for access and refresh tokens", async () => {
    const code = await getAuthCode(app);

    const res = await post(app, "/api/oauth/token", {
      grant_type: "authorization_code",
      code,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
    });
    expect(res.status).toBe(200);
    expect(res.json.success).toBe(true);
    expect(res.json.data.access_token).toMatch(/^eyJ/);
    expect(res.json.data.token_type).toBe("Bearer");
    expect(res.json.data.expires_in).toBe(3600);
    expect(res.json.data.refresh_token).toBeTruthy();
    expect(res.json.data.scope).toBe("read");
  });

  it("rejects double-spend of the same authorization code", async () => {
    const code = await getAuthCode(app);

    // First use succeeds
    const res1 = await post(app, "/api/oauth/token", {
      grant_type: "authorization_code",
      code,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
    });
    expect(res1.status).toBe(200);

    // Second use of the same code fails
    const res2 = await post(app, "/api/oauth/token", {
      grant_type: "authorization_code",
      code,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
    });
    expect(res2.status).toBe(400);
    expect(res2.json.error).toContain("Invalid or expired authorization code");
  });

  it("rejects an invalid authorization code", async () => {
    const res = await post(app, "/api/oauth/token", {
      grant_type: "authorization_code",
      code: "non-existent-code",
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
    });
    expect(res.status).toBe(400);
    expect(res.json.error).toContain("Invalid or expired authorization code");
  });

  it("rejects invalid client credentials", async () => {
    const code = await getAuthCode(app);

    const res = await post(app, "/api/oauth/token", {
      grant_type: "authorization_code",
      code,
      client_id: CLIENT_ID,
      client_secret: "wrong-secret",
    });
    expect(res.status).toBe(401);
    expect(res.json.error).toContain("Invalid client credentials");
  });
});

describe("GET /api/oauth/resource", () => {
  it("returns protected resource with a valid Bearer token", async () => {
    const code = await getAuthCode(app);
    const tokens = await getTokens(app, code);

    const res = await get(app, "/api/oauth/resource", {
      Authorization: `Bearer ${tokens.access_token}`,
    });
    expect(res.status).toBe(200);
    expect(res.json.success).toBe(true);
    expect(res.json.data.resource.message).toContain("successfully");
    expect(res.json.data.resource.user).toBe(USERNAME);
    expect(res.json.data.resource.scope).toBe("read");
    expect(res.json.data.resource.data).toHaveLength(2);
  });

  it("returns 401 without a Bearer token", async () => {
    const res = await get(app, "/api/oauth/resource");
    expect(res.status).toBe(401);
    expect(res.json.error).toContain("No Bearer token");
  });

  it("returns 401 with an invalid Bearer token", async () => {
    const res = await get(app, "/api/oauth/resource", {
      Authorization: "Bearer invalid-token-abc123",
    });
    expect(res.status).toBe(401);
    expect(res.json.error).toContain("Invalid or expired token");
  });
});

describe("POST /api/oauth/token (refresh_token)", () => {
  it("issues new tokens using a valid refresh token", async () => {
    const code = await getAuthCode(app);
    const tokens = await getTokens(app, code);
    const originalAccessToken = tokens.access_token;
    const originalRefreshToken = tokens.refresh_token;

    const res = await post(app, "/api/oauth/token", {
      grant_type: "refresh_token",
      refresh_token: originalRefreshToken,
      client_id: CLIENT_ID,
    });
    expect(res.status).toBe(200);
    expect(res.json.success).toBe(true);
    expect(res.json.data.access_token).toMatch(/^eyJ/);
    expect(res.json.data.refresh_token).toBeTruthy();
    // Refresh token is always rotated (new UUID)
    expect(res.json.data.refresh_token).not.toBe(originalRefreshToken);
    // New access token is a valid JWT
    expect(res.json.data.access_token).toMatch(/^eyJ/);
  });

  it("invalidates the old refresh token after use", async () => {
    const code = await getAuthCode(app);
    const tokens = await getTokens(app, code);

    // Use the refresh token once
    const res1 = await post(app, "/api/oauth/token", {
      grant_type: "refresh_token",
      refresh_token: tokens.refresh_token,
      client_id: CLIENT_ID,
    });
    expect(res1.status).toBe(200);

    // Try to reuse the same refresh token (rotation invalidates it)
    const res2 = await post(app, "/api/oauth/token", {
      grant_type: "refresh_token",
      refresh_token: tokens.refresh_token,
      client_id: CLIENT_ID,
    });
    expect(res2.status).toBe(400);
    expect(res2.json.error).toContain("Invalid refresh token");
  });

  it("rejects an invalid refresh token", async () => {
    const res = await post(app, "/api/oauth/token", {
      grant_type: "refresh_token",
      refresh_token: "bogus-refresh-token",
      client_id: CLIENT_ID,
    });
    expect(res.status).toBe(400);
    expect(res.json.error).toContain("Invalid refresh token");
  });
});

describe("Full OAuth 2.0 authorization code flow", () => {
  it("completes the entire flow: authorize -> code -> token -> resource", async () => {
    // Step 1: GET authorize (consent page)
    const consentRes = await get(
      app,
      `/api/oauth/authorize?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&scope=read&state=full-flow`,
    );
    expect(consentRes.status).toBe(200);
    expect(consentRes.json.data.step).toBe("authorization_page");

    // Step 2: POST authorize (user approves)
    const authRes = await post(app, "/api/oauth/authorize", {
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: "read",
      state: "full-flow",
      username: USERNAME,
      password: PASSWORD,
    });
    expect(authRes.status).toBe(200);
    const code = authRes.json.data.code;

    // Step 3: Exchange code for tokens
    const tokenRes = await post(app, "/api/oauth/token", {
      grant_type: "authorization_code",
      code,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
    });
    expect(tokenRes.status).toBe(200);
    const accessToken = tokenRes.json.data.access_token;

    // Step 4: Access protected resource
    const resourceRes = await get(app, "/api/oauth/resource", {
      Authorization: `Bearer ${accessToken}`,
    });
    expect(resourceRes.status).toBe(200);
    expect(resourceRes.json.data.resource.user).toBe(USERNAME);

    // Step 5: Refresh token
    const refreshRes = await post(app, "/api/oauth/token", {
      grant_type: "refresh_token",
      refresh_token: tokenRes.json.data.refresh_token,
      client_id: CLIENT_ID,
    });
    expect(refreshRes.status).toBe(200);
    const newAccessToken = refreshRes.json.data.access_token;

    // Step 6: Access resource with refreshed token
    const resourceRes2 = await get(app, "/api/oauth/resource", {
      Authorization: `Bearer ${newAccessToken}`,
    });
    expect(resourceRes2.status).toBe(200);
    expect(resourceRes2.json.data.resource.user).toBe(USERNAME);
  });
});
