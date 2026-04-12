import { describe, it, expect, beforeEach } from "vitest";
import { createTestApp, post, get } from "./test-helpers.js";
import type { Hono } from "hono";

let app: Hono;

beforeEach(() => {
  ({ app } = createTestApp());
});

/** Register a fresh user and return { username, password }. */
async function registerUser(username = "tokenuser", password = "s3cret!") {
  const res = await post(app, "/api/auth/password/register", { username, password });
  expect(res.status).toBe(200);
  return { username, password };
}

/** Register + login, returning the token response data. */
async function loginUser(username = "tokenuser", password = "s3cret!") {
  await registerUser(username, password);
  const res = await post(app, "/api/token/login", { username, password });
  expect(res.status).toBe(200);
  return res.json.data;
}

describe("POST /api/token/login", () => {
  it("returns tokens for valid credentials", async () => {
    const { username, password } = await registerUser();
    const res = await post(app, "/api/token/login", { username, password });

    expect(res.status).toBe(200);
    expect(res.json.success).toBe(true);

    const { accessToken, refreshToken, expiresIn, tokenType, user } = res.json.data;
    expect(accessToken).toMatch(/^eyJ/);
    expect(refreshToken).toMatch(/^eyJ/);
    expect(expiresIn).toBe(900);
    expect(tokenType).toBe("Bearer");
    expect(user.username).toBe(username);
  });

  it("rejects wrong password", async () => {
    const { username } = await registerUser();
    const res = await post(app, "/api/token/login", { username, password: "wrong" });

    expect(res.status).toBe(401);
    expect(res.json.success).toBe(false);
    expect(res.json.error).toContain("Invalid credentials");
  });

  it("rejects nonexistent user", async () => {
    const res = await post(app, "/api/token/login", {
      username: "nobody",
      password: "anything",
    });

    expect(res.status).toBe(401);
    expect(res.json.success).toBe(false);
    expect(res.json.error).toContain("Invalid credentials");
  });
});

describe("GET /api/token/profile", () => {
  it("returns user data with valid access token", async () => {
    const { accessToken, user } = await loginUser();
    const res = await get(app, "/api/token/profile", {
      Authorization: `Bearer ${accessToken}`,
    });

    expect(res.status).toBe(200);
    expect(res.json.success).toBe(true);
    expect(res.json.data.user.username).toBe(user.username);
    expect(res.json.data.decoded.type).toBe("access");
  });

  it("rejects missing Bearer token", async () => {
    const res = await get(app, "/api/token/profile");

    expect(res.status).toBe(401);
    expect(res.json.success).toBe(false);
    expect(res.json.error).toContain("No Bearer token");
  });

  it("rejects invalid token", async () => {
    const res = await get(app, "/api/token/profile", {
      Authorization: "Bearer this.is.invalid",
    });

    expect(res.status).toBe(401);
    expect(res.json.success).toBe(false);
  });

  it("rejects refresh token used as access token", async () => {
    const { refreshToken } = await loginUser();
    const res = await get(app, "/api/token/profile", {
      Authorization: `Bearer ${refreshToken}`,
    });

    // Refresh tokens are signed with a different secret, so verification
    // fails with "invalid signature" before the type check is reached.
    expect(res.status).toBe(401);
    expect(res.json.success).toBe(false);
  });
});

describe("POST /api/token/refresh", () => {
  it("returns new access token with valid refresh token", async () => {
    const { refreshToken } = await loginUser();
    const res = await post(app, "/api/token/refresh", { refreshToken });

    expect(res.status).toBe(200);
    expect(res.json.success).toBe(true);

    const { accessToken, expiresIn, tokenType } = res.json.data;
    expect(accessToken).toMatch(/^eyJ/);
    expect(expiresIn).toBe(900);
    expect(tokenType).toBe("Bearer");
  });

  it("refreshed access token works for profile", async () => {
    const { refreshToken } = await loginUser();
    const refreshRes = await post(app, "/api/token/refresh", { refreshToken });
    const newToken = refreshRes.json.data.accessToken;

    const profileRes = await get(app, "/api/token/profile", {
      Authorization: `Bearer ${newToken}`,
    });
    expect(profileRes.status).toBe(200);
    expect(profileRes.json.success).toBe(true);
    expect(profileRes.json.data.user.username).toBe("tokenuser");
  });

  it("rejects invalid refresh token", async () => {
    const res = await post(app, "/api/token/refresh", {
      refreshToken: "not.a.valid.token",
    });

    expect(res.status).toBe(401);
    expect(res.json.success).toBe(false);
  });
});
