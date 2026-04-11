import { describe, it, expect, beforeEach } from "vitest";
import { createTestApp, post, get, del } from "./test-helpers.js";
import type { Hono } from "hono";

let app: Hono;

beforeEach(() => {
  ({ app } = createTestApp());
});

/** Extract the session_id cookie value from a Set-Cookie header. */
function extractSessionCookie(headers: Headers): string | null {
  const setCookie = headers.get("set-cookie");
  if (!setCookie) return null;
  const match = setCookie.match(/session_id=([^;]+)/);
  return match ? match[1] : null;
}

describe("POST /api/session/login", () => {
  it("creates a session and returns Set-Cookie header", async () => {
    // "oidc-user" is seeded with password "demo123"
    const res = await post(app, "/api/session/login", {
      username: "oidc-user",
      password: "demo123",
    });
    expect(res.status).toBe(200);
    expect(res.json.success).toBe(true);
    expect(res.json.data.user.username).toBe("oidc-user");
    expect(res.json.data.session.sessionId).toBeTruthy();
    expect(res.json.data.session.expiresAt).toBeTruthy();

    // Should set a session cookie
    const sessionId = extractSessionCookie(res.headers);
    expect(sessionId).toBeTruthy();
    expect(sessionId).toBe(res.json.data.session.sessionId);
  });

  it("rejects wrong password", async () => {
    const res = await post(app, "/api/session/login", {
      username: "oidc-user",
      password: "wrong-password",
    });
    expect(res.status).toBe(401);
    expect(res.json.success).toBe(false);
    expect(res.json.error).toContain("Invalid credentials");
  });

  it("rejects nonexistent user", async () => {
    const res = await post(app, "/api/session/login", {
      username: "nobody",
      password: "anything",
    });
    expect(res.status).toBe(401);
  });

  it("rejects missing fields", async () => {
    const res = await post(app, "/api/session/login", {});
    expect(res.status).toBe(400);
    expect(res.json.error).toContain("Validation error");
  });
});

describe("GET /api/session/profile", () => {
  it("returns user data with a valid session cookie", async () => {
    // Login to get a session cookie
    const loginRes = await post(app, "/api/session/login", {
      username: "oidc-user",
      password: "demo123",
    });
    const sessionId = extractSessionCookie(loginRes.headers);
    expect(sessionId).toBeTruthy();

    // Access profile with the session cookie
    const profileRes = await get(app, "/api/session/profile", {
      Cookie: `session_id=${sessionId}`,
    });
    expect(profileRes.status).toBe(200);
    expect(profileRes.json.success).toBe(true);
    expect(profileRes.json.data.user.username).toBe("oidc-user");
    expect(profileRes.json.data.session.id).toBe(sessionId);
  });

  it("returns 401 without a session cookie", async () => {
    const res = await get(app, "/api/session/profile");
    expect(res.status).toBe(401);
    expect(res.json.success).toBe(false);
    expect(res.json.error).toContain("No session cookie");
  });

  it("returns 401 with an invalid session cookie", async () => {
    const res = await get(app, "/api/session/profile", {
      Cookie: "session_id=invalid-session-id-12345",
    });
    expect(res.status).toBe(401);
    expect(res.json.success).toBe(false);
    expect(res.json.error).toContain("expired or invalid");
  });
});

describe("DELETE /api/session/logout", () => {
  it("clears the session and subsequent profile access fails", async () => {
    // Login
    const loginRes = await post(app, "/api/session/login", {
      username: "oidc-user",
      password: "demo123",
    });
    const sessionId = extractSessionCookie(loginRes.headers);
    expect(sessionId).toBeTruthy();

    // Logout
    const logoutRes = await del(app, "/api/session/logout", {
      Cookie: `session_id=${sessionId}`,
    });
    expect(logoutRes.status).toBe(200);
    expect(logoutRes.json.success).toBe(true);
    expect(logoutRes.json.data.message).toBe("Logged out");

    // Profile should now fail with the old session cookie
    const profileRes = await get(app, "/api/session/profile", {
      Cookie: `session_id=${sessionId}`,
    });
    expect(profileRes.status).toBe(401);
  });

  it("succeeds even without a session cookie (no-op)", async () => {
    const res = await del(app, "/api/session/logout");
    expect(res.status).toBe(200);
    expect(res.json.success).toBe(true);
  });
});

describe("GET /api/session/store", () => {
  it("returns an empty sessions list initially", async () => {
    const res = await get(app, "/api/session/store");
    expect(res.status).toBe(200);
    expect(res.json.success).toBe(true);
    expect(res.json.data.sessions).toEqual([]);
  });

  it("returns sessions after login", async () => {
    // Login to create a session
    await post(app, "/api/session/login", {
      username: "oidc-user",
      password: "demo123",
    });

    const res = await get(app, "/api/session/store");
    expect(res.status).toBe(200);
    expect(res.json.data.sessions).toHaveLength(1);
    expect(res.json.data.sessions[0].username).toBe("oidc-user");
    expect(res.json.data.sessions[0].id).toBeTruthy();
    expect(res.json.data.sessions[0].expires_at).toBeTruthy();
  });

  it("reflects multiple sessions from different logins", async () => {
    await post(app, "/api/session/login", {
      username: "oidc-user",
      password: "demo123",
    });
    await post(app, "/api/session/login", {
      username: "saml-user",
      password: "demo123",
    });

    const res = await get(app, "/api/session/store");
    expect(res.status).toBe(200);
    expect(res.json.data.sessions).toHaveLength(2);
    const usernames = res.json.data.sessions.map(
      (s: { username: string }) => s.username,
    );
    expect(usernames).toContain("oidc-user");
    expect(usernames).toContain("saml-user");
  });
});
