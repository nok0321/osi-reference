import { describe, it, expect, beforeEach } from "vitest";
import { createTestApp, post, get } from "./test-helpers.js";
import type { Hono } from "hono";

let app: Hono;

beforeEach(() => {
  ({ app } = createTestApp());
});

describe("POST /api/auth/password/register", () => {
  it("registers a new user", async () => {
    const res = await post(app, "/api/auth/password/register", {
      username: "testuser",
      password: "testpass123",
    });
    expect(res.status).toBe(200);
    expect(res.json.success).toBe(true);
    expect(res.json.data.user.username).toBe("testuser");
    expect(res.json.data.user.id).toBeGreaterThan(0);
    // Should not leak password_hash
    expect(res.json.data.user.password_hash).toBeUndefined();
  });

  it("rejects duplicate username", async () => {
    await post(app, "/api/auth/password/register", { username: "dup", password: "pass" });
    const res = await post(app, "/api/auth/password/register", { username: "dup", password: "pass2" });
    expect(res.status).toBe(409);
    expect(res.json.success).toBe(false);
  });

  it("rejects empty body", async () => {
    const res = await post(app, "/api/auth/password/register", {});
    expect(res.status).toBe(400);
    expect(res.json.error).toContain("Validation error");
  });
});

describe("POST /api/auth/password/login", () => {
  beforeEach(async () => {
    await post(app, "/api/auth/password/register", { username: "alice", password: "secret" });
  });

  it("logs in with correct credentials", async () => {
    const res = await post(app, "/api/auth/password/login", { username: "alice", password: "secret" });
    expect(res.status).toBe(200);
    expect(res.json.success).toBe(true);
    expect(res.json.data.user.username).toBe("alice");
  });

  it("rejects wrong password", async () => {
    const res = await post(app, "/api/auth/password/login", { username: "alice", password: "wrong" });
    expect(res.status).toBe(401);
    expect(res.json.success).toBe(false);
  });

  it("rejects nonexistent user", async () => {
    const res = await post(app, "/api/auth/password/login", { username: "nobody", password: "x" });
    expect(res.status).toBe(401);
  });
});

describe("GET /api/auth/password/users", () => {
  it("returns user list with masked hashes", async () => {
    await post(app, "/api/auth/password/register", { username: "bob", password: "pass" });
    const res = await get(app, "/api/auth/password/users");
    expect(res.status).toBe(200);
    const users = res.json.data.users;
    expect(users.length).toBeGreaterThan(0);
    const bob = users.find((u: { username: string }) => u.username === "bob");
    expect(bob).toBeDefined();
    // Hash should be truncated (not full 60 chars)
    expect(bob.password_hash).toContain("...");
  });
});
