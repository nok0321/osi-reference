import { describe, it, expect, beforeEach } from "vitest";
import { Hono } from "hono";
import { createTestApp, post, get } from "./test-helpers.js";

let app: Hono;

beforeEach(() => {
  ({ app } = createTestApp());
});

describe("POST /api/rbac/check", () => {
  it("denies access for user with no roles", async () => {
    const res = await post(app, "/api/rbac/check", {
      subject: "oidc-user",
      resource: "articles",
      action: "read",
    });
    expect(res.status).toBe(200);
    expect(res.json.success).toBe(true);
    expect(res.json.data.allowed).toBe(false);
    expect(res.json.data.reason).toBe("No roles assigned");
  });

  it("grants access after role is assigned", async () => {
    await post(app, "/api/rbac/assign", { username: "oidc-user", roleName: "viewer" });
    const res = await post(app, "/api/rbac/check", {
      subject: "oidc-user",
      resource: "articles",
      action: "read",
    });
    expect(res.status).toBe(200);
    expect(res.json.data.allowed).toBe(true);
    expect(res.json.data.reason).toBe("Permission granted");
  });

  it("denies access for action not in role permissions", async () => {
    await post(app, "/api/rbac/assign", { username: "oidc-user", roleName: "viewer" });
    const res = await post(app, "/api/rbac/check", {
      subject: "oidc-user",
      resource: "articles",
      action: "delete",
    });
    expect(res.status).toBe(200);
    expect(res.json.data.allowed).toBe(false);
    expect(res.json.data.reason).toBe("Permission denied");
  });
});

describe("POST /api/rbac/abac/check", () => {
  it("passes when all policies are met", async () => {
    const res = await post(app, "/api/rbac/abac/check", {
      subject: "admin-user",
      resource: "articles",
      action: "write",
      context: { hour: 10, role: "admin" },
    });
    expect(res.status).toBe(200);
    expect(res.json.data.allowed).toBe(true);
    expect(res.json.data.reason).toBe("All policies passed");
  });

  it("fails when time is outside business hours", async () => {
    const res = await post(app, "/api/rbac/abac/check", {
      subject: "admin-user",
      resource: "articles",
      action: "read",
      context: { hour: 22, role: "admin" },
    });
    expect(res.status).toBe(200);
    expect(res.json.data.allowed).toBe(false);
    const timeStep = res.json.data.evaluationSteps.find(
      (s: { rule: string }) => s.rule === "time-restriction"
    );
    expect(timeStep.result).toBe("FAIL");
  });
});

describe("POST /api/rbac/acl/check", () => {
  it("allows admin to read file:report.pdf", async () => {
    const res = await post(app, "/api/rbac/acl/check", {
      subject: "admin",
      resource: "file:report.pdf",
      action: "read",
    });
    expect(res.status).toBe(200);
    expect(res.json.data.allowed).toBe(true);
    expect(res.json.data.reason).toBe("ACL permits access");
  });

  it("denies viewer write access to file:report.pdf", async () => {
    const res = await post(app, "/api/rbac/acl/check", {
      subject: "viewer",
      resource: "file:report.pdf",
      action: "write",
    });
    expect(res.status).toBe(200);
    expect(res.json.data.allowed).toBe(false);
    expect(res.json.data.reason).toBe("ACL denies access");
  });
});

describe("POST /api/rbac/assign", () => {
  it("returns 404 for nonexistent user or role", async () => {
    const res = await post(app, "/api/rbac/assign", { username: "nobody", roleName: "admin" });
    expect(res.status).toBe(404);
    expect(res.json.success).toBe(false);
  });
});

describe("GET /api/rbac/roles", () => {
  it("returns seeded roles with permissions", async () => {
    const res = await get(app, "/api/rbac/roles");
    expect(res.status).toBe(200);
    expect(res.json.success).toBe(true);
    const roles = res.json.data.roles;
    expect(roles).toHaveLength(3);
    const names = roles.map((r: { name: string }) => r.name).sort();
    expect(names).toEqual(["admin", "editor", "viewer"]);
    const admin = roles.find((r: { name: string }) => r.name === "admin");
    expect(admin.permissions).toContain("articles:read");
    expect(admin.permissions).toContain("settings:delete");
  });
});
