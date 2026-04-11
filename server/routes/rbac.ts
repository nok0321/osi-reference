import { Hono } from "hono";
import { getDb } from "../db/schema.js";
import { parseBody, accessCheckSchema, roleAssignSchema } from "../validation.js";
import type { UserRow, RoleRow, PermissionRow } from "../../shared/api-types.js";

export const rbacRoutes = new Hono();

// RBAC check
rbacRoutes.post("/check", async (c) => {
  const parsed = await parseBody(c, accessCheckSchema);
  if ("error" in parsed) return parsed.error;
  const { subject, resource, action } = parsed.data;
  const trace = c.get("trace");
  const db = getDb();
  const steps: { rule: string; result: string; detail: string }[] = [];

  // 1. Find user
  const t0 = performance.now();
  const user = db.prepare("SELECT id, username FROM users WHERE username = ?").get(subject) as Pick<UserRow, "id" | "username"> | undefined;
  trace.addDbQuery({
    sql: "SELECT id, username FROM users WHERE username = ?",
    params: [subject],
    rows: user ? [user] : [],
    ms: performance.now() - t0,
  });
  steps.push({
    rule: "Lookup user",
    result: user ? "FOUND" : "NOT_FOUND",
    detail: user ? `User ID: ${user.id}` : `User "${subject}" not found`,
  });

  if (!user) {
    return c.json({
      success: true,
      data: { allowed: false, reason: "User not found", evaluationSteps: steps },
    });
  }

  // 2. Find user's roles
  const t1 = performance.now();
  const roles = db.prepare(
    "SELECT r.id, r.name FROM roles r JOIN user_roles ur ON r.id = ur.role_id WHERE ur.user_id = ?"
  ).all(user.id) as Pick<RoleRow, "id" | "name">[];
  trace.addDbQuery({
    sql: "SELECT r.id, r.name FROM roles r JOIN user_roles ur ON r.id = ur.role_id WHERE ur.user_id = ?",
    params: [user.id],
    rows: roles,
    ms: performance.now() - t1,
  });
  steps.push({
    rule: "Lookup roles",
    result: roles.length > 0 ? "FOUND" : "NONE",
    detail: `Roles: [${roles.map((r) => r.name).join(", ")}]`,
  });

  if (roles.length === 0) {
    return c.json({
      success: true,
      data: { allowed: false, reason: "No roles assigned", evaluationSteps: steps },
    });
  }

  // 3. Check permissions for each role
  const roleIds = roles.map((r) => r.id);
  const placeholders = roleIds.map(() => "?").join(",");
  const t2 = performance.now();
  const perms = db.prepare(
    `SELECT p.name, p.resource, p.action FROM permissions p
     JOIN role_permissions rp ON p.id = rp.permission_id
     WHERE rp.role_id IN (${placeholders}) AND p.resource = ? AND p.action = ?`
  ).all(...roleIds, resource, action) as PermissionRow[];
  trace.addDbQuery({
    sql: `SELECT p.name, p.resource, p.action FROM permissions p JOIN role_permissions rp ON ... WHERE rp.role_id IN (${placeholders}) AND p.resource = ? AND p.action = ?`,
    params: [...roleIds, resource, action],
    rows: perms,
    ms: performance.now() - t2,
  });

  const allowed = perms.length > 0;
  steps.push({
    rule: "Check permission",
    result: allowed ? "ALLOW" : "DENY",
    detail: allowed
      ? `Permission "${resource}:${action}" found via role(s)`
      : `No permission "${resource}:${action}" for any assigned role`,
  });

  return c.json({
    success: true,
    data: { allowed, reason: allowed ? "Permission granted" : "Permission denied", evaluationSteps: steps },
  });
});

// ABAC check (attribute-based — simulated)
rbacRoutes.post("/abac/check", async (c) => {
  const parsed = await parseBody(c, accessCheckSchema);
  if ("error" in parsed) return parsed.error;
  const { subject, resource, action, context = {} } = parsed.data;
  const ctx = context as Record<string, string | number | boolean | undefined>;
  const trace = c.get("trace");
  const steps: { rule: string; result: string; detail: string }[] = [];

  // Simulated ABAC policies
  const policies = [
    {
      name: "time-restriction",
      check: () => {
        const hour = typeof ctx.hour === "number" ? ctx.hour : new Date().getHours();
        return hour >= 9 && hour < 18;
      },
      description: "Access only during business hours (9:00-18:00)",
    },
    {
      name: "department-match",
      check: () => !ctx.department || ctx.department === ctx.resourceDepartment,
      description: "Subject department must match resource department",
    },
    {
      name: "action-allowed",
      check: () => {
        if (context.role === "admin") return true;
        if (action === "read") return true;
        if (action === "write" && context.role === "editor") return true;
        return false;
      },
      description: "Action authorization based on role+action combination",
    },
  ];

  let allowed = true;
  for (const policy of policies) {
    const result = policy.check();
    steps.push({
      rule: policy.name,
      result: result ? "PASS" : "FAIL",
      detail: policy.description,
    });
    trace.addSessionOp({
      action: "ABAC_POLICY_EVAL",
      data: { policy: policy.name, result, context },
    });
    if (!result) allowed = false;
  }

  return c.json({
    success: true,
    data: {
      allowed,
      reason: allowed ? "All policies passed" : "One or more policies denied access",
      evaluationSteps: steps,
    },
  });
});

// ACL check
rbacRoutes.post("/acl/check", async (c) => {
  const parsed = await parseBody(c, accessCheckSchema);
  if ("error" in parsed) return parsed.error;
  const { subject, resource, action } = parsed.data;
  const steps: { rule: string; result: string; detail: string }[] = [];

  // Simulated ACL
  const acl: Record<string, Record<string, string[]>> = {
    "file:report.pdf": { admin: ["read", "write", "delete"], editor: ["read", "write"], viewer: ["read"] },
    "file:config.yml": { admin: ["read", "write", "delete"] },
    "api:/users": { admin: ["read", "write", "delete"], editor: ["read"], viewer: ["read"] },
  };

  const resourceAcl = acl[resource];
  steps.push({
    rule: "Lookup ACL entry",
    result: resourceAcl ? "FOUND" : "NOT_FOUND",
    detail: resourceAcl ? `ACL entries: ${JSON.stringify(resourceAcl)}` : `No ACL for "${resource}"`,
  });

  if (!resourceAcl) {
    return c.json({
      success: true,
      data: { allowed: false, reason: "No ACL entry for resource", evaluationSteps: steps },
    });
  }

  const subjectPerms = resourceAcl[subject] || [];
  steps.push({
    rule: "Check subject permissions",
    result: subjectPerms.length > 0 ? "FOUND" : "NOT_FOUND",
    detail: `Subject "${subject}" permissions: [${subjectPerms.join(", ")}]`,
  });

  const allowed = subjectPerms.includes(action);
  steps.push({
    rule: `Action "${action}" permitted?`,
    result: allowed ? "ALLOW" : "DENY",
    detail: allowed ? `"${action}" is in [${subjectPerms.join(", ")}]` : `"${action}" not in [${subjectPerms.join(", ")}]`,
  });

  return c.json({
    success: true,
    data: { allowed, reason: allowed ? "ACL permits access" : "ACL denies access", evaluationSteps: steps },
  });
});

// Assign role to user
rbacRoutes.post("/assign", async (c) => {
  const parsed = await parseBody(c, roleAssignSchema);
  if ("error" in parsed) return parsed.error;
  const { username, roleName } = parsed.data;
  const trace = c.get("trace");
  const db = getDb();

  const user = db.prepare("SELECT id FROM users WHERE username = ?").get(username) as Pick<UserRow, "id"> | undefined;
  const role = db.prepare("SELECT id FROM roles WHERE name = ?").get(roleName) as Pick<RoleRow, "id"> | undefined;

  if (!user || !role) {
    return c.json({ success: false, error: "User or role not found" }, 404);
  }

  db.prepare("INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)").run(user.id, role.id);
  trace.addDbQuery({
    sql: "INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)",
    params: [user.id, role.id],
    ms: 0,
  });

  return c.json({ success: true, data: { message: `Role "${roleName}" assigned to "${username}"` } });
});

// Get roles
rbacRoutes.get("/roles", (c) => {
  const db = getDb();
  const roles = db.prepare(
    `SELECT r.*, GROUP_CONCAT(p.name) as permissions
     FROM roles r
     LEFT JOIN role_permissions rp ON r.id = rp.role_id
     LEFT JOIN permissions p ON rp.permission_id = p.id
     GROUP BY r.id`
  ).all();
  return c.json({ success: true, data: { roles } });
});
