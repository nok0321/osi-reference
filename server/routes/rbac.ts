import { Hono } from "hono";
import { getDb } from "../db/schema.js";
import { parseBody, accessCheckSchema, roleAssignSchema, rbacAttackIdorSchema, rbacAttackHorizontalEscalationSchema, rbacAttackVerticalEscalationSchema, rbacAttackAbacTamperSchema } from "../validation.js";
import { runAttackScenario, sanitizeForDisplay } from "../utils/attack-runner.js";
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

// ─────────────────────────────────────────────────────────────────────────────
// 攻撃デモルート (Phase 2)
// 【教育目的専用】— 実 DB への書き込みは行いません (固定シードデータのみ使用)
// ─────────────────────────────────────────────────────────────────────────────

// 固定シードユーザー (全攻撃シナリオ共通)
// ROB-RBAC-3: 攻撃シナリオ実行中の意図しない変更を型レベルで排除するため Readonly 化
// ROB-RBAC-2: role は server/db/schema.ts の seedDb() と整合させる (charlie=viewer)
const SEED_USERS = {
  1: { id: 1, username: "seed_alice",       email: "alice@example.com",   role: "viewer", ownerId: 1 },
  2: { id: 2, username: "seed_bob",         email: "bob@example.com",     role: "editor", ownerId: 2 },
  3: { id: 3, username: "attacker_charlie", email: "charlie@example.com", role: "viewer", ownerId: 3 },
  4: { id: 4, username: "seed_admin",       email: "admin@example.com",   role: "admin",  ownerId: 4 },
} as const satisfies Readonly<Record<number, Readonly<{ id: number; username: string; email: string; role: string; ownerId: number }>>>;

// ── Scenario A: IDOR (Insecure Direct Object Reference) ──
type IdorExtra = {
  requestedVictimId: number;
  attackerId: number;
  vulnerableLeakedFields: string[];
  defendedRowsReturned: number;
};

rbacRoutes.post("/attack/idor", (c) =>
  runAttackScenario<typeof rbacAttackIdorSchema, IdorExtra>(c, {
    schema: rbacAttackIdorSchema,
    scenarioId: "rbac-idor",
    tabId: "rbac",
    async handler({ body, trace, recordStep }) {
      const { victimId, attackerId } = body;

      const victim = SEED_USERS[victimId as keyof typeof SEED_USERS];
      const attacker = SEED_USERS[attackerId as keyof typeof SEED_USERS];

      // Step 1 (probe): 攻撃者が自分の ID で正常リクエストを発行してエンドポイントを確認
      recordStep({
        id: "rbac-idor-s1",
        kind: "probe",
        label: "Attacker requests their own profile to confirm the endpoint exists",
        labelJa: "攻撃者が自分のプロファイルを正常取得してエンドポイントを確認",
        status: "success",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/rbac/attack/idor",
            body: { victimId: attackerId },
          },
          response: {
            status: 200,
            body: { id: attacker?.id, username: attacker?.username },
          },
        },
        detail: `Attacker (id=${attackerId}) accesses their own resource as a baseline.`,
        detailJa: `攻撃者 (id=${attackerId}) が自分のリソースにアクセスしてベースラインを確認します。`,
      });

      // Step 2 (tamper): victimId を別ユーザーに書き換え
      recordStep({
        id: "rbac-idor-s2",
        kind: "tamper",
        label: `Tamper victimId: ${attackerId} → ${victimId}`,
        labelJa: `victimId を改竄: ${attackerId} → ${victimId}`,
        status: "success",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/rbac/attack/idor",
            body: { victimId },
          },
          tamperedFields: ["victimId"],
        },
        detail: "Attacker changes the victimId parameter to target another user's resource.",
        detailJa: "攻撃者は victimId パラメータを変更して別ユーザーのリソースを狙います。",
      });

      // Step 3 (forge): 改竄 victimId を含むリクエストボディを構築
      recordStep({
        id: "rbac-idor-s3",
        kind: "forge",
        label: "Construct request body with forged victimId",
        labelJa: "改竄 victimId を含むリクエストボディを構築",
        status: "success",
        payload: {
          type: "generic",
          data: {
            originalVictimId: attackerId,
            forgedVictimId: victimId,
            requestPath: "/api/rbac/attack/idor",
          },
        },
        detail: "Request body is constructed with the forged victimId targeting the victim's resource.",
        detailJa: "改竄された victimId を含むリクエストボディを構築します。",
      });

      const t0 = performance.now();
      trace.addDbQuery({
        sql: "SELECT id, username, email, role FROM users WHERE id = ?  -- ※ owner_id チェックなし (脆弱)",
        params: [victimId],
        rows: victim ? [victim] : [],
        ms: performance.now() - t0,
      });

      // Step 4 (exploit): 脆弱版 — owner_id チェックなしで他ユーザーのデータを返却
      const vulnerableLeakedFields = victim ? Object.keys(victim) : [];
      recordStep({
        id: "rbac-idor-s4",
        kind: "exploit",
        label: victim ? "Vulnerable: returning resource without ownership check" : "Vulnerable path: victim id not found",
        labelJa: victim ? "脆弱版: 所有者チェックなしでリソース返却" : "脆弱版: victimId が見つかりません",
        status: victim ? "success" : "failed",
        payload: {
          type: "generic",
          data: {
            vulnerableFound: !!victim,
            vulnerableUsername: victim?.username ?? null,
            leakedFields: vulnerableLeakedFields,
          },
        },
        detail: victim
          ? `ownerId=${victim.ownerId}, attackerId=${attackerId} — mismatch was NOT detected. Vulnerable implementation leaked: ${vulnerableLeakedFields.join(", ")}`
          : `victimId=${victimId} not found in seed users — exploit path could not run`,
        detailJa: victim
          ? `ownerId=${victim.ownerId}, attackerId=${attackerId} — 不一致が検出されていない。脆弱実装が漏洩したフィールド: ${vulnerableLeakedFields.join(", ")}`
          : `victimId=${victimId} はシードユーザーに存在しません — 攻撃パスを実行できませんでした`,
      });

      // Step 5 (verify): 堅牢版 — owner_id チェックで拒否
      const ownershipMatches = victim?.ownerId === attackerId;
      recordStep({
        id: "rbac-idor-s5",
        kind: "verify",
        label: ownershipMatches ? "Defended: ownership matches — would allow" : "Defended: ownership check rejects request",
        labelJa: ownershipMatches ? "堅牢版: 所有者一致 — 許可されます (攻撃者自身)" : "堅牢版: 所有者チェックでリクエストを拒否",
        status: ownershipMatches ? "success" : "blocked",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/rbac/attack/idor",
          },
          response: {
            status: ownershipMatches ? 200 : 403,
            body: {
              error: ownershipMatches ? undefined : "Forbidden: you can only access your own resource",
              blockedBy: ownershipMatches ? undefined : "rbac_owner_id_check_enforced",
            },
          },
        },
        detail: ownershipMatches
          ? `Server-side WHERE owner_id = ${attackerId} matches — but this happens only when attacker requests own data.`
          : `Server-side WHERE owner_id = ${attackerId} eliminates row (ownerId=${victim?.ownerId ?? "n/a"}). Returns 0 rows → 403 Forbidden.`,
        detailJa: ownershipMatches
          ? `サーバー側の WHERE owner_id = ${attackerId} が一致しますが、これは攻撃者自身のデータをリクエストした場合のみです。`
          : `サーバー側の WHERE owner_id = ${attackerId} で行が除外され (ownerId=${victim?.ownerId ?? "n/a"})、0 行返却 → 403 Forbidden。`,
      });

      const summaryJa = victim
        ? "この実装は脆弱です: 所有者チェックが存在しないため、サーバーはユーザー操作可能な victimId だけを根拠に別ユーザーのデータを返しました。堅牢版は WHERE owner_id 句で拒否します。"
        : "このシナリオでは victimId が存在しないため exploit パスは空振りしましたが、所有者チェックが無いという脆弱性自体は変わりません。";
      const summary = victim
        ? "This implementation is vulnerable: no ownership check was performed, so the server returned another user's data based solely on the user-controlled 'victimId'. The defended path rejects via WHERE owner_id."
        : "In this scenario the victimId did not exist so the exploit path was a no-op, but the underlying vulnerability (missing ownership check) is unchanged.";

      return {
        blockedBy: "rbac_owner_id_check_enforced",
        summary,
        summaryJa,
        extra: {
          requestedVictimId: victimId,
          attackerId,
          vulnerableLeakedFields,
          defendedRowsReturned: 0,
        } satisfies IdorExtra,
        payload: {
          params: { victimId, attackerId },
          result: {
            vulnerableFound: !!victim,
            vulnerableUsername: victim?.username ?? null,
            ownershipMatches,
          },
        },
      };
    },
  })
);

// ── Scenario B: 水平権限昇格 ──
type HorizontalEscalationExtra = {
  attackerUserId: number;
  victimUserId: number;
  vulnerableArticleId: number;
  vulnerableTitlePreview: string | null;
  defendedRowsReturned: number;
  rbacRoleHasPermission: boolean;
};

// ROB-RBAC-3: 攻撃シナリオ実行中の意図しない変更を型レベルで排除するため Readonly 化
const SEED_ALICE_ARTICLE = {
  articleId: 42,
  title: "seed_alice の非公開メモ",
  ownerId: 1,
  content: "これは seed_alice のみが閲覧できるはずの非公開コンテンツです。",
} as const;

const SEED_ROLE_PERMISSIONS = {
  admin: ["articles:read", "articles:write", "articles:delete", "users:read", "users:write", "users:delete", "settings:read", "settings:write", "settings:delete"],
  editor: ["articles:read", "articles:write", "users:read"],
  viewer: ["articles:read", "users:read", "settings:read"],
} as const satisfies Readonly<Record<string, readonly string[]>>;

rbacRoutes.post("/attack/horizontal-escalation", (c) =>
  runAttackScenario<typeof rbacAttackHorizontalEscalationSchema, HorizontalEscalationExtra>(c, {
    schema: rbacAttackHorizontalEscalationSchema,
    scenarioId: "rbac-horizontal-privilege-escalation",
    tabId: "rbac",
    async handler({ body, trace, recordStep }) {
      const { attackerRole, attackerUserId, victimUserId, action } = body;
      const attackerUser = SEED_USERS[attackerUserId as keyof typeof SEED_USERS];
      const victimUser = SEED_USERS[victimUserId as keyof typeof SEED_USERS];
      const permissionKey = `articles:${action}`;
      const rolePerms: readonly string[] = SEED_ROLE_PERMISSIONS[attackerRole] ?? [];
      const rbacRoleHasPermission = rolePerms.includes(permissionKey);

      // Step 1 (probe): 攻撃者ロール確認
      recordStep({
        id: "rbac-horiz-s1",
        kind: "probe",
        label: `Probe: attacker role '${attackerRole}' — check if '${permissionKey}' permission exists`,
        labelJa: `探索: 攻撃者ロール '${attackerRole}' が '${permissionKey}' 権限を持つか確認`,
        status: "success",
        payload: {
          type: "generic",
          data: {
            attackerRole,
            permissionKey,
            rbacRoleHasPermission,
            permissions: SEED_ROLE_PERMISSIONS[attackerRole] ?? [],
          },
        },
        detail: `Role '${attackerRole}' has permission '${permissionKey}': ${rbacRoleHasPermission}. This is a valid RBAC check at the resource-type level.`,
        detailJa: `ロール '${attackerRole}' は '${permissionKey}' 権限を持ちます: ${rbacRoleHasPermission}。これはリソースタイプレベルの正当な RBAC チェックです。`,
      });

      // Step 2 (tamper): 自分の owner_id をリクエストに含めず、被害者の resource id だけを送信
      recordStep({
        id: "rbac-horiz-s2",
        kind: "tamper",
        label: `Tamper: send victim's article ID (${SEED_ALICE_ARTICLE.articleId}) without owner restriction`,
        labelJa: `改竄: 被害者の記事 ID (${SEED_ALICE_ARTICLE.articleId}) を所有者制限なしで送信`,
        status: "success",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/rbac/attack/horizontal-escalation",
            body: { attackerUserId, victimUserId, action },
            headers: { Authorization: `Bearer <${attackerUser?.username ?? "attacker"}_token>` },
          },
          tamperedFields: ["victimUserId"],
        },
        detail: `Attacker (userId=${attackerUserId}) sends victim's articleId=${SEED_ALICE_ARTICLE.articleId} without including their own owner_id constraint.`,
        detailJa: `攻撃者 (userId=${attackerUserId}) は被害者の articleId=${SEED_ALICE_ARTICLE.articleId} を自身の owner_id 制約なしで送信します。`,
      });

      // Step 3 (forge): 改竄リクエストボディ構築
      recordStep({
        id: "rbac-horiz-s3",
        kind: "forge",
        label: "Forge: construct request without owner_id constraint",
        labelJa: "偽造: owner_id 制約なしのリクエストを構築",
        status: "success",
        payload: {
          type: "generic",
          data: {
            forgedRequest: {
              articleId: SEED_ALICE_ARTICLE.articleId,
              attackerUserId,
              note: "owner_id フィールドを送信しない — サーバー側でも owner_id チェックがなければバイパス成立",
            },
          },
        },
        detail: "The forged request omits owner_id so the server query has no WHERE owner_id clause.",
        detailJa: "偽造リクエストは owner_id を含まないため、サーバークエリに WHERE owner_id 句が存在しません。",
      });

      // DB クエリ記録 (脆弱版と堅牢版の SQL を教育的に示す)
      trace.addDbQuery({
        sql: "SELECT * FROM articles WHERE id = ?  -- ※ owner_id チェックなし (脆弱)",
        params: [SEED_ALICE_ARTICLE.articleId],
        rows: rbacRoleHasPermission ? [SEED_ALICE_ARTICLE] : [],
        ms: 0,
      });
      trace.addDbQuery({
        sql: "SELECT * FROM articles WHERE id = ? AND owner_id = ?  -- owner_id チェックあり (堅牢)",
        params: [SEED_ALICE_ARTICLE.articleId, attackerUserId],
        rows: [],
        ms: 0,
      });

      // Step 4 (exploit): 脆弱版 — owner_id チェックなしで記事返却
      const vulnerableTitlePreview = rbacRoleHasPermission
        ? sanitizeForDisplay(SEED_ALICE_ARTICLE.title, 64)
        : null;
      recordStep({
        id: "rbac-horiz-s4",
        kind: "exploit",
        label: rbacRoleHasPermission
          ? "Vulnerable: article returned without owner_id check (horizontal escalation succeeded)"
          : "Vulnerable path: RBAC denied at role level — exploit could not proceed",
        labelJa: rbacRoleHasPermission
          ? "脆弱版: owner_id チェックなしで記事返却 (水平権限昇格成立)"
          : "脆弱版: ロールレベルで RBAC 拒否 — 攻撃パス実行不可",
        status: rbacRoleHasPermission ? "success" : "failed",
        payload: {
          type: "generic",
          data: {
            rbacRoleHasPermission,
            vulnerableArticleId: SEED_ALICE_ARTICLE.articleId,
            vulnerableTitlePreview,
            articleOwnerId: SEED_ALICE_ARTICLE.ownerId,
            attackerUserId,
          },
        },
        detail: rbacRoleHasPermission
          ? `Role '${attackerRole}' has '${permissionKey}' — server returned article owned by userId=${SEED_ALICE_ARTICLE.ownerId} to attacker userId=${attackerUserId}. Ownership mismatch was NOT detected.`
          : `Role '${attackerRole}' does NOT have '${permissionKey}' — RBAC blocked at the role level before reaching the owner check.`,
        detailJa: rbacRoleHasPermission
          ? `ロール '${attackerRole}' は '${permissionKey}' を持ちます — サーバーは userId=${SEED_ALICE_ARTICLE.ownerId} が所有する記事を攻撃者 userId=${attackerUserId} に返しました。所有権の不一致が検出されませんでした。`
          : `ロール '${attackerRole}' は '${permissionKey}' を持ちません — owner チェック前にロールレベルで RBAC がブロックしました。`,
      });

      // Step 5 (verify): 堅牢版 — owner_id 不一致で 403
      const ownershipMatches = SEED_ALICE_ARTICLE.ownerId === attackerUserId;
      recordStep({
        id: "rbac-horiz-s5",
        kind: "verify",
        label: ownershipMatches
          ? "Defended: ownership matches — would allow"
          : "Defended: owner_id mismatch — 403 Forbidden",
        labelJa: ownershipMatches
          ? "堅牢版: 所有者一致 — 許可されます"
          : "堅牢版: owner_id 不一致 — 403 Forbidden",
        status: ownershipMatches ? "success" : "blocked",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/rbac/attack/horizontal-escalation",
          },
          response: {
            status: ownershipMatches ? 200 : 403,
            body: {
              error: ownershipMatches ? undefined : "Forbidden: article does not belong to you",
              blockedBy: ownershipMatches ? undefined : "rbac_resource_owner_check_enforced",
            },
          },
        },
        detail: ownershipMatches
          ? `article.ownerId=${SEED_ALICE_ARTICLE.ownerId} === attackerUserId=${attackerUserId} — allowed.`
          : `article.ownerId=${SEED_ALICE_ARTICLE.ownerId} !== attackerUserId=${attackerUserId} — WHERE article.id = ? AND owner_id = ? returns 0 rows → 403.`,
        detailJa: ownershipMatches
          ? `article.ownerId=${SEED_ALICE_ARTICLE.ownerId} === attackerUserId=${attackerUserId} — 許可されます。`
          : `article.ownerId=${SEED_ALICE_ARTICLE.ownerId} !== attackerUserId=${attackerUserId} — WHERE article.id = ? AND owner_id = ? で 0 行返却 → 403。`,
      });

      const victimName = victimUser?.username ?? `userId=${victimUserId}`;
      const summaryJa = rbacRoleHasPermission
        ? `この実装は脆弱です: ロールレベルの RBAC は '${permissionKey}' を許可しますが、リソースの owner_id チェックが欠如しているため、攻撃者は ${victimName} の記事にアクセスできました。堅牢版は WHERE owner_id で拒否します。`
        : `このシナリオではロール '${attackerRole}' が '${permissionKey}' を持たないため攻撃パスは空振りしましたが、owner_id チェックが欠如しているという脆弱性は依然として存在します。`;
      const summary = rbacRoleHasPermission
        ? `This implementation is vulnerable: role-level RBAC permits '${permissionKey}' but the missing owner_id check allowed the attacker to access ${victimName}'s article. The defended path rejects via WHERE owner_id.`
        : `In this scenario role '${attackerRole}' does not have '${permissionKey}' so the exploit path was a no-op, but the underlying vulnerability (missing owner_id check) is unchanged.`;

      return {
        blockedBy: "rbac_resource_owner_check_enforced",
        summary,
        summaryJa,
        extra: {
          attackerUserId,
          victimUserId,
          vulnerableArticleId: SEED_ALICE_ARTICLE.articleId,
          vulnerableTitlePreview,
          defendedRowsReturned: 0,
          rbacRoleHasPermission,
        } satisfies HorizontalEscalationExtra,
        payload: {
          params: { attackerRole, attackerUserId, victimUserId, action },
          result: {
            rbacRoleHasPermission,
            vulnerableTitlePreview,
            ownershipMatches,
          },
        },
      };
    },
  })
);

// ── Scenario C: 垂直権限昇格 ──
type VerticalEscalationExtra = {
  attackerRole: string;
  targetUserId: number;
  vulnerableDeleteExecuted: boolean;
  defendedHttpStatus: number;
};

rbacRoutes.post("/attack/vertical-escalation", (c) =>
  runAttackScenario<typeof rbacAttackVerticalEscalationSchema, VerticalEscalationExtra>(c, {
    schema: rbacAttackVerticalEscalationSchema,
    scenarioId: "rbac-vertical-privilege-escalation",
    tabId: "rbac",
    async handler({ body, trace, recordStep }) {
      const { attackerRole, targetUserId } = body;
      const attackerUser = SEED_USERS[3]; // attacker_charlie
      const targetUser = SEED_USERS[targetUserId as keyof typeof SEED_USERS];
      const isAdminRole = attackerRole === "admin";

      // Step 1 (probe): 攻撃者ロール確認 (viewer)
      recordStep({
        id: "rbac-vert-s1",
        kind: "probe",
        label: `Probe: attacker has role '${attackerRole}' — identify admin-only endpoint`,
        labelJa: `探索: 攻撃者のロールは '${attackerRole}' — 管理者専用エンドポイントを特定`,
        status: "success",
        payload: {
          type: "generic",
          data: {
            attackerRole,
            attackerUsername: attackerUser?.username ?? "attacker_charlie",
            adminOnlyEndpoint: "POST /admin/users/delete",
            isAdminRole,
          },
        },
        detail: `Attacker has role '${attackerRole}'. They discover an admin-only endpoint: POST /admin/users/delete.`,
        detailJa: `攻撃者のロールは '${attackerRole}' です。管理者専用エンドポイント POST /admin/users/delete を発見しました。`,
      });

      // Step 2 (tamper): 管理者エンドポイントへ直接リクエスト構築
      recordStep({
        id: "rbac-vert-s2",
        kind: "tamper",
        label: "Tamper: craft direct request to admin-only endpoint bypassing role check",
        labelJa: "改竄: ロールチェックをバイパスして管理者専用エンドポイントに直接リクエストを構築",
        status: "success",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/admin/users/delete",
            headers: { Authorization: `Bearer <${attackerRole}_token>` },
            body: { targetUserId },
          },
          tamperedFields: ["Authorization"],
        },
        detail: `Attacker crafts a DELETE request for userId=${targetUserId} with their '${attackerRole}' token, hoping the server has no middleware role check.`,
        detailJa: `攻撃者は '${attackerRole}' トークンを使用して userId=${targetUserId} の削除リクエストを構築します。サーバーにミドルウェアのロールチェックがないことを期待しています。`,
      });

      // Step 3 (forge): 認証ヘッダ + 削除対象 ID を含むボディ構築
      recordStep({
        id: "rbac-vert-s3",
        kind: "forge",
        label: "Forge: complete request with auth header and target user ID",
        labelJa: "偽造: 認証ヘッダと削除対象ユーザー ID を含む完全なリクエストを構築",
        status: "success",
        payload: {
          type: "generic",
          data: {
            forgedRequest: {
              method: "POST",
              endpoint: "/admin/users/delete",
              headers: { Authorization: `Bearer <${attackerRole}_jwt>` },
              body: { targetUserId },
              note: "ロールチェックなしのサーバーはこのリクエストを受理してしまいます (シミュレーション)",
            },
          },
        },
        detail: "The forged request includes a valid JWT for the low-privilege role, sent directly to the admin endpoint.",
        detailJa: "偽造リクエストには低権限ロールの有効な JWT を含み、管理者エンドポイントに直接送信します。",
      });

      // Step 4 (exploit): 脆弱版 — ロールチェックなしで削除実行 (シミュレーション)
      trace.addSessionOp({
        action: "RBAC_ADMIN_OPERATION_SIMULATED",
        data: {
          operation: "DELETE_USER",
          targetUserId,
          targetUsername: targetUser?.username ?? `userId=${targetUserId}`,
          executedByRole: attackerRole,
          note: "シミュレーション — 実 DB への書き込みは行いません",
        },
      });

      recordStep({
        id: "rbac-vert-s4",
        kind: "exploit",
        label: isAdminRole
          ? "Attacker already has admin role — no escalation needed"
          : "Vulnerable: admin operation executed without role middleware (simulated)",
        labelJa: isAdminRole
          ? "攻撃者はすでに admin ロール — 昇格不要"
          : "脆弱版: ロールミドルウェアなしで管理者操作実行 (シミュレーション)",
        status: isAdminRole ? "failed" : "success",
        payload: {
          type: "generic",
          data: {
            operation: "DELETE_USER (simulated)",
            targetUserId,
            targetUsername: targetUser?.username ?? `userId=${targetUserId}`,
            executedByRole: attackerRole,
            vulnerableDeleteExecuted: !isAdminRole,
          },
        },
        detail: isAdminRole
          ? `Attacker already has 'admin' role — vertical escalation scenario requires a lower-privilege role.`
          : `No requireRole('admin') middleware exists on the endpoint. '${attackerRole}' user successfully simulated DELETE on userId=${targetUserId}.`,
        detailJa: isAdminRole
          ? `攻撃者はすでに 'admin' ロールを持っています — 垂直権限昇格には低権限ロールが必要です。`
          : `エンドポイントに requireRole('admin') ミドルウェアが存在しません。'${attackerRole}' ユーザーが userId=${targetUserId} の DELETE をシミュレート実行しました。`,
      });

      // Step 5 (verify): 堅牢版 — requireRole("admin") ミドルウェアが viewer を 403 拒否
      recordStep({
        id: "rbac-vert-s5",
        kind: "verify",
        label: isAdminRole
          ? "Defended: admin role would be allowed by middleware"
          : "Defended: requireRole('admin') middleware rejects non-admin — 403 Forbidden",
        labelJa: isAdminRole
          ? "堅牢版: admin ロールはミドルウェアで許可されます"
          : "堅牢版: requireRole('admin') ミドルウェアが非管理者を 403 拒否",
        status: isAdminRole ? "success" : "blocked",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/admin/users/delete",
          },
          response: {
            status: isAdminRole ? 200 : 403,
            body: {
              error: isAdminRole ? undefined : `Forbidden: role '${attackerRole}' is not authorized for this operation`,
              blockedBy: isAdminRole ? undefined : "rbac_role_check_middleware_enforced",
            },
          },
        },
        detail: isAdminRole
          ? `requireRole('admin') middleware: role 'admin' === 'admin' → allowed.`
          : `requireRole('admin') middleware: role '${attackerRole}' !== 'admin' → 403 Forbidden. Operation rejected before execution.`,
        detailJa: isAdminRole
          ? `requireRole('admin') ミドルウェア: ロール 'admin' === 'admin' → 許可。`
          : `requireRole('admin') ミドルウェア: ロール '${attackerRole}' !== 'admin' → 403 Forbidden。実行前に操作を拒否しました。`,
      });

      const summaryJa = isAdminRole
        ? `このシナリオでは attackerRole が 'admin' のため垂直権限昇格が発生しません。'viewer' または 'editor' でテストしてください。`
        : `この実装は脆弱です: requireRole('admin') ミドルウェアが存在しないため、'${attackerRole}' ロールのユーザーが管理者操作を実行できました。堅牢版はミドルウェアで 403 を返します。`;
      const summary = isAdminRole
        ? `In this scenario attackerRole is 'admin' so no vertical escalation occurs. Use 'viewer' or 'editor' to test this scenario.`
        : `This implementation is vulnerable: without requireRole('admin') middleware, a '${attackerRole}' user successfully executed an admin operation. The defended path returns 403 via middleware.`;

      return {
        blockedBy: "rbac_role_check_middleware_enforced",
        summary,
        summaryJa,
        extra: {
          attackerRole,
          targetUserId,
          vulnerableDeleteExecuted: !isAdminRole,
          defendedHttpStatus: 403,
        } satisfies VerticalEscalationExtra,
        payload: {
          params: { attackerRole, targetUserId },
          result: {
            vulnerableDeleteExecuted: !isAdminRole,
            targetUsername: targetUser?.username ?? null,
            isAdminRole,
          },
        },
      };
    },
  })
);

// ── Scenario D: ABAC 属性改竄 ──
type AbacTamperExtra = {
  clientProvidedDepartment: string;
  serverSideDepartment: string;
  vulnerableResult: "ALLOW" | "DENY";
  defendedResult: "ALLOW" | "DENY";
  isTampered: boolean;
};

// サーバー側の正規部署マッピング (DB 値相当)
// ROB-RBAC-3: 攻撃シナリオ実行中の意図しない変更を型レベルで排除するため Readonly 化
const SEED_USER_DEPARTMENTS = {
  seed_alice: "Engineering",
  seed_bob: "Marketing",
  attacker_charlie: "Engineering",
  seed_admin: "IT",
} as const satisfies Readonly<Record<string, string>>;

rbacRoutes.post("/attack/abac-tamper", (c) =>
  runAttackScenario<typeof rbacAttackAbacTamperSchema, AbacTamperExtra>(c, {
    schema: rbacAttackAbacTamperSchema,
    scenarioId: "rbac-abac-attribute-tampering",
    tabId: "rbac",
    async handler({ body, trace, recordStep }) {
      const { subject, action } = body;
      const clientDepartment = sanitizeForDisplay(body.clientDepartment, 64);
      const resourceDepartment = sanitizeForDisplay(body.resourceDepartment, 64);

      // サーバー側で正規部署を取得 (DB 値相当)
      const serverSideDepartment = SEED_USER_DEPARTMENTS[subject] ?? "Engineering";
      const isTampered = clientDepartment !== serverSideDepartment;

      // Step 1 (probe): 正常リクエスト — 改竄なしで拒否されることを示す
      const unalteredResult = serverSideDepartment === resourceDepartment ? "ALLOW" : "DENY";
      recordStep({
        id: "rbac-abac-s1",
        kind: "probe",
        label: `Probe: normal request — subject '${subject}' department is '${serverSideDepartment}', resource department is '${resourceDepartment}'`,
        labelJa: `探索: 正常リクエスト — '${subject}' の部署は '${serverSideDepartment}'、リソースの部署は '${resourceDepartment}'`,
        status: "success",
        payload: {
          type: "generic",
          data: {
            subject,
            serverSideDepartment,
            resourceDepartment,
            normalResult: unalteredResult,
          },
        },
        detail: `Server-side department='${serverSideDepartment}', resourceDepartment='${resourceDepartment}'. Normal policy result: ${unalteredResult}.`,
        detailJa: `サーバー側の部署='${serverSideDepartment}'、リソースの部署='${resourceDepartment}'。正常ポリシー評価結果: ${unalteredResult}。`,
      });

      // Step 2 (tamper): department を改竄 (Engineering → Finance など)
      recordStep({
        id: "rbac-abac-s2",
        kind: "tamper",
        label: isTampered
          ? `Tamper: department '${serverSideDepartment}' → '${clientDepartment}' to match resourceDepartment='${resourceDepartment}'`
          : `No tamper: clientDepartment '${clientDepartment}' matches server-side value`,
        labelJa: isTampered
          ? `改竄: 部署 '${serverSideDepartment}' → '${clientDepartment}' でリソース部署 '${resourceDepartment}' に合わせる`
          : `改竄なし: clientDepartment '${clientDepartment}' がサーバー側の値と一致`,
        status: "success",
        payload: {
          type: "generic",
          data: {
            originalDepartment: serverSideDepartment,
            tamperedDepartment: clientDepartment,
            resourceDepartment,
            isTampered,
            tamperedFields: isTampered ? ["clientDepartment"] : [],
          },
        },
        detail: isTampered
          ? `Client changes 'department' in request body from '${serverSideDepartment}' to '${clientDepartment}' to match the target resource's department.`
          : `No tampering detected — clientDepartment already equals server-side value '${serverSideDepartment}'.`,
        detailJa: isTampered
          ? `クライアントはリクエストボディの 'department' を '${serverSideDepartment}' から '${clientDepartment}' に変更し、ターゲットリソースの部署に合わせます。`
          : `改竄なし — clientDepartment はサーバー側の値 '${serverSideDepartment}' と同じです。`,
      });

      // Step 3 (forge): 改竄属性を含むリクエストボディ構築
      recordStep({
        id: "rbac-abac-s3",
        kind: "forge",
        label: "Forge: construct request body with tampered department attribute",
        labelJa: "偽造: 改竄された部署属性を含むリクエストボディを構築",
        status: "success",
        payload: {
          type: "generic",
          data: {
            forgedBody: {
              subject,
              action,
              context: {
                department: clientDepartment,
                resourceDepartment,
              },
            },
            note: "脆弱版 ABAC はこのクライアント送信値で department を評価します",
          },
        },
        detail: "The forged request uses client-supplied 'department' in the ABAC context, bypassing server-side attribute lookup.",
        detailJa: "偽造リクエストは ABAC コンテキストにクライアント提供の 'department' を使用し、サーバー側の属性ルックアップをバイパスします。",
      });

      // Step 4 (exploit): 脆弱版 — クライアント送信値でポリシーバイパス
      const vulnerableResult: "ALLOW" | "DENY" =
        clientDepartment === resourceDepartment ? "ALLOW" : "DENY";

      trace.addSessionOp({
        action: "ABAC_POLICY_EVAL",
        data: {
          mode: "vulnerable",
          subject,
          action,
          clientProvidedDepartment: clientDepartment,
          resourceDepartment,
          result: vulnerableResult,
          note: "脆弱版: クライアント送信値を使用してポリシーを評価しました",
        },
      });

      recordStep({
        id: "rbac-abac-s4",
        kind: "exploit",
        label: `Vulnerable ABAC: using client-provided department='${clientDepartment}' → result: ${vulnerableResult}`,
        labelJa: `脆弱版 ABAC: クライアント提供の department='${clientDepartment}' を使用 → 結果: ${vulnerableResult}`,
        status: vulnerableResult === "ALLOW" ? "success" : "failed",
        payload: {
          type: "generic",
          data: {
            mode: "vulnerable",
            policyEval: {
              department: clientDepartment,
              resourceDepartment,
              condition: `department === resourceDepartment`,
              result: vulnerableResult,
            },
          },
        },
        detail: `Vulnerable ABAC uses client-supplied department='${clientDepartment}'. Policy: '${clientDepartment}' === '${resourceDepartment}' → ${vulnerableResult}.`,
        detailJa: `脆弱版 ABAC はクライアント提供の department='${clientDepartment}' を使用します。ポリシー: '${clientDepartment}' === '${resourceDepartment}' → ${vulnerableResult}。`,
      });

      // Step 5 (verify): 堅牢版 — DB 値で評価して拒否
      const defendedResult: "ALLOW" | "DENY" =
        serverSideDepartment === resourceDepartment ? "ALLOW" : "DENY";

      trace.addSessionOp({
        action: "ABAC_POLICY_EVAL",
        data: {
          mode: "defended",
          subject,
          action,
          serverSideDepartment,
          resourceDepartment,
          result: defendedResult,
          note: "堅牢版: サーバー側 DB 値を使用してポリシーを評価しました",
        },
      });

      recordStep({
        id: "rbac-abac-s5",
        kind: "verify",
        label: `Defended ABAC: using server-side department='${serverSideDepartment}' → result: ${defendedResult}`,
        labelJa: `堅牢版 ABAC: サーバー側 department='${serverSideDepartment}' を使用 → 結果: ${defendedResult}`,
        status: defendedResult === "DENY" ? "blocked" : "success",
        payload: {
          type: "generic",
          data: {
            mode: "defended",
            policyEval: {
              serverSideDepartment,
              resourceDepartment,
              condition: `serverSideDepartment === resourceDepartment`,
              result: defendedResult,
            },
          },
        },
        detail: `Defended ABAC looks up department from server-side DB: '${serverSideDepartment}'. Policy: '${serverSideDepartment}' === '${resourceDepartment}' → ${defendedResult}.`,
        detailJa: `堅牢版 ABAC はサーバー側 DB から部署を取得します: '${serverSideDepartment}'。ポリシー: '${serverSideDepartment}' === '${resourceDepartment}' → ${defendedResult}。`,
      });

      const summaryJa = isTampered
        ? `この実装は脆弱です: クライアント送信の department 値を使って ABAC を評価しているため、攻撃者は department を '${serverSideDepartment}' から '${clientDepartment}' に改竄し、ポリシーを ${vulnerableResult} にバイパスしました。堅牢版はサーバー側 DB 値で評価し ${defendedResult} を返します。`
        : `このシナリオでは clientDepartment がサーバー側の値と同じため改竄が発生しませんでした。異なる部署値でテストすることで ABAC バイパスを体験できます。`;
      const summary = isTampered
        ? `This implementation is vulnerable: ABAC evaluated using client-supplied department, allowing the attacker to tamper '${serverSideDepartment}' → '${clientDepartment}' and bypass the policy (${vulnerableResult}). The defended path uses the server-side DB value and returns ${defendedResult}.`
        : `In this scenario clientDepartment matches the server-side value so no tampering occurred. Use a different department value to observe the ABAC bypass.`;

      return {
        blockedBy: "abac_server_side_attribute_lookup_enforced",
        summary,
        summaryJa,
        extra: {
          clientProvidedDepartment: clientDepartment,
          serverSideDepartment,
          vulnerableResult,
          defendedResult,
          isTampered,
        } satisfies AbacTamperExtra,
        payload: {
          params: { subject, clientDepartment, resourceDepartment, action },
          result: {
            isTampered,
            vulnerableResult,
            defendedResult,
          },
        },
      };
    },
  })
);
