/**
 * Phase 2 rbac タブ: 5 ステップ完全形 + 両モード並列実行のテスト。
 *
 * - 各シナリオは 1 リクエストで両モード (脆弱+堅牢) を必ず並列実行する。
 * - レスポンスは 5 ステップ完全形 (probe → tamper → forge → exploit → verify)。
 *   ステップ 4 (exploit) = 脆弱モード結果 (status: "success" または "failed")
 *   ステップ 5 (verify)  = 堅牢モード結果 (status: "blocked" または "success")
 * - outcome は常に "succeeded" (両モード示すため、HTTP status は 200 で統一)。
 * - シナリオ固有フィールドは E-1 ジェネリック化で `data.extra` 配下に格納される:
 *   - idor: extra.requestedVictimId / attackerId / vulnerableLeakedFields / defendedRowsReturned
 *   - horizontal-escalation: extra.attackerUserId / victimUserId / vulnerableArticleId / vulnerableTitlePreview / defendedRowsReturned / rbacRoleHasPermission
 *   - vertical-escalation: extra.attackerRole / targetUserId / vulnerableDeleteExecuted / defendedHttpStatus
 *   - abac-tamper: extra.clientProvidedDepartment / serverSideDepartment / vulnerableResult / defendedResult / isTampered
 */
import { describe, it, expect, beforeEach } from "vitest";
import { createTestApp, post } from "./test-helpers.js";
import type { Hono } from "hono";

let app: Hono;

beforeEach(() => {
  ({ app } = createTestApp());
});

// ── Scenario A: IDOR ──────────────────────────────────────────────────────────
describe("POST /api/rbac/attack/idor", () => {
  it("returns 5-step result with vulnerable leak + owner-check reject", async () => {
    const res = await post(app, "/api/rbac/attack/idor", {});
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.scenarioId).toBe("rbac-idor");
    // 5 ステップ完全形
    expect(res.json.data.steps).toHaveLength(5);
    // ステップ 1: probe
    expect(res.json.data.steps[0].kind).toBe("probe");
    // ステップ 4 (exploit, 脆弱モード) は status: "success" (victim が存在する場合)
    const exploitStep = res.json.data.steps[3];
    expect(exploitStep.kind).toBe("exploit");
    // ステップ 5 (verify, 堅牢モード) は status: "blocked" (ownership mismatch)
    const verifyStep = res.json.data.steps[4];
    expect(verifyStep.kind).toBe("verify");
    expect(verifyStep.status).toBe("blocked");
    // blockedBy
    expect(res.json.data.blockedBy).toBe("rbac_owner_id_check_enforced");
    // E-1: extra フィールド
    expect(res.json.data.extra.requestedVictimId).toBe(1); // default victimId
    expect(res.json.data.extra.attackerId).toBe(3); // default attackerId
    expect(Array.isArray(res.json.data.extra.vulnerableLeakedFields)).toBe(true);
    expect(res.json.data.extra.defendedRowsReturned).toBe(0);
    // _trace 検証
    expect(res.json._trace.attackSteps).toBeDefined();
    expect(res.json._trace.isAttackMode).toBe(true);
    expect(res.json.data.logId).toBeGreaterThan(0);
  });

  it("accepts custom victimId and attackerId", async () => {
    const res = await post(app, "/api/rbac/attack/idor", { victimId: 2, attackerId: 3 });
    expect(res.status).toBe(200);
    expect(res.json.data.extra.requestedVictimId).toBe(2);
    expect(res.json.data.extra.attackerId).toBe(3);
    expect(res.json.data.steps).toHaveLength(5);
  });

  it("rejects victimId out of range", async () => {
    const res = await post(app, "/api/rbac/attack/idor", { victimId: 0 });
    expect(res.status).toBe(400);
  });

  it("ignores unknown body fields (zod strips silently)", async () => {
    const res = await post(app, "/api/rbac/attack/idor", { legacyField: "ignored" });
    expect(res.status).toBe(200);
    expect(res.json.data.steps).toHaveLength(5);
  });
});

// ── Scenario B: 水平権限昇格 ─────────────────────────────────────────────────
describe("POST /api/rbac/attack/horizontal-escalation", () => {
  it("returns 5-step result with editor role — owner_id mismatch blocks in defended path", async () => {
    const res = await post(app, "/api/rbac/attack/horizontal-escalation", {});
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.scenarioId).toBe("rbac-horizontal-privilege-escalation");
    expect(res.json.data.steps).toHaveLength(5);
    // ステップ 4 (exploit): editor has articles:read — status should be "success"
    const exploitStep = res.json.data.steps[3];
    expect(exploitStep.kind).toBe("exploit");
    expect(exploitStep.status).toBe("success");
    // ステップ 5 (verify): owner_id mismatch → blocked
    const verifyStep = res.json.data.steps[4];
    expect(verifyStep.kind).toBe("verify");
    expect(verifyStep.status).toBe("blocked");
    expect(res.json.data.blockedBy).toBe("rbac_resource_owner_check_enforced");
    // E-1: extra
    expect(res.json.data.extra.attackerUserId).toBe(2);
    expect(res.json.data.extra.victimUserId).toBe(1);
    expect(res.json.data.extra.vulnerableArticleId).toBe(42);
    expect(res.json.data.extra.rbacRoleHasPermission).toBe(true);
    expect(res.json.data.extra.defendedRowsReturned).toBe(0);
    expect(res.json._trace.attackSteps).toHaveLength(5);
    expect(res.json._trace.isAttackMode).toBe(true);
  });

  it("viewer role without articles:write — exploit step is 'failed'", async () => {
    const res = await post(app, "/api/rbac/attack/horizontal-escalation", {
      attackerRole: "viewer",
      action: "write",
    });
    expect(res.status).toBe(200);
    expect(res.json.data.steps).toHaveLength(5);
    const exploitStep = res.json.data.steps[3];
    expect(exploitStep.kind).toBe("exploit");
    expect(exploitStep.status).toBe("failed");
    expect(res.json.data.extra.rbacRoleHasPermission).toBe(false);
    expect(res.json.data.extra.vulnerableTitlePreview).toBeNull();
  });

  it("rejects invalid attackerRole", async () => {
    const res = await post(app, "/api/rbac/attack/horizontal-escalation", {
      attackerRole: "superuser",
    });
    expect(res.status).toBe(400);
  });
});

// ── Scenario C: 垂直権限昇格 ─────────────────────────────────────────────────
describe("POST /api/rbac/attack/vertical-escalation", () => {
  it("returns 5-step result with viewer role — admin op blocked in defended path", async () => {
    const res = await post(app, "/api/rbac/attack/vertical-escalation", { attackerRole: "viewer" });
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.scenarioId).toBe("rbac-vertical-privilege-escalation");
    expect(res.json.data.steps).toHaveLength(5);
    // ステップ 4 (exploit): viewer — delete simulated → "success"
    const exploitStep = res.json.data.steps[3];
    expect(exploitStep.kind).toBe("exploit");
    expect(exploitStep.status).toBe("success");
    // ステップ 5 (verify): middleware blocks viewer → "blocked"
    const verifyStep = res.json.data.steps[4];
    expect(verifyStep.kind).toBe("verify");
    expect(verifyStep.status).toBe("blocked");
    expect(res.json.data.blockedBy).toBe("rbac_role_check_middleware_enforced");
    // E-1: extra
    expect(res.json.data.extra.attackerRole).toBe("viewer");
    expect(res.json.data.extra.vulnerableDeleteExecuted).toBe(true);
    expect(res.json.data.extra.defendedHttpStatus).toBe(403);
    expect(res.json._trace.attackSteps).toHaveLength(5);
    expect(res.json._trace.isAttackMode).toBe(true);
  });

  it("admin role — exploit step is 'failed' (no escalation needed)", async () => {
    const res = await post(app, "/api/rbac/attack/vertical-escalation", { attackerRole: "admin" });
    expect(res.status).toBe(200);
    expect(res.json.data.steps).toHaveLength(5);
    const exploitStep = res.json.data.steps[3];
    expect(exploitStep.status).toBe("failed");
    expect(res.json.data.extra.vulnerableDeleteExecuted).toBe(false);
  });

  it("uses default attackerRole=viewer when omitted", async () => {
    const res = await post(app, "/api/rbac/attack/vertical-escalation", {});
    expect(res.status).toBe(200);
    expect(res.json.data.extra.attackerRole).toBe("viewer");
    expect(res.json.data.steps).toHaveLength(5);
  });

  it("rejects invalid attackerRole", async () => {
    const res = await post(app, "/api/rbac/attack/vertical-escalation", { attackerRole: "root" });
    expect(res.status).toBe(400);
  });
});

// ── Scenario D: ABAC 属性改竄 ────────────────────────────────────────────────
describe("POST /api/rbac/attack/abac-tamper", () => {
  it("returns 5-step result with tampered department — vulnerable ALLOW, defended DENY", async () => {
    // attacker_charlie は Engineering だが Finance に改竄して Finance リソースにアクセス
    const res = await post(app, "/api/rbac/attack/abac-tamper", {
      subject: "attacker_charlie",
      clientDepartment: "Finance",
      resourceDepartment: "Finance",
      action: "read",
    });
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.scenarioId).toBe("rbac-abac-attribute-tampering");
    expect(res.json.data.steps).toHaveLength(5);
    // ステップ 4 (exploit): client Finance === resource Finance → ALLOW
    const exploitStep = res.json.data.steps[3];
    expect(exploitStep.kind).toBe("exploit");
    expect(exploitStep.status).toBe("success");
    // ステップ 5 (verify): server Engineering !== Finance → DENY → blocked
    const verifyStep = res.json.data.steps[4];
    expect(verifyStep.kind).toBe("verify");
    expect(verifyStep.status).toBe("blocked");
    expect(res.json.data.blockedBy).toBe("abac_server_side_attribute_lookup_enforced");
    // E-1: extra
    expect(res.json.data.extra.clientProvidedDepartment).toBe("Finance");
    expect(res.json.data.extra.serverSideDepartment).toBe("Engineering");
    expect(res.json.data.extra.vulnerableResult).toBe("ALLOW");
    expect(res.json.data.extra.defendedResult).toBe("DENY");
    expect(res.json.data.extra.isTampered).toBe(true);
    expect(res.json._trace.attackSteps).toHaveLength(5);
    expect(res.json._trace.isAttackMode).toBe(true);
  });

  it("no tamper when clientDepartment matches server-side value", async () => {
    // attacker_charlie は Engineering — clientDepartment も Engineering なら改竄なし
    const res = await post(app, "/api/rbac/attack/abac-tamper", {
      subject: "attacker_charlie",
      clientDepartment: "Engineering",
      resourceDepartment: "Engineering",
      action: "read",
    });
    expect(res.status).toBe(200);
    expect(res.json.data.extra.isTampered).toBe(false);
    expect(res.json.data.extra.vulnerableResult).toBe("ALLOW");
    expect(res.json.data.extra.defendedResult).toBe("ALLOW");
    expect(res.json.data.steps).toHaveLength(5);
  });

  it("uses default values when body is empty", async () => {
    const res = await post(app, "/api/rbac/attack/abac-tamper", {});
    expect(res.status).toBe(200);
    expect(res.json.data.steps).toHaveLength(5);
    // default subject=attacker_charlie (Engineering), clientDepartment=Finance → isTampered=true
    expect(res.json.data.extra.isTampered).toBe(true);
  });

  it("rejects invalid subject", async () => {
    const res = await post(app, "/api/rbac/attack/abac-tamper", { subject: "hacker" });
    expect(res.status).toBe(400);
  });
});

// ── E-1 / E-2 不変条件 (全 4 シナリオ) ─────────────────────────────────────
describe("E-1 / E-2 invariants across all RBAC scenarios", () => {
  it.each([
    ["idor", true],
    ["horizontal-escalation", true],
    ["vertical-escalation", true],
    ["abac-tamper", true],
  ] as const)(
    "%s: outcome=succeeded, 5 steps, _trace.attackSteps matches steps; extra %s",
    async (suffix, hasExtra) => {
      const res = await post(app, `/api/rbac/attack/${suffix}`, {});
      expect(res.status).toBe(200);
      expect(res.json.data.outcome).toBe("succeeded");
      expect(res.json.data.steps).toHaveLength(5);
      // _trace.attackSteps は data.steps と長さ一致
      expect(res.json._trace.attackSteps).toHaveLength(5);
      if (hasExtra) {
        expect(res.json.data.extra).toBeDefined();
      } else {
        expect(res.json.data.extra).toBeUndefined();
      }
    },
  );

  it("all 4 scenarios produce attack_log rows with unique logIds", async () => {
    const suffixes = ["idor", "horizontal-escalation", "vertical-escalation", "abac-tamper"];
    const logIds: number[] = [];
    for (const suffix of suffixes) {
      const res = await post(app, `/api/rbac/attack/${suffix}`, {});
      expect(res.json.data.logId).toBeGreaterThan(0);
      logIds.push(res.json.data.logId);
    }
    // 4 件のログ ID は重複しない
    const uniqueIds = new Set(logIds);
    expect(uniqueIds.size).toBe(4);
  });

  it("all 4 scenarios have blockedBy set to a non-empty string", async () => {
    const suffixes = ["idor", "horizontal-escalation", "vertical-escalation", "abac-tamper"];
    for (const suffix of suffixes) {
      const res = await post(app, `/api/rbac/attack/${suffix}`, {});
      expect(typeof res.json.data.blockedBy).toBe("string");
      expect(res.json.data.blockedBy.length).toBeGreaterThan(0);
    }
  });
});

// ── Production guard ─────────────────────────────────────────────────────────
describe("Production guard for RBAC attack routes", () => {
  it("attack route returns 403 when NODE_ENV=production", async () => {
    const orig = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    try {
      const res = await post(app, "/api/rbac/attack/idor", {});
      expect(res.status).toBe(403);
      expect(res.json.success).toBe(false);
      expect(res.json.error).toContain("disabled in production");
    } finally {
      process.env.NODE_ENV = orig;
    }
  });

  it("all 4 attack routes are blocked in production", async () => {
    const orig = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    const suffixes = ["idor", "horizontal-escalation", "vertical-escalation", "abac-tamper"];
    try {
      for (const suffix of suffixes) {
        const res = await post(app, `/api/rbac/attack/${suffix}`, {});
        expect(res.status).toBe(403);
      }
    } finally {
      process.env.NODE_ENV = orig;
    }
  });

  it("non-attack route is unaffected by production guard", async () => {
    const orig = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    try {
      const res = await post(app, "/api/rbac/check", {
        subject: "alice",
        resource: "documents",
        action: "read",
      });
      expect(res.status).toBe(200);
    } finally {
      process.env.NODE_ENV = orig;
    }
  });
});
