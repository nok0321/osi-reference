/**
 * Phase 2 第五コミット (session-vs-token タブ): 5 ステップ完全形 + 両モード並列実行のテスト。
 *
 * - 各シナリオは 1 リクエストで両モード (脆弱+堅牢) を必ず並列実行する。
 * - レスポンスは 5 ステップ完全形 (probe → tamper → forge → exploit → verify)。
 *   ステップ 4 (exploit) = 脆弱モード結果 (status: "success" または "failed")
 *   ステップ 5 (verify)  = 堅牢モード結果 (status: "blocked")
 * - outcome は常に "succeeded" (両モード示すため、HTTP status は 200 で統一)。
 * - シナリオ固有フィールドは E-1 ジェネリック化で `data.extra` 配下に格納される:
 *   - fixation: extra.attackerKnownSid / attackerKnownSidPreview / victimUsername / sessionRegeneratedInDefense
 *   - xss-cookie-theft: extra.vulnerableCookieReadable / defendedCookieReadable / xssPayloadPreview
 *   - token-replay: extra.accessTokenPreview / immediateReplayValid / delayedReplayValid / delayedReplayError
 */
import { describe, it, expect, beforeEach } from "vitest";
import { createTestApp, post } from "./test-helpers.js";
import type { Hono } from "hono";

let app: Hono;

beforeEach(() => {
  ({ app } = createTestApp());
});

// ── Scenario A: セッション固定攻撃 ────────────────────────────────────────────
describe("POST /api/session/attack/fixation", () => {
  it("returns 5-step result with vulnerable hijack + ID-regeneration block", async () => {
    const res = await post(app, "/api/session/attack/fixation", {});
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.scenarioId).toBe("session-fixation");
    // 5 ステップ完全形
    expect(res.json.data.steps).toHaveLength(5);
    // ステップ 1: probe
    expect(res.json.data.steps[0].kind).toBe("probe");
    // ステップ 4 (exploit, 脆弱モード) は status: "success" (seed_alice が存在する場合)
    const exploitStep = res.json.data.steps[3];
    expect(exploitStep.kind).toBe("exploit");
    expect(exploitStep.status).toBe("success");
    // ステップ 5 (verify, 堅牢モード) は status: "blocked"
    const verifyStep = res.json.data.steps[4];
    expect(verifyStep.kind).toBe("verify");
    expect(verifyStep.status).toBe("blocked");
    // blockedBy は堅牢モードの防御識別子
    expect(res.json.data.blockedBy).toBe("session_id_regenerated_after_login");
    // E-1: extra フィールドにシナリオ固有データ
    expect(res.json.data.extra.victimUsername).toBe("seed_alice");
    expect(res.json.data.extra.sessionRegeneratedInDefense).toBe(true);
    expect(res.json.data.extra.vulnerableHttpStatus).toBe(200);
    expect(res.json.data.extra.defendedHttpStatus).toBe(401);
    expect(typeof res.json.data.extra.attackerKnownSid).toBe("string");
    expect(res.json.data.extra.attackerKnownSidPreview).toContain("...");
    // _trace 検証
    expect(res.json._trace.attackSteps).toBeDefined();
    expect(res.json._trace.attackSteps).toHaveLength(5);
    expect(res.json._trace.isAttackMode).toBe(true);
    expect(res.json.data.logId).toBeGreaterThan(0);
  });

  it("ignores extra body fields (zod strips unknown keys silently)", async () => {
    const res = await post(app, "/api/session/attack/fixation", {
      legacyField: "ignored",
      anotherField: 123,
    });
    expect(res.status).toBe(200);
    expect(res.json.data.steps).toHaveLength(5);
  });

  it("is idempotent — second call also returns 200 (INSERT OR REPLACE)", async () => {
    const res1 = await post(app, "/api/session/attack/fixation", {});
    const res2 = await post(app, "/api/session/attack/fixation", {});
    expect(res1.status).toBe(200);
    expect(res2.status).toBe(200);
    expect(res2.json.data.steps).toHaveLength(5);
  });

  it("sessions table has is_attack_sim=1 row for the fixed SID after execution", async () => {
    await post(app, "/api/session/attack/fixation", {});
    // Verify via the store endpoint (only returns is_attack_sim=0 rows)
    // So we verify indirectly: the exploit step status is "success" meaning the SID was found
    const res = await post(app, "/api/session/attack/fixation", {});
    const exploitStep = res.json.data.steps[3];
    expect(exploitStep.status).toBe("success");
    // The extra field confirms the victim was found
    expect(res.json.data.extra.victimUsername).toBe("seed_alice");
  });
});

// ── Scenario B: XSS Cookie 窃取 ───────────────────────────────────────────────
describe("POST /api/session/attack/xss-cookie-theft", () => {
  it("returns 5-step result with vulnerable read + HttpOnly block", async () => {
    const res = await post(app, "/api/session/attack/xss-cookie-theft", {});
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.scenarioId).toBe("session-xss-cookie-theft");
    // 5 ステップ完全形
    expect(res.json.data.steps).toHaveLength(5);
    expect(res.json.data.steps[0].kind).toBe("probe");
    // ステップ 4 (exploit, 脆弱モード) は status: "success"
    const exploitStep = res.json.data.steps[3];
    expect(exploitStep.kind).toBe("exploit");
    expect(exploitStep.status).toBe("success");
    // ステップ 5 (verify, 堅牢モード) は status: "blocked"
    const verifyStep = res.json.data.steps[4];
    expect(verifyStep.kind).toBe("verify");
    expect(verifyStep.status).toBe("blocked");
    // blockedBy
    expect(res.json.data.blockedBy).toBe("cookie_httponly_attribute_enforced");
    // E-1: extra フィールド
    expect(res.json.data.extra.vulnerableCookieReadable).toBe(true);
    expect(res.json.data.extra.defendedCookieReadable).toBe(false);
    expect(typeof res.json.data.extra.xssPayloadPreview).toBe("string");
    expect(res.json.data.extra.xssPayloadPreview.length).toBeGreaterThan(0);
    expect(res.json.data.extra.victimUsername).toBe("seed_alice");
    expect(res.json.data.extra.vulnerableSidPreview).toContain("...");
    expect(res.json.data.extra.protectedSidPreview).toContain("...");
    // _trace 検証
    expect(res.json._trace.attackSteps).toHaveLength(5);
    expect(res.json._trace.isAttackMode).toBe(true);
    expect(res.json.data.logId).toBeGreaterThan(0);
  });

  it("ignores extra body fields", async () => {
    const res = await post(app, "/api/session/attack/xss-cookie-theft", {
      cookieString: "injected",
      httpOnly: false,
    });
    expect(res.status).toBe(200);
    expect(res.json.data.steps).toHaveLength(5);
  });

  it("does not INSERT any sessions rows (in-memory simulation only)", async () => {
    await post(app, "/api/session/attack/xss-cookie-theft", {});
    // The store endpoint returns only is_attack_sim=0 rows; XSS scenario does no DB insert
    const storeRes = await (await app.request("/api/session/store", { method: "GET" })).json();
    const sessionIds: string[] = (storeRes.data?.sessions ?? []).map((s: { id: string }) => s.id);
    // XSS_VULN_SID_v1 and XSS_PROTECTED_SID_v1 should never appear in the real sessions table
    expect(sessionIds).not.toContain("XSS_VULN_SID_v1");
    expect(sessionIds).not.toContain("XSS_PROTECTED_SID_v1");
  });
});

// ── Scenario C: トークンリプレイ攻撃 ─────────────────────────────────────────
describe("POST /api/token/attack/replay", () => {
  it("default scenarioDelay=960 → blocked in step 5", async () => {
    const res = await post(app, "/api/token/attack/replay", {});
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.scenarioId).toBe("token-replay");
    expect(res.json.data.steps).toHaveLength(5);
    // ステップ 4 (exploit): 即時リプレイは成立
    expect(res.json.data.steps[3].kind).toBe("exploit");
    expect(res.json.data.steps[3].status).toBe("success");
    // ステップ 5 (verify): 有効期限後リプレイは拒否
    expect(res.json.data.steps[4].kind).toBe("verify");
    expect(res.json.data.steps[4].status).toBe("blocked");
    expect(res.json.data.blockedBy).toBe("jwt_expiry_validation_enforced");
    // E-1: extra
    expect(res.json.data.extra.immediateReplayValid).toBe(true);
    expect(res.json.data.extra.delayedReplayValid).toBe(false);
    expect(typeof res.json.data.extra.delayedReplayError).toBe("string");
    expect(res.json.data.extra.delayedReplayError.length).toBeGreaterThan(0);
    expect(res.json.data.extra.victimUsername).toBe("seed_alice");
    expect(res.json.data.extra.expiresInSec).toBe(900);
    expect(res.json.data.extra.scenarioDelaySec).toBe(960); // default
    expect(res.json.data.extra.accessTokenPreview).toContain("...");
    expect(typeof res.json.data.extra.rotationNote).toBe("string");
    expect(typeof res.json.data.extra.rotationNoteJa).toBe("string");
    // _trace
    expect(res.json._trace.attackSteps).toHaveLength(5);
    expect(res.json._trace.isAttackMode).toBe(true);
    expect(res.json.data.logId).toBeGreaterThan(0);
  });

  it("scenarioDelay=0 → verify step still blocked (verify uses max(delay, expiresIn+1))", async () => {
    const res = await post(app, "/api/token/attack/replay", { scenarioDelay: 0 });
    expect(res.status).toBe(200);
    // Even with delay=0, the verify step simulates past-expiry using max(0, 901)=901
    expect(res.json.data.steps[4].kind).toBe("verify");
    expect(res.json.data.steps[4].status).toBe("blocked");
    expect(res.json.data.extra.scenarioDelaySec).toBe(0);
    expect(res.json.data.extra.delayedReplayValid).toBe(false);
  });

  it("scenarioDelay=900 → verify step blocked (900s = exact boundary; max(900,901)=901)", async () => {
    const res = await post(app, "/api/token/attack/replay", { scenarioDelay: 900 });
    expect(res.status).toBe(200);
    expect(res.json.data.steps[4].status).toBe("blocked");
  });

  it("scenarioDelay=86400 (max allowed) → returns 200", async () => {
    const res = await post(app, "/api/token/attack/replay", { scenarioDelay: 86400 });
    expect(res.status).toBe(200);
    expect(res.json.data.steps).toHaveLength(5);
    expect(res.json.data.extra.scenarioDelaySec).toBe(86400);
  });

  it("rejects scenarioDelay > 86400", async () => {
    const res = await post(app, "/api/token/attack/replay", { scenarioDelay: 86401 });
    expect(res.status).toBe(400);
  });

  it("rejects scenarioDelay < 0", async () => {
    const res = await post(app, "/api/token/attack/replay", { scenarioDelay: -1 });
    expect(res.status).toBe(400);
  });

  it("rejects non-integer scenarioDelay", async () => {
    const res = await post(app, "/api/token/attack/replay", { scenarioDelay: 1.5 });
    expect(res.status).toBe(400);
  });

  it("ignores extra body fields", async () => {
    const res = await post(app, "/api/token/attack/replay", { legacyField: "ignored" });
    expect(res.status).toBe(200);
    expect(res.json.data.steps).toHaveLength(5);
  });
});

// ── E-1 / E-2 invariants across all session-token scenarios ───────────────────
describe("E-1 / E-2 invariants across all session-token scenarios", () => {
  it.each([
    ["session", "fixation"],
    ["session", "xss-cookie-theft"],
    ["token", "replay"],
  ] as const)(
    "%s/%s: outcome=succeeded, 5 steps, _trace.attackSteps matches steps; extra defined",
    async (area, suffix) => {
      const res = await post(app, `/api/${area}/attack/${suffix}`, {});
      expect(res.status).toBe(200);
      expect(res.json.data.outcome).toBe("succeeded");
      expect(res.json.data.steps).toHaveLength(5);
      expect(res.json._trace.attackSteps).toHaveLength(5);
      expect(res.json.data.extra).toBeDefined();
    },
  );

  it("all 3 scenarios produce attack_log rows with unique logIds", async () => {
    const routes = [
      ["session", "fixation"],
      ["session", "xss-cookie-theft"],
      ["token", "replay"],
    ] as const;
    const logIds: number[] = [];
    for (const [area, suffix] of routes) {
      const res = await post(app, `/api/${area}/attack/${suffix}`, {});
      expect(res.json.data.logId).toBeGreaterThan(0);
      logIds.push(res.json.data.logId as number);
    }
    expect(new Set(logIds).size).toBe(3);
  });

  it("all 3 scenarios have blockedBy set to a non-empty snake_case string", async () => {
    const routes = [
      ["session", "fixation"],
      ["session", "xss-cookie-theft"],
      ["token", "replay"],
    ] as const;
    for (const [area, suffix] of routes) {
      const res = await post(app, `/api/${area}/attack/${suffix}`, {});
      expect(typeof res.json.data.blockedBy).toBe("string");
      expect(res.json.data.blockedBy).toMatch(/^[a-z][a-z0-9_]+$/);
    }
  });

  it("step 4 is exploit and step 5 is verify across all scenarios", async () => {
    const routes = [
      ["session", "fixation"],
      ["session", "xss-cookie-theft"],
      ["token", "replay"],
    ] as const;
    for (const [area, suffix] of routes) {
      const res = await post(app, `/api/${area}/attack/${suffix}`, {});
      const steps = res.json.data.steps;
      expect(steps[3].kind).toBe("exploit");
      expect(steps[4].kind).toBe("verify");
      expect(steps[4].status).toBe("blocked");
    }
  });

  it("summaryJa starts with 'この実装は' or 'このシナリオでは' across all scenarios", async () => {
    const routes = [
      ["session", "fixation"],
      ["session", "xss-cookie-theft"],
      ["token", "replay"],
    ] as const;
    for (const [area, suffix] of routes) {
      const res = await post(app, `/api/${area}/attack/${suffix}`, {});
      const summaryJa: string = res.json.data.summaryJa ?? "";
      const startsWithExpected =
        summaryJa.startsWith("この実装は") || summaryJa.startsWith("このシナリオでは");
      expect(
        startsWithExpected,
        `summaryJa for ${area}/${suffix} should start with 'この実装は' or 'このシナリオでは', got: "${summaryJa.substring(0, 30)}"`
      ).toBe(true);
    }
  });
});

// ── Production guard ───────────────────────────────────────────────────────────
describe("Production guard for session-token attack routes", () => {
  it.each([
    ["session", "fixation"],
    ["session", "xss-cookie-theft"],
    ["token", "replay"],
  ] as const)("%s/%s returns 403 when NODE_ENV=production", async (area, suffix) => {
    const orig = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    try {
      const res = await post(app, `/api/${area}/attack/${suffix}`, {});
      expect(res.status).toBe(403);
      expect(res.json.success).toBe(false);
      expect(res.json.error).toContain("disabled in production");
    } finally {
      process.env.NODE_ENV = orig;
    }
  });
});
