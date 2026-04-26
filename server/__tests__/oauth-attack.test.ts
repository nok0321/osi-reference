/**
 * Phase 2 第三コミット (oauth タブ): 5 ステップ完全形 + 両モード並列実行のテスト。
 *
 * - 各シナリオは 1 リクエストで両モード (脆弱+堅牢) を必ず並列実行する。
 * - レスポンスは 5 ステップ完全形 (probe → tamper → forge → exploit → verify)。
 *   ステップ 4 (exploit) = 脆弱モード結果 (status: "success")
 *   ステップ 5 (verify)  = 堅牢モード結果 (status: "blocked")
 * - outcome は常に "succeeded" (両モード示すため、HTTP status は 200 で統一)。
 * - シナリオ固有フィールドは E-1 ジェネリック化で `data.extra` 配下に格納される:
 *   - state-csrf: extra.victimSessionLinkedTo / expectedState / receivedState
 *   - redirect-uri-bypass: extra.attackerUri / prefixMatch / regexBadMatch / exactMatch
 *   - code-via-referer: extra.stolenCode / simulatedReferer / accessTokenPreview / pkceChallengePreview
 */
import { describe, it, expect, beforeEach } from "vitest";
import { createTestApp, post } from "./test-helpers.js";
import type { Hono } from "hono";

let app: Hono;

beforeEach(() => {
  ({ app } = createTestApp());
});

describe("POST /api/oauth/attack/state-csrf", () => {
  it("returns 5-step result with vulnerable accept + state-mismatch reject", async () => {
    const res = await post(app, "/api/oauth/attack/state-csrf", {});
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.scenarioId).toBe("oauth-state-csrf");
    // 5 ステップ完全形
    expect(res.json.data.steps).toHaveLength(5);
    // ステップ 4 (exploit, 脆弱モード) は status: "success"
    const exploitStep = res.json.data.steps[3];
    expect(exploitStep.kind).toBe("exploit");
    expect(exploitStep.status).toBe("success");
    // ステップ 5 (verify, 堅牢モード) は status: "blocked"
    const verifyStep = res.json.data.steps[4];
    expect(verifyStep.kind).toBe("verify");
    expect(verifyStep.status).toBe("blocked");
    // blockedBy は堅牢モードの防御指標
    expect(res.json.data.blockedBy).toBe("oauth_state_mismatch");
    // E-1: extra フィールドにシナリオ固有データ
    expect(res.json.data.extra.victimSessionLinkedTo).toBe("attacker_charlie");
    expect(typeof res.json.data.extra.expectedState).toBe("string");
    expect(typeof res.json.data.extra.receivedState).toBe("string");
    expect(res.json.data.extra.expectedState).not.toBe(res.json.data.extra.receivedState);
    // _trace 検証
    expect(res.json._trace.attackSteps).toBeDefined();
    expect(res.json._trace.isAttackMode).toBe(true);
    expect(res.json.data.logId).toBeGreaterThan(0);
  });

  it("ignores extra body fields (zod strips unknown keys silently)", async () => {
    // 旧契約 (useState/attackerCode) を送っても 200 で 5 ステップ返却 (フィールドは無視)
    const res = await post(app, "/api/oauth/attack/state-csrf", {
      useState: false,
      attackerCode: "LEGACY_CODE",
    });
    expect(res.status).toBe(200);
    expect(res.json.data.steps).toHaveLength(5);
  });
});

describe("POST /api/oauth/attack/redirect-uri-bypass", () => {
  it("returns 5-step result with prefix/regex_bad accept + exact-match reject", async () => {
    const res = await post(app, "/api/oauth/attack/redirect-uri-bypass", {});
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.steps).toHaveLength(5);
    // ステップ 4 (exploit, 脆弱モード) は status: "success"
    const exploitStep = res.json.data.steps[3];
    expect(exploitStep.kind).toBe("exploit");
    expect(exploitStep.status).toBe("success");
    // ステップ 5 (verify, 堅牢モード) は status: "blocked"
    const verifyStep = res.json.data.steps[4];
    expect(verifyStep.kind).toBe("verify");
    expect(verifyStep.status).toBe("blocked");
    expect(res.json.data.blockedBy).toBe("oauth_redirect_uri_exact_match");
    // E-1: extra で 3 検証モードの結果を比較
    expect(res.json.data.extra.attackerUri).toContain("attacker.example");
    expect(res.json.data.extra.prefixMatch).toBe(true);
    expect(res.json.data.extra.regexBadMatch).toBe(true);
    expect(res.json.data.extra.exactMatch).toBe(false);
  });

  it("accepts custom attackerRedirectUri if provided", async () => {
    const customUri = "http://localhost:3000/auth/oauth/callback.malicious.example/x";
    const res = await post(app, "/api/oauth/attack/redirect-uri-bypass", {
      attackerRedirectUri: customUri,
    });
    expect(res.status).toBe(200);
    expect(res.json.data.steps).toHaveLength(5);
    expect(res.json.data.extra.attackerUri).toBe(customUri);
  });

  it("rejects attackerRedirectUri over 512 chars", async () => {
    const oversized = "http://localhost:3000/" + "a".repeat(600);
    const res = await post(app, "/api/oauth/attack/redirect-uri-bypass", {
      attackerRedirectUri: oversized,
    });
    expect(res.status).toBe(400);
  });
});

describe("POST /api/oauth/attack/code-via-referer", () => {
  it("returns 5-step result with no-PKCE exchange + PKCE-blocked reject", async () => {
    const res = await post(app, "/api/oauth/attack/code-via-referer", {});
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.steps).toHaveLength(5);
    // ステップ 4 (exploit, 脆弱: PKCE なしでトークン交換成立) は status: "success"
    const exploitStep = res.json.data.steps[3];
    expect(exploitStep.kind).toBe("exploit");
    expect(exploitStep.status).toBe("success");
    // ステップ 5 (verify, 堅牢: code_verifier 欠如で拒否) は status: "blocked"
    const verifyStep = res.json.data.steps[4];
    expect(verifyStep.kind).toBe("verify");
    expect(verifyStep.status).toBe("blocked");
    expect(res.json.data.blockedBy).toBe("pkce_code_verifier_missing");
    // E-1: extra にシナリオ固有データ
    expect(typeof res.json.data.extra.stolenCode).toBe("string");
    expect(res.json.data.extra.simulatedReferer).toContain("code=");
    // 脆弱パスで access_token 発行された (preview のみ)
    expect(res.json.data.extra.accessTokenPreview).not.toBeNull();
    expect(typeof res.json.data.extra.accessTokenPreview).toBe("string");
    // PKCE challenge は両モード共通で生成済み (堅牢パスで参照)
    expect(typeof res.json.data.extra.pkceChallengePreview).toBe("string");
  });

  it("ignores extra body fields (zod strips unknown keys silently)", async () => {
    const res = await post(app, "/api/oauth/attack/code-via-referer", {
      pkceEnabled: false,
      stolenCode: "LEGACY_CODE",
    });
    expect(res.status).toBe(200);
    expect(res.json.data.steps).toHaveLength(5);
  });
});

describe("E-1 / E-2 invariants across all OAuth scenarios", () => {
  it.each([
    ["state-csrf", true],
    ["redirect-uri-bypass", true],
    ["code-via-referer", true],
  ] as const)(
    "%s: outcome=succeeded, 5 steps, _trace.attackSteps matches steps; extra %s",
    async (suffix, hasExtra) => {
      const res = await post(app, `/api/oauth/attack/${suffix}`, {});
      expect(res.status).toBe(200);
      expect(res.json.data.outcome).toBe("succeeded");
      expect(res.json.data.steps).toHaveLength(5);
      // _trace.attackSteps は data.steps と長さ一致 (両者は同一ステップ列を保持)
      expect(res.json._trace.attackSteps).toHaveLength(5);
      // E-1: extra フィールドの有無がジェネリック型と一致
      if (hasExtra) {
        expect(res.json.data.extra).toBeDefined();
      } else {
        expect(res.json.data.extra).toBeUndefined();
      }
    },
  );

  it("all 3 OAuth scenarios produce attack_log rows with finalize", async () => {
    const suffixes = ["state-csrf", "redirect-uri-bypass", "code-via-referer"];
    const logIds: number[] = [];
    for (const suffix of suffixes) {
      const res = await post(app, `/api/oauth/attack/${suffix}`, {});
      expect(res.json.data.logId).toBeGreaterThan(0);
      logIds.push(res.json.data.logId);
    }
    // 3 件のログ ID は重複しない (それぞれ独立した attack_log 行)
    const uniqueIds = new Set(logIds);
    expect(uniqueIds.size).toBe(3);
  });
});

describe("Production guard for OAuth attack routes", () => {
  it("attack route returns 403 when NODE_ENV=production", async () => {
    const orig = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    try {
      const res = await post(app, "/api/oauth/attack/state-csrf", {});
      expect(res.status).toBe(403);
      expect(res.json.success).toBe(false);
      expect(res.json.error).toContain("disabled in production");
    } finally {
      process.env.NODE_ENV = orig;
    }
  });
});
