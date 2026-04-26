/**
 * Phase 2 第一コミット (E-2): 5 ステップ完全形 + 両モード並列実行への再実装に伴うテスト更新。
 *
 * - 各シナリオは 1 リクエストで両モード (脆弱+堅牢) を必ず並列実行する。
 * - レスポンスは 5 ステップ完全形 (probe → tamper → forge → exploit → verify)。
 *   ステップ 4 (exploit) = 脆弱モード結果 (status: "success")
 *   ステップ 5 (verify)  = 堅牢モード結果 (status: "blocked")
 * - outcome は常に "succeeded" (両モード示すため、HTTP status は 200 で統一)。
 * - シナリオ固有フィールドは E-1 ジェネリック化で `data.extra` 配下に格納される:
 *   - weak-secret-bruteforce: extra.crackedSecret / extra.attemptCount
 *   - kid-injection: extra.kidResolved
 *   - alg-none / signature-stripping: extra なし
 */
import { describe, it, expect, beforeEach } from "vitest";
import { createTestApp, post } from "./test-helpers.js";
import type { Hono } from "hono";

let app: Hono;

beforeEach(() => {
  ({ app } = createTestApp());
});

describe("POST /api/jwt/attack/alg-none", () => {
  it("returns 5-step result with both lenient and strict mode outcomes", async () => {
    const res = await post(app, "/api/jwt/attack/alg-none", {});
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.scenarioId).toBe("jwt-alg-none");
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
    expect(res.json.data.blockedBy).toBe("jwt_algorithms_allowlist");
    // _trace 検証
    expect(res.json._trace.attackSteps).toBeDefined();
    expect(res.json._trace.isAttackMode).toBe(true);
    expect(res.json.data.logId).toBeGreaterThan(0);
  });

  it("ignores extra body fields (zod strips unknown keys silently)", async () => {
    // 旧契約 (mode/strict) を送っても 200 で 5 ステップ返却 (フィールドは無視される)
    const res = await post(app, "/api/jwt/attack/alg-none", {
      victim: { algorithm: "HS256", strict: false },
    });
    expect(res.status).toBe(200);
    expect(res.json.data.steps).toHaveLength(5);
  });
});

describe("POST /api/jwt/attack/weak-secret-bruteforce", () => {
  it("returns 5-step result with weak cracked + strong resisted", async () => {
    const res = await post(app, "/api/jwt/attack/weak-secret-bruteforce", {
      dictionarySize: 100,
    });
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.steps).toHaveLength(5);
    // E-1: extra フィールドにシナリオ固有データ
    expect(res.json.data.extra.crackedSecret).toBe("secret");
    expect(res.json.data.extra.attemptCount).toBeGreaterThanOrEqual(1);
    // ステップ 4 (forge, 脆弱モード) は status: "success"
    const forgeStep = res.json.data.steps[3];
    expect(forgeStep.kind).toBe("forge");
    expect(forgeStep.status).toBe("success");
    // ステップ 5 (verify, 堅牢モード) は status: "blocked"
    const verifyStep = res.json.data.steps[4];
    expect(verifyStep.kind).toBe("verify");
    expect(verifyStep.status).toBe("blocked");
    expect(res.json.data.blockedBy).toBe("strong_random_secret");
  });

  it("rejects dictionarySize over 200", async () => {
    const res = await post(app, "/api/jwt/attack/weak-secret-bruteforce", {
      dictionarySize: 201,
    });
    expect(res.status).toBe(400);
  });

  it("uses default dictionarySize when omitted", async () => {
    const res = await post(app, "/api/jwt/attack/weak-secret-bruteforce", {});
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.steps).toHaveLength(5);
  });
});

describe("POST /api/jwt/attack/signature-stripping", () => {
  it("returns 5-step result with decode-only accept + verify reject", async () => {
    const res = await post(app, "/api/jwt/attack/signature-stripping", {});
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.steps).toHaveLength(5);
    // ステップ 4 (exploit, 脆弱 decode-only) は status: "success"
    const exploitStep = res.json.data.steps[3];
    expect(exploitStep.kind).toBe("exploit");
    expect(exploitStep.status).toBe("success");
    // ステップ 5 (verify, 堅牢) は status: "blocked"
    const verifyStep = res.json.data.steps[4];
    expect(verifyStep.kind).toBe("verify");
    expect(verifyStep.status).toBe("blocked");
    expect(res.json.data.blockedBy).toBe("jwt_signature_mismatch");
  });

  it("accepts custom forgedToken if provided", async () => {
    const customForged = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4ifQ.CUSTOM_BAD_SIG";
    const res = await post(app, "/api/jwt/attack/signature-stripping", {
      forgedToken: customForged,
    });
    expect(res.status).toBe(200);
    expect(res.json.data.steps).toHaveLength(5);
  });
});

describe("POST /api/jwt/attack/kid-injection", () => {
  it("returns 5-step result with vulnerable accept + allowlist reject", async () => {
    const res = await post(app, "/api/jwt/attack/kid-injection", {
      injectedKid: "../public/attacker-key.pem",
    });
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.steps).toHaveLength(5);
    // E-1: extra.kidResolved にシナリオ固有データ
    expect(res.json.data.extra.kidResolved).toBe("../public/attacker-key.pem");
    // ステップ 4 (exploit, 脆弱) は status: "success"
    const exploitStep = res.json.data.steps[3];
    expect(exploitStep.kind).toBe("exploit");
    expect(exploitStep.status).toBe("success");
    // ステップ 5 (verify, 堅牢) は status: "blocked"
    const verifyStep = res.json.data.steps[4];
    expect(verifyStep.kind).toBe("verify");
    expect(verifyStep.status).toBe("blocked");
    expect(res.json.data.blockedBy).toBe("jwt_kid_not_in_allowlist");
  });

  it("uses default injected kid when omitted", async () => {
    const res = await post(app, "/api/jwt/attack/kid-injection", {});
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.extra.kidResolved).toBe("../public/attacker-key.pem");
  });

  it("attack_log row is inserted for every scenario", async () => {
    const res = await post(app, "/api/jwt/attack/kid-injection", {});
    expect(res.json.data.logId).toBeDefined();
    expect(typeof res.json.data.logId).toBe("number");
  });
});

describe("E-1 / E-2 invariants across all scenarios", () => {
  it.each([
    ["alg-none", false],
    ["weak-secret-bruteforce", true],
    ["signature-stripping", false],
    ["kid-injection", true],
  ] as const)(
    "%s: outcome=succeeded, 5 steps, _trace.attackSteps matches steps; extra %s",
    async (suffix, hasExtra) => {
      const res = await post(app, `/api/jwt/attack/${suffix}`, {});
      expect(res.status).toBe(200);
      expect(res.json.data.outcome).toBe("succeeded");
      expect(res.json.data.steps).toHaveLength(5);
      // _trace.attackSteps は data.steps と長さ一致 (両者は同一ステップ列を保持)
      expect(res.json._trace.attackSteps).toHaveLength(5);
      // E-1: extra フィールドの有無がジェネリック型と一致
      if (hasExtra) {
        expect(res.json.data.extra).toBeDefined();
      } else {
        // alg-none / signature-stripping は extra を持たない (デフォルト Record<string, never>)
        expect(res.json.data.extra).toBeUndefined();
      }
    },
  );

  it("all 4 scenarios produce attack_log rows with finalize", async () => {
    const suffixes = ["alg-none", "weak-secret-bruteforce", "signature-stripping", "kid-injection"];
    const logIds: number[] = [];
    for (const suffix of suffixes) {
      const res = await post(app, `/api/jwt/attack/${suffix}`, {});
      expect(res.json.data.logId).toBeGreaterThan(0);
      logIds.push(res.json.data.logId);
    }
    // 4 件のログ ID は重複しない (それぞれ独立した attack_log 行)
    const uniqueIds = new Set(logIds);
    expect(uniqueIds.size).toBe(4);
  });
});

describe("Production guard", () => {
  it("attack route returns 403 when NODE_ENV=production", async () => {
    const orig = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    try {
      const res = await post(app, "/api/jwt/attack/alg-none", {});
      expect(res.status).toBe(403);
      expect(res.json.success).toBe(false);
      expect(res.json.error).toContain("disabled in production");
    } finally {
      process.env.NODE_ENV = orig;
    }
  });

  it("non-attack route is unaffected by production guard", async () => {
    const orig = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    try {
      const res = await post(app, "/api/jwt/sign", {
        claims: { sub: "test-user" },
      });
      expect(res.status).toBe(200);
    } finally {
      process.env.NODE_ENV = orig;
    }
  });
});
