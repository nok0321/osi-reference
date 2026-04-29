/**
 * Phase 2 第十三コミット (sso-idp-apikey タブ): 5 ステップ完全形 + 両モード並列実行のテスト。
 *
 * - 各シナリオは 1 リクエストで両モード (脆弱+堅牢) を必ず並列実行する。
 * - レスポンスは 5 ステップ完全形 (probe → tamper → forge → exploit → verify)。
 *   ステップ 4 (exploit) = 脆弱モード結果 (status: "success" または "failed")
 *   ステップ 5 (verify)  = 堅牢モード結果 (status: "blocked")
 * - outcome は常に "succeeded" (両モード示すため、HTTP status は 200 で統一)。
 * - シナリオ固有フィールドは E-1 ジェネリック化で `data.extra` 配下に格納される:
 *   - apikey-leakage: extra.queryLoggedInUrl / headerNotLoggedInUrl /
 *     leakedKeyAcceptedBeforeRevocation / defendedRevocationRejected /
 *     attackKeyId / attackKeyInserted / leakedKeyPreview / logScopeNote
 *   - apikey-hmac-bypass: extra.vulnerable0CharMatchMs / vulnerable16CharMatchMs /
 *     defendedConstantTimeMs / vulnerableTimingLeakageMs / shortHmacKeySpace /
 *     fullHmacKeySpaceLabel / vulnerableAttackFeasible / defendedAttackBlocked /
 *     shortHmacSample / fullHmacSample / simulationNote
 *   - apikey-replay-no-timestamp: extra.vulnerableCanonicalReusable /
 *     vulnerableReplayAccepted / defendedReplayBlockedByTimestampSkew /
 *     defendedReplayBlockedByNonce / observedSkewMs / timestampSkewLimitMs /
 *     replayDelaySec / expiredReplayDelaySec / vulnerableCanonical /
 *     defendedCanonical / vulnerableHmacSample / defendedHmacSample / simulationNote
 *
 * E-3 痕跡削除 (apikey-leakage のみ DB INSERT あり):
 * api_keys に is_attack_sim=1 で漏洩キー再現行を INSERT、handler 末尾で DELETE。
 * 連続実行しても is_attack_sim=1 行が累積しないことを確認。
 */
import { describe, it, expect, beforeEach } from "vitest";
import { createTestApp, post } from "./test-helpers.js";
import type { Hono } from "hono";
import type Database from "better-sqlite3";

let app: Hono;
let db: Database.Database;

beforeEach(() => {
  ({ app, db } = createTestApp());
});

// ── Scenario A: API キー漏洩 ──────────────────────────────────────────────────
describe("POST /api/sso/attack/apikey-leakage", () => {
  it("returns 5-step result with vulnerable reuse + revocation block", async () => {
    const res = await post(app, "/api/sso/attack/apikey-leakage", {});
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.scenarioId).toBe("apikey-leakage");
    // 5 ステップ完全形
    expect(res.json.data.steps).toHaveLength(5);
    expect(res.json.data.steps[0].kind).toBe("probe");
    // ステップ 4 (exploit, 脆弱モード) は status: "success" (取消なしのため漏洩キー受理)
    const exploitStep = res.json.data.steps[3];
    expect(exploitStep.kind).toBe("exploit");
    expect(exploitStep.status).toBe("success");
    // ステップ 5 (verify, 堅牢モード) は status: "blocked"
    const verifyStep = res.json.data.steps[4];
    expect(verifyStep.kind).toBe("verify");
    expect(verifyStep.status).toBe("blocked");
    // blockedBy
    expect(res.json.data.blockedBy).toBe("api_key_revocation_invalidates_leaked_key");
    // E-1: extra
    expect(res.json.data.extra.queryLoggedInUrl).toBe(true);
    expect(res.json.data.extra.headerNotLoggedInUrl).toBe(true);
    expect(res.json.data.extra.leakedKeyAcceptedBeforeRevocation).toBe(true);
    expect(res.json.data.extra.defendedRevocationRejected).toBe(true);
    expect(res.json.data.extra.attackKeyInserted).toBe(true);
    expect(res.json.data.extra.attackKeyId).toMatch(/^key_atk_leak_/);
    expect(typeof res.json.data.extra.leakedKeyPreview).toBe("string");
    expect(res.json.data.extra.logScopeNote.ja).toContain("インメモリログ");
    expect(res.json.data.extra.logScopeNote.en).toContain("in-memory log");
    // _trace
    expect(res.json._trace.attackSteps).toBeDefined();
    expect(res.json._trace.attackSteps).toHaveLength(5);
    expect(res.json._trace.isAttackMode).toBe(true);
    expect(res.json.data.logId).toBeGreaterThan(0);
  });

  it("attack keys are inserted then cleaned up (no accumulation across calls)", async () => {
    // SEC-FIDO2-2 痕跡削除: scenario A は INSERT 後に DELETE まで完了する。
    // 連続実行しても is_attack_sim=1 行が累積しないことを確認。
    await post(app, "/api/sso/attack/apikey-leakage", {});
    await post(app, "/api/sso/attack/apikey-leakage", {});
    await post(app, "/api/sso/attack/apikey-leakage", {});
    const count = (db.prepare(
      "SELECT COUNT(*) as c FROM api_keys WHERE is_attack_sim = 1",
    ).get() as { c: number }).c;
    expect(count).toBe(0);
  });

  it("normal /verify/header endpoint never accepts attack-sim keys (E-3 isolation)", async () => {
    // 攻撃シナリオ実行中にも、正常系 endpoint は is_attack_sim=0 のみ参照することを確認。
    // 仮に痕跡削除前に並行アクセスがあっても、漏洩キーで認証は通らない。
    await post(app, "/api/sso/attack/apikey-leakage", {});
    // 正常系 /verify/header に漏洩キーを送っても 401 を返す (DELETE 後なので存在しない)
    const verifyRes = await post(
      app,
      "/api/sso/apikey/verify/header",
      {},
      { "X-API-Key": "demo_leaked_apikey_observed_in_access_log_for_education_only" },
    );
    expect(verifyRes.status).toBe(401);
  });

  it("ignores extra body fields (zod strips unknown keys silently)", async () => {
    const res = await post(app, "/api/sso/attack/apikey-leakage", {
      scenario: "query-vs-header",
      keyId: "key_seed0001",
      legacyField: "ignored",
    });
    expect(res.status).toBe(200);
    expect(res.json.data.steps).toHaveLength(5);
  });

  it("two consecutive calls produce distinct attackKeyId values (uuidv4 in INSERT)", async () => {
    const res1 = await post(app, "/api/sso/attack/apikey-leakage", {});
    const res2 = await post(app, "/api/sso/attack/apikey-leakage", {});
    expect(res1.json.data.extra.attackKeyId).not.toBe(res2.json.data.extra.attackKeyId);
    expect(res2.json.data.logId).toBeGreaterThan(res1.json.data.logId);
  });
});

// ── Scenario B: HMAC 検証バイパス ────────────────────────────────────────────
describe("POST /api/sso/attack/hmac-bypass", () => {
  it("returns 5-step result with vulnerable timing leakage + timingSafeEqual block", async () => {
    const res = await post(app, "/api/sso/attack/hmac-bypass", {});
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.scenarioId).toBe("apikey-hmac-bypass");
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
    expect(res.json.data.blockedBy).toBe("timing_safe_equal_and_full_length_hmac_enforced");
    // E-1: extra — タイミング差異の存在
    expect(res.json.data.extra.vulnerable0CharMatchMs).toBeGreaterThan(0);
    expect(res.json.data.extra.vulnerable16CharMatchMs).toBeGreaterThan(
      res.json.data.extra.vulnerable0CharMatchMs,
    );
    expect(res.json.data.extra.vulnerableTimingLeakageMs).toBeGreaterThan(0);
    expect(res.json.data.extra.defendedConstantTimeMs).toBeGreaterThan(0);
    // 鍵空間 — 4 バイト = 2^32, 32 バイトはラベル文字列
    expect(res.json.data.extra.shortHmacKeySpace).toBe(Math.pow(2, 32));
    expect(res.json.data.extra.fullHmacKeySpaceLabel).toContain("2^256");
    // 攻撃成立フラグ
    expect(res.json.data.extra.vulnerableAttackFeasible).toBe(true);
    expect(res.json.data.extra.defendedAttackBlocked).toBe(true);
    // HMAC サンプル長
    expect(res.json.data.extra.shortHmacSample).toHaveLength(8); // 4 バイト = 8 hex
    expect(res.json.data.extra.fullHmacSample).toHaveLength(64); // 32 バイト = 64 hex
    // 教育用シミュレーション注記
    expect(res.json.data.extra.simulationNote.ja).toContain("教育用シミュレーション");
    expect(res.json.data.extra.simulationNote.en).toContain("Educational simulation");
    // _trace
    expect(res.json._trace.cryptoOps).toBeDefined();
    const cryptoOpAlgos: string[] = (res.json._trace.cryptoOps ?? []).map(
      (o: { algo: string }) => o.algo,
    );
    expect(cryptoOpAlgos.some((a) => a.includes("short-circuit"))).toBe(true);
    expect(cryptoOpAlgos.some((a) => a.includes("timingSafeEqual"))).toBe(true);
    expect(res.json.data.logId).toBeGreaterThan(0);
  });

  it("does NOT INSERT any rows (in-memory simulation only)", async () => {
    await post(app, "/api/sso/attack/hmac-bypass", {});
    const count = (db.prepare(
      "SELECT COUNT(*) as c FROM api_keys WHERE is_attack_sim = 1",
    ).get() as { c: number }).c;
    expect(count).toBe(0);
  });

  it("ignores extra body fields", async () => {
    const res = await post(app, "/api/sso/attack/hmac-bypass", {
      compareMethod: "string-equal",
      hmacLength: 4,
      keyId: "key_seed0001",
      legacyField: "ignored",
    });
    expect(res.status).toBe(200);
    expect(res.json.data.steps).toHaveLength(5);
  });

  it("does not expose demoSecret plaintext in payload_json (SEC FINDING-5 masking)", async () => {
    // payload_json に保存されたシークレットは maskSecret() で長さ情報のみに変換される。
    // _trace.cryptoOps の input にも secret 平文を載せない (sso-apikey.ts の addCryptoOp で <masked>)。
    await post(app, "/api/sso/attack/hmac-bypass", {});
    const log = db.prepare(
      "SELECT payload_json FROM attack_log WHERE scenario_id = ? ORDER BY id DESC LIMIT 1",
    ).get("apikey-hmac-bypass") as { payload_json: string } | undefined;
    expect(log).toBeDefined();
    expect(log!.payload_json).not.toContain("demo-hmac-secret-for-education-only");
    expect(log!.payload_json).toContain("d***y"); // maskSecret("demo-hmac-secret-for-education-only") starts with "d" ends with "y"
  });
});

// ── Scenario C: タイムスタンプなしリプレイ ────────────────────────────────────
describe("POST /api/sso/attack/replay-no-timestamp", () => {
  it("returns 5-step result with vulnerable replay + timestamp/nonce block", async () => {
    const res = await post(app, "/api/sso/attack/replay-no-timestamp", {});
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.scenarioId).toBe("apikey-replay-no-timestamp");
    expect(res.json.data.steps).toHaveLength(5);
    expect(res.json.data.steps[0].kind).toBe("probe");
    const exploitStep = res.json.data.steps[3];
    expect(exploitStep.kind).toBe("exploit");
    expect(exploitStep.status).toBe("success");
    const verifyStep = res.json.data.steps[4];
    expect(verifyStep.kind).toBe("verify");
    expect(verifyStep.status).toBe("blocked");
    expect(res.json.data.blockedBy).toBe("timestamp_skew_and_nonce_one_time_use_enforced");
    // E-1: extra
    expect(res.json.data.extra.vulnerableCanonicalReusable).toBe(true);
    expect(res.json.data.extra.vulnerableReplayAccepted).toBe(true);
    expect(res.json.data.extra.defendedReplayBlockedByTimestampSkew).toBe(true);
    expect(res.json.data.extra.defendedReplayBlockedByNonce).toBe(true);
    // 観測値の一貫性
    expect(res.json.data.extra.observedSkewMs).toBeGreaterThan(
      res.json.data.extra.timestampSkewLimitMs,
    );
    expect(res.json.data.extra.replayDelaySec).toBe(60);
    expect(res.json.data.extra.expiredReplayDelaySec).toBe(360);
    // canonical の差異
    expect(res.json.data.extra.vulnerableCanonical).not.toContain("\n");
    expect(res.json.data.extra.defendedCanonical).toContain("\n");
    expect(res.json.data.extra.defendedCanonical).toContain("2026-04-30T12:00:00Z");
    // HMAC サンプル長 (32 バイト = 64 hex)
    expect(res.json.data.extra.vulnerableHmacSample).toHaveLength(64);
    expect(res.json.data.extra.defendedHmacSample).toHaveLength(64);
    // 脆弱 vs 堅牢で HMAC 値が異なる
    expect(res.json.data.extra.vulnerableHmacSample).not.toBe(
      res.json.data.extra.defendedHmacSample,
    );
    // 教育用シミュレーション注記
    expect(res.json.data.extra.simulationNote.ja).toContain("教育用シミュレーション");
    expect(res.json.data.extra.simulationNote.en).toContain("Educational simulation");
    // _trace
    expect(res.json._trace.cryptoOps).toBeDefined();
    const cryptoOps = res.json._trace.cryptoOps ?? [];
    const hasNonceOp = cryptoOps.some((o: { op: string }) =>
      o.op.includes("nonceUniquenessCheck"),
    );
    expect(hasNonceOp).toBe(true);
    expect(res.json.data.logId).toBeGreaterThan(0);
  });

  it("does NOT INSERT any rows (handler-local nonce Set only)", async () => {
    await post(app, "/api/sso/attack/replay-no-timestamp", {});
    const apiKeyCount = (db.prepare(
      "SELECT COUNT(*) as c FROM api_keys WHERE is_attack_sim = 1",
    ).get() as { c: number }).c;
    expect(apiKeyCount).toBe(0);
  });

  it("nonce Set is handler-local — fresh on each request, no cross-call leak", async () => {
    // ROB-FIDO2-2 / SEC-OIDC-2 教訓: handler-local Set のため、毎リクエストで fresh。
    // 連続実行しても各リクエスト内で nonce 一意性検査が成立し続ける。
    const res1 = await post(app, "/api/sso/attack/replay-no-timestamp", {});
    const res2 = await post(app, "/api/sso/attack/replay-no-timestamp", {});
    expect(res1.json.data.extra.defendedReplayBlockedByNonce).toBe(true);
    expect(res2.json.data.extra.defendedReplayBlockedByNonce).toBe(true);
  });

  it("ignores extra body fields", async () => {
    const res = await post(app, "/api/sso/attack/replay-no-timestamp", {
      phase: "replay",
      includeTimestamp: false,
      includeNonce: false,
      delaySimulatedMs: 60000,
      legacyField: "ignored",
    });
    expect(res.status).toBe(200);
    expect(res.json.data.steps).toHaveLength(5);
  });
});

// ── E-1 / E-2 invariants across all sso-apikey scenarios ──────────────────────
describe("E-1 / E-2 invariants across all sso-apikey scenarios", () => {
  it.each([
    ["apikey-leakage"],
    ["hmac-bypass"],
    ["replay-no-timestamp"],
  ] as const)(
    "sso/%s: outcome=succeeded, 5 steps, _trace.attackSteps matches steps; extra defined",
    async (suffix) => {
      const res = await post(app, `/api/sso/attack/${suffix}`, {});
      expect(res.status).toBe(200);
      expect(res.json.data.outcome).toBe("succeeded");
      expect(res.json.data.steps).toHaveLength(5);
      expect(res.json._trace.attackSteps).toHaveLength(5);
      expect(res.json.data.extra).toBeDefined();
    },
  );

  it("all 3 scenarios produce attack_log rows with unique logIds", async () => {
    const suffixes = ["apikey-leakage", "hmac-bypass", "replay-no-timestamp"] as const;
    const logIds: number[] = [];
    for (const suffix of suffixes) {
      const res = await post(app, `/api/sso/attack/${suffix}`, {});
      expect(res.json.data.logId).toBeGreaterThan(0);
      logIds.push(res.json.data.logId as number);
    }
    expect(new Set(logIds).size).toBe(3);
  });

  it("all 3 scenarios have blockedBy set to a non-empty snake_case string", async () => {
    const suffixes = ["apikey-leakage", "hmac-bypass", "replay-no-timestamp"] as const;
    for (const suffix of suffixes) {
      const res = await post(app, `/api/sso/attack/${suffix}`, {});
      expect(typeof res.json.data.blockedBy).toBe("string");
      expect(res.json.data.blockedBy).toMatch(/^[a-z][a-z0-9_]+$/);
    }
  });

  it("step 4 is exploit and step 5 is verify with status='blocked' across all scenarios", async () => {
    const suffixes = ["apikey-leakage", "hmac-bypass", "replay-no-timestamp"] as const;
    for (const suffix of suffixes) {
      const res = await post(app, `/api/sso/attack/${suffix}`, {});
      const steps = res.json.data.steps;
      expect(steps[3].kind).toBe("exploit");
      expect(steps[4].kind).toBe("verify");
      expect(steps[4].status).toBe("blocked");
    }
  });

  it("summaryJa starts with 'この実装は' or 'このシナリオでは' across all scenarios", async () => {
    const suffixes = ["apikey-leakage", "hmac-bypass", "replay-no-timestamp"] as const;
    for (const suffix of suffixes) {
      const res = await post(app, `/api/sso/attack/${suffix}`, {});
      const summaryJa: string = res.json.data.summaryJa ?? "";
      const startsWithExpected =
        summaryJa.startsWith("この実装は") || summaryJa.startsWith("このシナリオでは");
      expect(
        startsWithExpected,
        `summaryJa for sso/${suffix} should start with 'この実装は' or 'このシナリオでは', got: "${summaryJa.substring(0, 30)}"`,
      ).toBe(true);
    }
  });
});

// ── Production guard ──────────────────────────────────────────────────────────
describe("Production guard for sso-apikey attack routes", () => {
  it.each([
    ["apikey-leakage"],
    ["hmac-bypass"],
    ["replay-no-timestamp"],
  ] as const)("sso/%s returns 403 when NODE_ENV=production", async (suffix) => {
    const orig = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    try {
      const res = await post(app, `/api/sso/attack/${suffix}`, {});
      expect(res.status).toBe(403);
      expect(res.json.success).toBe(false);
      expect(res.json.error).toContain("disabled in production");
    } finally {
      process.env.NODE_ENV = orig;
    }
  });
});
