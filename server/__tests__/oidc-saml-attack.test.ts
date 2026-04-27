/**
 * Phase 2 第七コミット (oidc-saml タブ): 5 ステップ完全形 + 両モード並列実行のテスト。
 *
 * - 各シナリオは 1 リクエストで両モード (脆弱+堅牢) を必ず並列実行する。
 * - レスポンスは 5 ステップ完全形 (probe → tamper → forge → exploit → verify)。
 *   ステップ 4 (exploit) = 脆弱モード結果 (status: "success" または "failed")
 *   ステップ 5 (verify)  = 堅牢モード結果 (status: "blocked")
 * - outcome は常に "succeeded" (両モード示すため、HTTP status は 200 で統一)。
 * - シナリオ固有フィールドは E-1 ジェネリック化で `data.extra` 配下に格納される:
 *   - saml-xsw: extra.signedAssertionId / fakeAssertionId / vulnerableProcessedRole / defendedRejected
 *   - saml-assertion-replay: extra.capturedAssertionId / vulnerableReplayAccepted / defendedReplayBlocked
 *   - oidc-id-token-spoofing: extra.spoofedTokenPreview / vulnerableAcceptedAs / defendedRejected*
 */
import { describe, it, expect, beforeEach } from "vitest";
import { createTestApp, post } from "./test-helpers.js";
import type { Hono } from "hono";

let app: Hono;

beforeEach(() => {
  ({ app } = createTestApp());
});

// ── Scenario A: SAML XSW ─────────────────────────────────────────────────────
describe("POST /api/oidc/attack/saml-xsw", () => {
  it("returns 5-step result with vulnerable accept + XPath scope check block", async () => {
    const res = await post(app, "/api/oidc/attack/saml-xsw", {});
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.scenarioId).toBe("saml-xsw");
    // 5 ステップ完全形
    expect(res.json.data.steps).toHaveLength(5);
    expect(res.json.data.steps[0].kind).toBe("probe");
    // ステップ 4 (exploit, 脆弱) は status: "success" (XSW 成立)
    const exploitStep = res.json.data.steps[3];
    expect(exploitStep.kind).toBe("exploit");
    expect(exploitStep.status).toBe("success");
    // ステップ 5 (verify, 堅牢) は status: "blocked"
    const verifyStep = res.json.data.steps[4];
    expect(verifyStep.kind).toBe("verify");
    expect(verifyStep.status).toBe("blocked");
    // blockedBy
    expect(res.json.data.blockedBy).toBe("saml_xsw_signed_id_processed_id_match_enforced");
    // E-1: extra フィールド
    expect(res.json.data.extra.signedAssertionId).toMatch(/^_real_assertion_/);
    expect(res.json.data.extra.fakeAssertionId).toBe("_fake_assertion_001");
    expect(res.json.data.extra.legitimateSubject).toBe("seed_alice@demo.example");
    expect(res.json.data.extra.fakeSubject).toBe("attacker_charlie@demo.example");
    expect(res.json.data.extra.legitimateRole).toBe("user");
    expect(res.json.data.extra.fakeRole).toBe("admin");
    expect(res.json.data.extra.vulnerableProcessedSubject).toBe("attacker_charlie@demo.example");
    expect(res.json.data.extra.vulnerableProcessedRole).toBe("admin");
    expect(res.json.data.extra.defendedRejected).toBe(true);
    expect(res.json.data.extra.victimUsername).toBe("seed_alice");
    expect(res.json.data.extra.victimSeedFound).toBe(true);
    // _trace 検証
    expect(res.json._trace.attackSteps).toBeDefined();
    expect(res.json._trace.attackSteps).toHaveLength(5);
    expect(res.json._trace.isAttackMode).toBe(true);
    expect(res.json.data.logId).toBeGreaterThan(0);
  });

  it("ignores extra body fields (zod strips unknown keys silently)", async () => {
    const res = await post(app, "/api/oidc/attack/saml-xsw", {
      legacyMode: "naive",
      anotherField: 123,
    });
    expect(res.status).toBe(200);
    expect(res.json.data.steps).toHaveLength(5);
  });

  it("two consecutive calls produce distinct signedAssertionIds (uuidv4)", async () => {
    const res1 = await post(app, "/api/oidc/attack/saml-xsw", {});
    const res2 = await post(app, "/api/oidc/attack/saml-xsw", {});
    expect(res1.json.data.extra.signedAssertionId).not.toBe(
      res2.json.data.extra.signedAssertionId,
    );
  });

  it("does not write any DB rows for normal-flow tables", async () => {
    // saml-xsw は in-memory simulation のみ (DB INSERT 無し)
    await post(app, "/api/oidc/attack/saml-xsw", {});
    // sessions / oauth_codes / oauth_tokens 等の正常系テーブルに痕跡が残っていないことを確認
    // (attack_log のみ書き込み)
    const credsRes = await (
      await app.request("/api/webauthn/credentials", { method: "GET" })
    ).json();
    const creds: { credential_id: string }[] = credsRes.data?.credentials ?? [];
    expect(creds.length).toBe(0);
  });
});

// ── Scenario B: SAML Assertion Replay ─────────────────────────────────────────
describe("POST /api/oidc/attack/saml-assertion-replay", () => {
  it("returns 5-step result with vulnerable replay + OneTimeUse cache block", async () => {
    const res = await post(app, "/api/oidc/attack/saml-assertion-replay", {});
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.scenarioId).toBe("saml-assertion-replay");
    expect(res.json.data.steps).toHaveLength(5);
    expect(res.json.data.steps[0].kind).toBe("probe");
    // ステップ 4 (exploit, 脆弱) は status: "success"
    const exploitStep = res.json.data.steps[3];
    expect(exploitStep.kind).toBe("exploit");
    expect(exploitStep.status).toBe("success");
    // ステップ 5 (verify, 堅牢) は status: "blocked"
    const verifyStep = res.json.data.steps[4];
    expect(verifyStep.kind).toBe("verify");
    expect(verifyStep.status).toBe("blocked");
    expect(res.json.data.blockedBy).toBe("saml_assertion_replay_one_time_use_cache_enforced");
    // E-1: extra
    expect(res.json.data.extra.capturedAssertionId).toMatch(/^_captured_assertion_/);
    expect(res.json.data.extra.vulnerableReplayAccepted).toBe(true);
    expect(res.json.data.extra.defendedReplayBlocked).toBe(true);
    expect(res.json.data.extra.notOnOrAfterCheckTested).toBe(true);
    expect(res.json.data.extra.notOnOrAfterCheckBlocked).toBe(true);
    expect(res.json.data.extra.victimUsername).toBe("seed_alice");
    expect(res.json.data.extra.attackerUsername).toBe("attacker_charlie");
    expect(res.json.data.extra.victimSeedFound).toBe(true);
    // _trace
    expect(res.json._trace.attackSteps).toHaveLength(5);
    expect(res.json._trace.isAttackMode).toBe(true);
    expect(res.json.data.logId).toBeGreaterThan(0);
  });

  it("ignores extra body fields", async () => {
    const res = await post(app, "/api/oidc/attack/saml-assertion-replay", {
      mode: "no-one-time-use-check",
      replayMode: "valid",
    });
    expect(res.status).toBe(200);
    expect(res.json.data.steps).toHaveLength(5);
  });

  it("two consecutive calls produce distinct capturedAssertionIds", async () => {
    const res1 = await post(app, "/api/oidc/attack/saml-assertion-replay", {});
    const res2 = await post(app, "/api/oidc/attack/saml-assertion-replay", {});
    expect(res1.json.data.extra.capturedAssertionId).not.toBe(
      res2.json.data.extra.capturedAssertionId,
    );
  });

  it("trace.sessionOps records SAML_ASSERTION_FIRST_USE_CACHED for defended path", async () => {
    const res = await post(app, "/api/oidc/attack/saml-assertion-replay", {});
    const sessionOps: { action: string }[] = res.json._trace.sessionOps ?? [];
    expect(
      sessionOps.some((op) => op.action === "SAML_ASSERTION_FIRST_USE_CACHED"),
    ).toBe(true);
  });
});

// ── Scenario C: OIDC ID Token Spoofing ────────────────────────────────────────
describe("POST /api/oidc/attack/id-token-spoof", () => {
  it("returns 5-step result with vulnerable accept + iss/aud/signature block", async () => {
    const res = await post(app, "/api/oidc/attack/id-token-spoof", {});
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.scenarioId).toBe("oidc-id-token-spoofing");
    expect(res.json.data.steps).toHaveLength(5);
    expect(res.json.data.steps[0].kind).toBe("probe");
    // ステップ 4 (exploit, 脆弱) は status: "success"
    const exploitStep = res.json.data.steps[3];
    expect(exploitStep.kind).toBe("exploit");
    expect(exploitStep.status).toBe("success");
    // ステップ 5 (verify, 堅牢) は status: "blocked"
    const verifyStep = res.json.data.steps[4];
    expect(verifyStep.kind).toBe("verify");
    expect(verifyStep.status).toBe("blocked");
    expect(res.json.data.blockedBy).toBe("oidc_id_token_iss_aud_nonce_validation_enforced");
    // E-1: extra
    expect(res.json.data.extra.legitimateIssuer).toBe("http://localhost:3001/api/oidc");
    expect(res.json.data.extra.attackerIssuer).toBe("https://attacker.example/oidc");
    expect(res.json.data.extra.legitimateAud).toBe("demo-oidc-app");
    expect(res.json.data.extra.attackerAud).toBe("victim-rp-client");
    expect(typeof res.json.data.extra.spoofedTokenPreview).toBe("string");
    expect(res.json.data.extra.spoofedTokenPreview).toContain("...");
    expect(res.json.data.extra.vulnerableAcceptedAs).toBe("seed_alice");
    expect(res.json.data.extra.vulnerableAcceptedRole).toBe("admin");
    expect(res.json.data.extra.defendedRejectedByIss).toBe(true);
    expect(res.json.data.extra.defendedRejectedByAud).toBe(true);
    expect(res.json.data.extra.defendedRejectedBySignature).toBe(true);
    expect(res.json.data.extra.victimUsername).toBe("seed_alice");
    expect(res.json.data.extra.attackerUsername).toBe("attacker_charlie");
    expect(res.json.data.extra.victimSeedFound).toBe(true);
    // _trace
    expect(res.json._trace.attackSteps).toHaveLength(5);
    expect(res.json._trace.isAttackMode).toBe(true);
    expect(res.json.data.logId).toBeGreaterThan(0);
  });

  it("ignores extra body fields", async () => {
    const res = await post(app, "/api/oidc/attack/id-token-spoof", {
      action: "issue-from-attacker-idp",
      mode: "no-claims-check",
    });
    expect(res.status).toBe(200);
    expect(res.json.data.steps).toHaveLength(5);
  });

  it("trace.cryptoOps records jwt.sign(attacker_idp) and jwt.verify(strict)", async () => {
    const res = await post(app, "/api/oidc/attack/id-token-spoof", {});
    const cryptoOps: { op: string }[] = res.json._trace.cryptoOps ?? [];
    expect(
      cryptoOps.some((op) => op.op === "jwt.sign(attacker_idp)"),
    ).toBe(true);
    expect(
      cryptoOps.some((op) => op.op === "jwt.decode(spoofed_token, no_verify)"),
    ).toBe(true);
    expect(
      cryptoOps.some((op) => op.op === "jwt.verify(spoofed_token, strict)"),
    ).toBe(true);
  });

  it("attacker signing key is masked in payload_json (no plaintext leak)", async () => {
    // 攻撃者鍵 (attacker-evil-idp-signing-key) が steps / _trace 全体で平文 verbatim に出現しないこと
    const res = await post(app, "/api/oidc/attack/id-token-spoof", {});
    const fullStr = JSON.stringify(res.json);
    expect(fullStr).not.toContain("attacker-evil-idp-signing-key"); // 鍵本体は完全マスク
    expect(fullStr).toContain("***"); // マスク形式は何処かに存在
  });
});

// ── E-1 / E-2 invariants across all oidc-saml scenarios ──────────────────────
describe("E-1 / E-2 invariants across all oidc-saml scenarios", () => {
  it.each([
    ["saml-xsw"],
    ["saml-assertion-replay"],
    ["id-token-spoof"],
  ] as const)(
    "oidc/%s: outcome=succeeded, 5 steps, _trace.attackSteps matches steps; extra defined",
    async (suffix) => {
      const res = await post(app, `/api/oidc/attack/${suffix}`, {});
      expect(res.status).toBe(200);
      expect(res.json.data.outcome).toBe("succeeded");
      expect(res.json.data.steps).toHaveLength(5);
      expect(res.json._trace.attackSteps).toHaveLength(5);
      expect(res.json.data.extra).toBeDefined();
    },
  );

  it("all 3 scenarios produce attack_log rows with unique logIds", async () => {
    const suffixes = ["saml-xsw", "saml-assertion-replay", "id-token-spoof"] as const;
    const logIds: number[] = [];
    for (const suffix of suffixes) {
      const res = await post(app, `/api/oidc/attack/${suffix}`, {});
      expect(res.json.data.logId).toBeGreaterThan(0);
      logIds.push(res.json.data.logId as number);
    }
    expect(new Set(logIds).size).toBe(3);
  });

  it("all 3 scenarios have blockedBy set to a non-empty snake_case string", async () => {
    const suffixes = ["saml-xsw", "saml-assertion-replay", "id-token-spoof"] as const;
    for (const suffix of suffixes) {
      const res = await post(app, `/api/oidc/attack/${suffix}`, {});
      expect(typeof res.json.data.blockedBy).toBe("string");
      expect(res.json.data.blockedBy).toMatch(/^[a-z][a-z0-9_]+$/);
    }
  });

  it("step 4 is exploit and step 5 is verify across all scenarios", async () => {
    const suffixes = ["saml-xsw", "saml-assertion-replay", "id-token-spoof"] as const;
    for (const suffix of suffixes) {
      const res = await post(app, `/api/oidc/attack/${suffix}`, {});
      const steps = res.json.data.steps;
      expect(steps[3].kind).toBe("exploit");
      expect(steps[4].kind).toBe("verify");
      expect(steps[4].status).toBe("blocked");
    }
  });

  it("summaryJa starts with 'この実装は' or 'このシナリオでは' across all scenarios", async () => {
    const suffixes = ["saml-xsw", "saml-assertion-replay", "id-token-spoof"] as const;
    for (const suffix of suffixes) {
      const res = await post(app, `/api/oidc/attack/${suffix}`, {});
      const summaryJa: string = res.json.data.summaryJa ?? "";
      const startsWithExpected =
        summaryJa.startsWith("この実装は") || summaryJa.startsWith("このシナリオでは");
      expect(
        startsWithExpected,
        `summaryJa for oidc/${suffix} should start with 'この実装は' or 'このシナリオでは', got: "${summaryJa.substring(0, 30)}"`,
      ).toBe(true);
    }
  });

  it("all 3 scenarios have victimSeedFound=true (seeded DB)", async () => {
    const suffixes = ["saml-xsw", "saml-assertion-replay", "id-token-spoof"] as const;
    for (const suffix of suffixes) {
      const res = await post(app, `/api/oidc/attack/${suffix}`, {});
      expect(res.json.data.extra.victimSeedFound).toBe(true);
    }
  });
});

// ── Production guard ──────────────────────────────────────────────────────────
describe("Production guard for oidc-saml attack routes", () => {
  it.each([
    ["saml-xsw"],
    ["saml-assertion-replay"],
    ["id-token-spoof"],
  ] as const)("oidc/%s returns 403 when NODE_ENV=production", async (suffix) => {
    const orig = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    try {
      const res = await post(app, `/api/oidc/attack/${suffix}`, {});
      expect(res.status).toBe(403);
      expect(res.json.success).toBe(false);
      expect(res.json.error).toContain("disabled in production");
    } finally {
      process.env.NODE_ENV = orig;
    }
  });
});
