/**
 * Phase 2 第六コミット (fido2 タブ): 5 ステップ完全形 + 両モード並列実行のテスト。
 *
 * - 各シナリオは 1 リクエストで両モード (脆弱+堅牢) を必ず並列実行する。
 * - レスポンスは 5 ステップ完全形 (probe → tamper → forge → exploit → verify)。
 *   ステップ 4 (exploit) = 脆弱モード結果 (status: "success" または "failed")
 *   ステップ 5 (verify)  = 堅牢モード結果 (status: "blocked")
 * - outcome は常に "succeeded" (両モード示すため、HTTP status は 200 で統一)。
 * - シナリオ固有フィールドは E-1 ジェネリック化で `data.extra` 配下に格納される:
 *   - phishing-origin: extra.attackerOrigin / expectedOrigin / vulnerableAccepted / defendedRejected
 *   - vs-password-phishing: extra.passwordSucceeded / fido2Blocked / capturedPasswordMasked / comparison
 *   - challenge-replay: extra.replayChallengePreview / vulnerableReplayAccepted / defendedReplayBlocked
 *
 * このタブの特殊性 (DESIGN/15 §1.1):
 * 全シナリオで「プロトコル設計が攻撃を成立させない」ことを示す。
 * 堅牢モードのステップ 5 は必ず status: "blocked" で、blockedBy には防御識別子が入る。
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

// ── Scenario A: フィッシング origin 検証による失敗 ─────────────────────────────
describe("POST /api/webauthn/attack/phishing-origin", () => {
  it("returns 5-step result with vulnerable accept + origin-validation block", async () => {
    const res = await post(app, "/api/webauthn/attack/phishing-origin", {});
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.scenarioId).toBe("fido2-phishing-origin-rejection");
    // 5 ステップ完全形
    expect(res.json.data.steps).toHaveLength(5);
    // ステップ 1: probe
    expect(res.json.data.steps[0].kind).toBe("probe");
    // ステップ 4 (exploit, 脆弱モード) は status: "success" (origin チェック省略の受理)
    const exploitStep = res.json.data.steps[3];
    expect(exploitStep.kind).toBe("exploit");
    expect(exploitStep.status).toBe("success");
    // ステップ 5 (verify, 堅牢モード) は status: "blocked"
    const verifyStep = res.json.data.steps[4];
    expect(verifyStep.kind).toBe("verify");
    expect(verifyStep.status).toBe("blocked");
    // blockedBy
    expect(res.json.data.blockedBy).toBe("webauthn_origin_validation_enforced");
    // E-1: extra フィールド
    expect(res.json.data.extra.attackerOrigin).toBe("http://attacker.example");
    expect(res.json.data.extra.expectedOrigin).toBe("http://localhost:3000");
    expect(res.json.data.extra.vulnerableAccepted).toBe(true);
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
    const res = await post(app, "/api/webauthn/attack/phishing-origin", {
      legacyField: "ignored",
      anotherField: 123,
    });
    expect(res.status).toBe(200);
    expect(res.json.data.steps).toHaveLength(5);
  });

  it("does not INSERT any webauthn_credentials rows (in-memory simulation only)", async () => {
    await post(app, "/api/webauthn/attack/phishing-origin", {});
    // The /credentials endpoint returns only is_attack_sim=0 rows
    const credsRes = await (await app.request("/api/webauthn/credentials", { method: "GET" })).json();
    const credIds: string[] = (credsRes.data?.credentials ?? []).map(
      (c: { credential_id: string }) => c.credential_id,
    );
    // Phishing-origin scenario does no DB INSERT
    expect(credIds.length).toBe(0);
  });

  it("is idempotent — second call also returns 200", async () => {
    const res1 = await post(app, "/api/webauthn/attack/phishing-origin", {});
    const res2 = await post(app, "/api/webauthn/attack/phishing-origin", {});
    expect(res1.status).toBe(200);
    expect(res2.status).toBe(200);
    expect(res2.json.data.steps).toHaveLength(5);
  });
});

// ── Scenario B: パスワード vs FIDO2 フィッシング比較 ──────────────────────────
describe("POST /api/webauthn/attack/vs-password-phishing", () => {
  it("returns 5-step result with password-side success + FIDO2-side block", async () => {
    const res = await post(app, "/api/webauthn/attack/vs-password-phishing", {});
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.scenarioId).toBe("fido2-vs-password-phishing");
    expect(res.json.data.steps).toHaveLength(5);
    expect(res.json.data.steps[0].kind).toBe("probe");
    // ステップ 4 (exploit, パスワード側) は status: "success" (bcrypt.compare 一致)
    const exploitStep = res.json.data.steps[3];
    expect(exploitStep.kind).toBe("exploit");
    expect(exploitStep.status).toBe("success");
    // ステップ 5 (verify, FIDO2 側) は status: "blocked"
    const verifyStep = res.json.data.steps[4];
    expect(verifyStep.kind).toBe("verify");
    expect(verifyStep.status).toBe("blocked");
    expect(res.json.data.blockedBy).toBe("webauthn_origin_phishing_blocked");
    // E-1: extra
    expect(res.json.data.extra.passwordSucceeded).toBe(true);
    expect(res.json.data.extra.fido2Blocked).toBe(true);
    expect(typeof res.json.data.extra.capturedPasswordMasked).toBe("string");
    expect(res.json.data.extra.capturedPasswordMasked).toContain("***");
    expect(res.json.data.extra.attackerOrigin).toBe("http://attacker.example");
    expect(res.json.data.extra.victimUsername).toBe("seed_alice");
    expect(res.json.data.extra.victimSeedFound).toBe(true);
    expect(res.json.data.extra.comparison.passwordPhishingSuccessRate).toContain("100%");
    expect(res.json.data.extra.comparison.fido2PhishingSuccessRate).toContain("0%");
    // _trace
    expect(res.json._trace.attackSteps).toHaveLength(5);
    expect(res.json._trace.isAttackMode).toBe(true);
    expect(res.json.data.logId).toBeGreaterThan(0);
  });

  it("ignores extra body fields", async () => {
    const res = await post(app, "/api/webauthn/attack/vs-password-phishing", {
      bypassToggle: true,
    });
    expect(res.status).toBe(200);
    expect(res.json.data.steps).toHaveLength(5);
  });

  it("captured password is masked across full response (no plaintext leak in extra/steps/_trace)", async () => {
    // SEC-FIDO2-4: extra のみではなく steps / _trace.cryptoOps を含む全レスポンスで
    //              "Passw0rd!" が verbatim に出現しないことを保証。
    //              将来の handler 修正で誤って victimPasswordPlain を直接展開した場合に CI が検出可能に。
    const res = await post(app, "/api/webauthn/attack/vs-password-phishing", {});
    const fullStr = JSON.stringify(res.json);
    expect(fullStr).not.toContain("Passw0rd!"); // 全レスポンス + _trace 含めて完全マスク
    expect(fullStr).toContain("***"); // マスク形式は何処かに存在するはず
  });
});

// ── Scenario C: チャレンジリプレイ攻撃 (one-time 設計による阻止) ──────────────
describe("POST /api/webauthn/attack/challenge-replay", () => {
  it("returns 5-step result with vulnerable replay + one-time block", async () => {
    const res = await post(app, "/api/webauthn/attack/challenge-replay", {});
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.scenarioId).toBe("fido2-challenge-replay");
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
    expect(res.json.data.blockedBy).toBe("webauthn_challenge_one_time_consumed");
    // E-1: extra
    expect(typeof res.json.data.extra.replayChallengePreview).toBe("string");
    expect(res.json.data.extra.replayChallengePreview).toContain("...");
    expect(res.json.data.extra.vulnerableReplayAccepted).toBe(true);
    expect(res.json.data.extra.defendedReplayBlocked).toBe(true);
    expect(typeof res.json.data.extra.vulnerableSessionId).toBe("string");
    expect(typeof res.json.data.extra.defendedSessionId).toBe("string");
    expect(res.json.data.extra.attestationPreview).toContain("...");
    expect(res.json.data.extra.victimUsername).toBe("seed_alice");
    expect(res.json.data.extra.attackerUsername).toBe("attacker_charlie");
    expect(res.json.data.extra.victimSeedFound).toBe(true);
    // ROB-FIDO2-3: attackCredentialInserted を extra で観測可能
    expect(res.json.data.extra.attackCredentialInserted).toBe(true);
    // _trace
    expect(res.json._trace.attackSteps).toHaveLength(5);
    expect(res.json._trace.isAttackMode).toBe(true);
    expect(res.json.data.logId).toBeGreaterThan(0);
  });

  it("attack credentials are inserted then cleaned up (no accumulation across calls)", async () => {
    // ROB-FIDO2-15 / SEC-FIDO2-2: scenario C は INSERT 後に DELETE まで完了する。
    // 連続実行しても is_attack_sim=1 行が累積しないことを確認。
    await post(app, "/api/webauthn/attack/challenge-replay", {});
    await post(app, "/api/webauthn/attack/challenge-replay", {});
    await post(app, "/api/webauthn/attack/challenge-replay", {});
    const count = (db.prepare(
      "SELECT COUNT(*) as c FROM webauthn_credentials WHERE is_attack_sim = 1"
    ).get() as { c: number }).c;
    // 後始末で全て DELETE されているはず (attackCredentialInserted=true で INSERT 成立後に削除)
    expect(count).toBe(0);
  });

  it("normal /credentials listing never exposes is_attack_sim=1 rows", async () => {
    await post(app, "/api/webauthn/attack/challenge-replay", {});
    // The /credentials endpoint filters is_attack_sim=0; attack creds should NOT appear
    const credsRes = await (await app.request("/api/webauthn/credentials", { method: "GET" })).json();
    const normalCreds: { credential_id: string }[] = credsRes.data?.credentials ?? [];
    // No attack credentials should leak into the normal /credentials listing
    for (const c of normalCreds) {
      expect(c.credential_id.startsWith("attack-fido2-replay-")).toBe(false);
    }
  });

  it("ignores extra body fields", async () => {
    const res = await post(app, "/api/webauthn/attack/challenge-replay", { sid: "ignored" });
    expect(res.status).toBe(200);
    expect(res.json.data.steps).toHaveLength(5);
  });

  it("two consecutive calls produce distinct sessionIds (uuidv4)", async () => {
    const res1 = await post(app, "/api/webauthn/attack/challenge-replay", {});
    const res2 = await post(app, "/api/webauthn/attack/challenge-replay", {});
    expect(res1.json.data.extra.vulnerableSessionId).not.toBe(res2.json.data.extra.vulnerableSessionId);
    expect(res1.json.data.extra.defendedSessionId).not.toBe(res2.json.data.extra.defendedSessionId);
  });
});

// ── E-1 / E-2 invariants across all fido2 scenarios ──────────────────────────
describe("E-1 / E-2 invariants across all fido2 scenarios", () => {
  it.each([
    ["phishing-origin"],
    ["vs-password-phishing"],
    ["challenge-replay"],
  ] as const)(
    "webauthn/%s: outcome=succeeded, 5 steps, _trace.attackSteps matches steps; extra defined",
    async (suffix) => {
      const res = await post(app, `/api/webauthn/attack/${suffix}`, {});
      expect(res.status).toBe(200);
      expect(res.json.data.outcome).toBe("succeeded");
      expect(res.json.data.steps).toHaveLength(5);
      expect(res.json._trace.attackSteps).toHaveLength(5);
      expect(res.json.data.extra).toBeDefined();
    },
  );

  it("all 3 scenarios produce attack_log rows with unique logIds", async () => {
    const suffixes = ["phishing-origin", "vs-password-phishing", "challenge-replay"] as const;
    const logIds: number[] = [];
    for (const suffix of suffixes) {
      const res = await post(app, `/api/webauthn/attack/${suffix}`, {});
      expect(res.json.data.logId).toBeGreaterThan(0);
      logIds.push(res.json.data.logId as number);
    }
    expect(new Set(logIds).size).toBe(3);
  });

  it("all 3 scenarios have blockedBy set to a non-empty snake_case string", async () => {
    const suffixes = ["phishing-origin", "vs-password-phishing", "challenge-replay"] as const;
    for (const suffix of suffixes) {
      const res = await post(app, `/api/webauthn/attack/${suffix}`, {});
      expect(typeof res.json.data.blockedBy).toBe("string");
      expect(res.json.data.blockedBy).toMatch(/^[a-z][a-z0-9_]+$/);
    }
  });

  it("step 4 is exploit and step 5 is verify across all scenarios", async () => {
    const suffixes = ["phishing-origin", "vs-password-phishing", "challenge-replay"] as const;
    for (const suffix of suffixes) {
      const res = await post(app, `/api/webauthn/attack/${suffix}`, {});
      const steps = res.json.data.steps;
      expect(steps[3].kind).toBe("exploit");
      expect(steps[4].kind).toBe("verify");
      expect(steps[4].status).toBe("blocked");
    }
  });

  it("summaryJa starts with 'この実装は' or 'このシナリオでは' across all scenarios", async () => {
    const suffixes = ["phishing-origin", "vs-password-phishing", "challenge-replay"] as const;
    for (const suffix of suffixes) {
      const res = await post(app, `/api/webauthn/attack/${suffix}`, {});
      const summaryJa: string = res.json.data.summaryJa ?? "";
      const startsWithExpected =
        summaryJa.startsWith("この実装は") || summaryJa.startsWith("このシナリオでは");
      expect(
        startsWithExpected,
        `summaryJa for webauthn/${suffix} should start with 'この実装は' or 'このシナリオでは', got: "${summaryJa.substring(0, 30)}"`
      ).toBe(true);
    }
  });

  it("all 3 scenarios have victimSeedFound=true (seeded DB)", async () => {
    const suffixes = ["phishing-origin", "vs-password-phishing", "challenge-replay"] as const;
    for (const suffix of suffixes) {
      const res = await post(app, `/api/webauthn/attack/${suffix}`, {});
      expect(res.json.data.extra.victimSeedFound).toBe(true);
    }
  });
});

// ── Production guard ──────────────────────────────────────────────────────────
describe("Production guard for fido2 attack routes", () => {
  it.each([
    ["phishing-origin"],
    ["vs-password-phishing"],
    ["challenge-replay"],
  ] as const)("webauthn/%s returns 403 when NODE_ENV=production", async (suffix) => {
    const orig = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    try {
      const res = await post(app, `/api/webauthn/attack/${suffix}`, {});
      expect(res.status).toBe(403);
      expect(res.json.success).toBe(false);
      expect(res.json.error).toContain("disabled in production");
    } finally {
      process.env.NODE_ENV = orig;
    }
  });
});
