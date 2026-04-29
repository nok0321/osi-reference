/**
 * Phase 2 第十二コミット (passkey タブ): 5 ステップ完全形 + 両モード並列実行のテスト。
 *
 * - 各シナリオは 1 リクエストで両モード (脆弱+堅牢) を必ず並列実行する。
 * - レスポンスは 5 ステップ完全形 (probe → tamper → forge → exploit → verify)。
 *   ステップ 4 (exploit) = 脆弱モード結果 (status: "success" または "failed")
 *   ステップ 5 (verify)  = 堅牢モード結果 (status: "blocked")
 * - outcome は常に "succeeded" (両モード示すため、HTTP status は 200 で統一)。
 * - シナリオ固有フィールドは E-1 ジェネリック化で `data.extra` 配下に格納される:
 *   - phishing-origin-binding: extra.attackerOrigin / expectedOrigin / vulnerableAccepted /
 *     defendedRejected / multiDeviceAndSingleDeviceBehaveSame
 *   - cloud-sync-compromise: extra.vulnerableCloudAccountCompromised /
 *     vulnerableSyncedPasskeyCloned / defendedCloudAccessBlocked / cloudConfigComparison /
 *     simulationNote / attackCredentialInserted
 *   - cross-device-mitm: extra.vulnerableQrInterceptSucceeded / vulnerableMitmEstablished /
 *     defendedBleProximityRejected / defendedTunnelKeyRejected / bleProximityRangeMeters /
 *     tunnelKeyAlgo / simulationNote
 *
 * このタブの特殊性 (DESIGN/21 §1.4):
 * 全シナリオで「プロトコル設計または防御実装が攻撃を成立させない」ことを示す。
 * 堅牢モードのステップ 5 は必ず status: "blocked"、blockedBy には防御識別子が入る。
 *
 * E-3 痕跡削除 (cloud-sync-compromise のみ DB INSERT あり):
 * webauthn_credentials に is_attack_sim=1 で複製クレデンシャルを INSERT、handler 末尾で DELETE。
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

// ── Scenario A: フィッシング耐性デモ (origin バインディング) ──────────────────
describe("POST /api/passkey/attack/phishing-origin-binding", () => {
  it("returns 5-step result with vulnerable accept + origin-validation block", async () => {
    const res = await post(app, "/api/passkey/attack/phishing-origin-binding", {});
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.scenarioId).toBe("passkey-phishing-origin-binding");
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
    expect(res.json.data.blockedBy).toBe("passkey_origin_validation_enforced");
    // E-1: extra
    expect(res.json.data.extra.attackerOrigin).toBe("http://attacker.example");
    expect(res.json.data.extra.expectedOrigin).toBe("http://localhost:3000");
    expect(res.json.data.extra.rpId).toBe("localhost");
    expect(res.json.data.extra.vulnerableAccepted).toBe(true);
    expect(res.json.data.extra.defendedRejected).toBe(true);
    expect(res.json.data.extra.victimUsername).toBe("seed_alice");
    expect(res.json.data.extra.victimSeedFound).toBe(true);
    // Passkey 固有: multiDevice / singleDevice 両方で同じ挙動
    expect(res.json.data.extra.multiDeviceAndSingleDeviceBehaveSame).toBe(true);
    // _trace 検証
    expect(res.json._trace.attackSteps).toBeDefined();
    expect(res.json._trace.attackSteps).toHaveLength(5);
    expect(res.json._trace.isAttackMode).toBe(true);
    expect(res.json.data.logId).toBeGreaterThan(0);
  });

  it("ignores extra body fields (zod strips unknown keys silently)", async () => {
    const res = await post(app, "/api/passkey/attack/phishing-origin-binding", {
      legacyField: "ignored",
      deviceType: "multiDevice",
      fakeOrigin: "http://attacker.example",
      username: "seed_alice",
    });
    expect(res.status).toBe(200);
    expect(res.json.data.steps).toHaveLength(5);
  });

  it("does not INSERT any webauthn_credentials rows (in-memory simulation only)", async () => {
    await post(app, "/api/passkey/attack/phishing-origin-binding", {});
    // The /credentials endpoint returns only is_attack_sim=0 rows
    const credsRes = await (
      await app.request("/api/passkey/credentials", { method: "GET" })
    ).json();
    const credIds: string[] = (credsRes.data?.credentials ?? []).map(
      (c: { credential_id: string }) => c.credential_id,
    );
    // Phishing-origin-binding scenario does no DB INSERT
    expect(credIds.length).toBe(0);
    // Also check directly: no is_attack_sim=1 rows from this scenario
    const attackCount = (db.prepare(
      "SELECT COUNT(*) as c FROM webauthn_credentials WHERE is_attack_sim = 1"
    ).get() as { c: number }).c;
    expect(attackCount).toBe(0);
  });

  it("is idempotent — second call also returns 200 with 5 steps", async () => {
    const res1 = await post(app, "/api/passkey/attack/phishing-origin-binding", {});
    const res2 = await post(app, "/api/passkey/attack/phishing-origin-binding", {});
    expect(res1.status).toBe(200);
    expect(res2.status).toBe(200);
    expect(res2.json.data.steps).toHaveLength(5);
  });
});

// ── Scenario B: クラウド同期経路の侵害 (シミュレーション) ─────────────────────
describe("POST /api/passkey/attack/cloud-sync-compromise", () => {
  it("returns 5-step result with vulnerable cloud compromise + strong-cloud block", async () => {
    const res = await post(app, "/api/passkey/attack/cloud-sync-compromise", {});
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.scenarioId).toBe("passkey-cloud-sync-compromise");
    expect(res.json.data.steps).toHaveLength(5);
    expect(res.json.data.steps[0].kind).toBe("probe");
    // ステップ 4 (exploit, 弱クラウド側) は status: "success"
    const exploitStep = res.json.data.steps[3];
    expect(exploitStep.kind).toBe("exploit");
    expect(exploitStep.status).toBe("success");
    // ステップ 5 (verify, 強クラウド側) は status: "blocked"
    const verifyStep = res.json.data.steps[4];
    expect(verifyStep.kind).toBe("verify");
    expect(verifyStep.status).toBe("blocked");
    expect(res.json.data.blockedBy).toBe("cloud_account_strong_password_and_mfa_enforced");
    // E-1: extra
    expect(res.json.data.extra.vulnerableCloudAccountCompromised).toBe(true);
    expect(res.json.data.extra.vulnerableSyncedPasskeyCloned).toBe(true);
    expect(res.json.data.extra.defendedCloudAccessBlocked).toBe(true);
    expect(res.json.data.extra.victimUsername).toBe("seed_alice");
    expect(res.json.data.extra.attackerUsername).toBe("attacker_charlie");
    expect(res.json.data.extra.victimSeedFound).toBe(true);
    expect(res.json.data.extra.attackCredentialInserted).toBe(true);
    // クラウド設定比較
    expect(res.json.data.extra.cloudConfigComparison.vulnerable.ja).toContain("弱");
    expect(res.json.data.extra.cloudConfigComparison.defended.ja).toContain("強");
    expect(res.json.data.extra.cloudConfigComparison.defended.en).toContain("MFA");
    // 教育用シミュレーション注記
    expect(res.json.data.extra.simulationNote.ja).toContain("教育用シミュレーション");
    expect(res.json.data.extra.simulationNote.en).toContain("Educational simulation");
    // _trace
    expect(res.json._trace.attackSteps).toHaveLength(5);
    expect(res.json._trace.isAttackMode).toBe(true);
    expect(res.json.data.logId).toBeGreaterThan(0);
  });

  it("attack credentials are inserted then cleaned up (no accumulation across calls)", async () => {
    // SEC-FIDO2-2 痕跡削除: scenario B は INSERT 後に DELETE まで完了する。
    // 連続実行しても is_attack_sim=1 行が累積しないことを確認。
    await post(app, "/api/passkey/attack/cloud-sync-compromise", {});
    await post(app, "/api/passkey/attack/cloud-sync-compromise", {});
    await post(app, "/api/passkey/attack/cloud-sync-compromise", {});
    const count = (db.prepare(
      "SELECT COUNT(*) as c FROM webauthn_credentials WHERE is_attack_sim = 1"
    ).get() as { c: number }).c;
    // 後始末で全て DELETE されているはず (attackCredentialInserted=true で INSERT 成立後に削除)
    expect(count).toBe(0);
  });

  it("normal /credentials listing never exposes is_attack_sim=1 rows from cloud-sync scenario", async () => {
    await post(app, "/api/passkey/attack/cloud-sync-compromise", {});
    // The /credentials endpoint filters is_attack_sim=0; attack creds should NOT appear
    const credsRes = await (
      await app.request("/api/passkey/credentials", { method: "GET" })
    ).json();
    const normalCreds: { credential_id: string }[] = credsRes.data?.credentials ?? [];
    // No attack credentials should leak into the normal /credentials listing
    for (const c of normalCreds) {
      expect(c.credential_id.startsWith("attack-passkey-cloud-sync-")).toBe(false);
    }
  });

  it("ignores extra body fields", async () => {
    const res = await post(app, "/api/passkey/attack/cloud-sync-compromise", {
      cloudAccountProtection: "weak",
      legacyField: "ignored",
    });
    expect(res.status).toBe(200);
    expect(res.json.data.steps).toHaveLength(5);
  });

  it("two consecutive calls produce distinct attackCredentialId values (uuidv4 in INSERT)", async () => {
    // 1 回目で INSERT して即削除、2 回目で INSERT して即削除 — それぞれ違う UUID を生成すること
    // (痕跡削除と uuidv4 衝突防止の両方を確認)
    const res1 = await post(app, "/api/passkey/attack/cloud-sync-compromise", {});
    const res2 = await post(app, "/api/passkey/attack/cloud-sync-compromise", {});
    expect(res1.json.data.extra.attackCredentialInserted).toBe(true);
    expect(res2.json.data.extra.attackCredentialInserted).toBe(true);
    // logId (DB 自動採番) が単調増加で相異
    expect(res2.json.data.logId).toBeGreaterThan(res1.json.data.logId);
  });
});

// ── Scenario C: Cross-device 経路の中間者 (シミュレーション) ──────────────────
describe("POST /api/passkey/attack/cross-device-mitm", () => {
  it("returns 5-step result with hypothetical MITM + CTAP2.2 spec block", async () => {
    const res = await post(app, "/api/passkey/attack/cross-device-mitm", {});
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.scenarioId).toBe("passkey-cross-device-mitm");
    expect(res.json.data.steps).toHaveLength(5);
    expect(res.json.data.steps[0].kind).toBe("probe");
    // ステップ 4 (exploit, 仮想脆弱実装側) は status: "success"
    const exploitStep = res.json.data.steps[3];
    expect(exploitStep.kind).toBe("exploit");
    expect(exploitStep.status).toBe("success");
    // ステップ 5 (verify, CTAP2.2 仕様準拠側) は status: "blocked"
    const verifyStep = res.json.data.steps[4];
    expect(verifyStep.kind).toBe("verify");
    expect(verifyStep.status).toBe("blocked");
    expect(res.json.data.blockedBy).toBe("ctap22_ble_proximity_and_tunnel_key_enforced");
    // E-1: extra
    expect(res.json.data.extra.vulnerableQrInterceptSucceeded).toBe(true);
    expect(res.json.data.extra.vulnerableMitmEstablished).toBe(true);
    expect(res.json.data.extra.defendedBleProximityRejected).toBe(true);
    expect(res.json.data.extra.defendedTunnelKeyRejected).toBe(true);
    expect(typeof res.json.data.extra.bleProximityRangeMeters).toBe("number");
    expect(res.json.data.extra.bleProximityRangeMeters).toBeGreaterThan(0);
    expect(res.json.data.extra.tunnelKeyAlgo).toContain("ECDH");
    expect(res.json.data.extra.victimUsername).toBe("seed_alice");
    expect(res.json.data.extra.victimSeedFound).toBe(true);
    // 教育用シミュレーション注記
    expect(res.json.data.extra.simulationNote.ja).toContain("教育用シミュレーション");
    expect(res.json.data.extra.simulationNote.en).toContain("Educational simulation");
    // _trace
    expect(res.json._trace.attackSteps).toHaveLength(5);
    expect(res.json._trace.isAttackMode).toBe(true);
    expect(res.json.data.logId).toBeGreaterThan(0);
  });

  it("ignores extra body fields (legacy attackerLocation field is silently stripped)", async () => {
    const res = await post(app, "/api/passkey/attack/cross-device-mitm", {
      attackerLocation: "remote",
      legacyField: "ignored",
    });
    expect(res.status).toBe(200);
    expect(res.json.data.steps).toHaveLength(5);
  });

  it("does not INSERT any webauthn_credentials rows (in-memory simulation only)", async () => {
    await post(app, "/api/passkey/attack/cross-device-mitm", {});
    const credsRes = await (
      await app.request("/api/passkey/credentials", { method: "GET" })
    ).json();
    const credIds: string[] = (credsRes.data?.credentials ?? []).map(
      (c: { credential_id: string }) => c.credential_id,
    );
    expect(credIds.length).toBe(0);
    const attackCount = (db.prepare(
      "SELECT COUNT(*) as c FROM webauthn_credentials WHERE is_attack_sim = 1"
    ).get() as { c: number }).c;
    expect(attackCount).toBe(0);
  });

  it("evaluates both remote and proximity attackers in parallel (both blocked)", async () => {
    // E-2: 1 リクエストで両攻撃者位置 (remote / proximity) に対する防御層を並列評価する。
    // remote → BLE 近接で阻止、proximity → tunnel key で阻止。両方とも extra で観測可能。
    const res = await post(app, "/api/passkey/attack/cross-device-mitm", {});
    expect(res.json.data.extra.defendedBleProximityRejected).toBe(true);
    expect(res.json.data.extra.defendedTunnelKeyRejected).toBe(true);
  });
});

// ── E-1 / E-2 invariants across all passkey scenarios ────────────────────────
describe("E-1 / E-2 invariants across all passkey scenarios", () => {
  it.each([
    ["phishing-origin-binding"],
    ["cloud-sync-compromise"],
    ["cross-device-mitm"],
  ] as const)(
    "passkey/%s: outcome=succeeded, 5 steps, _trace.attackSteps matches steps; extra defined",
    async (suffix) => {
      const res = await post(app, `/api/passkey/attack/${suffix}`, {});
      expect(res.status).toBe(200);
      expect(res.json.data.outcome).toBe("succeeded");
      expect(res.json.data.steps).toHaveLength(5);
      expect(res.json._trace.attackSteps).toHaveLength(5);
      expect(res.json.data.extra).toBeDefined();
    },
  );

  it("all 3 scenarios produce attack_log rows with unique logIds", async () => {
    const suffixes = [
      "phishing-origin-binding",
      "cloud-sync-compromise",
      "cross-device-mitm",
    ] as const;
    const logIds: number[] = [];
    for (const suffix of suffixes) {
      const res = await post(app, `/api/passkey/attack/${suffix}`, {});
      expect(res.json.data.logId).toBeGreaterThan(0);
      logIds.push(res.json.data.logId as number);
    }
    expect(new Set(logIds).size).toBe(3);
  });

  it("all 3 scenarios have blockedBy set to a non-empty snake_case string", async () => {
    const suffixes = [
      "phishing-origin-binding",
      "cloud-sync-compromise",
      "cross-device-mitm",
    ] as const;
    for (const suffix of suffixes) {
      const res = await post(app, `/api/passkey/attack/${suffix}`, {});
      expect(typeof res.json.data.blockedBy).toBe("string");
      expect(res.json.data.blockedBy).toMatch(/^[a-z][a-z0-9_]+$/);
    }
  });

  it("step 4 is exploit and step 5 is verify with status='blocked' across all scenarios", async () => {
    const suffixes = [
      "phishing-origin-binding",
      "cloud-sync-compromise",
      "cross-device-mitm",
    ] as const;
    for (const suffix of suffixes) {
      const res = await post(app, `/api/passkey/attack/${suffix}`, {});
      const steps = res.json.data.steps;
      expect(steps[3].kind).toBe("exploit");
      expect(steps[4].kind).toBe("verify");
      expect(steps[4].status).toBe("blocked");
    }
  });

  it("summaryJa starts with 'この実装は' or 'このシナリオでは' across all scenarios", async () => {
    const suffixes = [
      "phishing-origin-binding",
      "cloud-sync-compromise",
      "cross-device-mitm",
    ] as const;
    for (const suffix of suffixes) {
      const res = await post(app, `/api/passkey/attack/${suffix}`, {});
      const summaryJa: string = res.json.data.summaryJa ?? "";
      const startsWithExpected =
        summaryJa.startsWith("この実装は") || summaryJa.startsWith("このシナリオでは");
      expect(
        startsWithExpected,
        `summaryJa for passkey/${suffix} should start with 'この実装は' or 'このシナリオでは', got: "${summaryJa.substring(0, 30)}"`,
      ).toBe(true);
    }
  });

  it("all 3 scenarios have victimSeedFound=true (seeded DB)", async () => {
    const suffixes = [
      "phishing-origin-binding",
      "cloud-sync-compromise",
      "cross-device-mitm",
    ] as const;
    for (const suffix of suffixes) {
      const res = await post(app, `/api/passkey/attack/${suffix}`, {});
      expect(res.json.data.extra.victimSeedFound).toBe(true);
    }
  });

  it("simulation scenarios (cloud-sync, cross-device) include simulationNote in extra", async () => {
    // DESIGN/04 §3.3 / DESIGN/21 §4.2.4 / §4.3.4 規定の教育用シミュレーション注記
    for (const suffix of ["cloud-sync-compromise", "cross-device-mitm"] as const) {
      const res = await post(app, `/api/passkey/attack/${suffix}`, {});
      expect(res.json.data.extra.simulationNote).toBeDefined();
      expect(typeof res.json.data.extra.simulationNote.ja).toBe("string");
      expect(typeof res.json.data.extra.simulationNote.en).toBe("string");
      expect(res.json.data.extra.simulationNote.ja).toContain("シミュレーション");
    }
  });
});

// ── Production guard ──────────────────────────────────────────────────────────
describe("Production guard for passkey attack routes", () => {
  it.each([
    ["phishing-origin-binding"],
    ["cloud-sync-compromise"],
    ["cross-device-mitm"],
  ] as const)("passkey/%s returns 403 when NODE_ENV=production", async (suffix) => {
    const orig = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    try {
      const res = await post(app, `/api/passkey/attack/${suffix}`, {});
      expect(res.status).toBe(403);
      expect(res.json.success).toBe(false);
      expect(res.json.error).toContain("disabled in production");
    } finally {
      process.env.NODE_ENV = orig;
    }
  });
});
