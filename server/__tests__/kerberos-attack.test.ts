/**
 * Phase 2 第八コミット (kerberos タブ): 5 ステップ完全形 + 両モード並列実行のテスト。
 *
 * - 各シナリオは 1 リクエストで両モード (脆弱+堅牢) を必ず並列実行する。
 * - レスポンスは 5 ステップ完全形 (probe → tamper → forge → exploit → verify)。
 *   ステップ 4 (exploit) = 脆弱モード結果 (status: "success" または "failed")
 *   ステップ 5 (verify)  = 堅牢モード結果 (status: "blocked")
 * - outcome は常に "succeeded" (両モード示すため、HTTP status は 200 で統一)。
 * - シナリオ固有フィールドは E-1 ジェネリック化で `data.extra` 配下に格納される:
 *   - kerberos-pass-the-ticket: extra.victimPrincipal / capturedTicketEncryptedPreview /
 *     vulnerableReplayAccepted / defendedReplayBlocked / victimSeedFound /
 *     attackTicketInsertError / attackTicketInserted
 *   - kerberos-kerberoasting (ROB-KERB-1 修正後): 1 リクエストで弱 SPN (脆弱) と 強 SPN (堅牢)
 *     の両方を並列実行する。extra.weakCrackedAtIndex / weakCrackedPasswordMasked /
 *     strongCrackedAtIndex / strongDictionaryExhaustedNoMatch /
 *     weakIsKerberoastResistant / strongIsKerberoastResistant
 *   - kerberos-golden-ticket: extra.forgedPrincipal / forgedTgtEncryptedPreview /
 *     vulnerableServiceTicketIssued / defendedRotationDetected / forgedTgtInserted /
 *     vulnerableDecryptError
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

// ── Scenario A: Pass-the-Ticket ───────────────────────────────────────────────
describe("POST /api/kerberos/attack/pass-the-ticket", () => {
  it("returns 5-step result with vulnerable replay + Authenticator nonce block", async () => {
    const res = await post(app, "/api/kerberos/attack/pass-the-ticket", {});
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.scenarioId).toBe("kerberos-pass-the-ticket");
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
    expect(res.json.data.blockedBy).toBe(
      "kerberos_authenticator_nonce_replay_cache_enforced",
    );
    // E-1: extra
    expect(res.json.data.extra.victimPrincipal).toBe("seed_alice@OSI-DEMO.LOCAL");
    expect(res.json.data.extra.servicePrincipal).toBe("http/web-server@OSI-DEMO.LOCAL");
    expect(typeof res.json.data.extra.capturedTicketEncryptedPreview).toBe("string");
    expect(res.json.data.extra.capturedTicketEncryptedPreview).toContain("...");
    expect(res.json.data.extra.vulnerableReplayAccepted).toBe(true);
    expect(res.json.data.extra.defendedReplayBlocked).toBe(true);
    expect(res.json.data.extra.victimSeedFound).toBe(true);
    expect(res.json.data.extra.attackTicketInsertError).toBeNull();
    expect(res.json.data.extra.attackTicketInserted).toBe(true);
    // _trace 検証
    expect(res.json._trace.attackSteps).toBeDefined();
    expect(res.json._trace.attackSteps).toHaveLength(5);
    expect(res.json._trace.isAttackMode).toBe(true);
    expect(res.json.data.logId).toBeGreaterThan(0);
  });

  it("ignores extra body fields (zod strips unknown keys silently)", async () => {
    const res = await post(app, "/api/kerberos/attack/pass-the-ticket", {
      legacyMode: "vulnerable",
      anotherField: 123,
    });
    expect(res.status).toBe(200);
    expect(res.json.data.steps).toHaveLength(5);
  });

  it("two consecutive calls produce distinct capturedTicketEncryptedPreview (random IV)", async () => {
    const res1 = await post(app, "/api/kerberos/attack/pass-the-ticket", {});
    const res2 = await post(app, "/api/kerberos/attack/pass-the-ticket", {});
    expect(res1.json.data.extra.capturedTicketEncryptedPreview).not.toBe(
      res2.json.data.extra.capturedTicketEncryptedPreview,
    );
  });

  it("cleans up is_attack_sim=1 ticket rows after handler completes (SEC-FIDO2-2)", async () => {
    await post(app, "/api/kerberos/attack/pass-the-ticket", {});
    // 痕跡削除パターン: handler 末尾で DELETE しているため累積しない
    const cnt = db
      .prepare("SELECT COUNT(*) AS c FROM kerberos_tickets WHERE is_attack_sim = 1")
      .get() as { c: number };
    expect(cnt.c).toBe(0);
  });

  it("trace.sessionOps records createSession_pass_the_ticket_vulnerable", async () => {
    const res = await post(app, "/api/kerberos/attack/pass-the-ticket", {});
    const sessionOps: { action: string }[] = res.json._trace.sessionOps ?? [];
    expect(
      sessionOps.some((op) => op.action === "createSession_pass_the_ticket_vulnerable"),
    ).toBe(true);
  });
});

// ── Scenario B: Kerberoasting (ROB-KERB-1: 弱/強 SPN を 1 リクエストで並列実行) ──
describe("POST /api/kerberos/attack/kerberoasting", () => {
  it("returns 5-step result with weak SPN cracked AND strong SPN policy block (parallel)", async () => {
    const res = await post(app, "/api/kerberos/attack/kerberoasting", {});
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.scenarioId).toBe("kerberos-kerberoasting");
    expect(res.json.data.steps).toHaveLength(5);
    expect(res.json.data.steps[0].kind).toBe("probe");
    // ステップ 4 (exploit, 脆弱: 弱 SPN は解読成立) は status: "success"
    const exploitStep = res.json.data.steps[3];
    expect(exploitStep.kind).toBe("exploit");
    expect(exploitStep.status).toBe("success");
    // ステップ 5 (verify, 堅牢) は status: "blocked"
    const verifyStep = res.json.data.steps[4];
    expect(verifyStep.kind).toBe("verify");
    expect(verifyStep.status).toBe("blocked");
    expect(res.json.data.blockedBy).toBe(
      "kerberos_kerberoasting_strong_service_account_password_enforced",
    );
    // E-1 / E-2: 両 SPN の結果が並列で extra に格納される
    expect(res.json.data.extra.weakSpn).toBe("http/weak-service");
    expect(res.json.data.extra.strongSpn).toBe("http/strong-service");
    expect(res.json.data.extra.dictionarySize).toBe(20);
    // 弱 SPN: 辞書 7 番目 (index 6 = "service123") で一致
    expect(res.json.data.extra.weakCrackedAtIndex).toBe(6);
    expect(typeof res.json.data.extra.weakCrackedPasswordMasked).toBe("string");
    expect(res.json.data.extra.weakCrackedPasswordMasked).toMatch(/\(len=\d+\)/);
    expect(res.json.data.extra.weakIsKerberoastResistant).toBe(false);
    // 強 SPN: 辞書全件で一致なし、policy 合格
    expect(res.json.data.extra.strongCrackedAtIndex).toBeNull();
    expect(res.json.data.extra.strongDictionaryExhaustedNoMatch).toBe(true);
    expect(res.json.data.extra.strongIsKerberoastResistant).toBe(true);
    // _trace
    expect(res.json._trace.attackSteps).toHaveLength(5);
    expect(res.json._trace.isAttackMode).toBe(true);
    expect(res.json.data.logId).toBeGreaterThan(0);
  });

  it("ignores extra body fields (targetSpn was removed from schema)", async () => {
    // ROB-KERB-1 修正後: targetSpn を渡しても zod が silently strip する
    const res = await post(app, "/api/kerberos/attack/kerberoasting", {
      targetSpn: "http/weak-service",
      legacyMode: true,
    });
    expect(res.status).toBe(200);
    // 弱/強 両モード並列実行は変わらない
    expect(res.json.data.extra.weakCrackedAtIndex).toBe(6);
    expect(res.json.data.extra.strongCrackedAtIndex).toBeNull();
  });

  it("does NOT leak weak service password verbatim in response body", async () => {
    // SEC FINDING-5: 平文パスワードは payload / extra に出さず maskSecret 化
    const res = await post(app, "/api/kerberos/attack/kerberoasting", {});
    const fullStr = JSON.stringify(res.json);
    expect(fullStr).not.toContain("service123"); // 平文パスワード非露出
    expect(fullStr).toContain("***"); // マスク形式は存在
  });

  it("does NOT leak strong service password verbatim in response body", async () => {
    // SEC: 強パスワードも常に payload に出さない (length / カテゴリ情報のみ disclose 可)
    const res = await post(app, "/api/kerberos/attack/kerberoasting", {});
    const fullStr = JSON.stringify(res.json);
    expect(fullStr).not.toContain("xK9#mP2$vQ7@nR4!jL8z");
  });
});

// ── Scenario C: Golden Ticket ─────────────────────────────────────────────────
describe("POST /api/kerberos/attack/golden-ticket", () => {
  it("returns 5-step result with forged TGT accepted + krbtgt rotation block", async () => {
    const res = await post(app, "/api/kerberos/attack/golden-ticket", {});
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.scenarioId).toBe("kerberos-golden-ticket");
    expect(res.json.data.steps).toHaveLength(5);
    expect(res.json.data.steps[0].kind).toBe("probe");
    // ステップ 4 (exploit, 脆弱) は status: "success" — KDC が偽造 TGT を受理
    const exploitStep = res.json.data.steps[3];
    expect(exploitStep.kind).toBe("exploit");
    expect(exploitStep.status).toBe("success");
    // ステップ 5 (verify, 堅牢) は status: "blocked"
    const verifyStep = res.json.data.steps[4];
    expect(verifyStep.kind).toBe("verify");
    expect(verifyStep.status).toBe("blocked");
    expect(res.json.data.blockedBy).toBe(
      "kerberos_krbtgt_double_reset_and_pac_validation_enforced",
    );
    // E-1: extra
    expect(res.json.data.extra.forgedPrincipal).toBe("administrator@OSI-DEMO.LOCAL");
    expect(res.json.data.extra.servicePrincipal).toBe("http/web-server@OSI-DEMO.LOCAL");
    expect(typeof res.json.data.extra.forgedTgtEncryptedPreview).toBe("string");
    expect(res.json.data.extra.forgedTgtEncryptedPreview).toContain("...");
    expect(res.json.data.extra.forgedValidUntil).toBe("2030-12-31T23:59:59.000Z");
    expect(res.json.data.extra.vulnerableServiceTicketIssued).toBe(true);
    expect(res.json.data.extra.defendedRotationDetected).toBe(true);
    expect(res.json.data.extra.prerequisiteOmitted).toBe(true);
    expect(res.json.data.extra.forgedTgtInsertError).toBeNull();
    expect(res.json.data.extra.forgedTgtInserted).toBe(true);
    // ROB-KERB-3: 復号エラーは設計上常に null (KDC_SECRET 一致のため必ず復号成功)
    expect(res.json.data.extra.vulnerableDecryptError).toBeNull();
    // _trace
    expect(res.json._trace.attackSteps).toHaveLength(5);
    expect(res.json._trace.isAttackMode).toBe(true);
    expect(res.json.data.logId).toBeGreaterThan(0);
  });

  it("ignores extra body fields", async () => {
    const res = await post(app, "/api/kerberos/attack/golden-ticket", {
      forgedPrincipal: "ignored", // E-2 で受け付けない
    });
    expect(res.status).toBe(200);
    expect(res.json.data.steps).toHaveLength(5);
  });

  it("cleans up is_attack_sim=1 forged TGT row after handler completes (SEC-FIDO2-2)", async () => {
    await post(app, "/api/kerberos/attack/golden-ticket", {});
    // 痕跡削除パターン: 偽造 TGT 行は handler 末尾で DELETE される
    const cnt = db
      .prepare("SELECT COUNT(*) AS c FROM kerberos_tickets WHERE is_attack_sim = 1")
      .get() as { c: number };
    expect(cnt.c).toBe(0);
  });

  it("trace.cryptoOps records forgeGoldenTicket and decryptTGT(forged_TGT_accepted)", async () => {
    const res = await post(app, "/api/kerberos/attack/golden-ticket", {});
    const cryptoOps: { op: string }[] = res.json._trace.cryptoOps ?? [];
    expect(cryptoOps.some((op) => op.op === "forgeGoldenTicket(stolen_krbtgt)")).toBe(
      true,
    );
    expect(
      cryptoOps.some((op) => op.op === "decryptTGT(forged_TGT_accepted)"),
    ).toBe(true);
    expect(
      cryptoOps.some((op) => op.op === "verifyTGT(post_krbtgt_rotation)"),
    ).toBe(true);
  });
});

// ── E-1 / E-2 invariants across all kerberos scenarios ────────────────────────
describe("E-1 / E-2 invariants across all kerberos scenarios", () => {
  it.each([
    ["pass-the-ticket"],
    ["kerberoasting"],
    ["golden-ticket"],
  ] as const)(
    "kerberos/%s: outcome=succeeded, 5 steps, _trace.attackSteps matches steps; extra defined",
    async (suffix) => {
      const res = await post(app, `/api/kerberos/attack/${suffix}`, {});
      expect(res.status).toBe(200);
      expect(res.json.data.outcome).toBe("succeeded");
      expect(res.json.data.steps).toHaveLength(5);
      expect(res.json._trace.attackSteps).toHaveLength(5);
      expect(res.json.data.extra).toBeDefined();
    },
  );

  it("all 3 scenarios produce attack_log rows with unique logIds", async () => {
    const suffixes = ["pass-the-ticket", "kerberoasting", "golden-ticket"] as const;
    const logIds: number[] = [];
    for (const suffix of suffixes) {
      const res = await post(app, `/api/kerberos/attack/${suffix}`, {});
      expect(res.json.data.logId).toBeGreaterThan(0);
      logIds.push(res.json.data.logId as number);
    }
    expect(new Set(logIds).size).toBe(3);
  });

  it("all 3 scenarios have blockedBy set to a non-empty snake_case string", async () => {
    const suffixes = ["pass-the-ticket", "kerberoasting", "golden-ticket"] as const;
    for (const suffix of suffixes) {
      const res = await post(app, `/api/kerberos/attack/${suffix}`, {});
      expect(typeof res.json.data.blockedBy).toBe("string");
      expect(res.json.data.blockedBy).toMatch(/^[a-z][a-z0-9_]+$/);
    }
  });

  it("step 4 is exploit and step 5 is verify across all scenarios", async () => {
    const suffixes = ["pass-the-ticket", "kerberoasting", "golden-ticket"] as const;
    for (const suffix of suffixes) {
      const res = await post(app, `/api/kerberos/attack/${suffix}`, {});
      const steps = res.json.data.steps;
      expect(steps[3].kind).toBe("exploit");
      expect(steps[4].kind).toBe("verify");
      expect(steps[4].status).toBe("blocked");
    }
  });

  it("summaryJa starts with 'この実装は' or 'このシナリオでは' across all scenarios", async () => {
    const suffixes = ["pass-the-ticket", "kerberoasting", "golden-ticket"] as const;
    for (const suffix of suffixes) {
      const res = await post(app, `/api/kerberos/attack/${suffix}`, {});
      const summaryJa: string = res.json.data.summaryJa ?? "";
      const startsWithExpected =
        summaryJa.startsWith("この実装は") || summaryJa.startsWith("このシナリオでは");
      expect(
        startsWithExpected,
        `summaryJa for kerberos/${suffix} should start with 'この実装は' or 'このシナリオでは', got: "${summaryJa.substring(0, 30)}"`,
      ).toBe(true);
    }
  });
});

// ── Production guard ──────────────────────────────────────────────────────────
describe("Production guard for kerberos attack routes", () => {
  it.each([
    ["pass-the-ticket"],
    ["kerberoasting"],
    ["golden-ticket"],
  ] as const)("kerberos/%s returns 403 when NODE_ENV=production", async (suffix) => {
    const orig = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    try {
      const res = await post(app, `/api/kerberos/attack/${suffix}`, {});
      expect(res.status).toBe(403);
      expect(res.json.success).toBe(false);
      expect(res.json.error).toContain("disabled in production");
    } finally {
      process.env.NODE_ENV = orig;
    }
  });
});
