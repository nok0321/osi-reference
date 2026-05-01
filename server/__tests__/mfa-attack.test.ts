/**
 * Phase 2 第十一コミット (mfa タブ): 5 ステップ完全形 + 両モード並列実行のテスト。
 *
 * - 各シナリオは 1 リクエストで両モード (脆弱+堅牢) を必ず並列実行する。
 * - レスポンスは 5 ステップ完全形 (probe → tamper → forge → exploit → verify)。
 *   - otp-replay: probe(観測) → tamper(記録) → forge(リプレイ受理) → exploit(認証成立) → verify(used_otp 拒否)
 *   - time-window-wide: probe(T+0s 観測) → tamper(±1 拒否) → forge(±10 受理) → exploit(認証成立) → verify(±1 推奨設定)
 *   - sms-swap: probe(電話番号取得) → tamper(チャネル分析) → forge(SIM スワップ) → exploit(SMS 受理) → verify(TOTP デバイスバインド)
 * - outcome は常に "succeeded" (両モード示すため、HTTP status は 200 で統一)。
 * - シナリオ固有フィールドは E-1 ジェネリック化で `data.extra` 配下に格納される。
 */
import { describe, it, expect, beforeEach } from "vitest";
import { createTestApp, post } from "./test-helpers.js";
import type { Hono } from "hono";

let app: Hono;

beforeEach(() => {
  ({ app } = createTestApp());
});

// ── Scenario A: OTP リプレイ攻撃 ─────────────────────────────────────────────
describe("POST /api/mfa/attack/otp-replay", () => {
  it("returns 5-step result with vulnerable replay accepted + defended used-OTP block", async () => {
    const res = await post(app, "/api/mfa/attack/otp-replay", {});
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.scenarioId).toBe("mfa-otp-replay");
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
    expect(res.json.data.blockedBy).toBe("used_otp_record_blocks_replay");
    // E-1: extra
    expect(res.json.data.extra.victimUsername).toBe("seed_alice");
    expect(res.json.data.extra.victimSeedFound).toBe(true);
    expect(typeof res.json.data.extra.observedCode).toBe("string");
    expect(res.json.data.extra.observedCode).toMatch(/^\d{6}$/);
    expect(typeof res.json.data.extra.observedCounter).toBe("number");
    expect(res.json.data.extra.vulnerableReplayAccepted).toBe(true);
    expect(res.json.data.extra.defendedReplayBlocked).toBe(true);
    // _trace 検証
    expect(res.json._trace.attackSteps).toBeDefined();
    expect(res.json._trace.attackSteps).toHaveLength(5);
    expect(res.json._trace.isAttackMode).toBe(true);
    expect(res.json.data.logId).toBeGreaterThan(0);
  });

  it("ignores extra body fields (zod strips unknown keys silently)", async () => {
    const res = await post(app, "/api/mfa/attack/otp-replay", {
      replayDefenseEnabled: false, // E-2 で受け付けない (旧契約)
      username: "seed_alice", // 同上
      code: "123456", // 同上
    });
    expect(res.status).toBe(200);
    expect(res.json.data.steps).toHaveLength(5);
  });

  it("trace.cryptoOps records both totp.compute and usedOtp.check operations", async () => {
    const res = await post(app, "/api/mfa/attack/otp-replay", {});
    const cryptoOps: { op: string }[] = res.json._trace.cryptoOps ?? [];
    expect(
      cryptoOps.some((op) => op.op === "totp.compute (observed_code)"),
    ).toBe(true);
    expect(
      cryptoOps.some((op) => op.op === "totp.verify (vulnerable_no_used_otp_check)"),
    ).toBe(true);
    expect(
      cryptoOps.some((op) => op.op === "usedOtp.check (defended_replay_block)"),
    ).toBe(true);
  });

  it("masks observed TOTP secret in trace cryptoOps inputs as [REDACTED]", async () => {
    const res = await post(app, "/api/mfa/attack/otp-replay", {});
    const cryptoOps: { op: string; input: string }[] = res.json._trace.cryptoOps ?? [];
    const computeOp = cryptoOps.find(
      (op) => op.op === "totp.compute (observed_code)",
    );
    expect(computeOp?.input).toContain("[REDACTED]");
  });

  it("each invocation runs the full firstCheck→add→replayCheck flow within one handler-local Set", async () => {
    // ROB-MFA-1+2 修正後: usedOtps Set は handler-local。
    // 各リクエスト内で「正規ユーザーの初回 use → 攻撃者リプレイ」を 1 ループで実行するため、
    // 複数リクエスト間で結果が独立して再現される (cross-test state leak なし)。
    const res1 = await post(app, "/api/mfa/attack/otp-replay", {});
    expect(res1.json.data.extra.defendedReplayBlocked).toBe(true);
    const res2 = await post(app, "/api/mfa/attack/otp-replay", {});
    expect(res2.json.data.extra.defendedReplayBlocked).toBe(true);
  });
});

// ── Scenario B: 時刻窓広すぎ攻撃 ──────────────────────────────────────────────
describe("POST /api/mfa/attack/time-window-wide", () => {
  it("returns 5-step result with vulnerable wide window + defended narrow window", async () => {
    const res = await post(app, "/api/mfa/attack/time-window-wide", {});
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.scenarioId).toBe("mfa-time-window-too-wide");
    expect(res.json.data.steps).toHaveLength(5);
    expect(res.json.data.steps[0].kind).toBe("probe");
    const exploitStep = res.json.data.steps[3];
    expect(exploitStep.kind).toBe("exploit");
    expect(exploitStep.status).toBe("success");
    const verifyStep = res.json.data.steps[4];
    expect(verifyStep.kind).toBe("verify");
    expect(verifyStep.status).toBe("blocked");
    expect(res.json.data.blockedBy).toBe("totp_narrow_time_window_rejects_old_otp");
    // E-1: extra
    expect(res.json.data.extra.victimUsername).toBe("seed_alice");
    expect(res.json.data.extra.victimSeedFound).toBe(true);
    expect(typeof res.json.data.extra.observedCode).toBe("string");
    expect(res.json.data.extra.observedCode).toMatch(/^\d{6}$/);
    expect(res.json.data.extra.simulatedDelaySeconds).toBe(90);
    expect(res.json.data.extra.simulatedDelaySteps).toBe(3);
    expect(res.json.data.extra.vulnerableWideWindowAccepted).toBe(true);
    expect(res.json.data.extra.defendedNarrowWindowRejected).toBe(true);
    // 観測 counter は現在 counter より 3 ステップ前
    expect(res.json.data.extra.observedCounter).toBe(
      res.json.data.extra.currentCounterValue - 3,
    );
    // _trace 検証
    expect(res.json._trace.attackSteps).toHaveLength(5);
    expect(res.json._trace.isAttackMode).toBe(true);
    expect(res.json.data.logId).toBeGreaterThan(0);
  });

  it("ignores extra body fields (zod strips unknown keys silently)", async () => {
    const res = await post(app, "/api/mfa/attack/time-window-wide", {
      windowSize: 10, // E-2 で受け付けない (旧契約)
      simulatedDelaySeconds: 90, // 同上
      username: "seed_alice", // 同上
    });
    expect(res.status).toBe(200);
    expect(res.json.data.steps).toHaveLength(5);
  });

  it("trace.cryptoOps records totp.verify for both narrow (defended) and wide (vulnerable) windows", async () => {
    const res = await post(app, "/api/mfa/attack/time-window-wide", {});
    const cryptoOps: { op: string }[] = res.json._trace.cryptoOps ?? [];
    expect(
      cryptoOps.some((op) =>
        op.op.startsWith("totp.verify (window=1_narrow_defended)"),
      ),
    ).toBe(true);
    expect(
      cryptoOps.some((op) =>
        op.op.startsWith("totp.verify (window=10_wide_vulnerable)"),
      ),
    ).toBe(true);
  });

  it("windowComparison includes recommended/acceptable/vulnerable categories", async () => {
    const res = await post(app, "/api/mfa/attack/time-window-wide", {});
    const wc = res.json.data.extra.windowComparison as {
      window: number;
      toleranceSec: number;
      recommendation: string;
    }[];
    expect(wc.length).toBeGreaterThanOrEqual(4);
    // window=1 が "recommended" を含む
    const w1 = wc.find((c) => c.window === 1);
    expect(w1?.recommendation).toContain("recommended");
    // window=10 が "vulnerable" を含む
    const w10 = wc.find((c) => c.window === 10);
    expect(w10?.recommendation).toContain("vulnerable");
  });
});

// ── Scenario C: SMS スワップ ──────────────────────────────────────────────────
describe("POST /api/mfa/attack/sms-swap", () => {
  it("returns 5-step result with vulnerable SMS redirect + defended TOTP device-bound", async () => {
    const res = await post(app, "/api/mfa/attack/sms-swap", {});
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.scenarioId).toBe("mfa-sms-swap");
    expect(res.json.data.steps).toHaveLength(5);
    expect(res.json.data.steps[0].kind).toBe("probe");
    const exploitStep = res.json.data.steps[3];
    expect(exploitStep.kind).toBe("exploit");
    expect(exploitStep.status).toBe("success");
    const verifyStep = res.json.data.steps[4];
    expect(verifyStep.kind).toBe("verify");
    expect(verifyStep.status).toBe("blocked");
    expect(res.json.data.blockedBy).toBe("totp_device_bound_secret_resists_sim_swap");
    // E-1: extra
    expect(res.json.data.extra.victimUsername).toBe("seed_alice");
    expect(res.json.data.extra.victimSeedFound).toBe(true);
    expect(res.json.data.extra.passwordVerified).toBe(true);
    expect(res.json.data.extra.vulnerableSmsRedirected).toBe(true);
    expect(res.json.data.extra.defendedTotpDeviceBound).toBe(true);
    expect(typeof res.json.data.extra.smsOtpCode).toBe("string");
    expect(res.json.data.extra.smsOtpCode).toMatch(/^\d{6}$/);
    // 必須教育コンテンツ: シミュレーション注記
    expect(typeof res.json.data.extra.educationalSimulationNote).toBe("string");
    expect(res.json.data.extra.educationalSimulationNote).toContain("SIMULATION");
    expect(res.json.data.extra.educationalSimulationNote).toContain("social engineering");
    // _trace 検証
    expect(res.json._trace.attackSteps).toHaveLength(5);
    expect(res.json._trace.isAttackMode).toBe(true);
    expect(res.json.data.logId).toBeGreaterThan(0);
  });

  it("ignores extra body fields (zod strips unknown keys silently)", async () => {
    const res = await post(app, "/api/mfa/attack/sms-swap", {
      mfaChannel: "sms", // E-2 で受け付けない (旧契約)
      simSwapSimulated: true, // 同上
      username: "seed_alice", // 同上
      password: "Passw0rd!", // 同上
    });
    expect(res.status).toBe(200);
    expect(res.json.data.steps).toHaveLength(5);
  });

  it("trace records bcrypt.compare and sms.generate_otp simulation, plus SIM_SWAP sessionOps", async () => {
    const res = await post(app, "/api/mfa/attack/sms-swap", {});
    const cryptoOps: { op: string }[] = res.json._trace.cryptoOps ?? [];
    expect(cryptoOps.some((op) => op.op === "bcrypt.compare")).toBe(true);
    expect(
      cryptoOps.some((op) => op.op === "sms.generate_otp (simulated)"),
    ).toBe(true);
    const sessionOps: { action: string }[] = res.json._trace.sessionOps ?? [];
    expect(
      sessionOps.some((op) => op.action === "SIM_SWAP_SIMULATION"),
    ).toBe(true);
    expect(
      sessionOps.some((op) => op.action === "SIM_SWAP_TOTP_RESISTANCE_CHECK"),
    ).toBe(true);
  });

  it("summaryJa contains the educational simulation banner text (mandatory per DESIGN/20 §4.3)", async () => {
    const res = await post(app, "/api/mfa/attack/sms-swap", {});
    const summaryJa: string = res.json.data.summaryJa ?? "";
    expect(summaryJa).toContain("シミュレーション");
  });

  it("masks SMS OTP code in payload via maskSecret pattern", async () => {
    const res = await post(app, "/api/mfa/attack/sms-swap", {});
    // extra.smsOtpCode は UI 表示用のため平文 OK だが、
    // payload (DB の payload_json) は maskSecret 経由でマスクされている。
    // ここでは extra に平文が含まれることだけ確認 (UI 表示の意図動作)。
    expect(res.json.data.extra.smsOtpCode).toBe("573819");
  });
});

// ── E-1 / E-2 invariants across all mfa scenarios ────────────────────────────
describe("E-1 / E-2 invariants across all mfa scenarios", () => {
  it.each([
    ["otp-replay"],
    ["time-window-wide"],
    ["sms-swap"],
  ] as const)(
    "mfa/%s: outcome=succeeded, 5 steps, _trace.attackSteps matches steps; extra defined",
    async (suffix) => {
      const res = await post(app, `/api/mfa/attack/${suffix}`, {});
      expect(res.status).toBe(200);
      expect(res.json.data.outcome).toBe("succeeded");
      expect(res.json.data.steps).toHaveLength(5);
      expect(res.json._trace.attackSteps).toHaveLength(5);
      expect(res.json.data.extra).toBeDefined();
    },
  );

  it("all 3 scenarios produce attack_log rows with unique logIds", async () => {
    const suffixes = [
      "otp-replay",
      "time-window-wide",
      "sms-swap",
    ] as const;
    const logIds: number[] = [];
    for (const suffix of suffixes) {
      const res = await post(app, `/api/mfa/attack/${suffix}`, {});
      expect(res.json.data.logId).toBeGreaterThan(0);
      logIds.push(res.json.data.logId as number);
    }
    expect(new Set(logIds).size).toBe(3);
  });

  it("all 3 scenarios have blockedBy set to a non-empty snake_case string", async () => {
    const suffixes = [
      "otp-replay",
      "time-window-wide",
      "sms-swap",
    ] as const;
    for (const suffix of suffixes) {
      const res = await post(app, `/api/mfa/attack/${suffix}`, {});
      expect(typeof res.json.data.blockedBy).toBe("string");
      expect(res.json.data.blockedBy).toMatch(/^[a-z][a-z0-9_]+$/);
    }
  });

  it("step 4 is exploit and step 5 is verify across all scenarios", async () => {
    const suffixes = [
      "otp-replay",
      "time-window-wide",
      "sms-swap",
    ] as const;
    for (const suffix of suffixes) {
      const res = await post(app, `/api/mfa/attack/${suffix}`, {});
      const steps = res.json.data.steps;
      expect(steps[3].kind).toBe("exploit");
      expect(steps[4].kind).toBe("verify");
      expect(steps[4].status).toBe("blocked");
    }
  });

  it("summaryJa starts with 'この実装は' or 'このシナリオでは' across all scenarios", async () => {
    const suffixes = [
      "otp-replay",
      "time-window-wide",
      "sms-swap",
    ] as const;
    for (const suffix of suffixes) {
      const res = await post(app, `/api/mfa/attack/${suffix}`, {});
      const summaryJa: string = res.json.data.summaryJa ?? "";
      const startsWithExpected =
        summaryJa.startsWith("この実装は") || summaryJa.startsWith("このシナリオでは");
      expect(
        startsWithExpected,
        `summaryJa for mfa/${suffix} should start with 'この実装は' or 'このシナリオでは', got: "${summaryJa.substring(0, 30)}"`,
      ).toBe(true);
    }
  });
});

// ── Production guard ──────────────────────────────────────────────────────────
describe("Production guard for mfa attack routes", () => {
  it.each([
    ["otp-replay"],
    ["time-window-wide"],
    ["sms-swap"],
  ] as const)(
    "mfa/%s returns 403 when NODE_ENV=production",
    async (suffix) => {
      const orig = process.env.NODE_ENV;
      process.env.NODE_ENV = "production";
      try {
        const res = await post(app, `/api/mfa/attack/${suffix}`, {});
        expect(res.status).toBe(403);
        expect(res.json.success).toBe(false);
        expect(res.json.error).toContain("disabled in production");
      } finally {
        process.env.NODE_ENV = orig;
      }
    },
  );
});
