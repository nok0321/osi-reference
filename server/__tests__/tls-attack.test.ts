/**
 * Phase 2 第九コミット (tls タブ): 5 ステップ完全形 + 両モード並列実行のテスト。
 *
 * - 各シナリオは 1 リクエストで両モード (脆弱+堅牢) を必ず並列実行する。
 * - レスポンスは 5 ステップ完全形 (probe → tamper → forge → exploit → verify)。
 *   ステップ 4 (exploit) = 脆弱モード結果 (status: "success" または "failed")
 *   ステップ 5 (verify)  = 堅牢モード結果 (status: "blocked")
 * - outcome は常に "succeeded" (両モード示すため、HTTP status は 200 で統一)。
 * - シナリオ固有フィールドは E-1 ジェネリック化で `data.extra` 配下に格納される:
 *   - tls-version-downgrade: extra.clientOfferedVersionsOriginal / versionsAfterMitm /
 *     vulnerableNegotiatedVersion / vulnerableNegotiatedCipher / vulnerableAccepted /
 *     defendedRejected / defendedMinVersion / defendedAlert
 *   - tls-self-signed-mitm: extra.legitimateCert / fakeCert /
 *     vulnerableMitmEstablished / defendedCertRejected / defendedAlert
 *   - tls-weak-cipher-negotiation: extra.clientOfferedCiphersOriginal /
 *     clientCiphersAfterMitm / vulnerableServerCiphers / defendedServerCiphers /
 *     vulnerableNegotiatedCipher / vulnerableSessionEstablished /
 *     defendedHandshakeFailure / defendedAlert
 */
import { describe, it, expect, beforeEach } from "vitest";
import { createTestApp, post } from "./test-helpers.js";
import type { Hono } from "hono";

let app: Hono;

beforeEach(() => {
  ({ app } = createTestApp());
});

// ── Scenario A: Version Downgrade ─────────────────────────────────────────────
describe("POST /api/tls/attack/version-downgrade", () => {
  it("returns 5-step result with vulnerable TLS 1.0 acceptance + SCSV block", async () => {
    const res = await post(app, "/api/tls/attack/version-downgrade", {});
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.scenarioId).toBe("tls-version-downgrade");
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
      "tls_fallback_scsv_inappropriate_fallback_alert_enforced",
    );
    // E-1: extra
    expect(res.json.data.extra.clientOfferedVersionsOriginal).toEqual([
      "TLS 1.0",
      "TLS 1.1",
      "TLS 1.2",
      "TLS 1.3",
    ]);
    expect(res.json.data.extra.versionsAfterMitm).toEqual(["TLS 1.0"]);
    expect(res.json.data.extra.vulnerableNegotiatedVersion).toBe("TLS 1.0");
    expect(res.json.data.extra.vulnerableNegotiatedCipher).toBe(
      "TLS_RSA_WITH_RC4_128_MD5",
    );
    expect(res.json.data.extra.vulnerableAccepted).toBe(true);
    expect(res.json.data.extra.defendedRejected).toBe(true);
    expect(res.json.data.extra.defendedMinVersion).toBe("TLS 1.3");
    expect(res.json.data.extra.defendedAlert).toBe("inappropriate_fallback");
    // _trace 検証
    expect(res.json._trace.attackSteps).toBeDefined();
    expect(res.json._trace.attackSteps).toHaveLength(5);
    expect(res.json._trace.isAttackMode).toBe(true);
    expect(res.json.data.logId).toBeGreaterThan(0);
  });

  it("ignores extra body fields (zod strips unknown keys silently)", async () => {
    const res = await post(app, "/api/tls/attack/version-downgrade", {
      mitmEnabled: true, // E-2 で受け付けない (旧契約)
      fallbackScsvEnabled: true, // 同上
    });
    expect(res.status).toBe(200);
    expect(res.json.data.steps).toHaveLength(5);
  });

  it("trace.cryptoOps records both vulnerable_no_scsv_check and defended_rfc7507", async () => {
    const res = await post(app, "/api/tls/attack/version-downgrade", {});
    const cryptoOps: { op: string }[] = res.json._trace.cryptoOps ?? [];
    expect(
      cryptoOps.some((op) => op.op === "tls.negotiateVersion (vulnerable_no_scsv_check)"),
    ).toBe(true);
    expect(
      cryptoOps.some((op) => op.op === "tls.checkFallbackSCSV (defended_rfc7507)"),
    ).toBe(true);
  });
});

// ── Scenario B: Self-Signed MITM ──────────────────────────────────────────────
describe("POST /api/tls/attack/self-signed-mitm", () => {
  it("returns 5-step result with vulnerable cert acceptance + CA chain block", async () => {
    const res = await post(app, "/api/tls/attack/self-signed-mitm", {});
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.scenarioId).toBe("tls-self-signed-mitm");
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
      "tls_ca_chain_validation_certificate_unknown_alert_enforced",
    );
    // E-1: extra
    expect(res.json.data.extra.legitimateCert.subject).toBe(
      "CN=localhost, O=OSI Demo, C=JP",
    );
    expect(res.json.data.extra.legitimateCert.issuer).toBe(
      "CN=OSI Demo CA, O=OSI Demo, C=JP",
    );
    expect(res.json.data.extra.legitimateCert.selfSigned).toBe(false);
    expect(res.json.data.extra.fakeCert.subject).toBe("CN=localhost, O=Attacker Corp");
    expect(res.json.data.extra.fakeCert.issuer).toBe("CN=localhost, O=Attacker Corp");
    expect(res.json.data.extra.fakeCert.selfSigned).toBe(true);
    expect(typeof res.json.data.extra.legitimateCert.fingerprintPreview).toBe("string");
    expect(res.json.data.extra.legitimateCert.fingerprintPreview).toContain("...");
    expect(typeof res.json.data.extra.fakeCert.fingerprintPreview).toBe("string");
    expect(res.json.data.extra.fakeCert.fingerprintPreview).toContain("...");
    expect(res.json.data.extra.vulnerableMitmEstablished).toBe(true);
    expect(res.json.data.extra.defendedCertRejected).toBe(true);
    expect(res.json.data.extra.defendedAlert).toBe("certificate_unknown");
    // _trace 検証
    expect(res.json._trace.attackSteps).toHaveLength(5);
    expect(res.json._trace.isAttackMode).toBe(true);
    expect(res.json.data.logId).toBeGreaterThan(0);
  });

  it("ignores extra body fields (zod strips unknown keys silently)", async () => {
    const res = await post(app, "/api/tls/attack/self-signed-mitm", {
      certValidationEnabled: false, // E-2 で受け付けない (旧契約)
    });
    expect(res.status).toBe(200);
    expect(res.json.data.steps).toHaveLength(5);
  });

  it("two consecutive calls produce distinct fingerprints (random key generation)", async () => {
    const res1 = await post(app, "/api/tls/attack/self-signed-mitm", {});
    const res2 = await post(app, "/api/tls/attack/self-signed-mitm", {});
    expect(res1.json.data.extra.legitimateCert.fingerprintPreview).not.toBe(
      res2.json.data.extra.legitimateCert.fingerprintPreview,
    );
    expect(res1.json.data.extra.fakeCert.fingerprintPreview).not.toBe(
      res2.json.data.extra.fakeCert.fingerprintPreview,
    );
  });

  it("trace.cryptoOps records generateSelfSignedCert and certChainValidation in both modes", async () => {
    const res = await post(app, "/api/tls/attack/self-signed-mitm", {});
    const cryptoOps: { op: string }[] = res.json._trace.cryptoOps ?? [];
    expect(
      cryptoOps.some((op) => op.op === "generateRSAKeyPair(legitimate_server)"),
    ).toBe(true);
    expect(cryptoOps.some((op) => op.op === "generateSelfSignedCert(attacker)")).toBe(
      true,
    );
    expect(
      cryptoOps.some((op) => op.op === "certChainValidation (vulnerable_disabled)"),
    ).toBe(true);
    expect(
      cryptoOps.some((op) => op.op === "certChainValidation (defended_strict)"),
    ).toBe(true);
  });
});

// ── Scenario C: Weak Cipher ───────────────────────────────────────────────────
describe("POST /api/tls/attack/weak-cipher", () => {
  it("returns 5-step result with vulnerable RC4 negotiation + AEAD allowlist block", async () => {
    const res = await post(app, "/api/tls/attack/weak-cipher", {});
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.scenarioId).toBe("tls-weak-cipher-negotiation");
    expect(res.json.data.steps).toHaveLength(5);
    expect(res.json.data.steps[0].kind).toBe("probe");
    // ステップ 4 (exploit, 脆弱: RC4 で交渉成立) は status: "success"
    const exploitStep = res.json.data.steps[3];
    expect(exploitStep.kind).toBe("exploit");
    expect(exploitStep.status).toBe("success");
    // ステップ 5 (verify, 堅牢) は status: "blocked"
    const verifyStep = res.json.data.steps[4];
    expect(verifyStep.kind).toBe("verify");
    expect(verifyStep.status).toBe("blocked");
    expect(res.json.data.blockedBy).toBe(
      "tls_cipher_allowlist_handshake_failure_alert_enforced",
    );
    // E-1: extra
    expect(res.json.data.extra.clientOfferedCiphersOriginal).toEqual([
      "TLS_AES_256_GCM_SHA384",
      "TLS_AES_128_GCM_SHA256",
      "TLS_CHACHA20_POLY1305_SHA256",
    ]);
    expect(res.json.data.extra.clientCiphersAfterMitm).toEqual([
      "TLS_RSA_WITH_RC4_128_MD5",
    ]);
    expect(res.json.data.extra.vulnerableServerCiphers).toContain(
      "TLS_RSA_WITH_RC4_128_MD5",
    );
    expect(res.json.data.extra.defendedServerCiphers).not.toContain(
      "TLS_RSA_WITH_RC4_128_MD5",
    );
    expect(res.json.data.extra.vulnerableNegotiatedCipher).toBe(
      "TLS_RSA_WITH_RC4_128_MD5",
    );
    expect(res.json.data.extra.vulnerableSessionEstablished).toBe(true);
    expect(res.json.data.extra.defendedHandshakeFailure).toBe(true);
    expect(res.json.data.extra.defendedAlert).toBe("handshake_failure");
    // _trace 検証
    expect(res.json._trace.attackSteps).toHaveLength(5);
    expect(res.json._trace.isAttackMode).toBe(true);
    expect(res.json.data.logId).toBeGreaterThan(0);
  });

  it("ignores extra body fields (zod strips unknown keys silently)", async () => {
    const res = await post(app, "/api/tls/attack/weak-cipher", {
      mitmEnabled: true, // E-2 で受け付けない (旧契約)
      serverAllowWeakCiphers: true, // 同上
    });
    expect(res.status).toBe(200);
    expect(res.json.data.steps).toHaveLength(5);
  });

  it("trace.cryptoOps records both vulnerable_server_with_legacy_ciphers and defended_server_aead_allowlist", async () => {
    const res = await post(app, "/api/tls/attack/weak-cipher", {});
    const cryptoOps: { op: string }[] = res.json._trace.cryptoOps ?? [];
    expect(
      cryptoOps.some(
        (op) =>
          op.op === "cipherSuiteNegotiation (vulnerable_server_with_legacy_ciphers)",
      ),
    ).toBe(true);
    expect(
      cryptoOps.some(
        (op) => op.op === "cipherSuiteNegotiation (defended_server_aead_allowlist)",
      ),
    ).toBe(true);
  });
});

// ── E-1 / E-2 invariants across all tls scenarios ─────────────────────────────
describe("E-1 / E-2 invariants across all tls scenarios", () => {
  it.each([
    ["version-downgrade"],
    ["self-signed-mitm"],
    ["weak-cipher"],
  ] as const)(
    "tls/%s: outcome=succeeded, 5 steps, _trace.attackSteps matches steps; extra defined",
    async (suffix) => {
      const res = await post(app, `/api/tls/attack/${suffix}`, {});
      expect(res.status).toBe(200);
      expect(res.json.data.outcome).toBe("succeeded");
      expect(res.json.data.steps).toHaveLength(5);
      expect(res.json._trace.attackSteps).toHaveLength(5);
      expect(res.json.data.extra).toBeDefined();
    },
  );

  it("all 3 scenarios produce attack_log rows with unique logIds", async () => {
    const suffixes = ["version-downgrade", "self-signed-mitm", "weak-cipher"] as const;
    const logIds: number[] = [];
    for (const suffix of suffixes) {
      const res = await post(app, `/api/tls/attack/${suffix}`, {});
      expect(res.json.data.logId).toBeGreaterThan(0);
      logIds.push(res.json.data.logId as number);
    }
    expect(new Set(logIds).size).toBe(3);
  });

  it("all 3 scenarios have blockedBy set to a non-empty snake_case string", async () => {
    const suffixes = ["version-downgrade", "self-signed-mitm", "weak-cipher"] as const;
    for (const suffix of suffixes) {
      const res = await post(app, `/api/tls/attack/${suffix}`, {});
      expect(typeof res.json.data.blockedBy).toBe("string");
      expect(res.json.data.blockedBy).toMatch(/^[a-z][a-z0-9_]+$/);
    }
  });

  it("step 4 is exploit and step 5 is verify across all scenarios", async () => {
    const suffixes = ["version-downgrade", "self-signed-mitm", "weak-cipher"] as const;
    for (const suffix of suffixes) {
      const res = await post(app, `/api/tls/attack/${suffix}`, {});
      const steps = res.json.data.steps;
      expect(steps[3].kind).toBe("exploit");
      expect(steps[4].kind).toBe("verify");
      expect(steps[4].status).toBe("blocked");
    }
  });

  it("summaryJa starts with 'この実装は' or 'このシナリオでは' across all scenarios", async () => {
    const suffixes = ["version-downgrade", "self-signed-mitm", "weak-cipher"] as const;
    for (const suffix of suffixes) {
      const res = await post(app, `/api/tls/attack/${suffix}`, {});
      const summaryJa: string = res.json.data.summaryJa ?? "";
      const startsWithExpected =
        summaryJa.startsWith("この実装は") || summaryJa.startsWith("このシナリオでは");
      expect(
        startsWithExpected,
        `summaryJa for tls/${suffix} should start with 'この実装は' or 'このシナリオでは', got: "${summaryJa.substring(0, 30)}"`,
      ).toBe(true);
    }
  });
});

// ── Production guard ──────────────────────────────────────────────────────────
describe("Production guard for tls attack routes", () => {
  it.each([
    ["version-downgrade"],
    ["self-signed-mitm"],
    ["weak-cipher"],
  ] as const)("tls/%s returns 403 when NODE_ENV=production", async (suffix) => {
    const orig = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    try {
      const res = await post(app, `/api/tls/attack/${suffix}`, {});
      expect(res.status).toBe(403);
      expect(res.json.success).toBe(false);
      expect(res.json.error).toContain("disabled in production");
    } finally {
      process.env.NODE_ENV = orig;
    }
  });
});
