import { Hono } from "hono";
import crypto from "crypto";
import {
  parseBody,
  tlsSessionSchema,
  tlsAttackVersionDowngradeSchema,
  tlsAttackSelfSignedMitmSchema,
  tlsAttackWeakCipherSchema,
} from "../validation.js";
import { createTtlStore } from "../utils/ttl-store.js";
import { runAttackScenario } from "../utils/attack-runner.js";

export const tlsSimRoutes = new Hono();

/*
 * EDUCATIONAL SIMULATION — NOT a real TLS 1.3 implementation.
 *
 * Simplifications vs RFC 8446 (TLS 1.3):
 * - Key derivation: real TLS 1.3 uses HKDF-Extract / HKDF-Expand-Label (RFC 5869).
 *   This demo uses simplified HMAC-SHA384 calls to illustrate the concept.
 * - Certificate verification: real TLS verifies X.509 certificate chains against trusted CAs.
 *   This demo generates a self-signed cert for display only.
 * - Handshake transcript: real TLS 1.3 hashes all handshake messages into the key schedule.
 *   This demo uses only clientRandom + serverRandom.
 * - Encrypted Extensions / Finished messages: omitted.
 * - 0-RTT (early data): not simulated.
 * - AEAD encryption: the demo derives keys but never actually encrypts application data.
 */

interface HandshakeState {
  clientRandom: string;
  serverRandom: string;
  serverKeyPair: { publicKey: string; privateKey: string };
  clientPublicKey?: string;
  sharedSecret?: string;
  handshakeSecret?: string;
  masterSecret?: string;
}
const handshakes = createTtlStore<HandshakeState>({ ttlMs: 5 * 60 * 1000 });

// Step 1: ClientHello
tlsSimRoutes.post("/client-hello", async (c) => {
  const parsed = await parseBody(c, tlsSessionSchema);
  if ("error" in parsed) return parsed.error;
  const { sessionId } = parsed.data;
  const trace = c.get("trace");

  const clientRandom = crypto.randomBytes(32).toString("hex");
  trace.addCryptoOp({
    op: "generateClientRandom",
    input: "crypto.randomBytes(32)",
    output: clientRandom.substring(0, 32) + "...",
    algo: "CSPRNG",
    detail: "32 bytes of cryptographically secure random data",
  });

  // Client generates ECDHE key pair
  const clientECDH = crypto.createECDH("prime256v1");
  clientECDH.generateKeys();
  const clientPubKey = clientECDH.getPublicKey("hex");

  trace.addCryptoOp({
    op: "generateECDHKeyPair(client)",
    input: "curve=P-256 (prime256v1)",
    output: `publicKey=${clientPubKey.substring(0, 30)}...`,
    algo: "ECDHE P-256",
    detail: "Client generates ephemeral key pair for key exchange",
  });

  // Generate server ECDH key pair
  const serverECDH = crypto.createECDH("prime256v1");
  serverECDH.generateKeys();
  const serverRandom = crypto.randomBytes(32).toString("hex");

  handshakes.set(sessionId, {
    clientRandom,
    serverRandom,
    serverKeyPair: {
      publicKey: serverECDH.getPublicKey("hex"),
      privateKey: serverECDH.getPrivateKey("hex"),
    },
    clientPublicKey: clientPubKey,
  });

  return c.json({
    success: true,
    data: {
      step: "ClientHello",
      clientRandom,
      clientPublicKey: clientPubKey,
      supportedCipherSuites: [
        "TLS_AES_256_GCM_SHA384",
        "TLS_AES_128_GCM_SHA256",
        "TLS_CHACHA20_POLY1305_SHA256",
      ],
      supportedGroups: ["x25519", "secp256r1", "secp384r1"],
      signatureAlgorithms: ["ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256"],
      tlsVersion: "TLS 1.3",
    },
  });
});

// Step 2: ServerHello + Key Exchange
tlsSimRoutes.post("/server-hello", async (c) => {
  const parsed = await parseBody(c, tlsSessionSchema);
  if ("error" in parsed) return parsed.error;
  const { sessionId } = parsed.data;
  const trace = c.get("trace");

  const state = handshakes.get(sessionId);
  if (!state) {
    return c.json({ success: false, error: "No handshake in progress" }, 400);
  }

  trace.addCryptoOp({
    op: "generateServerRandom",
    input: "crypto.randomBytes(32)",
    output: state.serverRandom.substring(0, 32) + "...",
    algo: "CSPRNG",
  });

  trace.addCryptoOp({
    op: "selectCipherSuite",
    input: "Client offered: AES_256_GCM, AES_128_GCM, CHACHA20",
    output: "TLS_AES_256_GCM_SHA384",
    algo: "Server preference",
    detail: "Server selects strongest mutually supported cipher suite",
  });

  return c.json({
    success: true,
    data: {
      step: "ServerHello",
      serverRandom: state.serverRandom,
      serverPublicKey: state.serverKeyPair.publicKey,
      selectedCipherSuite: "TLS_AES_256_GCM_SHA384",
      selectedGroup: "secp256r1",
      tlsVersion: "TLS 1.3",
    },
  });
});

// Step 3: Key Exchange computation
tlsSimRoutes.post("/key-exchange", async (c) => {
  const parsed = await parseBody(c, tlsSessionSchema);
  if ("error" in parsed) return parsed.error;
  const { sessionId } = parsed.data;
  const trace = c.get("trace");

  const state = handshakes.get(sessionId);
  if (!state || !state.clientPublicKey) {
    return c.json({ success: false, error: "Missing handshake state" }, 400);
  }

  // Compute shared secret
  const serverECDH = crypto.createECDH("prime256v1");
  serverECDH.setPrivateKey(state.serverKeyPair.privateKey, "hex");
  const sharedSecret = serverECDH.computeSecret(Buffer.from(state.clientPublicKey, "hex")).toString("hex");

  trace.addCryptoOp({
    op: "ECDHE computeSharedSecret",
    input: `serverPrivKey × clientPubKey`,
    output: sharedSecret.substring(0, 32) + "...",
    algo: "ECDHE P-256",
    detail: "Both sides compute same shared secret: server_priv × client_pub = client_priv × server_pub",
  });

  // Derive handshake secret (simplified HKDF)
  const handshakeSecret = crypto.createHmac("sha384", sharedSecret)
    .update(`${state.clientRandom}${state.serverRandom}`)
    .digest("hex");

  trace.addCryptoOp({
    op: "HKDF-Extract(handshakeSecret)",
    input: `sharedSecret + clientRandom + serverRandom`,
    output: handshakeSecret.substring(0, 32) + "...",
    algo: "HMAC-SHA384 (simplified HKDF)",
    detail: "Derive handshake traffic keys from shared secret and random values",
  });

  // Derive master secret
  const masterSecret = crypto.createHmac("sha384", handshakeSecret)
    .update("master-secret-derivation")
    .digest("hex");

  trace.addCryptoOp({
    op: "HKDF-Expand(masterSecret)",
    input: `handshakeSecret → master secret derivation`,
    output: masterSecret.substring(0, 32) + "...",
    algo: "HMAC-SHA384 (simplified HKDF)",
    detail: "Final master secret for application data encryption",
  });

  // Update the handshake state with derived secrets
  handshakes.set(sessionId, { ...state, sharedSecret, handshakeSecret, masterSecret });

  return c.json({
    success: true,
    data: {
      step: "KeyExchange",
      sharedSecret: sharedSecret.substring(0, 32) + "...",
      handshakeSecret: handshakeSecret.substring(0, 32) + "...",
      masterSecret: masterSecret.substring(0, 32) + "...",
      explanation: {
        ecdhe: "Elliptic Curve Diffie-Hellman Ephemeral — both sides derive same secret without transmitting it",
        forwardSecrecy: "Ephemeral keys are discarded after handshake — past sessions cannot be decrypted even if long-term key is compromised",
      },
    },
  });
});

// Step 4: Generate self-signed certificate for demo
tlsSimRoutes.get("/certificate", (c) => {
  const trace = c.get("trace");

  // Generate a fresh self-signed certificate
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  trace.addCryptoOp({
    op: "generateRSAKeyPair",
    input: "modulusLength=2048",
    output: `publicKey=${publicKey.substring(27, 60)}...`,
    algo: "RSA-2048",
    detail: "Key pair for certificate signing (in production: from CA)",
  });

  return c.json({
    success: true,
    data: {
      certificate: {
        subject: "CN=localhost, O=OSI Demo, C=JP",
        issuer: "CN=OSI Demo CA, O=OSI Demo, C=JP",
        serialNumber: crypto.randomBytes(16).toString("hex"),
        validFrom: new Date().toISOString(),
        validTo: new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString(),
        signatureAlgorithm: "SHA256withRSA",
        publicKey: publicKey.split("\n").slice(1, -2).join("").substring(0, 60) + "...",
        fingerprint: crypto.createHash("sha256").update(publicKey).digest("hex").substring(0, 40) + "...",
      },
      publicKeyPem: publicKey,
      explanation: {
        chain: ["End-entity (localhost)", "Intermediate CA", "Root CA"],
        verification: "Browser verifies chain: end-entity → intermediate → trusted root",
      },
    },
  });
});

// Finish handshake
tlsSimRoutes.post("/finish", async (c) => {
  const parsed = await parseBody(c, tlsSessionSchema);
  if ("error" in parsed) return parsed.error;
  const { sessionId } = parsed.data;
  const trace = c.get("trace");

  const state = handshakes.get(sessionId);
  if (!state?.masterSecret) {
    return c.json({ success: false, error: "Handshake not complete" }, 400);
  }

  // Derive application keys
  const clientWriteKey = crypto.createHmac("sha256", state.masterSecret)
    .update("client-write-key").digest("hex");
  const serverWriteKey = crypto.createHmac("sha256", state.masterSecret)
    .update("server-write-key").digest("hex");

  trace.addCryptoOp({
    op: "deriveApplicationKeys",
    input: `masterSecret → client/server write keys`,
    output: `clientKey=${clientWriteKey.substring(0, 16)}... serverKey=${serverWriteKey.substring(0, 16)}...`,
    algo: "HKDF-SHA256",
    detail: "Separate keys for client→server and server→client encryption",
  });

  // Cleanup
  handshakes.delete(sessionId);

  return c.json({
    success: true,
    data: {
      step: "Finished",
      clientWriteKey: clientWriteKey.substring(0, 32) + "...",
      serverWriteKey: serverWriteKey.substring(0, 32) + "...",
      message: "✓ TLS 1.3 handshake complete — application data is now encrypted",
      cipherSuite: "TLS_AES_256_GCM_SHA384",
    },
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// TLS 攻撃シナリオ (DESIGN/18-attack-tls.md 実装)
//
// 教育用シミュレーション — 実 TLS スタック (OpenSSL/BoringSSL) と異なり、本デモは
// バージョン交渉・暗号スイート選択・証明書検証を「概念モデル」で表現する。
// 本ファイル冒頭の注記を継承する。
//
// 攻撃ルートは必ず `runAttackScenario` 経由で 5 ステップ完全形 (probe → tamper → forge →
// exploit → verify) を 1 リクエストで両モード並列実行する (E-2)。outcome は常に "succeeded"、
// HTTP 200 で統一し、堅牢ステップ 5 の status="blocked" + blockedBy で防御識別子を表現する。
//
// ROB-KERB-1 教訓: 旧仕様の `mitmEnabled` / `fallbackScsvEnabled` 等の body フィールドで
// 「片方だけ実行」する形は採用しない。弱/強 を必ず handler 内で双方並列計算する。
//
// 安全装置: DESIGN/04-safety-guardrails.md
// ─────────────────────────────────────────────────────────────────────────────

// ── 共通シード (immutable) ──
// ROB-FIND-007 / ROB-RBAC-3 / ROB-FIDO2-5 / ROB-OIDC-3 / KERBEROS_DEMO_CONSTANTS と同パターン。
// バージョン文字列・暗号スイート名・証明書 subject/issuer 等の固定値を SSoT 一本化することで、
// 一方だけ変更し忘れて偶然一致してしまう事故 (= 検証バイパス) を防ぐ。
const TLS_DEMO_CONSTANTS = {
  // ── バージョンダウングレード (シナリオ A) ──
  // クライアントが本来提示する全バージョン (TLS 1.0-1.3)
  clientOfferedVersionsOriginal: ["TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"] as const,
  // MITM がストリップした後に残るバージョン
  downgradedVersion: "TLS 1.0",
  // 強い暗号スイート (TLS 1.3 AEAD)
  strongCipherSuite: "TLS_AES_256_GCM_SHA384",
  // FALLBACK_SCSV のセンチネル値 (RFC 7507 §3) — 表示用
  fallbackScsvSentinel: "TLS_FALLBACK_SCSV (0x5600)",
  // 堅牢サーバーのバージョンポリシー (TLS 1.3 のみ)
  defendedMinVersion: "TLS 1.3",

  // ── 自己署名 MITM (シナリオ B) ──
  legitimateCertSubject: "CN=localhost, O=OSI Demo, C=JP",
  legitimateCertIssuer: "CN=OSI Demo CA, O=OSI Demo, C=JP",
  fakeCertSubject: "CN=localhost, O=Attacker Corp",
  fakeCertIssuer: "CN=localhost, O=Attacker Corp", // 自己署名: subject = issuer
  trustedRootCaName: "OSI Demo CA",
  // ROB-RBAC-7 同パターン: subject CN マッチ判定で使用するなりすまし対象 CN
  victimCommonName: "CN=localhost",

  // ── 弱い暗号スイート (シナリオ C) ──
  // クライアントが本来提示する強い暗号 (TLS 1.3 AEAD のみ)
  clientOfferedCiphersStrong: [
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
  ] as const,
  // 脆弱サーバーがサポートする暗号 (RC4/3DES/NULL を含む)
  vulnerableServerCiphers: [
    "TLS_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_RC4_128_MD5",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_NULL_WITH_NULL_NULL",
  ] as const,
  // 堅牢サーバー (allowlist) がサポートする暗号 (AEAD のみ)
  defendedServerCiphers: [
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256",
  ] as const,
  // ROB-MEDIUM-2 修正: シナリオ A のダウングレード後暗号と シナリオ C で MITM が
  // ストリップ後に残す暗号は同一値 (RC4-MD5) — 1 つの SSoT に集約して
  // 「片方だけ変更し忘れて偶然一致してしまう事故」を排除 (旧 weakCipherSuiteDowngraded /
  // mitmStrippedRemaining の 2 スロットを統合)。
  weakCipherForcedByMitm: "TLS_RSA_WITH_RC4_128_MD5",
} as const satisfies Readonly<{
  clientOfferedVersionsOriginal: readonly string[];
  downgradedVersion: string;
  strongCipherSuite: string;
  fallbackScsvSentinel: string;
  defendedMinVersion: string;
  legitimateCertSubject: string;
  legitimateCertIssuer: string;
  fakeCertSubject: string;
  fakeCertIssuer: string;
  trustedRootCaName: string;
  victimCommonName: string;
  clientOfferedCiphersStrong: readonly string[];
  vulnerableServerCiphers: readonly string[];
  defendedServerCiphers: readonly string[];
  weakCipherForcedByMitm: string;
}>;

// 暗号スイート選択ヘルパー: サーバーがサポートする allowlist との intersection から
// 最強の暗号を選ぶ。共通暗号がなければ null (= handshake_failure)。
function selectCipherSuite(
  clientOffered: readonly string[],
  serverAllowed: readonly string[],
): string | null {
  // 弱から強の優先順位 (RC4 → 3DES → AES-128 → CHACHA20 → AES-256) — サーバーが
  // 「クライアント提示順を尊重」する素朴な実装をシミュレート (RFC 5246 §7.4.1.2)。
  for (const c of clientOffered) {
    if (serverAllowed.includes(c)) return c;
  }
  return null;
}

// バージョン選択ヘルパー: 提示バージョンとサーバーポリシーから最高位を選ぶ。
// SCSV 検証時はダウングレードを検知して null (= inappropriate_fallback)。
function selectTlsVersionVulnerable(offered: readonly string[]): string {
  // 脆弱: 提示順で最初のものをそのまま受理 (= MITM が削った後の 1.0 を受理)
  return offered[0] ?? "TLS 1.0";
}

// ── Scenario A: TLS_FALLBACK_SCSV による Version Downgrade 防御 ──
// 防御の核心: TLS_FALLBACK_SCSV (RFC 7507) を ClientHello に含めることで、
// サーバー側が「強制ダウングレードされた fallback ClientHello」を検知し、
// inappropriate_fallback アラートで接続を中断する。
type TlsVersionDowngradeExtra = {
  /** クライアントが本来提示した全バージョン (MITM 改竄前)。 */
  clientOfferedVersionsOriginal: string[];
  /** MITM がストリップ後に残したバージョン (脆弱パスでサーバーが受諾するもの)。 */
  versionsAfterMitm: string[];
  /** 脆弱サーバーが受諾したバージョン (常に downgradedVersion = "TLS 1.0")。 */
  vulnerableNegotiatedVersion: string;
  /** ダウングレード後に強制された弱暗号 (RC4-MD5)。 */
  vulnerableNegotiatedCipher: string;
  /** 脆弱モード: SCSV チェックなしのため受諾。設計上常に true。 */
  vulnerableAccepted: boolean;
  /** 堅牢モード: SCSV により inappropriate_fallback で拒否。設計上常に true。 */
  defendedRejected: boolean;
  /** 堅牢サーバーが宣言する最低バージョン (TLS 1.3)。 */
  defendedMinVersion: string;
  /** 堅牢モードで送出される RFC 7507 アラート名。 */
  defendedAlert: string;
};

tlsSimRoutes.post("/attack/version-downgrade", (c) =>
  runAttackScenario<typeof tlsAttackVersionDowngradeSchema, TlsVersionDowngradeExtra>(c, {
    schema: tlsAttackVersionDowngradeSchema,
    scenarioId: "tls-version-downgrade",
    tabId: "tls-deep",
    async handler({ recordStep, trace }) {
      const offeredOriginal = [...TLS_DEMO_CONSTANTS.clientOfferedVersionsOriginal];
      // MITM が TLS 1.2/1.3 を削除した後の supported_versions (TLS 1.0/1.1 のみ残す)
      const versionsAfterMitm = ["TLS 1.0"]; // 簡略化: 攻撃者は最低バージョンのみ残す
      const vulnerableNegotiatedVersion = selectTlsVersionVulnerable(versionsAfterMitm);
      const vulnerableNegotiatedCipher = TLS_DEMO_CONSTANTS.weakCipherForcedByMitm;

      // ── Step 1: probe — 攻撃者が ClientHello を傍受
      recordStep({
        id: "vd-1",
        kind: "probe",
        label: "Intercept ClientHello (client offers TLS 1.0–1.3)",
        labelJa: "ClientHello を傍受 — クライアントは TLS 1.0-1.3 を提示",
        status: "success",
        payload: {
          type: "tls",
          version: "TLS 1.3",
          cipherSuite: TLS_DEMO_CONSTANTS.strongCipherSuite,
        },
        detailJa:
          "攻撃者は MITM 経路で ClientHello を傍受します。クライアントは正規に TLS 1.0-1.3 のすべてのバージョンを supported_versions エクステンションで提示しています (TLS 1.3 が最高位)。",
        detail:
          "The attacker intercepts the ClientHello via MITM. The client legitimately advertises TLS 1.0-1.3 in its supported_versions extension (TLS 1.3 is the highest).",
      });

      // ── Step 2: tamper — MITM が supported_versions から TLS 1.2/1.3 を削除
      recordStep({
        id: "vd-2",
        kind: "tamper",
        label: "MITM removes TLS 1.2/1.3 from supported_versions",
        labelJa: "MITM が supported_versions から TLS 1.2/1.3 を削除",
        status: "success",
        payload: {
          type: "tls",
          version: "TLS 1.3",
          downgradedTo: TLS_DEMO_CONSTANTS.downgradedVersion,
          cipherSuite: TLS_DEMO_CONSTANTS.strongCipherSuite,
          weakCipherSuite: TLS_DEMO_CONSTANTS.weakCipherForcedByMitm,
        },
        detailJa:
          "攻撃者は ClientHello を改竄し、supported_versions エクステンションから TLS 1.2/1.3 を削除します。残ったのは TLS 1.0 のみで、サーバーは「クライアントが TLS 1.0 しか話せない」と誤認します。",
        detail:
          "The attacker tampers with the ClientHello, stripping TLS 1.2 and TLS 1.3 from the supported_versions extension. Only TLS 1.0 remains, and the server is misled into thinking the client speaks only TLS 1.0.",
      });

      // ── Step 3: forge — MITM が改竄済み ClientHello をサーバーへ送信
      recordStep({
        id: "vd-3",
        kind: "forge",
        label: "MITM forwards tampered ClientHello to server",
        labelJa: "MITM が改竄済み ClientHello をサーバーへ転送",
        status: "success",
        payload: {
          type: "tls",
          version: TLS_DEMO_CONSTANTS.downgradedVersion,
          downgradedTo: TLS_DEMO_CONSTANTS.downgradedVersion,
          weakCipherSuite: TLS_DEMO_CONSTANTS.weakCipherForcedByMitm,
        },
        detailJa:
          "MITM はバージョンを TLS 1.0 のみに絞った改竄 ClientHello をサーバーへ転送します。改竄された ClientHello には TLS_FALLBACK_SCSV センチネルは含まれません (脆弱パス) — または含まれます (堅牢パス、RFC 7507)。",
        detail:
          "The MITM forwards the tampered ClientHello (with only TLS 1.0 in supported_versions) to the server. The vulnerable path: no TLS_FALLBACK_SCSV sentinel. The defended path: TLS_FALLBACK_SCSV is present per RFC 7507.",
      });

      // ── Step 4: exploit (脆弱モード) — SCSV チェックなし → サーバーが TLS 1.0 を受諾
      // 設計上常に true (versionsAfterMitm が TLS 1.0 のみ → 脆弱サーバーは受諾)
      const vulnerableAccepted = vulnerableNegotiatedVersion === TLS_DEMO_CONSTANTS.downgradedVersion;
      trace.addCryptoOp({
        op: "tls.negotiateVersion (vulnerable_no_scsv_check)",
        input: `offered=[${versionsAfterMitm.join(",")}] (downgraded by MITM)`,
        output: vulnerableAccepted
          ? `${vulnerableNegotiatedVersion} accepted, cipher=${vulnerableNegotiatedCipher}`
          : "negotiation failed (unexpected)",
        algo: "TLS version negotiation (without TLS_FALLBACK_SCSV check)",
        detail:
          "Vulnerable: the server has no TLS_FALLBACK_SCSV check and simply accepts the highest version offered (which is TLS 1.0 after MITM stripping). RC4 cipher is then negotiated, exposing the connection to BEAST/POODLE-class attacks.",
      });
      recordStep({
        id: "vd-4",
        kind: "exploit",
        label: "Vulnerable: server accepts TLS 1.0 (no SCSV check) — weak cipher negotiated",
        labelJa: "脆弱版: サーバーが TLS 1.0 を受諾 (SCSV チェックなし) — 弱い暗号でネゴシエーション完了",
        status: vulnerableAccepted ? "success" : "failed",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/tls/attack/version-downgrade (vulnerable variant — no TLS_FALLBACK_SCSV)",
            headers: { "X-Attack-Sim": "version-downgrade" },
          },
          response: {
            status: vulnerableAccepted ? 200 : 500,
            body: vulnerableAccepted
              ? {
                  step: "ServerHello",
                  negotiatedVersion: vulnerableNegotiatedVersion,
                  negotiatedCipher: vulnerableNegotiatedCipher,
                  note: "Vulnerable: SCSV check missing. Server accepted MITM-downgraded TLS 1.0 with RC4 — connection now susceptible to BEAST/POODLE.",
                }
              : { error: "Negotiation unexpectedly failed." },
          },
        },
        detailJa: vulnerableAccepted
          ? "この実装は脆弱です: サーバーは TLS_FALLBACK_SCSV センチネルを検査しないため、MITM がダウングレードした TLS 1.0 をそのまま受諾します。RC4-MD5 がネゴシエーションされ、接続は BEAST/POODLE クラスの攻撃に露出します。"
          : "脆弱パス予期せず実行不可: バージョン交渉に失敗しました。",
        detail: vulnerableAccepted
          ? "This implementation is vulnerable: the server does not check the TLS_FALLBACK_SCSV sentinel and accepts the MITM-downgraded TLS 1.0 verbatim. RC4-MD5 is negotiated, exposing the connection to BEAST/POODLE-class attacks."
          : "Vulnerable path unexpectedly failed.",
      });

      // ── Step 5: verify (堅牢モード) — SCSV 検証で inappropriate_fallback アラート
      // 設計上常に true: SCSV 存在 + negotiated < client_max_version → reject
      const defendedRejected = true;
      trace.addCryptoOp({
        op: "tls.checkFallbackSCSV (defended_rfc7507)",
        input: `clientHello includes ${TLS_DEMO_CONSTANTS.fallbackScsvSentinel}, offered=[${versionsAfterMitm.join(",")}], serverMaxVersion=${TLS_DEMO_CONSTANTS.defendedMinVersion}`,
        output: defendedRejected
          ? "inappropriate_fallback alert (downgrade detected → connection aborted)"
          : "downgrade not detected (should not happen)",
        algo: "TLS_FALLBACK_SCSV (RFC 7507 §3)",
        detail:
          "Defended: when the server detects TLS_FALLBACK_SCSV in a ClientHello whose negotiated version is below the server's max, it knows a downgrade was forced and aborts with the inappropriate_fallback fatal alert (RFC 7507 §3).",
      });
      recordStep({
        id: "vd-5",
        kind: "verify",
        label: "Defended: TLS_FALLBACK_SCSV detects downgrade — inappropriate_fallback aborts handshake",
        labelJa: "堅牢版: TLS_FALLBACK_SCSV がダウングレードを検知 — inappropriate_fallback で接続中断",
        status: defendedRejected ? "blocked" : "failed",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/tls/attack/version-downgrade (defended variant — TLS_FALLBACK_SCSV)",
          },
          response: {
            status: 401,
            body: {
              error: "inappropriate_fallback alert: TLS_FALLBACK_SCSV present but negotiated version is below server's max — forced downgrade detected.",
              blockedBy: "tls_fallback_scsv_inappropriate_fallback_alert_enforced",
              policy: {
                rfc: "RFC 7507",
                serverMaxVersion: TLS_DEMO_CONSTANTS.defendedMinVersion,
                serverMinVersion: TLS_DEMO_CONSTANTS.defendedMinVersion,
                disabledVersions: ["TLS 1.0", "TLS 1.1", "TLS 1.2"],
              },
            },
          },
          tamperedFields: ["supported_versions (MITM stripped TLS 1.2/1.3)"],
        },
        detailJa:
          "堅牢実装は RFC 7507 §3 に従い、TLS_FALLBACK_SCSV センチネルが ClientHello に含まれている場合、サーバーは「クライアントがダウングレード後の再試行を行っている」と認識します。ネゴシエーション結果がサーバーの最高バージョンより低ければ inappropriate_fallback 致命的アラートを送出し、接続を中断します。さらに最低バージョンを TLS 1.3 に固定 (TLS 1.0/1.1/1.2 を完全無効化) することで、ダウングレード自体を不可能にします。",
        detail:
          "The defended implementation, per RFC 7507 §3, recognizes the TLS_FALLBACK_SCSV sentinel as a signal that the client is performing a downgrade-retry. If the negotiated version is below the server's max, it sends an inappropriate_fallback fatal alert and aborts. Additionally pinning the minimum version to TLS 1.3 (disabling TLS 1.0/1.1/1.2 entirely) makes downgrades impossible at the protocol level.",
      });

      return {
        blockedBy: "tls_fallback_scsv_inappropriate_fallback_alert_enforced",
        summary:
          "A vulnerable server with no TLS_FALLBACK_SCSV check accepts a MITM-downgraded TLS 1.0 ClientHello and negotiates RC4-MD5, exposing the connection to BEAST/POODLE-class attacks. The defended server detects the FALLBACK_SCSV sentinel and aborts with the inappropriate_fallback alert (RFC 7507). Both modes run in parallel within one request.",
        summaryJa:
          "この実装は脆弱です: TLS_FALLBACK_SCSV を検査しないサーバーは MITM がダウングレードした TLS 1.0 ClientHello を受諾し、RC4-MD5 でネゴシエーションして BEAST/POODLE クラスの攻撃に接続を露出させます。堅牢サーバーは FALLBACK_SCSV センチネルを検知し inappropriate_fallback アラート (RFC 7507) で接続を中断します。両モードを 1 リクエスト内で並列実行します。",
        extra: {
          clientOfferedVersionsOriginal: offeredOriginal,
          versionsAfterMitm,
          vulnerableNegotiatedVersion,
          vulnerableNegotiatedCipher,
          vulnerableAccepted,
          defendedRejected,
          defendedMinVersion: TLS_DEMO_CONSTANTS.defendedMinVersion,
          defendedAlert: "inappropriate_fallback",
        } satisfies TlsVersionDowngradeExtra,
        payload: {
          params: {},
          result: {
            clientOfferedVersionsOriginal: offeredOriginal,
            versionsAfterMitm,
            vulnerableNegotiatedVersion,
            vulnerableNegotiatedCipher,
            vulnerableAccepted,
            defendedRejected,
          },
        },
      };
    },
  }),
);

// ── Scenario B: 自己署名証明書による MITM ──
// 防御の核心: クライアント側で証明書チェーン検証を有効化 (rejectUnauthorized: true) し、
// 信頼されたルート CA からの署名連鎖を確認する。Certificate Pinning も追加防御。
type TlsSelfSignedMitmExtra = {
  legitimateCert: {
    subject: string;
    issuer: string;
    selfSigned: boolean;
    fingerprintPreview: string;
  };
  fakeCert: {
    subject: string;
    issuer: string;
    selfSigned: boolean;
    fingerprintPreview: string;
  };
  /** 脆弱モード: rejectUnauthorized=false → 偽証明書を受諾。設計上常に true。 */
  vulnerableMitmEstablished: boolean;
  /** 堅牢モード: CA チェーン検証で偽証明書を拒否。設計上常に true。 */
  defendedCertRejected: boolean;
  /** 堅牢モードのアラート名 (TLS Alert 46 = certificate_unknown)。 */
  defendedAlert: string;
};

tlsSimRoutes.post("/attack/self-signed-mitm", (c) =>
  runAttackScenario<typeof tlsAttackSelfSignedMitmSchema, TlsSelfSignedMitmExtra>(c, {
    schema: tlsAttackSelfSignedMitmSchema,
    scenarioId: "tls-self-signed-mitm",
    tabId: "tls-deep",
    async handler({ recordStep, trace }) {
      // 正規証明書 (CA 署名) と攻撃者の偽証明書 (自己署名) を 2 つ生成して並列実行
      const legitKeyPair = crypto.generateKeyPairSync("rsa", {
        modulusLength: 2048,
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
      });
      const fakeKeyPair = crypto.generateKeyPairSync("rsa", {
        modulusLength: 2048,
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
      });

      const legitFingerprint = crypto
        .createHash("sha256")
        .update(legitKeyPair.publicKey)
        .digest("hex");
      const fakeFingerprint = crypto
        .createHash("sha256")
        .update(fakeKeyPair.publicKey)
        .digest("hex");

      const legitFingerprintPreview = legitFingerprint.substring(0, 32) + "...";
      const fakeFingerprintPreview = fakeFingerprint.substring(0, 32) + "...";

      // ── Step 1: probe — 正規サーバーの証明書を観察 (CA 署名)
      trace.addCryptoOp({
        op: "generateRSAKeyPair(legitimate_server)",
        input: "modulusLength=2048",
        output: `legitFingerprint=${legitFingerprintPreview}`,
        algo: "RSA-2048 (CA-signed in production)",
        detail:
          "The legitimate server's certificate is signed by a trusted root CA (in this demo, conceptually 'OSI Demo CA').",
      });
      recordStep({
        id: "ssm-1",
        kind: "probe",
        label: "Observe legitimate server certificate (CA-signed)",
        labelJa: "正規サーバー証明書を観察 (CA 署名)",
        status: "success",
        payload: {
          type: "tls",
          certificate: {
            subject: TLS_DEMO_CONSTANTS.legitimateCertSubject,
            issuer: TLS_DEMO_CONSTANTS.legitimateCertIssuer,
            validFrom: new Date().toISOString(),
            validTo: new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString(),
            selfSigned: false,
          },
        },
        detailJa:
          "正規サーバーの証明書は信頼されたルート CA (デモでは概念的に 'OSI Demo CA') により署名されています。subject の CN とサーバーのドメイン名が一致し、issuer が信頼ストア内の CA と連鎖しています。",
        detail:
          "The legitimate server's certificate is signed by a trusted root CA (conceptually 'OSI Demo CA' in this demo). The subject CN matches the server's domain, and the issuer chains to a CA in the trust store.",
      });

      // ── Step 2: tamper — MITM が TLS ハンドシェイクを傍受
      recordStep({
        id: "ssm-2",
        kind: "tamper",
        label: "MITM intercepts TLS handshake (ARP spoofing simulated)",
        labelJa: "MITM が TLS ハンドシェイクを傍受 (ARP スプーフィングをシミュレート)",
        status: "success",
        payload: {
          type: "generic",
          data: {
            note: "Real MITM requires network path interception (ARP spoofing, DNS poisoning, rogue Wi-Fi AP, etc.). This demo abstracts that step.",
            noteJa: "実環境の MITM はネットワーク経路への介入 (ARP スプーフィング・DNS ポイズニング・偽 Wi-Fi AP 等) が必要。本デモはその手順を抽象化。",
            interceptionMethod: "ARP spoofing on local segment (simulated)",
          },
        },
        detailJa:
          "攻撃者はクライアントとサーバーの間に MITM として割り込みます。実環境では ARP スプーフィングや DNS ポイズニング、偽 Wi-Fi AP 等の手順が必要ですが、本デモはその手順を抽象化し、TLS ハンドシェイク段階のみを示します。",
        detail:
          "The attacker positions themselves as an MITM between client and server. In real environments this requires ARP spoofing, DNS poisoning, or a rogue Wi-Fi AP; this demo abstracts those steps and focuses on the TLS handshake phase.",
      });

      // ── Step 3: forge — 攻撃者が標的ドメイン向けの自己署名証明書を作成
      trace.addCryptoOp({
        op: "generateSelfSignedCert(attacker)",
        input: `subject=${TLS_DEMO_CONSTANTS.fakeCertSubject}`,
        output: `selfSigned=true, issuer=self, fingerprint=${fakeFingerprintPreview}`,
        algo: "RSA-2048 (self-signed by attacker)",
        detail:
          "The attacker generates a self-signed certificate impersonating the legitimate server. Subject CN = localhost matches the target, but the issuer is the attacker themselves (self-signed).",
      });
      recordStep({
        id: "ssm-3",
        kind: "forge",
        label: "Attacker creates self-signed certificate impersonating server",
        labelJa: "攻撃者がサーバーになりすます自己署名証明書を作成",
        status: "success",
        payload: {
          type: "tls",
          fakeCertificate: {
            subject: TLS_DEMO_CONSTANTS.fakeCertSubject,
            issuer: TLS_DEMO_CONSTANTS.fakeCertIssuer,
            selfSigned: true,
          },
        },
        detailJa:
          "攻撃者は標的ドメインの CN (localhost) を持つ自己署名証明書を生成します。subject = issuer (自己署名) のため、信頼されたルート CA からの署名連鎖は存在しません。攻撃者は MITM 経路で正規証明書をこの偽証明書に差し替えます。",
        detail:
          "The attacker generates a self-signed certificate with the target's CN (localhost). Since subject = issuer (self-signed), there is no signature chain to a trusted root CA. The attacker substitutes the legitimate certificate with this fake one through the MITM path.",
      });

      // ── Step 4: exploit (脆弱モード) — クライアントが rejectUnauthorized=false で偽証明書を受諾
      // ROB-MEDIUM-1 修正: bare literal `true` ではなく、SSoT 定数から派生する条件で
      // 「偽証明書がなりすまし subject (CN=localhost) を持つ」「偽証明書は trusted root
      // にチェーンしない」という事実から MITM 成立を導出。将来 fakeCert を「正規 CA に
      // チェーンする」に変更すれば、`vulnerableMitmEstablished` は false になり
      // 教材意図がコードに保たれる (sentinel 化)。
      const fakeCertImpersonatesVictim = TLS_DEMO_CONSTANTS.fakeCertSubject.startsWith(
        TLS_DEMO_CONSTANTS.victimCommonName,
      );
      const fakeCertChainsToTrustedRoot = TLS_DEMO_CONSTANTS.fakeCertIssuer.includes(
        TLS_DEMO_CONSTANTS.trustedRootCaName,
      );
      // 脆弱: rejectUnauthorized=false → 偽証明書が legit subject になりすましていれば MITM 成立
      // (検証無効では trusted root への chain は問われないため、なりすまし subject だけで十分)
      const vulnerableMitmEstablished = fakeCertImpersonatesVictim;
      trace.addCryptoOp({
        op: "certChainValidation (vulnerable_disabled)",
        input: "rejectUnauthorized=false (NODE_TLS_REJECT_UNAUTHORIZED=0 equivalent)",
        output: "SKIPPED — any certificate accepted",
        algo: "X.509 chain validation (DISABLED)",
        detail:
          "Vulnerable: the client has disabled certificate validation. The self-signed attacker certificate is accepted as if it were signed by a trusted CA. All TLS-encrypted traffic is now readable by the MITM (despite the connection being technically 'encrypted').",
      });
      recordStep({
        id: "ssm-4",
        kind: "exploit",
        label: "Vulnerable: rejectUnauthorized=false accepts fake cert — MITM established",
        labelJa: "脆弱版: rejectUnauthorized=false が偽証明書を受諾 — MITM 成立",
        status: vulnerableMitmEstablished ? "success" : "failed",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/tls/attack/self-signed-mitm (vulnerable variant — cert validation disabled)",
            headers: { "X-Attack-Sim": "self-signed-mitm" },
          },
          response: {
            status: vulnerableMitmEstablished ? 200 : 500,
            body: vulnerableMitmEstablished
              ? {
                  step: "ServerHello + Certificate (fake)",
                  certAcceptedAs: "trusted",
                  mitmEstablished: true,
                  interceptedExample: "HTTP GET /api/auth/login (now plaintext to MITM despite TLS)",
                  note: "Vulnerable: client disabled cert validation. MITM can now read and modify all TLS traffic.",
                }
              : { error: "Unexpected: validation succeeded with mismatched certificate." },
          },
          tamperedFields: ["server certificate (replaced with attacker self-signed)"],
        },
        detailJa: vulnerableMitmEstablished
          ? "この実装は脆弱です: クライアントが rejectUnauthorized=false (Node.js) や NODE_TLS_REJECT_UNAUTHORIZED=0 環境変数で証明書検証を無効化しているため、自己署名の偽証明書が受諾されます。TLS は確立しますが、MITM が両端の暗号化を解いて全トラフィックを読み書きできます。"
          : "脆弱パス予期せず実行不可: 検証無効でも証明書が受諾されませんでした。",
        detail: vulnerableMitmEstablished
          ? "This implementation is vulnerable: with rejectUnauthorized=false (Node.js) or NODE_TLS_REJECT_UNAUTHORIZED=0 set, the self-signed fake certificate is accepted. TLS is established, but the MITM controls both ends and can read/modify all traffic."
          : "Vulnerable path unexpectedly failed.",
      });

      // ── Step 5: verify (堅牢モード) — CA チェーン検証で偽証明書を拒否
      // ROB-MEDIUM-1 修正: bare literal `true` ではなく、SSoT 定数から派生する
      // 「偽証明書が自己署名 (subject == issuer)」かつ「trusted root にチェーンしない」
      // という事実から拒否を導出。将来 fakeCert を「正規 CA にチェーンする」に変更すれば
      // `defendedCertRejected` は false になり教材意図がコードに保たれる (sentinel 化)。
      const fakeCertIsSelfSigned =
        TLS_DEMO_CONSTANTS.fakeCertSubject === TLS_DEMO_CONSTANTS.fakeCertIssuer;
      // 堅牢: CA チェーン検証 (RFC 5280 §6) で trusted root に到達できない証明書を拒否
      const defendedCertRejected = fakeCertIsSelfSigned && !fakeCertChainsToTrustedRoot;
      trace.addCryptoOp({
        op: "certChainValidation (defended_strict)",
        input: `cert=${TLS_DEMO_CONSTANTS.fakeCertSubject} (self-signed: subject=issuer)`,
        output: defendedCertRejected
          ? "FAILED: issuer not in trusted root store (no chain to OSI Demo CA)"
          : "validation passed (should not happen)",
        algo: "X.509 chain validation (RFC 5280)",
        detail:
          "Defended: the client builds a certificate chain from the presented end-entity cert to a trusted root in its CA store. Self-signed certs (subject = issuer) terminate immediately without reaching a trusted root, so the chain validation fails. The TLS Alert 46 (certificate_unknown) aborts the handshake.",
      });
      recordStep({
        id: "ssm-5",
        kind: "verify",
        label: "Defended: CA chain validation rejects self-signed cert — certificate_unknown aborts",
        labelJa: "堅牢版: CA チェーン検証が自己署名証明書を拒否 — certificate_unknown で中断",
        status: defendedCertRejected ? "blocked" : "failed",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/tls/attack/self-signed-mitm (defended variant — strict CA chain validation)",
          },
          response: {
            status: 401,
            body: {
              error: "TLS Alert 46 (certificate_unknown): self-signed certificate cannot chain to trusted root.",
              blockedBy: "tls_ca_chain_validation_certificate_unknown_alert_enforced",
              policy: {
                rejectUnauthorized: true,
                trustedRoot: TLS_DEMO_CONSTANTS.trustedRootCaName,
                certificatePinningRecommended: true,
                rfc: "RFC 5280 §6 / RFC 8446 §4.4.2",
              },
              comparison: {
                legitimate: {
                  subject: TLS_DEMO_CONSTANTS.legitimateCertSubject,
                  issuer: TLS_DEMO_CONSTANTS.legitimateCertIssuer,
                  selfSigned: false,
                  chainToTrustedRoot: true,
                },
                fake: {
                  subject: TLS_DEMO_CONSTANTS.fakeCertSubject,
                  issuer: TLS_DEMO_CONSTANTS.fakeCertIssuer,
                  selfSigned: true,
                  chainToTrustedRoot: false,
                },
              },
            },
          },
        },
        detailJa:
          "堅牢実装は RFC 5280 §6 に従い、提示されたエンドエンティティ証明書から信頼されたルート CA への署名連鎖を構築・検証します。自己署名証明書 (subject = issuer) はルート CA に到達できないため検証に失敗し、TLS Alert 46 (certificate_unknown) でハンドシェイクを中断します。さらに Certificate Pinning (公開鍵フィンガープリント固定) を併用すれば、CA そのものが侵害された場合でも防御が成立します。",
        detail:
          "The defended implementation, per RFC 5280 §6, builds and validates a signature chain from the presented end-entity certificate to a trusted root CA. A self-signed certificate (subject = issuer) cannot reach a trusted root, so validation fails and the handshake aborts with TLS Alert 46 (certificate_unknown). Adding Certificate Pinning (pinning the public-key fingerprint) provides defense-in-depth even if a CA itself is compromised.",
      });

      return {
        blockedBy: "tls_ca_chain_validation_certificate_unknown_alert_enforced",
        summary:
          "A vulnerable client with rejectUnauthorized=false accepts a self-signed certificate substituted by an MITM, allowing the attacker to read all TLS-encrypted traffic. The defended client validates the certificate chain to a trusted root and rejects the self-signed cert with TLS Alert 46 (certificate_unknown). Both modes run in parallel within one request.",
        summaryJa:
          "この実装は脆弱です: rejectUnauthorized=false のクライアントは MITM が差し替えた自己署名証明書をそのまま受諾し、攻撃者が TLS 暗号化された全通信を読み書きできるようになります。堅牢クライアントは信頼されたルートへのチェーン検証を行い、自己署名証明書を TLS Alert 46 (certificate_unknown) で拒否します。両モードを 1 リクエスト内で並列実行します。",
        extra: {
          legitimateCert: {
            subject: TLS_DEMO_CONSTANTS.legitimateCertSubject,
            issuer: TLS_DEMO_CONSTANTS.legitimateCertIssuer,
            selfSigned: false,
            fingerprintPreview: legitFingerprintPreview,
          },
          fakeCert: {
            subject: TLS_DEMO_CONSTANTS.fakeCertSubject,
            issuer: TLS_DEMO_CONSTANTS.fakeCertIssuer,
            selfSigned: true,
            fingerprintPreview: fakeFingerprintPreview,
          },
          vulnerableMitmEstablished,
          defendedCertRejected,
          defendedAlert: "certificate_unknown",
        } satisfies TlsSelfSignedMitmExtra,
        payload: {
          params: {},
          result: {
            legitFingerprintPreview,
            fakeFingerprintPreview,
            vulnerableMitmEstablished,
            defendedCertRejected,
          },
        },
      };
    },
  }),
);

// ── Scenario C: 弱い暗号スイートネゴシエーション ──
// 防御の核心: サーバーが暗号スイート allowlist で AEAD (TLS 1.3 推奨) のみを許可し、
// RC4/3DES/NULL/EXPORT 等の廃止された暗号を完全に除外する。共通暗号がなければ
// handshake_failure で接続を中断する。
type TlsWeakCipherExtra = {
  /** クライアントが本来提示した強い暗号のリスト。 */
  clientOfferedCiphersOriginal: string[];
  /** MITM ストリップ後にクライアントが提示する暗号 (RC4 のみ)。 */
  clientCiphersAfterMitm: string[];
  /** 脆弱サーバーがサポートする暗号 (RC4/3DES/NULL を含む)。 */
  vulnerableServerCiphers: string[];
  /** 堅牢サーバー (allowlist) がサポートする暗号 (AEAD のみ)。 */
  defendedServerCiphers: string[];
  /** 脆弱モード: ネゴシエーション結果 (RC4-MD5)。 */
  vulnerableNegotiatedCipher: string | null;
  /** 脆弱モード: セッション確立に成功 (= 弱暗号で暗号化)。設計上常に true。 */
  vulnerableSessionEstablished: boolean;
  /** 堅牢モード: 共通暗号なし (= handshake_failure)。設計上常に true。 */
  defendedHandshakeFailure: boolean;
  /** 堅牢モードのアラート名 (TLS Alert 40 = handshake_failure)。 */
  defendedAlert: string;
};

tlsSimRoutes.post("/attack/weak-cipher", (c) =>
  runAttackScenario<typeof tlsAttackWeakCipherSchema, TlsWeakCipherExtra>(c, {
    schema: tlsAttackWeakCipherSchema,
    scenarioId: "tls-weak-cipher-negotiation",
    tabId: "tls-deep",
    async handler({ recordStep, trace }) {
      const offeredOriginal = [...TLS_DEMO_CONSTANTS.clientOfferedCiphersStrong];
      // MITM が強い暗号を全て削除し RC4-MD5 のみ残した状態
      const ciphersAfterMitm = [TLS_DEMO_CONSTANTS.weakCipherForcedByMitm];
      const vulnerableCiphers = [...TLS_DEMO_CONSTANTS.vulnerableServerCiphers];
      const defendedCiphers = [...TLS_DEMO_CONSTANTS.defendedServerCiphers];

      // 脆弱サーバーは RC4-MD5 を含む allowlist を持つので RC4 で交渉成立
      const vulnerableNegotiated = selectCipherSuite(ciphersAfterMitm, vulnerableCiphers);
      // 堅牢サーバーは AEAD のみの allowlist を持つので RC4 と一致せず → null
      const defendedNegotiated = selectCipherSuite(ciphersAfterMitm, defendedCiphers);

      // ── Step 1: probe — サーバーがサポートする暗号スイートを列挙
      trace.addCryptoOp({
        op: "tls.enumerateCipherSuites",
        input: "TLS handshake probe with comprehensive cipher list",
        output: `vulnerableServer=[${vulnerableCiphers.join(",")}], defendedServer=[${defendedCiphers.join(",")}]`,
        algo: "TLS cipher suite enumeration",
        detail:
          "The attacker probes both the vulnerable server (allows RC4/3DES/NULL) and the defended server (AEAD allowlist). The vulnerable server's allowlist includes deprecated ciphers retained for legacy compatibility.",
      });
      recordStep({
        id: "wc-1",
        kind: "probe",
        label: "Enumerate server cipher suite policies (both servers)",
        labelJa: "両サーバーの暗号スイートポリシーを列挙",
        status: "success",
        payload: {
          type: "generic",
          data: {
            note: "Comparing two server policies in parallel: vulnerable (allows weak ciphers) vs. defended (AEAD allowlist).",
            noteJa: "2 つのサーバーポリシーを並列比較: 脆弱版 (弱暗号を許可) vs 堅牢版 (AEAD 許可リスト)",
            vulnerableServerCiphers: vulnerableCiphers,
            defendedServerCiphers: defendedCiphers,
            weakCiphersInVulnerable: vulnerableCiphers.filter(
              (c) => c.includes("RC4") || c.includes("3DES") || c.includes("NULL"),
            ),
          },
        },
        detailJa:
          "攻撃者は両サーバー (脆弱版・堅牢版) がサポートする暗号スイートを列挙します。脆弱版は後方互換性のために RC4/3DES/NULL を残しています。堅牢版は TLS 1.3 AEAD (AES-GCM, ChaCha20-Poly1305) のみの allowlist を強制しています。",
        detail:
          "The attacker enumerates cipher suite policies for both servers (vulnerable + defended). The vulnerable server retains RC4/3DES/NULL for legacy compatibility. The defended server enforces a strict allowlist of TLS 1.3 AEAD ciphers only (AES-GCM, ChaCha20-Poly1305).",
      });

      // ── Step 2: tamper — MITM が ClientHello から強い暗号スイートを削除 → RC4 のみ残す
      recordStep({
        id: "wc-2",
        kind: "tamper",
        label: "MITM strips strong ciphers from ClientHello — only RC4 remains",
        labelJa: "MITM が ClientHello から強い暗号スイートを削除 — RC4 のみ残す",
        status: "success",
        payload: {
          type: "tls",
          cipherSuite: TLS_DEMO_CONSTANTS.strongCipherSuite,
          weakCipherSuite: TLS_DEMO_CONSTANTS.weakCipherForcedByMitm,
        },
        detailJa:
          "MITM は ClientHello の cipher_suites リストを書き換え、AEAD 暗号 (AES-GCM, ChaCha20-Poly1305) を全て削除し、RC4-MD5 のみを残します。サーバーは「クライアントが RC4 しか話せない」と誤認します。",
        detail:
          "The MITM tampers with the ClientHello's cipher_suites list, removing all AEAD ciphers (AES-GCM, ChaCha20-Poly1305) and leaving only RC4-MD5. The server is misled into thinking the client supports only RC4.",
      });

      // ── Step 3: forge — 改竄済み ClientHello をサーバーに送信
      recordStep({
        id: "wc-3",
        kind: "forge",
        label: "MITM forwards tampered ClientHello (RC4-only) to both servers",
        labelJa: "MITM が改竄済み ClientHello (RC4 のみ) を両サーバーへ転送",
        status: "success",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/tls/attack/weak-cipher (simulated TLS handshake — both server variants)",
            headers: { "X-Attack-Sim": "weak-cipher" },
            body: {
              cipherSuites: ciphersAfterMitm,
              note: "MITM stripped strong ciphers — only RC4-MD5 remains in the offered list",
            },
          },
          tamperedFields: ["cipher_suites (MITM removed all AEAD ciphers)"],
        },
        detailJa:
          "改竄済み ClientHello が両サーバーへ送信されます。脆弱版サーバー (RC4 を allowlist に含む) は受諾しますが、堅牢版サーバー (AEAD のみ) は共通暗号を見つけられません。",
        detail:
          "The tampered ClientHello is forwarded to both servers. The vulnerable server (RC4 in its allowlist) accepts; the defended server (AEAD only) finds no common cipher suite.",
      });

      // ── Step 4: exploit (脆弱モード) — RC4 を許可するサーバーが弱暗号で交渉成立
      const vulnerableSessionEstablished = vulnerableNegotiated !== null;
      trace.addCryptoOp({
        op: "cipherSuiteNegotiation (vulnerable_server_with_legacy_ciphers)",
        input: `client offered: [${ciphersAfterMitm.join(",")}] (MITM stripped strong ciphers)`,
        output: vulnerableSessionEstablished
          ? `negotiated: ${vulnerableNegotiated} — session established with broken cipher`
          : "no common cipher (unexpected)",
        algo: "TLS cipher suite negotiation (vulnerable server policy)",
        detail:
          "Vulnerable: the server retains RC4-MD5 in its allowlist for legacy compatibility, so it accepts the MITM-forced RC4 cipher. Session data is now encrypted with a known-broken algorithm; statistical biases in RC4 enable plaintext recovery (RFC 7465 deprecates RC4 entirely).",
      });
      recordStep({
        id: "wc-4",
        kind: "exploit",
        label: "Vulnerable: RC4-allowing server negotiates RC4-MD5 — broken cipher in use",
        labelJa: "脆弱版: RC4 を許可するサーバーが RC4-MD5 で交渉成立 — 破られた暗号でセッション確立",
        status: vulnerableSessionEstablished ? "success" : "failed",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/tls/attack/weak-cipher (vulnerable variant — server allows RC4/3DES/NULL)",
          },
          response: {
            status: vulnerableSessionEstablished ? 200 : 500,
            body: vulnerableSessionEstablished
              ? {
                  step: "ServerHello",
                  negotiatedCipher: vulnerableNegotiated,
                  encryptionStrength: "BROKEN (RC4 statistical biases enable plaintext recovery)",
                  rfc: "RFC 7465 (Prohibiting RC4 Cipher Suites)",
                  note: "Vulnerable: server's allowlist retains RC4 for legacy compatibility. Session is technically encrypted but the cipher is broken.",
                }
              : { error: "Negotiation unexpectedly failed." },
          },
        },
        detailJa: vulnerableSessionEstablished
          ? "この実装は脆弱です: サーバーが後方互換性のために RC4-MD5 を allowlist に残しているため、MITM が強制した RC4 暗号でネゴシエーションが成立します。セッションデータは「破られた暗号」で暗号化され、RC4 の統計バイアスにより平文を復元できます (RFC 7465 で RC4 は完全に廃止)。"
          : "脆弱パス予期せず実行不可: 共通暗号スイートが見つかりませんでした。",
        detail: vulnerableSessionEstablished
          ? "This implementation is vulnerable: the server retains RC4-MD5 in its allowlist for legacy compatibility, so it accepts the MITM-forced cipher. Session data is encrypted with a broken algorithm; RC4 statistical biases enable plaintext recovery (RFC 7465 deprecates RC4 entirely)."
          : "Vulnerable path unexpectedly failed.",
      });

      // ── Step 5: verify (堅牢モード) — AEAD allowlist が共通暗号なし → handshake_failure
      // 設計上常に true: defendedNegotiated は null (RC4 が AEAD allowlist に含まれない)
      const defendedHandshakeFailure = defendedNegotiated === null;
      trace.addCryptoOp({
        op: "cipherSuiteNegotiation (defended_server_aead_allowlist)",
        input: `client offered: [${ciphersAfterMitm.join(",")}], server allowlist: [${defendedCiphers.join(",")}]`,
        output: defendedHandshakeFailure
          ? "FAILED: no common cipher suite (handshake_failure alert)"
          : `negotiated: ${defendedNegotiated} (should not happen)`,
        algo: "TLS cipher suite negotiation (strict AEAD allowlist)",
        detail:
          "Defended: the server's allowlist excludes RC4/3DES/NULL/EXPORT and accepts only TLS 1.3 AEAD ciphers (AES-GCM, ChaCha20-Poly1305). The intersection with the MITM-stripped ClientHello (containing only RC4) is empty, so the handshake aborts with TLS Alert 40 (handshake_failure).",
      });
      recordStep({
        id: "wc-5",
        kind: "verify",
        label: "Defended: AEAD allowlist finds no common cipher — handshake_failure aborts",
        labelJa: "堅牢版: AEAD 許可リストで共通暗号なし — handshake_failure で中断",
        status: defendedHandshakeFailure ? "blocked" : "failed",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/tls/attack/weak-cipher (defended variant — AEAD-only allowlist)",
          },
          response: {
            status: 401,
            body: {
              error: "TLS Alert 40 (handshake_failure): no common cipher suite between client offer and server allowlist.",
              blockedBy: "tls_cipher_allowlist_handshake_failure_alert_enforced",
              policy: {
                allowlist: defendedCiphers,
                disabled: ["RC4 (RFC 7465)", "3DES (Sweet32)", "NULL", "EXPORT", "DES", "anonymous DH"],
                rfc: "RFC 8446 §B.4 / RFC 7465 / RFC 7525",
                qualysSslLabsRecommended: true,
              },
              comparison: {
                clientOfferedAfterMitm: ciphersAfterMitm,
                vulnerableNegotiated,
                defendedNegotiated,
              },
            },
          },
        },
        detailJa:
          "堅牢実装は RFC 8446 (TLS 1.3) と RFC 7525 (BCP 195) に従い、暗号スイート allowlist で TLS 1.3 AEAD のみを許可します (AES-GCM, ChaCha20-Poly1305)。RC4 (RFC 7465 で廃止)、3DES (Sweet32 攻撃の対象)、NULL、EXPORT、DES、匿名 DH は完全に除外されます。MITM がストリップ後の ClientHello (RC4 のみ) との共通暗号がないため、TLS Alert 40 (handshake_failure) でハンドシェイクを中断します。Qualys SSL Labs 等のツールで定期検証を推奨します。",
        detail:
          "The defended implementation, per RFC 8446 (TLS 1.3) and RFC 7525 (BCP 195), enforces a cipher suite allowlist of TLS 1.3 AEAD ciphers only (AES-GCM, ChaCha20-Poly1305). RC4 (deprecated by RFC 7465), 3DES (Sweet32-vulnerable), NULL, EXPORT, DES, and anonymous DH are all excluded. With no intersection between the MITM-stripped ClientHello (RC4 only) and the allowlist, TLS Alert 40 (handshake_failure) aborts the handshake. Periodic verification with Qualys SSL Labs is recommended.",
      });

      return {
        blockedBy: "tls_cipher_allowlist_handshake_failure_alert_enforced",
        summary:
          "A vulnerable server retaining RC4/3DES/NULL for legacy compatibility negotiates RC4-MD5 when an MITM strips strong ciphers from the ClientHello, exposing the connection to RC4-bias plaintext recovery. The defended server enforces an AEAD-only allowlist (TLS 1.3) and aborts the handshake with TLS Alert 40 (handshake_failure) when no common cipher exists. Both modes run in parallel within one request.",
        summaryJa:
          "この実装は脆弱です: 後方互換性のために RC4/3DES/NULL を残したサーバーは、MITM が強い暗号を削除した ClientHello に対して RC4-MD5 でネゴシエーションを成立させ、RC4 統計バイアスによる平文復元に接続を露出させます。堅牢サーバーは AEAD のみの allowlist (TLS 1.3) を強制し、共通暗号がない場合 TLS Alert 40 (handshake_failure) でハンドシェイクを中断します。両モードを 1 リクエスト内で並列実行します。",
        extra: {
          clientOfferedCiphersOriginal: offeredOriginal,
          clientCiphersAfterMitm: ciphersAfterMitm,
          vulnerableServerCiphers: vulnerableCiphers,
          defendedServerCiphers: defendedCiphers,
          vulnerableNegotiatedCipher: vulnerableNegotiated,
          vulnerableSessionEstablished,
          defendedHandshakeFailure,
          defendedAlert: "handshake_failure",
        } satisfies TlsWeakCipherExtra,
        payload: {
          params: {},
          result: {
            clientOfferedCiphersOriginal: offeredOriginal,
            clientCiphersAfterMitm: ciphersAfterMitm,
            vulnerableNegotiatedCipher: vulnerableNegotiated,
            vulnerableSessionEstablished,
            defendedHandshakeFailure,
          },
        },
      };
    },
  }),
);
