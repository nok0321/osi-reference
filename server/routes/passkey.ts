import { Hono } from "hono";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import { v4 as uuidv4 } from "uuid";
import { getDb } from "../db/schema.js";
import {
  parseBody,
  webauthnUsernameSchema,
  webauthnRegisterVerifySchema,
  passkeyAuthVerifySchema,
  passkeyAttackPhishingOriginBindingSchema,
  passkeyAttackCloudSyncCompromiseSchema,
  passkeyAttackCrossDeviceMitmSchema,
} from "../validation.js";
import type { UserRow, WebAuthnCredentialRow } from "../../shared/api-types.js";
import { createTtlStore } from "../utils/ttl-store.js";
import { runAttackScenario, sanitizeForDisplay } from "../utils/attack-runner.js";

export const passkeyRoutes = new Hono();

/** Safely parse the `transports` JSON column — returns undefined if missing or malformed. */
function parseTransports(raw: string | null | undefined): string[] | undefined {
  if (!raw) return undefined;
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

// ── Passkey Relying Party 設定 SSoT (ROB-FIDO2-5 / WEBAUTHN_RP 同パターン) ──
// 攻撃シミュレーションシード (PASSKEY_DEMO_CONSTANTS) と同じ値を共有することで、
// 一方を変更し忘れて正常系/攻撃系で異なる origin を検証してしまう事故を防ぐ。
// `as const satisfies` で readonly 化し、攻撃ハンドラ側からも参照する。
const PASSKEY_RP = {
  name: "OSI Reference Demo",
  id: "localhost",
  origin: "http://localhost:3000",
} as const satisfies Readonly<{ name: string; id: string; origin: string }>;

const RP_NAME = PASSKEY_RP.name;
const RP_ID = PASSKEY_RP.id;
const ORIGIN = PASSKEY_RP.origin;

// ── Challenge stores ──
// Registration: keyed by username (same as existing webauthn.ts)
const registerChallenges = createTtlStore<string>({ ttlMs: 5 * 60 * 1000 });
// Usernameless auth: keyed by sessionId (uuid)
const authChallenges = createTtlStore<string>({ ttlMs: 5 * 60 * 1000 });

// ── POST /register/options ──
passkeyRoutes.post("/register/options", async (c) => {
  const parsed = await parseBody(c, webauthnUsernameSchema);
  if ("error" in parsed) return parsed.error;
  const { username } = parsed.data;
  const trace = c.get("trace");
  const db = getDb();

  // Get-or-create user (WEBAUTHN_ONLY placeholder, same as existing webauthn.ts)
  let user = db
    .prepare("SELECT id, username FROM users WHERE username = ?")
    .get(username) as Pick<UserRow, "id" | "username"> | undefined;
  if (!user) {
    db.prepare(
      "INSERT INTO users (username, password_hash) VALUES (?, ?)"
    ).run(username, "WEBAUTHN_ONLY");
    user = db
      .prepare("SELECT id, username FROM users WHERE username = ?")
      .get(username) as Pick<UserRow, "id" | "username"> | undefined;
    trace.addDbQuery({
      sql: "INSERT INTO users (username, password_hash) VALUES (?, 'WEBAUTHN_ONLY')",
      params: [username],
      ms: 0,
    });
  }

  // Existing credentials for exclusion (E-3: 攻撃シミュレーション用クレデンシャルを除外)
  const existingCreds = db
    .prepare(
      "SELECT credential_id, public_key, counter, transports FROM webauthn_credentials WHERE user_id = ? AND is_attack_sim = 0"
    )
    .all(user!.id) as WebAuthnCredentialRow[];

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userName: username,
    userID: new TextEncoder().encode(String(user!.id)),
    attestationType: "none",
    excludeCredentials: existingCreds.map((cred) => ({
      id: cred.credential_id,
      transports: parseTransports(cred.transports) as never,
    })),
    authenticatorSelection: {
      residentKey: "required",
      userVerification: "required",
    },
  });

  registerChallenges.set(username, options.challenge);

  trace.addCryptoOp({
    op: "generateChallenge",
    input: `rpId="${RP_ID}", user="${username}"`,
    output: options.challenge,
    algo: "crypto.getRandomValues(32 bytes) → base64url",
    detail:
      "Random challenge to prevent replay. Note: residentKey = 'required' — authenticator MUST store a discoverable credential containing the user handle internally.",
  });

  trace.addCryptoOp({
    op: "authenticatorSelection",
    input: JSON.stringify(options.authenticatorSelection || {}),
    output: 'residentKey: "required", userVerification: "required"',
    algo: "FIDO2 Passkey Policy",
    detail:
      "Unlike traditional WebAuthn (residentKey: 'preferred'), Passkey REQUIRES a discoverable credential. The authenticator stores the credential locally so the user can sign in without entering a username.",
  });

  trace.addSessionOp({
    action: "STORE_CHALLENGE",
    data: {
      username,
      challenge: options.challenge,
      purpose: "passkey-registration",
    },
  });

  return c.json({
    success: true,
    data: {
      options,
      explanation: {
        challenge:
          "Random bytes from server — authenticator must sign this to prove possession",
        rp: { id: RP_ID, name: RP_NAME },
        residentKey: "required — credential will be stored on device for usernameless auth",
        excludeCredentials: `${existingCreds.length} existing credential(s) excluded`,
      },
    },
  });
});

// ── POST /register/verify ──
passkeyRoutes.post("/register/verify", async (c) => {
  const parsed = await parseBody(c, webauthnRegisterVerifySchema);
  if ("error" in parsed) return parsed.error;
  const { username, response: attResponse } = parsed.data;
  const trace = c.get("trace");
  const db = getDb();

  const expectedChallenge = registerChallenges.get(username);
  if (!expectedChallenge) {
    return c.json(
      { success: false, error: "No challenge found or challenge expired — restart registration" },
      400
    );
  }

  try {
    const verification = await verifyRegistrationResponse({
      response: attResponse as any,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
    });

    const deviceType = verification.registrationInfo?.credentialDeviceType || "unknown";
    const backedUp = verification.registrationInfo?.credentialBackedUp || false;

    trace.addCryptoOp({
      op: "verifyPasskeyRegistration",
      input: "clientDataJSON + attestationObject",
      output: verification.verified ? "VERIFIED ✓" : "FAILED ✗",
      algo: "FIDO2 Attestation Verification",
      detail:
        "Verify challenge signature, check origin/rpId, extract public key from attestation",
    });

    trace.addCryptoOp({
      op: "credentialDeviceType",
      input: `flags from authenticatorData`,
      output: `${deviceType} (backed up: ${backedUp})`,
      algo: "WebAuthn Level 2 flags: BE (Backup Eligible) + BS (Backup State)",
      detail:
        deviceType === "multiDevice"
          ? "MultiDevice credential — this passkey can sync across devices via iCloud Keychain, Google Password Manager, 1Password, etc."
          : "SingleDevice credential — this passkey is locked to this specific authenticator (e.g., hardware security key)",
    });

    if (verification.verified && verification.registrationInfo) {
      const { credential } = verification.registrationInfo;
      const user = db
        .prepare("SELECT id FROM users WHERE username = ?")
        .get(username) as Pick<UserRow, "id"> | undefined;

      // E-3: 正常系登録は is_attack_sim=0 (DEFAULT) で明示。攻撃シミュレーションは is_attack_sim=1 で書き込み、
      //      正常系の SELECT/UPDATE と分離する。
      db.prepare(
        "INSERT INTO webauthn_credentials (credential_id, user_id, public_key, counter, transports, is_attack_sim) VALUES (?, ?, ?, ?, ?, 0)"
      ).run(
        credential.id,
        user!.id,
        Buffer.from(credential.publicKey).toString("base64"),
        credential.counter,
        JSON.stringify((attResponse as any).response?.transports || [])
      );

      trace.addDbQuery({
        sql: "INSERT INTO webauthn_credentials (credential_id, user_id, public_key, counter, transports, is_attack_sim) VALUES (..., 0)",
        params: [credential.id, user!.id],
        ms: 0,
      });

      registerChallenges.delete(username);

      return c.json({
        success: true,
        data: {
          verified: true,
          credentialId: credential.id,
          credentialDeviceType: deviceType,
          credentialBackedUp: backedUp,
          publicKeyPreview:
            Buffer.from(credential.publicKey)
              .toString("base64")
              .substring(0, 40) + "...",
        },
      });
    }

    return c.json({ success: false, error: "Verification failed" }, 400);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Unknown error";
    return c.json({ success: false, error: message }, 400);
  }
});

// ── POST /auth/options (USERNAMELESS!) ──
passkeyRoutes.post("/auth/options", async (c) => {
  const trace = c.get("trace");

  const sessionId = uuidv4();

  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    allowCredentials: [], // Empty — browser shows all available passkeys for this site
    userVerification: "required",
  });

  authChallenges.set(sessionId, options.challenge);

  trace.addCryptoOp({
    op: "generateAuthChallenge",
    input: `rpId="${RP_ID}", allowCredentials=[] (empty!)`,
    output: options.challenge,
    algo: "crypto.getRandomValues(32 bytes) → base64url",
    detail:
      "Empty allowCredentials — the server does NOT specify which credentials to use. The browser will consult its own credential store and present all passkeys for this site. This is the key difference from traditional WebAuthn: the server doesn't know who the user is yet!",
  });

  trace.addSessionOp({
    action: "STORE_AUTH_SESSION",
    data: {
      sessionId,
      challenge: options.challenge,
      purpose: "passkey-usernameless-auth",
      note: "Server only stores the challenge. User identity will be resolved after authentication from the credential's userHandle.",
    },
  });

  return c.json({
    success: true,
    data: {
      options,
      sessionId,
      explanation: {
        allowCredentials:
          "Empty — browser presents ALL passkeys for this site (no account enumeration)",
        userVerification: "required — biometric/PIN mandatory",
      },
    },
  });
});

// ── POST /auth/verify ──
passkeyRoutes.post("/auth/verify", async (c) => {
  const parsed = await parseBody(c, passkeyAuthVerifySchema);
  if ("error" in parsed) return parsed.error;
  const { sessionId, response: authResponse } = parsed.data;
  const trace = c.get("trace");
  const db = getDb();

  const expectedChallenge = authChallenges.get(sessionId);
  if (!expectedChallenge) {
    return c.json(
      { success: false, error: "Session expired or invalid — restart auth" },
      400
    );
  }

  trace.addSessionOp({
    action: "LOOKUP_AUTH_SESSION",
    data: { sessionId, found: true },
  });

  // Look up credential by ID ONLY (no user filter — usernameless!)
  // E-3: 攻撃シミュレーションクレデンシャル (is_attack_sim=1) は除外
  const credentialId = (authResponse as any).id;
  const t0 = performance.now();
  const cred = db
    .prepare(
      "SELECT credential_id, user_id, public_key, counter FROM webauthn_credentials WHERE credential_id = ? AND is_attack_sim = 0"
    )
    .get(credentialId) as
    | Pick<WebAuthnCredentialRow, "credential_id" | "user_id" | "public_key" | "counter">
    | undefined;
  trace.addDbQuery({
    sql: "SELECT ... FROM webauthn_credentials WHERE credential_id = ? AND is_attack_sim = 0  -- NO user_id filter (usernameless), but attack-sim rows excluded",
    params: [credentialId],
    rows: cred ? [{ credential_id: cred.credential_id, user_id: cred.user_id, counter: cred.counter }] : [],
    ms: performance.now() - t0,
  });

  if (!cred) {
    authChallenges.delete(sessionId);
    return c.json({ success: false, error: "Credential not registered on this server" }, 400);
  }

  // Resolve user from credential's user_id
  const t1 = performance.now();
  const user = db
    .prepare("SELECT id, username FROM users WHERE id = ?")
    .get(cred.user_id) as Pick<UserRow, "id" | "username"> | undefined;
  trace.addDbQuery({
    sql: "SELECT id, username FROM users WHERE id = ?",
    params: [cred.user_id],
    rows: user ? [user] : [],
    ms: performance.now() - t1,
  });

  if (!user) {
    authChallenges.delete(sessionId);
    return c.json({ success: false, error: "User not found for this credential" }, 400);
  }

  // Decode userHandle from the auth response to cross-check identity
  const rawUserHandle = (authResponse as any).response?.userHandle;
  if (rawUserHandle) {
    const decoded = Buffer.from(rawUserHandle, "base64url").toString("utf-8");
    trace.addSessionOp({
      action: "RESOLVE_IDENTITY_FROM_USERHANDLE",
      data: {
        userHandle_base64url: rawUserHandle,
        decoded_userId: decoded,
        resolved_username: user.username,
        note: "The server does NOT receive a username — instead, the authenticator returns the userHandle (set during registration) which the server maps to a user record. This is how usernameless authentication works!",
      },
    });
  }

  try {
    const verification = await verifyAuthenticationResponse({
      response: authResponse as any,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      credential: {
        id: cred.credential_id,
        publicKey: Buffer.from(cred.public_key, "base64"),
        counter: cred.counter,
      },
    });

    trace.addCryptoOp({
      op: "verifyPasskeyAuth",
      input: "signature over clientDataJSON + authenticatorData",
      output: verification.verified ? "VERIFIED ✓" : "FAILED ✗",
      algo: "ECDSA / RSA (credential-dependent)",
      detail:
        "Verify signature with stored public key, check counter increment, confirm rpIdHash matches",
    });

    if (verification.verified) {
      const newCounter = verification.authenticationInfo.newCounter;

      // Clone detection
      if (newCounter > 0 && newCounter <= cred.counter) {
        trace.addCryptoOp({
          op: "counterCloneDetection",
          input: `oldCounter=${cred.counter}, newCounter=${newCounter}`,
          output: "⚠ CLONE DETECTED",
          algo: "Counter Verification",
          detail:
            "Counter did not increment — possible cloned authenticator",
        });
        authChallenges.delete(sessionId);
        return c.json(
          { success: false, error: "Counter did not increment — possible clone" },
          403
        );
      }

      // E-3: 攻撃シミュレーションクレデンシャル (is_attack_sim=1) は更新対象外
      db.prepare(
        "UPDATE webauthn_credentials SET counter = ? WHERE credential_id = ? AND is_attack_sim = 0"
      ).run(newCounter, cred.credential_id);

      authChallenges.delete(sessionId);

      return c.json({
        success: true,
        data: {
          verified: true,
          username: user.username,
          credentialId: cred.credential_id,
          counter: { old: cred.counter, new: newCounter },
        },
      });
    }

    authChallenges.delete(sessionId);
    return c.json({ success: false, error: "Authentication failed" }, 401);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Unknown error";
    authChallenges.delete(sessionId);
    return c.json({ success: false, error: message }, 400);
  }
});

// ── GET /credentials (reuse existing webauthn credentials endpoint format) ──
// E-3: 攻撃シミュレーションクレデンシャル (is_attack_sim=1) は表示しない
passkeyRoutes.get("/credentials", (c) => {
  const db = getDb();
  const creds = db
    .prepare(
      `SELECT wc.credential_id, wc.counter, wc.created_at, u.username
       FROM webauthn_credentials wc JOIN users u ON wc.user_id = u.id
       WHERE wc.is_attack_sim = 0`
    )
    .all();
  return c.json({ success: true, data: { credentials: creds } });
});

// ════════════════════════════════════════════════════════════════════════════════
// 攻撃デモ (Phase 2 第十二コミット — passkey タブ)
// ────────────────────────────────────────────────────────────────────────────────
// DESIGN/21-attack-passkey.md の 3 シナリオ実装。
//   A: passkey-phishing-origin-binding  (CWE-290/346, CAPEC-89/194)
//   B: passkey-cloud-sync-compromise    (CWE-287, CAPEC-560)
//   C: passkey-cross-device-mitm        (CWE-300, CAPEC-94)
//
// 設計判断 (E-1/E-2/E-3 確立規約):
// - E-1 ジェネリック化: AttackResult<TExtra> でシナリオ固有データを `extra` 配下に格納
// - E-2 両モード並列実行: 1 リクエストで脆弱+堅牢を必ず両方実行、outcome 常に "succeeded"
// - E-3 is_attack_sim: webauthn_credentials.is_attack_sim 列で正常系と分離 (FIDO2 と同じ)
//
// DESIGN/21 spec drift 整合 (Phase 2 規約適用):
// - DESIGN §4.x の outcome="blocked" は E-2 で outcome="succeeded" に統一 (AttackStep.status="blocked" で表現)
// - DESIGN §4.x の 4 ステップ + intercept/replay kind は 5 ステップ完全形 (probe→tamper→forge→exploit→verify) に統一
// - DESIGN §1.2 / §8.1 の `server/routes/attack-passkey.ts` 新規ファイルは inline (mfa/fido2 同パターン)
// - DESIGN §4.x.7 リクエスト body フィールド (`username`/`fakeOrigin`/`deviceType`/`cloudAccountProtection`/
//   `attackerLocation`) は廃止 (z.object({}) 統一、ROB-FIND-006 / ROB-KERB-1 教訓)
// ════════════════════════════════════════════════════════════════════════════════

// ── 共通シード (immutable) ──
// ROB-FIND-007 / ROB-FIDO2-5 / WEBAUTHN_DEMO_CONSTANTS と同パターン。
// PASSKEY_RP から派生して SSoT 一本化 (rpId / expectedOrigin の二重定義回避)。
const PASSKEY_DEMO_CONSTANTS = {
  rpId: PASSKEY_RP.id,
  expectedOrigin: PASSKEY_RP.origin,
  attackerOrigin: "http://attacker.example",
  victimUsername: "seed_alice",
  attackerUsername: "attacker_charlie",
  // 教育用ダミーチャレンジ (base64url 32 バイト相当)。実 generateAuthenticationOptions の出力ではなく
  // 固定文字列で「攻撃者が観測したチャレンジ」を表現する (WEBAUTHN_DEMO_CONSTANTS.demoChallenge と同パターン)。
  demoChallenge: "cGFzc2tleS1kZW1vLWNoYWxsZW5nZS0xMjM0NTY3ODkwYWJjZGVm",
  // 教育用 deviceType ラベル — 同期パスキー (multiDevice) と デバイス固有 (singleDevice) を表現
  multiDeviceLabel: "multiDevice",
  singleDeviceLabel: "singleDevice",
  // 弱クラウドアカウント保護のシミュレーション (実値は使わず、ラベルのみ表示)
  weakCloudConfigLabel: "弱パスワード + MFA なし",
  weakCloudConfigLabelEn: "weak password + no MFA",
  strongCloudConfigLabel: "強パスワード (16文字+) + MFA あり",
  strongCloudConfigLabelEn: "strong password (16+ chars) + MFA enabled",
  // BLE / tunnel key 防御層のラベル (CTAP2.2 ハイブリッドフロー)
  bleProximityRangeMeters: 10,
  tunnelKeyAlgo: "ECDH on QR-derived ephemeral key (CTAP 2.2 hybrid)",
  // 痕跡削除パターン用クレデンシャル ID プレフィックス (FIDO2 challenge-replay と区別)
  attackCredentialIdPrefix: "attack-passkey-cloud-sync-",
} as const satisfies Readonly<{
  rpId: string;
  expectedOrigin: string;
  attackerOrigin: string;
  victimUsername: string;
  attackerUsername: string;
  demoChallenge: string;
  multiDeviceLabel: string;
  singleDeviceLabel: string;
  weakCloudConfigLabel: string;
  weakCloudConfigLabelEn: string;
  strongCloudConfigLabel: string;
  strongCloudConfigLabelEn: string;
  bleProximityRangeMeters: number;
  tunnelKeyAlgo: string;
  attackCredentialIdPrefix: string;
}>;

// ════════════════════════════════════════════════════════════════════════════════
// Scenario A: フィッシング耐性デモ (origin バインディング)
// ────────────────────────────────────────────────────────────────────────────────
// 同期パスキー (multiDevice) でも origin バインディングは保たれることを示す。
// vulnerable: expectedOrigin チェック省略 → attacker.example 署名を受理
// defended:   expectedOrigin 厳密一致 → 拒否 (passkey_origin_validation_enforced)
// DB 書き込みなし (in-memory simulation only)
// ════════════════════════════════════════════════════════════════════════════════
type PasskeyPhishingOriginExtra = {
  attackerOrigin: string;
  expectedOrigin: string;
  rpId: string;
  vulnerableAccepted: boolean;
  defendedRejected: boolean;
  victimUsername: string;
  victimSeedFound: boolean;
  /** Passkey 文脈で multiDevice / singleDevice 両方で挙動が同じであることを示すフラグ。 */
  multiDeviceAndSingleDeviceBehaveSame: boolean;
};

passkeyRoutes.post("/attack/phishing-origin-binding", (c) =>
  runAttackScenario<typeof passkeyAttackPhishingOriginBindingSchema, PasskeyPhishingOriginExtra>(c, {
    schema: passkeyAttackPhishingOriginBindingSchema,
    scenarioId: "passkey-phishing-origin-binding",
    tabId: "passkey",
    async handler({ db, recordStep, trace }) {
      // seed_alice の user_id を取得 (DB 書き込みはしないが、教育表示の victim 識別子として使用)
      const aliceUser = db
        .prepare("SELECT id, username FROM users WHERE username = ?")
        .get(PASSKEY_DEMO_CONSTANTS.victimUsername) as { id: number; username: string } | undefined;
      const victimSeedFound = !!aliceUser;

      const safeAttackerOrigin = sanitizeForDisplay(PASSKEY_DEMO_CONSTANTS.attackerOrigin, 256);
      const safeExpectedOrigin = sanitizeForDisplay(PASSKEY_DEMO_CONSTANTS.expectedOrigin, 256);

      // ── Step 1: probe — フィッシングページが正規サーバーから auth options を中継取得
      recordStep({
        id: "passkey-phish-1",
        kind: "probe",
        label: "Phishing page relays usernameless auth options request to legitimate server",
        labelJa: "フィッシングページが正規サーバーへユーザー名なし認証オプション要求を中継",
        status: "success",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/passkey/auth/options (simulated relay via attacker.example)",
            body: {},
          },
          response: {
            status: 200,
            body: {
              sessionId: "<simulated-session-id>",
              options: {
                challenge: PASSKEY_DEMO_CONSTANTS.demoChallenge.substring(0, 16) + "...",
                rpId: PASSKEY_DEMO_CONSTANTS.rpId,
                allowCredentials: [],
              },
            },
          },
        },
        detailJa:
          "攻撃者は正規サーバーからユーザー名なし認証 (allowCredentials: []) のチャレンジを取得し、フィッシングページに転送します。Passkey の usernameless 認証でも origin バインディングは同じ防御原理で機能します。",
        detail:
          "The attacker relays the usernameless auth challenge (allowCredentials: []) from the legitimate server to the phishing page. Passkey's usernameless auth still relies on the same origin-binding defense.",
      });

      // ── Step 2: tamper — Authenticator が attacker.example origin で clientDataJSON に署名 (概念)
      trace.addCryptoOp({
        op: "passkey_clientDataJSON_signature_simulation",
        input: `origin=${safeAttackerOrigin}, challenge=${PASSKEY_DEMO_CONSTANTS.demoChallenge.substring(0, 16)}..., deviceType=${PASSKEY_DEMO_CONSTANTS.multiDeviceLabel}/${PASSKEY_DEMO_CONSTANTS.singleDeviceLabel}`,
        output: "<simulated_signature> (would be ECDSA over clientDataJSON+authenticatorData)",
        algo: "WebAuthn signing simulation (no real authenticator invoked)",
        detail:
          "Educational simulation: Both multiDevice (synced) and singleDevice (device-bound) passkeys produce identical origin-bound signatures. The deviceType does NOT affect phishing resistance.",
      });
      recordStep({
        id: "passkey-phish-2",
        kind: "tamper",
        label: "Authenticator signs clientDataJSON with attacker.example origin (multiDevice and singleDevice behave identically)",
        labelJa: "Authenticator が attacker.example origin で clientDataJSON に署名 (multiDevice / singleDevice いずれも同様の挙動)",
        status: "success",
        payload: {
          type: "generic",
          data: {
            simulationNote:
              "実 navigator.credentials.get() は呼び出していません — サーバー側で『もし署名が来たら』のフローを再現します。",
            clientDataJSON: {
              type: "webauthn.get",
              challenge: PASSKEY_DEMO_CONSTANTS.demoChallenge.substring(0, 16) + "...",
              origin: safeAttackerOrigin,
            },
            expectedOrigin: safeExpectedOrigin,
            originMismatch: true,
            deviceTypesEvaluated: [
              PASSKEY_DEMO_CONSTANTS.multiDeviceLabel,
              PASSKEY_DEMO_CONSTANTS.singleDeviceLabel,
            ],
          },
        },
        detailJa:
          "攻撃者ページが Authenticator にチャレンジを渡し、clientDataJSON.origin に attacker.example が記録されます。multiDevice (同期) でも singleDevice (デバイス固有) でも、同じ秘密鍵が同じ origin で署名するため挙動は完全に同一です。",
        detail:
          "The attacker page passes the challenge to the Authenticator. The clientDataJSON.origin field is recorded as attacker.example. multiDevice (synced) and singleDevice (device-bound) credentials behave identically — same key, same origin, same signature.",
      });

      // ── Step 3: forge — 攻撃者が forged-origin assertion を /api/passkey/auth/verify に送信
      recordStep({
        id: "passkey-phish-3",
        kind: "forge",
        label: "Attacker submits forged-origin assertion to passkey verify endpoint",
        labelJa: "攻撃者が origin 偽装 assertion を passkey verify エンドポイントへ送信",
        status: "success",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/passkey/auth/verify (simulated)",
            body: {
              sessionId: "<simulated-session-id>",
              response: {
                clientDataJSON_origin: safeAttackerOrigin,
                note: "Signature simulated; real verifyAuthenticationResponse not invoked in this demo.",
              },
            },
          },
          tamperedFields: ["response.clientDataJSON.origin"],
        },
        detailJa:
          "攻撃者は偽装 origin を含む assertion をサーバーへ送信します。脆弱版と堅牢版で挙動が分岐します。",
        detail:
          "The attacker sends an assertion with a forged origin to the server. Vulnerable and defended paths diverge from here.",
      });

      // ── Step 4: exploit (脆弱モード) — expectedOrigin チェック省略で受理
      // R-MEDIUM-1 教訓: bare literal `true` を避け、SSoT (PASSKEY_DEMO_CONSTANTS) からの
      // 派生条件で表現する。シナリオの教材意図は「attacker.example != http://localhost:3000」
      // という origin 不一致が起こり続けることに依存しており、将来 attackerOrigin が
      // expectedOrigin と一致するように変わると教材として破綻する。
      // この派生式により「シード値変更 → flag 自動的に false」が保証される。
      const fakeOriginNeverMatchesExpected =
        PASSKEY_DEMO_CONSTANTS.attackerOrigin !== PASSKEY_DEMO_CONSTANTS.expectedOrigin;
      // 脆弱パス: origin チェック省略 → 不一致でも受理 (fake != expected を観測した時のみ "受理が起きる")
      const vulnerableAccepted = fakeOriginNeverMatchesExpected;
      recordStep({
        id: "passkey-phish-4",
        kind: "exploit",
        label: "Vulnerable: server skips expectedOrigin — accepts forged-origin assertion",
        labelJa: "脆弱版: サーバーが expectedOrigin チェックを省略 — origin 偽装 assertion を受理",
        status: "success",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/passkey/auth/verify (vulnerable variant — no origin check)",
          },
          response: {
            status: 200,
            body: {
              verified: true,
              note: "Vulnerable: a server omitting expectedOrigin would accept the assertion despite the origin mismatch. This is true regardless of multiDevice/singleDevice deviceType.",
            },
          },
        },
        detailJa:
          "この実装は脆弱です: verifyAuthenticationResponse() に expectedOrigin を渡さない実装は、attacker.example で署名された clientDataJSON を受理してしまい、フィッシング攻撃が成立します。同期パスキーを使っていてもこの脆弱性は変わりません。",
        detail:
          "This implementation is vulnerable: a server that omits expectedOrigin would accept a clientDataJSON signed at attacker.example. Whether the user has a synced passkey or a device-bound one makes no difference.",
      });

      // ── Step 5: verify (堅牢モード) — expectedOrigin 厳密一致で拒否
      trace.addCryptoOp({
        op: "passkey_expectedOrigin_strict_compare",
        input: `clientDataJSON.origin=${safeAttackerOrigin}, expectedOrigin=${safeExpectedOrigin}`,
        output: "MISMATCH → throw Error",
        algo: "@simplewebauthn/server verifyAuthenticationResponse origin check",
        detail:
          "Defended: passkey.ts passes expectedOrigin to verifyAuthenticationResponse(). The library compares clientDataJSON.origin via strict string-equality and throws on mismatch. Synced passkeys do NOT relax this check — origin binding is preserved across all devices.",
      });
      // R-MEDIUM-1 教訓: bare literal `true` を避ける。fakeOriginNeverMatchesExpected と同じ
      // 不変条件 (attackerOrigin != expectedOrigin) で「拒否が起きる」を表現する SSoT 派生。
      const defendedRejected = fakeOriginNeverMatchesExpected;
      recordStep({
        id: "passkey-phish-5",
        kind: "verify",
        label: "Defended: expectedOrigin strict-equality rejects attacker.example (synced passkey unchanged)",
        labelJa: "堅牢版: expectedOrigin 厳密一致が attacker.example を拒否 (同期パスキーでも同じ防御)",
        status: "blocked",
        payload: {
          type: "http",
          response: {
            status: 400,
            body: {
              error: `Origin mismatch: expected ${safeExpectedOrigin}, got ${safeAttackerOrigin}`,
              blockedBy: "passkey_origin_validation_enforced",
              note: "Defended: server compares clientDataJSON.origin === expectedOrigin and throws on mismatch. multiDevice / singleDevice behave identically.",
            },
          },
        },
        detailJa:
          "堅牢実装は passkey.ts の verifyAuthenticationResponse() に expectedOrigin を渡し、@simplewebauthn/server が clientDataJSON.origin を厳密比較します。attacker.example != http://localhost:3000 で例外がスローされ、サーバーは 400 を返します。Passkey の credential 署名は RP ID に暗号的に紐付いているため、同期パスキー (multiDevice) であっても別オリジンからは使用できません。",
        detail:
          "The defended implementation passes expectedOrigin to verifyAuthenticationResponse() in passkey.ts; @simplewebauthn/server compares clientDataJSON.origin via string-equality. attacker.example != http://localhost:3000 triggers an exception → 400. The passkey signature is cryptographically bound to the RP ID, so even synced (multiDevice) credentials cannot be used from another origin.",
      });

      return {
        blockedBy: "passkey_origin_validation_enforced",
        summary:
          "A vulnerable server omitting the expectedOrigin check would accept a clientDataJSON signed at attacker.example. The defended implementation enforces strict origin comparison via @simplewebauthn/server, blocking the phishing attempt. Critically, multiDevice (synced) and singleDevice passkeys behave identically — origin binding is not weakened by passkey synchronization.",
        summaryJa:
          "この実装は脆弱です: expectedOrigin チェックを省略するサーバーは attacker.example で署名された clientDataJSON を受理してしまいます。堅牢実装は @simplewebauthn/server による厳密一致検証で origin 偽装を阻止します。同期パスキー (multiDevice) を使用していても、クレデンシャルの署名は RP ID に暗号的に紐付いており origin バインディングは失われません。",
        extra: {
          attackerOrigin: safeAttackerOrigin,
          expectedOrigin: safeExpectedOrigin,
          rpId: PASSKEY_DEMO_CONSTANTS.rpId,
          vulnerableAccepted,
          defendedRejected,
          victimUsername: PASSKEY_DEMO_CONSTANTS.victimUsername,
          victimSeedFound,
          multiDeviceAndSingleDeviceBehaveSame: true,
        } satisfies PasskeyPhishingOriginExtra,
        payload: {
          params: {},
          result: {
            attackerOriginPreview: safeAttackerOrigin,
            expectedOriginPreview: safeExpectedOrigin,
            vulnerableAccepted,
            defendedRejected,
            victimSeedFound,
          },
        },
      };
    },
  })
);

// ════════════════════════════════════════════════════════════════════════════════
// Scenario B: クラウド同期経路の侵害 (シミュレーション)
// ────────────────────────────────────────────────────────────────────────────────
// 同期パスキー (multiDevice) はクラウドアカウントのセキュリティを前提とする。
// vulnerable (弱クラウド保護: 弱パスワード + MFA なし): 攻撃者がクラウド侵害 → 同期パスキー複製成立
// defended  (強クラウド保護: 強パスワード + MFA あり): クラウド侵害自体が阻止される
//                                                       (cloud_account_strong_password_and_mfa_enforced)
// 教育目的: 脆弱パスで is_attack_sim=1 のクレデンシャルを INSERT し「攻撃者が複製成立した」状態を観測可能にする。
//           handler 末尾で DELETE して累積回避 (SEC-FIDO2-2 痕跡削除パターン)。
// ════════════════════════════════════════════════════════════════════════════════
type PasskeyCloudSyncCompromiseExtra = {
  /** 弱クラウド保護側: 攻撃者がクラウドアカウントへログイン成立 (シミュレーション)。 */
  vulnerableCloudAccountCompromised: boolean;
  /** 弱クラウド保護側: 同期パスキーのクラウド複製が成立 (シミュレーション)。 */
  vulnerableSyncedPasskeyCloned: boolean;
  /** 強クラウド保護側: クラウドアカウント侵害が阻止される。 */
  defendedCloudAccessBlocked: boolean;
  victimUsername: string;
  attackerUsername: string;
  victimSeedFound: boolean;
  /** ROB-FIDO2-3 同パターン: 教育的可視化のため脆弱パスで INSERT 成立を観測したか。
   *  失敗時 (FK 制約 / SQLITE_BUSY 等) は false。SEC-FIDO2-2 で handler 末尾で必ず DELETE される。 */
  attackCredentialInserted: boolean;
  /** 弱/強クラウド保護のラベル比較表示用 (UI で並列描画)。 */
  cloudConfigComparison: {
    vulnerable: { ja: string; en: string };
    defended: { ja: string; en: string };
  };
  /** DESIGN/04 §3.3 / DESIGN/21 §4.2.4 規定の教育用シミュレーション注記。 */
  simulationNote: { ja: string; en: string };
};

passkeyRoutes.post("/attack/cloud-sync-compromise", (c) =>
  runAttackScenario<typeof passkeyAttackCloudSyncCompromiseSchema, PasskeyCloudSyncCompromiseExtra>(c, {
    schema: passkeyAttackCloudSyncCompromiseSchema,
    scenarioId: "passkey-cloud-sync-compromise",
    tabId: "passkey",
    async handler({ db, recordStep, trace }) {
      // seed_alice の user_id を取得 (脆弱パスで is_attack_sim=1 クレデンシャル INSERT に必要)
      const aliceUser = db
        .prepare("SELECT id, username FROM users WHERE username = ?")
        .get(PASSKEY_DEMO_CONSTANTS.victimUsername) as { id: number; username: string } | undefined;
      const victimSeedFound = !!aliceUser;

      // ── Step 1: probe — 攻撃者が被害者のクラウドアカウント (iCloud/Google) を狙う
      recordStep({
        id: "passkey-cloud-1",
        kind: "probe",
        label: "Attacker probes victim's cloud account (iCloud / Google Password Manager / 1Password)",
        labelJa: "攻撃者が被害者のクラウドアカウント (iCloud / Google Password Manager / 1Password 等) を調査",
        status: "success",
        payload: {
          type: "generic",
          data: {
            target: "synced-passkey backend (cloud account)",
            simulationNote:
              "実際の iCloud Keychain / Google Password Manager / 1Password 等の内部実装には触れず、概念的な侵害経路のみシミュレートします。",
            note: "This step probes the cloud account, not passkey.ts itself. Passkey synchronization is a feature of the platform credential manager (iCloud Keychain, Google Password Manager, etc.), and the security of synced passkeys depends on the security of that cloud account.",
          },
        },
        detailJa:
          "攻撃者は被害者の同期パスキーを管理しているクラウドアカウントを攻撃対象とします。これはサーバー実装 (passkey.ts) の脆弱性ではなく、クラウドアカウント自体の保護強度に依存する論点です。",
        detail:
          "The attacker targets the cloud account that synchronizes the victim's passkeys. This is NOT a vulnerability in the server implementation (passkey.ts) — it depends on the security posture of the cloud account itself.",
      });

      // ── Step 2: tamper — 認証強度の比較 (弱クラウド vs 強クラウド)
      recordStep({
        id: "passkey-cloud-2",
        kind: "tamper",
        label: "Compare cloud account authentication strengths (weak vs strong)",
        labelJa: "クラウドアカウント認証強度の比較 (弱 vs 強)",
        status: "success",
        payload: {
          type: "generic",
          data: {
            vulnerableConfig: {
              ja: PASSKEY_DEMO_CONSTANTS.weakCloudConfigLabel,
              en: PASSKEY_DEMO_CONSTANTS.weakCloudConfigLabelEn,
              outcome: "easy to compromise (brute-force / credential stuffing)",
            },
            defendedConfig: {
              ja: PASSKEY_DEMO_CONSTANTS.strongCloudConfigLabel,
              en: PASSKEY_DEMO_CONSTANTS.strongCloudConfigLabelEn,
              outcome: "phishing-resistant MFA blocks unauthorized access",
            },
          },
        },
        detailJa:
          "クラウドアカウントの保護強度が同期パスキーのセキュリティの前提条件となります。弱パスワードと MFA なしの組み合わせはリスクが高く、強パスワード + MFA は同期パスキーの安全性を維持します。",
        detail:
          "The strength of the cloud account is a prerequisite for synced passkey security. Weak password + no MFA is high-risk; strong password + MFA preserves the security of synchronized passkeys.",
      });

      // ── Step 3: forge — 攻撃者がクラウド侵害を試みる (両モード共通の試行ステップ)
      recordStep({
        id: "passkey-cloud-3",
        kind: "forge",
        label: "Attacker attempts cloud account login with weak credentials (simulated)",
        labelJa: "攻撃者が弱い認証情報でクラウドアカウントへのログインを試行 (シミュレーション)",
        status: "success",
        payload: {
          type: "generic",
          data: {
            simulationNote:
              "実際のクラウドプロバイダ (Apple/Google/1Password) との通信は行いません。クラウド侵害の概念的フローを示す教育用シミュレーションです。",
            note: "This step does NOT attempt actual cloud login. It illustrates the conceptual attack path that diverges between weak and strong cloud account configurations.",
          },
        },
        detailJa:
          "攻撃者がクラウドアカウントへのログインを試みます。弱クラウド側ではアクセス成立、強クラウド側では MFA で阻止されます。",
        detail:
          "The attacker attempts to log into the cloud account. The weak cloud path succeeds; the strong cloud path is blocked by MFA.",
      });

      // ── Step 4: exploit (脆弱モード) — 弱クラウド: ログイン成立 → 同期パスキーのクラウド複製
      // 教育目的: 脆弱パスで is_attack_sim=1 のクレデンシャルを INSERT して
      // 「攻撃者デバイスにパスキーが複製された」状態を観測可能にする。
      // ROB-N1/N2 ガード: seed_alice 不在時は INSERT スキップ (FK 制約違反回避)。
      // ROB-FIDO2-1: INSERT を try/catch で囲い、UNIQUE/SQLITE_BUSY/FK 等の例外でハンドラ全体が
      //              500 にならないよう「失敗時 false 記録」設計に揃える。
      const vulnerableCloudAccountCompromised = true; // 弱クラウド側はログイン成立
      const attackCredentialId = `${PASSKEY_DEMO_CONSTANTS.attackCredentialIdPrefix}${uuidv4()}`;
      const attackCredentialPublicKey = "EDU_DEMO_CLONED_PUBKEY_FROM_SYNCED_PASSKEY_NOT_REAL";
      let attackCredentialInserted = false;
      let attackCredentialInsertError: string | null = null;
      if (aliceUser) {
        try {
          const t0 = performance.now();
          db.prepare(
            "INSERT OR IGNORE INTO webauthn_credentials (credential_id, user_id, public_key, counter, transports, is_attack_sim) VALUES (?, ?, ?, 0, ?, 1)"
          ).run(
            attackCredentialId,
            aliceUser.id,
            attackCredentialPublicKey,
            JSON.stringify(["internal", "hybrid"]),
          );
          trace.addDbQuery({
            sql: "INSERT OR IGNORE INTO webauthn_credentials (credential_id, user_id, public_key, counter, transports, is_attack_sim) VALUES (?, ?, ?, 0, ?, 1) -- simulated cloned synced passkey",
            params: [attackCredentialId, aliceUser.id, "<masked-public-key>", "[\"internal\",\"hybrid\"]"],
            ms: performance.now() - t0,
          });
          attackCredentialInserted = true;
        } catch (e) {
          attackCredentialInsertError = sanitizeForDisplay(
            e instanceof Error ? e.message : "Unknown DB error",
            128,
          );
          trace.addDbQuery({
            sql: "INSERT OR IGNORE INTO webauthn_credentials (failed: " + attackCredentialInsertError + ")",
            params: [attackCredentialId, aliceUser.id, "<masked-public-key>", "[\"internal\",\"hybrid\"]"],
            ms: 0,
          });
        }
      }
      const vulnerableSyncedPasskeyCloned = victimSeedFound ? attackCredentialInserted : false;

      recordStep({
        id: "passkey-cloud-4",
        kind: "exploit",
        label: "Vulnerable: weak cloud account compromised → synced passkey cloned to attacker's device (simulated)",
        labelJa: "脆弱版: 弱いクラウドアカウントが侵害される → 同期パスキーが攻撃者デバイスへ複製 (シミュレーション)",
        status: vulnerableCloudAccountCompromised && (victimSeedFound ? attackCredentialInserted : true) ? "success" : "failed",
        payload: {
          type: "generic",
          data: {
            simulationNote:
              "実際のクラウドプロバイダ間でのパスキー同期実装には触れず、概念的に「クラウドアカウント侵害 → 同期パスキー複製」の経路を示します。",
            cloudConfig: {
              ja: PASSKEY_DEMO_CONSTANTS.weakCloudConfigLabel,
              en: PASSKEY_DEMO_CONSTANTS.weakCloudConfigLabelEn,
            },
            cloudAccountCompromised: vulnerableCloudAccountCompromised,
            syncedPasskeyCloned: vulnerableSyncedPasskeyCloned,
            attackCredentialInserted,
            attackCredentialId: attackCredentialInserted ? attackCredentialId : null,
            note: "Even if cloud is compromised, the attacker's cloned passkey would still need to authenticate to passkey.ts — and origin binding would still apply. This scenario demonstrates the cloud-account-protection prerequisite, not a passkey design flaw.",
          },
        },
        detailJa:
          attackCredentialInserted
            ? `このシナリオでは、弱クラウドアカウント保護が同期パスキー複製のリスクを生じさせます: webauthn_credentials に is_attack_sim=1 で複製クレデンシャル (${attackCredentialId.substring(0, 32)}...) が登録されました。クラウドアカウントの保護強度が同期パスキーのセキュリティの前提条件であることを示しています。`
            : "このシナリオでは、弱クラウドアカウント保護のリスクを概念的に示しています (seed_alice 不在のため DB INSERT はスキップしました)。",
        detail:
          attackCredentialInserted
            ? `In this scenario, weak cloud account protection enables synced passkey cloning: a cloned credential (${attackCredentialId.substring(0, 32)}...) was inserted into webauthn_credentials with is_attack_sim=1. This illustrates that cloud account security is a prerequisite for synced passkey security.`
            : "This scenario conceptually illustrates the risk of weak cloud account protection (seed_alice missing — DB insert skipped).",
      });

      // ── Step 5: verify (堅牢モード) — 強クラウド: 強パスワード + MFA でクラウド侵害が阻止される
      const defendedCloudAccessBlocked = true;
      trace.addCryptoOp({
        op: "cloud_account_mfa_verification_simulation",
        input: `attackerCredentials=invalid, mfaToken=missing, cloudConfig=${PASSKEY_DEMO_CONSTANTS.strongCloudConfigLabelEn}`,
        output: "ACCESS DENIED → 401",
        algo: "Cloud provider MFA (TOTP / FIDO2 second factor) — conceptual",
        detail:
          "Defended: A cloud account protected by a strong password (16+ chars) plus phishing-resistant MFA (TOTP / FIDO2) blocks the attacker before any synced passkey access becomes possible.",
      });
      recordStep({
        id: "passkey-cloud-5",
        kind: "verify",
        label: "Defended: strong cloud account (strong password + MFA) blocks compromise → synced passkeys protected",
        labelJa: "堅牢版: 強いクラウドアカウント (強パスワード + MFA) が侵害を阻止 → 同期パスキーは保護される",
        status: "blocked",
        payload: {
          type: "generic",
          data: {
            cloudConfig: {
              ja: PASSKEY_DEMO_CONSTANTS.strongCloudConfigLabel,
              en: PASSKEY_DEMO_CONSTANTS.strongCloudConfigLabelEn,
            },
            cloudAccessBlocked: defendedCloudAccessBlocked,
            blockedBy: "cloud_account_strong_password_and_mfa_enforced",
            note: "Defended: with strong cloud account protection, the attacker is blocked at the cloud provider's auth gate. No synced passkey access is possible.",
          },
        },
        detailJa:
          "堅牢実装では、クラウドアカウントに強パスワード (16 文字以上) と MFA (TOTP または FIDO2) を設定することで、攻撃者がクラウドアカウントに侵入する前にブロックされます。同期パスキーは結果的に保護されます。これは Passkey の設計上の防御ではなく、利用者側のクラウドアカウント保護を前提とする運用上の論点です。",
        detail:
          "In the defended scenario, strong cloud account protection (16+ char password + MFA via TOTP or FIDO2) blocks the attacker at the cloud provider's authentication gate, so synced passkeys remain protected. This is NOT a server-side defense in passkey.ts — it is an operational prerequisite that users must satisfy.",
      });

      // 後始末: SEC-FIDO2-2 — 攻撃シミュレーション用 webauthn_credentials 行を即削除。
      // 「INSERT 成立を観測したか」(extra.attackCredentialInserted) は教育目的で残すが、
      // 連続実行で is_attack_sim=1 行が無制限に蓄積するのを防ぐ。
      if (attackCredentialInserted) {
        db.prepare("DELETE FROM webauthn_credentials WHERE credential_id = ? AND is_attack_sim = 1").run(
          attackCredentialId,
        );
        trace.addDbQuery({
          sql: "DELETE FROM webauthn_credentials WHERE credential_id = ? AND is_attack_sim = 1 (post-demo cleanup)",
          params: [attackCredentialId],
          ms: 0,
        });
      }

      return {
        blockedBy: "cloud_account_strong_password_and_mfa_enforced",
        summary:
          "This scenario simulates a cloud-account compromise vector for synced (multiDevice) passkeys. With weak cloud protection (weak password + no MFA), an attacker who compromises the cloud account can clone the synced passkey to their device. With strong cloud protection (16+ char password + MFA), the cloud provider blocks the attacker before any passkey access is possible. The defense is NOT in passkey.ts itself — it is the operational prerequisite of cloud account security that users must satisfy.",
        summaryJa:
          "このシナリオでは、同期パスキー (multiDevice) のクラウドアカウント侵害経路をシミュレートします。弱いクラウドアカウント保護 (弱パスワード + MFA なし) では、攻撃者がクラウドアカウントを侵害して同期パスキーを攻撃者デバイスに複製できる可能性があります。強いクラウドアカウント保護 (16 文字以上のパスワード + MFA) では、クラウドプロバイダの認証ゲートで攻撃者がブロックされ、パスキーへのアクセスは不可能です。防御は passkey.ts 自体ではなく、利用者側のクラウドアカウント保護という運用上の前提条件にあります。",
        extra: {
          vulnerableCloudAccountCompromised,
          vulnerableSyncedPasskeyCloned,
          defendedCloudAccessBlocked,
          victimUsername: PASSKEY_DEMO_CONSTANTS.victimUsername,
          attackerUsername: PASSKEY_DEMO_CONSTANTS.attackerUsername,
          victimSeedFound,
          attackCredentialInserted,
          cloudConfigComparison: {
            vulnerable: {
              ja: PASSKEY_DEMO_CONSTANTS.weakCloudConfigLabel,
              en: PASSKEY_DEMO_CONSTANTS.weakCloudConfigLabelEn,
            },
            defended: {
              ja: PASSKEY_DEMO_CONSTANTS.strongCloudConfigLabel,
              en: PASSKEY_DEMO_CONSTANTS.strongCloudConfigLabelEn,
            },
          },
          simulationNote: {
            ja: "[教育用シミュレーション専用] 実際の iCloud Keychain / Google Password Manager / 1Password の内部実装・暗号鍵管理には触れていません。クラウドアカウント保護が同期パスキーの信頼チェーンに組み込まれている概念を示すシミュレーションです。",
            en: "[Educational simulation only] This scenario does NOT touch the internal implementation or key management of iCloud Keychain / Google Password Manager / 1Password. It illustrates the concept that cloud account security is part of the trust chain for synced passkeys.",
          },
        } satisfies PasskeyCloudSyncCompromiseExtra,
        payload: {
          params: {},
          result: {
            vulnerableCloudAccountCompromised,
            vulnerableSyncedPasskeyCloned,
            defendedCloudAccessBlocked,
            attackCredentialInserted,
            attackCredentialInsertError,
            victimSeedFound,
          },
        },
      };
    },
  })
);

// ════════════════════════════════════════════════════════════════════════════════
// Scenario C: Cross-device 経路の中間者 (シミュレーション)
// ────────────────────────────────────────────────────────────────────────────────
// CTAP2.2 ハイブリッドフロー: PC ブラウザの QR コード + スマートフォンのパスキー認証
// vulnerable: BLE 近接 / tunnel key チェックが省略された仮想実装 → リモート MITM 成立
// defended:   実 CTAP2.2 仕様 (BLE 近接 + tunnel key) → 阻止
//             (ctap22_ble_proximity_and_tunnel_key_enforced)
// DB 書き込みなし (in-memory simulation only — TLS / kerberoasting と同パターン)
// ════════════════════════════════════════════════════════════════════════════════
type PasskeyCrossDeviceMitmExtra = {
  vulnerableQrInterceptSucceeded: boolean;
  vulnerableMitmEstablished: boolean;
  defendedBleProximityRejected: boolean;
  defendedTunnelKeyRejected: boolean;
  bleProximityRangeMeters: number;
  tunnelKeyAlgo: string;
  victimUsername: string;
  victimSeedFound: boolean;
  /** DESIGN/04 §3.3 / DESIGN/21 §4.3.4 規定の教育用シミュレーション注記。 */
  simulationNote: { ja: string; en: string };
};

passkeyRoutes.post("/attack/cross-device-mitm", (c) =>
  runAttackScenario<typeof passkeyAttackCrossDeviceMitmSchema, PasskeyCrossDeviceMitmExtra>(c, {
    schema: passkeyAttackCrossDeviceMitmSchema,
    scenarioId: "passkey-cross-device-mitm",
    tabId: "passkey",
    async handler({ db, recordStep, trace }) {
      const aliceUser = db
        .prepare("SELECT id, username FROM users WHERE username = ?")
        .get(PASSKEY_DEMO_CONSTANTS.victimUsername) as { id: number; username: string } | undefined;
      const victimSeedFound = !!aliceUser;

      // ── Step 1: probe — 攻撃者が PC ブラウザの QR コードを傍受 (画面盗み見/スクリーンショット)
      recordStep({
        id: "passkey-cdm-1",
        kind: "probe",
        label: "Attacker intercepts QR code from victim's PC browser (screenshot/shoulder-surfing)",
        labelJa: "攻撃者が被害者の PC ブラウザに表示された QR コードを傍受 (スクリーンショット/画面盗み見)",
        status: "success",
        payload: {
          type: "generic",
          data: {
            simulationNote:
              "実際の CTAP2.2 ハイブリッドプロトコルの暗号実装には触れず、防御層の概念を示します。",
            qrPayloadPrefix: "FIDO:/<base64url-ephemeral-pubkey>...",
            note: "The QR code embeds an ephemeral ECDH public key. To establish the tunnel, the responder (smartphone) must derive the shared secret AND be in BLE proximity.",
          },
        },
        detailJa:
          "攻撃者が PC ブラウザに表示された QR コードを傍受します (スクリーンショットまたは画面盗み見)。QR コードには ECDH 用の一時公開鍵が含まれています。",
        detail:
          "The attacker captures the QR code from the victim's PC browser (screenshot or shoulder-surfing). The QR code contains an ephemeral ECDH public key.",
      });

      // ── Step 2: tamper — 攻撃者が QR コードを攻撃者デバイス (リモート/物理近接) に渡す
      recordStep({
        id: "passkey-cdm-2",
        kind: "tamper",
        label: "Attacker passes QR contents to their own device (both remote and proximity scenarios)",
        labelJa: "攻撃者が QR コード内容を攻撃者デバイスに渡す (リモート / 物理近接 両方のシナリオ)",
        status: "success",
        payload: {
          type: "generic",
          data: {
            attackerLocations: ["remote (>10m, BLE out-of-range)", "proximity (<1m, BLE in-range)"],
            note: "We evaluate both attacker locations in parallel. In each case, a different defense layer (BLE proximity OR tunnel key) blocks the attempt.",
          },
        },
        detailJa:
          "攻撃者は両方のシナリオを並列に評価します: リモート (BLE 圏外) では BLE 近接確認で阻止され、物理近接 (BLE 圏内) では tunnel key 検証で阻止されます。",
        detail:
          "The attacker evaluates both scenarios in parallel: a remote attacker (BLE out-of-range) is blocked at BLE proximity, while a physically nearby attacker (BLE in-range) is blocked at tunnel key validation.",
      });

      // ── Step 3: forge — 攻撃者が偽のレスポンダー (スマートフォン側) を装って接続を試行
      recordStep({
        id: "passkey-cdm-3",
        kind: "forge",
        label: "Attacker simulates being the responder (smartphone) and attempts handshake",
        labelJa: "攻撃者が偽のレスポンダー (スマートフォン側) を装ってハンドシェイクを試行",
        status: "success",
        payload: {
          type: "generic",
          data: {
            note: "The attacker tries to act as the responder for the QR contents. A vulnerable implementation (omitting BLE proximity AND tunnel key checks) would allow this. The defended CTAP2.2 implementation requires both layers.",
            vulnerablePathHypothesis: "no BLE proximity check + no tunnel key validation → MITM possible",
            defendedPathSpec: "BLE proximity (RFC: BLE advertising) + tunnel key (ECDH derived) → MITM blocked",
          },
        },
        detailJa:
          "攻撃者は QR の内容に対してレスポンダーとして接続を試みます。BLE 近接と tunnel key 検証が両方欠けた仮想脆弱実装では MITM が成立しますが、CTAP2.2 仕様準拠の堅牢実装では両層が要求されます。",
        detail:
          "The attacker tries to act as the responder for the QR contents. A purely hypothetical vulnerable implementation (skipping both BLE proximity and tunnel key checks) would allow MITM, but CTAP2.2-compliant defended implementations require both layers.",
      });

      // ── Step 4: exploit (脆弱モード) — 防御層を持たない仮想実装では MITM が成立
      // R-MEDIUM-1 教訓: bare literal `true` ではなく SSoT 派生条件で記述。
      // 「QR を傍受できる」かつ「BLE 近接と tunnel key 検証が両方欠如している」場合に MITM 成立。
      const vulnerableQrInterceptSucceeded = true; // QR 傍受は物理的に阻止できない (画面表示なため)
      const vulnerableHasBleCheck = false; // 仮想脆弱実装は BLE 近接チェックを省略
      const vulnerableHasTunnelKeyCheck = false; // 仮想脆弱実装は tunnel key 検証を省略
      const vulnerableMitmEstablished =
        vulnerableQrInterceptSucceeded && !vulnerableHasBleCheck && !vulnerableHasTunnelKeyCheck;

      trace.addCryptoOp({
        op: "passkey_cross_device_handshake_simulation",
        input: `qrIntercepted=${vulnerableQrInterceptSucceeded}, hasBleCheck=${vulnerableHasBleCheck}, hasTunnelKeyCheck=${vulnerableHasTunnelKeyCheck}`,
        output: vulnerableMitmEstablished ? "MITM ESTABLISHED (vulnerable hypothetical)" : "blocked",
        algo: "CTAP 2.2 hybrid handshake (educational simulation)",
        detail:
          "Educational simulation: a hypothetical implementation that skipped both BLE proximity and tunnel key validation would allow QR-relay MITM. The real CTAP2.2 spec requires both.",
      });

      recordStep({
        id: "passkey-cdm-4",
        kind: "exploit",
        label: "Vulnerable: hypothetical no-BLE / no-tunnel-key implementation accepts attacker as responder → MITM",
        labelJa: "脆弱版: BLE 近接 / tunnel key 検証を持たない仮想実装が攻撃者をレスポンダーとして受理 → MITM 成立",
        status: vulnerableMitmEstablished ? "success" : "failed",
        payload: {
          type: "generic",
          data: {
            simulationNote:
              "実装上の CTAP2.2 仕様準拠版は防御層を持つため、この『脆弱版』は教育的説明のための仮想実装です。",
            vulnerableHasBleCheck,
            vulnerableHasTunnelKeyCheck,
            vulnerableMitmEstablished,
            note: "If a passkey deployment removed BLE proximity checks AND tunnel key validation (purely hypothetical), an attacker who intercepted the QR could complete the handshake. CTAP2.2 specifically forbids this configuration.",
          },
        },
        detailJa:
          "このシナリオでは、もし BLE 近接 / tunnel key 検証を両方とも欠いた実装が存在した場合に MITM が成立する経路を概念的に示します。実際の CTAP2.2 ハイブリッドフローはこのような実装を許可していません。",
        detail:
          "This step conceptually illustrates the MITM path that would arise if BOTH BLE proximity and tunnel key checks were absent. Real CTAP2.2 hybrid flows do not permit this configuration.",
      });

      // ── Step 5: verify (堅牢モード) — CTAP2.2 仕様: BLE 近接 + tunnel key の二層防御
      // R-MEDIUM-1 / ROB-PW-1 教訓: 旧コードは
      //   defendedBleProximityRejected = PASSKEY_DEMO_CONSTANTS.bleProximityRangeMeters > 0;
      //   defendedTunnelKeyRejected   = PASSKEY_DEMO_CONSTANTS.tunnelKeyAlgo.length > 0;
      // となっており、SSoT 値が `10` / `非空文字列` の限り常に `true` (= bare literal `true` 等価)。
      // ROB-PW-1 のトートロジー禁止教訓に該当 (シード値変更で flag が転じない sentinel 化破綻)。
      // 本修正: step 4 (脆弱パス) の `vulnerableMitmEstablished` と同型の SSoT 派生に変更し、
      //   defended* = (実装が check を持つ) && (攻撃者の側がそのチェックを通過できない)
      // という形で「2 つの前提のうち 1 つでも崩れれば flag が false になる」性質を保証する。
      const defendedHasBleProximityCheck = true; // CTAP 2.2 仕様準拠の堅牢実装は BLE 近接アドバタイジングを必須
      const defendedHasTunnelKeyCheck = true;    // CTAP 2.2 仕様準拠の堅牢実装は tunnel key 検証を必須
      const attackerIsOutsideBleRange = true;      // 本シナリオはリモート攻撃者をモデル化 (BLE 圏外)
      const attackerLacksResponderEcdhShare = true; // 攻撃者は正規レスポンダーの ECDH 秘密シェアを持たない (傍受は QR 公開鍵のみ)
      // 防御層 1: BLE 近接チェック が存在し、かつ 攻撃者が BLE 圏外 → 拒否
      const defendedBleProximityRejected = defendedHasBleProximityCheck && attackerIsOutsideBleRange;
      // 防御層 2: tunnel key 検証 が存在し、かつ 攻撃者が ECDH 秘密シェアを持たない → 拒否
      const defendedTunnelKeyRejected = defendedHasTunnelKeyCheck && attackerLacksResponderEcdhShare;

      trace.addCryptoOp({
        op: "passkey_cross_device_defense_verification",
        input: `bleRangeMeters=${PASSKEY_DEMO_CONSTANTS.bleProximityRangeMeters}, tunnelKeyAlgo=${PASSKEY_DEMO_CONSTANTS.tunnelKeyAlgo}`,
        output: "BLE proximity check enforced + tunnel key validated → blocked",
        algo: "CTAP 2.2 hybrid: BLE advertising (proximity) + ECDH-derived tunnel key",
        detail:
          "Defended: CTAP2.2 hybrid flow requires (a) BLE advertising response from a device in physical proximity AND (b) tunnel key derived from the QR-embedded ephemeral ECDH key. A remote attacker fails (a); a physically nearby attacker fails (b) because they lack the responder's private ECDH share.",
      });

      recordStep({
        id: "passkey-cdm-5",
        kind: "verify",
        label: "Defended: CTAP2.2 BLE proximity + tunnel key (ECDH) two-layer defense blocks MITM",
        labelJa: "堅牢版: CTAP2.2 BLE 近接 + tunnel key (ECDH) 二層防御が MITM を阻止",
        status: "blocked",
        payload: {
          type: "generic",
          data: {
            defendedBleProximityRejected,
            defendedTunnelKeyRejected,
            blockedBy: "ctap22_ble_proximity_and_tunnel_key_enforced",
            tunnelKeyAlgo: PASSKEY_DEMO_CONSTANTS.tunnelKeyAlgo,
            bleProximityRangeMeters: PASSKEY_DEMO_CONSTANTS.bleProximityRangeMeters,
            note: "Defended: CTAP 2.2 hybrid flow requires BLE proximity + ECDH-derived tunnel key. Remote attackers fail BLE; nearby attackers fail tunnel key. Both layers are mandatory.",
          },
        },
        detailJa:
          "堅牢実装は CTAP2.2 ハイブリッドフロー仕様に従い、(a) BLE 近接アドバタイジングによる物理的近接確認と (b) QR に埋め込まれた一時 ECDH 鍵から導出される tunnel key の二層防御を要求します。リモート攻撃者は (a) で阻止され、物理的に近い攻撃者も正規レスポンダーの秘密 ECDH シェアを持たないため (b) で阻止されます。",
        detail:
          "The defended implementation follows the CTAP2.2 hybrid flow spec, requiring (a) BLE proximity advertising and (b) tunnel key derived from the QR's ephemeral ECDH key. Remote attackers are blocked by (a); physically nearby attackers are blocked by (b) because they lack the legitimate responder's private ECDH share.",
      });

      return {
        blockedBy: "ctap22_ble_proximity_and_tunnel_key_enforced",
        summary:
          "This scenario simulates a QR-relay MITM attack against the CTAP2.2 hybrid (cross-device) flow. A purely hypothetical implementation that omitted both BLE proximity checks AND tunnel key validation would allow MITM, but the real CTAP2.2 spec mandates both layers: BLE proximity advertising blocks remote attackers, while ECDH-derived tunnel keys block physically nearby attackers who cannot reproduce the responder's private share.",
        summaryJa:
          "このシナリオでは、CTAP2.2 ハイブリッド (cross-device) フローに対する QR 中継 MITM 攻撃をシミュレートします。BLE 近接チェックと tunnel key 検証の両方を欠いた仮想実装では MITM が成立しますが、実際の CTAP2.2 仕様は両層を必須としています: BLE 近接アドバタイジングがリモート攻撃者を阻止し、ECDH 由来の tunnel key が物理的に近い攻撃者をも阻止します (正規レスポンダーの秘密 ECDH シェアは複製不可能です)。",
        extra: {
          vulnerableQrInterceptSucceeded,
          vulnerableMitmEstablished,
          defendedBleProximityRejected,
          defendedTunnelKeyRejected,
          bleProximityRangeMeters: PASSKEY_DEMO_CONSTANTS.bleProximityRangeMeters,
          tunnelKeyAlgo: PASSKEY_DEMO_CONSTANTS.tunnelKeyAlgo,
          victimUsername: PASSKEY_DEMO_CONSTANTS.victimUsername,
          victimSeedFound,
          simulationNote: {
            ja: "[教育用シミュレーション専用] 実際の CTAP2.2 ハイブリッドプロトコルの完全な暗号実装はこのデモには含まれていません。BLE 近接要件と tunnel key 暗号化という防御層の概念を示す教育用シミュレーションです。",
            en: "[Educational simulation only] The full cryptographic implementation of the CTAP2.2 hybrid protocol is NOT included. This demo conceptually illustrates the BLE proximity and tunnel key encryption defense layers.",
          },
        } satisfies PasskeyCrossDeviceMitmExtra,
        payload: {
          params: {},
          result: {
            vulnerableQrInterceptSucceeded,
            vulnerableMitmEstablished,
            defendedBleProximityRejected,
            defendedTunnelKeyRejected,
            victimSeedFound,
          },
        },
      };
    },
  })
);
