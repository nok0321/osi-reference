import { Hono } from "hono";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import type { RegistrationResponseJSON, AuthenticationResponseJSON } from "@simplewebauthn/server";
import bcrypt from "bcryptjs";
import { v4 as uuidv4 } from "uuid";
import { getDb } from "../db/schema.js";
import {
  parseBody,
  webauthnUsernameSchema,
  webauthnRegisterVerifySchema,
  webauthnAuthVerifySchema,
  webauthnAttackPhishingOriginSchema,
  webauthnAttackVsPasswordPhishingSchema,
  webauthnAttackChallengeReplaySchema,
} from "../validation.js";
import type { UserRow, WebAuthnCredentialRow } from "../../shared/api-types.js";
import { createTtlStore } from "../utils/ttl-store.js";
import { runAttackScenario, maskSecret, sanitizeForDisplay } from "../utils/attack-runner.js";

export const webauthnRoutes = new Hono();

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

// ── WebAuthn Relying Party 設定 SSoT (ROB-FIDO2-5) ──
// 攻撃シミュレーションシード (WEBAUTHN_DEMO_CONSTANTS) と同じ値を共有することで、
// 一方を変更し忘れて正常系/攻撃系で異なる origin を検証してしまう事故を防ぐ。
// `as const` で readonly 化し、攻撃ハンドラ側からも参照する。
const WEBAUTHN_RP = {
  name: "OSI Reference Demo",
  id: "localhost",
  origin: "http://localhost:3000",
} as const satisfies Readonly<{ name: string; id: string; origin: string }>;

const RP_NAME = WEBAUTHN_RP.name;
const RP_ID = WEBAUTHN_RP.id;
const ORIGIN = WEBAUTHN_RP.origin;

// In-memory challenge store (keyed by sessionId to prevent concurrent-tab overwrites)
const challenges = createTtlStore<{ challenge: string; username: string }>({ ttlMs: 5 * 60 * 1000 });

webauthnRoutes.post("/register/options", async (c) => {
  const parsed = await parseBody(c, webauthnUsernameSchema);
  if ("error" in parsed) return parsed.error;
  const { username } = parsed.data;
  const trace = c.get("trace");
  const db = getDb();

  // Get or create user
  let user = db.prepare("SELECT id, username FROM users WHERE username = ?").get(username) as Pick<UserRow, "id" | "username"> | undefined;
  if (!user) {
    // Create a placeholder user for WebAuthn-only registration
    db.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)").run(username, "WEBAUTHN_ONLY");
    user = db.prepare("SELECT id, username FROM users WHERE username = ?").get(username) as Pick<UserRow, "id" | "username"> | undefined;
    trace.addDbQuery({
      sql: "INSERT INTO users (username, password_hash) VALUES (?, 'WEBAUTHN_ONLY')",
      params: [username],
      ms: 0,
    });
  }
  if (!user) {
    return c.json({ success: false, error: "Failed to create user" }, 500);
  }

  // Get existing credentials (E-3: 攻撃シミュレーション用クレデンシャルを除外)
  const existingCreds = db.prepare(
    "SELECT credential_id, public_key, counter, transports FROM webauthn_credentials WHERE user_id = ? AND is_attack_sim = 0"
  ).all(user.id) as WebAuthnCredentialRow[];

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userName: username,
    userID: new TextEncoder().encode(String(user.id)),
    attestationType: "none",
    excludeCredentials: existingCreds.map((cred) => ({
      id: cred.credential_id,
      transports: parseTransports(cred.transports) as never,
    })),
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "preferred",
    },
  });

  const sessionId = uuidv4();
  challenges.set(sessionId, { challenge: options.challenge, username });

  trace.addCryptoOp({
    op: "generateChallenge",
    input: `rpId="${RP_ID}", user="${username}"`,
    output: options.challenge,
    algo: "crypto.getRandomValues(32 bytes) → base64url",
    detail: "Server generates random challenge to prevent replay attacks",
  });

  trace.addSessionOp({
    action: "STORE_CHALLENGE",
    data: { sessionId, username, challenge: options.challenge, purpose: "registration" },
  });

  return c.json({
    success: true,
    data: {
      sessionId,
      options,
      explanation: {
        challenge: "Random bytes from server — authenticator must sign this",
        rp: { id: RP_ID, name: RP_NAME },
        excludeCredentials: `${existingCreds.length} existing credential(s) excluded`,
      },
    },
  });
});

webauthnRoutes.post("/register/verify", async (c) => {
  const parsed = await parseBody(c, webauthnRegisterVerifySchema);
  if ("error" in parsed) return parsed.error;
  const { sessionId, username, response: attResponseRaw } = parsed.data;
  const attResponse = attResponseRaw as unknown as RegistrationResponseJSON;
  const trace = c.get("trace");
  const db = getDb();

  const stored = challenges.get(sessionId);
  if (!stored || stored.username !== username) {
    return c.json({ success: false, error: "No challenge found or challenge expired — start registration first" }, 400);
  }

  try {
    const verification = await verifyRegistrationResponse({
      response: attResponse,
      expectedChallenge: stored.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
    });

    trace.addCryptoOp({
      op: "verifyRegistration",
      input: `clientDataJSON + attestationObject`,
      output: verification.verified ? "VERIFIED ✓" : "FAILED ✗",
      algo: "FIDO2 Attestation Verification",
      detail: "Verify challenge signature, check origin/rpId, extract public key",
    });

    if (verification.verified && verification.registrationInfo) {
      const { credential } = verification.registrationInfo;
      const user = db.prepare("SELECT id FROM users WHERE username = ?").get(username) as Pick<UserRow, "id"> | undefined;
      if (!user) {
        return c.json({ success: false, error: "User not found" }, 500);
      }

      // E-3: is_attack_sim=0 で正常系クレデンシャルを明示的に挿入
      db.prepare(
        "INSERT INTO webauthn_credentials (credential_id, user_id, public_key, counter, transports, is_attack_sim) VALUES (?, ?, ?, ?, ?, 0)"
      ).run(
        credential.id,
        user.id,
        Buffer.from(credential.publicKey).toString("base64"),
        credential.counter,
        JSON.stringify(attResponse.response?.transports ?? [])
      );

      trace.addDbQuery({
        sql: "INSERT INTO webauthn_credentials (credential_id, user_id, public_key, counter, transports, is_attack_sim) VALUES (..., 0)",
        params: [credential.id, user.id],
        ms: 0,
      });

      challenges.delete(sessionId);

      return c.json({
        success: true,
        data: {
          verified: true,
          credentialId: credential.id,
          publicKeyPreview: Buffer.from(credential.publicKey).toString("base64").substring(0, 40) + "...",
          counter: credential.counter,
        },
      });
    }

    return c.json({ success: false, error: "Verification failed" }, 400);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Unknown error";
    return c.json({ success: false, error: message }, 400);
  }
});

webauthnRoutes.post("/auth/options", async (c) => {
  const parsed = await parseBody(c, webauthnUsernameSchema);
  if ("error" in parsed) return parsed.error;
  const { username } = parsed.data;
  const trace = c.get("trace");
  const db = getDb();

  const user = db.prepare("SELECT id FROM users WHERE username = ?").get(username) as Pick<UserRow, "id"> | undefined;
  if (!user) {
    return c.json({ success: false, error: "User not found" }, 404);
  }

  // E-3: 攻撃シミュレーション用クレデンシャルを除外
  const creds = db.prepare(
    "SELECT credential_id, public_key, counter, transports FROM webauthn_credentials WHERE user_id = ? AND is_attack_sim = 0"
  ).all(user.id) as WebAuthnCredentialRow[];

  if (creds.length === 0) {
    return c.json({ success: false, error: "No credentials registered" }, 400);
  }

  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    allowCredentials: creds.map((cred) => ({
      id: cred.credential_id,
      transports: parseTransports(cred.transports) as never,
    })),
    userVerification: "preferred",
  });

  const sessionId = uuidv4();
  challenges.set(sessionId, { challenge: options.challenge, username });

  trace.addCryptoOp({
    op: "generateAuthChallenge",
    input: `rpId="${RP_ID}", user="${username}", credentials=${creds.length}`,
    output: options.challenge,
    algo: "crypto.getRandomValues(32 bytes) → base64url",
    detail: "New challenge for authentication — must be signed by registered credential",
  });

  return c.json({
    success: true,
    data: {
      sessionId,
      options,
      explanation: {
        challenge: "Fresh random bytes — authenticator signs with private key",
        allowCredentials: `${creds.length} registered credential(s)`,
      },
    },
  });
});

webauthnRoutes.post("/auth/verify", async (c) => {
  const parsed = await parseBody(c, webauthnAuthVerifySchema);
  if ("error" in parsed) return parsed.error;
  const { sessionId, username, response: authResponseRaw } = parsed.data;
  const authResponse = authResponseRaw as unknown as AuthenticationResponseJSON;
  const trace = c.get("trace");
  const db = getDb();

  const stored = challenges.get(sessionId);
  if (!stored || stored.username !== username) {
    return c.json({ success: false, error: "No challenge found or challenge expired" }, 400);
  }

  const user = db.prepare("SELECT id FROM users WHERE username = ?").get(username) as Pick<UserRow, "id"> | undefined;
  if (!user) {
    return c.json({ success: false, error: "User not found" }, 404);
  }

  // E-3: 攻撃シミュレーション用クレデンシャルを除外
  const cred = db.prepare(
    "SELECT credential_id, public_key, counter FROM webauthn_credentials WHERE credential_id = ? AND user_id = ? AND is_attack_sim = 0"
  ).get(authResponse.id, user.id) as Pick<WebAuthnCredentialRow, "credential_id" | "public_key" | "counter"> | undefined;

  if (!cred) {
    return c.json({ success: false, error: "Credential not found" }, 400);
  }

  try {
    const verification = await verifyAuthenticationResponse({
      response: authResponse,
      expectedChallenge: stored.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      credential: {
        id: cred.credential_id,
        publicKey: Buffer.from(cred.public_key, "base64"),
        counter: cred.counter,
      },
    });

    trace.addCryptoOp({
      op: "verifyAuthentication",
      input: `signature over clientDataJSON + authenticatorData`,
      output: verification.verified ? "VERIFIED ✓" : "FAILED ✗",
      algo: "ECDSA / RSA (credential-dependent)",
      detail: "Verify signature with stored public key, check counter increment",
    });

    if (verification.verified) {
      const newCounter = verification.authenticationInfo.newCounter;

      // Clone detection: counter must always increment
      if (newCounter > 0 && newCounter <= cred.counter) {
        trace.addCryptoOp({
          op: "counterCloneDetection",
          input: `oldCounter=${cred.counter}, newCounter=${newCounter}`,
          output: "⚠ CLONE DETECTED",
          algo: "Counter Verification",
          detail: "Counter did not increment — possible cloned authenticator",
        });
        return c.json({
          success: false,
          error: "Authenticator counter did not increment — possible clone detected",
        }, 403);
      }

      // Update counter (E-3: 正常系クレデンシャルのみ対象)
      db.prepare("UPDATE webauthn_credentials SET counter = ? WHERE credential_id = ? AND is_attack_sim = 0").run(
        newCounter,
        cred.credential_id
      );
      // ROB-FIDO2-14: 教育目的の可視化のため UPDATE もトレース (counter 単調増加が観察可能)
      trace.addDbQuery({
        sql: "UPDATE webauthn_credentials SET counter = ? WHERE credential_id = ? AND is_attack_sim = 0",
        params: [newCounter, cred.credential_id],
        ms: 0,
      });
      challenges.delete(sessionId);

      return c.json({
        success: true,
        data: {
          verified: true,
          username,
          counter: { old: cred.counter, new: verification.authenticationInfo.newCounter },
        },
      });
    }

    return c.json({ success: false, error: "Authentication failed" }, 401);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Unknown error";
    return c.json({ success: false, error: message }, 400);
  }
});

webauthnRoutes.get("/credentials", (c) => {
  const db = getDb();
  // E-3: 攻撃シミュレーション用クレデンシャルは別経路で確認するため除外
  const creds = db.prepare(
    `SELECT wc.credential_id, wc.counter, wc.created_at, u.username
     FROM webauthn_credentials wc JOIN users u ON wc.user_id = u.id
     WHERE wc.is_attack_sim = 0`
  ).all();
  return c.json({ success: true, data: { credentials: creds } });
});

/**
 * 攻撃デモルート: fido2 (WebAuthn) タブ
 *
 * 【教育目的専用】
 * このコードは OSI 参照アプリの教材機能として、
 * ローカル環境の固定シードデータに対する攻撃シミュレーションを提供します。
 *
 * - 外部ネットワークへのリクエストは行いません (attacker.example は概念的な架空ドメイン)
 * - 実 navigator.credentials API 呼び出しは行わず、サーバー側で署名検証フローのみシミュレートします
 * - @simplewebauthn/server の verifyAuthenticationResponse / verifyRegistrationResponse は呼び出しません
 *   (実際のクライアントデータが揃わないため)
 * - 本番環境での使用は想定していません (ensureAttackEnabled middleware が NODE_ENV=production で 403 拒否)
 *
 * 対象 CWE: CWE-290 (origin spoofing), CWE-294 (replay), CWE-346 (origin validation)
 * 対象 CAPEC: CAPEC-60 (replay), CAPEC-89 (phishing), CAPEC-94 (man-in-the-middle), CAPEC-194 (fake the source)
 * 関連設計書: DESIGN/15-attack-fido2.md
 * 安全装置: DESIGN/04-safety-guardrails.md
 *
 * このタブの特殊性 (DESIGN/15 §1.1):
 * 他タブと異なり、本タブは「プロトコル設計が攻撃を成立させない」ことを示す。
 * 全シナリオで堅牢モードのステップ 5 が status: "blocked" となるが、
 * E-2 規約により AttackResult.outcome は常に "succeeded" を返す。
 */

// ── 共通シード (immutable) ──
// ROB-FIND-007 / ROB-RBAC-3 と同パターンで `as const satisfies Readonly<...>` を採用。
// ROB-FIDO2-5: rpId / expectedOrigin は本番 WEBAUTHN_RP から派生して SSoT 一本化。
const WEBAUTHN_DEMO_CONSTANTS = {
  rpId: WEBAUTHN_RP.id,
  expectedOrigin: WEBAUTHN_RP.origin,
  attackerOrigin: "http://attacker.example",
  victimUsername: "seed_alice",
  attackerUsername: "attacker_charlie",
  // 教育用ダミーチャレンジ (base64url 32 バイト相当)。実 generateRegistrationOptions の出力ではなく
  // 固定文字列で「リプレイされた攻撃者制御チャレンジ」を表現する。
  demoChallenge: "ZmlkbzItZGVtby1jaGFsbGVuZ2UtcmVwbGF5ZWQtMTIzNDU",
  // 教育用ダミー attestationObject prefix。実バイナリではなく短い base64url 表現で署名された結果を表現。
  demoAttestationPreview: "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVh",
  // フィッシングシナリオで「ユーザーが入力したパスワード」(seed_alice の seedPwd と一致) を表す
  // — シミュレーション専用。`bcrypt.compare` で実際にハッシュと比較する。
  victimPasswordPlain: "Passw0rd!",
} as const satisfies Readonly<{
  rpId: string;
  expectedOrigin: string;
  attackerOrigin: string;
  victimUsername: string;
  attackerUsername: string;
  demoChallenge: string;
  demoAttestationPreview: string;
  victimPasswordPlain: string;
}>;

// ── Scenario A: フィッシング origin 検証による失敗 ──
type PhishingOriginExtra = {
  attackerOrigin: string;
  expectedOrigin: string;
  vulnerableAccepted: boolean;
  defendedRejected: boolean;
  victimUsername: string;
  /** ROB-N1/N2: seed_alice 不在時は false。 */
  victimSeedFound: boolean;
};

webauthnRoutes.post("/attack/phishing-origin", (c) =>
  runAttackScenario<typeof webauthnAttackPhishingOriginSchema, PhishingOriginExtra>(c, {
    schema: webauthnAttackPhishingOriginSchema,
    scenarioId: "fido2-phishing-origin-rejection",
    tabId: "fido2",
    async handler({ db, recordStep, trace }) {
      // seed_alice の user_id を取得 (DB 書き込みはしないが、教育表示の victimUserId として使用)
      const aliceUser = db
        .prepare("SELECT id, username FROM users WHERE username = ?")
        .get(WEBAUTHN_DEMO_CONSTANTS.victimUsername) as { id: number; username: string } | undefined;
      const victimSeedFound = !!aliceUser;

      const safeAttackerOrigin = sanitizeForDisplay(WEBAUTHN_DEMO_CONSTANTS.attackerOrigin, 256);
      const safeExpectedOrigin = sanitizeForDisplay(WEBAUTHN_DEMO_CONSTANTS.expectedOrigin, 256);

      // ── Step 1: probe — 攻撃者が正規サーバーから auth options を中継取得 (シミュレーション)
      recordStep({
        id: "phish-1",
        kind: "probe",
        label: "Attacker relays auth options request to legitimate server",
        labelJa: "攻撃者が正規サーバーへ認証オプション要求を中継",
        status: "success",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/webauthn/auth/options (simulated relay)",
            body: { username: WEBAUTHN_DEMO_CONSTANTS.victimUsername },
          },
          response: {
            status: 200,
            body: {
              sessionId: "<simulated-session-id>",
              options: { challenge: WEBAUTHN_DEMO_CONSTANTS.demoChallenge.substring(0, 16) + "...", rpId: WEBAUTHN_DEMO_CONSTANTS.rpId },
            },
          },
        },
        detailJa:
          "攻撃者は正規サーバーから WebAuthn 認証チャレンジを取得し、フィッシングページに転送します (中継型 MITM)。",
        detail:
          "The attacker relays the WebAuthn auth challenge from the legitimate server to the phishing page (relay-style MITM).",
      });

      // ── Step 2: tamper — Authenticator が attacker.example origin で clientDataJSON に署名 (概念的)
      trace.addCryptoOp({
        op: "clientDataJSON_signature_simulation",
        input: `origin=${safeAttackerOrigin}, challenge=${WEBAUTHN_DEMO_CONSTANTS.demoChallenge.substring(0, 16)}...`,
        output: "<simulated_signature> (would be ECDSA over clientDataJSON+authenticatorData)",
        algo: "WebAuthn signing simulation (no real authenticator invoked)",
        detail: "Educational simulation: real Authenticator would refuse to sign for an unknown rpId in practice.",
      });
      recordStep({
        id: "phish-2",
        kind: "tamper",
        label: "Authenticator signs clientDataJSON with attacker.example origin",
        labelJa: "Authenticator が attacker.example origin で clientDataJSON に署名 (シミュレーション)",
        status: "success",
        payload: {
          type: "generic",
          data: {
            simulationNote:
              "実 navigator.credentials API は呼び出していません — サーバー側で『もし署名が来たら』のフローを再現します。",
            clientDataJSON: {
              type: "webauthn.get",
              challenge: WEBAUTHN_DEMO_CONSTANTS.demoChallenge.substring(0, 16) + "...",
              origin: safeAttackerOrigin,
            },
            expectedOrigin: safeExpectedOrigin,
            originMismatch: true,
          },
        },
        detailJa:
          "攻撃者ページが Authenticator にチャレンジを渡し、clientDataJSON.origin に attacker.example が記録されます。これはサーバーの origin 検証で拒否される必要があります。",
        detail:
          "The attacker page passes the challenge to the Authenticator. The clientDataJSON.origin field is recorded as attacker.example. Server-side origin validation must reject this.",
      });

      // ── Step 3: forge — 攻撃者が forged signature を /api/webauthn/auth/verify に送信 (シミュレーション)
      recordStep({
        id: "phish-3",
        kind: "forge",
        label: "Attacker submits forged-origin assertion to verify endpoint",
        labelJa: "攻撃者が origin 偽装 assertion を verify エンドポイントへ送信",
        status: "success",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/webauthn/auth/verify (simulated)",
            body: {
              sessionId: "<simulated-session-id>",
              username: WEBAUTHN_DEMO_CONSTANTS.victimUsername,
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

      // ── Step 4: exploit — 脆弱モード (expectedOrigin チェック省略): 受理されてしまう
      const vulnerableAccepted = true; // 脆弱実装は origin を見ないため受理
      recordStep({
        id: "phish-4",
        kind: "exploit",
        label: "Vulnerable: server skips expectedOrigin check — accepts forged-origin assertion",
        labelJa: "脆弱版: サーバーが expectedOrigin チェックを省略 — origin 偽装 assertion を受理",
        status: "success",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/webauthn/auth/verify (vulnerable variant — no origin check)",
          },
          response: {
            status: 200,
            body: {
              verified: true,
              username: WEBAUTHN_DEMO_CONSTANTS.victimUsername,
              note: "Vulnerable: a server omitting expectedOrigin would accept the assertion despite the origin mismatch.",
            },
          },
        },
        detailJa:
          "この実装は脆弱です: verifyAuthenticationResponse() に expectedOrigin を渡さない、もしくは検証をスキップする実装は、attacker.example で署名された clientDataJSON を受理してしまい、フィッシング攻撃が成立します。",
        detail:
          "This implementation is vulnerable: a server that omits expectedOrigin (or skips the validation) would accept a clientDataJSON signed at attacker.example, allowing the phishing attack to succeed.",
      });

      // ── Step 5: verify — 堅牢モード (expectedOrigin 厳密一致): origin 不一致で拒否
      trace.addCryptoOp({
        op: "expectedOrigin_strict_compare",
        input: `clientDataJSON.origin=${safeAttackerOrigin}, expectedOrigin=${safeExpectedOrigin}`,
        output: "MISMATCH → throw Error",
        algo: "@simplewebauthn/server verifyAuthenticationResponse origin check",
        detail:
          "Defended: the server compares clientDataJSON.origin with expectedOrigin string-equality and throws on mismatch.",
      });
      const defendedRejected = true; // 堅牢実装は origin 不一致で必ず拒否
      recordStep({
        id: "phish-5",
        kind: "verify",
        label: "Defended: expectedOrigin strict-equality check rejects attacker.example",
        labelJa: "堅牢版: expectedOrigin 厳密一致チェックが attacker.example を拒否",
        status: "blocked",
        payload: {
          type: "http",
          response: {
            status: 400,
            body: {
              error: `Origin mismatch: expected ${safeExpectedOrigin}, got ${safeAttackerOrigin}`,
              blockedBy: "webauthn_origin_validation_enforced",
            },
          },
        },
        detailJa:
          "堅牢実装は verifyAuthenticationResponse() に expectedOrigin を渡し、@simplewebauthn/server が clientDataJSON.origin を厳密比較します。attacker.example != http://localhost:3000 で例外がスローされ、サーバーは 400 を返します。",
        detail:
          "The defended implementation passes expectedOrigin to verifyAuthenticationResponse(); @simplewebauthn/server compares clientDataJSON.origin via string-equality. attacker.example != http://localhost:3000 triggers an exception and the server returns 400.",
      });

      return {
        blockedBy: "webauthn_origin_validation_enforced",
        summary:
          "A vulnerable server omitting the expectedOrigin check would accept a clientDataJSON signed at attacker.example. The defended implementation enforces strict origin comparison via @simplewebauthn/server, blocking the phishing attempt.",
        summaryJa:
          "この実装は脆弱です: expectedOrigin チェックを省略するサーバーは attacker.example で署名された clientDataJSON を受理してしまいます。堅牢実装は @simplewebauthn/server による厳密一致検証で origin 偽装を阻止します。",
        extra: {
          attackerOrigin: safeAttackerOrigin,
          expectedOrigin: safeExpectedOrigin,
          vulnerableAccepted,
          defendedRejected,
          victimUsername: WEBAUTHN_DEMO_CONSTANTS.victimUsername,
          victimSeedFound,
        } satisfies PhishingOriginExtra,
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

// ── Scenario B: パスワード vs FIDO2 フィッシング比較 ──
type VsPasswordPhishingExtra = {
  passwordSucceeded: boolean;
  fido2Blocked: boolean;
  capturedPasswordMasked: string | null;
  attackerOrigin: string;
  expectedOrigin: string;
  victimUsername: string;
  victimSeedFound: boolean;
  comparison: {
    passwordPhishingSuccessRate: string;
    fido2PhishingSuccessRate: string;
  };
};

webauthnRoutes.post("/attack/vs-password-phishing", (c) =>
  runAttackScenario<typeof webauthnAttackVsPasswordPhishingSchema, VsPasswordPhishingExtra>(c, {
    schema: webauthnAttackVsPasswordPhishingSchema,
    scenarioId: "fido2-vs-password-phishing",
    tabId: "fido2",
    async handler({ db, recordStep, trace }) {
      // seed_alice の user_id とパスワードハッシュを取得 (パスワード側比較で bcrypt.compare 実行)
      const aliceUser = db
        .prepare("SELECT id, username, password_hash FROM users WHERE username = ?")
        .get(WEBAUTHN_DEMO_CONSTANTS.victimUsername) as
        | { id: number; username: string; password_hash: string }
        | undefined;
      const victimSeedFound = !!aliceUser;

      const safeAttackerOrigin = sanitizeForDisplay(WEBAUTHN_DEMO_CONSTANTS.attackerOrigin, 256);
      const safeExpectedOrigin = sanitizeForDisplay(WEBAUTHN_DEMO_CONSTANTS.expectedOrigin, 256);

      // ── Step 1: probe — 同一フィッシングページが両方の認証方式を提示
      recordStep({
        id: "vs-1",
        kind: "probe",
        label: "Phishing page presents both password and WebAuthn flows",
        labelJa: "フィッシングページがパスワードと WebAuthn の両方を提示",
        status: "success",
        payload: {
          type: "http",
          request: {
            method: "GET",
            url: `${safeAttackerOrigin}/login (simulated phishing page)`,
          },
          response: {
            status: 200,
            body: {
              note: "Phishing page mimics the legitimate site; presents both password form and WebAuthn prompt.",
              targetVictim: WEBAUTHN_DEMO_CONSTANTS.victimUsername,
            },
          },
        },
        detailJa:
          "攻撃者は同じフィッシングページに両方の認証方式を仕込みます。被害者はどちらを選んでも騙されたつもりです。",
        detail:
          "The attacker embeds both authentication methods on the same phishing page. The victim believes they are using the legitimate site regardless of choice.",
      });

      // ── Step 2: tamper — 被害者がパスワードを入力 (中継キャプチャ) + Authenticator が attacker.example で署名
      recordStep({
        id: "vs-2",
        kind: "tamper",
        label: "Victim enters password (captured) and Authenticator signs with attacker.example",
        labelJa: "被害者がパスワードを入力 (傍受) + Authenticator が attacker.example で署名",
        status: "success",
        payload: {
          type: "generic",
          data: {
            passwordSide: {
              capturedPasswordMasked: maskSecret(WEBAUTHN_DEMO_CONSTANTS.victimPasswordPlain),
              note: "Phishing form sends the password to attacker-controlled server.",
            },
            fido2Side: {
              clientDataJSON_origin: safeAttackerOrigin,
              expectedOrigin: safeExpectedOrigin,
              note: "Authenticator simulation — real navigator.credentials API not invoked in this demo.",
            },
          },
        },
        detailJa:
          "パスワード側: フォームに入力された平文が攻撃者サーバーに送信されます (中継 MITM)。FIDO2 側: Authenticator が attacker.example origin で署名 (シミュレーション)。",
        detail:
          "Password side: the plaintext password is sent to the attacker-controlled server (relay MITM). FIDO2 side: the Authenticator signs with attacker.example origin (simulation).",
      });

      // ── Step 3: forge — 攻撃者が両方の認証情報を正規サーバーに転送
      recordStep({
        id: "vs-3",
        kind: "forge",
        label: "Attacker replays password to /login and forwards FIDO2 assertion to /verify",
        labelJa: "攻撃者がパスワードを /login へ、FIDO2 assertion を /verify へ転送",
        status: "success",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/session/login (password — attacker relay) AND /api/webauthn/auth/verify (FIDO2 — attacker relay)",
          },
        },
        detailJa:
          "攻撃者は窃取したパスワードを正規 /login に再送し、FIDO2 assertion を正規 verify に転送します。",
        detail:
          "The attacker replays the stolen password to the legitimate /login endpoint and forwards the FIDO2 assertion to the legitimate verify endpoint.",
      });

      // ── Step 4: exploit (脆弱モード = パスワード側) — bcrypt.compare で認証成立
      let passwordSucceeded = false;
      if (aliceUser) {
        const t0 = performance.now();
        passwordSucceeded = await bcrypt.compare(
          WEBAUTHN_DEMO_CONSTANTS.victimPasswordPlain,
          aliceUser.password_hash,
        );
        trace.addCryptoOp({
          op: "bcrypt_compare_simulated_phishing_password",
          input: `password=${maskSecret(WEBAUTHN_DEMO_CONSTANTS.victimPasswordPlain)}, hash=<seed_alice.password_hash>`,
          output: passwordSucceeded ? "MATCH ✓ — phishing succeeded" : "NO MATCH ✗",
          algo: "bcrypt (educational comparison; phishing password equals seed value)",
          detail: `Compared in ${(performance.now() - t0).toFixed(1)}ms. Vulnerable because the server cannot tell the request originated from a phishing page.`,
        });
      }
      recordStep({
        id: "vs-4",
        kind: "exploit",
        label: "Vulnerable (password): server has no origin signal — phishing replay succeeds",
        labelJa: "脆弱版 (パスワード): サーバーに origin 信号がないため中継リプレイが成立",
        status: passwordSucceeded ? "success" : "failed",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/session/login (password — attacker relay)",
            body: { username: WEBAUTHN_DEMO_CONSTANTS.victimUsername, password: maskSecret(WEBAUTHN_DEMO_CONSTANTS.victimPasswordPlain) },
          },
          response: {
            status: passwordSucceeded ? 200 : 401,
            body: passwordSucceeded
              ? { success: true, note: "Vulnerable: bcrypt.compare matched — server cannot detect this came from a phishing relay." }
              : { error: "Invalid credentials (seed_alice missing — fallback)" },
          },
        },
        detailJa: passwordSucceeded
          ? `この実装は脆弱です: パスワード認証は origin 情報を持たないため、攻撃者がフィッシング経由で取得したパスワード (${maskSecret(WEBAUTHN_DEMO_CONSTANTS.victimPasswordPlain)}) を正規サーバーに送信するだけで認証が成立します。`
          : "脆弱パス実行不可: seed_alice が DB に存在しないため bcrypt.compare をスキップしました。",
        detail: passwordSucceeded
          ? `Vulnerable: password authentication has no origin signal. The attacker can replay the captured password (${maskSecret(WEBAUTHN_DEMO_CONSTANTS.victimPasswordPlain)}) to the legitimate server and succeed.`
          : "Vulnerable path could not run — seed_alice missing from seeds.",
      });

      // ── Step 5: verify (堅牢モード = FIDO2 側) — origin 検証で拒否
      trace.addCryptoOp({
        op: "fido2_origin_check_strict",
        input: `clientDataJSON.origin=${safeAttackerOrigin}, expectedOrigin=${safeExpectedOrigin}`,
        output: "MISMATCH → reject",
        algo: "@simplewebauthn/server origin validation",
        detail:
          "Defended: FIDO2 binds the signature to the origin (attacker.example), so it cannot be replayed against http://localhost:3000.",
      });
      const fido2Blocked = true;
      recordStep({
        id: "vs-5",
        kind: "verify",
        label: "Defended (FIDO2): origin validation blocks the relayed assertion",
        labelJa: "堅牢版 (FIDO2): origin 検証が中継 assertion を拒否",
        status: "blocked",
        payload: {
          type: "http",
          response: {
            status: 400,
            body: {
              error: `Origin mismatch: expected ${safeExpectedOrigin}, got ${safeAttackerOrigin}`,
              blockedBy: "webauthn_origin_phishing_blocked",
              note: "FIDO2 cryptographically binds the signature to attacker.example, so the legitimate server rejects it.",
            },
          },
        },
        detailJa:
          "堅牢実装 (FIDO2): assertion 内の clientDataJSON.origin は attacker.example で署名されているため、正規サーバーの expectedOrigin (http://localhost:3000) と一致せず拒否されます。攻撃者は assertion を盗んでも再利用できません。",
        detail:
          "Defended (FIDO2): the assertion's clientDataJSON.origin is cryptographically bound to attacker.example, so the legitimate server's expectedOrigin (http://localhost:3000) check rejects it. The attacker cannot reuse the assertion.",
      });

      return {
        blockedBy: "webauthn_origin_phishing_blocked",
        summary:
          "Same phishing scenario: password authentication is captured and replayed successfully (vulnerable), while FIDO2's origin binding blocks the relayed assertion (defended).",
        summaryJa:
          "このシナリオでは同じフィッシング攻撃をパスワードと FIDO2 で比較しました。パスワードは中継リプレイで成立しますが、FIDO2 は origin バインディングにより assertion 再利用が暗号的に不可能です。",
        extra: {
          passwordSucceeded,
          fido2Blocked,
          capturedPasswordMasked: maskSecret(WEBAUTHN_DEMO_CONSTANTS.victimPasswordPlain),
          attackerOrigin: safeAttackerOrigin,
          expectedOrigin: safeExpectedOrigin,
          victimUsername: WEBAUTHN_DEMO_CONSTANTS.victimUsername,
          victimSeedFound,
          comparison: {
            // ROB-FIDO2-9: passwordSucceeded に応じて文字列を動的化。
            // seed_alice 不在等で bcrypt.compare が成立しなかった場合に "100%" の固定文字列が
            // 表示される教育的誤誘導を回避。fido2 側は origin バインドで常に 0%。
            passwordPhishingSuccessRate: passwordSucceeded
              ? "100% (no origin signal)"
              : "N/A (seed_alice missing — bcrypt.compare not exercised)",
            fido2PhishingSuccessRate: "0% (origin-bound signature)",
          },
        } satisfies VsPasswordPhishingExtra,
        payload: {
          params: {},
          result: {
            passwordSucceeded,
            fido2Blocked,
            capturedPasswordMasked: maskSecret(WEBAUTHN_DEMO_CONSTANTS.victimPasswordPlain),
            victimSeedFound,
          },
        },
      };
    },
  })
);

// ── Scenario C: チャレンジリプレイ攻撃 (one-time 設計による阻止) ──
// ROB-FIDO2-2 / SEC-FIDO2-6: 教育用 challenge ストアは handler ローカル化。
// 本番 `challenges` (line 47) との混同を避けるため命名は `attackSimReplayChallenges`
// で「攻撃シミュレーション専用」を明示。両 sessionId を 1 リクエスト内で完結消費するため
// グローバル保持は不要 (TTL store は handler ごとに fresh、setInterval リソースリーク回避)。

type ChallengeReplayExtra = {
  replayChallengePreview: string;
  vulnerableReplayAccepted: boolean;
  defendedReplayBlocked: boolean;
  vulnerableSessionId: string;
  defendedSessionId: string;
  attestationPreview: string;
  victimUsername: string;
  attackerUsername: string;
  /** ROB-N1/N2: seed_alice 不在時は false (DB INSERT スキップ)。 */
  victimSeedFound: boolean;
  /** ROB-FIDO2-3: 教育的可視化のため脆弱パスで INSERT した行が成功したかどうか。
   *  失敗時 (FK 制約 / UNIQUE 衝突 / SQLITE_BUSY 等) は false。SEC-FIDO2-2 対応で
   *  return 直前に DELETE するため、本フラグは「INSERT 成立を観測したか」のみを示す。 */
  attackCredentialInserted: boolean;
};

webauthnRoutes.post("/attack/challenge-replay", (c) =>
  runAttackScenario<typeof webauthnAttackChallengeReplaySchema, ChallengeReplayExtra>(c, {
    schema: webauthnAttackChallengeReplaySchema,
    scenarioId: "fido2-challenge-replay",
    tabId: "fido2",
    async handler({ db, recordStep, trace }) {
      // ROB-FIDO2-2 / SEC-FIDO2-6: handler ローカルの TTL store。
      // 1 リクエストの両モード並列実行で完結消費するため、グローバル singleton 化不要。
      // TTL 5 分は実 challenges と整合 (handler 完了直前に明示 destroy で setInterval リーク防止)。
      const attackSimReplayChallenges = createTtlStore<{ challenge: string; username: string }>({
        ttlMs: 5 * 60 * 1000,
      });

      // 教育用 sessionId は実 uuidv4 で発行 (実装と同じ管理パスを再現)
      const vulnerableSessionId = uuidv4();
      const defendedSessionId = uuidv4();

      // seed_alice の user_id を取得 (脆弱パスで is_attack_sim=1 のクレデンシャルを INSERT する前提)
      const aliceUser = db
        .prepare("SELECT id, username FROM users WHERE username = ?")
        .get(WEBAUTHN_DEMO_CONSTANTS.victimUsername) as { id: number; username: string } | undefined;
      const victimSeedFound = !!aliceUser;

      const challengePreview = WEBAUTHN_DEMO_CONSTANTS.demoChallenge.substring(0, 16) + "...";
      const attestationPreview = WEBAUTHN_DEMO_CONSTANTS.demoAttestationPreview.substring(0, 32) + "...";

      // 両モード共通の事前準備: チャレンジを発行 + 教育用ストアに格納
      attackSimReplayChallenges.set(vulnerableSessionId, {
        challenge: WEBAUTHN_DEMO_CONSTANTS.demoChallenge,
        username: WEBAUTHN_DEMO_CONSTANTS.victimUsername,
      });
      attackSimReplayChallenges.set(defendedSessionId, {
        challenge: WEBAUTHN_DEMO_CONSTANTS.demoChallenge,
        username: WEBAUTHN_DEMO_CONSTANTS.victimUsername,
      });
      trace.addSessionOp({
        action: "STORE_CHALLENGE_FOR_REPLAY_DEMO",
        data: {
          isAttackMode: true,
          vulnerableSessionId,
          defendedSessionId,
          challengePreview,
          username: WEBAUTHN_DEMO_CONSTANTS.victimUsername,
          ttlSec: 300,
          note: "Educational TTL store separate from production challenges store.",
        },
      });

      // ── Step 1: probe — 攻撃者が seed_alice の登録セレモニーを観察し sessionId+challenge を傍受
      recordStep({
        id: "replay-1",
        kind: "probe",
        label: "Attacker observes seed_alice's registration challenge issuance",
        labelJa: "攻撃者が seed_alice の登録チャレンジ発行を観察",
        status: "success",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/webauthn/register/options (observed by attacker)",
            body: { username: WEBAUTHN_DEMO_CONSTANTS.victimUsername },
          },
          response: {
            status: 200,
            body: {
              sessionId: "<original-session-id-observed>",
              options: { challenge: challengePreview, rpId: WEBAUTHN_DEMO_CONSTANTS.rpId },
            },
          },
        },
        detailJa:
          "攻撃者は seed_alice の登録セレモニーで発行された sessionId とチャレンジを傍受します (シミュレーション)。",
        detail:
          "The attacker intercepts the sessionId and challenge issued during seed_alice's registration ceremony (simulated).",
      });

      // ── Step 2: tamper — 攻撃者が attestationObject を傍受
      recordStep({
        id: "replay-2",
        kind: "tamper",
        label: "Attacker captures seed_alice's attestationObject",
        labelJa: "攻撃者が seed_alice の attestationObject を傍受",
        status: "success",
        payload: {
          type: "generic",
          data: {
            attestationObjectPreview: attestationPreview,
            note: "Attestation contains the authenticator's signature over the challenge — bound to seed_alice's authenticator key.",
            simulationNote:
              "実際のバイナリ attestationObject ではなく教育用の固定文字列 prefix を使用しています。",
          },
        },
        detailJa:
          "attacker は attestationObject を傍受。これは seed_alice の認証器秘密鍵によりチャレンジに対して署名されたものです。",
        detail:
          "The attacker captures the attestationObject — signed over the challenge by seed_alice's authenticator private key.",
      });

      // ── Step 3: forge — 攻撃者が両方の sessionId に対して attestation を再送する準備
      recordStep({
        id: "replay-3",
        kind: "forge",
        label: "Attacker prepares to replay attestation against two server variants",
        labelJa: "攻撃者が 2 種類のサーバー実装に対して attestation を再送する準備",
        status: "success",
        payload: {
          type: "generic",
          data: {
            vulnerableSessionId,
            defendedSessionId,
            note: "Both variants will receive the same captured attestation. Behavior diverges based on whether the challenge is consumed (one-time) or kept (vulnerable).",
          },
        },
        detailJa:
          "両方のサーバー実装に同じ attestation を送ります。脆弱版 (チャレンジ削除なし) と堅牢版 (challenges.delete) で挙動が分岐します。",
        detail:
          "The attacker submits the same attestation to both variants. The vulnerable path keeps the challenge, while the defended path consumes it on first use.",
      });

      // ── Step 4: exploit (脆弱モード) — チャレンジ削除を省略して再送が成立
      // 脆弱パスでは challenges.get(sid) は削除せず、何度でも同じ challenge を返す
      const vulnerableLookup = attackSimReplayChallenges.get(vulnerableSessionId);
      const vulnerableReplayAccepted = !!vulnerableLookup;

      // 教育目的: 脆弱パスで is_attack_sim=1 のクレデンシャルを INSERT して
      // 「攻撃者が登録に成功した」状態を観測可能にする (E-3 の教育的可視化)。
      // ROB-N1/N2 ガード: seed_alice が居なければ INSERT をスキップ (FK 制約違反回避)。
      // ROB-FIDO2-1: INSERT 自体を try/catch で囲い、UNIQUE/SQLITE_BUSY/FK 等の予期せぬ例外で
      //              ハンドラ全体が 500 にならないよう ROB-N1 と同じ「失敗時 false 記録」設計に揃える。
      // ROB-FIDO2-10: vulnerableSessionId は uuidv4 で衝突は理論上発生しないが、
      //              defensive な OR IGNORE で「同一プロセス再起動でも崩れない」ことを保証する。
      const attackCredentialId = `attack-fido2-replay-${vulnerableSessionId}`;
      const attackCredentialPublicKey = "EDU_DEMO_PUBLIC_KEY_BASE64_NOT_REAL";
      let attackCredentialInserted = false;
      let attackCredentialInsertError: string | null = null;
      if (aliceUser && vulnerableReplayAccepted) {
        try {
          const t0 = performance.now();
          db.prepare(
            "INSERT OR IGNORE INTO webauthn_credentials (credential_id, user_id, public_key, counter, transports, is_attack_sim) VALUES (?, ?, ?, 0, ?, 1)"
          ).run(attackCredentialId, aliceUser.id, attackCredentialPublicKey, JSON.stringify(["internal"]));
          trace.addDbQuery({
            sql: "INSERT OR IGNORE INTO webauthn_credentials (credential_id, user_id, public_key, counter, transports, is_attack_sim) VALUES (?, ?, ?, 0, ?, 1)",
            params: [attackCredentialId, aliceUser.id, "<masked-public-key>", "[\"internal\"]"],
            ms: performance.now() - t0,
          });
          attackCredentialInserted = true;
        } catch (e) {
          // 教育目的: DB 例外でハンドラ全体を 500 にせず、step 4 を failed で記録
          attackCredentialInsertError = sanitizeForDisplay(
            e instanceof Error ? e.message : "Unknown DB error",
            128,
          );
          trace.addDbQuery({
            sql: "INSERT OR IGNORE INTO webauthn_credentials (failed: " + attackCredentialInsertError + ")",
            params: [attackCredentialId, aliceUser.id, "<masked-public-key>", "[\"internal\"]"],
            ms: 0,
          });
        }
      }

      recordStep({
        id: "replay-4",
        kind: "exploit",
        label: "Vulnerable: challenge is not deleted — replay succeeds, attacker registers credential",
        labelJa: "脆弱版: チャレンジが削除されない — リプレイが成立、攻撃者がクレデンシャル登録",
        status: vulnerableReplayAccepted && (victimSeedFound ? attackCredentialInserted : true) ? "success" : "failed",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/webauthn/register/verify (vulnerable variant — no challenges.delete)",
            body: {
              sessionId: vulnerableSessionId,
              username: WEBAUTHN_DEMO_CONSTANTS.victimUsername,
              attestationObjectPreview: attestationPreview,
            },
          },
          response: {
            status: 200,
            body: {
              verified: true,
              note: vulnerableReplayAccepted
                ? "Vulnerable: server kept the challenge in store, allowing the captured attestation to be accepted."
                : "Vulnerable path lookup failed — TTL store may have expired the challenge.",
              attackCredentialInserted,
              attackCredentialId: attackCredentialInserted ? attackCredentialId : null,
            },
          },
        },
        detailJa: vulnerableReplayAccepted
          ? `この実装は脆弱です: 検証成功後に challenges.delete(sessionId) を呼ばない実装は、傍受された attestation を受理してしまいます。${attackCredentialInserted ? `webauthn_credentials に is_attack_sim=1 で攻撃者用クレデンシャル (${attackCredentialId.substring(0, 24)}...) が登録されました。` : "(seed_alice 不在のため DB INSERT はスキップしました)"}`
          : "脆弱パス実行不可: TTL ストアからチャレンジが消えていた可能性があります。",
        detail: vulnerableReplayAccepted
          ? `This implementation is vulnerable: a server that omits challenges.delete(sessionId) after verification will accept the captured attestation. ${attackCredentialInserted ? `An attacker credential (${attackCredentialId.substring(0, 24)}...) was inserted into webauthn_credentials with is_attack_sim=1.` : "(seed_alice missing — DB insert skipped)"}`
          : "Vulnerable path could not run — challenge may have been evicted from the TTL store.",
      });

      // ── Step 5: verify (堅牢モード) — challenges.delete(sessionId) で one-time 設計を実装 → リプレイ拒否
      // 堅牢パスではまず lookup → delete → 同じ sessionId への 2 回目 lookup は undefined
      const firstLookup = attackSimReplayChallenges.get(defendedSessionId);
      attackSimReplayChallenges.delete(defendedSessionId); // ← 防御の核心: 検証後に即削除
      trace.addSessionOp({
        action: "WEBAUTHN_CHALLENGE_CONSUMED",
        data: {
          isAttackMode: true,
          sessionId: defendedSessionId,
          firstLookupSucceeded: !!firstLookup,
          note: "Defended: challenges.delete(sessionId) called immediately after first verification.",
        },
      });
      const secondLookup = attackSimReplayChallenges.get(defendedSessionId);
      const defendedReplayBlocked = !secondLookup;
      recordStep({
        id: "replay-5",
        kind: "verify",
        label: "Defended: challenges.delete(sessionId) consumes the challenge — replay blocked",
        labelJa: "堅牢版: challenges.delete(sessionId) でチャレンジを消費 — リプレイ拒否",
        status: defendedReplayBlocked ? "blocked" : "failed",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/webauthn/register/verify (defended variant — second submission)",
            body: {
              sessionId: defendedSessionId,
              username: WEBAUTHN_DEMO_CONSTANTS.victimUsername,
              attestationObjectPreview: attestationPreview,
            },
          },
          response: {
            status: 400,
            body: {
              error: "No challenge found or challenge expired",
              blockedBy: "webauthn_challenge_one_time_consumed",
              note: "Defended: challenges.delete() removed the challenge after first verification; the second submission finds nothing.",
            },
          },
        },
        detailJa:
          "堅牢実装は verifyRegistrationResponse() 成功後に challenges.delete(sessionId) を呼びます。2 回目の submission では challenges.get(sessionId) が undefined を返し、サーバーは『No challenge found』として 400 を返します。",
        detail:
          "The defended implementation calls challenges.delete(sessionId) after a successful verifyRegistrationResponse(). On the second submission, challenges.get(sessionId) returns undefined, and the server returns 400 'No challenge found'.",
      });

      // 後始末 1: 脆弱パスのチャレンジも明示的に削除 (TTL 経過待ちでメモリ汚染回避)
      attackSimReplayChallenges.delete(vulnerableSessionId);

      // 後始末 2: SEC-FIDO2-2 — 攻撃シミュレーション用 webauthn_credentials 行を即削除。
      // 「INSERT 成立を観測したか」(extra.attackCredentialInserted) は教育目的で残すが、
      // 連続実行で is_attack_sim=1 行が無制限に蓄積するのを防ぐため。
      // 教育的可視化はトレース (trace.addDbQuery) と AttackStep.payload で十分カバーされる。
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
        blockedBy: "webauthn_challenge_one_time_consumed",
        summary:
          "A vulnerable server keeping the challenge after verification accepts the captured attestation (replay succeeds). The defended implementation calls challenges.delete(sessionId) immediately after first use, blocking any replay.",
        summaryJa:
          "この実装は脆弱です: チャレンジ削除を省略する実装は傍受された attestation を再受理してしまいます。堅牢実装は challenges.delete(sessionId) で初回検証後に即削除し、リプレイを完全に阻止します。",
        extra: {
          replayChallengePreview: challengePreview,
          vulnerableReplayAccepted,
          defendedReplayBlocked,
          vulnerableSessionId,
          defendedSessionId,
          attestationPreview,
          victimUsername: WEBAUTHN_DEMO_CONSTANTS.victimUsername,
          attackerUsername: WEBAUTHN_DEMO_CONSTANTS.attackerUsername,
          victimSeedFound,
          attackCredentialInserted,
        } satisfies ChallengeReplayExtra,
        payload: {
          params: {},
          result: {
            replayChallengePreview: challengePreview,
            vulnerableReplayAccepted,
            defendedReplayBlocked,
            attackCredentialInserted,
            attackCredentialInsertError,
            victimSeedFound,
          },
        },
      };
    },
  })
);
