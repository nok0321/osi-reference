import { Hono } from "hono";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { v4 as uuidv4 } from "uuid";
import { getDb } from "../db/schema.js";
import bcrypt from "bcryptjs";
import {
  parseBody,
  oidcAuthorizeSchema,
  oidcTokenSchema,
  samlSsoSchema,
  samlAttackXswSchema,
  samlAttackAssertionReplaySchema,
  oidcAttackIdTokenSpoofSchema,
} from "../validation.js";
import type { UserRow, OAuthClientRow } from "../../shared/api-types.js";
import { createTtlStore } from "../utils/ttl-store.js";
import { runAttackScenario, maskSecret, sanitizeForDisplay } from "../utils/attack-runner.js";

export const oidcSamlSimRoutes = new Hono();

const OIDC_SECRET = "osi-demo-oidc-signing-key";
const ISSUER = "http://localhost:3001/api/oidc";

// ── OIDC Discovery ──
oidcSamlSimRoutes.get("/.well-known/openid-configuration", (c) => {
  return c.json({
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/authorize`,
    token_endpoint: `${ISSUER}/token`,
    userinfo_endpoint: `${ISSUER}/userinfo`,
    jwks_uri: `${ISSUER}/jwks`,
    response_types_supported: ["code"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["HS256"],
    scopes_supported: ["openid", "profile", "email"],
    token_endpoint_auth_methods_supported: ["client_secret_post"],
    claims_supported: ["sub", "name", "email", "iss", "aud", "exp", "iat", "nonce"],
  });
});

// ── OIDC Authorization ──
interface OidcCodeData {
  userId: number;
  nonce: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
}
const oidcChallenges = createTtlStore<OidcCodeData>({ ttlMs: 10 * 60 * 1000 });

oidcSamlSimRoutes.post("/authorize", async (c) => {
  const parsed = await parseBody(c, oidcAuthorizeSchema);
  if ("error" in parsed) return parsed.error;
  const { username, password, client_id, redirect_uri, scope, state, nonce, code_challenge, code_challenge_method } = parsed.data;
  const trace = c.get("trace");
  const db = getDb();

  // Verify client and redirect_uri against registered client (reuse oauth_clients table)
  const client = db
    .prepare("SELECT client_id, client_secret, name, redirect_uris FROM oauth_clients WHERE client_id = ?")
    .get(client_id) as OAuthClientRow | undefined;
  if (!client) {
    return c.json({ success: false, error: "Unknown client_id" }, 400);
  }
  const registeredUris: string[] = JSON.parse(client.redirect_uris || "[]");
  if (!registeredUris.includes(redirect_uri)) {
    return c.json(
      { success: false, error: `Invalid redirect_uri. Registered: ${registeredUris.join(", ")}` },
      400
    );
  }

  const user = db.prepare("SELECT id, username, password_hash FROM users WHERE username = ?").get(username) as UserRow | undefined;
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return c.json({ success: false, error: "Invalid credentials" }, 401);
  }

  const code = uuidv4();
  oidcChallenges.set(code, {
    userId: user.id,
    nonce: nonce || "",
    codeChallenge: code_challenge,
    codeChallengeMethod: code_challenge_method,
  });

  trace.addCryptoOp({
    op: "generateAuthCode(OIDC)",
    input: `user=${username}, scope=${scope}`,
    output: code,
    algo: "UUIDv4",
    detail: code_challenge
      ? `PKCE enabled: code_challenge_method=${code_challenge_method}`
      : "No PKCE — code_challenge not provided",
  });

  return c.json({
    success: true,
    data: {
      code,
      state,
      redirect: `${redirect_uri}?code=${code}&state=${state}`,
      pkce: code_challenge ? { method: code_challenge_method, challenge: code_challenge } : null,
    },
  });
});

// ── OIDC Token Exchange ──
oidcSamlSimRoutes.post("/token", async (c) => {
  const parsed = await parseBody(c, oidcTokenSchema);
  if ("error" in parsed) return parsed.error;
  const { code, client_id, client_secret, redirect_uri, code_verifier } = parsed.data;
  const trace = c.get("trace");
  const db = getDb();

  const codeData = oidcChallenges.get(code);
  if (!codeData) {
    return c.json({ success: false, error: "Invalid or expired authorization code" }, 400);
  }

  // PKCE verification
  if (codeData.codeChallenge) {
    if (!code_verifier) {
      return c.json({ success: false, error: "code_verifier required for PKCE" }, 400);
    }
    let computedChallenge: string;
    if (codeData.codeChallengeMethod === "S256") {
      computedChallenge = crypto.createHash("sha256").update(code_verifier).digest("base64url");
    } else {
      computedChallenge = code_verifier;
    }
    const computedBuf = Buffer.from(computedChallenge, "utf8");
    const storedBuf = Buffer.from(codeData.codeChallenge, "utf8");
    const pkceValid =
      computedBuf.length === storedBuf.length &&
      crypto.timingSafeEqual(computedBuf, storedBuf);
    trace.addCryptoOp({
      op: "PKCE verify",
      input: `code_verifier="${code_verifier.substring(0, 20)}..."`,
      output: pkceValid ? "MATCH ✓" : "MISMATCH ✗",
      algo: codeData.codeChallengeMethod || "plain",
      detail: `SHA256(code_verifier) vs stored code_challenge (constant-time compare)`,
    });
    if (!pkceValid) {
      return c.json({ success: false, error: "PKCE verification failed" }, 400);
    }
  }

  const user = db.prepare("SELECT id, username FROM users WHERE id = ?").get(codeData.userId) as Pick<UserRow, "id" | "username"> | undefined;
  if (!user) {
    return c.json({ success: false, error: "User not found" }, 500);
  }

  // Generate ID Token
  const idToken = jwt.sign(
    {
      iss: ISSUER,
      sub: String(user.id),
      aud: client_id,
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
      nonce: codeData.nonce,
      name: user.username,
      email: `${user.username}@demo.example`,
    },
    OIDC_SECRET,
    { algorithm: "HS256" }
  );
  trace.addCryptoOp({
    op: "jwt.sign(id_token)",
    input: `sub=${user.id}, aud=${client_id}, nonce=${codeData.nonce}`,
    output: idToken.substring(0, 40) + "...",
    algo: "HS256",
    detail: "OpenID Connect ID Token — contains user identity claims",
  });

  // Generate access token
  const accessToken = jwt.sign(
    { sub: String(user.id), scope: "openid profile email", type: "oidc_access" },
    OIDC_SECRET,
    { expiresIn: "1h" }
  );

  oidcChallenges.delete(code);

  return c.json({
    success: true,
    data: {
      access_token: accessToken,
      id_token: idToken,
      token_type: "Bearer",
      expires_in: 3600,
      scope: "openid profile email",
      id_token_decoded: jwt.decode(idToken),
    },
  });
});

// ── OIDC UserInfo ──
oidcSamlSimRoutes.get("/userinfo", (c) => {
  const trace = c.get("trace");
  const auth = c.req.header("Authorization");
  if (!auth?.startsWith("Bearer ")) {
    return c.json({ success: false, error: "No Bearer token" }, 401);
  }
  try {
    const decoded = jwt.verify(auth.slice(7), OIDC_SECRET) as { sub: string; scope: string };
    trace.addCryptoOp({
      op: "jwt.verify(oidc_access_token)",
      input: auth.slice(7).substring(0, 30) + "...",
      output: "VALID ✓",
      algo: "HS256",
    });
    const db = getDb();
    const user = db.prepare("SELECT id, username FROM users WHERE id = ?").get(decoded.sub) as Pick<UserRow, "id" | "username"> | undefined;
    if (!user) {
      return c.json({ success: false, error: "User not found" }, 401);
    }
    return c.json({
      sub: String(user.id),
      name: user.username,
      email: `${user.username}@demo.example`,
      email_verified: true,
    });
  } catch {
    return c.json({ success: false, error: "Invalid token" }, 401);
  }
});

/*
 * EDUCATIONAL SIMULATION — NOT a real SAML implementation.
 *
 * Simplifications vs real SAML 2.0:
 * - Assertion format: real SAML uses XML with XML Digital Signature (RSA-SHA256 / ECDSA).
 *   This demo returns JSON with HMAC-SHA256 for readability.
 * - Encryption: real SAML optionally encrypts assertions with XML Encryption.
 *   This demo sends assertions in plaintext.
 * - Binding protocol: real SAML uses HTTP-POST or HTTP-Redirect binding with Base64-encoded XML.
 *   This demo uses a simple JSON API.
 * - Metadata exchange: real SPs and IdPs exchange XML metadata with embedded certificates.
 *   This demo has a minimal /metadata endpoint.
 * - Signature validation: real SPs verify XML-DSIG against the IdP's public certificate.
 *   This demo skips certificate-based verification entirely.
 */

// ── SAML Simulation ──
oidcSamlSimRoutes.post("/saml/sso", async (c) => {
  const parsed = await parseBody(c, samlSsoSchema);
  if ("error" in parsed) return parsed.error;
  const { username, password, sp_entity_id } = parsed.data;
  const trace = c.get("trace");
  const db = getDb();

  const user = db.prepare("SELECT id, username, password_hash FROM users WHERE username = ?").get(username) as UserRow | undefined;
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return c.json({ success: false, error: "Invalid credentials" }, 401);
  }

  const assertionId = `_${uuidv4()}`;
  const issueInstant = new Date().toISOString();
  const notOnOrAfter = new Date(Date.now() + 5 * 60 * 1000).toISOString();

  // Simulated SAML Assertion (simplified XML structure as JSON for visualization)
  const assertion = {
    "@ID": assertionId,
    "@IssueInstant": issueInstant,
    Issuer: ISSUER,
    Subject: {
      NameID: { "@Format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", "#text": `${username}@demo.example` },
      SubjectConfirmation: { "@Method": "urn:oasis:names:tc:SAML:2.0:cm:bearer", SubjectConfirmationData: { "@NotOnOrAfter": notOnOrAfter, "@Recipient": sp_entity_id } },
    },
    Conditions: { "@NotBefore": issueInstant, "@NotOnOrAfter": notOnOrAfter, AudienceRestriction: { Audience: sp_entity_id } },
    AuthnStatement: { "@AuthnInstant": issueInstant, AuthnContext: { AuthnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:Password" } },
    AttributeStatement: {
      Attributes: [
        { Name: "email", Value: `${username}@demo.example` },
        { Name: "displayName", Value: username },
        { Name: "role", Value: "user" },
      ],
    },
  };

  // Simulate signing
  const assertionJson = JSON.stringify(assertion);
  const signature = crypto.createHmac("sha256", OIDC_SECRET).update(assertionJson).digest("base64");
  trace.addCryptoOp({
    op: "signSAMLAssertion",
    input: `Assertion ID=${assertionId}, Subject=${username}`,
    output: signature.substring(0, 30) + "...",
    algo: "HMAC-SHA256 (simulated XML-DSIG)",
    detail: "In real SAML: XML Digital Signature with RSA-SHA256 or ECDSA",
  });

  return c.json({
    success: true,
    data: {
      assertion,
      signature,
      samlResponse: Buffer.from(assertionJson).toString("base64"),
      assertionId,
      explanation: {
        flow: "SP-initiated SSO",
        steps: [
          "1. SP sends AuthnRequest to IdP",
          "2. IdP authenticates user",
          "3. IdP creates SAML Assertion with user attributes",
          "4. IdP signs assertion with private key",
          "5. IdP sends SAMLResponse (Base64) back to SP",
          "6. SP validates signature and extracts attributes",
        ],
      },
    },
  });
});

// SAML metadata
oidcSamlSimRoutes.get("/saml/metadata", (c) => {
  return c.json({
    entityID: ISSUER,
    singleSignOnService: `${ISSUER}/saml/sso`,
    nameIDFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    signingCertificate: "(self-signed demo certificate)",
  });
});

/**
 * 攻撃デモルート: oidc-saml タブ
 *
 * 【教育目的専用】
 * このコードは OSI 参照アプリの教材機能として、
 * ローカル環境の固定シードデータに対する攻撃シミュレーションを提供します。
 *
 * - 外部ネットワークへのリクエストは行いません (attacker.example は概念的な架空ドメイン)
 * - 実 XML パーサ・XPath 検証は使用せず、JSON で 2 層構造を簡略表現します
 * - 攻撃者 IdP は jsonwebtoken の sign() でローカル発行を再現します
 * - 本番環境での使用は想定していません (ensureAttackEnabled middleware が NODE_ENV=production で 403 拒否)
 *
 * 対象 CWE: CWE-345 (insufficient verification), CWE-294 (capture-replay), CWE-1004 (insufficient credential protection)
 * 対象 CAPEC: CAPEC-475 (XSW signature spoofing), CAPEC-60 (replay), CAPEC-196 (credential forging)
 * 関連設計書: DESIGN/16-attack-oidc-saml.md
 * 安全装置: DESIGN/04-safety-guardrails.md
 */

// ── 共通シード (immutable) ──
// ROB-FIND-007 / ROB-RBAC-3 / ROB-FIDO2-5 と同パターンで `as const satisfies Readonly<...>` を採用。
// 攻撃者制御値 (attackerIssuer / attackerAud / attackerNonce / attackerSigningKey) と
// 正規値 (legitimateIssuer / legitimateAud / legitimateNonce) の対比を SSoT 一本化することで、
// 一方を変更し忘れて両者が偶然一致してしまう事故 (= 検証バイパス) を防ぐ。
// ROB-OIDC-3: 各シナリオで散在していた TTL / 期限 / 固定 ID / メールサフィックスを SSoT に集約。
const OIDC_SAML_DEMO_CONSTANTS = {
  victimUsername: "seed_alice",
  attackerUsername: "attacker_charlie",
  // フィッシング/中継シナリオで「ユーザーが事前に傍受されたパスワード」を表す
  // — シミュレーション専用。`bcrypt.compare` で実際にハッシュと比較する (seed_alice の seedPwd と一致)。
  victimPasswordPlain: "Passw0rd!",
  legitimateIssuer: ISSUER, // "http://localhost:3001/api/oidc"
  attackerIssuer: "https://attacker.example/oidc",
  // OIDC client_id (RP の aud クレームに対応)。OidcSamlFlow.tsx で使用される値と整合
  legitimateAud: "demo-oidc-app",
  attackerAud: "victim-rp-client",
  spEntityId: "https://sp.example.com/metadata",
  // 教育用固定 nonce (実装は authorize 時に nonce を保存する。この値は「期待されている nonce」を表す)。
  // 攻撃者発行の attackerNonce との不一致を堅牢パスのトレース出力で対比するために使用 (SPEC-OIDC-1)。
  legitimateNonce: "legit_nonce_abc123",
  attackerNonce: "attacker_nonce_xyz",
  // 攻撃者 IdP の HMAC 鍵 (デモ用 — 正規 OIDC_SECRET と異なる値であることを示す)。
  // 「攻撃者は自分の IdP を制御」という前提 (DESIGN/16 §4.3) の表現。
  attackerSigningKey: "attacker-evil-idp-signing-key",
  // 教育用 SAML アサーションの NotOnOrAfter ウィンドウ (5 分)。oidc-saml-sim.ts /saml/sso と整合。
  assertionLifetimeMs: 5 * 60 * 1000,
  // 教育用「期限切れアサーション」のオフセット (現在時刻より 1 分前)。
  expiredAssertionOffsetMs: 60 * 1000,
  // OneTimeUse キャッシュの TTL (10 分)。assertionLifetimeMs より長く、テストの確実性を優先。
  replayCacheTtlMs: 10 * 60 * 1000,
  // XSW シナリオで外側に挿入する固定 fake assertion ID。
  fakeAssertionId: "_fake_assertion_001",
  // 教育用メールアドレスのドメインサフィックス (RFC 6761 .example で実害なし)。
  demoEmailSuffix: "@demo.example",
} as const satisfies Readonly<{
  victimUsername: string;
  attackerUsername: string;
  victimPasswordPlain: string;
  legitimateIssuer: string;
  attackerIssuer: string;
  legitimateAud: string;
  attackerAud: string;
  spEntityId: string;
  legitimateNonce: string;
  attackerNonce: string;
  attackerSigningKey: string;
  assertionLifetimeMs: number;
  expiredAssertionOffsetMs: number;
  replayCacheTtlMs: number;
  fakeAssertionId: string;
  demoEmailSuffix: string;
}>;

// ── Scenario A: SAML XML Signature Wrapping (XSW) ──
// 防御の核心: 署名対象の要素 ID と実際に処理するアサーション要素の ID が一致することを XPath で確認する。
// 素朴なパーサは「署名が通れば OK」と判断し、ラップされた外側の偽アサーションを処理してしまう。
type SamlXswExtra = {
  signedAssertionId: string;
  fakeAssertionId: string;
  legitimateSubject: string;
  fakeSubject: string;
  legitimateRole: string;
  fakeRole: string;
  vulnerableProcessedSubject: string;
  vulnerableProcessedRole: string;
  defendedRejected: boolean;
  victimUsername: string;
  /** ROB-N1/N2: seed_alice 不在時は false (bcrypt.compare をスキップ)。 */
  victimSeedFound: boolean;
};

oidcSamlSimRoutes.post("/attack/saml-xsw", (c) =>
  runAttackScenario<typeof samlAttackXswSchema, SamlXswExtra>(c, {
    schema: samlAttackXswSchema,
    scenarioId: "saml-xsw",
    tabId: "oidc-saml",
    async handler({ db, recordStep, trace }) {
      // ROB-N1/N2: seed_alice 不在ガード (bcrypt.compare は seed_alice 前提)
      const aliceUser = db
        .prepare("SELECT id, username, password_hash FROM users WHERE username = ?")
        .get(OIDC_SAML_DEMO_CONSTANTS.victimUsername) as
        | { id: number; username: string; password_hash: string }
        | undefined;
      const victimSeedFound = !!aliceUser;

      // assertion ID: 内側 (正規・署名済み) と 外側 (偽・署名対象外)
      const signedAssertionId = `_real_assertion_${uuidv4().substring(0, 12)}`;
      const fakeAssertionId = OIDC_SAML_DEMO_CONSTANTS.fakeAssertionId;

      const legitimateSubject = `${OIDC_SAML_DEMO_CONSTANTS.victimUsername}${OIDC_SAML_DEMO_CONSTANTS.demoEmailSuffix}`;
      const fakeSubject = `${OIDC_SAML_DEMO_CONSTANTS.attackerUsername}${OIDC_SAML_DEMO_CONSTANTS.demoEmailSuffix}`;
      const legitimateRole = "user";
      const fakeRole = "admin";
      const safeFakeSubject = sanitizeForDisplay(fakeSubject, 256);

      // 正規認証 (real bcrypt.compare → 正規アサーション取得をシミュレート)
      let legitimateAuthOk = false;
      if (aliceUser) {
        const t0 = performance.now();
        legitimateAuthOk = await bcrypt.compare(
          OIDC_SAML_DEMO_CONSTANTS.victimPasswordPlain,
          aliceUser.password_hash,
        );
        trace.addCryptoOp({
          op: "bcrypt_compare(seed_alice_for_legitimate_assertion)",
          input: `username=${OIDC_SAML_DEMO_CONSTANTS.victimUsername}, password=${maskSecret(OIDC_SAML_DEMO_CONSTANTS.victimPasswordPlain)}`,
          output: legitimateAuthOk ? "MATCH ✓" : "NO MATCH ✗",
          algo: `bcrypt (verified in ${(performance.now() - t0).toFixed(1)}ms)`,
          detail:
            "Real authentication of seed_alice to obtain a baseline legitimate SAML assertion. The attacker is assumed to have credentials (e.g., previously phished) — this step recreates that baseline.",
        });
      }

      // 内側 (正規) アサーションを構築 + HMAC-SHA256 で署名
      const notOnOrAfter = new Date(
        Date.now() + OIDC_SAML_DEMO_CONSTANTS.assertionLifetimeMs,
      ).toISOString();
      const legitimateAssertion = {
        "@ID": signedAssertionId,
        Issuer: OIDC_SAML_DEMO_CONSTANTS.legitimateIssuer,
        Subject: { NameID: { "#text": legitimateSubject } },
        Conditions: { "@NotOnOrAfter": notOnOrAfter },
        AttributeStatement: { Attributes: [{ Name: "role", Value: legitimateRole }] },
      };
      const legitimateAssertionJson = JSON.stringify(legitimateAssertion);
      const signature = legitimateAuthOk
        ? crypto.createHmac("sha256", OIDC_SECRET).update(legitimateAssertionJson).digest("base64")
        : "<not-computed: seed_alice missing>";
      const signaturePreview =
        signature.length > 30 ? signature.substring(0, 30) + "..." : signature;

      trace.addCryptoOp({
        op: "signSAMLAssertion(legitimate_inner)",
        input: `AssertionID=${signedAssertionId}, Subject=${legitimateSubject}, role=${legitimateRole}`,
        output: signaturePreview,
        algo: "HMAC-SHA256 (simulated XML-DSIG)",
        detail:
          "Signature is computed over the inner (legitimate) assertion. The outer fake assertion is NOT covered by this signature — XSW exploits this gap.",
      });

      // ── Step 1: probe — 攻撃者が seed_alice として認証して正規 SAML アサーションを取得
      recordStep({
        id: "xsw-1",
        kind: "probe",
        label: "Attacker authenticates as seed_alice and obtains legitimate SAML assertion",
        labelJa: "攻撃者が seed_alice として認証し、正規 SAML アサーションを取得",
        status: legitimateAuthOk ? "success" : "failed",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/oidc/saml/sso (attacker uses pre-captured credentials)",
            body: {
              username: OIDC_SAML_DEMO_CONSTANTS.victimUsername,
              password: maskSecret(OIDC_SAML_DEMO_CONSTANTS.victimPasswordPlain),
              sp_entity_id: OIDC_SAML_DEMO_CONSTANTS.spEntityId,
            },
          },
          response: {
            status: legitimateAuthOk ? 200 : 401,
            body: legitimateAuthOk
              ? {
                  assertion: {
                    "@ID": signedAssertionId,
                    Subject: { NameID: { "#text": legitimateSubject } },
                    Conditions: { "@NotOnOrAfter": notOnOrAfter },
                    AttributeStatement: { Attributes: [{ Name: "role", Value: legitimateRole }] },
                  },
                  signature: signaturePreview,
                }
              : { error: "seed_alice missing — DB seed unavailable" },
          },
        },
        detailJa: legitimateAuthOk
          ? "攻撃者は事前に傍受されたパスワードで seed_alice として認証し、正規 SAML アサーションを取得します。署名は内側 (正規) アサーションに対して計算されます。"
          : "シナリオ実行不可: seed_alice が DB に存在しません。",
        detail: legitimateAuthOk
          ? "The attacker authenticates as seed_alice (password assumed pre-captured) and obtains a legitimate SAML assertion. The signature is computed over the inner (legitimate) assertion."
          : "Scenario unavailable: seed_alice missing from seeds.",
      });

      // ── Step 2: tamper — 攻撃者が XSW ペイロードを構築 (外側=偽 admin / 内側=正規 user)
      recordStep({
        id: "xsw-2",
        kind: "tamper",
        label: "Attacker wraps legitimate assertion and inserts fake admin assertion in outer scope",
        labelJa: "攻撃者が正規アサーションをラップし偽管理者アサーションを外側に挿入",
        status: "success",
        payload: {
          type: "generic",
          data: {
            note: "XSW 構造: 外側に偽 (admin) を配置し、内側の正規 (user) を SignedAssertion 要素としてラップ。署名は内側 ID を参照しているが、素朴なパーサは外側を処理する。",
            outerFakeAssertion: {
              "@ID": fakeAssertionId,
              Subject: { NameID: { "#text": safeFakeSubject } },
              AttributeStatement: { Attributes: [{ Name: "role", Value: fakeRole }] },
              note: "署名対象外。攻撃者が任意に作成したアサーション。",
            },
            innerSignedAssertion: {
              "@ID": signedAssertionId,
              Subject: { NameID: { "#text": legitimateSubject } },
              AttributeStatement: { Attributes: [{ Name: "role", Value: legitimateRole }] },
              note: "署名対象。seed_alice に対する正当な署名。",
            },
            signaturePreview,
            signedId: signedAssertionId,
          },
        },
        detailJa:
          "攻撃者は正規アサーションを SignedAssertion 要素としてラップし、その外側に偽の管理者アサーション (admin / attacker_charlie) を挿入します。署名は内側 ID に対して有効ですが、外側は署名範囲外です。",
        detail:
          "The attacker wraps the legitimate assertion as SignedAssertion and inserts a fake admin assertion (admin / attacker_charlie) outside it. The signature is valid for the inner ID, but the outer is outside the signature scope.",
      });

      // ── Step 3: forge — 攻撃者が XSW ペイロードを SP に送信
      recordStep({
        id: "xsw-3",
        kind: "forge",
        label: "Attacker submits XSW payload to SP for verification",
        labelJa: "攻撃者が XSW ペイロードを SP に送信",
        status: "success",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/oidc/attack/saml-xsw (simulated SP submission — both variants receive same payload)",
            body: {
              SAMLResponse: {
                Assertion: {
                  "@ID": fakeAssertionId,
                  Subject: { NameID: { "#text": safeFakeSubject } },
                  AttributeStatement: { Attributes: [{ Name: "role", Value: fakeRole }] },
                },
                SignedAssertion: {
                  assertion: {
                    "@ID": signedAssertionId,
                    Subject: { NameID: { "#text": legitimateSubject } },
                    AttributeStatement: { Attributes: [{ Name: "role", Value: legitimateRole }] },
                  },
                  signature: signaturePreview,
                },
              },
            },
          },
          tamperedFields: ["SAMLResponse.Assertion"],
        },
        detailJa:
          "攻撃者は XSW ペイロード (外側=偽 / 内側=正規署名済み) を SP の検証エンドポイントに送信します。SP の実装次第で成立または阻止します。",
        detail:
          "The attacker sends the XSW payload (outer=fake / inner=signed) to the SP's verify endpoint. Behavior depends on the SP implementation.",
      });

      // ── Step 4: exploit (脆弱モード) — 素朴なパーサが署名を確認するが処理対象は外側偽
      const vulnerableProcessedSubject = safeFakeSubject;
      const vulnerableProcessedRole = fakeRole;
      trace.addCryptoOp({
        op: "naiveVerify(SAMLResponse_xsw)",
        input: `signedId=${signedAssertionId}, processedId=${fakeAssertionId}, signedSubject=${legitimateSubject}, processedSubject=${safeFakeSubject}`,
        output: `signatureValid=true, processedSubject=${safeFakeSubject}, processedRole=${fakeRole} — XSW SUCCESS`,
        algo: "naive-scope-check (no XPath ID match)",
        detail:
          "Vulnerable: signature verification only checks 'is the signature valid?'. The processed assertion (outer fake) differs from the signed assertion (inner real) — XSW exploits this gap.",
      });
      recordStep({
        id: "xsw-4",
        kind: "exploit",
        label: "Vulnerable: naive parser accepts XSW — signature valid but processes fake admin assertion",
        labelJa: "脆弱版: 素朴なパーサが XSW を受理 — 署名は有効だが偽管理者アサーションを処理",
        // ROB-OIDC-4: status は legitimateAuthOk に連動。seed_alice 不在 (= signature が "<not-computed>")
        // のときに「XSW 成立」を主張するのは教育的に誤誘導なので failed として扱う。
        status: legitimateAuthOk ? "success" : "failed",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/oidc/attack/saml-xsw (vulnerable variant — no XPath scope check)",
          },
          response: {
            status: legitimateAuthOk ? 200 : 401,
            body: legitimateAuthOk
              ? {
                  outcome: "succeeded",
                  signatureValid: true,
                  processedSubject: vulnerableProcessedSubject,
                  processedRole: vulnerableProcessedRole,
                  note: "Vulnerable: signature is valid for the inner element, but the parser processes the outer fake assertion. XSW succeeded.",
                }
              : {
                  error: "Vulnerable path could not run — seed_alice missing from seeds (no legitimate signature to wrap).",
                },
          },
        },
        detailJa: legitimateAuthOk
          ? "この実装は脆弱です: 素朴なパーサは『署名が通れば OK』と判断し、外側の偽アサーション (admin / attacker_charlie) の属性を読み込んでしまいます。署名対象 ID と処理対象 ID の不一致を検出していません。"
          : "脆弱パス実行不可: seed_alice が DB に存在しないため正規署名を構築できず、XSW のラップ対象がありません。",
        detail: legitimateAuthOk
          ? "This implementation is vulnerable: a naive parser concludes 'signature OK' and processes the outer fake assertion's attributes (admin / attacker_charlie). It fails to detect the mismatch between the signed ID and the processed ID."
          : "Vulnerable path could not run — seed_alice missing from seeds, so no legitimate signature exists to wrap.",
      });

      // ── Step 5: verify (堅牢モード) — XPath 署名範囲検証で ID 不一致を検出 → 拒否
      const defendedRejected = signedAssertionId !== fakeAssertionId; // 設計上常に true
      trace.addCryptoOp({
        op: "strictVerify(XPath_scope_check)",
        input: `signedId=${signedAssertionId}, processedId=${fakeAssertionId}`,
        output: defendedRejected ? "MISMATCH → reject (XSW DETECTED)" : "match (no XSW)",
        algo: "XPath signature scope check (xml-crypto pattern)",
        detail:
          "Defended: the strict parser uses XPath to verify that the signed element ID matches the processed element ID. Mismatch → throw → SP returns 400.",
      });
      recordStep({
        id: "xsw-5",
        kind: "verify",
        label: "Defended: strict parser detects ID mismatch between signed and processed assertion — XSW blocked",
        labelJa: "堅牢版: 厳密なパーサが署名対象 ID と処理対象 ID の不一致を検出 — XSW 阻止",
        status: defendedRejected ? "blocked" : "failed",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/oidc/attack/saml-xsw (defended variant — XPath scope check)",
          },
          response: {
            status: 400,
            body: {
              error: `XSW detected: signed ID='${signedAssertionId}' !== processed ID='${fakeAssertionId}'`,
              blockedBy: "saml_xsw_signed_id_processed_id_match_enforced",
            },
          },
        },
        detailJa:
          "堅牢実装は XPath による署名範囲検証で『署名対象の要素 ID』と『実際に処理するアサーション要素の ID』が一致することを確認します。XSW ペイロードでは 2 つの ID が異なるため、検証は失敗し SP は 400 を返します。",
        detail:
          "The defended implementation uses XPath to verify that 'the signed element ID' equals 'the processed assertion element ID'. In an XSW payload, these two IDs differ, so verification fails and the SP returns 400.",
      });

      return {
        blockedBy: "saml_xsw_signed_id_processed_id_match_enforced",
        summary:
          "A vulnerable SP that only checks 'signature valid?' accepts the XSW payload and processes the outer fake admin assertion. The defended SP enforces XPath scope check (signed ID === processed ID), blocking XSW.",
        summaryJa:
          "この実装は脆弱です: 署名検証のみ通過すれば OK と判断する SP は XSW ペイロードを受理し、外側の偽管理者アサーションを処理してしまいます。堅牢実装は XPath による署名範囲検証 (署名対象 ID === 処理対象 ID) で XSW を阻止します。",
        extra: {
          signedAssertionId,
          fakeAssertionId,
          legitimateSubject,
          fakeSubject: safeFakeSubject,
          legitimateRole,
          fakeRole,
          vulnerableProcessedSubject,
          vulnerableProcessedRole,
          defendedRejected,
          victimUsername: OIDC_SAML_DEMO_CONSTANTS.victimUsername,
          victimSeedFound,
        } satisfies SamlXswExtra,
        payload: {
          params: {},
          result: {
            signedAssertionIdPreview: signedAssertionId.substring(0, 24) + "...",
            fakeAssertionId,
            vulnerableProcessedRole,
            defendedRejected,
            victimSeedFound,
          },
        },
      };
    },
  })
);

// ── Scenario B: SAML Assertion Replay ──
// 防御の核心: アサーション ID を OneTimeUse キャッシュに記録し、再使用を拒否する。
// NotOnOrAfter による時刻制約も併せて検証する。
type SamlAssertionReplayExtra = {
  capturedAssertionId: string;
  vulnerableReplayAccepted: boolean;
  defendedReplayBlocked: boolean;
  notOnOrAfterCheckTested: boolean;
  notOnOrAfterCheckBlocked: boolean;
  victimUsername: string;
  attackerUsername: string;
  /** ROB-N1/N2: seed_alice 不在時は false (bcrypt.compare をスキップ)。 */
  victimSeedFound: boolean;
};

oidcSamlSimRoutes.post("/attack/saml-assertion-replay", (c) =>
  runAttackScenario<typeof samlAttackAssertionReplaySchema, SamlAssertionReplayExtra>(c, {
    schema: samlAttackAssertionReplaySchema,
    scenarioId: "saml-assertion-replay",
    tabId: "oidc-saml",
    async handler({ db, recordStep, trace }) {
      // ROB-FIDO2-2 / SEC-FIDO2-6: handler ローカルの TTL store。
      // 1 リクエスト内で完結消費するため、グローバル singleton 化不要。
      // TTL 10 分は SAML アサーションの NotOnOrAfter (5 分) より長く、テストの確実性を優先。
      // ROB-OIDC-1 / SEC-OIDC-2: try/finally で例外時も destroy() を必ず実行 (setInterval リーク防止)。
      const attackSimUsedAssertions = createTtlStore<{
        usedAt: number;
        assertionId: string;
      }>({ ttlMs: OIDC_SAML_DEMO_CONSTANTS.replayCacheTtlMs });

      try {
      // ROB-N1/N2: seed_alice 不在ガード
      const aliceUser = db
        .prepare("SELECT id, username, password_hash FROM users WHERE username = ?")
        .get(OIDC_SAML_DEMO_CONSTANTS.victimUsername) as
        | { id: number; username: string; password_hash: string }
        | undefined;
      const victimSeedFound = !!aliceUser;

      // 認証 (real bcrypt) → assertion 生成
      let legitimateAuthOk = false;
      if (aliceUser) {
        const t0 = performance.now();
        legitimateAuthOk = await bcrypt.compare(
          OIDC_SAML_DEMO_CONSTANTS.victimPasswordPlain,
          aliceUser.password_hash,
        );
        trace.addCryptoOp({
          op: "bcrypt_compare(seed_alice_for_replay_baseline)",
          input: `username=${OIDC_SAML_DEMO_CONSTANTS.victimUsername}, password=${maskSecret(OIDC_SAML_DEMO_CONSTANTS.victimPasswordPlain)}`,
          output: legitimateAuthOk ? "MATCH ✓" : "NO MATCH ✗",
          algo: `bcrypt (verified in ${(performance.now() - t0).toFixed(1)}ms)`,
          detail:
            "Real authentication of seed_alice. The captured SAML assertion in this scenario is treated as if intercepted via TLS misconfiguration or log leakage.",
        });
      }

      const capturedAssertionId = `_captured_assertion_${uuidv4().substring(0, 12)}`;
      const notOnOrAfter = new Date(
        Date.now() + OIDC_SAML_DEMO_CONSTANTS.assertionLifetimeMs,
      ).toISOString();
      const expiredNotOnOrAfter = new Date(
        Date.now() - OIDC_SAML_DEMO_CONSTANTS.expiredAssertionOffsetMs,
      ).toISOString();
      const subject = `${OIDC_SAML_DEMO_CONSTANTS.victimUsername}${OIDC_SAML_DEMO_CONSTANTS.demoEmailSuffix}`;

      const capturedAssertion = {
        "@ID": capturedAssertionId,
        Subject: { NameID: { "#text": subject } },
        Conditions: { "@NotOnOrAfter": notOnOrAfter },
        AttributeStatement: { Attributes: [{ Name: "role", Value: "user" }] },
      };
      const capturedAssertionJson = JSON.stringify(capturedAssertion);
      const capturedSignature = legitimateAuthOk
        ? crypto.createHmac("sha256", OIDC_SECRET).update(capturedAssertionJson).digest("base64")
        : "<not-computed: seed_alice missing>";
      const capturedSignaturePreview =
        capturedSignature.length > 30 ? capturedSignature.substring(0, 30) + "..." : capturedSignature;

      // ── Step 1: probe — 攻撃者がアサーションを傍受 (シミュレーション)
      recordStep({
        id: "replay-1",
        kind: "probe",
        label: "Attacker captures seed_alice's SAML assertion (simulated interception)",
        labelJa: "攻撃者が seed_alice の SAML アサーションを傍受 (シミュレーション)",
        status: legitimateAuthOk ? "success" : "failed",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/oidc/saml/sso (intercepted by attacker)",
            body: {
              username: OIDC_SAML_DEMO_CONSTANTS.victimUsername,
              password: maskSecret(OIDC_SAML_DEMO_CONSTANTS.victimPasswordPlain),
              sp_entity_id: OIDC_SAML_DEMO_CONSTANTS.spEntityId,
            },
          },
          response: {
            status: legitimateAuthOk ? 200 : 401,
            body: legitimateAuthOk
              ? {
                  assertionId: capturedAssertionId,
                  subject,
                  notOnOrAfter,
                  oneTimeUsePresent: false,
                  signature: capturedSignaturePreview,
                }
              : { error: "seed_alice missing — DB seed unavailable" },
          },
        },
        detailJa:
          "攻撃者は seed_alice の認証中に有効な SAML アサーションを傍受します (TLS 設定不備・ログ漏洩等を想定)。アサーションには NotOnOrAfter 制約があるが OneTimeUse 要素はありません。",
        detail:
          "The attacker intercepts a valid SAML assertion during seed_alice's authentication (assumed via TLS misconfiguration or log leakage). The assertion has NotOnOrAfter but no OneTimeUse element.",
      });

      // ── Step 2: tamper — 攻撃者がリプレイ用に同じアサーションを再パッケージ (改変なし)
      recordStep({
        id: "replay-2",
        kind: "tamper",
        label: "Attacker repackages captured assertion for replay (no modification)",
        labelJa: "攻撃者が傍受済みアサーションをリプレイ用に再パッケージ (改変なし)",
        status: "success",
        payload: {
          type: "generic",
          data: {
            assertionId: capturedAssertionId,
            note: "アサーションは改変せず、同じ署名・同じ ID で再送する。リプレイ攻撃の成立は SP 側の OneTimeUse キャッシュ有無に依存する。",
            signaturePreview: capturedSignaturePreview,
            notOnOrAfter,
            currentTime: new Date().toISOString(),
          },
        },
        detailJa:
          "攻撃者はアサーションを改変せず、同じ署名・同じ ID で SP に再送する準備をします。リプレイ成立は SP 側の OneTimeUse キャッシュ有無に依存します。",
        detail:
          "The attacker prepares to resubmit the assertion unchanged (same signature, same ID). Replay success depends on whether the SP maintains a OneTimeUse cache.",
      });

      // ── Step 3: forge — 攻撃者が SP に再送 (両モード並列実行のため両方に同じペイロード)
      recordStep({
        id: "replay-3",
        kind: "forge",
        label: "Attacker submits replay assertion to both SP variants",
        labelJa: "攻撃者が両モードの SP に同じリプレイアサーションを送信",
        status: "success",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/oidc/attack/saml-assertion-replay (simulated SP submission — both variants receive same payload)",
            body: {
              assertionId: capturedAssertionId,
              signature: capturedSignaturePreview,
              notOnOrAfter,
            },
          },
        },
        detailJa:
          "攻撃者は同じアサーションを両モードの SP に送信します。脆弱版 (キャッシュなし) と堅牢版 (OneTimeUse キャッシュあり) で挙動が分岐します。",
        detail:
          "The attacker submits the same assertion to both SP variants. The vulnerable variant (no cache) and the defended variant (OneTimeUse cache) diverge from here.",
      });

      // ── Step 4: exploit (脆弱モード) — リプレイキャッシュ無し → 受理
      // 脆弱パスでは何度送っても受理される (cache なし、署名は有効、有効期間内)
      const vulnerableReplayAccepted = legitimateAuthOk;
      trace.addCryptoOp({
        op: "verifyHmac(replayed_assertion)",
        input: `assertionId=${capturedAssertionId}, signaturePreview=${capturedSignaturePreview}`,
        output: vulnerableReplayAccepted
          ? "VALID (no replay cache — reuse allowed)"
          : "skipped (seed_alice missing)",
        algo: "HMAC-SHA256 (no replay cache check)",
        detail:
          "Vulnerable: signature is valid and NotOnOrAfter is in the future, but the SP does not maintain a OneTimeUse cache, so the same assertion is accepted again.",
      });
      if (vulnerableReplayAccepted) {
        trace.addSessionOp({
          action: "createSession_replay_vulnerable",
          data: {
            isAttackMode: true,
            sessionFor: subject,
            sourceAssertionId: capturedAssertionId,
            note: "Vulnerable: a fresh session is created from the replayed assertion — attacker now has access.",
          },
        });
      }
      recordStep({
        id: "replay-4",
        kind: "exploit",
        label: "Vulnerable: SP without OneTimeUse cache accepts replay — attacker session created",
        labelJa: "脆弱版: OneTimeUse キャッシュなし SP がリプレイを受理 — 攻撃者セッション生成",
        status: vulnerableReplayAccepted ? "success" : "failed",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/oidc/attack/saml-assertion-replay (vulnerable variant — no replay cache)",
          },
          response: {
            status: vulnerableReplayAccepted ? 200 : 401,
            body: vulnerableReplayAccepted
              ? {
                  outcome: "succeeded",
                  subject,
                  newSession: "session_attacker_replay_demo",
                  note: "Vulnerable: assertion has valid signature and is within time window. Without OneTimeUse cache, the SP creates a session for the attacker.",
                }
              : { error: "Vulnerable path could not run — seed_alice missing." },
          },
        },
        detailJa: vulnerableReplayAccepted
          ? "この実装は脆弱です: 使用済みアサーション ID のキャッシュがない実装は、署名と有効期間が正しい限り、同一アサーションの再送で新しいセッションを作成してしまいます。"
          : "脆弱パス実行不可: seed_alice が DB に存在しないため bcrypt.compare をスキップしました。",
        detail: vulnerableReplayAccepted
          ? "This implementation is vulnerable: an SP without a OneTimeUse cache creates a new session whenever the signature is valid and the assertion is within its time window — including on replay."
          : "Vulnerable path could not run — seed_alice missing from seeds.",
      });

      // ── Step 5: verify (堅牢モード) — OneTimeUse キャッシュ + NotOnOrAfter 検証で阻止
      // First use: cache the assertion ID
      if (legitimateAuthOk) {
        attackSimUsedAssertions.set(capturedAssertionId, {
          usedAt: Date.now(),
          assertionId: capturedAssertionId,
        });
        trace.addSessionOp({
          action: "SAML_ASSERTION_FIRST_USE_CACHED",
          data: {
            isAttackMode: true,
            assertionId: capturedAssertionId,
            cachedAt: new Date().toISOString(),
            ttlSec: 600,
            note: "Defended: first use of assertion is accepted and cached. Subsequent replays will be detected.",
          },
        });
      }

      // Second use (replay attempt): cache hit → BLOCKED
      const replayDetected = attackSimUsedAssertions.has(capturedAssertionId);
      const defendedReplayBlocked = replayDetected;

      // 期限切れアサーションの検証も併せて報告 (extra に含める)
      const now = Date.now();
      const expiredNotOnOrAfterMs = new Date(expiredNotOnOrAfter).getTime();
      const notOnOrAfterCheckTested = true;
      const notOnOrAfterCheckBlocked = expiredNotOnOrAfterMs < now; // 設計上常に true

      trace.addCryptoOp({
        op: "strictVerify(OneTimeUse_cache_check)",
        input: `assertionId=${capturedAssertionId}, cacheHit=${replayDetected}`,
        output: defendedReplayBlocked ? "REPLAY DETECTED → reject (cache hit)" : "first use (accept)",
        algo: "OneTimeUse cache + NotOnOrAfter check",
        detail:
          "Defended: SP maintains a TTL-bounded cache of assertion IDs. On first use, the ID is cached. On replay, the cache lookup returns hit → reject.",
      });
      trace.addCryptoOp({
        op: "strictVerify(NotOnOrAfter_check)",
        input: `notOnOrAfter=${expiredNotOnOrAfter}, currentTime=${new Date(now).toISOString()}`,
        output: notOnOrAfterCheckBlocked
          ? "EXPIRED → reject"
          : "within window (accept)",
        algo: "Time-window comparison",
        detail:
          "Defended: SP checks the assertion's NotOnOrAfter against the current time. Expired assertions are rejected even if the signature is valid.",
      });
      recordStep({
        id: "replay-5",
        kind: "verify",
        label: "Defended: OneTimeUse cache detects replay — assertion rejected",
        labelJa: "堅牢版: OneTimeUse キャッシュがリプレイを検出 — アサーション拒否",
        status: defendedReplayBlocked ? "blocked" : "failed",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/oidc/attack/saml-assertion-replay (defended variant — OneTimeUse cache)",
          },
          response: {
            status: 400,
            body: {
              error: `Replay detected: assertion ID '${capturedAssertionId}' already used`,
              blockedBy: "saml_assertion_replay_one_time_use_cache_enforced",
              firstUsedAt: new Date(now).toISOString(),
              alsoEnforced: {
                notOnOrAfterCheck: notOnOrAfterCheckBlocked
                  ? "expired assertions also rejected"
                  : "n/a",
              },
            },
          },
        },
        detailJa:
          "堅牢実装は受理済みアサーション ID を TTL 付きキャッシュに記録します。再送時にキャッシュヒットで再使用を検出し、SP は 400 を返します。NotOnOrAfter 検証も併せて期限切れを拒否します。",
        detail:
          "The defended SP maintains a TTL-bounded cache of accepted assertion IDs. On replay, the cache hit detects reuse and the SP returns 400. The NotOnOrAfter check additionally rejects expired assertions.",
      });

      // 後始末: cache から該当エントリを明示削除 (TTL 経過待ちでメモリ汚染回避)
      attackSimUsedAssertions.delete(capturedAssertionId);

      return {
        blockedBy: "saml_assertion_replay_one_time_use_cache_enforced",
        summary:
          "A vulnerable SP without a OneTimeUse cache accepts replayed assertions whose signature and time window are valid. The defended SP caches accepted assertion IDs and detects replays. NotOnOrAfter validation additionally rejects expired assertions.",
        summaryJa:
          "この実装は脆弱です: OneTimeUse キャッシュがない SP は、署名と有効期間が正しいアサーションの再送を受理してしまいます。堅牢実装は受理済みアサーション ID を TTL 付きキャッシュに記録してリプレイを阻止し、NotOnOrAfter 検証で期限切れも拒否します。",
        extra: {
          capturedAssertionId,
          vulnerableReplayAccepted,
          defendedReplayBlocked,
          notOnOrAfterCheckTested,
          notOnOrAfterCheckBlocked,
          victimUsername: OIDC_SAML_DEMO_CONSTANTS.victimUsername,
          attackerUsername: OIDC_SAML_DEMO_CONSTANTS.attackerUsername,
          victimSeedFound,
        } satisfies SamlAssertionReplayExtra,
        payload: {
          params: {},
          result: {
            capturedAssertionIdPreview: capturedAssertionId.substring(0, 24) + "...",
            vulnerableReplayAccepted,
            defendedReplayBlocked,
            notOnOrAfterCheckBlocked,
            victimSeedFound,
          },
        },
      };
      } finally {
        // ROB-OIDC-1 / SEC-OIDC-2: 例外時も setInterval リーク防止のため必ず destroy()
        attackSimUsedAssertions.destroy();
      }
    },
  })
);

// ── Scenario C: OIDC ID Token Spoofing ──
// 防御の核心: jwt.verify に issuer / audience オプションを渡し、nonce を別途検証する。
// 脆弱な RP は jwt.decode のみで「sub クレームをそのまま信用」してしまう。
type OidcIdTokenSpoofingExtra = {
  legitimateIssuer: string;
  attackerIssuer: string;
  legitimateAud: string;
  attackerAud: string;
  legitimateNonce: string;
  attackerNonce: string;
  spoofedTokenPreview: string;
  vulnerableAcceptedAs: string;
  vulnerableAcceptedRole: string;
  /** ROB-OIDC-7: jwt.decode が null を返した場合は false (脆弱パス実行不可)。 */
  vulnerableDecodeOk: boolean;
  defendedRejectedByIss: boolean;
  defendedRejectedByAud: boolean;
  defendedRejectedByNonce: boolean;
  defendedRejectedBySignature: boolean;
  /** ROB-OIDC-2: jsonwebtoken が投げたエラー種別 (JsonWebTokenError / TokenExpiredError 等)。 */
  defendedErrorName: string | null;
  victimUsername: string;
  attackerUsername: string;
  /** ROB-N1/N2: seed_alice 不在時は false (sub クレームに seed_alice の id を使えない)。 */
  victimSeedFound: boolean;
};

oidcSamlSimRoutes.post("/attack/id-token-spoof", (c) =>
  runAttackScenario<typeof oidcAttackIdTokenSpoofSchema, OidcIdTokenSpoofingExtra>(c, {
    schema: oidcAttackIdTokenSpoofSchema,
    scenarioId: "oidc-id-token-spoofing",
    tabId: "oidc-saml",
    async handler({ db, recordStep, trace }) {
      // seed_alice の sub クレーム (= user.id) を取得
      const aliceUser = db
        .prepare("SELECT id, username FROM users WHERE username = ?")
        .get(OIDC_SAML_DEMO_CONSTANTS.victimUsername) as
        | { id: number; username: string }
        | undefined;
      const victimSeedFound = !!aliceUser;
      // seed_alice 不在時もシナリオは成立 (sub 値は仕様デフォルト "1" を使用)
      const targetSub = aliceUser ? String(aliceUser.id) : "1";

      // ── Step 1: probe — 攻撃者が自身の OIDC IdP (attacker.example) を制御している前提
      recordStep({
        id: "spoof-1",
        kind: "probe",
        label: "Attacker controls their own OIDC IdP (attacker.example)",
        labelJa: "攻撃者が自身の OIDC IdP (attacker.example) を制御",
        status: "success",
        payload: {
          type: "generic",
          data: {
            note: "前提: 攻撃者は自身のドメインに OIDC IdP を立てており、任意クレームを持つ ID Token を発行できます。これは実環境では『攻撃者ドメインを取得し OIDC を実装する』という条件 (現実的な脅威モデル) を表現します。",
            attackerIssuer: OIDC_SAML_DEMO_CONSTANTS.attackerIssuer,
            attackerSigningKeyMasked: maskSecret(OIDC_SAML_DEMO_CONSTANTS.attackerSigningKey),
            legitimateIssuer: OIDC_SAML_DEMO_CONSTANTS.legitimateIssuer,
            legitimateAud: OIDC_SAML_DEMO_CONSTANTS.legitimateAud,
            targetVictimSub: targetSub,
            targetVictimName: OIDC_SAML_DEMO_CONSTANTS.victimUsername,
          },
        },
        detailJa:
          "攻撃者は自身のドメイン (attacker.example) で OIDC IdP を運用しています。任意の sub / name / role を持つ ID Token を発行できます。ターゲット RP は seed_alice の認証を期待しています。",
        detail:
          "The attacker operates an OIDC IdP at their own domain (attacker.example). They can issue ID Tokens with arbitrary sub / name / role claims. The target RP expects to authenticate seed_alice.",
      });

      // ── Step 2: tamper — 攻撃者 IdP が偽 ID Token を発行 (iss=attacker.example, role=admin)
      const spoofedToken = jwt.sign(
        {
          iss: OIDC_SAML_DEMO_CONSTANTS.attackerIssuer,
          sub: targetSub,
          aud: OIDC_SAML_DEMO_CONSTANTS.attackerAud,
          exp: Math.floor(Date.now() / 1000) + 3600,
          iat: Math.floor(Date.now() / 1000),
          nonce: OIDC_SAML_DEMO_CONSTANTS.attackerNonce,
          name: OIDC_SAML_DEMO_CONSTANTS.victimUsername,
          role: "admin",
        },
        OIDC_SAML_DEMO_CONSTANTS.attackerSigningKey,
        { algorithm: "HS256" },
      );
      const spoofedTokenPreview = spoofedToken.substring(0, 40) + "...";

      trace.addCryptoOp({
        op: "jwt.sign(attacker_idp)",
        input: `iss=${OIDC_SAML_DEMO_CONSTANTS.attackerIssuer}, sub=${targetSub}, aud=${OIDC_SAML_DEMO_CONSTANTS.attackerAud}, name=${OIDC_SAML_DEMO_CONSTANTS.victimUsername}, role=admin`,
        output: spoofedTokenPreview,
        algo: "HS256 (signed with attacker's own signing key)",
        detail:
          "The attacker's own IdP issues an ID Token claiming to be seed_alice with admin role. Note: iss / aud / nonce all differ from the legitimate IdP's expected values.",
      });
      recordStep({
        id: "spoof-2",
        kind: "tamper",
        label: "Attacker IdP issues spoofed ID Token impersonating seed_alice with admin role",
        labelJa: "攻撃者 IdP が seed_alice を偽装し admin ロールを主張する ID Token を発行",
        status: "success",
        payload: {
          type: "token",
          before: "<no token>",
          after: spoofedTokenPreview,
          algo: "HS256",
          decodedHeader: { alg: "HS256", typ: "JWT" },
          decodedPayload: {
            iss: OIDC_SAML_DEMO_CONSTANTS.attackerIssuer,
            sub: targetSub,
            aud: OIDC_SAML_DEMO_CONSTANTS.attackerAud,
            nonce: OIDC_SAML_DEMO_CONSTANTS.attackerNonce,
            name: OIDC_SAML_DEMO_CONSTANTS.victimUsername,
            role: "admin",
          },
          signatureValid: true,
        },
        detailJa:
          "攻撃者 IdP が seed_alice の身元を偽る ID Token を発行します。iss は attacker.example、aud と nonce も攻撃者制御の値です。署名は攻撃者の鍵で生成されているため、正規 IdP の鍵では検証できません。",
        detail:
          "The attacker IdP issues an ID Token impersonating seed_alice. The iss is attacker.example, and aud/nonce are attacker-controlled. The signature uses the attacker's key, so it will not verify under the legitimate IdP's key.",
      });

      // ── Step 3: forge — 攻撃者がターゲット RP に偽 ID Token を提示
      recordStep({
        id: "spoof-3",
        kind: "forge",
        label: "Attacker submits spoofed ID Token to target RP",
        labelJa: "攻撃者が偽 ID Token をターゲット RP に送信",
        status: "success",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/oidc/attack/id-token-spoof (simulated RP submission — both variants receive same token)",
            headers: { Authorization: `Bearer ${spoofedTokenPreview}` },
          },
          tamperedFields: ["Authorization (Bearer token)"],
        },
        detailJa:
          "攻撃者は偽 ID Token を Bearer トークンとしてターゲット RP に送信します。脆弱版 (jwt.decode のみ) と堅牢版 (jwt.verify with iss/aud) で挙動が分岐します。",
        detail:
          "The attacker presents the spoofed ID Token as a Bearer token to the target RP. The vulnerable variant (jwt.decode only) and the defended variant (jwt.verify with iss/aud) diverge from here.",
      });

      // ── Step 4: exploit (脆弱モード) — RP が jwt.decode のみで検証なし → 受理
      // ROB-OIDC-7: jwt.decode が null を返した場合は攻撃成立を主張しない (step status="failed")。
      const vulnerableDecoded = jwt.decode(spoofedToken) as
        | {
            iss?: string;
            sub?: string;
            aud?: string;
            nonce?: string;
            name?: string;
            role?: string;
          }
        | null;
      const vulnerableDecodeOk = vulnerableDecoded !== null;
      // 攻撃成立条件: decode が成功し、name/role クレームが署名対象通り読み取れること。
      // null の場合 (壊れたトークン等) は教育的誤誘導を避けるため fallback を使わず "<decode-failed>" を表示。
      const vulnerableAcceptedAs = vulnerableDecodeOk
        ? (vulnerableDecoded?.name ?? "<no-name-claim>")
        : "<decode-failed>";
      const vulnerableAcceptedRole = vulnerableDecodeOk
        ? (vulnerableDecoded?.role ?? "<no-role-claim>")
        : "<decode-failed>";

      trace.addCryptoOp({
        op: "jwt.decode(spoofed_token, no_verify)",
        input: spoofedTokenPreview,
        output: vulnerableDecodeOk
          ? `sub=${vulnerableDecoded?.sub}, name=${vulnerableAcceptedAs}, role=${vulnerableAcceptedRole}, iss=${vulnerableDecoded?.iss} (NOT verified), aud=${vulnerableDecoded?.aud} (NOT verified), nonce=${vulnerableDecoded?.nonce} (NOT verified)`
          : "DECODE_FAILED — token could not be parsed",
        algo: "decode-only (no signature/iss/aud/nonce check)",
        detail:
          "Vulnerable: jwt.decode does not verify the signature, iss, aud, or nonce. The attacker's spoofed token is accepted at face value — sub claim is trusted blindly.",
      });
      if (vulnerableDecodeOk) {
        trace.addSessionOp({
          action: "createSession_spoofed_id_token_vulnerable",
          data: {
            isAttackMode: true,
            authenticatedAs: vulnerableAcceptedAs,
            role: vulnerableAcceptedRole,
            tokenSourceIss: vulnerableDecoded?.iss,
            note: "Vulnerable: a session is created from the spoofed token — attacker now has admin access posing as seed_alice.",
          },
        });
      }
      recordStep({
        id: "spoof-4",
        kind: "exploit",
        label: "Vulnerable: RP uses jwt.decode only — accepts spoofed token, attacker authenticates as seed_alice/admin",
        labelJa: "脆弱版: RP が jwt.decode のみで検証 — 偽トークンを受理、攻撃者が seed_alice/admin として認証",
        // ROB-OIDC-7: decode 失敗時は失敗ステータスを返す (教育的誤誘導回避)
        status: vulnerableDecodeOk ? "success" : "failed",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/oidc/attack/id-token-spoof (vulnerable variant — no claims check)",
          },
          response: {
            status: vulnerableDecodeOk ? 200 : 400,
            body: vulnerableDecodeOk
              ? {
                  outcome: "succeeded",
                  authenticatedAs: vulnerableAcceptedAs,
                  role: vulnerableAcceptedRole,
                  tokenIss: vulnerableDecoded?.iss,
                  tokenAud: vulnerableDecoded?.aud,
                  note: "Vulnerable: jwt.decode does not verify signature/iss/aud/nonce. The attacker's ID Token from attacker.example is accepted, granting admin access.",
                }
              : {
                  error: "Vulnerable path could not run — jwt.decode returned null (malformed token).",
                },
          },
        },
        detailJa: vulnerableDecodeOk
          ? "この実装は脆弱です: jwt.decode は署名・iss・aud・nonce のいずれも検証しないため、攻撃者 IdP が発行した ID Token を受理してしまいます。RP は sub クレーム (seed_alice) と role クレーム (admin) をそのまま信用し、攻撃者が seed_alice/admin として認証されます。"
          : "脆弱パス実行不可: jwt.decode が null を返しました (トークン破損)。",
        detail: vulnerableDecodeOk
          ? "This implementation is vulnerable: jwt.decode does not verify signature, iss, aud, or nonce. The attacker's ID Token from attacker.example is accepted at face value, and the RP authenticates the attacker as seed_alice with admin role."
          : "Vulnerable path could not run — jwt.decode returned null (malformed token).",
      });

      // ── Step 5: verify (堅牢モード) — jwt.verify with iss/aud + nonce check で拒否
      let defendedRejectedByIss = false;
      let defendedRejectedByAud = false;
      let defendedRejectedBySignature = false;
      let defendedRejectedByNonce = false;
      let defendedError: string | null = null;
      let defendedErrorName: string | null = null;

      try {
        // 厳密検証: 正規 OIDC_SECRET で署名検証 + iss/aud オプション
        // 攻撃者は OIDC_SECRET を知らないため、署名検証は必ず失敗する
        jwt.verify(spoofedToken, OIDC_SECRET, {
          algorithms: ["HS256"],
          issuer: OIDC_SAML_DEMO_CONSTANTS.legitimateIssuer,
          audience: OIDC_SAML_DEMO_CONSTANTS.legitimateAud,
        });
      } catch (e) {
        defendedError = e instanceof Error ? e.message : "Unknown error";
        defendedErrorName = e instanceof Error ? e.name : null;
        // ROB-OIDC-2: jsonwebtoken のエラータイプを判別して、フラグを正確に立てる。
        // - JsonWebTokenError "invalid signature" → 署名失敗
        // - JsonWebTokenError "jwt issuer invalid" → iss 不一致 (issuer option ヒット)
        // - JsonWebTokenError "jwt audience invalid" → aud 不一致 (audience option ヒット)
        // - TokenExpiredError → 有効期限切れ (本シナリオでは exp=Date.now()+3600 のため発生しない)
        // - その他 → 一般エラーとして defendedError のみ記録
        const msg = (defendedError ?? "").toLowerCase();
        if (msg.includes("invalid signature") || msg.includes("invalid token")) {
          defendedRejectedBySignature = true;
        } else if (msg.includes("issuer invalid")) {
          defendedRejectedByIss = true;
        } else if (msg.includes("audience invalid")) {
          defendedRejectedByAud = true;
        } else {
          // 不明エラー時は signature failure として保守的に扱う (jsonwebtoken の文言変化に備えるフォールバック)
          defendedRejectedBySignature = true;
        }
      }

      // 仮に署名が通っていても iss/aud/nonce 検証で拒否されることを示すため、
      // 実 jwt.verify が立てたフラグに加えて、デコード結果との比較も「同等の検証が立つ」ことを記録する。
      // SPEC-OIDC-1: legitimateNonce を期待値として参照し、攻撃者発行 nonce との不一致を可視化。
      const decoded = jwt.decode(spoofedToken) as
        | { iss?: string; aud?: string; nonce?: string }
        | null;
      const issMismatch = decoded?.iss !== OIDC_SAML_DEMO_CONSTANTS.legitimateIssuer;
      const audMismatch = decoded?.aud !== OIDC_SAML_DEMO_CONSTANTS.legitimateAud;
      const nonceMismatch = decoded?.nonce !== OIDC_SAML_DEMO_CONSTANTS.legitimateNonce;
      // 署名失敗フラグが立っていても、追加の検証 (iss/aud/nonce) も「もし署名が通っていても拒否される」
      // ことを示すため反映する。
      defendedRejectedByIss = defendedRejectedByIss || issMismatch;
      defendedRejectedByAud = defendedRejectedByAud || audMismatch;
      defendedRejectedByNonce = nonceMismatch;

      trace.addCryptoOp({
        op: "jwt.verify(spoofed_token, strict)",
        input: `token=${spoofedTokenPreview}, expectedIss=${OIDC_SAML_DEMO_CONSTANTS.legitimateIssuer}, expectedAud=${OIDC_SAML_DEMO_CONSTANTS.legitimateAud}, expectedNonce=${OIDC_SAML_DEMO_CONSTANTS.legitimateNonce}`,
        output: `REJECTED — ${sanitizeForDisplay(defendedError ?? "verification error", 128)} (errorName=${defendedErrorName ?? "n/a"}; signatureCheck=${defendedRejectedBySignature ? "REJECT" : "n/a"}; iss: ${decoded?.iss} vs ${OIDC_SAML_DEMO_CONSTANTS.legitimateIssuer} → ${issMismatch ? "REJECT" : "ACCEPT"}; aud: ${decoded?.aud} vs ${OIDC_SAML_DEMO_CONSTANTS.legitimateAud} → ${audMismatch ? "REJECT" : "ACCEPT"}; nonce: ${decoded?.nonce} vs ${OIDC_SAML_DEMO_CONSTANTS.legitimateNonce} → ${nonceMismatch ? "REJECT" : "ACCEPT"})`,
        algo: "HS256 + iss/aud/nonce strict check (OIDC Core 1.0 §3.1.3.7)",
        detail:
          "Defended: jwt.verify performs (1) signature check with the registered IdP's key, (2) iss strict-equality check, (3) aud check. The nonce check is performed separately against the value generated during the authorization request. The spoofed token fails the signature check first; even if it had passed, iss/aud/nonce checks would block it.",
      });
      recordStep({
        id: "spoof-5",
        kind: "verify",
        label: "Defended: jwt.verify with iss/aud rejects spoofed token (signature + claim mismatch)",
        labelJa: "堅牢版: jwt.verify with iss/aud が偽トークンを拒否 (署名 + クレーム不一致)",
        status: defendedRejectedBySignature || defendedRejectedByIss || defendedRejectedByAud || defendedRejectedByNonce ? "blocked" : "failed",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/oidc/attack/id-token-spoof (defended variant — strict claim check)",
          },
          response: {
            status: 401,
            body: {
              error: `ID Token validation failed: signature verification rejected (token signed with attacker's key, not legitimate IdP's key); iss check would also reject (received="${decoded?.iss}", expected="${OIDC_SAML_DEMO_CONSTANTS.legitimateIssuer}"); aud check would also reject (received="${decoded?.aud}", expected="${OIDC_SAML_DEMO_CONSTANTS.legitimateAud}"); nonce check would also reject (received="${decoded?.nonce}", expected="${OIDC_SAML_DEMO_CONSTANTS.legitimateNonce}")`,
              blockedBy: "oidc_id_token_iss_aud_nonce_validation_enforced",
              checks: {
                signature: defendedRejectedBySignature ? "REJECT" : "ACCEPT",
                iss: defendedRejectedByIss ? "REJECT" : "ACCEPT",
                aud: defendedRejectedByAud ? "REJECT" : "ACCEPT",
                nonce: defendedRejectedByNonce ? "REJECT" : "ACCEPT",
              },
              jwtErrorName: defendedErrorName,
            },
          },
        },
        detailJa:
          "堅牢実装は jwt.verify に issuer / audience オプションを渡し、署名検証 + iss/aud 検証を必須化します。nonce 検証は authorize 時に生成した値と別途比較します。攻撃者の鍵で署名された偽 ID Token は (1) 署名検証で拒否され、仮に通過したとしても (2) iss が attacker.example で正規 IdP と一致せず、(3) aud が victim-rp-client で自身の client_id と一致せず、(4) nonce も attacker_nonce_xyz で期待値 legit_nonce_abc123 と一致しないため拒否されます。OIDC Core 1.0 §3.1.3.7 準拠。",
        detail:
          "The defended implementation passes issuer / audience to jwt.verify, requiring signature verification AND iss/aud check. The nonce is checked separately against the value generated during authorization. The spoofed token (signed with the attacker's key) is rejected by (1) signature check; even if that passed, (2) iss would not match (attacker.example ≠ legitimate IdP), (3) aud would not match (victim-rp-client ≠ self client_id), and (4) nonce would not match (attacker_nonce_xyz ≠ expected legit_nonce_abc123). Compliant with OIDC Core 1.0 §3.1.3.7.",
      });

      return {
        blockedBy: "oidc_id_token_iss_aud_nonce_validation_enforced",
        summary:
          "A vulnerable RP using jwt.decode without iss/aud/nonce validation accepts an ID Token forged by an attacker-controlled IdP. The defended RP enforces jwt.verify with issuer/audience plus separate nonce check, blocking the attack via OIDC Core 1.0 §3.1.3.7-compliant validation.",
        summaryJa:
          "この実装は脆弱です: iss/aud/nonce 検証を省略した jwt.decode のみの RP は、攻撃者制御 IdP が発行した偽 ID Token を受理してしまいます。堅牢実装は jwt.verify に issuer/audience を渡し、nonce も別途検証することで OIDC Core 1.0 §3.1.3.7 準拠の検証を行い、この攻撃を阻止します。",
        extra: {
          legitimateIssuer: OIDC_SAML_DEMO_CONSTANTS.legitimateIssuer,
          attackerIssuer: OIDC_SAML_DEMO_CONSTANTS.attackerIssuer,
          legitimateAud: OIDC_SAML_DEMO_CONSTANTS.legitimateAud,
          attackerAud: OIDC_SAML_DEMO_CONSTANTS.attackerAud,
          legitimateNonce: OIDC_SAML_DEMO_CONSTANTS.legitimateNonce,
          attackerNonce: OIDC_SAML_DEMO_CONSTANTS.attackerNonce,
          spoofedTokenPreview,
          vulnerableAcceptedAs,
          vulnerableAcceptedRole,
          vulnerableDecodeOk,
          defendedRejectedByIss,
          defendedRejectedByAud,
          defendedRejectedByNonce,
          defendedRejectedBySignature,
          defendedErrorName,
          victimUsername: OIDC_SAML_DEMO_CONSTANTS.victimUsername,
          attackerUsername: OIDC_SAML_DEMO_CONSTANTS.attackerUsername,
          victimSeedFound,
        } satisfies OidcIdTokenSpoofingExtra,
        payload: {
          params: {},
          result: {
            spoofedTokenPreview,
            vulnerableAcceptedAs,
            vulnerableAcceptedRole,
            vulnerableDecodeOk,
            defendedRejectedByIss,
            defendedRejectedByAud,
            defendedRejectedByNonce,
            defendedRejectedBySignature,
            defendedErrorName,
            victimSeedFound,
          },
        },
      };
    },
  })
);
