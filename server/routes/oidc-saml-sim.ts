import { Hono } from "hono";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { v4 as uuidv4 } from "uuid";
import { getDb } from "../db/schema.js";
import bcrypt from "bcryptjs";
import { parseBody, oidcAuthorizeSchema, oidcTokenSchema, samlSsoSchema } from "../validation.js";
import type { UserRow, OAuthClientRow } from "../../shared/api-types.js";
import { createTtlStore } from "../utils/ttl-store.js";

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
