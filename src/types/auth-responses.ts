/**
 * Auth Demo API Response Types
 *
 * These interfaces describe the `data` field returned by each auth route.
 * The API client already unwraps the `{ success: true, data: {...} }` envelope,
 * so these represent what the client receives in `res.data`.
 */

import type {
  OidcTokenResponse,
  KerberosTicketRow,
  TotpEnrollResponse,
  TotpEnrollVerifyResponse,
  TotpLoginStep1Response,
  TotpLoginStep2Response,
  PasskeyAuthOptionsResponse,
  PasskeyAuthVerifyResponse,
  PasskeyRegisterVerifyResponse,
} from "../../shared/api-types";

// ════════════════════════════════════════════════════════════════════
// Session Auth  (server/routes/session-auth.ts)
// ════════════════════════════════════════════════════════════════════

/** POST /api/session/login */
export interface SessionLoginData {
  user: { id: number; username: string };
  session: { sessionId: string; expiresAt: string };
}

/** GET /api/session/profile */
export interface SessionProfileData {
  user: { id: number; username: string };
  session: { id: string; expiresAt: string };
}

/** DELETE /api/session/logout */
export interface SessionLogoutData {
  message: string;
}

/** GET /api/session/store */
export interface SessionStoreData {
  sessions: Array<{
    id: string;
    user_id: number;
    username: string;
    created_at: string;
    expires_at: string;
  }>;
}

// ════════════════════════════════════════════════════════════════════
// Token Auth  (server/routes/token-auth.ts)
// ════════════════════════════════════════════════════════════════════

/** POST /api/token/login */
export interface TokenLoginData {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  tokenType: string;
  user: { id: number; username: string };
}

/** GET /api/token/profile */
export interface TokenProfileData {
  user: { id: number; username: string };
  decoded: { sub: number; username: string; type: string };
}

/** POST /api/token/refresh */
export interface TokenRefreshData {
  accessToken: string;
  expiresIn: number;
  tokenType: string;
}

// ════════════════════════════════════════════════════════════════════
// OAuth 2.0  (server/routes/oauth-sim.ts)
// ════════════════════════════════════════════════════════════════════

/** GET /api/oauth/authorize — authorization page info */
export interface OAuthAuthorizePageData {
  step: "authorization_page";
  client: { id: string; name: string };
  requestedScope: string;
  redirectUri: string;
  state: string;
  message: string;
}

/** POST /api/oauth/authorize — authorization code issued */
export interface OAuthCodeData {
  step: "authorization_code_issued";
  code: string;
  redirectUri: string;
  expiresAt: string;
}

/** POST /api/oauth/token — token exchange (authorization_code or refresh_token) */
export interface OAuthTokenData {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token: string;
  scope: string;
}

/** GET /api/oauth/resource — protected resource */
export interface OAuthResourceData {
  resource: {
    message: string;
    user: string;
    scope: string;
    data: Array<{ id: number; title: string; content: string }>;
  };
}

// ════════════════════════════════════════════════════════════════════
// Kerberos  (server/routes/kerberos-sim.ts)
// ════════════════════════════════════════════════════════════════════

/** Encrypted blob with IV, used in Kerberos ticket structures */
export interface KerberosEncryptedBlob {
  encrypted: string;
  iv: string;
}

/** Decrypted TGT payload */
export interface KerberosTgtPayload {
  principal: string;
  sessionKey: string;
  validUntil: string;
  flags: string[];
}

/** Decrypted service ticket payload */
export interface KerberosServiceTicketPayload {
  principal: string;
  servicePrincipal: string;
  sessionKey: string;
  validUntil: string;
}

/** POST /api/kerberos/as-req */
export interface KerberosAsData {
  step: "AS-REP";
  tgt: KerberosEncryptedBlob;
  encryptedSessionKey: KerberosEncryptedBlob;
  decryptedTgt: KerberosTgtPayload;
  realm: string;
  message: string;
}

/** POST /api/kerberos/tgs-req */
export interface KerberosTgsData {
  step: "TGS-REP";
  serviceTicket: KerberosEncryptedBlob;
  decryptedServiceTicket: KerberosServiceTicketPayload;
  message: string;
}

/** POST /api/kerberos/ap-req */
export interface KerberosApData {
  step: "AP-REP";
  authenticated: boolean;
  principal: string;
  service: string;
  decryptedTicket: KerberosServiceTicketPayload;
  message: string;
}

/** GET /api/kerberos/ticket-cache */
export interface KerberosTicketCacheData {
  tickets: KerberosTicketRow[];
}

/** POST /api/kerberos/reset */
export interface KerberosResetData {
  message: string;
}

// ════════════════════════════════════════════════════════════════════
// TLS 1.3  (server/routes/tls-sim.ts)
// ════════════════════════════════════════════════════════════════════

/** POST /api/tls/client-hello */
export interface TlsClientHelloData {
  step: "ClientHello";
  clientRandom: string;
  clientPublicKey: string;
  supportedCipherSuites: string[];
  supportedGroups: string[];
  signatureAlgorithms: string[];
  tlsVersion: string;
}

/** POST /api/tls/server-hello */
export interface TlsServerHelloData {
  step: "ServerHello";
  serverRandom: string;
  serverPublicKey: string;
  selectedCipherSuite: string;
  selectedGroup: string;
  tlsVersion: string;
}

/** POST /api/tls/key-exchange */
export interface TlsKeyExchangeData {
  step: "KeyExchange";
  sharedSecret: string;
  handshakeSecret: string;
  masterSecret: string;
  explanation: {
    ecdhe: string;
    forwardSecrecy: string;
  };
}

/** GET /api/tls/certificate */
export interface TlsCertificateData {
  certificate: {
    subject: string;
    issuer: string;
    serialNumber: string;
    validFrom: string;
    validTo: string;
    signatureAlgorithm: string;
    publicKey: string;
    fingerprint: string;
  };
  publicKeyPem: string;
  explanation: {
    chain: string[];
    verification: string;
  };
}

/** POST /api/tls/finish */
export interface TlsFinishData {
  step: "Finished";
  clientWriteKey: string;
  serverWriteKey: string;
  message: string;
  cipherSuite: string;
}

// ════════════════════════════════════════════════════════════════════
// OIDC & SAML  (server/routes/oidc-saml-sim.ts)
// ════════════════════════════════════════════════════════════════════

/** POST /api/oidc/authorize */
export interface OidcAuthorizeData {
  code: string;
  state: string;
  redirect: string;
  pkce: { method: string; challenge: string } | null;
}

/**
 * POST /api/oidc/token
 *
 * Extends the shared OidcTokenResponse with the decoded ID token payload.
 */
export interface OidcTokenData extends OidcTokenResponse {
  id_token_decoded: OidcIdTokenClaims | null;
}

/** Decoded claims inside an OIDC ID Token */
export interface OidcIdTokenClaims {
  iss: string;
  sub: string;
  aud: string;
  exp: number;
  iat: number;
  nonce: string;
  name: string;
  email: string;
}

/**
 * GET /api/oidc/userinfo
 *
 * Note: This endpoint returns the data directly (not wrapped in success/data).
 */
export interface OidcUserInfoData {
  sub: string;
  name: string;
  email: string;
  email_verified: boolean;
}

/** SAML Assertion attribute */
export interface SamlAttribute {
  Name: string;
  Value: string;
}

/** SAML Assertion structure (JSON representation) */
export interface SamlAssertion {
  "@ID": string;
  "@IssueInstant": string;
  Issuer: string;
  Subject: {
    NameID: { "@Format": string; "#text": string };
    SubjectConfirmation: {
      "@Method": string;
      SubjectConfirmationData: { "@NotOnOrAfter": string; "@Recipient": string };
    };
  };
  Conditions: {
    "@NotBefore": string;
    "@NotOnOrAfter": string;
    AudienceRestriction: { Audience: string };
  };
  AuthnStatement: {
    "@AuthnInstant": string;
    AuthnContext: { AuthnContextClassRef: string };
  };
  AttributeStatement: {
    Attributes: SamlAttribute[];
  };
}

/** POST /api/oidc/saml/sso */
export interface SamlSsoData {
  assertion: SamlAssertion;
  signature: string;
  samlResponse: string;
  assertionId: string;
  explanation: {
    flow: string;
    steps: string[];
  };
}

// ════════════════════════════════════════════════════════════════════
// SSO & API Key  (server/routes/sso-apikey.ts)
// ════════════════════════════════════════════════════════════════════

/** POST /api/sso/login */
export interface SsoLoginData {
  ssoToken: string;
  username: string;
  message: string;
}

/** POST /api/sso/access (access-service) */
export interface SsoAccessData {
  authenticated: boolean;
  username: string;
  service: string;
  accessedServices: string[];
  message: string;
}

/** POST /api/sso/apikey/generate */
export interface ApiKeyGenerateData {
  keyId: string;
  rawKey: string;
  prefix: string;
  warning: string;
}

/** POST /api/sso/apikey/verify/hmac */
export interface ApiKeyHmacVerifyData {
  valid: boolean;
  keyId: string;
  canonical: string;
  expectedSignature: string;
}

/** POST /api/sso/apikey/verify/header, GET /api/sso/apikey/verify/query */
export interface ApiKeyVerifyData {
  valid: boolean;
  keyId: string;
  name: string;
  method: string;
  message: string;
}

// ════════════════════════════════════════════════════════════════════
// WebAuthn / FIDO2  (server/routes/webauthn.ts)
// ════════════════════════════════════════════════════════════════════

/** POST /api/webauthn/register/options */
export interface WebAuthnRegisterOptionsData {
  sessionId: string;
  options: unknown; // PublicKeyCredentialCreationOptionsJSON from @simplewebauthn/server
  explanation: {
    challenge: string;
    rp: { id: string; name: string };
    excludeCredentials: string;
  };
}

/** POST /api/webauthn/register/verify */
export interface WebAuthnRegisterVerifyData {
  verified: boolean;
  credentialId: string;
  publicKeyPreview: string;
  counter: number;
}

/** POST /api/webauthn/auth/options */
export interface WebAuthnAuthOptionsData {
  sessionId: string;
  options: unknown; // PublicKeyCredentialRequestOptionsJSON from @simplewebauthn/server
  explanation: {
    challenge: string;
    allowCredentials: string;
  };
}

/** POST /api/webauthn/auth/verify */
export interface WebAuthnAuthVerifyData {
  verified: boolean;
  username: string;
  counter: { old: number; new: number };
}

// ════════════════════════════════════════════════════════════════════
// MFA / TOTP  (server/routes/mfa-totp.ts)
// ════════════════════════════════════════════════════════════════════

// Re-export shared types that match the actual response shapes exactly
export type { TotpEnrollResponse, TotpEnrollVerifyResponse, TotpLoginStep1Response, TotpLoginStep2Response };

/** Alias for POST /api/mfa/totp/enroll/start — same as TotpEnrollResponse */
export type MfaEnrollStartData = TotpEnrollResponse;

/** Alias for POST /api/mfa/totp/enroll/verify — same as TotpEnrollVerifyResponse */
export type MfaEnrollVerifyData = TotpEnrollVerifyResponse;

/** Alias for POST /api/mfa/totp/login/step1 — same as TotpLoginStep1Response */
export type MfaLoginStep1Data = TotpLoginStep1Response;

/** Alias for POST /api/mfa/totp/login/step2 — same as TotpLoginStep2Response */
export type MfaLoginStep2Data = TotpLoginStep2Response;

// ════════════════════════════════════════════════════════════════════
// Passkey  (server/routes/passkey.ts)
// ════════════════════════════════════════════════════════════════════

// Re-export shared types that match the actual response shapes exactly
export type { PasskeyAuthOptionsResponse, PasskeyAuthVerifyResponse, PasskeyRegisterVerifyResponse };

/** POST /api/passkey/register/options */
export interface PasskeyRegisterOptionsData {
  options: unknown; // PublicKeyCredentialCreationOptionsJSON from @simplewebauthn/server
  explanation: {
    challenge: string;
    rp: { id: string; name: string };
    residentKey: string;
    excludeCredentials: string;
  };
}

/** Alias for POST /api/passkey/register/verify — same as PasskeyRegisterVerifyResponse */
export type PasskeyRegisterVerifyData = PasskeyRegisterVerifyResponse;

/** Alias for POST /api/passkey/auth/options — same as PasskeyAuthOptionsResponse */
export type PasskeyAuthOptionsData = PasskeyAuthOptionsResponse;

/** Alias for POST /api/passkey/auth/verify — same as PasskeyAuthVerifyResponse */
export type PasskeyAuthVerifyData = PasskeyAuthVerifyResponse;
