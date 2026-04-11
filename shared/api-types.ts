/* ── Shared types: server ↔ client ── */

export interface DbQuery {
  sql: string;
  params: unknown[];
  rows?: unknown[];
  ms: number;
}

export interface CryptoOp {
  op: string;
  input: string;
  output: string;
  algo: string;
  detail?: string;
}

export interface SessionOp {
  action: string;
  data: unknown;
}

export interface ServerTrace {
  dbQueries?: DbQuery[];
  cryptoOps?: CryptoOp[];
  sessionOps?: SessionOp[];
}

export interface ApiResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
  _trace?: ServerTrace;
}

/* ── Password Auth ── */
export interface RegisterRequest {
  username: string;
  password: string;
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface UserRow {
  id: number;
  username: string;
  password_hash: string;
  created_at: string;
}

/* ── JWT ── */
export interface JwtSignRequest {
  claims: Record<string, unknown>;
  algorithm?: "HS256" | "RS256";
  expiresIn?: number; // seconds
}

export interface JwtVerifyRequest {
  token: string;
}

/* ── OAuth ── */
export interface OAuthAuthorizeRequest {
  client_id: string;
  redirect_uri: string;
  scope: string;
  state: string;
  response_type: "code";
}

export interface OAuthTokenRequest {
  grant_type: "authorization_code" | "refresh_token";
  code?: string;
  refresh_token?: string;
  client_id: string;
  client_secret?: string;
}

/* ── Session / Token Auth ── */
export interface SessionInfo {
  sessionId: string;
  userId: number;
  username: string;
  createdAt: string;
  expiresAt: string;
}

export interface TokenInfo {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

/* ── RBAC/ABAC/ACL ── */
export interface AccessCheckRequest {
  subject: string;
  resource: string;
  action: string;
  context?: Record<string, unknown>;
}

export interface AccessCheckResult {
  allowed: boolean;
  reason: string;
  evaluationSteps: { rule: string; result: string; detail: string }[];
}

/* ── WebAuthn ── */
export interface WebAuthnUser {
  id: string;
  username: string;
  credentials: { credentialId: string; publicKey: string; counter: number }[];
}

/* ── Kerberos ── */
export interface KerberosTicket {
  type: "TGT" | "ServiceTicket";
  principal: string;
  realm: string;
  encryptedData: string;
  decryptedFields?: Record<string, string>;
  validUntil: string;
  sessionKey: string;
}

/* ── OIDC ── */
export interface OidcTokenResponse {
  access_token: string;
  id_token: string;
  token_type: "Bearer";
  expires_in: number;
  scope: string;
}

/* ── API Key ── */
export interface ApiKeyInfo {
  keyId: string;
  prefix: string;
  hash: string;
  createdAt: string;
  lastUsed?: string;
}

/* ── Database Row Types ── */
export interface OAuthClientRow {
  client_id: string;
  client_secret: string;
  name: string;
  redirect_uris: string; // JSON string
}

export interface OAuthCodeRow {
  code: string;
  client_id: string;
  user_id: number;
  scope: string;
  redirect_uri: string;
  expires_at: string;
  used: number;
}

export interface OAuthTokenRow {
  access_token: string;
  refresh_token: string;
  client_id: string;
  user_id: number;
  scope: string;
  expires_at: string;
}

export interface SessionRow {
  id: string;
  user_id: number;
  username?: string; // from JOIN
  data: string;
  created_at: string;
  expires_at: string;
}

export interface RoleRow {
  id: number;
  name: string;
  permissions?: string; // from GROUP_CONCAT
}

export interface PermissionRow {
  id: number;
  name: string;
  resource: string;
  action: string;
}

export interface WebAuthnCredentialRow {
  credential_id: string;
  user_id: number;
  public_key: string;
  counter: number;
  transports: string | null; // JSON string
  created_at: string;
  username?: string; // from JOIN
}

export interface ApiKeyRow {
  key_id: string;
  key_prefix: string;
  key_hash: string;
  name: string;
  created_at: string;
  last_used: string | null;
}

export interface KerberosTicketRow {
  id: number;
  ticket_type: string;
  principal: string;
  realm: string;
  encrypted_data: string;
  session_key: string;
  valid_until: string;
  created_at: string;
}

/* ── MFA / TOTP ── */
export interface UserMfaRow {
  user_id: number;
  secret: string;
  verified: number;
  created_at: string;
  verified_at: string | null;
}

export interface TotpEnrollResponse {
  secret: string;
  otpauthUri: string;
  qrCodeSvg: string;
  issuer: string;
  label: string;
}

export interface TotpEnrollVerifyResponse {
  verified: boolean;
  verifiedAt: string;
}

export interface TotpLoginStep1Response {
  requiresMfa: boolean;
  challengeId: string | null;
  message: string;
}

export interface TotpLoginStep2Response {
  success: boolean;
  username: string;
  message: string;
}

/* ── Passkey (usernameless WebAuthn) ── */
export interface PasskeyAuthOptionsResponse {
  options: unknown; // PublicKeyCredentialRequestOptionsJSON
  sessionId: string;
  explanation: {
    allowCredentials: string;
    userVerification: string;
  };
}

export interface PasskeyAuthVerifyResponse {
  verified: boolean;
  username: string;
  credentialId: string;
  counter: { old: number; new: number };
}

export interface PasskeyRegisterVerifyResponse {
  verified: boolean;
  credentialId: string;
  credentialDeviceType: string;
  credentialBackedUp: boolean;
  publicKeyPreview: string;
}
