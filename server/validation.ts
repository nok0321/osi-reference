/**
 * Zod schemas for all API route inputs.
 * Centralised validation prevents injection and ensures type safety.
 */
import { z } from "zod";
import type { Context } from "hono";

// ── Helpers ──

/** Parse request JSON with a zod schema. Returns 400 on failure. */
export async function parseBody<T extends z.ZodTypeAny>(
  c: Context,
  schema: T,
): Promise<{ data: z.infer<T> } | { error: Response }> {
  const raw = await c.req.json().catch(() => null);
  const result = schema.safeParse(raw);
  if (!result.success) {
    // In production, avoid leaking internal zod paths/messages. In dev, show details for debuggability.
    const isProd = process.env.NODE_ENV === "production";
    const message = isProd
      ? "Invalid input"
      : `Validation error: ${result.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ")}`;
    return { error: c.json({ success: false, error: message }, 400) };
  }
  return { data: result.data };
}

// ── Reusable fields ──
const username = z.string().min(1).max(64);
const password = z.string().min(1).max(256);

// ── Password Auth ──
export const registerSchema = z.object({ username, password });
export const loginSchema = z.object({ username, password });

// ── JWT Ops ──
export const jwtSignSchema = z.object({
  claims: z.record(z.string(), z.unknown()),
  algorithm: z.enum(["HS256", "RS256"]).default("HS256"),
  expiresIn: z.number().int().min(1).max(86400).default(3600),
});

export const jwtVerifySchema = z.object({
  token: z.string().min(1),
  algorithm: z.enum(["HS256", "RS256"]).default("HS256"),
});

export const jwtDecodeSchema = z.object({
  token: z.string().min(1),
});

// ── JWT Attack Demo ──
// E-2: 排他選択モードを廃止。各シナリオは 1 リクエストで両モード (脆弱+堅牢) を必ず並列実行する。
//      `mode` / `victim.strict` / `secretType` 等のモード選択フィールドは削除。
//      `forgedToken` / `injectedKid` はテスト用カスタム入力としてオプションで残す
//      (本体が実際に参照しているフィールドのみ。デッドフィールドは削除 — ROB-FIND-006)。
//      未知のフィールドは zod デフォルトで silently 削除される (旧契約クライアント互換)。
export const jwtAttackAlgNoneSchema = z.object({});

export const jwtAttackWeakSecretSchema = z.object({
  dictionarySize: z.number().int().min(1).max(200).default(100),
});

export const jwtAttackSignatureStrippingSchema = z.object({
  forgedToken: z.string().max(2048).optional(),
});

export const jwtAttackKidInjectionSchema = z.object({
  injectedKid: z.string().max(256).optional(),
});

// ── Session Auth ──
export const sessionLoginSchema = z.object({ username, password });

// ── Token Auth ──
export const tokenLoginSchema = z.object({ username, password });
export const tokenRefreshSchema = z.object({ refreshToken: z.string().min(1) });

// ── OAuth ──
export const oauthAuthorizeSchema = z.object({
  client_id: z.string().min(1),
  redirect_uri: z.string().min(1),
  scope: z.string().min(1).default("read"),
  state: z.string().default(""),
  username,
  password,
});

export const oauthTokenSchema = z.object({
  grant_type: z.enum(["authorization_code", "refresh_token"]),
  code: z.string().optional(),
  refresh_token: z.string().optional(),
  client_id: z.string().min(1),
  client_secret: z.string().optional(),
  redirect_uri: z.string().optional(),
});

// ── RBAC / ABAC / ACL ──
export const accessCheckSchema = z.object({
  subject: z.string().min(1),
  resource: z.string().min(1),
  action: z.string().min(1),
  context: z.record(z.string(), z.unknown()).optional(),
});

export const roleAssignSchema = z.object({
  username: z.string().min(1),
  roleName: z.string().min(1),
});

// ── WebAuthn ──
export const webauthnUsernameSchema = z.object({ username: z.string().min(1).max(64) });
export const webauthnRegisterVerifySchema = z.object({
  sessionId: z.string().uuid(),
  username: z.string().min(1).max(64),
  response: z.record(z.string(), z.unknown()),
});
export const webauthnAuthVerifySchema = z.object({
  sessionId: z.string().uuid(),
  username: z.string().min(1).max(64),
  response: z.record(z.string(), z.unknown()),
});

// ── Kerberos ──
export const kerberosAsReqSchema = z.object({
  principal: z.string().min(1),
  password: z.string().default("password"),
});
export const kerberosTgsReqSchema = z.object({
  tgt: z.string().min(1),
  tgtIv: z.string().min(1),
  servicePrincipal: z.string().min(1),
});
export const kerberosApReqSchema = z.object({
  serviceTicket: z.string().min(1),
  serviceTicketIv: z.string().min(1),
});

// ── OIDC / SAML ──
export const oidcAuthorizeSchema = z.object({
  username,
  password,
  client_id: z.string().min(1),
  redirect_uri: z.string().min(1),
  scope: z.string().default("openid"),
  state: z.string().default(""),
  nonce: z.string().optional(),
  // RFC 7636 §4.2: code_challenge is BASE64URL(SHA256(code_verifier)), 43–128 chars
  code_challenge: z.string().min(43).max(128).optional(),
  // RFC 7636 §4.3: only "S256" or "plain" are valid
  code_challenge_method: z.enum(["S256", "plain"]).optional(),
});

export const oidcTokenSchema = z.object({
  code: z.string().min(1),
  client_id: z.string().min(1),
  client_secret: z.string().optional(),
  redirect_uri: z.string().optional(),
  code_verifier: z.string().optional(),
});

export const samlSsoSchema = z.object({
  username,
  password,
  sp_entity_id: z.string().min(1),
});

// ── TLS ──
export const tlsSessionSchema = z.object({ sessionId: z.string().min(1) });

// ── MFA / TOTP ──
export const totpEnrollStartSchema = z.object({ username });
export const totpEnrollVerifySchema = z.object({
  username,
  code: z.string().regex(/^\d{6}$/, "code must be 6 digits"),
});
export const totpLoginStep1Schema = z.object({ username, password });
export const totpLoginStep2Schema = z.object({
  challengeId: z.string().min(1),
  code: z.string().regex(/^\d{6}$/, "code must be 6 digits"),
});

// ── Passkey (usernameless WebAuthn) ──
export const passkeyAuthOptionsSchema = z.object({}).passthrough();
export const passkeyAuthVerifySchema = z.object({
  sessionId: z.string().min(1),
  response: z.record(z.string(), z.unknown()),
});

// ── OAuth Attack Demo ──
// E-2: 各シナリオは 1 リクエストで両モード (脆弱+堅牢) を必ず並列実行する。
//      モード選択フィールドは廃止。handler が実際に参照するフィールドのみ (ROB-FIND-006)。
export const oauthAttackStateCsrfSchema = z.object({});

export const oauthAttackRedirectUriBypassSchema = z.object({
  attackerRedirectUri: z.string().max(512).optional(),
});

export const oauthAttackCodeViaRefererSchema = z.object({});

// ── SSO / API Key ──
export const ssoLoginSchema = z.object({ username: z.string().min(1) });
export const ssoAccessServiceSchema = z.object({
  ssoToken: z.string().min(1),
  serviceName: z.string().min(1).max(64).regex(/^[a-zA-Z0-9_-]+$/, "serviceName must be alphanumeric with hyphens/underscores"),
});
export const apikeyGenerateSchema = z.object({ name: z.string().max(128).default("default") });
export const apikeyHmacSchema = z.object({
  keyId: z.string().min(1),
  timestamp: z.string().min(1),
  body: z.unknown(),
  signature: z.string().min(1),
});
