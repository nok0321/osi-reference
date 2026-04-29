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

// ── RBAC Attack Demo ──
// E-2: 各シナリオは 1 リクエストで両モード (脆弱+堅牢) を必ず並列実行する。
//      handler が実際に参照するフィールドのみ (ROB-FIND-006)。
//      default() を付与することで body 省略可能にする (oauth スキーマ参照)。
export const rbacAttackIdorSchema = z.object({
  victimId: z.number().int().min(1).max(999).default(1),
  attackerId: z.number().int().min(1).max(999).default(3),
});

export const rbacAttackHorizontalEscalationSchema = z.object({
  attackerRole: z.enum(["admin", "editor", "viewer"]).default("editor"),
  attackerUserId: z.number().int().min(1).max(999).default(2),
  victimUserId: z.number().int().min(1).max(999).default(1),
  action: z.enum(["read", "write", "delete"]).default("read"),
});

export const rbacAttackVerticalEscalationSchema = z.object({
  attackerRole: z.enum(["admin", "editor", "viewer"]).default("viewer"),
  targetUserId: z.number().int().min(1).max(999).default(1),
});

export const rbacAttackAbacTamperSchema = z.object({
  subject: z.enum(["seed_alice", "seed_bob", "attacker_charlie", "seed_admin"]).default("attacker_charlie"),
  clientDepartment: z.enum(["Engineering", "Marketing", "Finance", "IT"]).default("Finance"),
  resourceDepartment: z.enum(["Engineering", "Marketing", "Finance", "IT"]).default("Finance"),
  action: z.enum(["read", "write"]).default("read"),
});

// ── Session/Token Attack Demo ──
// E-2: 各シナリオは 1 リクエストで両モード (脆弱+堅牢) を必ず並列実行する。
//      handler が実際に参照するフィールドのみ (ROB-FIND-006)。
export const sessionAttackFixationSchema = z.object({});

export const sessionAttackXssCookieTheftSchema = z.object({});

// scenarioDelay: ユーザー指定の経過秒数。実際に verify ステップで適用される時刻オフセットは
// handler 内で `Math.max(scenarioDelay, expiresInSec+1)` (expiresInSec=900) に正規化され、
// 教育目的「有効期限超過リプレイの拒否」を確実に観測できる (SEC-1 / SEC-4)。
// scenarioDelay 自体はユーザー意図値として extra.scenarioDelaySec に保持される。
export const tokenAttackReplaySchema = z.object({
  scenarioDelay: z.number().int().min(0).max(86400).default(960), // 0=即時, 960=16分(=有効期限超過)
});

// ── WebAuthn / FIDO2 Attack Demo ──
// E-2: 各シナリオは 1 リクエストで両モード (脆弱+堅牢) を必ず並列実行する。
//      handler が実際に参照するフィールドのみ (ROB-FIND-006)。
//      default() を付与することで body 省略可能にする (oauth/rbac/session スキーマ参照)。
export const webauthnAttackPhishingOriginSchema = z.object({});

export const webauthnAttackVsPasswordPhishingSchema = z.object({});

export const webauthnAttackChallengeReplaySchema = z.object({});

// ── OIDC / SAML Attack Demo ──
// E-2: 各シナリオは 1 リクエストで両モード (脆弱+堅牢) を必ず並列実行する。
//      handler が実際に参照するフィールドのみ (ROB-FIND-006)。
//      default() を付与することで body 省略可能にする (oauth/rbac/session/fido2 スキーマ参照)。
export const samlAttackXswSchema = z.object({});

export const samlAttackAssertionReplaySchema = z.object({});

export const oidcAttackIdTokenSpoofSchema = z.object({});

// ── Kerberos Attack Demo ──
// E-2: 各シナリオは 1 リクエストで両モード (脆弱+堅牢) を必ず並列実行する。
//      handler が実際に参照するフィールドのみ (ROB-FIND-006)。
//      kerberoasting は弱 SPN (脆弱) と強 SPN (堅牢) の両方を 1 リクエストで実行する
//      (ROB-KERB-1 修正)。targetSpn は廃止。
export const kerberosAttackPassTheTicketSchema = z.object({});

export const kerberosAttackKerberoastingSchema = z.object({});

export const kerberosAttackGoldenTicketSchema = z.object({});

// ── TLS Attack Demo ──
// E-2: 各シナリオは 1 リクエストで両モード (脆弱+堅牢) を必ず並列実行する。
//      旧仕様の `mitmEnabled` / `fallbackScsvEnabled` / `certValidationEnabled` /
//      `serverAllowWeakCiphers` 等のモード選択フィールドは廃止 (ROB-KERB-1 教訓 / ROB-FIND-006)。
//      handler 内で弱/強 (脆弱/堅牢) を双方並列計算する。
export const tlsAttackVersionDowngradeSchema = z.object({});

export const tlsAttackSelfSignedMitmSchema = z.object({});

export const tlsAttackWeakCipherSchema = z.object({});

// ── Password Attack Demo ──
// E-2: 各シナリオは 1 リクエストで両モード (脆弱+堅牢) を必ず並列実行する。
//      handler が実際に参照するフィールドのみ (ROB-FIND-006)。
//      モード選択フィールドは廃止 — bcrypt vs SHA-1/MD5 / 短絡評価 vs timingSafeEqual /
//      レート制限なし vs あり を必ず両方並列実行する。
export const passwordAttackRainbowVsBcryptSchema = z.object({});

export const passwordAttackTimingStringCompareSchema = z.object({});

export const passwordAttackBruteforceSchema = z.object({});

// ── MFA Attack Demo ──
// E-2: 各シナリオは 1 リクエストで両モード (脆弱+堅牢) を必ず並列実行する。
//      handler が実際に参照するフィールドのみ (ROB-FIND-006)。
//      モード選択フィールド (replayDefenseEnabled / windowSize / mfaChannel / simSwapSimulated)
//      は仕様上 DEAD FIELD — handler 内で両モード固定実行する (ROB-KERB-1 教訓)。
export const mfaAttackOtpReplaySchema = z.object({});

export const mfaAttackTimeWindowWideSchema = z.object({});

export const mfaAttackSmsSwapSchema = z.object({});

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
