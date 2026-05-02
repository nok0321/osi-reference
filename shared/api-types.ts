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
  /** 攻撃シナリオのステップ一覧。攻撃デモエンドポイントのみ付与。 */
  attackSteps?: AttackStep[];
  /** 攻撃デモエンドポイント (/attack/) から発生したトレースの場合 true。middleware が自動セット。 */
  isAttackMode?: boolean;
  /** "live" = victim コンテナとの実通信 / "narration" = orchestrator 内部シム (DESIGN/31 §4.2) */
  mode?: "live" | "narration";
  /** mode: "live" のときに付与。victim 内部の DB/暗号操作が orchestrator から観測不能であることを明示。 */
  victimNote?: string;
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

export interface RefreshTokenRow {
  jti: string;
  user_id: number;
  expires_at: string;
  revoked: number;
  created_at: string;
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

/* ── Attack Demo Catalog (教育用シミュレーション専用型) ── */

/**
 * 攻撃ステップの操作種別。
 * DataFlowPanel および AttackStepTimeline コンポーネントでアイコン・色の選択に使用される。
 */
export type AttackStepKind =
  | "intercept"
  | "tamper"
  | "replay"
  | "forge"
  | "probe"
  | "verify"
  | "exploit"
  | "blocked";

/**
 * 攻撃シナリオを構成する1ステップ。
 * ServerTrace.attackSteps[] に格納され、DataFlowPanel の Trace タブで時系列表示される。
 */
export interface AttackStep {
  id: string;
  kind: AttackStepKind;
  label: string;
  labelJa: string;
  status: "pending" | "running" | "success" | "failed" | "blocked";
  payload?: AttackStepPayload;
  detail?: string;
  detailJa?: string;
  /** Unix ミリ秒。addAttackStep() が自動付与する。 */
  timestamp: number;
}

/**
 * 攻撃ステップが保持するペイロードデータ。
 * `type` フィールドで TypeScript の型絞り込みが可能なタグ付きユニオン。
 */
export type AttackStepPayload =
  | {
      type: "http";
      request?: {
        method: string;
        url: string;
        headers?: Record<string, string>;
        body?: unknown;
      };
      response?: {
        status: number;
        headers?: Record<string, string>;
        body?: unknown;
      };
      tamperedFields?: string[];
    }
  | {
      type: "token";
      before?: string;
      after?: string;
      algo?: string;
      decodedHeader?: Record<string, unknown>;
      decodedPayload?: Record<string, unknown>;
      signatureValid?: boolean;
    }
  | {
      type: "credential";
      username?: string;
      passwordHashAlgo?: string;
      triedPasswords?: string[];
      crackedPassword?: string;
      apiKeyPrefix?: string;
      apiKeySecret?: string;
      clearedFlag?: string;
    }
  | {
      type: "ticket";
      ticketId?: string;
      ticketType?: "TGT" | "ServiceTicket";
      principal?: string;
      encryptedFor?: string;
      realm?: string;
      encryptedData?: string;
      decryptedFields?: Record<string, string>;
      sessionKey?: string;
      validUntil?: string;
      stolenFrom?: string;
    }
  | {
      type: "saml";
      assertionXml?: string;
      signatureValid?: boolean;
      spEntityId?: string;
      nameId?: string;
      attributes?: Record<string, string>;
      notOnOrAfter?: string;
    }
  | {
      type: "tls";
      version?: string;
      downgradedTo?: string;
      cipherSuite?: string;
      weakCipherSuite?: string;
      certificate?: {
        subject: string;
        issuer: string;
        validFrom: string;
        validTo: string;
        selfSigned: boolean;
      };
      fakeCertificate?: {
        subject: string;
        issuer: string;
        selfSigned: boolean;
      };
    }
  | {
      type: "generic";
      data: Record<string, unknown>;
    };

/**
 * 攻撃シナリオ実行の全体結果。
 * POST /api/<area>/attack/<scenario-id> の成功レスポンスの data フィールドに格納される。
 * outcome リテラル: "succeeded" | "blocked" | "error" ("success" ではない)
 *
 * `TExtra` ジェネリックでシナリオ固有の追加フィールドを `extra` に格納する (E-1)。
 * デフォルトは `Record<string, never>` (extra 不要なシナリオ向け)。
 */
export interface AttackResult<TExtra = Record<string, never>> {
  scenarioId: string;
  outcome: "succeeded" | "blocked" | "error";
  startedAt: number;
  finishedAt: number;
  /** 実行されたすべてのステップ (時系列順)。 */
  steps: AttackStep[];
  blockedBy?: string;
  summary?: string;
  summaryJa?: string;
  logId?: number;
  /** シナリオ固有の追加フィールド (ジェネリック)。 */
  extra?: TExtra;
}

/**
 * 攻撃シナリオのメタ情報。
 * tabId は src/types/security.ts の AuthSubView 型と一致させる (循環参照回避のため string)。
 * severity リテラル順: "info" | "low" | "medium" | "high" | "critical"
 */
export interface AttackScenarioMeta {
  id: string;
  /** AuthSubView 型と一致させる。例: "jwt", "oauth", "rbac" */
  tabId: string;
  name: string;
  nameJa: string;
  category: string;
  cweId?: string;
  capecId?: string;
  difficulty: 1 | 2 | 3 | 4 | 5;
  osiLayer: number | string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  description: string;
  descriptionJa: string;
  mitigation: string;
  mitigationJa: string;
  references?: string[];

  /** 防御コード例。AttackDefensePanel で表示。 */
  codeHints?: { lang: string; label: string; code: string }[];

  /** 既存の防御実装ファイルへのポインタ。AttackDefensePanel で表示。 */
  existingFileLinks?: { path: string; description: string }[];

  /**
   * シナリオが脆弱/堅牢の両モードを 1 リクエストで並列実行する場合の表示用ラベル (E-2)。
   * UI は両モードの結果 (5 ステップ完全形のうちステップ 4=脆弱、ステップ 5=堅牢) を並列表示する。
   * `body` は不要 (排他選択モードは廃止)。
   */
  modes?: {
    id: string;
    labelJa: string;
    label: string;
    /** "vulnerable"=脆弱モード (赤系) / "defensive"=堅牢モード (緑系)。UI スタイルに使用。 */
    kind: "vulnerable" | "defensive";
  }[];

  /**
   * "live"     : Docker victim コンテナと実通信 → POST /api/orchestrator/exec
   * "narration": orchestrator 内部シム → POST /api/<area>/attack/<scenario-id>
   * 未指定時は "narration" として扱う (Phase 1 移行期間の後方互換)。
   */
  mode?: "live" | "narration";

  /**
   * mode: "live" シナリオで RawHttpComposer の初期値として使うテンプレート。
   * 学習者は target の dropdown と headers/body を編集してから送信する。
   */
  liveTemplate?: {
    target: VictimTarget;
    method: HttpMethod;
    path: string;
    headers?: Record<string, string>;
    body?: string;
  };
}

/* ── Live Attack: Orchestrator API (DESIGN/31) ── */

/**
 * VICTIM_ALLOWLIST のキー文字列リテラル union。
 * ブラウザは `target` フィールドにこのキーのみ送信できる (URL 偽造防止)。
 * orchestrator が allowlist から baseUrl を解決する。
 */
export type VictimTarget =
  | "victim-web"
  | "attacker-shell"
  | "victim-tls-proxy"
  | "victim-saml-idp";

/**
 * VICTIM_ALLOWLIST の値エントリ。
 * baseUrl の上書きは禁止 (環境変数も含む)。Phase ガードに利用される `phaseAvailable` を持つ。
 */
export interface VictimEntry {
  /**
   * 転送先 URL。`http://` または `https://` で始まる完全 URL。
   * `exec://<container-name>` で始まる場合は docker exec 経由のコマンド実行を示す (Phase 2+ の attacker-shell 用)。
   */
  baseUrl: string;
  /** この victim が接続する Docker ネットワーク名。 */
  network: "victim-net";
  /** この victim が利用可能になる最初の Phase 番号。 */
  phaseAvailable: 1 | 2 | 3 | 4 | 5;
}

export type HttpMethod = "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS";

/** 学習者が RawHttpComposer で組み立てたリクエストのフロント送信フォーマット。 */
export interface OrchestratorExecRequest {
  /** AttackScenarioMeta.id と一致させる。例: "jwt-alg-none" */
  scenarioId: string;
  /** VICTIM_ALLOWLIST のキー文字列。baseUrl は orchestrator が allowlist から取得する。 */
  target: VictimTarget;
  request: {
    method: HttpMethod;
    /** pathname + query string。"/" で始まる必要がある。 */
    path: string;
    headers: Record<string, string>;
    body?: string | null;
  };
  /** victim コンテナへの接続タイムアウト (ms)。100–10000、デフォルト 3000。 */
  timeoutMs?: number;
}

export interface RawHttpRequest {
  /** "POST /jwt/verify HTTP/1.1" 形式のリクエスト行 */
  line: string;
  headers: Record<string, string>;
  body: string | null;
  /** 送信した総バイト数 (ヘッダ + ボディ) */
  bytesSent: number;
}

export interface RawHttpResponse {
  /** "HTTP/1.1 200 OK" 形式のステータス行 */
  line: string;
  status: number;
  headers: Record<string, string>;
  body: string | null;
  /** 受信した総バイト数 (ヘッダ + ボディ) */
  bytesReceived: number;
}

/**
 * 双方向 raw HTTP キャプチャ。browser⇄orchestrator + orchestrator⇄victim の両ペア。
 * メモリ上のみ保持し、attack_log には summary のみを書き込む (DESIGN/31 §6.4)。
 */
export interface RawExchange {
  browserToOrchestrator: {
    request: RawHttpRequest;
    response: RawHttpResponse;
  };
  orchestratorToVictim: {
    request: RawHttpRequest;
    response: RawHttpResponse;
    /** VICTIM_ALLOWLIST から解決された baseUrl */
    targetResolvedTo: string;
  };
  /** browser → orchestrator → victim → orchestrator → browser の総経過 (ms) */
  elapsedMs: number;
}

/**
 * POST /api/orchestrator/exec の成功レスポンス型。
 * AttackResult に live モード固有フィールドを追加する。
 */
export interface OrchestratorExecResponse extends AttackResult {
  rawExchange: RawExchange;
  mode: "live";
}

/** attack_log テーブルの行型。 */
export interface AttackLogRow {
  id: number;
  scenario_id: string;
  tab_id: string;
  started_at: number;
  finished_at: number | null;
  success: 0 | 1;
  blocked_by: string | null;
  steps_json: string | null;
  payload_json: string | null;
  user_session_id: string | null;
}
