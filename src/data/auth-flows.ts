import type { OAuthStep, JwtSection, JwtField, TlsStep, AuthMethodComparison, RbacRole, AbacPolicy, AclEntry, PolicyRule } from "../types/security";

export const OAUTH_STEPS: OAuthStep[] = [
  {
    stepNumber: 1,
    from: "user", to: "client",
    action: "Access Resource", actionJa: "リソースアクセス",
    description: "User clicks 'Login with Provider' button on the client application",
    descriptionJa: "ユーザーがクライアントアプリの「プロバイダーでログイン」ボタンをクリック",
    osiLayers: [7],
    isSecure: false,
  },
  {
    stepNumber: 2,
    from: "client", to: "auth-server",
    action: "Authorization Request", actionJa: "認可リクエスト",
    description: "Client redirects user to authorization server with client_id, redirect_uri, scope, state",
    descriptionJa: "クライアントがユーザーを認可サーバーにリダイレクト (client_id, redirect_uri, scope, state付き)",
    dataPayload: "GET /authorize?client_id=abc&redirect_uri=...&scope=read&state=xyz",
    osiLayers: [7, 6],
    isSecure: true,
  },
  {
    stepNumber: 3,
    from: "auth-server", to: "user",
    action: "Login Prompt", actionJa: "ログインプロンプト",
    description: "Authorization server presents login form and consent screen to the user",
    descriptionJa: "認可サーバーがユーザーにログインフォームと同意画面を表示",
    osiLayers: [7],
    isSecure: true,
  },
  {
    stepNumber: 4,
    from: "user", to: "auth-server",
    action: "Credentials + Consent", actionJa: "認証情報＋同意",
    description: "User authenticates (username/password, MFA) and approves the requested scopes",
    descriptionJa: "ユーザーが認証 (ユーザー名/パスワード, MFA) し、要求されたスコープを承認",
    osiLayers: [7, 6],
    isSecure: true,
  },
  {
    stepNumber: 5,
    from: "auth-server", to: "client",
    action: "Authorization Code", actionJa: "認可コード",
    description: "Server redirects back to client's redirect_uri with short-lived authorization code and state",
    descriptionJa: "サーバーが短命の認可コードとstateをクライアントのredirect_uriにリダイレクト",
    dataPayload: "302 → redirect_uri?code=AUTH_CODE&state=xyz",
    osiLayers: [7],
    isSecure: true,
  },
  {
    stepNumber: 6,
    from: "client", to: "auth-server",
    action: "Token Exchange", actionJa: "トークン交換",
    description: "Client exchanges authorization code for tokens (sends client_secret server-side)",
    descriptionJa: "クライアントが認可コードをトークンに交換 (client_secretをサーバーサイドで送信)",
    dataPayload: "POST /token {grant_type=authorization_code, code=AUTH_CODE, client_secret=...}",
    osiLayers: [7, 6, 4],
    isSecure: true,
  },
  {
    stepNumber: 7,
    from: "auth-server", to: "client",
    action: "Access + Refresh Tokens", actionJa: "アクセス＋リフレッシュトークン",
    description: "Authorization server returns access_token (short-lived), refresh_token (long-lived), and token_type",
    descriptionJa: "認可サーバーがaccess_token (短命), refresh_token (長命), token_typeを返却",
    dataPayload: '{"access_token":"eyJ...", "refresh_token":"dGhp...", "expires_in":3600}',
    osiLayers: [7, 6],
    isSecure: true,
  },
  {
    stepNumber: 8,
    from: "client", to: "resource-server",
    action: "API Request with Token", actionJa: "トークン付きAPIリクエスト",
    description: "Client accesses protected resource using Bearer token in Authorization header",
    descriptionJa: "クライアントがAuthorizationヘッダのBearerトークンで保護リソースにアクセス",
    dataPayload: "GET /api/user Authorization: Bearer eyJ...",
    osiLayers: [7, 6, 4],
    isSecure: true,
  },
];

export const OAUTH_ACTORS = [
  { id: "user" as const, name: "User", nameJa: "ユーザー", color: "#1677FF" },
  { id: "client" as const, name: "Client App", nameJa: "クライアント", color: "#08979C" },
  { id: "auth-server" as const, name: "Auth Server", nameJa: "認可サーバー", color: "#531DAB" },
  { id: "resource-server" as const, name: "Resource Server", nameJa: "リソースサーバー", color: "#7CB305" },
];

// Sample JWT
export const SAMPLE_JWT_ENCODED = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxNTE2MjQyNjIyLCJpc3MiOiJhdXRoLmV4YW1wbGUuY29tIiwiYXVkIjoiYXBpLmV4YW1wbGUuY29tIn0.POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZWF1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxG-W9KcEEbDRcZc0nH3L7LzYptiy1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguEIcoqPJ1n3pIWk_dUZegpqx0Lka21H6XxUTxiy8OcaarA8zdnPUnV6AmNP3ecFawIFYdvJB_cm-GvpCSbr8G8y_Mllj8f4x9nBH8pQux89_6gUY618iYv7tuPWBFfEbLxtF2pZS6YC1aSfLQxaOoaBSTpoRyXw";

export const JWT_SECTIONS: JwtSection[] = [
  {
    name: "header",
    color: "#ff6b6b",
    encoded: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
    decoded: '{\n  "alg": "RS256",\n  "typ": "JWT"\n}',
    fields: [
      { key: "alg", value: "RS256", description: "Signing algorithm (RSA SHA-256)", descriptionJa: "署名アルゴリズム (RSA SHA-256)" },
      { key: "typ", value: "JWT", description: "Token type", descriptionJa: "トークン種別" },
    ],
  },
  {
    name: "payload",
    color: "#a855f7",
    encoded: "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxNTE2MjQyNjIyLCJpc3MiOiJhdXRoLmV4YW1wbGUuY29tIiwiYXVkIjoiYXBpLmV4YW1wbGUuY29tIn0",
    decoded: '{\n  "sub": "1234567890",\n  "name": "John Doe",\n  "admin": true,\n  "iat": 1516239022,\n  "exp": 1516242622,\n  "iss": "auth.example.com",\n  "aud": "api.example.com"\n}',
    fields: [
      { key: "sub", value: "1234567890", description: "Subject (user ID)", descriptionJa: "サブジェクト (ユーザーID)" },
      { key: "name", value: "John Doe", description: "User display name", descriptionJa: "ユーザー表示名" },
      { key: "admin", value: "true", description: "Custom claim: admin role", descriptionJa: "カスタムクレーム: 管理者ロール" },
      { key: "iat", value: "1516239022", description: "Issued at (Unix timestamp)", descriptionJa: "発行日時 (Unixタイムスタンプ)" },
      { key: "exp", value: "1516242622", description: "Expiration time", descriptionJa: "有効期限" },
      { key: "iss", value: "auth.example.com", description: "Issuer", descriptionJa: "発行者" },
      { key: "aud", value: "api.example.com", description: "Audience", descriptionJa: "受信者" },
    ],
  },
  {
    name: "signature",
    color: "#3b82f6",
    encoded: "POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0...",
    decoded: "RSASHA256(\n  base64UrlEncode(header) + \".\" +\n  base64UrlEncode(payload),\n  publicKey,\n  privateKey\n)",
    fields: [
      { key: "algorithm", value: "RSASHA256", description: "RSA signature with SHA-256 hash", descriptionJa: "SHA-256ハッシュによるRSA署名" },
      { key: "input", value: "header.payload", description: "Base64url encoded header + payload", descriptionJa: "Base64urlエンコードされたheader + payload" },
      { key: "key", value: "Private Key", description: "Server's RSA private key signs the token", descriptionJa: "サーバーのRSA秘密鍵でトークンに署名" },
    ],
  },
];

// === TLS Deep Dive Steps ===
export const TLS_DEEP_STEPS: TlsStep[] = [
  {
    stepNumber: 1, name: "TCP Handshake", nameJa: "TCPハンドシェイク",
    direction: "both",
    description: "TCP 3-way handshake establishes reliable transport. SYN → SYN-ACK → ACK. Consumes 1 RTT.",
    descriptionJa: "TCP 3ウェイハンドシェイクで信頼性のある転送路を確立。SYN → SYN-ACK → ACK。1 RTT消費。",
    osiLayer: 4,
    dataFields: [
      { name: "SYN", value: "seq=0" },
      { name: "SYN-ACK", value: "seq=0, ack=1" },
      { name: "ACK", value: "seq=1, ack=1" },
    ],
  },
  {
    stepNumber: 2, name: "ClientHello", nameJa: "ClientHello",
    direction: "client-to-server",
    description: "Client sends supported TLS versions, cipher suites, key_share extension (X25519), SNI, and random bytes.",
    descriptionJa: "クライアントが対応TLSバージョン、暗号スイート、key_share拡張(X25519)、SNI、ランダムバイトを送信。",
    cryptoDetails: "TLS 1.3 only. Key share enables 1-RTT handshake by sending public key upfront.",
    cryptoDetailsJa: "TLS 1.3専用。公開鍵を先行送信することで1-RTTハンドシェイクを実現。",
    osiLayer: 6,
    dataFields: [
      { name: "Version", value: "TLS 1.3 (0x0304)" },
      { name: "Cipher Suites", value: "TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305" },
      { name: "Key Share", value: "X25519 public key (32 bytes)" },
      { name: "SNI", value: "example.com" },
    ],
  },
  {
    stepNumber: 3, name: "ServerHello", nameJa: "ServerHello",
    direction: "server-to-client",
    description: "Server selects cipher suite and key share group. Sends its X25519 public key for ECDHE.",
    descriptionJa: "サーバーが暗号スイートと鍵共有グループを選択。ECDHE用のX25519公開鍵を送信。",
    cryptoDetails: "Selected: TLS_AES_256_GCM_SHA384 with X25519 ECDHE.",
    cryptoDetailsJa: "選択: TLS_AES_256_GCM_SHA384 + X25519 ECDHE。",
    osiLayer: 6,
    dataFields: [
      { name: "Selected Cipher", value: "TLS_AES_256_GCM_SHA384" },
      { name: "Key Share", value: "X25519 public key (32 bytes)" },
    ],
  },
  {
    stepNumber: 4, name: "EncryptedExtensions", nameJa: "暗号化拡張",
    direction: "server-to-client",
    description: "Server sends extensions that are not needed for key exchange, now encrypted with handshake keys.",
    descriptionJa: "サーバーが鍵交換に不要な拡張を送信。ハンドシェイク鍵で暗号化済み。",
    cryptoDetails: "From this point, all server messages are encrypted with handshake traffic keys derived from ECDHE shared secret.",
    cryptoDetailsJa: "この時点から、すべてのサーバーメッセージはECDHE共有秘密から導出されたハンドシェイクトラフィック鍵で暗号化。",
    osiLayer: 6,
    dataFields: [
      { name: "ALPN", value: "h2 (HTTP/2)" },
    ],
  },
  {
    stepNumber: 5, name: "Certificate", nameJa: "証明書",
    direction: "server-to-client",
    description: "Server sends X.509 certificate chain: leaf cert → intermediate CA → (implicit) root CA.",
    descriptionJa: "サーバーがX.509証明書チェーンを送信: リーフ証明書 → 中間CA → (暗黙の) ルートCA。",
    cryptoDetails: "Client verifies: signature chain, hostname match (SAN), expiry, revocation (OCSP/CRL).",
    cryptoDetailsJa: "クライアントが検証: 署名チェーン、ホスト名一致(SAN)、有効期限、失効確認(OCSP/CRL)。",
    osiLayer: 6,
    dataFields: [
      { name: "Subject", value: "CN=example.com" },
      { name: "Issuer", value: "CN=Let's Encrypt Authority X3" },
      { name: "Validity", value: "90 days" },
      { name: "Key", value: "EC P-256 (256 bits)" },
    ],
  },
  {
    stepNumber: 6, name: "CertificateVerify", nameJa: "証明書検証",
    direction: "server-to-client",
    description: "Server proves ownership of private key by signing the handshake transcript hash.",
    descriptionJa: "サーバーがハンドシェイクトランスクリプトのハッシュに署名して秘密鍵の所有を証明。",
    cryptoDetails: "Signature algorithm: ECDSA with SHA-256 over transcript hash. Prevents replay attacks.",
    cryptoDetailsJa: "署名アルゴリズム: トランスクリプトハッシュに対するECDSA+SHA-256。リプレイ攻撃を防止。",
    osiLayer: 6,
    dataFields: [
      { name: "Algorithm", value: "ECDSA-SHA256" },
      { name: "Input", value: "SHA-256(handshake_messages)" },
    ],
  },
  {
    stepNumber: 7, name: "Server Finished", nameJa: "サーバーFinished",
    direction: "server-to-client",
    description: "Server sends Finished message with HMAC of entire handshake. Confirms key derivation is consistent.",
    descriptionJa: "サーバーがハンドシェイク全体のHMAC付きFinishedメッセージを送信。鍵導出の一貫性を確認。",
    cryptoDetails: "HMAC-SHA384 over handshake transcript using server handshake traffic secret.",
    cryptoDetailsJa: "サーバーハンドシェイクトラフィックシークレットを使用したトランスクリプトのHMAC-SHA384。",
    osiLayer: 6,
    dataFields: [
      { name: "Verify Data", value: "HMAC-SHA384(finished_key, transcript)" },
    ],
  },
  {
    stepNumber: 8, name: "Client Finished", nameJa: "クライアントFinished",
    direction: "client-to-server",
    description: "Client verifies server's Finished, computes ECDHE shared secret, derives application traffic keys, sends its Finished.",
    descriptionJa: "クライアントがサーバーのFinishedを検証、ECDHE共有秘密を計算、アプリケーショントラフィック鍵を導出、自身のFinishedを送信。",
    cryptoDetails: "Key schedule: ECDHE → HKDF-Extract → Derive-Secret → handshake keys → application keys. Forward secrecy achieved.",
    cryptoDetailsJa: "鍵スケジュール: ECDHE → HKDF-Extract → Derive-Secret → ハンドシェイク鍵 → アプリケーション鍵。前方秘匿性を達成。",
    osiLayer: 6,
    dataFields: [
      { name: "Key Derivation", value: "HKDF-SHA384" },
      { name: "Application Keys", value: "AES-256-GCM + IV (per direction)" },
      { name: "Total RTT", value: "1-RTT (after TCP)" },
    ],
  },
];

// === Session vs Token Comparison ===
export const AUTH_COMPARISON: AuthMethodComparison[] = [
  {
    aspect: "Storage", aspectJa: "保存場所",
    session: { value: "Server-side (memory/DB/Redis)", valueJa: "サーバー側 (メモリ/DB/Redis)", pros: "No sensitive data on client", prosJa: "クライアントに機密データなし", cons: "Server state scales with users", consJa: "サーバー状態がユーザー数に比例" },
    token: { value: "Client-side (localStorage/cookie)", valueJa: "クライアント側 (localStorage/cookie)", pros: "Stateless server, easy to scale", prosJa: "ステートレスサーバー、スケール容易", cons: "Token theft risk (XSS)", consJa: "トークン盗難リスク (XSS)" },
  },
  {
    aspect: "Scalability", aspectJa: "スケーラビリティ",
    session: { value: "Requires sticky sessions or shared store", valueJa: "スティッキーセッションまたは共有ストアが必要", pros: "Simple for single-server", prosJa: "シングルサーバーではシンプル", cons: "Hard to scale horizontally", consJa: "水平スケールが困難" },
    token: { value: "Any server can validate independently", valueJa: "任意のサーバーが独立して検証可能", pros: "Perfect for microservices", prosJa: "マイクロサービスに最適", cons: "Token size grows with claims", consJa: "クレーム増加でトークンサイズ増大" },
  },
  {
    aspect: "Revocation", aspectJa: "無効化",
    session: { value: "Delete session from store", valueJa: "ストアからセッション削除", pros: "Immediate revocation", prosJa: "即時無効化", cons: "Need access to session store", consJa: "セッションストアへのアクセスが必要" },
    token: { value: "Wait for expiry or use blocklist", valueJa: "期限切れ待ちまたはブロックリスト", pros: "No central store needed", prosJa: "中央ストア不要", cons: "Hard to revoke before expiry", consJa: "期限前の無効化が困難" },
  },
  {
    aspect: "Size", aspectJa: "サイズ",
    session: { value: "Small session ID (~32 bytes)", valueJa: "小さなセッションID (~32バイト)", pros: "Minimal bandwidth", prosJa: "最小限の帯域幅", cons: "Requires server lookup", consJa: "サーバールックアップが必要" },
    token: { value: "JWT can be 1KB+ with claims", valueJa: "JWTはクレーム付きで1KB以上", pros: "Self-contained, no lookup", prosJa: "自己完結型、ルックアップ不要", cons: "Larger per-request overhead", consJa: "リクエストごとのオーバーヘッド大" },
  },
  {
    aspect: "CSRF Protection", aspectJa: "CSRF対策",
    session: { value: "Needs CSRF token (cookie-based)", valueJa: "CSRFトークンが必要 (cookieベース)", pros: "Proven pattern (SameSite + token)", prosJa: "実績のあるパターン (SameSite + トークン)", cons: "Extra implementation work", consJa: "追加の実装作業" },
    token: { value: "Immune if stored in header/localStorage", valueJa: "ヘッダ/localStorageなら影響なし", pros: "No CSRF concern with Bearer", prosJa: "Bearerトークンはcsrf不要", cons: "XSS becomes the threat vector", consJa: "XSSが脅威ベクトルに" },
  },
  {
    aspect: "Cross-Domain", aspectJa: "クロスドメイン",
    session: { value: "Limited to same origin (cookies)", valueJa: "同一オリジンに限定 (cookie)", pros: "Built-in browser security", prosJa: "ブラウザ組み込みセキュリティ", cons: "Complex for multi-domain", consJa: "マルチドメインでは複雑" },
    token: { value: "Works across any domain (CORS)", valueJa: "任意のドメインで動作 (CORS)", pros: "Ideal for APIs / SPAs", prosJa: "API / SPAに最適", cons: "Needs careful CORS config", consJa: "慎重なCORS設定が必要" },
  },
];

// === RBAC Roles ===
export const RBAC_ROLES: RbacRole[] = [
  {
    name: "Admin", nameJa: "管理者",
    permissions: ["users:read", "users:write", "users:delete", "posts:read", "posts:write", "posts:delete", "settings:manage"],
    color: "#ff4d4f",
  },
  {
    name: "Editor", nameJa: "編集者",
    permissions: ["posts:read", "posts:write", "posts:delete", "users:read"],
    color: "#faad14",
  },
  {
    name: "Author", nameJa: "著者",
    permissions: ["posts:read", "posts:write"],
    color: "#1677ff",
  },
  {
    name: "Viewer", nameJa: "閲覧者",
    permissions: ["posts:read", "users:read"],
    color: "#52c41a",
  },
];

export const ALL_PERMISSIONS = [
  "users:read", "users:write", "users:delete",
  "posts:read", "posts:write", "posts:delete",
  "settings:manage",
];

// === ABAC Policies ===
export const ABAC_POLICIES: AbacPolicy[] = [
  {
    subject: "User (role=editor, dept=marketing)",
    resource: "Document (type=report, dept=marketing)",
    action: "edit",
    condition: "subject.dept == resource.dept AND subject.role IN ['editor', 'admin']",
    conditionJa: "subject.dept == resource.dept AND subject.role IN ['editor', 'admin']",
    result: "allow",
  },
  {
    subject: "User (role=editor, dept=engineering)",
    resource: "Document (type=report, dept=marketing)",
    action: "edit",
    condition: "subject.dept == resource.dept → FALSE",
    conditionJa: "subject.dept == resource.dept → FALSE",
    result: "deny",
  },
  {
    subject: "User (role=admin, dept=any)",
    resource: "Document (type=any, dept=any)",
    action: "delete",
    condition: "subject.role == 'admin' AND time.hour BETWEEN 9 AND 17",
    conditionJa: "subject.role == 'admin' AND time.hour BETWEEN 9 AND 17",
    result: "allow",
  },
  {
    subject: "User (role=viewer, ip=10.0.0.x)",
    resource: "Document (classification=confidential)",
    action: "read",
    condition: "resource.classification != 'confidential' OR subject.clearance >= 'secret'",
    conditionJa: "resource.classification != 'confidential' OR subject.clearance >= 'secret'",
    result: "deny",
  },
];

/* ──── ACL (Access Control List) ──── */

export const ACL_ENTRIES: AclEntry[] = [
  { subject: "alice", resource: "/home/alice", permissions: ["read", "write", "execute"], effect: "allow" },
  { subject: "alice", resource: "/shared/docs", permissions: ["read", "write"], effect: "allow" },
  { subject: "alice", resource: "/admin/config", permissions: ["read"], effect: "deny" },
  { subject: "bob", resource: "/home/bob", permissions: ["read", "write", "execute"], effect: "allow" },
  { subject: "bob", resource: "/shared/docs", permissions: ["read"], effect: "allow" },
  { subject: "bob", resource: "/shared/docs", permissions: ["write"], effect: "deny" },
  { subject: "charlie", resource: "/home/charlie", permissions: ["read", "write", "execute"], effect: "allow" },
  { subject: "charlie", resource: "/shared/docs", permissions: ["read", "write", "delete"], effect: "allow" },
  { subject: "charlie", resource: "/admin/config", permissions: ["read", "write"], effect: "allow" },
];

export const ACL_RESOURCES = ["/home/{user}", "/shared/docs", "/admin/config"];
export const ACL_SUBJECTS = ["alice", "bob", "charlie"];

/* ──── Policy-Based Authorization ──── */

export const POLICY_RULES: PolicyRule[] = [
  {
    id: "p1",
    name: "Allow admins full access",
    nameJa: "管理者にフルアクセスを許可",
    effect: "allow",
    principal: 'principal.role == "admin"',
    action: "*",
    resource: "*",
    condition: "true",
    conditionJa: "常に",
  },
  {
    id: "p2",
    name: "Allow editors to update own dept docs",
    nameJa: "エディタに自部門ドキュメント更新を許可",
    effect: "allow",
    principal: 'principal.role == "editor"',
    action: "update",
    resource: "Document",
    condition: "principal.dept == resource.dept",
    conditionJa: "principal.dept == resource.dept",
  },
  {
    id: "p3",
    name: "Deny access outside business hours",
    nameJa: "営業時間外のアクセスを拒否",
    effect: "deny",
    principal: "*",
    action: "*",
    resource: "FinancialReport",
    condition: "context.time.hour < 9 || context.time.hour > 18",
    conditionJa: "context.time.hour < 9 || context.time.hour > 18",
  },
  {
    id: "p4",
    name: "Allow read from internal network",
    nameJa: "内部ネットワークからの読み取りを許可",
    effect: "allow",
    principal: 'principal.role == "viewer"',
    action: "read",
    resource: "InternalDoc",
    condition: 'context.ip.startsWith("10.0.")',
    conditionJa: 'context.ip.startsWith("10.0.")',
  },
  {
    id: "p5",
    name: "Deny delete on archived resources",
    nameJa: "アーカイブリソースの削除を拒否",
    effect: "deny",
    principal: "*",
    action: "delete",
    resource: "Document",
    condition: 'resource.status == "archived"',
    conditionJa: 'resource.status == "archived"',
  },
];
