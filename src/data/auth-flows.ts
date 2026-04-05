import type { OAuthStep, JwtSection, JwtField } from "../types/security";

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
