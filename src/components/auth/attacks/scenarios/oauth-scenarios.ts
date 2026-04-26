import type { AttackScenarioMeta } from "../../../../../shared/api-types";

export const oauthScenarios: AttackScenarioMeta[] = [
  {
    id: "oauth-state-csrf",
    tabId: "oauth",
    name: "State Parameter CSRF",
    nameJa: "state 欠落 CSRF",
    category: "Authorization / CSRF",
    cweId: "CWE-352",
    capecId: "CAPEC-62",
    difficulty: 2,
    osiLayer: 7,
    severity: "high",
    description:
      "This is a proof-of-concept for CWE-352 / CAPEC-62. When the OAuth client omits the state parameter, an attacker can forge a callback request containing the attacker's own authorization code, causing the victim's session to be linked to the attacker's account.",
    descriptionJa:
      "これは CWE-352 / CAPEC-62 の概念実証です。OAuth クライアントが state パラメータを省略した場合、攻撃者は自身の認可コードを含むコールバックリクエストを偽造し、被害者のセッションを攻撃者のアカウントに紐付けることが可能になります。",
    mitigation:
      "Always generate a cryptographically random state value (at least 128 bits, e.g. crypto.randomUUID()) before the authorization request, store it in sessionStorage, and verify it on callback. Delete it after use.",
    mitigationJa:
      "認可リクエスト前に暗号学的ランダムな state 値 (最低 128 ビット、例: crypto.randomUUID()) を生成し、sessionStorage に保存してコールバックで照合してください。使用後は必ず削除します。",
    references: [
      "https://tools.ietf.org/html/rfc6749#section-10.12",
      "https://cwe.mitre.org/data/definitions/352.html",
      "https://owasp.org/www-community/attacks/csrf",
    ],
    codeHints: [
      {
        lang: "typescript",
        label: "State generation and verification (recommended)",
        code: `// 認可リクエスト前: 暗号学的安全な乱数で state を生成
const state = crypto.randomUUID();
sessionStorage.setItem("oauth_state", state);

// コールバック受信時: state を照合
const receivedState = new URLSearchParams(location.search).get("state");
const savedState = sessionStorage.getItem("oauth_state");
if (receivedState !== savedState) {
  throw new Error("State mismatch — possible CSRF attack");
}
sessionStorage.removeItem("oauth_state"); // 使用後は削除`,
      },
      {
        lang: "typescript",
        label: "Vulnerable pattern (do not use)",
        code: `// state を省略して認可リクエストを送信 — 危険
const authUrl = \`/api/oauth/authorize?client_id=demo-app&redirect_uri=\${redirectUri}&scope=read\`;
// コールバックで state を検証しない — CSRF 成立`,
      },
    ],
    existingFileLinks: [
      {
        path: "server/routes/oauth-sim.ts",
        description:
          "POST /api/oauth/attack/state-csrf — 両モード並列実行で state 検証の有無を比較",
      },
    ],
    modes: [
      {
        id: "no-state",
        labelJa: "state なし (脆弱)",
        label: "Without state (vulnerable)",
        kind: "vulnerable",
      },
      {
        id: "with-state",
        labelJa: "state あり (防御)",
        label: "With state (defended)",
        kind: "defensive",
      },
    ],
  },
  {
    id: "oauth-redirect-uri-bypass",
    tabId: "oauth",
    name: "redirect_uri Validation Bypass",
    nameJa: "redirect_uri 検証バイパス",
    category: "Authorization / Open Redirect",
    cweId: "CWE-601",
    capecId: "CAPEC-194",
    difficulty: 3,
    osiLayer: 7,
    severity: "high",
    description:
      "This is a proof-of-concept for CWE-601 / CAPEC-194. When the authorization server validates redirect_uri using prefix matching (startsWith) or an unescaped-dot regex instead of exact string equality, an attacker can register a URI that passes validation but redirects to an attacker-controlled server.",
    descriptionJa:
      "これは CWE-601 / CAPEC-194 の概念実証です。認可サーバーが redirect_uri を完全一致ではなく前方一致 (startsWith) やドットエスケープ漏れ正規表現で検証している場合、攻撃者は検証を通過しつつ攻撃者制御のサーバーにリダイレクトする URI を利用できます。",
    mitigation:
      "Always validate redirect_uri against the registered list using exact string equality (registeredUris.includes(redirectUri)). Never use prefix matching or regex without proper escaping. Require pre-registration of all redirect URIs.",
    mitigationJa:
      "redirect_uri の検証は必ず登録済みリストとの完全一致 (registeredUris.includes(redirectUri)) で行ってください。前方一致や適切にエスケープされていない正規表現は使わないでください。すべての redirect_uri を事前登録必須にしてください。",
    references: [
      "https://tools.ietf.org/html/rfc6749#section-3.1.2",
      "https://tools.ietf.org/html/rfc6819#section-5.2.3.5",
      "https://cwe.mitre.org/data/definitions/601.html",
    ],
    codeHints: [
      {
        lang: "typescript",
        label: "Safe: exact-match validation (oauth-sim.ts の実装)",
        code: `// 安全な実装: 完全一致 (oauth-sim.ts の既存実装)
const isValid = registeredUris.includes(redirectUri); // OK

// 脆弱な実装 (前方一致) — 使わない
const isVuln1 = registeredUris.some(r => redirectUri.startsWith(r)); // NG

// 脆弱な実装 (ドットエスケープ漏れ) — 使わない
const isVuln2 = /^http:\\/\\/localhost:3000\\/auth\\/oauth\\/callback/.test(redirectUri); // NG`,
      },
    ],
    existingFileLinks: [
      {
        path: "server/routes/oauth-sim.ts",
        description:
          "GET /api/oauth/authorize が registeredUris.includes(redirectUri) で完全一致検証を実装 (堅牢実装)",
      },
      {
        path: "server/routes/oauth-sim.ts",
        description:
          "POST /api/oauth/attack/redirect-uri-bypass — prefix / regex_bad / exact の 3 パターンを 1 リクエストで比較",
      },
    ],
    modes: [
      {
        id: "prefix-regex",
        labelJa: "前方一致 / 誤正規表現 (脆弱)",
        label: "Prefix / bad regex (vulnerable)",
        kind: "vulnerable",
      },
      {
        id: "exact",
        labelJa: "完全一致 (防御)",
        label: "Exact match (defended)",
        kind: "defensive",
      },
    ],
  },
  {
    id: "oauth-code-via-referer",
    tabId: "oauth",
    name: "Authorization Code Interception (Referer Leak)",
    nameJa: "認可コード傍受 (Referer 漏洩)",
    category: "Authorization / Information Exposure",
    cweId: "CWE-200",
    capecId: "CAPEC-94",
    difficulty: 2,
    osiLayer: 7,
    severity: "medium",
    description:
      "This is a proof-of-concept for CWE-200 / CWE-598 / CAPEC-94. The OAuth authorization code is passed as a query parameter in the callback URL. If the callback page loads external resources, the browser sends the full URL (including the code) as the Referer header to those servers. Without PKCE, an intercepted code can be exchanged for an access token.",
    descriptionJa:
      "これは CWE-200 / CWE-598 / CAPEC-94 の概念実証です。OAuth 認可コードはコールバック URL のクエリパラメータとして渡されます。コールバックページが外部リソースを読み込む場合、ブラウザは認可コードを含む完全な URL を Referer ヘッダとして送信します。PKCE なしでは、傍受されたコードがトークン交換に悪用される可能性があります。",
    mitigation:
      "Use PKCE (RFC 7636) for all public clients (SPAs, mobile apps). Set Referrer-Policy: no-referrer on the callback page. Move the authorization code to a fragment (#) where possible.",
    mitigationJa:
      "すべての公開クライアント (SPA、モバイルアプリ) で PKCE (RFC 7636) を使用してください。コールバックページに Referrer-Policy: no-referrer ヘッダを設定してください。可能であれば認可コードをフラグメント (#) で渡すようにしてください。",
    references: [
      "https://tools.ietf.org/html/rfc7636",
      "https://cwe.mitre.org/data/definitions/200.html",
      "https://cwe.mitre.org/data/definitions/598.html",
    ],
    codeHints: [
      {
        lang: "typescript",
        label: "PKCE implementation (RFC 7636 — recommended)",
        code: `// 1. 認可リクエスト前: code_verifier と code_challenge を生成
const codeVerifier = btoa(String.fromCharCode(
  ...crypto.getRandomValues(new Uint8Array(32))
)).replace(/[+/=]/g, (c) => ({"+": "-", "/": "_", "=": ""})[c]!);

const codeChallenge = btoa(String.fromCharCode(
  ...new Uint8Array(await crypto.subtle.digest(
    "SHA-256", new TextEncoder().encode(codeVerifier)
  ))
)).replace(/[+/=]/g, (c) => ({"+": "-", "/": "_", "=": ""})[c]!);

// 2. 認可リクエストに code_challenge を付与
const authUrl = \`/api/oauth/authorize?...&code_challenge=\${codeChallenge}&code_challenge_method=S256\`;

// 3. トークン交換時に code_verifier を送信
fetch("/api/oauth/token", { body: JSON.stringify({ code, code_verifier: codeVerifier }) });`,
      },
    ],
    existingFileLinks: [
      {
        path: "server/routes/oauth-sim.ts",
        description:
          "POST /api/oauth/attack/code-via-referer — Referer 漏洩シミュレーション + PKCE 防御比較",
      },
    ],
    modes: [
      {
        id: "no-pkce",
        labelJa: "PKCE なし (脆弱)",
        label: "Without PKCE (vulnerable)",
        kind: "vulnerable",
      },
      {
        id: "with-pkce",
        labelJa: "PKCE あり (防御)",
        label: "With PKCE (defended)",
        kind: "defensive",
      },
    ],
  },
];
