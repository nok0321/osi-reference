import type { AttackScenarioMeta } from "../../../../../shared/api-types";

export const jwtScenarios: AttackScenarioMeta[] = [
  {
    id: "jwt-alg-none",
    tabId: "jwt",
    name: "Algorithm None Attack",
    nameJa: "alg=none 攻撃",
    category: "Authentication / Token Forgery",
    cweId: "CWE-345",
    capecId: "CAPEC-196",
    difficulty: 2,
    osiLayer: 7,
    severity: "critical",
    description: "This is a proof-of-concept for CWE-345 / CAPEC-196. Rewriting the alg field to 'none' bypasses signature verification when the algorithms allowlist is omitted.",
    descriptionJa: "これは CWE-345 / CAPEC-196 の概念実証です。alg フィールドを none に書き換えることで、algorithms 許可リストが省略された JWT 検証を突破するシナリオです。",
    mitigation: "Always pass the algorithms allowlist to jwt.verify(). Never accept alg=none for authentication tokens. Keep your JWT library updated.",
    mitigationJa: "jwt.verify() には必ず algorithms 許可リストを渡してください。認証トークンで alg=none を受理してはいけません。JWT ライブラリは常に最新版を使用してください。",
    references: [
      "https://tools.ietf.org/html/rfc7519",
      "https://tools.ietf.org/html/rfc7518#section-3.6",
      "https://cwe.mitre.org/data/definitions/345.html",
    ],
    codeHints: [
      {
        lang: "typescript",
        label: "Strict verification (recommended)",
        code: `// 必ず algorithms 許可リストを指定する
const decoded = jwt.verify(token, secret, {
  algorithms: ["HS256", "RS256"]  // alg=none を拒否
});`,
      },
      {
        lang: "typescript",
        label: "Vulnerable pattern (do not use)",
        code: `// algorithms 省略 → alg=none を許容するライブラリ実装で脆弱
const decoded = jwt.verify(token, secret);  // 危険`,
      },
    ],
    existingFileLinks: [
      { path: "server/routes/jwt-ops.ts", description: "POST /api/jwt/verify が algorithms allowlist を明示指定 (堅牢実装)" },
    ],
    modes: [
      {
        id: "lenient",
        labelJa: "脆弱検証 (algorithms 省略)",
        label: "Lenient verifier (algorithms omitted)",
        body: { victim: { algorithm: "HS256", strict: false } },
        kind: "vulnerable",
      },
      {
        id: "strict",
        labelJa: "堅牢検証 (algorithms 許可リスト)",
        label: "Strict verifier (algorithms allowlist)",
        body: { victim: { algorithm: "HS256", strict: true } },
        kind: "defensive",
      },
    ],
  },
  {
    id: "jwt-weak-secret-bruteforce",
    tabId: "jwt",
    name: "HS256 Weak Secret Brute Force",
    nameJa: "HS256 弱秘密鍵ブルートフォース",
    category: "Authentication / Key Recovery",
    cweId: "CWE-326",
    capecId: "CAPEC-49",
    difficulty: 2,
    osiLayer: 7,
    severity: "high",
    description: "This is a proof-of-concept for CWE-326 / CAPEC-49. HS256 secrets can be recovered offline by iterating over common passwords and comparing HMAC outputs. A weak secret like 'secret' can be found in a single attempt.",
    descriptionJa: "これは CWE-326 / CAPEC-49 の概念実証です。HS256 の秘密鍵はオフラインで辞書を順次試行して HMAC 出力を比較することで回復できます。'secret' のような弱い秘密鍵は 1 回の試行で発見されます。",
    mitigation: "Use a minimum 256-bit (32-byte) cryptographically random secret. Generate with crypto.randomBytes(32).toString('hex'). Never use dictionary words or short strings. Consider migrating to RS256 / ES256.",
    mitigationJa: "秘密鍵は最低 256 ビット以上のランダム値を使用してください。crypto.randomBytes(32).toString('hex') 等で生成し、辞書語や短い文字列を使ってはいけません。RS256 / ES256 への移行も検討してください。",
    references: [
      "https://tools.ietf.org/html/rfc7518#section-3.2",
      "https://cwe.mitre.org/data/definitions/326.html",
      "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
    ],
    codeHints: [
      {
        lang: "typescript",
        label: "Generate a strong secret",
        code: `import crypto from "crypto";
// 256 ビット (32 バイト) のランダム秘密鍵を生成
const secret = crypto.randomBytes(32).toString("hex");
// 例: "a3f1c9e2b4d6..." (64 文字の hex 文字列)`,
      },
      {
        lang: "typescript",
        label: "Vulnerable pattern (do not use)",
        code: `// 辞書語や短い文字列は絶対に使わない
const secret = "secret";      // 危険: 辞書の 1 件目で発見される
const secret2 = "mysecret";   // 危険: 辞書に含まれる可能性が高い`,
      },
    ],
    existingFileLinks: [
      { path: "server/routes/jwt-ops.ts", description: "HS256_SECRET が 38 文字のランダム文字列 (相対的に強い実装)" },
    ],
    modes: [
      {
        id: "weak",
        labelJa: '弱秘密鍵 ("secret")',
        label: 'Weak secret ("secret")',
        body: { secretType: "weak", dictionarySize: 100 },
        kind: "vulnerable",
      },
      {
        id: "strong",
        labelJa: "強秘密鍵 (38 文字ランダム)",
        label: "Strong secret (38-char random)",
        body: { secretType: "strong", dictionarySize: 100 },
        kind: "defensive",
      },
    ],
  },
  {
    id: "jwt-signature-stripping",
    tabId: "jwt",
    name: "Signature Stripping Attack",
    nameJa: "署名ストリッピング攻撃",
    category: "Authentication / Signature Bypass",
    cweId: "CWE-347",
    capecId: "CAPEC-196",
    difficulty: 1,
    osiLayer: 7,
    severity: "critical",
    description: "This is a proof-of-concept for CWE-347 / CAPEC-196. Using jwt.decode() instead of jwt.verify() skips signature validation entirely, allowing any crafted payload to be accepted as legitimate.",
    descriptionJa: "これは CWE-347 / CAPEC-196 の概念実証です。jwt.verify() の代わりに jwt.decode() を使用すると署名検証が完全にスキップされ、任意のペイロードが正当なものとして受理されます。",
    mitigation: "Always use jwt.verify() for authentication. Never use jwt.decode() to make access control decisions. jwt.decode() should only be used for logging or debugging purposes.",
    mitigationJa: "常に jwt.verify() を使ってください。jwt.decode() は署名を検証しないため認証に使ってはいけません。decode() の用途はロギング・デバッグに限定してください。",
    references: [
      "https://tools.ietf.org/html/rfc7519#section-7.2",
      "https://cwe.mitre.org/data/definitions/347.html",
      "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
    ],
    codeHints: [
      {
        lang: "typescript",
        label: "Correct: verify before trusting payload",
        code: `// 認証には必ず verify() を使う
try {
  const decoded = jwt.verify(token, secret, {
    algorithms: ["HS256"]
  });
  // decoded は検証済み
} catch (err) {
  // 無効なトークン
}`,
      },
      {
        lang: "typescript",
        label: "Vulnerable pattern (do not use)",
        code: `// decode() は署名を検証しない
// 任意のペイロードが受理されてしまう
const decoded = jwt.decode(token);  // 危険: 認証に使ってはいけない
if (decoded?.role === "admin") { /* ... */ }`,
      },
    ],
    existingFileLinks: [
      { path: "server/routes/jwt-ops.ts", description: "POST /api/jwt/decode が警告付きで decode-only を提供 (教育用)" },
    ],
    modes: [
      {
        id: "decode-only",
        labelJa: "decode-only エンドポイント",
        label: "decode-only endpoint",
        body: { mode: "decode-only" },
        kind: "vulnerable",
      },
      {
        id: "verify",
        labelJa: "verify エンドポイント",
        label: "verify endpoint",
        body: { mode: "verify" },
        kind: "defensive",
      },
    ],
  },
  {
    id: "jwt-kid-injection",
    tabId: "jwt",
    name: "kid Header Injection",
    nameJa: "kid ヘッダインジェクション",
    category: "Authentication / Path Traversal",
    cweId: "CWE-22",
    capecId: "CAPEC-88",
    difficulty: 3,
    osiLayer: 7,
    severity: "high",
    description: "This is a proof-of-concept for CWE-22 / CAPEC-88. The JWT kid (Key ID) header value is used unsanitized as a key file path. An attacker can inject a path traversal string to make the server use an attacker-controlled key for verification.",
    descriptionJa: "これは CWE-22 / CAPEC-88 の概念実証です。JWT の kid (Key ID) ヘッダ値がサニタイズされずに鍵ファイルパスとして使用されます。攻撃者はパストラバーサル文字列を注入してサーバーに攻撃者制御の鍵を使用させることができます。",
    mitigation: "Always validate the kid header value against an allowlist before using it to resolve a key. Never concatenate kid directly into file paths or SQL queries. Treat kid as an opaque identifier and resolve keys only through a trusted map.",
    mitigationJa: "kid ヘッダの値は許可リスト検証してください。kid を直接ファイルパスや SQL クエリに連結してはいけません。kid を不透明な識別子として扱い、信頼できるマップ経由でのみ鍵を解決してください。",
    references: [
      "https://portswigger.net/web-security/jwt/algorithm-confusion",
      "https://cwe.mitre.org/data/definitions/22.html",
      "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
    ],
    codeHints: [
      {
        lang: "typescript",
        label: "Safe: allowlist-based key resolution",
        code: `const KEY_MAP: Record<string, string> = {
  "key-1": process.env.PUBLIC_KEY_1!,
  "key-2": process.env.PUBLIC_KEY_2!,
};

function resolveKey(kid: string): string {
  const key = KEY_MAP[kid];  // 許可リストのみ
  if (!key) throw new Error("Unknown kid");
  return key;
}`,
      },
      {
        lang: "typescript",
        label: "Vulnerable pattern (do not use)",
        code: `// kid を直接ファイルパスに連結 — 危険
const key = fs.readFileSync(\`/keys/\${kid}.pem\`);
// kid="../etc/passwd" などのパストラバーサルが可能`,
      },
    ],
    existingFileLinks: [
      { path: "server/routes/jwt-ops.ts", description: "攻撃シミュレーション: 実ファイル読み込みなし、kid 解決はシミュレーションのみ" },
    ],
    modes: [
      {
        id: "vulnerable",
        labelJa: "脆弱実装 (kid 直接使用)",
        label: "Vulnerable (kid used directly)",
        body: { injectedKid: "../public/attacker-key.pem", mode: "vulnerable" },
        kind: "vulnerable",
      },
      {
        id: "allowlist",
        labelJa: "許可リスト実装",
        label: "Allowlist implementation",
        body: { injectedKid: "../public/attacker-key.pem", mode: "allowlist" },
        kind: "defensive",
      },
    ],
  },
];
