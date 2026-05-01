import type { AttackScenarioMeta } from "../../../../../shared/api-types";

/**
 * SSO / API Key 攻撃シナリオメタ (DESIGN/19-attack-sso-apikey.md, Phase 2 第十三コミット)。
 *
 * 全 3 シナリオは E-2 契約 (両モード並列実行) のため outcome="succeeded" 固定。
 * AttackStep 4 (脆弱モード) = status:"success", AttackStep 5 (堅牢モード) = status:"blocked"。
 */
export const ssoApikeyScenarios: AttackScenarioMeta[] = [
  {
    id: "apikey-leakage",
    tabId: "sso-idp-apikey",
    name: "API Key Leakage (via URL Log)",
    nameJa: "API キー漏洩 (ログ・URL 経由)",
    category: "A2:Broken Authentication",
    cweId: "CWE-200",
    capecId: "CAPEC-117",
    difficulty: 2,
    osiLayer: 7,
    severity: "high",
    description:
      "This is a proof-of-concept for CWE-200 (Exposure of Sensitive Information) / CWE-798 (Hard-coded Credentials) / CAPEC-117 (Interception). API keys sent as URL query parameters (?api_key=...) are recorded verbatim in server access logs, proxy logs, browser history, and Referer headers. Once leaked, the key remains exploitable until revoked. The demo simulates an attacker reusing a leaked key, then shows the defended path: header transmission keeps the key out of URL logs, and revocation invalidates leaked keys immediately.",
    descriptionJa:
      "これは CWE-200 (機密情報露出) / CWE-798 (ハードコードされた認証情報) / CAPEC-117 (傍受) の概念実証です。URL クエリパラメータ (?api_key=...) として送信された API キーは、サーバー / プロキシ / CDN / ブラウザ履歴 / Referer ヘッダに完全文字列で記録されます。漏洩したキーは取消されない限り無期限に悪用されます。本デモでは攻撃者が漏洩キーを再利用する経路と、堅牢パスでヘッダ送信 (URL ログ非露出) + 取消エンドポイントによる即時無効化を対比します。",
    mitigation:
      "Always transmit API keys via HTTP headers (Authorization: Bearer ... or X-API-Key: ...) — never in URL query parameters. Provide a revocation endpoint (PATCH /keys/:id/revoke setting revoked_at = NOW) and include `WHERE revoked_at IS NULL` in lookup queries. Add `expires_at` for short-lived keys and rotate them regularly. The existing `sso-apikey.ts:149-161` demonstrates both header and query verification side-by-side; production usage should remove the query variant.",
    mitigationJa:
      "API キーは必ず HTTP ヘッダ (Authorization: Bearer ... または X-API-Key: ...) で送信してください — URL クエリパラメータは使用禁止です。取消エンドポイント (PATCH /keys/:id/revoke で revoked_at = NOW を設定) を提供し、ルックアップクエリには `WHERE revoked_at IS NULL` を含めてください。短命化のため `expires_at` カラムを追加し、定期的なローテーションを運用ポリシーで義務付けてください。既存の sso-apikey.ts:149-161 はヘッダとクエリの 2 経路を並列に教材として提供していますが、本番ではクエリ経路を削除すべきです。",
    references: [
      "https://cwe.mitre.org/data/definitions/200.html",
      "https://cwe.mitre.org/data/definitions/798.html",
      "https://capec.mitre.org/data/definitions/117.html",
      "https://owasp.org/www-project-api-security/",
      "https://datatracker.ietf.org/doc/html/rfc6750",
    ],
    codeHints: [
      {
        lang: "typescript",
        label: "Vulnerable: API key in URL query parameter (do not use)",
        code: `// 脆弱な実装: URL クエリでキーを送信
const res = await fetch(\`/api/resource?api_key=\${apiKey}\`);
// → Web サーバー / プロキシ / CDN / ブラウザ履歴に以下が記録される:
//   GET /api/resource?api_key=sk-XXXXXXXX HTTP/1.1 200
// → Referer ヘッダ経由で外部サイトにも漏洩する可能性`,
      },
      {
        lang: "typescript",
        label: "Defended: header transmission + revocation (sso-apikey.ts pattern)",
        code: `// 推奨: ヘッダ送信 (URL ログに残らない)
const res = await fetch("/api/resource", {
  method: "POST",
  headers: {
    "Authorization": \`Bearer \${apiKey}\`,
    "Content-Type": "application/json",
  },
  body: JSON.stringify(payload),
});

// 取消エンドポイント (revocation)
// ALTER TABLE api_keys ADD COLUMN revoked_at TEXT;
// PATCH /api/keys/:keyId/revoke → UPDATE api_keys SET revoked_at = datetime('now')

// キー検証時に revoked_at を確認
const key = db.prepare(
  "SELECT * FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL AND is_attack_sim = 0"
).get(keyHash);
if (!key) return c.json({ error: "Invalid or revoked API key" }, 401);`,
      },
    ],
    existingFileLinks: [
      {
        path: "server/routes/sso-apikey.ts",
        description:
          "POST /api/sso/apikey/verify/header — ヘッダ送信版 (URL ログ非露出) と GET /verify/query (脆弱) を並列に教材として提供",
      },
      {
        path: "server/routes/sso-apikey.ts",
        description:
          "POST /api/sso/attack/apikey-leakage — クエリ vs ヘッダ送信比較 + 漏洩キー再利用 + 取消による拒否の 5 ステップ並列デモ",
      },
    ],
    modes: [
      {
        id: "query-no-revocation",
        labelJa: "クエリ送信 + 取消なし (脆弱)",
        label: "Query transmission + no revocation (vulnerable)",
        kind: "vulnerable",
      },
      {
        id: "header-with-revocation",
        labelJa: "ヘッダ送信 + 取消あり (防御)",
        label: "Header transmission + revocation (defended)",
        kind: "defensive",
      },
    ],
  },
  {
    id: "apikey-hmac-bypass",
    tabId: "sso-idp-apikey",
    name: "HMAC Bypass (Timing Attack / Short HMAC)",
    nameJa: "HMAC 検証バイパス (タイミング攻撃 / 短い HMAC)",
    category: "A2:Broken Authentication",
    cweId: "CWE-208",
    capecId: "CAPEC-462",
    difficulty: 4,
    osiLayer: 7,
    severity: "high",
    description:
      "This is a proof-of-concept for CWE-208 (Observable Timing Discrepancy) / CWE-326 (Inadequate Encryption Strength) / CAPEC-462 (Cryptanalysis). When HMAC verification uses === for string comparison, the response time grows proportionally to the matching prefix length, leaking information byte-by-byte to a timing attacker. Separately, a short HMAC (4 bytes = 2^32 keyspace) is brute-forceable on commodity GPUs. The defended implementation uses crypto.timingSafeEqual (constant time) and full 32-byte HMAC (2^256 keyspace, computationally infeasible). Response times in this demo are exaggerated server-side simulation values.",
    descriptionJa:
      "これは CWE-208 (観測可能なタイミング差異) / CWE-326 (不十分な暗号強度) / CAPEC-462 (暗号解読) の概念実証です。HMAC 検証で === 演算子による文字列比較を使うと、一致した文字数に比例して比較時間が伸び、攻撃者は1バイトずつ正解を統計的に推定できます。別途、短い HMAC (4 バイト = 鍵空間 2^32) は現代の GPU で総当り可能です。堅牢実装は crypto.timingSafeEqual (定数時間) + 32 バイト HMAC (鍵空間 2^256、計算上不可能) を使用します。本デモの応答時間はサーバー側で誇張したシミュレーション値です。",
    mitigation:
      "Always use crypto.timingSafeEqual for HMAC comparison (Node.js standard API; constant-time XOR-and-accumulate). Use the full HMAC-SHA256 output (32 bytes / 64 hex chars / 256 bits) — never truncate. Reject buffers of mismatched length immediately (length info itself is sensitive). The existing sso-apikey.ts:229-235 implements this pattern correctly: `Buffer.from(expectedSig, 'hex')` + `crypto.timingSafeEqual` with explicit length check.",
    mitigationJa:
      "HMAC 比較には必ず crypto.timingSafeEqual を使用してください (Node.js 標準 API、定数時間 XOR-累積)。HMAC は HMAC-SHA256 の完全な出力 (32 バイト / 64 hex 文字 / 256 ビット) を使用 — 切り詰めは禁止です。バッファ長が一致しない場合は即時 false を返してください (長さ情報自体が機密)。既存の sso-apikey.ts:229-235 はこの規範を実装済みです: Buffer.from(expectedSig, 'hex') + 明示的長さチェック付き crypto.timingSafeEqual。",
    references: [
      "https://cwe.mitre.org/data/definitions/208.html",
      "https://cwe.mitre.org/data/definitions/326.html",
      "https://capec.mitre.org/data/definitions/462.html",
      "https://nodejs.org/api/crypto.html#cryptotimingsafeequala-b",
      "https://en.wikipedia.org/wiki/Timing_attack",
    ],
    codeHints: [
      {
        lang: "typescript",
        label: "Vulnerable: === comparison + 4-byte HMAC (do not use)",
        code: `// 脆弱な実装 A: === 比較 (短絡評価でタイミング漏洩)
const vulnerableCompare = (a: string, b: string): boolean => a === b;

// 脆弱な実装 B: HMAC を切り詰める (鍵空間 2^32 → 総当り可能)
const shortHmac = crypto
  .createHmac("sha256", secret)
  .update(canonical)
  .digest("hex")
  .substring(0, 8); // 先頭 8 文字 = 4 バイト = 2^32 鍵空間

// 攻撃者は (a) タイミング情報から正解プレフィックスを 1 バイトずつ推定、
// (b) 4 バイト HMAC の鍵空間を GPU で総当り、いずれかで突破可能`,
      },
      {
        lang: "typescript",
        label: "Defended: timingSafeEqual + 32-byte HMAC (sso-apikey.ts:229-235)",
        code: `import crypto from "crypto";

// 安全な実装 (現行 sso-apikey.ts の実装):
const expectedSig = crypto
  .createHmac("sha256", secret)
  .update(canonical)
  .digest("hex"); // 64 文字 hex = 32 バイト = 2^256 鍵空間 (切り詰めない)

const expectedBuf = Buffer.from(expectedSig, "hex");
const providedBuf = signature ? Buffer.from(signature, "hex") : Buffer.alloc(0);

// 長さ不一致は即時 false (長さ情報を漏洩しない)
const valid =
  providedBuf.length === expectedBuf.length
    ? crypto.timingSafeEqual(expectedBuf, providedBuf)  // ← 定数時間比較
    : false;`,
      },
    ],
    existingFileLinks: [
      {
        path: "server/routes/sso-apikey.ts",
        description:
          "POST /api/sso/apikey/verify/hmac:229-235 — crypto.timingSafeEqual + 32 バイト HMAC で定数時間比較を実装する堅牢実装の参照点",
      },
      {
        path: "server/routes/sso-apikey.ts",
        description:
          "POST /api/sso/attack/hmac-bypass — === vs timingSafeEqual の応答時間差 + 4 バイト vs 32 バイト HMAC の鍵空間比較を 5 ステップ並列で示す",
      },
    ],
    modes: [
      {
        id: "string-equal-short-hmac",
        labelJa: "=== + 4 バイト HMAC (脆弱)",
        label: "=== + 4-byte HMAC (vulnerable)",
        kind: "vulnerable",
      },
      {
        id: "timing-safe-full-hmac",
        labelJa: "timingSafeEqual + 32 バイト HMAC (防御)",
        label: "timingSafeEqual + 32-byte HMAC (defended)",
        kind: "defensive",
      },
    ],
  },
  {
    id: "apikey-replay-no-timestamp",
    tabId: "sso-idp-apikey",
    name: "Replay Without Timestamp",
    nameJa: "タイムスタンプなしリプレイ",
    category: "A7:Identification and Authentication Failures",
    cweId: "CWE-294",
    capecId: "CAPEC-60",
    difficulty: 2,
    osiLayer: 7,
    severity: "medium",
    description:
      "This is a proof-of-concept for CWE-294 (Authentication Bypass by Capture-replay) / CAPEC-60 (Reusing Session IDs). When the HMAC canonical string contains only the body (no timestamp), an attacker who intercepts a single valid request can replay it indefinitely — the same body produces the same canonical, hence the same signature. The defended implementation includes timestamp in the canonical string and validates ±5min skew (sso-apikey.ts:189-207); a nonce uniqueness cache (handler-local Set, FIDO2 / OIDC-SAML pattern) blocks in-window replays. Real-world replay typically requires HTTPS interception (MITM); this demo assumes HTTP or post-key-leak scenarios.",
    descriptionJa:
      "これは CWE-294 (録音再生による認証バイパス) / CAPEC-60 (セッション ID 再利用) の概念実証です。HMAC canonical 文字列にタイムスタンプを含まない場合、攻撃者が1度傍受した正当なリクエストを無期限に再送可能です — 同じボディが同じ canonical を生成し、結果として同じ署名が得られます。堅牢実装は canonical にタイムスタンプを含めて ±5 分 skew を検査 (sso-apikey.ts:189-207) し、nonce 一意性キャッシュ (handler-local Set、FIDO2 / OIDC-SAML 同パターン) で窓内リプレイも阻止します。実環境のリプレイには HTTPS 通信の傍受 (MITM) が必要 — 本デモは HTTP または鍵漏洩後の状況を想定しています。",
    mitigation:
      "Include timestamp (and ideally a nonce) in the HMAC canonical string. Validate timestamp skew (±5 minutes is standard, accommodating NTP drift) at sso-apikey.ts:189-207. Add a nonce uniqueness cache (handler-local Set or DB table with TTL cleanup) to block in-window replays. The DESIGN/19 §4.3 nonce DB option (used_nonces table with auto-cleanup of >5min entries) is a more durable alternative for distributed deployments.",
    mitigationJa:
      "HMAC canonical 文字列にタイムスタンプ (理想的には nonce も) を含めてください。タイムスタンプ skew は ±5 分 (NTP ずれを許容する標準値) で検査します (sso-apikey.ts:189-207)。窓内リプレイを阻止するため nonce 一意性キャッシュ (handler-local Set または TTL クリーンアップ付き DB テーブル) を追加してください。分散デプロイ向けには DESIGN/19 §4.3 の nonce DB 案 (used_nonces テーブル + 5 分超過自動削除) が永続性のある代替策です。",
    references: [
      "https://cwe.mitre.org/data/definitions/294.html",
      "https://capec.mitre.org/data/definitions/60.html",
      "https://datatracker.ietf.org/doc/html/rfc7616",
      "https://owasp.org/www-community/attacks/Replay_attack",
    ],
    codeHints: [
      {
        lang: "typescript",
        label: "Vulnerable: canonical = body only (do not use)",
        code: `// 脆弱な実装: timestamp なしで HMAC のみ検証
function vulnerableHmacVerify(body: object, signature: string, keyHash: string): boolean {
  // canonical に timestamp を含まない → リプレイ可能
  const canonical = JSON.stringify(body);
  const expected = crypto.createHmac("sha256", keyHash).update(canonical).digest("hex");
  return crypto.timingSafeEqual(
    Buffer.from(expected, "hex"),
    Buffer.from(signature, "hex"),
  );
  // ↑ signature が body のみに依存するため、攻撃者は 1 度傍受すれば無期限に再送可能
}`,
      },
      {
        lang: "typescript",
        label: "Defended: timestamp + nonce in canonical (sso-apikey.ts:208 + extension)",
        code: `// 防御実装 (現行 sso-apikey.ts:208 の設計): タイムスタンプ込み canonical
const canonical = \`\${timestamp}\\n\${JSON.stringify(body)}\`;
// → 元のタイムスタンプを使う必要があり、5 分で期限切れ

// 強化版: nonce DB チェック追加
const usedNonceRow = db.prepare(
  "SELECT 1 FROM used_nonces WHERE nonce = ? AND created_at > datetime('now', '-5 minutes')"
).get(nonce);
if (usedNonceRow) {
  return c.json({ error: "Nonce already used within the time window" }, 401);
}
db.prepare(
  "INSERT INTO used_nonces (nonce, created_at) VALUES (?, datetime('now'))"
).run(nonce);

// nonce を canonical に含めることで更に強化
const canonicalWithNonce = \`\${timestamp}\\n\${nonce}\\n\${JSON.stringify(body)}\`;`,
      },
    ],
    existingFileLinks: [
      {
        path: "server/routes/sso-apikey.ts",
        description:
          "POST /api/sso/apikey/verify/hmac:189-207 — タイムスタンプ ±5 分 skew 検査の堅牢実装 + sso-apikey.ts:208 — canonical = `${timestamp}\\n${body}` 形式",
      },
      {
        path: "server/routes/sso-apikey.ts",
        description:
          "POST /api/sso/attack/replay-no-timestamp — timestamp なし canonical のリプレイ成立 vs ±5 分窓 + nonce 一意性検査による拒否を 5 ステップ並列で示す",
      },
    ],
    modes: [
      {
        id: "no-timestamp-no-nonce",
        labelJa: "timestamp / nonce なし (脆弱)",
        label: "No timestamp / no nonce (vulnerable)",
        kind: "vulnerable",
      },
      {
        id: "timestamp-skew-and-nonce",
        labelJa: "±5 分 skew + nonce 一意性検査 (防御)",
        label: "±5min skew + nonce uniqueness (defended)",
        kind: "defensive",
      },
    ],
  },
];
