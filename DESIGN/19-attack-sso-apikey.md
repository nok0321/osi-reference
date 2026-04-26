---
title: 攻撃デモカタログ — SSO / API Key 攻撃詳細
phase: design
tab-id: sso-idp-apikey
safety-reviewed: false
last-updated: 2026-04-26
---

## 教育目的

本ファイルは **教育用シミュレーション** の実装設計である。
記載された攻撃手法は `localhost` 上の固定シードデータに対してのみ動作するよう設計されており、
実環境への攻撃を意図したものではない。

攻撃シミュレーションはすべて「この防御がなぜ必要か」を体感するための概念実証であり、
各シナリオには必ず防御策の解説と実装例が対になっている。

---

# 19. SSO / API Key 攻撃カタログ

## 1. 概要

「SSO / API Key (sso-idp-apikey)」タブは、SSO セッション伝播と API キー生成・HMAC 検証を
正常系で学ぶ既存の Defender View を持つ。このカタログは同タブに **Attacker View** を追加し、
API キーと HMAC 署名の設計上の欠陥が攻撃者にどのように悪用されるかを体感的に理解させる。

### 1.1 防御側既存実装の参照

| ファイル | 役割 |
|---------|------|
| `server/routes/sso-apikey.ts` | `POST /api/sso/apikey/generate` (32 バイト乱数キー生成・SHA-256 ハッシュ格納)、`POST /api/sso/apikey/verify/header` と `GET /api/sso/apikey/verify/query` (ヘッダ vs クエリ送信)、`POST /api/sso/apikey/verify/hmac` (タイムスタンプ skew ±5 分 + `crypto.timingSafeEqual`) を実装 |
| `src/components/auth/SsoPatterns.tsx` | `ApiKeyDemo` コンポーネント。ヘッダ/クエリ切替送信 + `DataFlowPanel` による HTTP/Trace 可視化 |
| `server/db/schema.ts` | `api_keys` テーブル: `key_id`, `key_prefix`, `key_hash` (SHA-256), `name`, `created_at`, `last_used` |

### 1.2 攻撃デモの追加方針

既存の `SsoPatterns.tsx` に `ViewModeToggle` を追加し、Attacker View として
`SsoApikeyAttackPanel` コンポーネントを条件表示する。
攻撃 API は既存の `server/routes/sso-apikey.ts` にサブパス `/attack/*` として追加する
(DESIGN/01-architecture.md §2.1 のルート配置方針に準拠)。

---

## 2. 攻撃シナリオ一覧

| # | シナリオ ID | 攻撃名 | CWE | CAPEC | OSI 層 | 深刻度 |
|---|------------|--------|-----|-------|--------|-------|
| A | `apikey-leakage` | API キー漏洩 (URL クエリ・ログ経由) | CWE-200, CWE-798 | CAPEC-117 | L7 (Application) | High |
| B | `apikey-hmac-bypass` | HMAC 検証バイパス (タイミング攻撃 / 短い HMAC) | CWE-208, CWE-326 | CAPEC-462 | L7 (Application) | High |
| C | `apikey-replay-no-timestamp` | タイムスタンプなしリプレイ | CWE-294 | CAPEC-60 | L7 (Application) | Medium |

---

## 3. 既存防御側実装

### 3.1 `server/routes/sso-apikey.ts` の構造

```
ssoApikeyRoutes
├── POST /apikey/generate
│   ├── crypto.randomBytes(32).toString("base64url")  ← 32 バイト (256 ビット) 乱数キー生成
│   ├── rawKey.substring(0, 8)                        ← prefix (ログ・UI 表示用)
│   ├── crypto.createHash("sha256").update(rawKey)    ← SHA-256 ハッシュ生成
│   └── INSERT INTO api_keys (key_hash のみ格納)       ← 生のキーはサーバー非保持
├── POST /apikey/verify/header
│   ├── c.req.header("X-API-Key")                     ← リクエストヘッダから取得
│   └── verifyApiKey()                                ← ハッシュ照合
├── GET /apikey/verify/query
│   ├── c.req.query("api_key")                        ← URL クエリから取得
│   └── verifyApiKey()                                ← ヘッダと同一ロジック
└── POST /apikey/verify/hmac
    ├── parseTimestamp(timestamp)                     ← ISO-8601 / エポック秒/ms を解釈
    ├── skew = |now - ts| > 5min → 401               ← タイムスタンプ skew チェック
    ├── canonical = `${timestamp}\n${JSON.stringify(body)}`
    ├── HMAC-SHA256(secret=key_hash, data=canonical)  ← 期待署名を計算
    └── crypto.timingSafeEqual(expected, provided)    ← 定数時間比較
```

`trace.addCryptoOp()` により、`generateApiKey` / `hashApiKey` / `hashProvidedKey` /
`timestampSkewCheck` / `HMAC-SHA256` / `compareSignatures` の操作詳細が
`_trace.cryptoOps` に記録され `DataFlowPanel` の Trace タブで可視化される。

### 3.2 `server/db/schema.ts` の api_keys テーブル

```sql
CREATE TABLE IF NOT EXISTS api_keys (
  key_id     TEXT PRIMARY KEY,          -- "key_xxxxxxxx" 形式の識別子
  key_prefix TEXT NOT NULL,             -- 生キーの先頭 8 文字 (UI 表示用)
  key_hash   TEXT NOT NULL,             -- SHA-256 ハッシュ (サーバーはハッシュのみ保持)
  name       TEXT NOT NULL DEFAULT 'default',
  created_at TEXT DEFAULT (datetime('now')),
  last_used  TEXT
);
```

`key_hash` は SHA-256 (64 文字 hex) で格納される。
生の API キーはサーバー側に保持されないため、生成時に一度だけクライアントに返す設計。
攻撃シミュレーション用レコードには `is_attack_sim` フラグカラムを追加し、
正常系クエリから除外する (DESIGN/04-safety-guardrails.md §5.3 に準拠)。

### 3.3 既存実装の防御上の強み

| 防御要素 | 実装箇所 | 効果 |
|---------|---------|------|
| 32 バイト乱数キー生成 | `crypto.randomBytes(32)` | 総当りが計算上不可能な鍵空間 (2^256) を確保 |
| ハッシュのみ格納 | `SHA-256(rawKey)` を DB 保存 | DB 漏洩時に生キーが露出しない |
| タイムスタンプ skew ±5 分 | `sso-apikey.ts:200` | 録音再生攻撃 (リプレイ) を 5 分以内の時間窓に限定 |
| `crypto.timingSafeEqual` | `sso-apikey.ts:231` | HMAC 比較でのタイミング攻撃を防止 |

### 3.4 既存実装の改善余地

| 項目 | 現状 | 改善案 |
|------|------|--------|
| URL クエリ送信 | `/apikey/verify/query?api_key=...` が存在 | クエリ送信はアクセスログ漏洩リスクがある。ヘッダ送信のみに制限を検討 |
| nonce 管理 | 未実装 | timestamp + nonce の組み合わせで同一時間窓内のリプレイを防止 |
| キーローテーション | 未実装 | 定期的な key_id の再発行と旧キーの失効ルートの提供 |
| キー有効期限 | 未実装 | `expires_at` カラム追加と期限切れキーの自動拒否 |

---

## 4. シナリオ詳細

---

### 4.1 `apikey-leakage`

#### 概要

これは **CWE-200 / CWE-798 / CAPEC-117** の概念実証である。
API キーが URL クエリパラメータ (`?api_key=...`) として送信されると、
Webサーバーのアクセスログ・プロキシログ・ブラウザ履歴・Referer ヘッダに
キー文字列がそのまま記録される。
また、API キーが設定ファイルやソースコードにハードコードされた場合、
Git 公開リポジトリへのコミットにより漏洩する。
漏洩したキーは取消 (revocation) されない限り半永久的に悪用され続ける。

本デモでは「ヘッダ送信」と「クエリ送信」の比較を行い、
サーバーアクセスログへの記録差を視覚的に示す。
また「キーの即時取消」操作と「取消後の同一キーによるアクセス拒否」を体感させる。

**実環境との差異の注記 (必須)**:
実環境のログはシステム管理者・ログ解析基盤・CDN プロバイダが閲覧可能であり、
複数ホップ先でも記録される。このデモはローカルサーバーのインメモリログのみを対象とする。

#### CWE / CAPEC / OSI 層

| 項目 | 値 |
|------|-----|
| CWE | CWE-200 (Exposure of Sensitive Information), CWE-798 (Hard-coded Credentials) |
| CAPEC | CAPEC-117 (Interception) |
| OSI 層 | Layer 7 — Application |
| 深刻度 | High |

#### 前提条件 (脆弱な状況)

攻撃者は以下の条件を満たしている:

1. ターゲット API のクライアントコードまたは通信ログへのアクセスを取得済み
   (Git 公開リポジトリ・アクセスログ・プロキシログなど)
2. API キーが URL クエリパラメータで送信されており、ログに平文で記録されている
3. 取得したキーが取消されていない

**脆弱な送信例** (このシナリオでシミュレーションする実装):

```typescript
// 脆弱な例 (教育用シミュレーション専用 — 実際には使用しない)
// URL クエリでキーを送信: GET /api/resource?api_key=sk-XXXXXXXX
const res = await fetch(`/api/resource?api_key=${apiKey}`);
// → Webサーバーアクセスログに以下が記録される:
//   GET /api/resource?api_key=sk-XXXXXXXX HTTP/1.1 200
// → プロキシ・CDN・ロードバランサ全段のログにも同様に記録される
```

#### 攻撃ステップ (AttackStep[] の具体例)

```typescript
const steps: AttackStep[] = [
  {
    id: "step-1",
    kind: "intercept",
    label: "Observe API key in server access log (query parameter)",
    labelJa: "サーバーアクセスログでクエリパラメータの API キーを観測",
    status: "success",
    payload: {
      type: "http",
      request: {
        method: "GET",
        url: "/api/sso/apikey/verify/query?api_key=SEED_APIKEY_VALUE",
        body: null,
      },
      response: {
        status: 200,
        body: { success: true, data: { valid: true, method: "Query Parameter (?api_key=...)" } },
      },
    },
    detail: "The API key appears verbatim in the URL. Server access logs record the full URL including the key.",
    detailJa: "API キーが URL にそのまま含まれます。サーバーアクセスログにはキー文字列を含む URL が完全に記録されます。",
    timestamp: Date.now(),
  },
  {
    id: "step-2",
    kind: "probe",
    label: "Compare: API key in header is NOT recorded in URL log",
    labelJa: "比較: ヘッダ送信のキーは URL ログに記録されない",
    status: "blocked",
    payload: {
      type: "http",
      request: {
        method: "POST",
        url: "/api/sso/apikey/verify/header",
        headers: { "X-API-Key": "SEED_APIKEY_VALUE" },
        body: {},
      },
      response: {
        status: 200,
        body: { success: true, data: { valid: true, method: "Header (X-API-Key)" } },
      },
    },
    detail: "Header-based API key is not recorded in the URL access log. The key value is hidden from proxy/CDN logs.",
    detailJa: "ヘッダ送信の API キーは URL アクセスログに記録されません。プロキシ/CDN のログにキー値が残りません。",
    timestamp: Date.now(),
  },
  {
    id: "step-3",
    kind: "exploit",
    label: "Re-use leaked key to access protected resource",
    labelJa: "漏洩したキーを再利用して保護リソースにアクセス",
    status: "success",
    payload: {
      type: "http",
      request: {
        method: "GET",
        url: "/api/sso/apikey/verify/query?api_key=SEED_APIKEY_VALUE",
        body: null,
      },
      response: {
        status: 200,
        body: { success: true, data: { valid: true, keyId: "key_seed0001", name: "leaked-key" } },
      },
    },
    detail: "The leaked key is still valid. An attacker can reuse it indefinitely unless it is revoked.",
    detailJa: "漏洩したキーはまだ有効です。取消されない限り攻撃者は無期限に再利用できます。",
    timestamp: Date.now(),
  },
  {
    id: "step-4",
    kind: "verify",
    label: "Revoke the key and verify access is denied",
    labelJa: "キーを取消して同一キーでのアクセスが拒否されることを確認",
    status: "blocked",
    payload: {
      type: "http",
      request: {
        method: "DELETE",
        url: "/api/sso/attack/apikey-leakage/revoke",
        body: { keyId: "key_seed0001" },
      },
      response: {
        status: 401,
        body: { success: false, error: "Invalid API key" },
      },
    },
    detail: "After revocation, the same key is rejected. Revocation is the primary mitigation for leaked keys.",
    detailJa: "取消後、同一キーは拒否されます。取消 (revocation) が漏洩キーへの主要な緩和策です。",
    timestamp: Date.now(),
  },
];
```

#### 期待される結果 (AttackResult)

```typescript
const result: AttackResult = {
  scenarioId: "apikey-leakage",
  outcome: "succeeded",  // クエリ送信では漏洩リスクが成立する
  startedAt: /* Unix ms */,
  finishedAt: /* Unix ms */,
  steps,
  blockedBy: "キー取消 (revocation) + ヘッダ送信への変更",
  summary: "API key in query parameter is recorded in server access logs. Header transmission prevents URL logging. Revocation stops further misuse.",
  summaryJa: "クエリパラメータの API キーはサーバーアクセスログに記録されます。ヘッダ送信で URL ログへの漏洩を防止できます。取消によりキーの悪用を停止できます。",
};
```

UI 上の表示:
- step-1: 攻撃成立 (オレンジ) — クエリ送信でログ記録成功
- step-2: 防御成立 (緑) — ヘッダ送信ではログに残らない
- step-3: 攻撃成立 (オレンジ) — 漏洩キーの再利用が成立
- step-4: 防御成立 (緑) — 取消後はアクセス拒否
- 結果バナー: 「この実装は設計上の欠陥があります: クエリパラメータ送信により API キーがアクセスログに記録されます」

#### 防御策 (defenseRecommendation)

**既存実装ファイルへのリンク**:
- `server/routes/sso-apikey.ts:149-161` — `/verify/header` と `/verify/query` の2ルートの比較
- `server/db/schema.ts` — `api_keys` テーブル (revocation のための `revoked_at` カラム追加案)

**防御策の要点**:

1. API キーは必ず HTTP ヘッダ (`Authorization: Bearer ...` または `X-API-Key: ...`) で送信する
2. URL クエリパラメータへの API キー送信を禁止する (エンドポイント自体を廃止することが理想)
3. API キーに有効期限 (`expires_at`) を設けて短命化する
4. 漏洩が発覚した場合に即座に取消できる revocation エンドポイントを実装する
5. 定期的なキーローテーション (rotation) を運用ポリシーで義務付ける

**codeHints の具体例**:

```typescript
// 推奨: ヘッダ送信 (URL ログに残らない)
const res = await fetch("/api/resource", {
  method: "POST",
  headers: {
    "Authorization": `Bearer ${apiKey}`,  // または X-API-Key ヘッダ
    "Content-Type": "application/json",
  },
  body: JSON.stringify(payload),
});

// 非推奨: クエリ送信 (URL ログに記録される)
// const res = await fetch(`/api/resource?api_key=${apiKey}`); // ← 使用禁止

// キー取消 (revocation) のサーバー実装例
// ALTER TABLE api_keys ADD COLUMN revoked_at TEXT;
// PATCH /api/keys/:keyId/revoke → UPDATE api_keys SET revoked_at = datetime('now')

// キー検証時に revoked_at を確認
const key = db.prepare(
  "SELECT * FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL"
).get(keyHash);
if (!key) return c.json({ error: "Invalid or revoked API key" }, 401);
```

#### API 契約

```
POST /api/sso/attack/apikey-leakage
```

**リクエスト**:

```json
{
  "scenario": "query-vs-header",
  "keyId": "key_seed0001"
}
```

| フィールド | 型 | 必須 | 説明 |
|-----------|---|------|------|
| `scenario` | `"query-vs-header"` | 必須 | 実行するサブシナリオ種別 |
| `keyId` | `string` | 必須 | 固定シードキー ID (`key_seed0001` のみ受け付ける) |

**レスポンス**:

```json
{
  "success": true,
  "data": {
    "scenarioId": "apikey-leakage",
    "outcome": "succeeded",
    "startedAt": 1745592000000,
    "finishedAt": 1745592000120,
    "steps": [ /* AttackStep[] — 上記 steps と同一 */ ],
    "summary": "API key in query parameter recorded in access log. Header transmission hides the key.",
    "summaryJa": "クエリパラメータの API キーがアクセスログに記録されました。ヘッダ送信ではキーが隠蔽されます。"
  },
  "_trace": {
    "sessionOps": [
      {
        "action": "READ_API_KEY",
        "data": {
          "method": "Query Parameter (?api_key=...)",
          "value": "SEED_API...",
          "loggedInUrl": true,
          "note": "キーが URL に含まれるためアクセスログに記録されます"
        }
      }
    ],
    "cryptoOps": [
      {
        "op": "hashProvidedKey",
        "input": "\"SEED_APIK...\"",
        "output": "a3f1bc...(20chars)...",
        "algo": "SHA-256",
        "detail": "Hash the provided key to compare with stored hash"
      }
    ],
    "dbQueries": [
      {
        "sql": "SELECT key_id, name FROM api_keys WHERE key_hash = ?",
        "params": ["a3f1bc...(20chars)..."],
        "rows": [{ "key_id": "key_seed0001", "name": "leaked-key" }],
        "ms": 0.5
      }
    ],
    "isAttackMode": true
  }
}
```

#### _trace 内訳

| trace 種別 | 内容 |
|-----------|------|
| `SessionOp` | `READ_API_KEY` — 送信方法 (クエリ vs ヘッダ) と `loggedInUrl` フラグ。クエリ送信時は `true` を設定してフロントエンドで赤色ハイライト |
| `CryptoOp` | `hashProvidedKey` — SHA-256 ハッシュ化操作 |
| `DbQuery` | `SELECT api_keys WHERE key_hash = ?` — キー照合クエリ |

#### UI フロー

```
[Attacker View 起動]
  ↓
[教育用バナー表示: 常時固定]
  ↓
[シナリオセレクタ: "API キー漏洩 (ログ・URL 経由)" を選択]
  ↓
[送信方式比較パネル]
  左列: クエリ送信 (脆弱)
  右列: ヘッダ送信 (安全)
  ↓
[「攻撃を実行」ボタン]
  ↓
[AttackStepTimeline アニメーション]
  step-1 intercept: クエリ送信でキーがログ記録 → SUCCESS (オレンジ)
  step-2 probe:     ヘッダ送信ではログに残らない → BLOCKED (緑)
  step-3 exploit:   漏洩キーの再利用が成立 → SUCCESS (オレンジ)
  step-4 verify:    キー取消後はアクセス拒否 → BLOCKED (緑)
  ↓
[アクセスログ表示エリア: クエリ vs ヘッダの差を side-by-side 表示]
  左: "GET /api/...?api_key=SEED_API... 200" (キーが丸見え)
  右: "POST /api/... [X-API-Key: ****] 200" (キーは非表示)
  ↓
[AttackResultBanner: "この実装は設計上の欠陥があります: クエリパラメータ送信により API キーがログに記録されます"]
  ↓
[AttackDefensePanel 自動展開: ヘッダ送信への変更 / revocation / rotation]
  ↓
[DataFlowPanel: HTTP タブ / Trace タブ (SessionOp + CryptoOp) / DB タブ (api_keys 照合)]
```

#### i18n キー一覧 (このシナリオ固有)

| キー概念 | 日本語 | English |
|---------|--------|---------|
| シナリオ名 | `API キー漏洩 (ログ・URL 経由)` | `API Key Leakage (via Log / URL)` |
| クエリ送信ラベル | `クエリ送信 (脆弱)` | `Query Transmission (Vulnerable)` |
| ヘッダ送信ラベル | `ヘッダ送信 (推奨)` | `Header Transmission (Recommended)` |
| ログ記録あり | `アクセスログに記録される` | `Recorded in access log` |
| ログ記録なし | `URL ログには記録されない` | `Not recorded in URL log` |
| step-1 ラベル | `クエリパラメータの API キーをアクセスログで観測` | `Observe API key in server access log (query parameter)` |
| step-2 ラベル | `ヘッダ送信では URL ログに記録されない (比較)` | `Header method not recorded in URL log (comparison)` |
| step-3 ラベル | `漏洩したキーで保護リソースに再アクセス` | `Re-access protected resource with leaked key` |
| step-4 ラベル | `キー取消後はアクセスが拒否されることを確認` | `Verify access is denied after key revocation` |
| 攻撃成立メッセージ | `この実装は設計上の欠陥があります: クエリパラメータ送信により API キーがアクセスログに記録されます` | `This implementation has a design flaw: query parameter transmission records the API key in access logs` |
| 防御成立メッセージ | `防御が機能しました: ヘッダ送信により API キーが URL ログから保護されました` | `Defense succeeded: header transmission protects the API key from URL log recording` |
| 取消後拒否メッセージ | `防御が機能しました: キー取消により漏洩キーでのアクセスが阻止されました` | `Defense succeeded: key revocation blocked access with the leaked key` |
| ログ比較注記 | `注: このデモはローカルサーバーのインメモリログのみを対象としています` | `Note: This demo targets only local server in-memory logs` |
| rotation 推奨 | `定期的なキーローテーションにより漏洩の影響を限定できます` | `Regular key rotation limits the impact of leaked keys` |

---

### 4.2 `apikey-hmac-bypass`

#### 概要

これは **CWE-208 / CWE-326 / CAPEC-462** の概念実証である。
HMAC 検証において `===` 演算子による文字列比較を使うと、
一致した文字数が多いほど比較処理時間が長くなるタイミング差異が生じ、
攻撃者は1バイトずつ正解の HMAC を統計的に推定できる (タイミング攻撃)。
また、HMAC が極端に短い (例: 4 バイト = 8 文字 hex) 場合は
総当りで正解を発見できてしまう (CWE-326: 不十分な暗号強度)。

本デモでは `===` 比較 vs `crypto.timingSafeEqual` の応答時間差と、
HMAC 長 4 バイト (8 hex 文字) vs 32 バイト (64 hex 文字) の総当り成否を比較する。

**実環境との差異の注記 (必須)**:
実環境ではネットワーク遅延・OS スケジューリングのジッターにより再現が困難です。
タイミング攻撃には数十万回の測定と統計分析を要します。
このデモは概念的な差異を誇張して表示しています。

#### CWE / CAPEC / OSI 層

| 項目 | 値 |
|------|-----|
| CWE | CWE-208 (Observable Timing Discrepancy), CWE-326 (Inadequate Encryption Strength) |
| CAPEC | CAPEC-462 (Cross-Channel Scripting — タイミング攻撃への適用) |
| OSI 層 | Layer 7 — Application |
| 深刻度 | High |

#### 前提条件 (脆弱な実装)

攻撃者は以下の条件を満たしている:

1. HMAC 検証エンドポイントへの繰り返しアクセスが可能
2. サーバーが `===` による短絡評価比較を使用している、または HMAC が非常に短い
3. タイミング差異シナリオでは: 攻撃者が高精度で応答時間を計測できる

**脆弱な実装例** (このシナリオでシミュレーションする実装):

```typescript
// 脆弱な実装例 A: === による短絡評価比較 (教育用シミュレーション専用)
function vulnerableHmacCompare(provided: string, expected: string): boolean {
  return provided === expected;  // 先頭一致文字数に比例して処理時間が変化する
}

// 脆弱な実装例 B: 4 バイト HMAC (教育用シミュレーション専用)
const shortHmac = crypto.createHmac("sha256", secret)
  .update(canonical)
  .digest("hex")
  .substring(0, 8);  // 先頭 8 文字 (4 バイト) のみ使用 → 総当り可能
```

#### 攻撃ステップ (AttackStep[] の具体例)

```typescript
const steps: AttackStep[] = [
  {
    id: "step-1",
    kind: "probe",
    label: "Probe timing difference: 0-char HMAC match with === comparison",
    labelJa: "=== 比較で 0 文字一致のタイミング差異を計測",
    status: "success",
    payload: {
      type: "generic",
      data: {
        probeSignature: "00000000000000000000000000000000",
        matchedHexChars: 0,
        compareMethod: "=== (short-circuit)",
        simulatedTimeMs: 0.8,
      },
    },
    detail: "=== comparison stops at first mismatch. Fast response when no characters match.",
    detailJa: "=== 比較は最初の不一致で停止します。一致文字数 0 では最速の応答時間です。",
    timestamp: Date.now(),
  },
  {
    id: "step-2",
    kind: "probe",
    label: "Probe timing difference: 16-char HMAC match with === comparison",
    labelJa: "=== 比較で 16 文字一致のタイミング差異を計測",
    status: "success",
    payload: {
      type: "generic",
      data: {
        probeSignature: "CORRECT_16_CHARS_THEN_ZEROS",
        matchedHexChars: 16,
        compareMethod: "=== (short-circuit)",
        simulatedTimeMs: 1.6,
      },
    },
    detail: "16 matching characters cause 2x longer comparison time, leaking information about correct prefix.",
    detailJa: "16 文字一致により比較時間が 2 倍になり、正解プレフィックスの情報が漏洩します。",
    timestamp: Date.now(),
  },
  {
    id: "step-3",
    kind: "exploit",
    label: "Brute-force 4-byte HMAC (total 2^32 ≈ 4.29 billion combinations — simulated)",
    labelJa: "4 バイト HMAC を総当り (2^32 ≈ 42 億通り — サーバー側シミュレーション)",
    status: "success",
    payload: {
      type: "generic",
      data: {
        hmacLength: 4,
        hmacBits: 32,
        keySpace: 4294967296,
        simulatedAttemptsToSuccess: 2147483648,
        shortHmacValue: "a3b1f2c0",
        attackFeasible: true,
        note: "4-byte HMAC is computationally feasible to brute-force offline",
        noteJa: "4 バイト HMAC はオフライン総当りが計算上可能です",
      },
    },
    detail: "With only 4 bytes, the HMAC has 2^32 possible values. Server-side simulation shows the attack succeeds.",
    detailJa: "4 バイトでは 2^32 通りのみ。サーバー側シミュレーションで攻撃が成立することを示します。",
    timestamp: Date.now(),
  },
  {
    id: "step-4",
    kind: "verify",
    label: "Verify: crypto.timingSafeEqual + 32-byte HMAC blocks both attacks",
    labelJa: "確認: timingSafeEqual + 32 バイト HMAC で両攻撃を阻止",
    status: "blocked",
    payload: {
      type: "generic",
      data: {
        hmacLength: 32,
        hmacBits: 256,
        keySpace: "2^256 (≈ 10^77 — computationally infeasible)",
        compareMethod: "crypto.timingSafeEqual",
        timingVarianceMs: 0.05,
        note: "Timing variance is within noise floor. Brute-force is infeasible at 256 bits.",
        noteJa: "タイミング差異はノイズレベル以下。256 ビットでは総当りは計算上不可能。",
      },
    },
    detail: "crypto.timingSafeEqual eliminates timing side-channel. 32-byte HMAC makes brute-force infeasible.",
    detailJa: "crypto.timingSafeEqual がタイミングサイドチャネルを排除します。32 バイト HMAC により総当りが計算上不可能になります。",
    timestamp: Date.now(),
  },
];
```

#### 期待される結果 (AttackResult)

```typescript
const result: AttackResult = {
  scenarioId: "apikey-hmac-bypass",
  outcome: "succeeded",  // === 比較 + 4 バイト HMAC では攻撃が成立
  startedAt: /* Unix ms */,
  finishedAt: /* Unix ms */,
  steps,
  blockedBy: "crypto.timingSafeEqual + 32 バイト HMAC",
  summary: "=== comparison leaks timing information. 4-byte HMAC is brute-forceable. timingSafeEqual + 32-byte HMAC blocks both attacks.",
  summaryJa: "=== 比較はタイミング情報を漏洩します。4 バイト HMAC は総当り可能です。timingSafeEqual + 32 バイト HMAC で両攻撃を阻止します。",
};
```

#### 防御策 (defenseRecommendation)

**既存実装ファイルへのリンク**:
- `server/routes/sso-apikey.ts:229-240` — `crypto.timingSafeEqual` による定数時間比較の実装
- `server/routes/sso-apikey.ts:218` — `crypto.createHmac("sha256", key.key_hash).update(canonical).digest("hex")` による 32 バイト (64 hex 文字) HMAC 生成

**防御策の要点**:

1. HMAC 比較には必ず `crypto.timingSafeEqual` を使用する (Node.js 標準 API)
2. HMAC のビット長は最低 256 ビット (HMAC-SHA256 の出力全体 = 32 バイト = 64 hex 文字)
3. HMAC をバイト長で切り詰めて使用してはならない
4. 比較前に入力バッファが同一長でない場合は必ず `false` を返す (長さ情報の漏洩防止)

**codeHints の具体例**:

```typescript
import crypto from "crypto";

// 脆弱な実装 A: === による短絡評価 (使用禁止)
const vulnerableCompare = (a: string, b: string): boolean => a === b;

// 脆弱な実装 B: HMAC を切り詰める (使用禁止)
const shortHmac = hmac.digest("hex").substring(0, 8); // 4 バイト — 総当り可能

// 安全な実装 (推奨 — 現行 sso-apikey.ts の実装)
const expectedBuf = Buffer.from(expectedSig, "hex");          // 32 バイト (256 ビット)
const providedBuf = signature
  ? Buffer.from(signature, "hex")
  : Buffer.alloc(0);
// 長さ不一致は即時 false (長さ情報を漏洩しない)
const valid =
  providedBuf.length === expectedBuf.length
    ? crypto.timingSafeEqual(expectedBuf, providedBuf)
    : false;

// HMAC は常に完全な出力を使用する
const expectedSig = crypto
  .createHmac("sha256", secret)
  .update(canonical)
  .digest("hex"); // 64 文字 hex = 32 バイト — 切り詰めない
```

#### API 契約

```
POST /api/sso/attack/hmac-bypass
```

**リクエスト**:

```json
{
  "compareMethod": "string-equal",
  "hmacLength": 4,
  "keyId": "key_seed0001",
  "timestamp": "2026-04-26T12:00:00Z",
  "body": { "resource": "seed-resource" }
}
```

| フィールド | 型 | 必須 | 説明 |
|-----------|---|------|------|
| `compareMethod` | `"string-equal" \| "timing-safe"` | 必須 | 比較方法の選択 |
| `hmacLength` | `4 \| 32` | 必須 | HMAC バイト長 (4 で脆弱、32 で安全) |
| `keyId` | `string` | 必須 | 固定シードキー ID (`key_seed0001` のみ) |
| `timestamp` | `string` | 必須 | ISO-8601 タイムスタンプ |
| `body` | `object` | 必須 | 署名対象のリクエストボディ |

**レスポンス (=== 比較 + 4 バイト HMAC)**:

```json
{
  "success": true,
  "data": {
    "scenarioId": "apikey-hmac-bypass",
    "outcome": "succeeded",
    "startedAt": 1745592000000,
    "finishedAt": 1745592000200,
    "steps": [ /* AttackStep[] */ ],
    "summary": "=== comparison leaks timing. 4-byte HMAC brute-forced.",
    "summaryJa": "=== 比較がタイミングを漏洩。4 バイト HMAC が総当りされました。"
  },
  "_trace": {
    "cryptoOps": [
      {
        "op": "HMAC-SHA256 (truncated)",
        "input": "secret=key_hash, data=canonical",
        "output": "a3b1f2c0 (4 bytes — TRUNCATED)",
        "algo": "HMAC-SHA256 (4-byte output)",
        "detail": "WARNING: 4-byte HMAC has only 2^32 possible values. Brute-force feasible."
      },
      {
        "op": "compareSignatures (===)",
        "input": "provided=a3b1f2c0 vs computed=a3b1f2c0",
        "output": "MATCH ✓ (but timing leakage exists)",
        "algo": "string === (short-circuit)",
        "detail": "Short-circuit comparison leaks timing information proportional to matching prefix length."
      }
    ],
    "isAttackMode": true
  }
}
```

#### _trace 内訳

| trace 種別 | 内容 |
|-----------|------|
| `CryptoOp` | `HMAC-SHA256 (truncated)` — 4 バイト切り詰め時の出力と警告 |
| `CryptoOp` | `compareSignatures (===)` — 短絡評価比較の応答時間 (サーバー側シミュレーション値) |
| `CryptoOp` | `compareSignatures (timingSafeEqual)` — 定数時間比較との比較 |
| `DbQuery` | `SELECT api_keys WHERE key_id = ?` — シードキーの取得 |

#### UI フロー

```
[Attacker View 起動]
  ↓
[教育用バナー表示: 常時固定]
  ↓
[シナリオセレクタ: "HMAC 検証バイパス" を選択]
  ↓
[設定エリア]
  - 比較方式: === (短絡評価) / timingSafeEqual のラジオ選択
  - HMAC 長: 4 バイト (脆弱) / 32 バイト (安全) のラジオ選択
  ↓
[「攻撃を実行」ボタン]
  ↓
[AttackStepTimeline アニメーション]
  step-1 probe:  === 比較、0 文字一致 → 応答時間 0.8ms
  step-2 probe:  === 比較、16 文字一致 → 応答時間 1.6ms
  step-3 exploit: 4 バイト HMAC 総当り成立 → SUCCESS (オレンジ)
  step-4 verify:  timingSafeEqual + 32 バイト → BLOCKED (緑)
  ↓
[応答時間比較バー: === vs timingSafeEqual の横並びバーグラフ]
  + [HMAC 鍵空間テーブル: 4 バイト (2^32) vs 32 バイト (2^256)]
  ↓
[AttackResultBanner: "この実装は設計上の欠陥があります: === 比較がタイミング情報を漏洩します / 4 バイト HMAC が総当り可能です"]
  ↓
[AttackDefensePanel: timingSafeEqual の使用 / 32 バイト HMAC / 長さ不一致の即時拒否]
  ↓
[DataFlowPanel: HTTP / Trace (CryptoOp タイミング比較)]
```

#### i18n キー一覧 (このシナリオ固有)

| キー概念 | 日本語 | English |
|---------|--------|---------|
| シナリオ名 | `HMAC 検証バイパス (タイミング攻撃 / 短い HMAC)` | `HMAC Bypass (Timing Attack / Short HMAC)` |
| 比較方式ラベル | `署名比較方式` | `Signature comparison method` |
| === ラジオラベル | `=== 短絡評価 (脆弱)` | `=== Short-circuit (Vulnerable)` |
| timingSafeEqual ラベル | `timingSafeEqual (安全)` | `timingSafeEqual (Secure)` |
| HMAC 長ラベル | `HMAC バイト長` | `HMAC byte length` |
| 4 バイトラベル | `4 バイト (脆弱 — 2^32 通り)` | `4 bytes (Vulnerable — 2^32 values)` |
| 32 バイトラベル | `32 バイト (安全 — 2^256 通り)` | `32 bytes (Secure — 2^256 values)` |
| step-1 ラベル | `=== 比較で 0 文字一致のタイミング差異を計測` | `Measure timing: 0-char HMAC match with === comparison` |
| step-2 ラベル | `=== 比較で 16 文字一致のタイミング差異を計測` | `Measure timing: 16-char HMAC match with === comparison` |
| step-3 ラベル | `4 バイト HMAC の総当りが成立 (サーバー側シミュレーション)` | `4-byte HMAC brute-force succeeded (server-side simulation)` |
| step-4 ラベル | `timingSafeEqual + 32 バイト HMAC が両攻撃を阻止` | `timingSafeEqual + 32-byte HMAC blocks both attacks` |
| 応答時間ラベル | `応答時間 (ms)` | `Response time (ms)` |
| 鍵空間ラベル | `鍵空間` | `Key space` |
| 攻撃成立メッセージ A | `この実装は設計上の欠陥があります: === 比較がタイミング情報を漏洩します` | `This implementation has a design flaw: === comparison leaks timing information` |
| 攻撃成立メッセージ B | `この実装は設計上の欠陥があります: 4 バイト HMAC は総当りが成立します` | `This implementation has a design flaw: 4-byte HMAC is susceptible to brute-force` |
| 防御成立メッセージ | `防御が機能しました: timingSafeEqual が差異を排除し、32 バイト HMAC が総当りを阻止しました` | `Defense succeeded: timingSafeEqual eliminated timing discrepancy and 32-byte HMAC blocked brute-force` |
| タイミング注記 | `注: 応答時間は概念的差異を誇張したシミュレーション値です` | `Note: Response times are exaggerated simulation values for conceptual clarity` |
| 総当り注記 | `注: 総当り処理はサーバー側でシミュレーションしており、ブラウザからの実試行ではありません` | `Note: Brute-force is simulated server-side, not actual attempts from the browser` |

---

### 4.3 `apikey-replay-no-timestamp`

#### 概要

これは **CWE-294 / CAPEC-60** の概念実証である。
HMAC 署名されたリクエストでも、リクエスト本文にタイムスタンプ (`timestamp`) と
ノンス (`nonce`) が含まれていない場合、攻撃者は一度観測した正当なリクエストを
そのままコピーして再送することで同一の操作を繰り返し実行できる
(録音再生攻撃 / リプレイ攻撃)。

本デモでは「タイムスタンプ + nonce なし」の署名済みリクエストを傍受し、
数秒後に同一リクエストを再送して成立する様子を示す。
次に「±5 分 timestamp + nonce DB チェック」が有効な実装で同一再送が拒否される様子を対比する。

**実環境との差異の注記 (必須)**:
実環境でのリプレイ攻撃には、HTTPS 通信の傍受 (MITM) が前提となります。
HTTPS 使用時は傍受自体が困難です。このデモは HTTP または鍵漏洩後のシナリオを想定しています。

#### CWE / CAPEC / OSI 層

| 項目 | 値 |
|------|-----|
| CWE | CWE-294 (Authentication Bypass by Capture-replay) |
| CAPEC | CAPEC-60 (Reusing Session IDs (aka Session Replay)) |
| OSI 層 | Layer 7 — Application |
| 深刻度 | Medium |

#### 前提条件 (脆弱な実装)

攻撃者は以下の条件を満たしている:

1. 正規ユーザーの HMAC 署名済みリクエストを一度傍受または記録済み
2. サーバー側の HMAC 検証に timestamp/nonce チェックが実装されていない
3. 攻撃者は傍受したリクエストをそのまま再送できる

**脆弱な実装例** (このシナリオでシミュレーションする実装):

```typescript
// 脆弱な実装例 (教育用シミュレーション専用): timestamp なしで HMAC のみ検証
function vulnerableHmacVerify(body: object, signature: string, keyHash: string): boolean {
  // canonical に timestamp を含まない → リプレイ可能
  const canonical = JSON.stringify(body);
  const expected = crypto.createHmac("sha256", keyHash).update(canonical).digest("hex");
  const expectedBuf = Buffer.from(expected, "hex");
  const providedBuf = Buffer.from(signature, "hex");
  return providedBuf.length === expectedBuf.length
    ? crypto.timingSafeEqual(expectedBuf, providedBuf)
    : false;
  // → signature は body に依存するだけなので、同じ body を送ればいつでも通る
}
```

#### 攻撃ステップ (AttackStep[] の具体例)

```typescript
const steps: AttackStep[] = [
  {
    id: "step-1",
    kind: "intercept",
    label: "Capture a valid HMAC-signed request (no timestamp in body)",
    labelJa: "有効な HMAC 署名済みリクエストを傍受 (ボディにタイムスタンプなし)",
    status: "success",
    payload: {
      type: "http",
      request: {
        method: "POST",
        url: "/api/sso/attack/replay-no-timestamp/send-original",
        body: {
          keyId: "key_seed0001",
          body: { resource: "seed-resource", action: "read" },
          signature: "HMAC_OF_BODY_WITHOUT_TIMESTAMP",
          // timestamp フィールドなし
        },
      },
      response: {
        status: 200,
        body: { success: true, data: { valid: true, message: "Request authenticated" } },
      },
    },
    detail: "Attacker captures this request. The signature covers only the body, not a timestamp.",
    detailJa: "攻撃者がこのリクエストを傍受します。署名はボディのみをカバーし、タイムスタンプを含みません。",
    timestamp: Date.now(),
  },
  {
    id: "step-2",
    kind: "exploit",
    label: "Replay the captured request 60 seconds later — same signature accepted",
    labelJa: "60 秒後に傍受したリクエストをそのまま再送 — 同一署名が受理される",
    status: "success",
    payload: {
      type: "http",
      request: {
        method: "POST",
        url: "/api/sso/attack/replay-no-timestamp/replay",
        body: {
          keyId: "key_seed0001",
          body: { resource: "seed-resource", action: "read" },
          signature: "HMAC_OF_BODY_WITHOUT_TIMESTAMP",
          delaySimulatedMs: 60000,
        },
      },
      response: {
        status: 200,
        body: { success: true, data: { valid: true, message: "Replayed request accepted" } },
      },
    },
    detail: "Without timestamp, the signature is identical to the original. Server cannot distinguish original from replay.",
    detailJa: "タイムスタンプなしでは署名が元のリクエストと同一です。サーバーは元のリクエストとリプレイを区別できません。",
    timestamp: Date.now(),
  },
  {
    id: "step-3",
    kind: "verify",
    label: "Verify: timestamp + 5-min window rejects the replay",
    labelJa: "確認: timestamp + 5 分窓でリプレイが拒否される",
    status: "blocked",
    payload: {
      type: "http",
      request: {
        method: "POST",
        url: "/api/sso/apikey/verify/hmac",
        body: {
          keyId: "key_seed0001",
          timestamp: "2026-04-26T11:55:00Z",  // 6 分前 — 窓外
          body: { resource: "seed-resource", action: "read" },
          signature: "OLD_HMAC_WITH_EXPIRED_TIMESTAMP",
        },
      },
      response: {
        status: 401,
        body: { success: false, error: "Timestamp invalid or outside ±5min skew window" },
      },
    },
    detail: "The existing /verify/hmac implementation checks timestamp skew (±5min). Replay with expired timestamp is rejected.",
    detailJa: "既存の /verify/hmac 実装がタイムスタンプ skew (±5 分) を検査します。期限切れタイムスタンプのリプレイは拒否されます。",
    timestamp: Date.now(),
  },
  {
    id: "step-4",
    kind: "verify",
    label: "Verify: nonce DB prevents replay within the 5-min window",
    labelJa: "確認: nonce DB が 5 分窓内のリプレイを防止",
    status: "blocked",
    payload: {
      type: "generic",
      data: {
        nonce: "unique-nonce-abc123",
        nonceAlreadyUsed: true,
        rejectionReason: "Nonce already used within the time window",
        rejectionReasonJa: "タイムウィンドウ内で nonce が既に使用されています",
      },
    },
    detail: "Even within the 5-min window, a used nonce is stored in DB and rejected on second use.",
    detailJa: "5 分窓内でも使用済み nonce が DB に記録され、2 回目の使用は拒否されます。",
    timestamp: Date.now(),
  },
];
```

#### 期待される結果 (AttackResult)

```typescript
const result: AttackResult = {
  scenarioId: "apikey-replay-no-timestamp",
  outcome: "succeeded",  // timestamp なし実装ではリプレイが成立
  startedAt: /* Unix ms */,
  finishedAt: /* Unix ms */,
  steps,
  blockedBy: "timestamp ±5 分窓 + nonce DB チェック",
  summary: "Without timestamp in canonical string, HMAC signature is replayable indefinitely. Timestamp + nonce prevents replay.",
  summaryJa: "canonical 文字列にタイムスタンプがなければ HMAC 署名は無期限に再使用可能です。timestamp + nonce でリプレイを防止します。",
};
```

#### 防御策 (defenseRecommendation)

**既存実装ファイルへのリンク**:
- `server/routes/sso-apikey.ts:163-205` — `HMAC_TIMESTAMP_SKEW_MS = 5 * 60 * 1000` と `parseTimestamp` によるタイムスタンプ skew チェックの実装
- `server/routes/sso-apikey.ts:208` — `canonical = \`${timestamp}\n${JSON.stringify(body)}\`` — canonical 文字列にタイムスタンプを含む設計

**防御策の要点**:

1. HMAC の canonical 文字列には必ずタイムスタンプを含める
2. タイムスタンプの許容範囲を ±5 分 (または更に短く) に制限する
3. nonce (使い捨て乱数値) を canonical に含め、使用済み nonce を DB に保存して重複使用を拒否する
4. nonce DB のレコードは許容ウィンドウ (5 分) 経過後に削除してストレージを節約する

**codeHints の具体例**:

```typescript
// 防御実装 (現行 sso-apikey.ts の設計): タイムスタンプ込み canonical
const canonical = `${timestamp}\n${JSON.stringify(body)}`;
// → リプレイするには元のタイムスタンプを使う必要があり、5 分で期限切れになる

// 強化版: nonce DB チェック追加
const nonce = c.req.json().nonce;
const usedNonce = db.prepare(
  "SELECT 1 FROM used_nonces WHERE nonce = ? AND created_at > datetime('now', '-5 minutes')"
).get(nonce);
if (usedNonce) {
  return c.json({ error: "Nonce already used within the time window" }, 401);
}
// nonce を DB に記録
db.prepare("INSERT INTO used_nonces (nonce, created_at) VALUES (?, datetime('now'))").run(nonce);

// nonce を canonical に含めることで更に強化
const canonical = `${timestamp}\n${nonce}\n${JSON.stringify(body)}`;
```

```sql
-- used_nonces テーブル (新規追加)
CREATE TABLE IF NOT EXISTS used_nonces (
  nonce      TEXT PRIMARY KEY,
  created_at TEXT DEFAULT (datetime('now'))
);
-- 5 分経過レコードの定期クリーンアップ (リセット時にも実行)
DELETE FROM used_nonces WHERE created_at < datetime('now', '-5 minutes');
```

#### API 契約

```
POST /api/sso/attack/replay-no-timestamp
```

**リクエスト**:

```json
{
  "phase": "capture",
  "keyId": "key_seed0001",
  "body": { "resource": "seed-resource", "action": "read" },
  "includeTimestamp": false,
  "includeNonce": false
}
```

| フィールド | 型 | 必須 | 説明 |
|-----------|---|------|------|
| `phase` | `"capture" \| "replay"` | 必須 | `capture`: 元リクエストの署名生成と送信。`replay`: 保存済み署名の再送 |
| `keyId` | `string` | 必須 | 固定シードキー ID |
| `body` | `object` | 必須 | 署名対象のリクエストボディ |
| `includeTimestamp` | `boolean` | 任意 | `true` にすると timestamp を canonical に含める (デフォルト `false` — 脆弱な実装) |
| `includeNonce` | `boolean` | 任意 | `true` にすると nonce を canonical に含め DB チェックを行う (デフォルト `false`) |

**レスポンス (phase: "replay", timestamp なし → リプレイ成立)**:

```json
{
  "success": true,
  "data": {
    "scenarioId": "apikey-replay-no-timestamp",
    "outcome": "succeeded",
    "startedAt": 1745592000000,
    "finishedAt": 1745592060120,
    "steps": [ /* AttackStep[] */ ],
    "summary": "Replay succeeded. No timestamp in canonical string.",
    "summaryJa": "リプレイが成立しました。canonical 文字列にタイムスタンプがありません。"
  },
  "_trace": {
    "cryptoOps": [
      {
        "op": "buildCanonicalString",
        "input": "body only (no timestamp)",
        "output": "{\"resource\":\"seed-resource\",\"action\":\"read\"}",
        "algo": "string concatenation",
        "detail": "WARNING: canonical string contains no timestamp — HMAC is replayable indefinitely"
      },
      {
        "op": "HMAC-SHA256",
        "input": "secret=key_hash, data=canonical (no timestamp)",
        "output": "HMAC_VALUE_SAME_AS_ORIGINAL...",
        "algo": "HMAC-SHA256",
        "detail": "Identical canonical string produces identical HMAC — server cannot detect replay"
      }
    ],
    "dbQueries": [
      {
        "sql": "SELECT key_id FROM api_keys WHERE key_id = ?",
        "params": ["key_seed0001"],
        "rows": [{ "key_id": "key_seed0001" }],
        "ms": 0.4
      }
    ],
    "isAttackMode": true
  }
}
```

#### _trace 内訳

| trace 種別 | 内容 |
|-----------|------|
| `CryptoOp` | `buildCanonicalString` — タイムスタンプ有無での canonical 文字列差異と警告 |
| `CryptoOp` | `HMAC-SHA256` — 元リクエストとリプレイリクエストで同一値になることの確認 |
| `CryptoOp` | `timestampSkewCheck` — timestamp あり版での skew 検査と拒否の記録 |
| `DbQuery` | `SELECT used_nonces WHERE nonce = ?` — nonce DB チェック (nonce あり版) |
| `DbQuery` | `INSERT INTO used_nonces` — nonce 使用記録 (nonce あり版) |

#### UI フロー

```
[Attacker View 起動]
  ↓
[教育用バナー表示: 常時固定]
  ↓
[シナリオセレクタ: "タイムスタンプなしリプレイ" を選択]
  ↓
[設定エリア]
  - タイムスタンプ含有: なし (脆弱) / あり (防御) トグル
  - nonce 含有: なし (脆弱) / あり (防御) トグル
  - 再送遅延シミュレーション: 0 秒 / 60 秒 / 5.5 分 スライダー
  ↓
[「攻撃を実行」ボタン]
  ↓
[AttackStepTimeline アニメーション]
  step-1 intercept: 有効な署名済みリクエストを傍受 → SUCCESS
  step-2 exploit:   60 秒後に同一リクエストを再送 → SUCCESS / BLOCKED (設定による)
  step-3 verify:    timestamp ±5 分窓が期限切れリプレイを拒否 → BLOCKED (緑)
  step-4 verify:    nonce DB が同一窓内のリプレイを拒否 → BLOCKED (緑)
  ↓
[canonical 文字列差異ビュー]
  タイムスタンプなし: '{"resource":"seed-resource","action":"read"}'
  タイムスタンプあり: '2026-04-26T12:00:00Z\n{"resource":"...","action":"read"}'
  ↓
[AttackResultBanner]
  リプレイ成立: "この実装は設計上の欠陥があります: canonical にタイムスタンプがないためリプレイが成立します"
  リプレイ失敗: "防御が機能しました: timestamp ±5 分窓 / nonce DB がリプレイを拒否しました"
  ↓
[AttackDefensePanel: canonical へのタイムスタンプ組み込み / nonce DB / 窓サイズのトレードオフ]
  ↓
[DataFlowPanel: HTTP / Trace (CryptoOp canonical 比較) / DB (used_nonces テーブル)]
```

#### i18n キー一覧 (このシナリオ固有)

| キー概念 | 日本語 | English |
|---------|--------|---------|
| シナリオ名 | `タイムスタンプなしリプレイ` | `Replay Without Timestamp` |
| タイムスタンプ含有トグル | `タイムスタンプ` | `Timestamp` |
| タイムスタンプなしラベル | `なし (脆弱な実装)` | `None (Vulnerable)` |
| タイムスタンプありラベル | `あり (±5 分窓)` | `Included (±5-min window)` |
| nonce 含有トグル | `Nonce` | `Nonce` |
| nonce なしラベル | `なし (脆弱な実装)` | `None (Vulnerable)` |
| nonce ありラベル | `あり (使い捨て DB チェック)` | `Included (one-time DB check)` |
| 再送遅延ラベル | `再送遅延シミュレーション` | `Replay delay simulation` |
| canonical 差異ラベル | `canonical 文字列の差異` | `Canonical string difference` |
| step-1 ラベル | `有効な HMAC 署名済みリクエストを傍受` | `Capture a valid HMAC-signed request` |
| step-2 ラベル | `傍受したリクエストを 60 秒後に再送` | `Replay captured request 60 seconds later` |
| step-3 ラベル | `timestamp ±5 分窓が期限切れリプレイを拒否` | `Timestamp ±5-min window rejects expired replay` |
| step-4 ラベル | `nonce DB が同一窓内のリプレイを拒否` | `Nonce DB prevents replay within the time window` |
| 攻撃成立メッセージ | `この実装は設計上の欠陥があります: canonical にタイムスタンプがないためリプレイが成立します` | `This implementation has a design flaw: no timestamp in canonical string makes HMAC replayable` |
| 防御成立メッセージ (timestamp) | `防御が機能しました: timestamp ±5 分窓が期限切れリプレイを拒否しました` | `Defense succeeded: timestamp ±5-min window rejected expired replay` |
| 防御成立メッセージ (nonce) | `防御が機能しました: nonce DB が同一ウィンドウ内のリプレイを拒否しました` | `Defense succeeded: nonce DB rejected replay within the time window` |
| HTTPS 注記 | `注: 実環境でのリプレイには HTTPS 通信の傍受 (MITM) が前提です` | `Note: Real-world replay requires intercepting HTTPS traffic (MITM)` |
| 窓サイズ注記 | `±5 分は NTP ずれを考慮した標準的な設定です` | `±5 minutes is a standard setting that accommodates NTP clock drift` |

---

## 5. UI コンポーネント設計

### 5.1 ディレクトリ構成

```
src/components/auth/attacks/sso-apikey/
├── SsoApikeyAttackPanel.tsx        ← 3シナリオを統括するメインパネル
├── ApikeyLeakageScenario.tsx       ← シナリオ A: クエリ vs ヘッダ比較・revocation
├── ApikeyHmacBypassScenario.tsx    ← シナリオ B: タイミング攻撃 / 短い HMAC
├── ApikeyReplayScenario.tsx        ← シナリオ C: リプレイ / timestamp + nonce
└── SsoApikeyAttack.css             ← 3シナリオ共通スタイル
```

### 5.2 `SsoApikeyAttackPanel.tsx` の責務

```typescript
// SsoPatterns.tsx への組み込みイメージ
import SsoApikeyAttackPanel from "./attacks/sso-apikey/SsoApikeyAttackPanel";
import { Show } from "solid-js";

// viewMode Signal (ViewModeToggle で管理)
<Show when={viewMode() === "attacker"}>
  <SsoApikeyAttackPanel tabId="sso-idp-apikey" />
</Show>
```

`SsoApikeyAttackPanel` は以下を担当する:

1. `EducationalWarningBanner` の常時表示 (position: sticky; dismissable 禁止)
2. `AttackScenarioSelector` で 3 シナリオの切り替え
3. 選択中シナリオに対応する `ApikeyLeakageScenario` / `ApikeyHmacBypassScenario` / `ApikeyReplayScenario` のレンダリング
4. `DataFlowPanel scopeId="attack-sso-idp-apikey"` の表示

### 5.3 各シナリオコンポーネントの props 設計

```typescript
// ApikeyLeakageScenario.tsx
interface ApikeyLeakageScenarioProps {
  onResult: (result: AttackResult) => void;
  onRunning: (running: boolean) => void;
}

// ApikeyHmacBypassScenario.tsx
interface ApikeyHmacBypassScenarioProps {
  onResult: (result: AttackResult) => void;
  onRunning: (running: boolean) => void;
  compareMethod: "string-equal" | "timing-safe";  // ラジオ選択
  hmacLength: 4 | 32;                              // ラジオ選択
}

// ApikeyReplayScenario.tsx
interface ApikeyReplayScenarioProps {
  onResult: (result: AttackResult) => void;
  onRunning: (running: boolean) => void;
  includeTimestamp: boolean;  // トグル
  includeNonce: boolean;      // トグル
  delaySeconds: number;       // スライダー (0 / 60 / 330)
}
```

### 5.4 Solid.js 実装上の注意

CLAUDE.md の SolidJS 必須ルールに従い以下を遵守する:

- props デストラクチャリング禁止: `props.onResult(...)` でアクセス
- 条件描画: `<Show when={...}>` を使用 (早期リターン禁止)
- リスト描画: `<For each={...}>` を使用
- Signal 更新: `setResult(prev => ...)` で新オブジェクト生成
- `onMount` 内での D3 初期化 (タイミング比較バーグラフに D3 使用)

---

## 6. テスト要件

### 6.1 ユニットテスト (バックエンドハンドラ単体)

対象: `server/routes/sso-apikey.ts` への攻撃サブパス追加分

| テスト ID | 検証内容 | 期待結果 |
|---------|---------|---------|
| `sso-atk-01` | `POST /attack/apikey-leakage` にシードキーを送信 | `outcome: "succeeded"`, step-1 の `loggedInUrl: true` を含む |
| `sso-atk-02` | `POST /attack/apikey-leakage` でキー取消後に同一キーを送信 | step-4 の `status: "blocked"`, HTTP 401 |
| `sso-atk-03` | `POST /attack/hmac-bypass` に `compareMethod: "string-equal", hmacLength: 4` を送信 | `outcome: "succeeded"`, step-3 の `attackFeasible: true` |
| `sso-atk-04` | `POST /attack/hmac-bypass` に `compareMethod: "timing-safe", hmacLength: 32` を送信 | `outcome: "blocked"`, step-4 の `status: "blocked"` |
| `sso-atk-05` | `POST /attack/hmac-bypass` の `_trace.cryptoOps` に `"compareSignatures"` が含まれる | `algo` フィールドが `"string === (short-circuit)"` または `"crypto.timingSafeEqual"` |
| `sso-atk-06` | `POST /attack/replay-no-timestamp` に `phase: "replay", includeTimestamp: false` を送信 | `outcome: "succeeded"`, step-2 の `status: "success"` |
| `sso-atk-07` | `POST /attack/replay-no-timestamp` に `phase: "replay", includeTimestamp: true, delaySeconds: 360` を送信 | `outcome: "blocked"`, step-3 の `status: "blocked"` (skew 超過) |
| `sso-atk-08` | `POST /attack/replay-no-timestamp` に `phase: "replay", includeTimestamp: true, includeNonce: true, delaySeconds: 0` を2回送信 | 2 回目は `outcome: "blocked"` (nonce 重複) |
| `sso-atk-09` | 存在しないキー ID を送信 | `400 Bad Request`, バリデーションエラー |
| `sso-atk-10` | 本番環境 (`NODE_ENV=production`) でいずれかの攻撃エンドポイントに送信 | `403 Forbidden` |

### 6.2 E2E テスト (UI フロー)

対象: `src/components/auth/attacks/sso-apikey/SsoApikeyAttackPanel.tsx`

| テスト ID | 操作 | 期待結果 |
|---------|------|---------|
| `e2e-sso-01` | SsoPatterns タブで Attacker View に切り替える | `EducationalWarningBanner` が表示される |
| `e2e-sso-02` | バナーの閉じるボタンが存在しないことを確認する | バナーが常時表示されている (`dismissable` なし) |
| `e2e-sso-03` | シナリオ A を選択して「攻撃を実行」を押す | `AttackStepTimeline` が 4 ステップを順に表示し、step-2/4 が緑 BLOCKED になる |
| `e2e-sso-04` | シナリオ A でアクセスログ比較ビューが表示されることを確認する | クエリ送信の URL にキーが表示され、ヘッダ送信の URL には含まれない |
| `e2e-sso-05` | シナリオ B で `compareMethod: "timing-safe", hmacLength: 32` を選択して実行 | `AttackResultBanner` が緑 (防御成立) で表示される |
| `e2e-sso-06` | シナリオ B で応答時間比較バーグラフが表示されることを確認する | `=== (short-circuit)` vs `timingSafeEqual` の 2 系列バーが横並びで表示される |
| `e2e-sso-07` | シナリオ C で `includeTimestamp: false` にして実行する | `AttackResultBanner` がオレンジ (攻撃成立) で表示される |
| `e2e-sso-08` | シナリオ C で `includeTimestamp: true, delaySeconds: 360` にして実行する | step-3 が緑 BLOCKED になる |
| `e2e-sso-09` | 攻撃完了後に防御策パネルを確認する | `AttackDefensePanel` が自動展開されている |
| `e2e-sso-10` | Defender View に切り替える | 通常の `SsoDemo` / `ApiKeyDemo` が表示され、攻撃バナーが消える |

---

## 7. i18n キー一覧表 (ja/en)

| # | キー概念 | 日本語 | English |
|---|---------|--------|---------|
| 1 | 攻撃者モード切替 | `攻撃者モード` | `Attacker Mode` |
| 2 | 防御者モード切替 | `防御者モード` | `Defender Mode` |
| 3 | 教育バナーテキスト | `教育用シミュレーション — 実環境を攻撃するためのコードではありません` | `Educational simulation — not for use against real systems` |
| 4 | シナリオ A 名 | `API キー漏洩 (ログ・URL 経由)` | `API Key Leakage (via Log / URL)` |
| 5 | シナリオ B 名 | `HMAC 検証バイパス (タイミング攻撃 / 短い HMAC)` | `HMAC Bypass (Timing Attack / Short HMAC)` |
| 6 | シナリオ C 名 | `タイムスタンプなしリプレイ` | `Replay Without Timestamp` |
| 7 | 攻撃実行ボタン | `攻撃を実行` | `Run Attack` |
| 8 | 実行中ラベル | `実行中...` | `Running...` |
| 9 | 攻撃成立バナー | `この実装は設計上の欠陥があります` | `This implementation has a design flaw` |
| 10 | 防御成立バナー | `防御が機能しました:` | `Defense succeeded:` |
| 11 | 前提条件ラベル | `前提条件:` | `Prerequisite:` |
| 12 | 深刻度ラベル | `深刻度:` | `Severity:` |
| 13 | 防御策を見るボタン | `防御策を見る` | `Show Defense Recommendation` |
| 14 | ペイロード展開ラベル | `ペイロード` | `Payload` |
| 15 | クエリ送信ラベル | `クエリ送信 (脆弱)` | `Query Transmission (Vulnerable)` |
| 16 | ヘッダ送信ラベル | `ヘッダ送信 (推奨)` | `Header Transmission (Recommended)` |
| 17 | アクセスログ比較ラベル | `アクセスログ比較` | `Access Log Comparison` |
| 18 | ログ記録あり | `URL ログに記録される` | `Recorded in URL log` |
| 19 | ログ記録なし | `URL ログには記録されない` | `Not recorded in URL log` |
| 20 | キー取消ボタン | `このキーを取消す` | `Revoke this key` |
| 21 | rotation 推奨 | `定期的なキーローテーションを推奨します` | `Regular key rotation is recommended` |
| 22 | 短寿命キー推奨 | `短命キー (有効期限 24 時間以内) を推奨します` | `Short-lived keys (expires within 24h) are recommended` |
| 23 | 比較方式ラベル | `署名比較方式` | `Signature comparison method` |
| 24 | === ラジオラベル | `=== 短絡評価 (脆弱)` | `=== Short-circuit (Vulnerable)` |
| 25 | timingSafeEqual ラベル | `timingSafeEqual (安全)` | `timingSafeEqual (Secure)` |
| 26 | HMAC 長ラベル | `HMAC バイト長` | `HMAC byte length` |
| 27 | 4 バイトラベル | `4 バイト (脆弱 — 2^32 通り)` | `4 bytes (Vulnerable — 2^32 values)` |
| 28 | 32 バイトラベル | `32 バイト (安全 — 2^256 通り)` | `32 bytes (Secure — 2^256 values)` |
| 29 | 応答時間ラベル | `応答時間 (ms)` | `Response time (ms)` |
| 30 | 鍵空間ラベル | `鍵空間` | `Key space` |
| 31 | タイミング注記 | `注: 応答時間は概念的差異を誇張したシミュレーション値です` | `Note: Response times are exaggerated simulation values` |
| 32 | 総当り注記 | `注: 総当り処理はサーバー側シミュレーションです` | `Note: Brute-force is server-side simulation` |
| 33 | タイムスタンプ含有トグル | `タイムスタンプ` | `Timestamp` |
| 34 | タイムスタンプなしラベル | `なし (脆弱な実装)` | `None (Vulnerable)` |
| 35 | タイムスタンプありラベル | `あり (±5 分窓)` | `Included (±5-min window)` |
| 36 | nonce 含有トグル | `Nonce` | `Nonce` |
| 37 | nonce なしラベル | `なし (脆弱な実装)` | `None (Vulnerable)` |
| 38 | nonce ありラベル | `あり (使い捨て DB チェック)` | `Included (one-time DB check)` |
| 39 | 再送遅延ラベル | `再送遅延シミュレーション` | `Replay delay simulation` |
| 40 | canonical 差異ラベル | `canonical 文字列の差異` | `Canonical string difference` |
| 41 | HTTPS 注記 | `注: 実環境でのリプレイには HTTPS 通信の傍受が前提です` | `Note: Real-world replay requires intercepting HTTPS traffic` |
| 42 | 窓サイズ注記 | `±5 分は NTP ずれを考慮した標準的な設定です` | `±5 minutes is a standard setting accommodating NTP clock drift` |
| 43 | タイムラインARIAラベル | `攻撃ステップログ` | `Attack step log` |
| 44 | ログ漏洩 CWE テキスト | `これは CWE-200 / CWE-798 / CAPEC-117 の概念実証です。` | `This is a proof-of-concept for CWE-200 / CWE-798 / CAPEC-117.` |
| 45 | HMAC バイパス CWE テキスト | `これは CWE-208 / CWE-326 / CAPEC-462 の概念実証です。` | `This is a proof-of-concept for CWE-208 / CWE-326 / CAPEC-462.` |
| 46 | リプレイ CWE テキスト | `これは CWE-294 / CAPEC-60 の概念実証です。` | `This is a proof-of-concept for CWE-294 / CAPEC-60.` |

---

## 8. 関連ファイル

### 8.1 基盤設計書

| ファイル | 参照目的 |
|---------|---------|
| [DESIGN/00-overview.md](./00-overview.md) | 全体目的・カタログマトリクス (行 143-145: sso-idp-apikey の 3 シナリオ) |
| [DESIGN/01-architecture.md](./01-architecture.md) | バックエンドルート配置方針 (サブパス `/attack/*`) / フロントエンドコンポーネント階層 |
| [DESIGN/02-ui-spec.md](./02-ui-spec.md) | `ViewModeToggle` / `AttackStepTimeline` / `AttackResultBanner` / `AttackDefensePanel` の詳細仕様 |
| [DESIGN/03-data-model.md](./03-data-model.md) | `AttackStep` / `AttackResult` / `AttackScenarioMeta` / `ServerTrace` 拡張の型定義 |
| [DESIGN/04-safety-guardrails.md](./04-safety-guardrails.md) | 禁止表現一覧 / ペイロード作成ルール / 開発レビューチェックリスト |

### 8.2 既存実装ファイル (変更・参照対象)

| ファイルパス | 変更種別 | 変更内容 |
|------------|---------|---------|
| `server/routes/sso-apikey.ts` | 追加 | `POST /attack/apikey-leakage`, `POST /attack/hmac-bypass`, `POST /attack/replay-no-timestamp` の 3 エンドポイントを追加 |
| `src/components/auth/SsoPatterns.tsx` | 追加 | `ViewModeToggle` import + `<Show when={viewMode() === "attacker"}>` ブロックで `SsoApikeyAttackPanel` を条件表示 |
| `server/db/schema.ts` | 追加 | `used_nonces` テーブル (nonce DB チェック用) の DDL を `initSchema()` に追加 / `api_keys` テーブルに `revoked_at TEXT` カラム追加 / `seedDb()` にリセット処理を追加 |
| `shared/api-types.ts` | 追加 | `AttackStep`, `AttackResult`, `AttackScenarioMeta`, `ServerTrace` 拡張 (DESIGN/03 参照) |

### 8.3 新規作成ファイル

| ファイルパス | 役割 |
|------------|------|
| `src/components/auth/attacks/sso-apikey/SsoApikeyAttackPanel.tsx` | 3 シナリオを統括するメインパネル |
| `src/components/auth/attacks/sso-apikey/ApikeyLeakageScenario.tsx` | シナリオ A: クエリ vs ヘッダ比較・revocation |
| `src/components/auth/attacks/sso-apikey/ApikeyHmacBypassScenario.tsx` | シナリオ B: タイミング攻撃 + 短い HMAC 総当り |
| `src/components/auth/attacks/sso-apikey/ApikeyReplayScenario.tsx` | シナリオ C: リプレイ / timestamp + nonce |
| `src/components/auth/attacks/sso-apikey/SsoApikeyAttack.css` | 3 シナリオ共通スタイル |
| `src/components/auth/attacks/scenarios/sso-apikey-scenarios.ts` | `AttackScenarioMeta[]` の静的定義 (3 シナリオ分) |
| `server/routes/attack-sso-apikey.ts` | SSO / API Key タブ攻撃ルート (DESIGN/00 §9.3 の命名規則に準拠) |

---

*このドキュメントは `DESIGN/19-attack-sso-apikey.md` に配置。
実装を開始する前に DESIGN/00 〜 04 の基盤設計書を読了し、
特に DESIGN/04-safety-guardrails.md §4 のレビューチェックリストを確認すること。*
