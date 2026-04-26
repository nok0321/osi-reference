---
title: 攻撃デモカタログ — JWT 攻撃詳細
phase: design
last-updated: 2026-04-26
safety-reviewed: false
---

## 教育目的

本ファイルは **教育用シミュレーション** の実装設計である。
記載された攻撃手法は `localhost` 上の固定シードデータに対してのみ動作するよう設計されており、
実環境への攻撃を意図したものではない。

攻撃シミュレーションはすべて「この防御がなぜ必要か」を体感するための概念実証であり、
各シナリオには必ず防御策の解説と実装例が対になっている。

---

# 11. JWT 攻撃詳細設計

## 1. 概要

JWT (JSON Web Token) は認証情報をコンパクトかつ自己完結した形式で伝達するための標準規格 (RFC 7519) である。
ヘッダ・ペイロード・署名の3部構成を Base64url エンコードしてドット (`.`) で連結するシンプルな設計が
広く採用されている一方、実装の誤りや設計上の落とし穴が多く、攻撃者に悪用されやすい特性を持つ。

本設計書では JWT タブ (`tabId: "jwt"`) に対して以下の4シナリオを実装する。

| # | シナリオ ID | 攻撃名 | 深刻度 | CWE |
|---|------------|--------|--------|-----|
| A | `jwt-alg-none` | alg=none 攻撃 | Critical | CWE-345 |
| B | `jwt-weak-secret-bruteforce` | HS256 弱秘密鍵ブルートフォース | High | CWE-326 |
| C | `jwt-signature-stripping` | 署名ストリッピング | Critical | CWE-347 |
| D | `jwt-kid-injection` | kid ヘッダインジェクション | High | CWE-22, CWE-90 |

各シナリオは `server/routes/attack-jwt.ts` (新規作成) で処理され、
フロントエンドは `src/components/auth/attacks/jwt/` 配下のコンポーネントで表示する。

---

## 2. 攻撃シナリオ一覧テーブル

| シナリオ ID | 攻撃名 | CWE | CAPEC | OSI 層 | 深刻度 | 難易度 |
|------------|--------|-----|-------|--------|--------|--------|
| `jwt-alg-none` | alg=none 署名バイパス | CWE-345 | CAPEC-196 | L7 | Critical | 2 |
| `jwt-weak-secret-bruteforce` | HS256 弱秘密鍵ブルートフォース | CWE-326, CWE-307 | CAPEC-49 | L7 | High | 2 |
| `jwt-signature-stripping` | 署名ストリッピング (decode-only) | CWE-347 | CAPEC-196 | L7 | Critical | 1 |
| `jwt-kid-injection` | kid ヘッダインジェクション | CWE-22, CWE-90 | CAPEC-88 | L7 | High | 3 |

**難易度 (1=易〜5=難)** はシナリオの技術的複雑さを表す。

---

## 3. 既存防御側実装

### 3.1 `server/routes/jwt-ops.ts` の現状

既存の `jwt-ops.ts` は以下の実装を持つ。

```typescript
// Demo secrets (visible for educational purposes)
const HS256_SECRET = "osi-demo-secret-key-for-hs256-signing";

const ALLOWED_ALGORITHMS = ["HS256", "RS256"] as const;
type AllowedAlgorithm = (typeof ALLOWED_ALGORITHMS)[number];
```

`POST /api/jwt/verify` は次のように `algorithms` オプションを明示指定している:

```typescript
const decoded = jwt.verify(token, secret, { algorithms: [algorithm as jwt.Algorithm] });
```

### 3.2 `ALLOWED_ALGORITHMS` 許可リストの重要性

`ALLOWED_ALGORITHMS = ["HS256", "RS256"]` は **許可リスト (allowlist)** として機能する。
`jsonwebtoken` ライブラリの `verify()` に `algorithms` オプションを渡すことで、
ライブラリが許可リスト外のアルゴリズム (特に `"none"`) を受理することを防ぐ。

このガードが **ない** 場合 (またはライブラリが古い場合) に成立する攻撃が
本設計書のシナリオ A「alg=none 攻撃」および C「署名ストリッピング」である。

| 実装パターン | 攻撃 A 耐性 | 攻撃 C 耐性 |
|------------|-----------|-----------|
| `jwt.verify(token, secret, { algorithms: ["HS256"] })` | あり | あり |
| `jwt.verify(token, secret)` (algorithms 省略) | **なし** | 条件付き |
| `jwt.decode(token)` のみ (verify 省略) | **なし** | **なし** |

> **教材ポイント**: 攻撃デモでは「脆弱検証エンドポイント」と「堅牢検証エンドポイント」を
> 別々のサーバーサイドハンドラとして実装し、同じ改竄トークンに対する応答の差を並列比較する。

### 3.3 `POST /api/jwt/decode` のアンチパターン

既存の `/decode` エンドポイントは `jwt.decode()` のみを使用しており、
レスポンスに `"Decoded WITHOUT verification!"` という警告を含む。
この「検証なしデコード」が署名ストリッピング (シナリオ C) の脆弱実装例として機能する。

---

## 4. シナリオ詳細

---

### 4.1 シナリオ A: alg=none 攻撃

**シナリオ ID**: `jwt-alg-none`

#### 4.1.1 概要

これは **CWE-345 / CAPEC-196** の概念実証である。
JWT ヘッダの `alg` フィールドを `"none"` に書き換え、署名部を空文字列にすることで、
`algorithms` オプションを明示しない (または古い) JWT 検証ライブラリを騙し、
署名なしのトークンを有効と判定させる攻撃手法をシミュレーションする。

#### 4.1.2 CWE / CAPEC

| 項目 | 値 |
|-----|-----|
| CWE | CWE-345 (Insufficient Verification of Data Authenticity) |
| CAPEC | CAPEC-196 (Session Credential Falsification through Forging) |
| OSI 層 | L7 (アプリケーション層) |
| 深刻度 | Critical |

#### 4.1.3 前提条件

- 攻撃者は有効な JWT トークンを1つ入手済み (傍受・漏洩・正規登録いずれでも可)
- ターゲットサーバーの JWT 検証が `algorithms` オプションを明示していない、
  またはライブラリが `alg=none` を許容する旧バージョンである

#### 4.1.4 AttackStep[] 具体例

```typescript
const steps: AttackStep[] = [
  {
    id: "alg-none-1",
    kind: "probe",
    label: "Decode original JWT header",
    labelJa: "元 JWT ヘッダをデコード",
    status: "success",
    payload: {
      type: "token",
      before: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzZWVkX2FsaWNlIiwicm9sZSI6InZpZXdlciIsImlhdCI6MTcxNDAwMDAwMCwiZXhwIjoxNzE0MDAzNjAwfQ.HMAC_SIGNATURE_HERE",
      algo: "HS256",
      decodedHeader: { alg: "HS256", typ: "JWT" },
      decodedPayload: { sub: "seed_alice", role: "viewer", iat: 1714000000, exp: 1714003600 },
    },
    detail: "Base64url decode the first segment to read the algorithm field.",
    detailJa: "最初のセグメントを Base64url デコードして alg フィールドを確認します。",
    timestamp: Date.now(),
  },
  {
    id: "alg-none-2",
    kind: "tamper",
    label: "Rewrite alg='none' and escalate role to admin",
    labelJa: "alg='none' に書き換え、role を admin に昇格",
    status: "success",
    payload: {
      type: "token",
      before: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
      after:  "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0",
      algo: "none",
      decodedHeader: { alg: "none", typ: "JWT" },
      decodedPayload: { sub: "seed_alice", role: "admin", iat: 1714000000, exp: 1714003600 },
    },
    detail: "Set alg to 'none' in header. Re-encode payload with role=admin.",
    detailJa: "ヘッダの alg を 'none' に変更し、ペイロードの role を admin に書き換えて再エンコードします。",
    timestamp: Date.now(),
  },
  {
    id: "alg-none-3",
    kind: "forge",
    label: "Drop signature segment (keep trailing dot)",
    labelJa: "署名セグメントを削除 (末尾ドットを維持)",
    status: "success",
    payload: {
      type: "token",
      before: "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4ifQ.HMAC_REMOVED",
      after:  "eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.",
      algo: "none",
      signatureValid: false,
    },
    detail: "alg=none tokens must have an empty signature. The trailing dot is required by the JWT spec.",
    detailJa: "alg=none トークンは空の署名セグメントが必要です。末尾のドットは JWT 仕様で必須です。",
    timestamp: Date.now(),
  },
  {
    id: "alg-none-4",
    kind: "exploit",
    label: "Send forged token to lenient verifier",
    labelJa: "偽造トークンを脆弱検証エンドポイントに送信",
    status: "success",
    payload: {
      type: "http",
      request: {
        method: "POST",
        url: "/api/jwt/attack/alg-none",
        headers: { "Content-Type": "application/json" },
        body: {
          forgedToken: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJzZWVkX2FsaWNlIiwicm9sZSI6ImFkbWluIn0.",
          mode: "lenient",
        },
      },
      response: {
        status: 200,
        body: {
          outcome: "succeeded",
          decoded: { sub: "seed_alice", role: "admin" },
          message: "このシナリオでは algorithms オプションが省略されているため、alg=none が受理されました。",
        },
      },
    },
    detail: "The lenient endpoint calls jwt.verify() without specifying algorithms, accepting alg=none.",
    detailJa: "脆弱なエンドポイントは algorithms オプションなしで jwt.verify() を呼ぶため、alg=none を受け入れます。",
    timestamp: Date.now(),
  },
  {
    id: "alg-none-5",
    kind: "verify",
    label: "Send same forged token to strict verifier",
    labelJa: "同じ偽造トークンを堅牢検証エンドポイントに送信",
    status: "blocked",
    payload: {
      type: "http",
      request: {
        method: "POST",
        url: "/api/jwt/attack/alg-none",
        headers: { "Content-Type": "application/json" },
        body: {
          forgedToken: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJzZWVkX2FsaWNlIiwicm9sZSI6ImFkbWluIn0.",
          mode: "strict",
        },
      },
      response: {
        status: 401,
        body: {
          outcome: "blocked",
          blockedBy: "jwt_algorithms_allowlist",
          error: "invalid algorithm",
          message: "防御が機能しました: algorithms 許可リストが alg=none を拒否しました。",
        },
      },
    },
    detail: "The strict endpoint passes { algorithms: ['HS256', 'RS256'] } to jwt.verify(), rejecting none.",
    detailJa: "堅牢なエンドポイントは jwt.verify() に { algorithms: ['HS256', 'RS256'] } を渡し、none を拒否します。",
    timestamp: Date.now(),
  },
];
```

#### 4.1.5 期待結果 (E-2: 5 ステップ完全形 + 両モード並列実行)

1 リクエストで両モード (脆弱+堅牢) を並列実行し、5 ステップを返す。
`outcome` は両モードが揃って実行されたことを示すため常に `"succeeded"` (HTTP 200)。
モード別の結果はステップ 4 (脆弱) と ステップ 5 (堅牢) の `status` で判別する。

| HTTP status | outcome | ステップ 4 (exploit, 脆弱) | ステップ 5 (verify, 堅牢) | blockedBy |
|------------|---------|---------------------------|---------------------------|-----------|
| 200 | `succeeded` | `status: "success"` (alg=none 受理) | `status: "blocked"` (allowlist 拒否) | `"jwt_algorithms_allowlist"` |

#### 4.1.6 防御策

1. **`algorithms` 許可リストを必ず指定**: `jwt.verify(token, secret, { algorithms: ["HS256"] })`
2. **`"none"` アルゴリズムを明示的に拒否**: ライブラリバージョンに依存しない防御
3. **ライブラリを最新に保つ**: `jsonwebtoken` v9.0.0 以降はデフォルトで `none` を拒否
4. **RFC 7518 §3.6 に従い、`alg=none` は署名が不要なケース (暗号化済みJWE) のみ許可**

> 実環境では現代のほとんどの JWT ライブラリはデフォルトで none を拒否するよう更新されています。
> このデモは `algorithms` オプション省略というアンチパターンが依然として危険であることを示します。

#### 4.1.7 API 契約 (E-2 / E-1)

```
POST /api/jwt/attack/alg-none
Content-Type: application/json

Request:
{}    // 不要 (両モード並列実行のためモード選択フィールドなし。
      //  未知のフィールドは zod が silently 削除し旧契約クライアント互換)

Response (200 OK 固定):
{
  "success": true,
  "data": {
    "scenarioId": "jwt-alg-none",
    "outcome": "succeeded",        // E-2: 両モード実行のため常に succeeded
    "startedAt": number,
    "finishedAt": number,
    "steps": AttackStep[],          // 5 ステップ完全形 (probe → tamper → forge → exploit → verify)
    "blockedBy": "jwt_algorithms_allowlist",  // 堅牢モードの防御指標 (常に格納)
    "summary": string,
    "summaryJa": string,
    "logId": number
    // E-1: alg-none は extra なし (AttackResult のデフォルト Record<string, never>)
  },
  "_trace": {
    "cryptoOps": CryptoOp[],
    "attackSteps": AttackStep[],    // data.steps と同じ 5 件 (timestamp 共有)
    "isAttackMode": true             // /attack/ パス検出で middleware が自動付与
  }
}
```

> **テスト用オプション (E01)**: 全攻撃ルートはハンドラ本体が実際に参照するフィールド (例: kid-injection の `injectedKid`、
> signature-stripping の `forgedToken`) のみ schema にオプションで残す。alg-none は外部入力を必要としないため
> リクエスト body は空でよい (旧契約の `originalToken` / `victim.strict` は ROB-FIND-006 で削除済み)。

#### 4.1.8 `_trace` 内訳

| 操作 | kind | 説明 |
|------|------|------|
| `base64url.decode(header)` | CryptoOp | 元ヘッダのデコード |
| `base64url.encode(forged-header)` | CryptoOp | 改竄ヘッダの再エンコード |
| `base64url.encode(forged-payload)` | CryptoOp | ペイロード (role=admin) の再エンコード |
| `jwt.verify(lenient)` | CryptoOp | algorithms 省略での検証 → PASS |
| `jwt.verify(strict)` | CryptoOp | algorithms=["HS256","RS256"] での検証 → FAIL |
| `INSERT attack_log` | DbQuery | 実行履歴の保存 |

#### 4.1.9 UI フロー

1. `ViewModeToggle` で Attacker View に切り替え
2. シナリオセレクタで `jwt-alg-none` を選択
3. `EducationalWarningBanner` が最上部に固定表示
4. 「このシナリオでは `algorithms` 検証が省略されているため、署名バイパスが成立しました」説明文
5. [実行] ボタンで `AttackStepTimeline` がステップ 1〜5 を順番にアニメーション表示
6. ステップ 4: 脆弱側 → `status: "success"` (赤)、ステップ 5: 堅牢側 → `status: "blocked"` (緑)
7. `AttackDefensePanel` が自動展開: ALLOWED_ALGORITHMS の実装例コードを表示
8. `DataFlowPanel` で HTTP exchange と `_trace` の CryptoOp を確認可能

#### 4.1.10 i18n キー

| キー | 日本語 | 英語 |
|-----|--------|------|
| `attack.jwt.algNone.title` | alg=none 攻撃 | Algorithm None Attack |
| `attack.jwt.algNone.desc` | これは CWE-345 の概念実証です。alg フィールドを none に書き換えることで、署名検証なしにサーバーを騙すことができる状況をシミュレーションします。 | This is a proof-of-concept for CWE-345. It simulates rewriting the alg field to none to bypass signature verification. |
| `attack.jwt.algNone.stepDecode` | 元 JWT ヘッダをデコード | Decode original JWT header |
| `attack.jwt.algNone.stepTamper` | alg を none に改竄・role を admin に昇格 | Rewrite alg=none, escalate role to admin |
| `attack.jwt.algNone.stepForge` | 署名セグメントを削除 | Drop signature segment |
| `attack.jwt.algNone.stepExploit` | 脆弱検証エンドポイントに送信 | Send to lenient verifier |
| `attack.jwt.algNone.stepVerify` | 堅牢検証エンドポイントに送信 | Send to strict verifier |
| `attack.jwt.algNone.succeeded` | この実装は脆弱です: algorithms 省略により alg=none が受理されました。 | This implementation is vulnerable: alg=none accepted due to missing algorithms option. |
| `attack.jwt.algNone.blocked` | 防御が機能しました: algorithms 許可リストが alg=none を拒否しました。 | Defense worked: algorithms allowlist rejected alg=none. |
| `attack.jwt.algNone.realworld` | 現代のほとんどの JWT ライブラリはデフォルトで none を拒否するよう更新されています。 | Most modern JWT libraries now reject none by default. |

---

### 4.2 シナリオ B: HS256 弱秘密鍵ブルートフォース

**シナリオ ID**: `jwt-weak-secret-bruteforce`

#### 4.2.1 概要

これは **CWE-326 / CAPEC-49** の概念実証である。
HS256 の秘密鍵が辞書語 (`"secret"`, `"password"`, `"123456"` 等) である場合、
攻撃者はトークン1つを入手するだけでオフライン総当り攻撃が可能になることをシミュレーションする。
十分な長さのランダム秘密鍵では同じ辞書が通用しないことを対比表示する。

#### 4.2.2 CWE / CAPEC

| 項目 | 値 |
|-----|-----|
| CWE | CWE-326 (Inadequate Encryption Strength), CWE-307 (Improper Restriction of Excessive Authentication Attempts) |
| CAPEC | CAPEC-49 (Password Brute Forcing) |
| OSI 層 | L7 (アプリケーション層) |
| 深刻度 | High |

#### 4.2.3 前提条件

- 攻撃者は HS256 で署名された有効な JWT を1つ入手済み
- サーバーの秘密鍵が辞書語 (短い英単語・数字列) である
- 攻撃はサーバーへの接続なし、オフラインで実行可能 (HMAC-SHA256 の計算のみ)

#### 4.2.4 AttackStep[] 具体例

```typescript
const steps: AttackStep[] = [
  {
    id: "brute-1",
    kind: "intercept",
    label: "Capture HS256 JWT token",
    labelJa: "HS256 JWT トークンを入手",
    status: "success",
    payload: {
      type: "token",
      before: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzZWVkX2FsaWNlIiwicm9sZSI6ImFkbWluIn0.WEAK_HMAC_SIG",
      algo: "HS256",
      decodedHeader: { alg: "HS256", typ: "JWT" },
      decodedPayload: { sub: "seed_alice", role: "admin" },
    },
    detail: "Attacker obtains a signed HS256 token. Signing input is public (header.payload).",
    detailJa: "攻撃者は HS256 署名済みトークンを入手します。署名入力 (header.payload) は公開情報です。",
    timestamp: Date.now(),
  },
  {
    id: "brute-2",
    kind: "probe",
    label: "Begin offline dictionary attack (100 candidates)",
    labelJa: "オフライン辞書攻撃を開始 (100 候補)",
    status: "success",
    payload: {
      type: "generic",
      data: {
        dictionary: ["secret", "password", "123456", "jwt-secret", "mysecret", "token", "admin", "qwerty", "letmein", "..."],
        totalCandidates: 100,
        targetAlgo: "HMAC-SHA256",
        serverConnectionRequired: false,
        note: "オフライン攻撃のため、サーバーへの接続は不要です。",
      },
    },
    detail: "HMAC-SHA256 can be computed locally. No server requests needed.",
    detailJa: "HMAC-SHA256 はローカルで計算できます。サーバーへのリクエストは不要です。",
    timestamp: Date.now(),
  },
  {
    id: "brute-3",
    kind: "exploit",
    label: "Match found: weak secret cracked",
    labelJa: "一致発見: 弱い秘密鍵がクラックされました",
    status: "success",
    payload: {
      type: "credential",
      crackedPassword: "secret",
      triedPasswords: ["admin", "password", "123456", "secret"],
    },
    detail: "HMAC-SHA256(header.payload, 'secret') matches the token signature.",
    detailJa: "HMAC-SHA256(header.payload, 'secret') がトークン署名と一致しました。",
    timestamp: Date.now(),
  },
  {
    id: "brute-4",
    kind: "forge",
    label: "Re-sign token with cracked secret (role=admin)",
    labelJa: "クラックした秘密鍵で新規トークン署名 (role=admin)",
    status: "success",
    payload: {
      type: "token",
      after: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhdHRhY2tlcl9jaGFybGllIiwicm9sZSI6ImFkbWluIn0.NEW_VALID_HMAC",
      algo: "HS256",
      decodedPayload: { sub: "attacker_charlie", role: "admin" },
      signatureValid: true,
    },
    detail: "With the secret known, attacker can forge any payload with a valid signature.",
    detailJa: "秘密鍵が判明すれば、任意のペイロードで有効な署名を生成できます。",
    timestamp: Date.now(),
  },
  {
    id: "brute-5",
    kind: "verify",
    label: "Strong random secret resists dictionary (all 100 fail)",
    labelJa: "十分なランダム秘密鍵では辞書が通用しない (100件全て失敗)",
    status: "blocked",
    payload: {
      type: "generic",
      data: {
        strongSecret: "osi-demo-secret-key-for-hs256-signing (38文字のランダム文字列)",
        triedCandidates: 100,
        matched: 0,
        conclusion: "防御が機能しました: 十分な長さのランダム秘密鍵はブルートフォースに耐性があります。",
      },
    },
    detail: "A 38-char random secret is not in any dictionary. Brute force fails.",
    detailJa: "38文字のランダム文字列はいかなる辞書にも含まれません。ブルートフォースは失敗します。",
    timestamp: Date.now(),
  },
];
```

#### 4.2.5 期待結果 (E-2: 5 ステップ完全形 + 両モード並列実行)

1 リクエストで弱秘密鍵 (`"secret"`) と強秘密鍵 (HS256_SECRET = 38 文字ランダム) を両方ループする。
ステップ 4 (forge) で弱側のクラック結果を、ステップ 5 (verify) で強側の防御結果を返す。

| HTTP status | outcome | ステップ 4 (forge, 弱秘密鍵) | ステップ 5 (verify, 強秘密鍵) | extra | blockedBy |
|------------|---------|----------------------------|------------------------------|-------|-----------|
| 200 | `succeeded` | `status: "success"` (1 件目=`"secret"` で一致) | `status: "blocked"` (全 100 件失敗) | `{ crackedSecret: "secret", attemptCount: 1 }` | `"strong_random_secret"` |

> **ROB-FIND-010**: 強秘密鍵が辞書に含まれている場合 (HS256_SECRET 設定ミス) はステップ 5 を `status: "failed"`
> + 警告ラベル「strong secret unexpectedly cracked at "X"」で記録し、防御失敗を可視化する。

#### 4.2.6 防御策

1. **秘密鍵は最低256ビット (32バイト) 以上のランダム値を使用**: `crypto.randomBytes(32).toString("hex")`
2. **辞書語・短い文字列を鍵に使わない**: 辞書攻撃は秒単位で成立する
3. **RS256 / ES256 への移行を検討**: 秘密鍵 (署名鍵) を公開鍵と分離する非対称鍵方式を使うと、トークンを入手しても秘密鍵の総当りが困難になる
4. **鍵のローテーション**: 定期的に秘密鍵を変更し、古いトークンを無効化する

> 実環境では IP レート制限・WAF・アカウントロックアウトにより、
> オンラインブルートフォースは阻止されます。ただし HS256 のオフライン攻撃は
> サーバーへの接続なしに実行できるため、弱い秘密鍵は致命的なリスクです。

#### 4.2.7 API 契約 (E-2 / E-1)

```
POST /api/jwt/attack/weak-secret-bruteforce
Content-Type: application/json

Request:
{
  "dictionarySize"?: number   // 辞書サイズ (デフォルト 100, 最大 200)
                              // E-2: secretType / targetToken は廃止 (両モード並列実行のため不要)
}

Response (200 OK 固定):
{
  "success": true,
  "data": {
    "scenarioId": "jwt-weak-secret-bruteforce",
    "outcome": "succeeded",        // E-2: 両モード実行のため常に succeeded
    "startedAt": number,
    "finishedAt": number,
    "steps": AttackStep[],          // 5 ステップ (intercept → probe → exploit → forge → verify)
    "blockedBy": "strong_random_secret",  // 堅牢モード (強秘密鍵) の防御指標
    "summary": string,
    "summaryJa": string,
    "logId": number,
    // E-1: シナリオ固有の追加フィールドは extra 配下に格納
    "extra": {
      "crackedSecret": string | null,  // 弱秘密鍵側でクラックされた秘密鍵 (表示用、平文)
      "attemptCount": number            // 弱秘密鍵側で何件目に発見されたか
    }
  },
  "_trace": {
    "cryptoOps": CryptoOp[],
    "attackSteps": AttackStep[],
    "isAttackMode": true
  }
}
```

> **簡略化の注意**: ブルートフォースループは **サーバー側** で実行し、結果のみを返す。
> フロントエンドで実際の HMAC 計算ループは行わない (04-safety-guardrails.md §1.3 準拠)。
> **SEC FINDING-5**: `extra.crackedSecret` は教育表示用に平文で返すが、
> `attack_log.payload_json` には `maskSecret()` 経由でマスク化された値のみ保存する (DB 漏洩耐性)。

#### 4.2.8 `_trace` 内訳

| 操作 | kind | 説明 |
|------|------|------|
| `HMAC-SHA256 dictionary trial (N attempts)` | CryptoOp | 辞書攻撃の試行サマリー |
| `HMAC-SHA256 verify(crackedSecret)` | CryptoOp | 一致した秘密鍵での最終検証 |
| `jwt.sign(forgedPayload, crackedSecret)` | CryptoOp | 偽造トークンの署名 (succeeded 時) |
| `INSERT attack_log` | DbQuery | 実行履歴の保存 |

#### 4.2.9 UI フロー

1. Attacker View に切り替え → `EducationalWarningBanner` 表示
2. シナリオセレクタで `jwt-weak-secret-bruteforce` を選択
3. 「弱い秘密鍵」/「強い秘密鍵」の切替ラジオボタンで比較モードを選択
4. [実行] で `AttackStepTimeline` がステップ 1〜5 をアニメーション
5. ステップ 3 で辞書の試行状況をプログレス表示 (試行中は `status: "running"`)
6. 結果バナーに「クラックまでの試行数: N 件」または「全 100 件失敗」を表示
7. `AttackDefensePanel`: 強固な秘密鍵生成コード (`crypto.randomBytes`) を表示

#### 4.2.10 i18n キー

| キー | 日本語 | 英語 |
|-----|--------|------|
| `attack.jwt.weakSecret.title` | HS256 弱秘密鍵ブルートフォース | HS256 Weak Secret Brute Force |
| `attack.jwt.weakSecret.desc` | これは CWE-326 の概念実証です。HS256 の秘密鍵が辞書語の場合、トークンを入手するだけでオフライン総当りが可能になります。 | This is a proof-of-concept for CWE-326. If the HS256 secret is a dictionary word, an attacker can crack it offline. |
| `attack.jwt.weakSecret.stepCapture` | HS256 JWT トークンを入手 | Capture HS256 JWT token |
| `attack.jwt.weakSecret.stepDict` | オフライン辞書攻撃を開始 | Begin offline dictionary attack |
| `attack.jwt.weakSecret.stepCracked` | 弱い秘密鍵がクラックされました | Weak secret cracked |
| `attack.jwt.weakSecret.stepForge` | クラックした秘密鍵で新規トークンを署名 | Re-sign token with cracked secret |
| `attack.jwt.weakSecret.stepStrong` | 強い秘密鍵では辞書が通用しない | Strong secret resists dictionary |
| `attack.jwt.weakSecret.succeeded` | この実装は脆弱です: 秘密鍵 "secret" は辞書 N 件目で発見されました。 | This implementation is vulnerable: secret found in dictionary at attempt N. |
| `attack.jwt.weakSecret.blocked` | 防御が機能しました: 十分な長さのランダム秘密鍵はブルートフォースに耐性があります。 | Defense worked: strong random secret resists brute force. |
| `attack.jwt.weakSecret.realworld` | 実環境では IP レート制限により、オンラインブルートフォースは阻止されます。ただし HS256 のオフライン攻撃はサーバーへの接続なしに実行できます。 | In real environments, online brute force is blocked by rate limiting. However, HS256 offline attacks require no server connection. |

---

### 4.3 シナリオ C: 署名ストリッピング

**シナリオ ID**: `jwt-signature-stripping`

#### 4.3.1 概要

これは **CWE-347 / CAPEC-196** の概念実証である。
一部のアプリケーションで `jsonwebtoken` の `decode()` (署名検証なし) と `verify()` (署名検証あり) を
混同し、`decode()` の戻り値を信頼するアンチパターンが存在する。
本シナリオでは「decode だけ」と「verify する」の挙動差を比較し、
`decode()` のみを使った認証が攻撃者にとってどれほど容易に突破できるかをシミュレーションする。

#### 4.3.2 CWE / CAPEC

| 項目 | 値 |
|-----|-----|
| CWE | CWE-347 (Improper Verification of Cryptographic Signature) |
| CAPEC | CAPEC-196 (Session Credential Falsification through Forging) |
| OSI 層 | L7 (アプリケーション層) |
| 深刻度 | Critical |

#### 4.3.3 前提条件

- ターゲットの認証ロジックが `jwt.decode()` の結果を信頼 (verify を呼ばない)
- 攻撃者は任意の JWT ヘッダ・ペイロードを構成できる (署名は不正でも可)

#### 4.3.4 AttackStep[] 具体例

```typescript
const steps: AttackStep[] = [
  {
    id: "strip-1",
    kind: "probe",
    label: "Inspect target: uses jwt.decode() without verify",
    labelJa: "ターゲット調査: jwt.decode() のみで verify を省略",
    status: "success",
    payload: {
      type: "generic",
      data: {
        vulnerableCode: "const user = jwt.decode(token); // verify() を呼ばずに信頼",
        secureCode: "const user = jwt.verify(token, secret, { algorithms: ['HS256'] });",
        antipatternReason: "decode() はヘッダ/ペイロードを Base64url 復号するだけで署名を検証しない",
      },
    },
    detail: "jwt.decode() only decodes — it never checks the signature. Any forged token passes.",
    detailJa: "jwt.decode() はデコードのみで、署名を一切検証しません。任意の偽造トークンが通過します。",
    timestamp: Date.now(),
  },
  {
    id: "strip-2",
    kind: "forge",
    label: "Craft token with invalid signature but elevated claims",
    labelJa: "無効な署名で管理者クレームを持つトークンを偽造",
    status: "success",
    payload: {
      type: "token",
      after: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhdHRhY2tlcl9jaGFybGllIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzE0MDAwMDAwfQ.INVALID_SIGNATURE_XXXXXXXX",
      algo: "HS256",
      decodedHeader: { alg: "HS256", typ: "JWT" },
      decodedPayload: { sub: "attacker_charlie", role: "admin", iat: 1714000000 },
      signatureValid: false,
    },
    detail: "Forge a token with role=admin. Signature is garbage, but decode() won't check it.",
    detailJa: "role=admin のトークンを偽造します。署名はでたらめですが、decode() は検証しません。",
    timestamp: Date.now(),
  },
  {
    id: "strip-3",
    kind: "exploit",
    label: "Submit forged token to decode-only endpoint",
    labelJa: "偽造トークンを decode-only エンドポイントに送信",
    status: "success",
    payload: {
      type: "http",
      request: {
        method: "POST",
        url: "/api/jwt/attack/signature-stripping",
        headers: { "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4ifQ.INVALID_SIG" },
        body: { mode: "decode-only" },
      },
      response: {
        status: 200,
        body: {
          outcome: "succeeded",
          decoded: { sub: "attacker_charlie", role: "admin" },
          message: "このシナリオでは decode() のみを使用しているため、無効な署名のトークンが受け入れられました。",
        },
      },
    },
    detail: "The decode-only endpoint accepts any token regardless of signature.",
    detailJa: "decode-only エンドポイントは署名に関わらず任意のトークンを受け入れます。",
    timestamp: Date.now(),
  },
  {
    id: "strip-4",
    kind: "verify",
    label: "Same token rejected by verify endpoint",
    labelJa: "同じトークンが verify エンドポイントで拒否される",
    status: "blocked",
    payload: {
      type: "http",
      request: {
        method: "POST",
        url: "/api/jwt/attack/signature-stripping",
        headers: { "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4ifQ.INVALID_SIG" },
        body: { mode: "verify" },
      },
      response: {
        status: 401,
        body: {
          outcome: "blocked",
          blockedBy: "jwt_signature_mismatch",
          error: "invalid signature",
          message: "防御が機能しました: jwt.verify() が署名の不一致を検出しました。",
        },
      },
    },
    detail: "jwt.verify() detects the signature mismatch and throws JsonWebTokenError.",
    detailJa: "jwt.verify() が署名の不一致を検出し、JsonWebTokenError をスローします。",
    timestamp: Date.now(),
  },
];
```

#### 4.3.5 期待結果 (E-2: 5 ステップ完全形 + 両モード並列実行)

| HTTP status | outcome | ステップ 4 (exploit, decode-only) | ステップ 5 (verify, jwt.verify) | blockedBy |
|------------|---------|-----------------------------------|-------------------------------|-----------|
| 200 | `succeeded` | `status: "success"` (decode で受理) または `status: "failed"` (壊れたトークンで decode null) | `status: "blocked"` (署名不一致拒否) | `"jwt_signature_mismatch"` |

> **ROB-FIND-003**: `forgedToken` が構造的に壊れている (Base64url 不正、ピリオド数不一致等) 場合、
> `jwt.decode()` は null を返すため、ステップ 4 は `status: "failed"` で記録される。
> 教育的整合性を保つため "success" と取り違えない。

#### 4.3.6 防御策

1. **常に `jwt.verify()` を使う**: `jwt.decode()` は署名を検証しないため、認証に使ってはならない
2. **`decode()` の用途を限定**: ロギング・デバッグ目的のみ (既存 `/api/jwt/decode` の警告メッセージが正しい設計)
3. **TypeScript の型チェックを活用**: `verify()` の戻り値を `JwtPayload` 型として扱い、`decode()` の結果とは型を分ける
4. **コードレビューで確認**: `jwt.decode(` の使用箇所を必ずレビューし、verify を省略していないか確認する

#### 4.3.7 API 契約 (E-2)

```
POST /api/jwt/attack/signature-stripping
Content-Type: application/json

Request:
{
  "forgedToken"?: string    // テスト用オプション (E01)。省略時は無効署名の Admin トークンを
                            // サーバ側で自動生成。E-2 で mode フィールドは廃止 (両モード並列実行)。
}

Response (200 OK 固定):
{
  "success": true,
  "data": {
    "scenarioId": "jwt-signature-stripping",
    "outcome": "succeeded",        // E-2: 両モード実行のため常に succeeded
    "startedAt": number,
    "finishedAt": number,
    "steps": AttackStep[],          // 5 ステップ (probe → tamper → forge → exploit → verify)
    "blockedBy": "jwt_signature_mismatch",
    "summary": string,
    "summaryJa": string,
    "logId": number
    // E-1: signature-stripping は extra なし
  },
  "_trace": {
    "cryptoOps": CryptoOp[],
    "attackSteps": AttackStep[],
    "isAttackMode": true
  }
}
```

#### 4.3.8 `_trace` 内訳

| 操作 | kind | 説明 |
|------|------|------|
| `jwt.decode(forgedToken)` | CryptoOp | 署名検証なしデコード → 成功 |
| `jwt.verify(forgedToken, secret)` | CryptoOp | 署名検証 → JsonWebTokenError |
| `INSERT attack_log` | DbQuery | 実行履歴の保存 |

#### 4.3.9 UI フロー

1. Attacker View に切り替え → バナー表示
2. シナリオセレクタで `jwt-signature-stripping` を選択
3. 左パネル: `decode()` のみのコード、右パネル: `verify()` を使うコードをサイドバイサイド表示
4. [実行] で `AttackStepTimeline` がステップ 1〜4 を順番に実行
5. ステップ 3 と 4 の結果を左右で対比する結果バナー表示
6. `AttackDefensePanel`: `decode()` と `verify()` の違いのコードスニペット比較を表示

#### 4.3.10 i18n キー

| キー | 日本語 | 英語 |
|-----|--------|------|
| `attack.jwt.sigStrip.title` | 署名ストリッピング | Signature Stripping |
| `attack.jwt.sigStrip.desc` | これは CWE-347 の概念実証です。jwt.decode() のみを使って認証する実装は、任意の偽造トークンを受け入れてしまいます。 | This is a proof-of-concept for CWE-347. Implementations that only call jwt.decode() accept any forged token. |
| `attack.jwt.sigStrip.stepProbe` | ターゲットが decode() のみを使用していることを調査 | Inspect target uses decode() only |
| `attack.jwt.sigStrip.stepForge` | 無効な署名のトークンを偽造 | Forge token with invalid signature |
| `attack.jwt.sigStrip.stepExploit` | decode-only エンドポイントに送信 | Submit to decode-only endpoint |
| `attack.jwt.sigStrip.stepVerify` | verify エンドポイントで拒否される | Rejected by verify endpoint |
| `attack.jwt.sigStrip.succeeded` | この実装は脆弱です: decode() のみを使用しているため、無効な署名のトークンが受け入れられました。 | This implementation is vulnerable: decode() accepts tokens with invalid signatures. |
| `attack.jwt.sigStrip.blocked` | 防御が機能しました: jwt.verify() が署名の不一致を検出しました。 | Defense worked: jwt.verify() detected signature mismatch. |

---

### 4.4 シナリオ D: kid ヘッダインジェクション

**シナリオ ID**: `jwt-kid-injection`

#### 4.4.1 概要

これは **CWE-22 / CWE-90 / CAPEC-88** の概念実証である。
JWT の `kid` (Key ID) ヘッダパラメータは、複数の鍵を管理する場合にどの鍵を使うかを指示するためのものである。
ターゲットの実装が `kid` の値をファイルパスまたは SQL クエリに直接結合する場合、
攻撃者は `kid` に `"../public/attacker-key.pem"` のようなパストラバーサル文字列や
SQL インジェクション文字列を埋め込み、攻撃者が制御する鍵で署名を検証させることができる。

#### 4.4.2 CWE / CAPEC

| 項目 | 値 |
|-----|-----|
| CWE | CWE-22 (Improper Limitation of a Pathname to a Restricted Directory — Path Traversal), CWE-90 (Improper Neutralization of Special Elements used in an LDAP Query) |
| CAPEC | CAPEC-88 (OS Command Injection) |
| OSI 層 | L7 (アプリケーション層) |
| 深刻度 | High |

#### 4.4.3 前提条件

- ターゲットの JWT 検証が `kid` ヘッダをサニタイズせずにファイルパスや DB クエリに使用している
- 攻撃者はターゲットサーバーのファイルシステム構成、または DB の `keys` テーブルスキーマを推測できる
- 攻撃者は自身が生成した鍵ペアを持っており、特定のパスに配置できる (または DB に挿入できる) 状況

#### 4.4.4 AttackStep[] 具体例

```typescript
const steps: AttackStep[] = [
  {
    id: "kid-1",
    kind: "probe",
    label: "Inspect JWT header for kid field",
    labelJa: "JWT ヘッダの kid フィールドを確認",
    status: "success",
    payload: {
      type: "token",
      before: "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0xIn0.eyJzdWIiOiJzZWVkX2FsaWNlIn0.RS256_SIG",
      algo: "RS256",
      decodedHeader: { alg: "RS256", kid: "key-1", typ: "JWT" },
      decodedPayload: { sub: "seed_alice", role: "viewer" },
    },
    detail: "The kid field instructs the server which key to use for verification.",
    detailJa: "kid フィールドはサーバーに検証に使う鍵を指示します。",
    timestamp: Date.now(),
  },
  {
    id: "kid-2",
    kind: "tamper",
    label: "Inject path traversal in kid header",
    labelJa: "kid ヘッダにパストラバーサルを注入",
    status: "success",
    payload: {
      type: "token",
      before: "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0xIn0",
      after:  "eyJhbGciOiJSUzI1NiIsImtpZCI6Ii4uL3B1YmxpYy9hdHRhY2tlci1rZXkucGVtIn0",
      decodedHeader: { alg: "RS256", kid: "../public/attacker-key.pem", typ: "JWT" },
      algo: "RS256",
    },
    detail: "Attacker replaces kid with '../public/attacker-key.pem' — a path traversal payload.",
    detailJa: "攻撃者は kid を '../public/attacker-key.pem' に置き換えます — パストラバーサルペイロードです。",
    timestamp: Date.now(),
  },
  {
    id: "kid-3",
    kind: "forge",
    label: "Sign forged payload with attacker-controlled key",
    labelJa: "攻撃者制御の鍵で偽造ペイロードに署名",
    status: "success",
    payload: {
      type: "token",
      after: "eyJhbGciOiJSUzI1NiIsImtpZCI6Ii4uL3B1YmxpYy9hdHRhY2tlci1rZXkucGVtIn0.eyJzdWIiOiJhdHRhY2tlcl9jaGFybGllIiwicm9sZSI6ImFkbWluIn0.ATTACKER_RSA_SIG",
      algo: "RS256",
      decodedPayload: { sub: "attacker_charlie", role: "admin" },
      signatureValid: true,
    },
    detail: "Forged token is signed with attacker's private key. Server will load attacker-key.pem for verification.",
    detailJa: "偽造トークンは攻撃者の秘密鍵で署名されます。サーバーは attacker-key.pem を鍵として読み込みます。",
    timestamp: Date.now(),
  },
  {
    id: "kid-4",
    kind: "exploit",
    label: "Submit forged token to vulnerable kid endpoint",
    labelJa: "偽造トークンを脆弱 kid エンドポイントに送信",
    status: "success",
    payload: {
      type: "http",
      request: {
        method: "POST",
        url: "/api/jwt/attack/kid-injection",
        headers: { "Content-Type": "application/json" },
        body: {
          forgedToken: "eyJhbGciOiJSUzI1NiIsImtpZCI6Ii4uL3B1YmxpYy9hdHRhY2tlci1rZXkucGVtIn0.eyJyb2xlIjoiYWRtaW4ifQ.ATTACKER_SIG",
          mode: "vulnerable",
        },
      },
      response: {
        status: 200,
        body: {
          outcome: "succeeded",
          decoded: { sub: "attacker_charlie", role: "admin" },
          kidResolved: "../public/attacker-key.pem",
          message: "この実装は脆弱です: kid をサニタイズせずにファイルパスに使用しているため、攻撃者制御の鍵で検証が通りました。",
        },
      },
    },
    detail: "The server loads the key at the path derived from kid without sanitization.",
    detailJa: "サーバーはサニタイズなしに kid から派生したパスの鍵を読み込みます。",
    timestamp: Date.now(),
  },
  {
    id: "kid-5",
    kind: "verify",
    label: "Allowlist-protected endpoint rejects injected kid",
    labelJa: "許可リスト保護エンドポイントが注入 kid を拒否",
    status: "blocked",
    payload: {
      type: "http",
      request: {
        method: "POST",
        url: "/api/jwt/attack/kid-injection",
        body: { mode: "allowlist" },
      },
      response: {
        status: 401,
        body: {
          outcome: "blocked",
          blockedBy: "jwt_kid_not_in_allowlist",
          error: "unknown key id: ../public/attacker-key.pem",
          message: "防御が機能しました: kid 許可リスト検証が不正な kid を拒否しました。",
        },
      },
    },
    detail: "Allowlist validation: only 'key-1', 'key-2' are valid kids. Any other value is rejected.",
    detailJa: "許可リスト検証: 有効な kid は 'key-1', 'key-2' のみ。それ以外の値は拒否されます。",
    timestamp: Date.now(),
  },
];
```

#### 4.4.5 期待結果 (E-2: 5 ステップ完全形 + 両モード並列実行)

| HTTP status | outcome | ステップ 4 (exploit, 脆弱) | ステップ 5 (verify, allowlist) | extra | blockedBy |
|------------|---------|---------------------------|---------------------------------|-------|-----------|
| 200 | `succeeded` | `status: "success"` (kid をパスとして解決) | `status: "blocked"` (allowlist 拒否) | `{ kidResolved: "../public/attacker-key.pem" }` | `"jwt_kid_not_in_allowlist"` |

> **SEC FINDING-3**: ハンドラは `injectedKid` を `sanitizeForDisplay()` で制御文字除去 + 長さ制限してから
> `kidResolved` および `payload` 各所に格納する (XSS sink 防御深層)。
> **ROB-FIND-007**: 許可リストは `ReadonlySet<string>` 型で TypeScript 静的に変更不能化。

#### 4.4.6 防御策

1. **kid の許可リスト検証**: `kid` の値をファイルパスや SQL に渡す前に許可されたキー ID のセットと照合する
   ```typescript
   const ALLOWED_KID = new Set(["key-1", "key-2"]);
   if (!ALLOWED_KID.has(header.kid)) throw new Error("unknown key id");
   ```
2. **ファイルパスの結合に `path.resolve` + `path.startsWith` を使う**: パストラバーサルを防ぐ
3. **DB クエリにはプレースホルダーを使う**: `WHERE kid = ?` のようにパラメータ化クエリを使用
4. **kid を不透明な識別子として扱う**: パスや SQL に直接連結しない設計にする

#### 4.4.7 API 契約 (E-2 / E-1)

```
POST /api/jwt/attack/kid-injection
Content-Type: application/json

Request:
{
  "injectedKid"?: string    // テスト用オプション (E01)。省略時は "../public/attacker-key.pem"。
                            // E-2 で mode フィールドは廃止 (両モード並列実行)。
}

Response (200 OK 固定):
{
  "success": true,
  "data": {
    "scenarioId": "jwt-kid-injection",
    "outcome": "succeeded",        // E-2: 両モード実行のため常に succeeded
    "startedAt": number,
    "finishedAt": number,
    "steps": AttackStep[],          // 5 ステップ (probe → tamper → forge → exploit → verify)
    "blockedBy": "jwt_kid_not_in_allowlist",
    "summary": string,
    "summaryJa": string,
    "logId": number,
    // E-1: シナリオ固有の追加フィールドは extra 配下
    "extra": {
      "kidResolved": string         // sanitizeForDisplay で正規化済み
    }
  },
  "_trace": {
    "cryptoOps": CryptoOp[],
    "attackSteps": AttackStep[],
    "isAttackMode": true
  }
}
```

#### 4.4.8 `_trace` 内訳

| 操作 | kind | 説明 |
|------|------|------|
| `kid allowlist check` | CryptoOp | kid の許可リスト照合結果 |
| `fs.readFile(kidPath)` | CryptoOp | 脆弱モード: kid から派生したパスの鍵ファイル読み込み (シミュレーション) |
| `jwt.verify(token, attackerPublicKey)` | CryptoOp | 攻撃者制御の鍵での署名検証 |
| `INSERT attack_log` | DbQuery | 実行履歴の保存 |

#### 4.4.9 UI フロー

1. Attacker View に切り替え → バナー表示
2. シナリオセレクタで `jwt-kid-injection` を選択
3. `kid` 値の入力フォームを表示 (デフォルト値: `"../public/attacker-key.pem"`)
4. 「脆弱実装」/「許可リスト実装」の切替トグル
5. [実行] で `AttackStepTimeline` がステップ 1〜5 を順番にアニメーション
6. ステップ 2 で `kid` 改竄の before/after を diff 表示
7. `AttackDefensePanel`: `ALLOWED_KID` 許可リストのコードスニペットを表示

#### 4.4.10 i18n キー

| キー | 日本語 | 英語 |
|-----|--------|------|
| `attack.jwt.kidInject.title` | kid ヘッダインジェクション | kid Header Injection |
| `attack.jwt.kidInject.desc` | これは CWE-22 / CWE-90 の概念実証です。kid ヘッダをパストラバーサル文字列に書き換えて、攻撃者制御の鍵で署名検証を通す攻撃をシミュレーションします。 | This is a proof-of-concept for CWE-22 / CWE-90. Rewriting the kid header to a path traversal string tricks the server into verifying with an attacker-controlled key. |
| `attack.jwt.kidInject.stepProbe` | JWT ヘッダの kid フィールドを確認 | Inspect JWT header for kid field |
| `attack.jwt.kidInject.stepTamper` | kid ヘッダにパストラバーサルを注入 | Inject path traversal in kid header |
| `attack.jwt.kidInject.stepForge` | 攻撃者制御の鍵でトークンを署名 | Sign forged token with attacker key |
| `attack.jwt.kidInject.stepExploit` | 脆弱エンドポイントに送信 | Submit to vulnerable endpoint |
| `attack.jwt.kidInject.stepVerify` | 許可リスト保護エンドポイントで拒否 | Rejected by allowlist endpoint |
| `attack.jwt.kidInject.succeeded` | この実装は脆弱です: kid をサニタイズせずにファイルパスに使用しているため、攻撃者制御の鍵で検証が通りました。 | This implementation is vulnerable: kid used as file path without sanitization. |
| `attack.jwt.kidInject.blocked` | 防御が機能しました: kid 許可リスト検証が不正な kid を拒否しました。 | Defense worked: kid allowlist rejected the injected value. |

---

## 5. UI コンポーネント設計

### 5.1 ディレクトリ構造 (実装後の正本、Phase 1 + 第二コミットで確定)

```
src/components/auth/
├── JwtInspector.tsx                    # Defender View ↔ Attacker View 切替の親コンポーネント
└── attacks/
    ├── shared/
    │   ├── ViewModeToggle.tsx          # defender/attacker 切替トグル
    │   ├── AttackPanel.tsx             # 汎用シナリオセレクタ + 実行ボタン + 並列ラベル表示
    │   ├── AttackStepTimeline.tsx      # 5 ステップの時系列アニメーション
    │   ├── AttackResultBanner.tsx      # outcome / blockedBy / summary バナー
    │   ├── AttackDefensePanel.tsx      # 防御コードヒント + 既存ファイルリンク
    │   └── EducationalWarningBanner.tsx
    └── scenarios/
        └── jwt-scenarios.ts            # AttackScenarioMeta[] (4 シナリオの静的メタ)
```

> **D11 (旧設計との差分)**: シナリオ別コンポーネント (`JwtAlgNoneAttack.tsx` 等) は廃止。
> `AttackPanel` が `jwt-scenarios.ts` から `AttackScenarioMeta[]` を受け取り、選択シナリオに対して
> `runAttackScenario` ヘルパー経由のバックエンド呼び出しを共通化する。
> シナリオ固有のフォーム要素 (例: `injectedKid` 入力) は `AttackPanel` 内のシナリオ別 props で抽象化する。

### 5.2 `JwtAttackView.tsx` の責務

```typescript
// src/components/auth/attacks/jwt/JwtAttackView.tsx
import { createSignal } from "solid-js";
import { Show, For } from "solid-js";
import EducationalWarningBanner from "../../../shared/EducationalWarningBanner";
import ViewModeToggle from "../../../shared/ViewModeToggle";
import JwtAlgNoneAttack from "./JwtAlgNoneAttack";
import JwtWeakSecretAttack from "./JwtWeakSecretAttack";
import JwtSignatureStripping from "./JwtSignatureStripping";
import JwtKidInjection from "./JwtKidInjection";
import { useI18n } from "../../../../i18n/context";

const JWT_ATTACK_SCENARIOS = [
  { id: "jwt-alg-none",               labelJa: "alg=none 攻撃",                 severity: "critical" },
  { id: "jwt-weak-secret-bruteforce", labelJa: "HS256 弱秘密鍵ブルートフォース", severity: "high" },
  { id: "jwt-signature-stripping",    labelJa: "署名ストリッピング",             severity: "critical" },
  { id: "jwt-kid-injection",          labelJa: "kid ヘッダインジェクション",     severity: "high" },
] as const;

type JwtAttackScenarioId = typeof JWT_ATTACK_SCENARIOS[number]["id"];

// scopeId は DataFlowPanel と接続するための識別子
const SCOPE = "attack-jwt";

export default function JwtAttackView() {
  const { t } = useI18n();
  const [selectedScenario, setSelectedScenario] =
    createSignal<JwtAttackScenarioId>("jwt-alg-none");

  return (
    <div class="jwt-attack-view">
      <EducationalWarningBanner />

      {/* シナリオセレクタ */}
      <div class="attack-scenario-selector">
        <label class="form-label">
          {t("攻撃シナリオを選択", "Select Attack Scenario")}
        </label>
        <For each={JWT_ATTACK_SCENARIOS}>
          {(scenario) => (
            <button
              class="scenario-btn"
              classList={{
                active: selectedScenario() === scenario.id,
                "severity-critical": scenario.severity === "critical",
                "severity-high": scenario.severity === "high",
              }}
              onClick={() => setSelectedScenario(scenario.id)}
            >
              {t(scenario.labelJa, scenario.id)}
            </button>
          )}
        </For>
      </div>

      {/* 選択シナリオのコンポーネント */}
      <Show when={selectedScenario() === "jwt-alg-none"}>
        <JwtAlgNoneAttack scopeId={SCOPE} />
      </Show>
      <Show when={selectedScenario() === "jwt-weak-secret-bruteforce"}>
        <JwtWeakSecretAttack scopeId={SCOPE} />
      </Show>
      <Show when={selectedScenario() === "jwt-signature-stripping"}>
        <JwtSignatureStripping scopeId={SCOPE} />
      </Show>
      <Show when={selectedScenario() === "jwt-kid-injection"}>
        <JwtKidInjection scopeId={SCOPE} />
      </Show>
    </div>
  );
}
```

### 5.3 各シナリオコンポーネントの共通 Props 型

```typescript
interface JwtAttackScenarioProps {
  /** DataFlowPanel に渡すスコープ ID ("attack-jwt") */
  scopeId: string;
}
```

### 5.4 AttackPanel の動作 (E-2: 並列ラベル表示)

`AttackPanel` は選択シナリオに対して 1 リクエストで両モード並列実行を起動し、
結果を 5 ステップの timeline + AttackScenarioMeta.modes の並列ラベルで対比表示する。
モード排他選択トグルは廃止 (E-2)。

```typescript
// src/components/auth/attacks/shared/AttackPanel.tsx (簡略疑似コード)
export default function AttackPanel(props: {
  tabId: string;
  scenarios: AttackScenarioMeta[];
  onRunScenario: (s: AttackScenarioMeta) => Promise<AttackResult<unknown>>;
}) {
  const [selected, setSelected] = createSignal<AttackScenarioMeta | null>(null);
  const [result, setResult] = createSignal<AttackResult<unknown> | null>(null);
  const [loading, setLoading] = createSignal(false);

  async function handleExecute() {
    if (!selected()) return;
    setLoading(true);
    setResult(await props.onRunScenario(selected()!));
    setLoading(false);
  }

  return (
    <div class="attack-panel">
      <EducationalWarningBanner />
      {/* シナリオセレクタ */}
      <For each={props.scenarios}>{(s) => (
        <button onClick={() => setSelected(s)}>{s.nameJa}</button>
      )}</For>

      {/* 実行ボタン (排他モードトグルなし — 1 クリックで両モード並列実行) */}
      <button onClick={handleExecute} disabled={!selected() || loading()}>
        {t("攻撃を実行 (両モード並列)", "Execute Attack (parallel both modes)")}
      </button>

      <Show when={result()}>
        {/* AttackScenarioMeta.modes の vulnerable/defensive ラベルを並列表示 */}
        <div class="attack-mode-labels">
          <For each={selected()?.modes}>{(m) => (
            <span classList={{
              "mode-vulnerable": m.kind === "vulnerable",
              "mode-defensive": m.kind === "defensive",
            }}>{m.labelJa}</span>
          )}</For>
        </div>
        {/* ステップ 4 (脆弱) / ステップ 5 (堅牢) を並列ハイライト */}
        <AttackStepTimeline steps={result()!.steps} />
        <AttackResultBanner result={result()!} />
        <AttackDefensePanel scenario={selected()!} />
      </Show>
    </div>
  );
}
```

### 5.5 `JwtInspector.tsx` への統合 (Phase 1 で確定)

`JwtInspector.tsx` は `viewMode` Signal (タブ別マップ管理) で defender/attacker を切替え、
attacker 側で `AttackPanel` に `jwtScenarios` と `runAttackScenario` 経由のバックエンド呼び出しを渡す。

```tsx
import ViewModeToggle from "./attacks/shared/ViewModeToggle";
import AttackPanel from "./attacks/shared/AttackPanel";
import { jwtScenarios } from "./attacks/scenarios/jwt-scenarios";
import { apiPost } from "../../api/client";
import { getViewMode } from "../../state/security-state"; // タブ別マップ
import type { AttackResult } from "../../../shared/api-types";

return (
  <div class="jwt-inspector">
    <ViewModeToggle tabId="jwt" />
    <Show when={getViewMode("jwt") === "defender"}>
      {/* 既存 Defender View */}
    </Show>
    <Show when={getViewMode("jwt") === "attacker"}>
      <AttackPanel
        tabId="jwt"
        scenarios={jwtScenarios}
        onRunScenario={async (s) => {
          const suffix = s.id.replace(/^jwt-/, "");
          // E-2: body は不要 (両モード並列実行)。テスト用オプションのみシナリオ別に渡す。
          const res = await apiPost<AttackResult<unknown>>(
            `/api/jwt/attack/${suffix}`, {}, "attack-jwt",
          );
          return res.data ?? { /* error fallback */ };
        }}
      />
    </Show>
  </div>
);
```

---

## 6. テスト要件

### 6.1 バックエンド API テスト (`server/__tests__/jwt-attack.test.ts`、E-2 後)

E-2 で「1 リクエストで両モード並列実行」設計に変更したため、モード排他選択ベースのテストは廃止。
代わりに 5 ステップ完全形 + extra ジェネリックの不変条件を `it.each` で網羅検証する。

| テストケース | 期待結果 |
|------------|---------|
| `POST /api/jwt/attack/alg-none` (body なし) | `outcome: "succeeded"`, HTTP 200, steps.length=5, ステップ 4=success/exploit, ステップ 5=blocked/verify, `blockedBy: "jwt_algorithms_allowlist"` |
| `POST /api/jwt/attack/alg-none` (旧契約 victim/strict 等を含む) | 200 + 5 ステップ (zod が未知フィールドを silently 削除し旧契約クライアント互換) |
| `POST /api/jwt/attack/weak-secret-bruteforce` `dictionarySize=100` | `outcome: "succeeded"`, `extra.crackedSecret="secret"`, `extra.attemptCount>=1`, `blockedBy: "strong_random_secret"` |
| `POST /api/jwt/attack/weak-secret-bruteforce` `dictionarySize=201` (上限超過) | HTTP 400 |
| `POST /api/jwt/attack/weak-secret-bruteforce` (body 省略) | デフォルト `dictionarySize=100` で 200 + 5 ステップ |
| `POST /api/jwt/attack/signature-stripping` (body なし) | `outcome: "succeeded"`, 5 ステップ, `blockedBy: "jwt_signature_mismatch"` |
| `POST /api/jwt/attack/signature-stripping` `forgedToken` 指定 | テスト用カスタムトークンで 200 + 5 ステップ (壊れたトークンならステップ 4 が `status: "failed"`) |
| `POST /api/jwt/attack/kid-injection` `injectedKid="../public/attacker-key.pem"` | `outcome: "succeeded"`, `extra.kidResolved="../public/attacker-key.pem"`, `blockedBy: "jwt_kid_not_in_allowlist"` |
| `POST /api/jwt/attack/kid-injection` (body なし) | デフォルト `injectedKid` で 200 + `extra.kidResolved` 設定 |
| **E-1/E-2 不変条件 (`it.each` 4 シナリオ)**: outcome=succeeded, steps.length=5, `_trace.attackSteps.length=5`, extra の有無がジェネリック型と一致 (alg-none/signature-stripping は undefined / weak-secret/kid-injection は object) | 4 シナリオで網羅検証 |
| 4 シナリオ全件: `data.logId > 0` かつ 4 件の logId が一意 | 検証 |
| 全エンドポイント: `_trace.attackSteps` と `_trace.isAttackMode: true` が付与 | 検証 |
| 本番ガード: `NODE_ENV=production` で 403 / `error: "...disabled in production"` | 検証 |
| 本番ガード: 非攻撃ルート (`/api/jwt/sign`) は production でも 200 | 検証 |
| **ヘルパー単体テスト (`server/utils/attack-runner.test.ts`)**: clipJson サイズ上限、maskSecret マスキング、sanitizeForDisplay 制御文字除去 | 11 件 |

### 6.2 フロントエンド コンポーネントテスト

| テストケース | 内容 |
|------------|------|
| `JwtAttackView` レンダリング | `EducationalWarningBanner` が表示されること |
| シナリオセレクタ | 各シナリオボタンクリックで対応コンポーネントが表示されること |
| `JwtAlgNoneAttack` | [実行] クリックで `apiPost` が呼ばれること |
| `JwtAlgNoneAttack` | 結果受信後に `AttackStepTimeline` が表示されること |
| `ViewModeToggle` | "attacker" に切り替えると `JwtAttackView` が表示されること |
| `ViewModeToggle` | "defender" に切り替えると既存 `JwtInspector` コンテンツが表示されること |

### 6.3 安全装置テスト (04-safety-guardrails.md §4 チェックリスト)

| チェック項目 | 検証方法 |
|------------|---------|
| 全 `fetch` / `apiPost` の宛先が `/api/<area>/attack/*` または相対パスのみ | コードグレップ |
| `EducationalWarningBanner` が `display: none` にならない | CSS 検査 |
| 攻撃成立文言が「この実装は」または「このシナリオでは」で始まる | テキストアサーション |
| `console.log` に攻撃ペイロードを出力していない | コードグレップ |

---

## 7. i18n キー一覧表

`src/i18n/context.tsx` の `t()` ヘルパーで使用するキーと文言をまとめる。

| キー | 日本語 | 英語 |
|-----|--------|------|
| `attack.jwt.title` | JWT 攻撃デモ | JWT Attack Demo |
| `attack.jwt.scenarioSelector` | 攻撃シナリオを選択 | Select Attack Scenario |
| `attack.jwt.execute` | 攻撃を実行 | Execute Attack |
| `attack.jwt.lenientMode` | 脆弱検証モード | Lenient Verifier Mode |
| `attack.jwt.strictMode` | 堅牢検証モード | Strict Verifier Mode |
| `attack.jwt.algNone.title` | alg=none 攻撃 | Algorithm None Attack |
| `attack.jwt.algNone.desc` | これは CWE-345 の概念実証です。alg フィールドを none に書き換えることで、署名検証なしにサーバーを騙すことができる状況をシミュレーションします。 | This is a proof-of-concept for CWE-345. Simulates bypassing signature verification by setting alg=none. |
| `attack.jwt.algNone.stepDecode` | 元 JWT ヘッダをデコード | Decode original JWT header |
| `attack.jwt.algNone.stepTamper` | alg を none に改竄・role を admin に昇格 | Rewrite alg=none, escalate role to admin |
| `attack.jwt.algNone.stepForge` | 署名セグメントを削除 | Drop signature segment |
| `attack.jwt.algNone.stepExploit` | 脆弱検証エンドポイントに送信 | Send to lenient verifier |
| `attack.jwt.algNone.stepVerify` | 堅牢検証エンドポイントに送信 | Send to strict verifier |
| `attack.jwt.algNone.succeeded` | この実装は脆弱です: algorithms 省略により alg=none が受理されました。 | This implementation is vulnerable: alg=none accepted due to missing algorithms option. |
| `attack.jwt.algNone.blocked` | 防御が機能しました: algorithms 許可リストが alg=none を拒否しました。 | Defense worked: algorithms allowlist rejected alg=none. |
| `attack.jwt.algNone.realworld` | 現代のほとんどの JWT ライブラリはデフォルトで none を拒否するよう更新されています。 | Most modern JWT libraries now reject none by default. |
| `attack.jwt.weakSecret.title` | HS256 弱秘密鍵ブルートフォース | HS256 Weak Secret Brute Force |
| `attack.jwt.weakSecret.desc` | これは CWE-326 の概念実証です。HS256 の秘密鍵が辞書語の場合、トークンを入手するだけでオフライン総当りが可能になります。 | This is a proof-of-concept for CWE-326. If the HS256 secret is a dictionary word, offline brute force is possible. |
| `attack.jwt.weakSecret.stepCapture` | HS256 JWT トークンを入手 | Capture HS256 JWT token |
| `attack.jwt.weakSecret.stepDict` | オフライン辞書攻撃を開始 | Begin offline dictionary attack |
| `attack.jwt.weakSecret.stepCracked` | 弱い秘密鍵がクラックされました | Weak secret cracked |
| `attack.jwt.weakSecret.stepForge` | クラックした秘密鍵で新規トークンを署名 | Re-sign token with cracked secret |
| `attack.jwt.weakSecret.stepStrong` | 強い秘密鍵では辞書が通用しない | Strong secret resists dictionary |
| `attack.jwt.weakSecret.succeeded` | この実装は脆弱です: 秘密鍵が辞書で発見されました。 | This implementation is vulnerable: secret found in dictionary. |
| `attack.jwt.weakSecret.blocked` | 防御が機能しました: 十分な長さのランダム秘密鍵はブルートフォースに耐性があります。 | Defense worked: strong random secret resists brute force. |
| `attack.jwt.weakSecret.realworld` | 実環境では IP レート制限によりオンラインブルートフォースは阻止されます。ただし HS256 のオフライン攻撃はサーバーへの接続なしに実行できます。 | In real environments, online brute force is blocked by rate limiting. HS256 offline attacks require no server connection. |
| `attack.jwt.sigStrip.title` | 署名ストリッピング | Signature Stripping |
| `attack.jwt.sigStrip.desc` | これは CWE-347 の概念実証です。jwt.decode() のみを使って認証する実装は、任意の偽造トークンを受け入れてしまいます。 | This is a proof-of-concept for CWE-347. Implementations using only jwt.decode() accept any forged token. |
| `attack.jwt.sigStrip.stepProbe` | ターゲットが decode() のみを使用していることを調査 | Inspect target uses decode() only |
| `attack.jwt.sigStrip.stepForge` | 無効な署名のトークンを偽造 | Forge token with invalid signature |
| `attack.jwt.sigStrip.stepExploit` | decode-only エンドポイントに送信 | Submit to decode-only endpoint |
| `attack.jwt.sigStrip.stepVerify` | verify エンドポイントで拒否される | Rejected by verify endpoint |
| `attack.jwt.sigStrip.succeeded` | この実装は脆弱です: decode() のみを使用しているため、無効な署名のトークンが受け入れられました。 | This implementation is vulnerable: decode() accepts tokens with invalid signatures. |
| `attack.jwt.sigStrip.blocked` | 防御が機能しました: jwt.verify() が署名の不一致を検出しました。 | Defense worked: jwt.verify() detected signature mismatch. |
| `attack.jwt.kidInject.title` | kid ヘッダインジェクション | kid Header Injection |
| `attack.jwt.kidInject.desc` | これは CWE-22 / CWE-90 の概念実証です。kid ヘッダをパストラバーサル文字列に書き換えて、攻撃者制御の鍵で署名検証を通す攻撃をシミュレーションします。 | This is a proof-of-concept for CWE-22/CWE-90. Simulates injecting a path traversal string into the kid header. |
| `attack.jwt.kidInject.stepProbe` | JWT ヘッダの kid フィールドを確認 | Inspect JWT header for kid field |
| `attack.jwt.kidInject.stepTamper` | kid ヘッダにパストラバーサルを注入 | Inject path traversal in kid header |
| `attack.jwt.kidInject.stepForge` | 攻撃者制御の鍵でトークンを署名 | Sign forged token with attacker key |
| `attack.jwt.kidInject.stepExploit` | 脆弱エンドポイントに送信 | Submit to vulnerable endpoint |
| `attack.jwt.kidInject.stepVerify` | 許可リスト保護エンドポイントで拒否 | Rejected by allowlist endpoint |
| `attack.jwt.kidInject.succeeded` | この実装は脆弱です: kid をサニタイズせずにファイルパスに使用しているため、攻撃者制御の鍵で検証が通りました。 | This implementation is vulnerable: kid used as file path without sanitization. |
| `attack.jwt.kidInject.blocked` | 防御が機能しました: kid 許可リスト検証が不正な kid を拒否しました。 | Defense worked: kid allowlist rejected the injected value. |

---

## 8. 関連ファイル

### 8.1 既存ファイル (Phase 1 + Phase 2 第二コミット時点の正本)

| ファイルパス | 変更種別 | 変更内容 |
|------------|---------|---------|
| `server/routes/jwt-ops.ts` | 修正 | 既存の `/sign`/`/verify`/`/decode`/`/keys` (防御側) はそのまま、`/attack/*` 4 ルートを追加 (`runAttackScenario` ヘルパー経由) |
| `src/components/auth/JwtInspector.tsx` | 修正 | `ViewModeToggle` (タブ別 viewMode) + `AttackPanel` の条件描画追加 |
| `shared/api-types.ts` | 修正 | `AttackStep`, `AttackResult<TExtra>`, `AttackStepPayload`, `AttackScenarioMeta`, `ServerTrace.attackSteps`/`isAttackMode` 追加 |
| `server/middleware/trace-logger.ts` | 修正 | `addAttackStep()` (timestamp 共有規約 ROB-FIND-009) + `isAttackMode` 自動付与 |
| `server/db/schema.ts` | 修正 | `attack_log` テーブル + 6 テーブルに `is_attack_sim` 列 + idempotent migrateSchema |
| `server/db/queries.ts` | 修正 | `insertAttackLog()` / `finalizeAttackLog()` ヘルパー、`cleanExpiredSessions()` に `is_attack_sim = 0` フィルタ |
| `server/validation.ts` | 修正 | 4 シナリオの zod スキーマ (デッドフィールド削除済み: ROB-FIND-006) |

### 8.2 Phase 0/1/2 で作成済みファイル

| ファイルパス | 役割 |
|------------|------|
| `server/utils/attack-runner.ts` | **runAttackScenario ヘルパー** (SEC-12 / ROB-FIND-011 統合) + `clipJson`/`maskSecret`/`sanitizeForDisplay` |
| `server/utils/attack-runner.test.ts` | ヘルパー単体テスト (11 件) |
| `server/__tests__/jwt-attack.test.ts` | 4 シナリオ統合テスト + E-1/E-2 不変条件 + 本番ガード (19 件) |
| `server/middleware/attack-guard.ts` | 本番環境で `/attack/*` を 403 で無効化 |
| `src/components/auth/attacks/shared/EducationalWarningBanner.tsx` | dismiss 不可の警告バナー |
| `src/components/auth/attacks/shared/ViewModeToggle.tsx` | defender/attacker 切替 (タブ別マップ) |
| `src/components/auth/attacks/shared/AttackPanel.tsx` | 汎用シナリオセレクタ + 並列ラベル表示 |
| `src/components/auth/attacks/shared/AttackStepTimeline.tsx` | 5 ステップの時系列アニメーション |
| `src/components/auth/attacks/shared/AttackResultBanner.tsx` | outcome / blockedBy / summary バナー |
| `src/components/auth/attacks/shared/AttackDefensePanel.tsx` | codeHints / existingFileLinks 表示 |
| `src/components/auth/attacks/scenarios/jwt-scenarios.ts` | `AttackScenarioMeta[]` (4 シナリオの静的メタ) |

### 8.3 設計書内参照

| ファイルパス | 参照目的 |
|------------|---------|
| `DESIGN/00-overview.md` | 全体目的・攻撃カタログマトリクスの確認 |
| `DESIGN/03-data-model.md` | `AttackStep`, `AttackResult`, `AttackStepPayload` 型定義 |
| `DESIGN/04-safety-guardrails.md` | 教育安全装置の文言ルール・チェックリスト |

### 8.4 参考 RFC / 外部資料 (教材リンク用)

| 資料 | URL | 関連シナリオ |
|-----|-----|------------|
| RFC 7519 (JWT) | https://tools.ietf.org/html/rfc7519 | 全シナリオ |
| RFC 7518 §3.6 (alg=none) | https://tools.ietf.org/html/rfc7518#section-3.6 | シナリオ A |
| OWASP JWT Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html | 全シナリオ |
| CWE-345 | https://cwe.mitre.org/data/definitions/345.html | シナリオ A |
| CWE-326 | https://cwe.mitre.org/data/definitions/326.html | シナリオ B |
| CWE-347 | https://cwe.mitre.org/data/definitions/347.html | シナリオ C |
| CWE-22 | https://cwe.mitre.org/data/definitions/22.html | シナリオ D |

---

*このドキュメントは `DESIGN/11-attack-jwt.md` に配置。*
*実装は `DESIGN/01-architecture.md` のルート登録手順に従い `server/index.ts` にエンドポイントを登録すること。*
