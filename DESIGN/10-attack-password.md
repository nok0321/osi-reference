---
title: パスワード認証 攻撃カタログ
phase: design
tab-id: auth-methods
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

# 10. パスワード認証 攻撃カタログ

## 1. 概要

「認証方式 (auth-methods)」タブは、パスワード認証の基礎と bcrypt によるハッシュ化を正常系で
学ぶ既存の Defender View を持つ。このカタログは同タブに **Attacker View** を追加し、
パスワード保護の設計上の欠陥が攻撃者にどのように悪用されるかを体感的に理解させる。

### 1.1 防御側既存実装の参照

| ファイル | 役割 |
|---------|------|
| `server/routes/password-auth.ts` | 登録 (`POST /api/auth/password/register`) と ログイン (`POST /api/auth/password/login`) のルートハンドラ。`bcryptjs` で saltRounds=10 のハッシュ生成・比較を実装 |
| `src/components/auth/AuthMethods.tsx` | `PasswordDemo` コンポーネント。登録/ログインフォーム + users テーブル表示 + `DataFlowPanel` による HTTP/Trace 可視化 |
| `server/db/schema.ts` | `users` テーブル定義: `id`, `username` (UNIQUE), `password_hash`, `created_at` |

### 1.2 攻撃デモの追加方針

既存の `AuthMethods.tsx` に `ViewModeToggle` を追加し、Attacker View として
`PasswordAttackPanel` コンポーネントを条件表示する。
攻撃 API は既存の `server/routes/password-auth.ts` にサブパス `/attack/*` として追加する
(DESIGN/01-architecture.md §2.1 のルート配置方針に準拠)。

---

## 2. 攻撃シナリオ一覧

| # | シナリオ ID | 攻撃名 | CWE | CAPEC | OSI 層 | 深刻度 |
|---|------------|--------|-----|-------|--------|-------|
| A | `password-rainbow-vs-bcrypt` | bcrypt vs レインボーテーブル比較 | CWE-916 | CAPEC-55 | L7 (Application) | High |
| B | `password-timing-string-compare` | タイミング攻撃 (文字列比較) | CWE-208 | CAPEC-462 | L7 (Application) | Medium |
| C | `password-bruteforce-no-rate-limit` | レート制限なしブルートフォース | CWE-307 | CAPEC-112 | L7 (Application) | High |

---

## 3. 既存防御側実装

### 3.1 `server/routes/password-auth.ts` の構造

```
passwordAuthRoutes
├── POST /register
│   ├── bcrypt.genSalt(10)          ← saltRounds=10 (2^10 = 1024 反復)
│   ├── bcrypt.hash(password, salt) ← Blowfish key schedule でハッシュ生成
│   └── INSERT INTO users           ← username + password_hash を保存
├── POST /login
│   ├── SELECT users WHERE username ← ユーザー検索
│   ├── bcrypt.compare(pw, hash)    ← 定数時間比較 (bcryptjs 内部実装)
│   └── success/fail を返却
└── GET /users
    └── password_hash を先頭29文字+... でマスク表示 (教育用)
```

`trace.addCryptoOp()` により、`bcrypt.genSalt` / `bcrypt.hash` / `bcrypt.compare` の
操作詳細が `_trace.cryptoOps` に記録され `DataFlowPanel` の Trace タブで可視化される。

### 3.2 `server/db/schema.ts` の users テーブル

```sql
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,          -- bcrypt ハッシュ ($2a$10$...)
  created_at    TEXT DEFAULT (datetime('now'))
);
```

`password_hash` は必ず bcrypt 形式 (`$2a$10$...` 60文字) で格納される。
攻撃シミュレーション用のシードユーザーには `is_attack_sim` フラグカラムを追加し、
正常系クエリから除外する (DESIGN/04-safety-guardrails.md §5.3 に準拠)。

### 3.3 既存実装の防御上の強み

| 防御要素 | 実装箇所 | 効果 |
|---------|---------|------|
| bcrypt ソルト自動付与 | `bcrypt.genSalt(10)` | 同一パスワードでも異なるハッシュになるためレインボーテーブルが無効化される |
| 計算コスト (2^10) | saltRounds=10 | ハッシュ計算に意図的な遅延を加え、大量試行のコストを増大させる |
| bcrypt.compare の定数時間比較 | `password-auth.ts:93` | タイミング攻撃による文字列比較の脆弱性を排除 |

### 3.4 既存実装の改善余地

| 項目 | 現状 | 改善案 |
|------|------|--------|
| レート制限 | 未実装 | IP ごとのログイン失敗回数を制限する (シナリオ C で体感) |
| アカウントロックアウト | 未実装 | N 回失敗で一時ロック |
| Argon2id への移行 | bcrypt 使用 | OWASP 推奨のメモリハード関数 Argon2id へ移行を検討 |

---

## 4. シナリオ詳細

---

### 4.1 `password-rainbow-vs-bcrypt`

#### 概要

これは **CWE-916 / CAPEC-55** の概念実証である。
SHA-1 や MD5 などの高速ハッシュ関数でパスワードを保護した実装は、
事前計算済みのレインボーテーブル (入力値 → ハッシュ値の逆引き辞書) を用いることで
即座に元のパスワードを特定される可能性がある。
一方、bcrypt はソルト＋計算コストによってレインボーテーブルを無効化する。

同一パスワード `"password123"` を SHA-1 / MD5 / bcrypt の3アルゴリズムでハッシュ化し、
サーバー側にプリセットした「レインボーテーブル風辞書」との照合結果を比較表示することで、
アルゴリズム選択が与えるセキュリティ上の差異を体感させる。

**実環境との差異の注記 (必須)**:
実環境では数百 GB のレインボーテーブルデータベースが使用されるが、
このデモはサーバー側に組み込んだ 10 件の固定辞書によるシミュレーションである。

#### CWE / CAPEC / OSI 層

| 項目 | 値 |
|------|-----|
| CWE | CWE-916 (Use of Password Hash With Insufficient Computational Effort) |
| CAPEC | CAPEC-55 (Rainbow Table Password Cracking) |
| OSI 層 | Layer 7 — Application |
| 深刻度 | High |

#### 前提条件 (脆弱な実装の例)

攻撃者は以下の条件を満たしている:

1. 標的の `users` テーブル (または同等のストレージ) への読み取りアクセスを取得済み
   (SQL インジェクション・DB 漏洩等による。このデモではその取得過程を省略)
2. 取得した `password_hash` フィールドの値が SHA-1 または MD5 ハッシュ形式である
3. 攻撃者はレインボーテーブルまたは辞書 DB を保有している

**脆弱な実装例** (このシナリオでシミュレーションする実装):

```typescript
// 脆弱な実装例 (実際には使用しない — 教育用シミュレーション専用)
import crypto from "crypto";

// SHA-1 でパスワードをハッシュ化 (ソルトなし)
function weakHash_sha1(password: string): string {
  return crypto.createHash("sha1").update(password).digest("hex");
}

// MD5 でパスワードをハッシュ化 (ソルトなし)
function weakHash_md5(password: string): string {
  return crypto.createHash("md5").update(password).digest("hex");
}
```

#### 攻撃ステップ (AttackStep[] の具体例)

```typescript
const steps: AttackStep[] = [
  {
    id: "step-1",
    kind: "intercept",
    label: "Obtain password hash from leaked DB record",
    labelJa: "漏洩 DB レコードからパスワードハッシュを取得",
    status: "success",
    payload: {
      type: "credential",
      username: "seed_alice",
      passwordHashAlgo: "sha1",
      // 教育用固定値: SHA-1("password123") = cbfdac6008f9cab4083784cbd1874f76618d2a97
    },
    detail: "The attacker obtains a SHA-1 hash from a leaked database dump. No salt is present.",
    detailJa: "攻撃者は漏洩した DB ダンプから SHA-1 ハッシュを取得します。ソルトは存在しません。",
    timestamp: Date.now(),
  },
  {
    id: "step-2",
    kind: "probe",
    label: "Query rainbow table for SHA-1 hash",
    labelJa: "SHA-1 ハッシュをレインボーテーブルで照合",
    status: "success",
    payload: {
      type: "credential",
      username: "seed_alice",
      passwordHashAlgo: "sha1",
      crackedPassword: "password123",
    },
    detail: "SHA-1 hash 'cbfdac6...' found in rainbow table within milliseconds.",
    detailJa: "SHA-1 ハッシュ 'cbfdac6...' がレインボーテーブルでミリ秒以内に発見されました。",
    timestamp: Date.now(),
  },
  {
    id: "step-3",
    kind: "probe",
    label: "Query rainbow table for MD5 hash",
    labelJa: "MD5 ハッシュをレインボーテーブルで照合",
    status: "success",
    payload: {
      type: "credential",
      username: "seed_alice",
      passwordHashAlgo: "md5",
      crackedPassword: "password123",
    },
    detail: "MD5 hash '482c811d...' found in rainbow table within milliseconds.",
    detailJa: "MD5 ハッシュ '482c811d...' がレインボーテーブルでミリ秒以内に発見されました。",
    timestamp: Date.now(),
  },
  {
    id: "step-4",
    kind: "verify",
    label: "Attempt rainbow table lookup for bcrypt hash",
    labelJa: "bcrypt ハッシュのレインボーテーブル照合を試行",
    status: "blocked",
    payload: {
      type: "credential",
      username: "seed_alice",
      passwordHashAlgo: "bcrypt",
      // bcrypt ハッシュはソルトを含み計算コストが高いため逆引き不可
    },
    detail: "bcrypt hash includes a unique salt and 1024 Blowfish iterations. Rainbow table lookup is infeasible.",
    detailJa: "bcrypt ハッシュは一意のソルトを含み Blowfish 1024 回反復を要するため、レインボーテーブルによる逆引きは実行不能です。",
    timestamp: Date.now(),
  },
];
```

#### 期待される結果 (AttackResult)

```typescript
const result: AttackResult = {
  scenarioId: "password-rainbow-vs-bcrypt",
  outcome: "succeeded",  // SHA-1/MD5 については攻撃が成立
  startedAt: /* Unix ms */,
  finishedAt: /* Unix ms */,
  steps,
  summary: "SHA-1 and MD5 hashes were reversed in milliseconds via dictionary lookup. bcrypt with salt blocked the lookup entirely.",
  summaryJa: "SHA-1 および MD5 ハッシュは辞書照合でミリ秒以内に逆引きされました。ソルト付き bcrypt は照合を完全に阻止しました。",
};
```

UI 上の表示:
- step-1〜3: 攻撃成立 (警告色オレンジ)
- step-4: 防御成立 (緑)
- 結果バナー: 「この実装は脆弱です: SHA-1/MD5 ハッシュはレインボーテーブルで即座に逆引きされました」

#### 防御策 (defenseRecommendation)

**既存実装ファイルへのリンク**:
- `server/routes/password-auth.ts:31-48` — `bcrypt.genSalt(10)` と `bcrypt.hash` の実装
- `server/db/schema.ts:39` — `password_hash TEXT NOT NULL` カラム定義

**防御策の要点**:

1. パスワードのハッシュには必ずソルト付きの計算コストの高い関数を使用する
2. SHA-1 / MD5 / SHA-256 をパスワードハッシュに使用しない (高速すぎるため)
3. bcrypt の saltRounds は最低 10 (本番環境では 12 以上を推奨)
4. より強力な選択肢として Argon2id (OWASP 第一推奨) を検討する

**codeHints の具体例**:

```typescript
// 推奨: bcrypt (現実装)
import bcrypt from "bcryptjs";
const salt = await bcrypt.genSalt(12); // 本番では 12 以上を推奨
const hash = await bcrypt.hash(password, salt);

// より推奨: Argon2id (OWASP Password Storage Cheat Sheet 第一推奨)
// npm install argon2
import argon2 from "argon2";
const hash = await argon2.hash(password, {
  type: argon2.argon2id,
  memoryCost: 65536,  // 64MB
  timeCost: 3,        // 3 回反復
  parallelism: 4,
});
```

**参考リンク**:
- OWASP Password Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- CWE-916: https://cwe.mitre.org/data/definitions/916.html
- CAPEC-55: https://capec.mitre.org/data/definitions/55.html

#### API 契約

```
POST /api/auth/password/attack/rainbow-vs-bcrypt
```

**リクエスト**:

```json
{
  "username": "seed_alice",
  "password": "password123",
  "algorithm": "sha1"
}
```

| フィールド | 型 | 必須 | 説明 |
|-----------|---|------|------|
| `username` | `string` | 必須 | 固定シードユーザー名 (`seed_alice` / `seed_bob` のみ受け付ける) |
| `password` | `string` | 必須 | 試行するパスワード文字列 (最大 72 文字) |
| `algorithm` | `"sha1" \| "md5" \| "bcrypt"` | 必須 | 比較に使用するハッシュアルゴリズム |

**レスポンス**:

```json
{
  "success": true,
  "data": {
    "scenarioId": "password-rainbow-vs-bcrypt",
    "outcome": "succeeded",
    "startedAt": 1745592000000,
    "finishedAt": 1745592000045,
    "steps": [
      {
        "id": "step-1",
        "kind": "intercept",
        "label": "Obtain password hash from leaked DB record",
        "labelJa": "漏洩 DB レコードからパスワードハッシュを取得",
        "status": "success",
        "payload": {
          "type": "credential",
          "username": "seed_alice",
          "passwordHashAlgo": "sha1"
        },
        "timestamp": 1745592000010
      },
      {
        "id": "step-2",
        "kind": "probe",
        "label": "Query rainbow table for SHA-1 hash",
        "labelJa": "SHA-1 ハッシュをレインボーテーブルで照合",
        "status": "success",
        "payload": {
          "type": "credential",
          "username": "seed_alice",
          "passwordHashAlgo": "sha1",
          "crackedPassword": "password123"
        },
        "timestamp": 1745592000025
      },
      {
        "id": "step-4",
        "kind": "verify",
        "label": "Attempt rainbow table lookup for bcrypt hash",
        "labelJa": "bcrypt ハッシュのレインボーテーブル照合を試行",
        "status": "blocked",
        "payload": {
          "type": "credential",
          "username": "seed_alice",
          "passwordHashAlgo": "bcrypt"
        },
        "timestamp": 1745592000040
      }
    ],
    "summary": "SHA-1 and MD5 hashes were reversed via dictionary lookup. bcrypt blocked the lookup.",
    "summaryJa": "SHA-1 および MD5 ハッシュは辞書照合で逆引きされました。bcrypt は照合を阻止しました。"
  },
  "_trace": {
    "cryptoOps": [
      {
        "op": "crypto.createHash(sha1)",
        "input": "password=\\\"[REDACTED]\\\"",
        "output": "cbfdac6008f9cab4083784cbd1874f76618d2a97",
        "algo": "sha1",
        "detail": "Unsalted SHA-1 hash. Fixed output for same input — rainbow table feasible."
      },
      {
        "op": "rainbow_table.lookup",
        "input": "hash=\\\"cbfdac6008f9cab4083784cbd1874f76618d2a97\\\"",
        "output": "FOUND: password123",
        "algo": "lookup",
        "detail": "Hash found in precomputed dictionary in <1ms."
      },
      {
        "op": "bcrypt.hash",
        "input": "password=\\\"[REDACTED]\\\", saltRounds=10",
        "output": "$2a$10$...(60 chars, unique per hash)",
        "algo": "bcrypt",
        "detail": "bcrypt includes random salt — same password produces different hash each time. Rainbow table infeasible."
      }
    ],
    "dbQueries": [
      {
        "sql": "SELECT hash FROM rainbow_table_sim WHERE hash = ?",
        "params": ["cbfdac6008f9cab4083784cbd1874f76618d2a97"],
        "rows": [{ "hash": "cbfdac6008f9cab4083784cbd1874f76618d2a97", "plaintext": "password123" }],
        "ms": 0.8
      }
    ],
    "attackSteps": [ /* AttackStep[] — 上記 steps と同一 */ ]
  }
}
```

#### _trace 内訳

| trace 種別 | 内容 |
|-----------|------|
| `DbQuery` | `SELECT hash FROM rainbow_table_sim WHERE hash = ?` — シミュレーション用辞書テーブルへの照合クエリ (SHA-1/MD5 で一致、bcrypt で不一致) |
| `CryptoOp` | `crypto.createHash("sha1")`, `crypto.createHash("md5")`, `bcrypt.hash()` — 各アルゴリズムのハッシュ計算と照合結果 |
| `AttackStep` | 上記 4 ステップ |

`rainbow_table_sim` は `server/db/schema.ts` に追加する教育専用の固定辞書テーブル。
`(hash TEXT PRIMARY KEY, plaintext TEXT NOT NULL, algo TEXT NOT NULL)` の構造で、
10 件の固定シードデータ (`password123`, `hunter2`, `letmein` 等の弱パスワード) を持つ。

#### UI フロー

```
[Attacker View 起動]
  ↓
[教育用バナー表示: 常時固定]
  ↓
[シナリオセレクタ: "bcrypt vs レインボーテーブル" を選択]
  ↓
[アルゴリズム選択ラジオ: SHA-1 / MD5 / bcrypt]
  ↓
[「攻撃を実行」ボタン]
  ↓
[AttackStepTimeline アニメーション]
  step-1 intercept: 漏洩 DB からハッシュ取得 → SUCCESS (オレンジ)
  step-2 probe:     SHA-1 レインボーテーブル照合 → SUCCESS/BLOCKED (アルゴリズムにより変化)
  step-3 probe:     MD5 レインボーテーブル照合  → SUCCESS/BLOCKED
  step-4 verify:    bcrypt 照合試行 → BLOCKED (緑)
  ↓
[AttackResultBanner: "この実装は脆弱です: SHA-1/MD5 はレインボーテーブルで逆引きされました"]
  ↓
[AttackDefensePanel 自動展開: bcrypt/Argon2id の防御策]
  ↓
[DataFlowPanel: HTTP タブ (リクエスト/レスポンス) / Trace タブ (CryptoOp + AttackStep) / DB タブ (rainbow_table_sim 照合)]
```

#### i18n キー一覧 (このシナリオ固有)

| キー概念 | 日本語 | English |
|---------|--------|---------|
| シナリオ名 | `bcrypt vs レインボーテーブル比較` | `bcrypt vs Rainbow Table Comparison` |
| アルゴリズム選択ラベル | `ハッシュアルゴリズムを選択` | `Select hash algorithm` |
| step-1 ラベル | `漏洩 DB レコードからパスワードハッシュを取得` | `Obtain password hash from leaked DB record` |
| step-2 ラベル | `SHA-1 ハッシュをレインボーテーブルで照合` | `Query rainbow table for SHA-1 hash` |
| step-3 ラベル | `MD5 ハッシュをレインボーテーブルで照合` | `Query rainbow table for MD5 hash` |
| step-4 ラベル | `bcrypt ハッシュのレインボーテーブル照合を試行` | `Attempt rainbow table lookup for bcrypt hash` |
| 攻撃成立メッセージ | `この実装は脆弱です: SHA-1/MD5 ハッシュはレインボーテーブルで逆引きされました` | `This implementation is vulnerable: SHA-1/MD5 hashes were reversed via rainbow table` |
| 防御成立メッセージ | `防御が機能しました: bcrypt のソルトと計算コストがレインボーテーブルを無効化しました` | `Defense succeeded: bcrypt salt and cost factor invalidate rainbow table lookups` |
| 辞書シミュレーション注記 | `注: このデモは 10 件の固定辞書によるシミュレーションです` | `Note: This demo uses a 10-entry fixed dictionary simulation` |
| Argon2id 推奨テキスト | `OWASP は Argon2id をパスワードハッシュの第一推奨としています` | `OWASP recommends Argon2id as the primary choice for password hashing` |

---

### 4.2 `password-timing-string-compare`

#### 概要

これは **CWE-208 / CAPEC-462** の概念実証である。
`===` 演算子による文字列比較は短絡評価 (一致しない文字が見つかった時点で即座に `false` を返す)
のため、パスワードの先頭から何文字が正解と一致するかによって処理時間が微妙に変化する。
攻撃者はこの応答時間の差異を統計的に分析することで、パスワードを1文字ずつ特定できる。

このデモでは同一の「正解パスワード」に対して「先頭1文字一致」「先頭3文字一致」「全文字一致」
のケースで人工的に再現した応答時間の差異を比較表示する。
また `crypto.timingSafeEqual` を用いた定数時間比較による改善パターンも併記する。

**実環境との差異の注記 (必須)**:
実環境ではネットワーク遅延・OS スケジューリングのジッターにより再現が困難であり、
数十万回の測定と統計分析を要する。このデモは概念的な差異を誇張して表示している。

#### CWE / CAPEC / OSI 層

| 項目 | 値 |
|------|-----|
| CWE | CWE-208 (Observable Timing Discrepancy) |
| CAPEC | CAPEC-462 (Cross-Channel Scripting) ※パスワードタイミング攻撃への適用 |
| OSI 層 | Layer 7 — Application |
| 深刻度 | Medium |

#### 前提条件 (脆弱な実装の例)

攻撃者は以下の条件を満たしている:

1. ログインエンドポイントへの繰り返しアクセスが可能
2. エンドポイントがパスワード比較に `===` 演算子またはそれに相当する短絡評価比較を使用している
3. 攻撃者は応答時間を高精度で計測できる (同一ネットワークセグメント内などの低レイテンシ環境)

**脆弱な実装例** (このシナリオでシミュレーションする実装):

```typescript
// 脆弱な実装例 (教育用シミュレーション専用 — 実際のログイン処理には使用しない)
function vulnerableStringCompare(inputPassword: string, storedPassword: string): boolean {
  // === は短絡評価: 最初に不一致な文字で即座に false を返す
  // パスワード長や先頭一致文字数によって処理時間が変化する
  return inputPassword === storedPassword;
}
```

#### 攻撃ステップ (AttackStep[] の具体例)

```typescript
const steps: AttackStep[] = [
  {
    id: "step-1",
    kind: "probe",
    label: "Measure response time with 0-character match (wrong first char)",
    labelJa: "先頭文字不一致のケースで応答時間を計測",
    status: "success",
    payload: {
      type: "generic",
      data: {
        testedPassword: "x_______",  // 先頭文字が正解と異なる
        matchedChars: 0,
        responseTimeMs: 1.2,         // 人工的に誇張した値
        compareMethod: "=== (short-circuit)",
      },
    },
    detail: "Comparison stops at first character. Fastest response time.",
    detailJa: "比較は先頭文字で停止します。最速の応答時間です。",
    timestamp: Date.now(),
  },
  {
    id: "step-2",
    kind: "probe",
    label: "Measure response time with 3-character match",
    labelJa: "先頭3文字一致のケースで応答時間を計測",
    status: "success",
    payload: {
      type: "generic",
      data: {
        testedPassword: "pas_____",  // 先頭 3 文字が正解と一致
        matchedChars: 3,
        responseTimeMs: 1.8,         // 先頭 0 文字一致より遅い
        compareMethod: "=== (short-circuit)",
      },
    },
    detail: "Comparison continues for 3 characters before stopping. Slightly slower.",
    detailJa: "比較は 3 文字目まで継続してから停止します。わずかに遅延します。",
    timestamp: Date.now(),
  },
  {
    id: "step-3",
    kind: "exploit",
    label: "Infer password length via timing difference",
    labelJa: "タイミング差異からパスワードを推定",
    status: "success",
    payload: {
      type: "generic",
      data: {
        observation: "Response time increases proportionally to matched prefix length",
        observationJa: "応答時間は一致プレフィックス長に比例して増加する",
        inferredPasswordPrefix: "pas",
        nextCharToTest: "s",
      },
    },
    detail: "By iterating one character at a time, an attacker can determine each character of the password.",
    detailJa: "1文字ずつ試行することで、攻撃者はパスワードの各文字を特定できます。",
    timestamp: Date.now(),
  },
  {
    id: "step-4",
    kind: "verify",
    label: "Verify timing-safe comparison eliminates the discrepancy",
    labelJa: "定数時間比較がタイミング差異を排除することを確認",
    status: "blocked",
    payload: {
      type: "generic",
      data: {
        compareMethod: "crypto.timingSafeEqual",
        responseTimeMs_zeroMatch: 2.1,
        responseTimeMs_threeMatch: 2.0,
        responseTimeMs_fullMatch: 2.1,
        timingVarianceMs: 0.1,  // 無視できるジッター範囲
        note: "All comparisons take the same time regardless of match length",
        noteJa: "一致文字数に関わらずすべての比較が同一時間を要する",
      },
    },
    detail: "crypto.timingSafeEqual always compares all bytes, making timing side-channel infeasible.",
    detailJa: "crypto.timingSafeEqual は常に全バイトを比較するため、タイミングサイドチャネルが成立しません。",
    timestamp: Date.now(),
  },
];
```

#### 期待される結果 (AttackResult)

```typescript
const result: AttackResult = {
  scenarioId: "password-timing-string-compare",
  outcome: "succeeded",  // 脆弱な === 比較では攻撃が成立
  startedAt: /* Unix ms */,
  finishedAt: /* Unix ms */,
  steps,
  blockedBy: "crypto.timingSafeEqual による定数時間比較",
  summary: "Short-circuit string comparison leaks timing information. crypto.timingSafeEqual eliminates the discrepancy.",
  summaryJa: "短絡評価文字列比較はタイミング情報を漏洩します。crypto.timingSafeEqual が差異を排除します。",
};
```

#### 防御策 (defenseRecommendation)

**既存実装ファイルへのリンク**:
- `server/routes/password-auth.ts:93` — `bcrypt.compare(password, user.password_hash)` の実装
  (bcrypt.compare は内部的に定数時間比較を使用しているため、タイミング攻撃に耐性がある)

**防御策の要点**:

1. パスワード比較には必ず定数時間比較関数を使用する
2. `bcrypt.compare` は内部実装で定数時間比較を使用しているため安全
3. 独自の文字列比較が必要な場合は `crypto.timingSafeEqual` を使用する

**codeHints の具体例**:

```typescript
import crypto from "crypto";

// 脆弱な実装 (使用禁止)
function vulnerable(a: string, b: string): boolean {
  return a === b;  // 短絡評価 — タイミング情報を漏洩する
}

// 安全な実装 (推奨)
function timingSafe(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  // 長さが異なる場合も情報漏洩しないよう固定長バッファを使用
  const len = Math.max(bufA.length, bufB.length);
  const paddedA = Buffer.alloc(len);
  const paddedB = Buffer.alloc(len);
  bufA.copy(paddedA);
  bufB.copy(paddedB);
  return crypto.timingSafeEqual(paddedA, paddedB);
}

// bcrypt を使用する場合はそのまま compare でよい (内部が定数時間)
import bcrypt from "bcryptjs";
const match = await bcrypt.compare(inputPassword, storedHash); // 安全
```

#### API 契約

```
POST /api/auth/password/attack/timing-string-compare
```

**リクエスト**:

```json
{
  "username": "seed_alice",
  "targetPassword": "password123",
  "probePasswords": [
    "x_______",
    "pas_____",
    "password123"
  ]
}
```

| フィールド | 型 | 必須 | 説明 |
|-----------|---|------|------|
| `username` | `string` | 必須 | 固定シードユーザー名 |
| `targetPassword` | `string` | 必須 | 正解となるパスワード (シードユーザーのパスワード) |
| `probePasswords` | `string[]` | 必須 | 計測対象のパスワード候補 (最大 5 件) |

**レスポンス**:

```json
{
  "success": true,
  "data": {
    "scenarioId": "password-timing-string-compare",
    "outcome": "succeeded",
    "startedAt": 1745592000000,
    "finishedAt": 1745592000200,
    "steps": [
      {
        "id": "step-1",
        "kind": "probe",
        "label": "Measure response time with 0-character match",
        "labelJa": "先頭文字不一致のケースで応答時間を計測",
        "status": "success",
        "payload": {
          "type": "generic",
          "data": {
            "testedPassword": "x_______",
            "matchedChars": 0,
            "responseTimeMs": 1.2,
            "compareMethod": "=== (short-circuit)"
          }
        },
        "timestamp": 1745592000050
      }
    ],
    "summary": "Short-circuit comparison leaks timing. timingSafeEqual eliminates the discrepancy.",
    "summaryJa": "短絡評価比較はタイミングを漏洩します。timingSafeEqual が差異を排除します。"
  },
  "_trace": {
    "cryptoOps": [
      {
        "op": "string.===",
        "input": "probe=\\\"x_______\\\" vs target=\\\"password123\\\"",
        "output": "false (stopped at char 0)",
        "algo": "short-circuit-equal",
        "detail": "Comparison terminated at first character. Simulated time: 1.2ms"
      },
      {
        "op": "crypto.timingSafeEqual",
        "input": "probe=\\\"x_______\\\" vs target=\\\"password123\\\"",
        "output": "false (all bytes compared)",
        "algo": "timing-safe-equal",
        "detail": "All bytes compared regardless of match length. Simulated time: 2.1ms"
      }
    ],
    "attackSteps": [ /* AttackStep[] */ ]
  }
}
```

#### _trace 内訳

| trace 種別 | 内容 |
|-----------|------|
| `CryptoOp` | `string.===` による短絡評価比較と `crypto.timingSafeEqual` による定数時間比較の各応答時間 (サーバー側でシミュレーション値として生成) |
| `AttackStep` | 上記 4 ステップ (probe x2 → exploit → blocked) |
| `DbQuery` | なし (このシナリオは DB アクセス不要) |

**注意**: 実際の応答時間差異はサーバー側で `Math.max(0, matchedChars * 0.15) + Math.random() * 0.5` 相当の
人工的なシミュレーション値として生成する。実測値ではない旨を DataFlowPanel に注記表示する。

#### UI フロー

```
[Attacker View 起動]
  ↓
[教育用バナー表示: 常時固定]
  ↓
[シナリオセレクタ: "タイミング攻撃 (文字列比較)" を選択]
  ↓
[プローブパスワード入力 (最大 5 件)] + [「攻撃を実行」ボタン]
  ↓
[AttackStepTimeline アニメーション]
  step-1 probe:  先頭0文字一致 → SUCCESS + 応答時間 1.2ms
  step-2 probe:  先頭3文字一致 → SUCCESS + 応答時間 1.8ms
  step-3 exploit: タイミング差異から文字を推定 → SUCCESS
  step-4 verify:  定数時間比較で差異なし → BLOCKED (緑)
  ↓
[応答時間比較グラフ: 棒グラフ or テーブルで === vs timingSafeEqual を並列表示]
  ↓
[AttackResultBanner: "この実装は脆弱です: 短絡評価比較がタイミング情報を漏洩します"]
  ↓
[AttackDefensePanel: crypto.timingSafeEqual の使用方法]
  ↓
[DataFlowPanel: HTTP / Trace (CryptoOp 比較) ]
```

#### i18n キー一覧 (このシナリオ固有)

| キー概念 | 日本語 | English |
|---------|--------|---------|
| シナリオ名 | `タイミング攻撃 (文字列比較)` | `Timing Attack (String Comparison)` |
| プローブ入力ラベル | `試行パスワード (最大5件)` | `Probe passwords (up to 5)` |
| 応答時間ラベル | `応答時間 (ms)` | `Response time (ms)` |
| step-1 ラベル | `先頭文字不一致のケースで応答時間を計測` | `Measure response time: 0-character match` |
| step-2 ラベル | `先頭3文字一致のケースで応答時間を計測` | `Measure response time: 3-character match` |
| step-3 ラベル | `タイミング差異からパスワードを推定` | `Infer password via timing difference` |
| step-4 ラベル | `定数時間比較がタイミング差異を排除することを確認` | `Verify timing-safe comparison eliminates discrepancy` |
| シミュレーション注記 | `注: 応答時間は概念的差異を誇張したシミュレーション値です` | `Note: Response times are exaggerated simulation values for conceptual clarity` |
| 攻撃成立メッセージ | `この実装は脆弱です: 短絡評価比較がタイミング情報を漏洩します` | `This implementation is vulnerable: short-circuit comparison leaks timing information` |
| 防御成立メッセージ | `防御が機能しました: crypto.timingSafeEqual がタイミング差異を排除しました` | `Defense succeeded: crypto.timingSafeEqual eliminated timing discrepancy` |

---

### 4.3 `password-bruteforce-no-rate-limit`

#### 概要

これは **CWE-307 / CAPEC-112** の概念実証である。
ログイン失敗回数に上限を設けていない実装では、攻撃者が辞書攻撃 (よく使われるパスワードの
リストを順に試行する方法) によって正解パスワードを発見できる。
100 候補パスワードの固定辞書を投げ、レート制限あり/なしで成功/阻止される様子を比較表示する。

**実環境との差異の注記 (必須)**:
実環境では IP レート制限・WAF・CAPTCHA・アカウントロックアウトにより阻止されます。
このデモではサーバー側でシミュレーション結果を一括返却しており、
実際にブラウザから 100 リクエストを送信するわけではありません。

#### CWE / CAPEC / OSI 層

| 項目 | 値 |
|------|-----|
| CWE | CWE-307 (Improper Restriction of Excessive Authentication Attempts) |
| CAPEC | CAPEC-112 (Brute Force) |
| OSI 層 | Layer 7 — Application |
| 深刻度 | High |

#### 前提条件 (脆弱な実装の例)

攻撃者は以下の条件を満たしている:

1. 標的ユーザー名を特定済み (`seed_alice` — ユーザー列挙攻撃によって発見)
2. ログインエンドポイントに失敗回数の制限がなく、何度でも試行できる
3. 攻撃者は上位パスワードの辞書を保有している

**脆弱な実装例** (このシナリオでシミュレーションする実装):

```typescript
// 脆弱な実装例 (教育用シミュレーション専用 — 現実装のログインに相当)
// server/routes/password-auth.ts の POST /login は現在レート制限なし
app.post("/login", async (c) => {
  const { username, password } = await c.req.json();
  // ← ここに失敗カウンターの確認なし / レート制限なし
  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
  const match = await bcrypt.compare(password, user.password_hash);
  return c.json({ success: match });
  // ← 失敗してもカウンターを増加させない / ロックアウトなし
});
```

#### 攻撃ステップ (AttackStep[] の具体例)

```typescript
// SEED_DICTIONARY: サーバー側に埋め込む固定辞書 (100 件)
// 実際のリクエストはサーバー側でシミュレーションするため、
// フロントエンドからは単一の API 呼び出しのみ行う (DESIGN/04 §1.3 簡略化原則に準拠)

const steps: AttackStep[] = [
  {
    id: "step-1",
    kind: "probe",
    label: "Enumerate target username via login error messages",
    labelJa: "ログインエラーメッセージでターゲットのユーザー名を特定",
    status: "success",
    payload: {
      type: "http",
      request: {
        method: "POST",
        url: "/api/auth/password/login",
        body: { username: "seed_alice", password: "wrong" },
      },
      response: {
        status: 401,
        body: { success: false, error: "Invalid password" },
        // "User not found" ではなく "Invalid password" → ユーザー名は存在する
      },
    },
    detail: "Different error messages for 'user not found' vs 'invalid password' reveal valid usernames.",
    detailJa: "'ユーザーが見つかりません' と 'パスワードが無効です' の異なるエラーメッセージが有効なユーザー名を明かします。",
    timestamp: Date.now(),
  },
  {
    id: "step-2",
    kind: "probe",
    label: "Submit 100-entry dictionary without rate limiting (simulated server-side)",
    labelJa: "レート制限なしで 100 件の辞書を投入 (サーバー側シミュレーション)",
    status: "success",
    payload: {
      type: "generic",
      data: {
        wordlistSize: 100,
        attemptsSimulated: 100,
        rateLimitEnabled: false,
        blockedAt: null,
        foundAt: 42,
        foundPassword: "password123",
        elapsedMs: 450,
      },
    },
    detail: "Without rate limiting, 100 passwords can be tested rapidly. Match found at attempt #42.",
    detailJa: "レート制限がなければ 100 件のパスワードを即座に試行できます。42 回目で一致が発見されました。",
    timestamp: Date.now(),
  },
  {
    id: "step-3",
    kind: "exploit",
    label: "Authenticate with discovered password",
    labelJa: "発見したパスワードで認証成功",
    status: "success",
    payload: {
      type: "http",
      request: {
        method: "POST",
        url: "/api/auth/password/login",
        body: { username: "seed_alice", password: "password123" },
      },
      response: {
        status: 200,
        body: {
          success: true,
          data: {
            user: { id: 1, username: "seed_alice" },
            message: "Login successful",
          },
        },
      },
    },
    detail: "Authentication succeeded with the discovered password. Account is compromised.",
    detailJa: "発見したパスワードで認証が成功しました。アカウントが侵害されています。",
    timestamp: Date.now(),
  },
  {
    id: "step-4",
    kind: "blocked",
    label: "Verify: rate limiting blocks the same attack",
    labelJa: "確認: レート制限が同じ攻撃を阻止する",
    status: "blocked",
    payload: {
      type: "generic",
      data: {
        wordlistSize: 100,
        attemptsSimulated: 5,
        rateLimitEnabled: true,
        rateLimitPolicy: "5 failures per minute per IP",
        blockedAt: 5,
        blockedResponse: { status: 429, error: "Too Many Requests. Try again in 60 seconds." },
      },
    },
    detail: "With rate limiting enabled, the attacker is blocked after 5 failed attempts.",
    detailJa: "レート制限が有効な場合、攻撃者は 5 回の失敗後にブロックされます。",
    timestamp: Date.now(),
  },
];
```

#### 期待される結果 (AttackResult)

```typescript
const result: AttackResult = {
  scenarioId: "password-bruteforce-no-rate-limit",
  outcome: "succeeded",  // レート制限なし実装では攻撃が成立
  startedAt: /* Unix ms */,
  finishedAt: /* Unix ms */,
  steps,
  blockedBy: "レート制限 (5 failures/min/IP)",
  summary: "Without rate limiting, 100-entry dictionary succeeded in 42 attempts. Rate limiting blocked at attempt #5.",
  summaryJa: "レート制限がない場合、100 件の辞書攻撃が 42 回目で成功しました。レート制限は 5 回目でブロックしました。",
};
```

#### 防御策 (defenseRecommendation)

**既存実装ファイルへのリンク**:
- `server/routes/password-auth.ts:69-115` — POST /login ハンドラ (現状レート制限なし)
- `server/db/schema.ts:36-43` — `users` テーブル (現状 `login_attempts` カラムなし)

**防御策の要点**:

1. IP ごとのログイン失敗回数を計測し、閾値超過でレート制限または一時ブロックを実施する
2. ユーザーアカウント単位でのロックアウト (例: 10 回失敗で 15 分ロック) を実装する
3. ユーザー列挙を防ぐため、存在しないユーザーと誤パスワードのエラーメッセージを統一する
4. 重要エンドポイントには CAPTCHA または多要素認証を追加する

**codeHints の具体例**:

```typescript
// server/routes/password-auth.ts への追加例 (概念)
import { RateLimiter } from "some-rate-limit-library";

const loginLimiter = new RateLimiter({
  windowMs: 60 * 1000,  // 1 分
  max: 5,               // 最大 5 回
  message: "Too Many Requests. Try again in 60 seconds.",
  keyGenerator: (c) => c.req.header("x-forwarded-for") ?? "unknown",
});

passwordAuthRoutes.post("/login", loginLimiter, async (c) => {
  // ... 既存のログイン処理
});

// ユーザー列挙防止: エラーメッセージを統一する
if (!user || !(await bcrypt.compare(password, user.password_hash))) {
  // "User not found" と "Invalid password" を区別しない
  return c.json({ success: false, error: "Invalid credentials" }, 401);
}
```

```sql
-- users テーブルへのカラム追加案
ALTER TABLE users ADD COLUMN login_attempts INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN locked_until TEXT;  -- ISO 8601
```

#### API 契約

```
POST /api/auth/password/attack/bruteforce-no-rate-limit
```

**リクエスト**:

```json
{
  "username": "seed_alice",
  "wordlist": [
    "123456", "password", "12345678", "qwerty", "abc123",
    "monkey", "1234567", "letmein", "trustno1", "dragon",
    "password123"
  ],
  "rateLimitEnabled": false
}
```

| フィールド | 型 | 必須 | 説明 |
|-----------|---|------|------|
| `username` | `string` | 必須 | 固定シードユーザー名 |
| `wordlist` | `string[]` | 必須 | 試行パスワード候補 (最大 20 件。デモ簡略化のため上限あり) |
| `rateLimitEnabled` | `boolean` | 任意 | `true` の場合、5 回でブロックするシミュレーションを行う (デフォルト `false`) |

**レスポンス (レート制限なし、パスワード一致あり)**:

```json
{
  "success": true,
  "data": {
    "scenarioId": "password-bruteforce-no-rate-limit",
    "outcome": "succeeded",
    "startedAt": 1745592000000,
    "finishedAt": 1745592000450,
    "steps": [
      {
        "id": "step-1",
        "kind": "probe",
        "label": "Enumerate target username via login error messages",
        "labelJa": "ログインエラーメッセージでターゲットのユーザー名を特定",
        "status": "success",
        "payload": {
          "type": "http",
          "request": { "method": "POST", "url": "/api/auth/password/login", "body": { "username": "seed_alice", "password": "wrong" } },
          "response": { "status": 401, "body": { "success": false, "error": "Invalid password" } }
        },
        "timestamp": 1745592000100
      },
      {
        "id": "step-2",
        "kind": "probe",
        "label": "Submit dictionary without rate limiting",
        "labelJa": "レート制限なしで辞書を投入",
        "status": "success",
        "payload": {
          "type": "generic",
          "data": {
            "wordlistSize": 11,
            "rateLimitEnabled": false,
            "foundAt": 11,
            "foundPassword": "password123",
            "elapsedMs": 320
          }
        },
        "timestamp": 1745592000200
      },
      {
        "id": "step-3",
        "kind": "exploit",
        "label": "Authenticate with discovered password",
        "labelJa": "発見したパスワードで認証成功",
        "status": "success",
        "payload": {
          "type": "http",
          "request": { "method": "POST", "url": "/api/auth/password/login", "body": { "username": "seed_alice", "password": "password123" } },
          "response": { "status": 200, "body": { "success": true, "data": { "user": { "id": 1, "username": "seed_alice" } } } }
        },
        "timestamp": 1745592000400
      }
    ],
    "summary": "Without rate limiting, dictionary attack found the password at attempt #11.",
    "summaryJa": "レート制限がない場合、辞書攻撃が 11 回目でパスワードを発見しました。"
  },
  "_trace": {
    "dbQueries": [
      {
        "sql": "SELECT id, username, password_hash FROM users WHERE username = ? AND is_attack_sim = 0",
        "params": ["seed_alice"],
        "rows": [{ "id": 1, "username": "seed_alice", "password_hash": "$2a$10$..." }],
        "ms": 1.2
      }
    ],
    "cryptoOps": [
      {
        "op": "bcrypt.compare (bulk simulation)",
        "input": "wordlist_size=11, target_username=seed_alice",
        "output": "match found at index 10: \\\"password123\\\"",
        "algo": "bcrypt",
        "detail": "Server-side simulation of 11 bcrypt.compare() calls. Each call ~100ms at saltRounds=10."
      }
    ],
    "attackSteps": [ /* AttackStep[] */ ]
  }
}
```

**レスポンス (レート制限あり)**:

```json
{
  "success": true,
  "data": {
    "scenarioId": "password-bruteforce-no-rate-limit",
    "outcome": "blocked",
    "blockedBy": "rate_limit_5_per_minute",
    "steps": [
      {
        "id": "step-4",
        "kind": "blocked",
        "label": "Rate limiting blocks after 5 attempts",
        "labelJa": "レート制限が 5 回目でブロック",
        "status": "blocked",
        "payload": {
          "type": "http",
          "response": { "status": 429, "body": { "error": "Too Many Requests. Try again in 60 seconds." } }
        },
        "timestamp": 1745592000500
      }
    ],
    "summary": "Rate limiting blocked the attack after 5 failed attempts.",
    "summaryJa": "レート制限が 5 回の失敗後に攻撃をブロックしました。"
  },
  "_trace": { /* ... */ }
}
```

#### _trace 内訳

| trace 種別 | 内容 |
|-----------|------|
| `DbQuery` | `SELECT users WHERE username = ? AND is_attack_sim = 0` — シードユーザーの hash 取得 |
| `CryptoOp` | `bcrypt.compare (bulk simulation)` — 辞書全件のバルク比較結果サマリー (個別ログは省略してサマリーのみ) |
| `AttackStep` | probe (ユーザー列挙) → probe (辞書投入) → exploit (認証成功) → blocked (レート制限) |

#### UI フロー

```
[Attacker View 起動]
  ↓
[教育用バナー表示: 常時固定]
  ↓
[シナリオセレクタ: "レート制限なしブルートフォース" を選択]
  ↓
[設定エリア]
  - ターゲットユーザー名: seed_alice (固定)
  - 辞書パスワード: プリセット 20 件 (編集不可。ユーザーが任意のパスワードをリストに追加できると
    実際の攻撃ツールになるため禁止)
  - レート制限トグル: OFF (脆弱) / ON (防御済み) ← このトグルが教材の核心
  ↓
[「攻撃を実行」ボタン]
  ↓
[AttackStepTimeline アニメーション]
  step-1 probe:   ユーザー名列挙 → SUCCESS
  step-2 probe:   辞書投入結果 (レート制限 OFF → 42 回目で発見 / ON → 5 回でブロック)
  step-3 exploit: 認証成功 (レート制限 OFF 時のみ)
  step-4 blocked: レート制限ブロック (レート制限 ON 時のみ)
  ↓
[AttackResultBanner]
  レート制限 OFF: "この実装は脆弱です: レート制限がなければブルートフォースが成立しました"
  レート制限 ON:  "防御が機能しました: レート制限が 5 回目で攻撃をブロックしました"
  ↓
[AttackDefensePanel: レート制限・アカウントロックアウト・ユーザー列挙防止の実装方法]
  ↓
[DataFlowPanel: HTTP / Trace (CryptoOp bulk sim) / DB (users 検索)]
```

#### i18n キー一覧 (このシナリオ固有)

| キー概念 | 日本語 | English |
|---------|--------|---------|
| シナリオ名 | `レート制限なしブルートフォース` | `Brute Force Without Rate Limiting` |
| レート制限トグルラベル | `レート制限` | `Rate Limiting` |
| レート制限 OFF ラベル | `無効 (脆弱な実装)` | `Disabled (Vulnerable)` |
| レート制限 ON ラベル | `有効 (防御済み)` | `Enabled (Protected)` |
| step-1 ラベル | `ログインエラーメッセージでターゲットのユーザー名を特定` | `Enumerate target username via error message difference` |
| step-2 ラベル | `レート制限なしで辞書を投入 (サーバー側シミュレーション)` | `Submit dictionary without rate limiting (server-side simulation)` |
| step-3 ラベル | `発見したパスワードで認証成功` | `Authenticate with discovered password` |
| step-4 ラベル | `レート制限が攻撃をブロック` | `Rate limiting blocks the attack` |
| 辞書件数ラベル | `辞書パスワード候補数` | `Dictionary wordlist size` |
| 発見ラベル | `{N} 回目で一致` | `Match found at attempt #{N}` |
| 攻撃成立メッセージ | `この実装は脆弱です: レート制限がなければブルートフォースが成立しました` | `This implementation is vulnerable: without rate limiting, brute force succeeded` |
| 防御成立メッセージ | `防御が機能しました: レート制限が {N} 回目で攻撃をブロックしました` | `Defense succeeded: rate limiting blocked the attack at attempt #{N}` |
| サーバーシミュレーション注記 | `注: ブラウザから実際のリクエストを {N} 件送信しているわけではありません` | `Note: This does not send {N} actual requests from the browser` |

---

## 5. UI コンポーネント設計

### 5.1 ディレクトリ構成

```
src/components/auth/attacks/password/
├── PasswordAttackPanel.tsx      ← 3シナリオを統括するメインパネル
├── RainbowVsBcryptScenario.tsx  ← シナリオ A の実行ロジックと入力フォーム
├── TimingAttackScenario.tsx     ← シナリオ B の実行ロジックと入力フォーム
├── BruteForceScenario.tsx       ← シナリオ C の実行ロジックとレート制限トグル
└── PasswordAttack.css           ← 3シナリオ共通スタイル
```

### 5.2 `PasswordAttackPanel.tsx` の責務

```typescript
// AuthMethods.tsx への組み込みイメージ
import PasswordAttackPanel from "./attacks/password/PasswordAttackPanel";
import { Show } from "solid-js";

// useSearchParams から viewMode を取得
<Show when={viewMode() === "attacker"}>
  <PasswordAttackPanel tabId="auth-methods" />
</Show>
```

`PasswordAttackPanel` は以下を担当する:

1. `EducationalWarningBanner` の常時表示
2. `AttackScenarioSelector` で 3 シナリオの切り替え
3. 選択中シナリオに対応する `RainbowVsBcryptScenario` / `TimingAttackScenario` / `BruteForceScenario` のレンダリング
4. `DataFlowPanel scopeId="attack-auth-methods"` の表示

各シナリオコンポーネントは `onRunScenario` コールバック経由で API を呼び出し、
結果を `setCurrentResult()` に設定する。

### 5.3 各シナリオコンポーネントの props 設計

```typescript
// RainbowVsBcryptScenario.tsx
interface RainbowVsBcryptScenarioProps {
  onResult: (result: AttackResult) => void;
  onRunning: (running: boolean) => void;
}

// TimingAttackScenario.tsx
interface TimingAttackScenarioProps {
  onResult: (result: AttackResult) => void;
  onRunning: (running: boolean) => void;
}

// BruteForceScenario.tsx
interface BruteForceScenarioProps {
  onResult: (result: AttackResult) => void;
  onRunning: (running: boolean) => void;
}
```

---

## 6. テスト要件

### 6.1 ユニットテスト (バックエンドハンドラ単体)

対象ファイル: `server/routes/password-auth.ts` への攻撃サブパス追加分

| テスト ID | 検証内容 | 期待結果 |
|---------|---------|---------|
| `pw-atk-01` | `POST /attack/rainbow-vs-bcrypt` に `algorithm: "sha1"` を送信 | `outcome: "succeeded"`, step-4 の `status: "blocked"` を含む |
| `pw-atk-02` | `POST /attack/rainbow-vs-bcrypt` に `algorithm: "bcrypt"` を送信 | `outcome: "blocked"`, 全ステップの `status: "blocked"` |
| `pw-atk-03` | `POST /attack/timing-string-compare` に先頭0文字一致のプローブを送信 | `cryptoOps` に `string.===` の短絡評価記録が含まれる |
| `pw-atk-04` | `POST /attack/bruteforce-no-rate-limit` に `rateLimitEnabled: false` で送信 | `outcome: "succeeded"`, `foundAt` が非 null |
| `pw-atk-05` | `POST /attack/bruteforce-no-rate-limit` に `rateLimitEnabled: true` で送信 | `outcome: "blocked"`, `blockedBy: "rate_limit_5_per_minute"` |
| `pw-atk-06` | `POST /attack/rainbow-vs-bcrypt` に存在しないユーザー名を送信 | `400 Bad Request`, バリデーションエラー |
| `pw-atk-07` | `POST /attack/bruteforce-no-rate-limit` に 21 件の wordlist を送信 | `400 Bad Request` (上限 20 件制約) |
| `pw-atk-08` | 本番環境 (`NODE_ENV=production`) でいずれかの攻撃エンドポイントに送信 | `403 Forbidden` |

### 6.2 E2E テスト (UI フロー)

対象: `src/components/auth/attacks/password/PasswordAttackPanel.tsx`

| テスト ID | 操作 | 期待結果 |
|---------|------|---------|
| `e2e-pw-01` | AuthMethods タブで Attacker View に切り替える | `EducationalWarningBanner` が表示される |
| `e2e-pw-02` | シナリオ A を選択して「攻撃を実行」を押す | `AttackStepTimeline` が 4 ステップを順に表示し、step-4 が緑 BLOCKED になる |
| `e2e-pw-03` | シナリオ C でレート制限 ON にして実行する | `AttackResultBanner` が緑 (防御成立) で表示される |
| `e2e-pw-04` | シナリオ C でレート制限 OFF にして実行する | `AttackResultBanner` がオレンジ (攻撃成立) で表示される |
| `e2e-pw-05` | 攻撃完了後に防御策パネルを確認する | `AttackDefensePanel` が自動展開されている |
| `e2e-pw-06` | Defender View に切り替える | 通常の `PasswordDemo` が表示され、攻撃バナーが消える |

---

## 7. i18n キー一覧表 (ja/en)

| # | キー概念 | 日本語 | English |
|---|---------|--------|---------|
| 1 | 攻撃者モード切替 | `攻撃者モード` | `Attacker Mode` |
| 2 | 防御者モード切替 | `防御者モード` | `Defender Mode` |
| 3 | 教育バナーテキスト | `教育用シミュレーション — 実環境を攻撃するためのコードではありません` | `Educational simulation — not for use against real systems` |
| 4 | シナリオ A 名 | `bcrypt vs レインボーテーブル比較` | `bcrypt vs Rainbow Table Comparison` |
| 5 | シナリオ B 名 | `タイミング攻撃 (文字列比較)` | `Timing Attack (String Comparison)` |
| 6 | シナリオ C 名 | `レート制限なしブルートフォース` | `Brute Force Without Rate Limiting` |
| 7 | 攻撃実行ボタン | `攻撃を実行` | `Run Attack` |
| 8 | 実行中ラベル | `実行中...` | `Running...` |
| 9 | 攻撃成立バナー | `攻撃成立 — この実装は脆弱です` | `Attack succeeded — this implementation is vulnerable` |
| 10 | 防御成立バナー | `防御成立 —` | `Defense succeeded —` |
| 11 | 前提条件ラベル | `前提条件:` | `Prerequisite:` |
| 12 | 深刻度ラベル | `深刻度:` | `Severity:` |
| 13 | 防御策を見るボタン | `防御策を見る` | `Show Defense Recommendation` |
| 14 | ペイロード展開ラベル | `ペイロード` | `Payload` |
| 15 | アルゴリズム選択ラベル | `ハッシュアルゴリズムを選択` | `Select hash algorithm` |
| 16 | SHA-1 ラベル | `SHA-1 (安全でない)` | `SHA-1 (insecure)` |
| 17 | MD5 ラベル | `MD5 (安全でない)` | `MD5 (insecure)` |
| 18 | bcrypt ラベル | `bcrypt (推奨)` | `bcrypt (recommended)` |
| 19 | 応答時間ラベル | `応答時間 (ms)` | `Response time (ms)` |
| 20 | レート制限トグル | `レート制限` | `Rate Limiting` |
| 21 | レート制限 OFF | `無効 (脆弱な実装)` | `Disabled (Vulnerable)` |
| 22 | レート制限 ON | `有効 (防御済み)` | `Enabled (Protected)` |
| 23 | 辞書件数ラベル | `辞書パスワード候補数` | `Dictionary wordlist size` |
| 24 | 一致発見ラベル | `{N} 回目で一致` | `Match found at attempt #{N}` |
| 25 | シミュレーション注記 (レインボー) | `注: このデモは 10 件の固定辞書によるシミュレーションです` | `Note: This demo uses a 10-entry fixed dictionary simulation` |
| 26 | シミュレーション注記 (タイミング) | `注: 応答時間は概念的差異を誇張したシミュレーション値です` | `Note: Response times are exaggerated simulation values for conceptual clarity` |
| 27 | シミュレーション注記 (ブルートフォース) | `注: ブラウザから実際のリクエストを複数送信しているわけではありません` | `Note: This does not send multiple actual requests from the browser` |
| 28 | Argon2id 推奨 | `OWASP は Argon2id をパスワードハッシュの第一推奨としています` | `OWASP recommends Argon2id as the primary choice for password hashing` |
| 29 | ユーザー列挙リスク | `異なるエラーメッセージは有効なユーザー名を特定するヒントになります` | `Different error messages reveal valid usernames to attackers` |
| 30 | タイムラインARIAラベル | `攻撃ステップログ` | `Attack step log` |

---

## 8. 関連ファイル

### 8.1 基盤設計書

| ファイル | 参照目的 |
|---------|---------|
| [DESIGN/00-overview.md](./00-overview.md) | 全体目的・カタログマトリクス・教育安全装置の4原則概要 |
| [DESIGN/01-architecture.md](./01-architecture.md) | バックエンドルート配置方針 (サブパス `/attack/*` 追加) / フロントエンドコンポーネント階層 |
| [DESIGN/02-ui-spec.md](./02-ui-spec.md) | `ViewModeToggle` / `AttackStepTimeline` / `AttackResultBanner` / `AttackDefensePanel` の詳細仕様 |
| [DESIGN/03-data-model.md](./03-data-model.md) | `AttackStep` / `AttackResult` / `AttackScenarioMeta` / `ServerTrace` 拡張の型定義 |
| [DESIGN/04-safety-guardrails.md](./04-safety-guardrails.md) | 禁止表現一覧 / ペイロード作成ルール / 開発レビューチェックリスト |

### 8.2 既存実装ファイル (変更・参照対象)

| ファイルパス | 変更種別 | 変更内容 |
|------------|---------|---------|
| `server/routes/password-auth.ts` | 追加 | `POST /attack/rainbow-vs-bcrypt`, `POST /attack/timing-string-compare`, `POST /attack/bruteforce-no-rate-limit` の 3 エンドポイントを追加 |
| `src/components/auth/AuthMethods.tsx` | 追加 | `ViewModeToggle` import + `<Show when={viewMode() === "attacker"}>` ブロックで `PasswordAttackPanel` を条件表示 |
| `server/db/schema.ts` | 追加 | `rainbow_table_sim` テーブル (教育専用固定辞書, 10 件) と `attack_log` テーブルの DDL を `initSchema()` に追加 / `seedDb()` にリセット処理を追加 |
| `shared/api-types.ts` | 追加 | `AttackStep`, `AttackResult`, `AttackScenarioMeta`, `ServerTrace` 拡張 (DESIGN/03 参照) |

### 8.3 新規作成ファイル

| ファイルパス | 役割 |
|------------|------|
| `src/components/auth/attacks/password/PasswordAttackPanel.tsx` | 3 シナリオを統括するメインパネル |
| `src/components/auth/attacks/password/RainbowVsBcryptScenario.tsx` | シナリオ A の実行ロジックと入力フォーム |
| `src/components/auth/attacks/password/TimingAttackScenario.tsx` | シナリオ B の実行ロジックと応答時間比較表示 |
| `src/components/auth/attacks/password/BruteForceScenario.tsx` | シナリオ C の実行ロジックとレート制限トグル |
| `src/components/auth/attacks/password/PasswordAttack.css` | 3 シナリオ共通スタイル |
| `src/components/auth/attacks/scenarios/password-scenarios.ts` | `AttackScenarioMeta[]` の静的定義 (3 シナリオ分) |

---

*このドキュメントは `DESIGN/10-attack-password.md` に配置。
実装を開始する前に DESIGN/00 〜 04 の基盤設計書を読了し、
特に DESIGN/04-safety-guardrails.md §4 のレビューチェックリストを確認すること。*
