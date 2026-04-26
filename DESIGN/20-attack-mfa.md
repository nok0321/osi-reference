---
title: 攻撃デモカタログ — MFA/TOTP 攻撃詳細
phase: design
tab-id: mfa
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

# 20. MFA/TOTP 攻撃カタログ

## 1. 概要

「MFA (mfa)」タブは、TOTP (Time-based One-Time Password) を用いた2要素認証の登録・ログインフローを
正常系で学ぶ既存の Defender View を持つ。このカタログは同タブに **Attacker View** を追加し、
TOTP および SMS OTP に対する攻撃が、どのような実装上の設計欠陥を突くものかを体感させる。

### 1.1 防御側既存実装の参照

| ファイル | 役割 |
|---------|------|
| `server/routes/mfa-totp.ts` | TOTP 登録 (`/enroll/start`, `/enroll/verify`) と 2 段階ログイン (`/login/step1`, `/login/step2`) のルートハンドラ。`verifyTotpWithDetail` (±1 時刻窓) を実装 |
| `server/utils/totp.ts` | `computeTotp` / `verifyTotpWithDetail` / `currentCounter` — HMAC-SHA1 + 動的切り捨て (RFC 6238) の実装。ウィンドウサイズは ±1 (±30 秒) |
| `src/components/auth/MfaFlow.tsx` | `MfaDemo` コンポーネント。登録/ログインフォーム + `user_mfa` テーブル表示 + `DataFlowPanel` による HTTP/Trace 可視化 |
| `server/db/schema.ts` | `user_mfa` テーブル: `user_id`, `secret`, `verified`, `created_at`, `verified_at` |

### 1.2 攻撃デモの追加方針

既存の `MfaFlow.tsx` に `ViewModeToggle` を追加し、Attacker View として
`MfaAttackPanel` コンポーネントを条件表示する。
攻撃 API は `server/routes/attack-mfa.ts` として新規作成し、
`server/index.ts` のルート登録に追加する
(DESIGN/01-architecture.md §2.1 のルート配置方針に準拠)。

---

## 2. 攻撃シナリオ一覧

| # | シナリオ ID | 攻撃名 | CWE | CAPEC | OSI 層 | 深刻度 |
|---|------------|--------|-----|-------|--------|-------|
| A | `mfa-otp-replay` | OTP リプレイ攻撃 | CWE-294 | CAPEC-60 | L7 (Application) | Medium |
| B | `mfa-time-window-too-wide` | 時刻同期ずれ攻撃 (時計の窓を広げすぎ) | CWE-208 | CAPEC-462 | L7 (Application) | Medium |
| C | `mfa-sms-swap` | SMS 乗っ取り (SIM スワップ シミュレーション) | CWE-308 / CWE-294 | CAPEC-115 | L7 (Application) | High |

---

## 3. 既存防御側実装

### 3.1 `server/routes/mfa-totp.ts` の構造

```
mfaTotpRoutes
├── POST /totp/enroll/start
│   ├── crypto.randomBytes(20)         ← 160bit CSPRNG シークレット生成 (RFC 6238)
│   ├── base32Encode(rawSecret)        ← RFC 4648 Base32 エンコード
│   ├── INSERT INTO user_mfa (upsert)  ← secret, verified=0 を保存
│   └── QRCode.toString(otpauthUri)    ← otpauth:// URI を SVG QR コードへ変換
├── POST /totp/enroll/verify
│   ├── base32Decode(secret)           ← シークレットをバイト列へ復元
│   ├── verifyTotpWithDetail()         ← ±1 窓 (t-1, t, t+1) で HMAC-SHA1 計算・比較
│   └── UPDATE user_mfa SET verified=1 ← 検証成功で MFA 有効化
├── POST /totp/login/step1
│   ├── bcrypt.compare(pw, hash)       ← 第1要素: パスワード検証
│   ├── loginChallenges.set(uuid, ...) ← 5分 TTL の challengeId 発行
│   └── { requiresMfa, challengeId }   ← Step2 へのバトン
└── POST /totp/login/step2
    ├── loginChallenges.get(challengeId) ← 既存チャレンジの解決
    ├── verifyTotpWithDetail()          ← 第2要素: TOTP 検証
    └── loginChallenges.delete()        ← チャレンジを消費 (1回限り)
```

`trace.addCryptoOp()` / `trace.addSessionOp()` / `trace.addDbQuery()` により、
各ステップの暗号操作・セッション操作・DB アクセスが `_trace` に記録され
`DataFlowPanel` の Trace タブで可視化される。

### 3.2 `server/utils/totp.ts` の TOTP 検証ロジック

```typescript
// 現行実装 (概要)
export function verifyTotpWithDetail(secret: string, code: string) {
  const key = base32Decode(secret);
  const counter = currentCounter();   // Math.floor(Date.now() / 1000 / TOTP_PERIOD)
  const window = 1;                   // ±1 = ±30 秒

  for (let delta = -window; delta <= window; delta++) {
    const candidate = computeTotp(key, counter + delta);
    if (timingSafeEqual(candidate, code)) return { match: ..., attempts: [...] };
  }
  return { match: null, attempts: [...] };
}
```

`TOTP_PERIOD = 30` 秒。ウィンドウは `±1` (= ±30 秒) で固定。
使用済み OTP を記録する仕組みは **現状未実装** (シナリオ A の攻撃対象)。

### 3.3 `server/db/schema.ts` の user_mfa テーブル

```sql
CREATE TABLE IF NOT EXISTS user_mfa (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER UNIQUE NOT NULL REFERENCES users(id),
  secret      TEXT NOT NULL,           -- Base32 エンコード済み TOTP シークレット
  verified    INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT DEFAULT (datetime('now')),
  verified_at TEXT
);
```

使用済み OTP を追跡する `used_otps` テーブルは現状存在しない (シナリオ A で体感)。

### 3.4 既存実装の防御上の強み

| 防御要素 | 実装箇所 | 効果 |
|---------|---------|------|
| ±1 時刻窓 | `verifyTotpWithDetail`, `window=1` | クロックドリフトを許容しつつ、許容範囲を ±30 秒に限定する |
| 定数時間比較 | `crypto.timingSafeEqual` (totp.ts 内部) | タイミング攻撃で OTP を推測されることを防ぐ |
| 短命 challengeId | `loginChallenges` TTL 5 分 | Step1 パスワード検証済みフラグを再使用させない |
| チャレンジ 1 回限り消費 | `loginChallenges.delete()` | Step2 完了後の challengeId 再利用を防ぐ |
| CSPRNG シークレット | `crypto.randomBytes(20)` | 160bit の予測不能なシークレット生成 |

### 3.5 既存実装の改善余地 (攻撃デモで体感する箇所)

| 項目 | 現状 | 改善案 |
|------|------|--------|
| 使用済み OTP の記録 | 未実装 | `used_otps` テーブルに検証済み OTP を TTL 付きで保存し、再使用を拒否する (シナリオ A) |
| 時刻窓の設定可変化 | ±1 固定 | 環境変数で設定可能にする。広げすぎない (±2 以上は非推奨) (シナリオ B) |
| SMS OTP サポート | 未実装 | SMS OTP は TOTP/Push に比べてセキュリティが低い。教材として「使うべきでない理由」を示す (シナリオ C) |

---

## 4. シナリオ詳細

---

### 4.1 `mfa-otp-replay`

#### 概要

これは **CWE-294 / CAPEC-60** の概念実証である。
TOTP は「時刻ベースのワンタイムパスワード」であり、本来は1回だけ使用できるよう設計されている。
しかし使用済みの OTP をサーバー側で記録・拒否する実装がない場合、
攻撃者がショルダーハッキング等で観測した OTP を同じ 30 秒ウィンドウ内に再送すれば、
サーバーは同一コードを2回目も正当なものとして受理してしまう。

このデモでは、`seed_alice` の TOTP コードを1回目に正常送信した直後、
同一コードを2回目に送信する。
「使用済み OTP DB なし」と「使用済み OTP DB あり (防御済み)」の挙動差を比較表示する。

**実環境との差異の注記 (必須)**:
実環境では攻撃者が同じ 30 秒ウィンドウ内に観測・再送する必要があり、タイミング的な制約がある。
ただし TOTP ウィンドウ ±1 を採用している場合、実際には最大 90 秒の有効期間があるため、
OTP リプレイのリスクは現実的な脅威として認識されている。

#### CWE / CAPEC / OSI 層

| 項目 | 値 |
|------|-----|
| CWE | CWE-294 (Authentication Bypass by Capture-replay) |
| CAPEC | CAPEC-60 (Reusing Session IDs (a.k.a. Session Replay)) |
| OSI 層 | Layer 7 — Application |
| 深刻度 | Medium |

#### 前提条件 (脆弱な実装の例)

攻撃者は以下の条件を満たしている:

1. 正規ユーザー (`seed_alice`) の TOTP コードを一度観測している
   (ショルダーハッキング、画面録画、フィッシングサイトへのリアルタイム中継等。このデモでは取得過程を省略)
2. サーバーが使用済み OTP を記録・拒否していない
3. 攻撃者は観測した OTP をその有効期間内 (最大 90 秒: ±1 窓の場合) に再送できる

**脆弱な実装例** (このシナリオでシミュレーションする実装):

```typescript
// 脆弱な実装例 (教育用シミュレーション専用 — 現行 totp/login/step2 に相当)
// verifyTotpWithDetail() が一致した時点で成功を返す
// → 同じコードを2回送っても2回目も一致してしまう

async function vulnerableLoginStep2(challengeId: string, code: string) {
  const challenge = loginChallenges.get(challengeId);
  const { match } = verifyTotpWithDetail(secret, code);
  if (match) {
    loginChallenges.delete(challengeId);
    return { success: true };   // ← 使用済みかどうかチェックしていない
  }
  return { success: false };
}
```

#### 攻撃ステップ (AttackStep[] の具体例)

```typescript
const steps: AttackStep[] = [
  {
    id: "step-1",
    kind: "intercept",
    label: "Observe TOTP code used by legitimate user",
    labelJa: "正規ユーザーが使用した TOTP コードを観測",
    status: "success",
    payload: {
      type: "generic",
      data: {
        username: "seed_alice",
        observedCode: "847291",   // 固定シードデモ値
        observedAt: "T+0s",
        validUntil: "T+90s",     // ±1 窓の場合の最大有効期間
        method: "shoulder-surfing (simulated)",
      },
    },
    detail: "Attacker observes a TOTP code entered by seed_alice. The code is valid for up to 90 seconds with ±1 window.",
    detailJa: "攻撃者は seed_alice が入力した TOTP コードを観測します。±1 窓では最大 90 秒間有効です。",
    timestamp: Date.now(),
  },
  {
    id: "step-2",
    kind: "exploit",
    label: "Replay the same OTP code within the valid window (no used-OTP DB)",
    labelJa: "有効期間内に同一 OTP コードを再送 (使用済み OTP DB なし)",
    status: "success",
    payload: {
      type: "http",
      request: {
        method: "POST",
        url: "/api/mfa/attack/otp-replay",
        body: {
          username: "seed_alice",
          code: "847291",       // 1回目と同一コード
          replayAttempt: true,
          replayDefenseEnabled: false,
        },
      },
      response: {
        status: 200,
        body: {
          success: true,
          outcome: "succeeded",
          detail: "OTP accepted on second use — no used-OTP record found",
        },
      },
    },
    detail: "The server accepts the replayed OTP because it has no record of prior use.",
    detailJa: "サーバーは使用済み記録がないため、再送された OTP を受理してしまいます。",
    timestamp: Date.now(),
  },
  {
    id: "step-3",
    kind: "verify",
    label: "Replay blocked when used-OTP DB is enabled",
    labelJa: "使用済み OTP DB が有効な場合はリプレイをブロック",
    status: "blocked",
    payload: {
      type: "http",
      request: {
        method: "POST",
        url: "/api/mfa/attack/otp-replay",
        body: {
          username: "seed_alice",
          code: "847291",
          replayAttempt: true,
          replayDefenseEnabled: true,
        },
      },
      response: {
        status: 401,
        body: {
          success: false,
          outcome: "blocked",
          blockedBy: "used_otps DB record",
          detail: "OTP '847291' already used at T+0s. Replay rejected.",
        },
      },
    },
    detail: "With used-OTP DB enabled, the server recognizes the code was already consumed and rejects it.",
    detailJa: "使用済み OTP DB が有効な場合、サーバーはコードが既に使用済みであることを認識し拒否します。",
    timestamp: Date.now(),
  },
];
```

#### 期待される結果 (AttackResult)

```typescript
const result: AttackResult = {
  scenarioId: "mfa-otp-replay",
  outcome: "succeeded",   // 使用済み OTP DB なし実装では攻撃が成立
  startedAt: /* Unix ms */,
  finishedAt: /* Unix ms */,
  steps,
  blockedBy: "used_otps テーブルによる使用済み OTP 記録",
  summary: "Without used-OTP tracking, a replayed TOTP code is accepted a second time. Tracking consumed OTPs blocks the replay.",
  summaryJa: "使用済み OTP を記録しない実装では、同一 OTP コードが2回目も受理されます。使用済み記録によりリプレイを阻止できます。",
};
```

UI 上の表示:
- step-1: 傍受 (オレンジ)
- step-2: 攻撃成立 (赤)  — 使用済み DB なし
- step-3: 防御成立 (緑)  — 使用済み DB あり

#### 防御策 (defenseRecommendation)

**既存実装ファイルへのリンク**:
- `server/routes/mfa-totp.ts:368-443` — `POST /totp/login/step2` (現状、使用済み OTP チェックなし)
- `server/db/schema.ts` — `user_mfa` テーブル定義 (`used_otps` テーブルは未追加)
- `server/utils/totp.ts` — `verifyTotpWithDetail` (TOTP 検証コアロジック)

**防御策の要点**:

1. TOTP 検証成功時に `(user_id, counter)` の組み合わせを `used_otps` テーブルに保存する
2. 次回以降の TOTP 検証時に `used_otps` を照合し、同一 `(user_id, counter)` が存在すれば拒否する
3. `used_otps` のレコードは counter 値の経過後 (例: ウィンドウ + 1 期間 = 約 90 秒) に削除してよい
4. 各 counter 値のエントリは 1 つのセッションでのみ有効とする

**codeHints の具体例**:

```typescript
// server/db/schema.ts への追加例
// CREATE TABLE IF NOT EXISTS used_otps (
//   id         INTEGER PRIMARY KEY AUTOINCREMENT,
//   user_id    INTEGER NOT NULL REFERENCES users(id),
//   counter    INTEGER NOT NULL,
//   used_at    TEXT DEFAULT (datetime('now')),
//   UNIQUE(user_id, counter)         -- 同一 counter の 2 回目使用を DB レベルで拒否
// );

// server/routes/mfa-totp.ts の step2 への追加例
const existingUse = db
  .prepare("SELECT id FROM used_otps WHERE user_id = ? AND counter = ?")
  .get(challenge.userId, match.counter);
if (existingUse) {
  return c.json({ success: false, error: "OTP already used. Please wait for the next code." }, 401);
}
// 使用済みとして記録
db.prepare("INSERT OR IGNORE INTO used_otps (user_id, counter) VALUES (?, ?)")
  .run(challenge.userId, match.counter);
```

**参考リンク**:
- RFC 6238 §5.2: https://www.rfc-editor.org/rfc/rfc6238#section-5.2 — TOTP アルゴリズム仕様 (リプレイ対策は実装者の責任)
- CWE-294: https://cwe.mitre.org/data/definitions/294.html
- CAPEC-60: https://capec.mitre.org/data/definitions/60.html

#### API 契約

```
POST /api/mfa/attack/otp-replay
```

**リクエスト**:

```json
{
  "username": "seed_alice",
  "code": "847291",
  "replayAttempt": true,
  "replayDefenseEnabled": false
}
```

| フィールド | 型 | 必須 | 説明 |
|-----------|---|------|------|
| `username` | `string` | 必須 | 固定シードユーザー名 (`seed_alice` / `seed_bob` のみ受け付ける) |
| `code` | `string` | 必須 | 6桁 OTP コード文字列 |
| `replayAttempt` | `boolean` | 任意 | `true` の場合、サーバーはこのコードが既に1回使用済みである状態をシミュレートする |
| `replayDefenseEnabled` | `boolean` | 任意 | `true` の場合、使用済み OTP DB のチェックを有効にする (デフォルト `false`) |

**レスポンス (防御なし、リプレイ成立)**:

```json
{
  "success": true,
  "data": {
    "scenarioId": "mfa-otp-replay",
    "outcome": "succeeded",
    "startedAt": 1745592000000,
    "finishedAt": 1745592000080,
    "steps": [
      {
        "id": "step-1",
        "kind": "intercept",
        "label": "Observe TOTP code used by legitimate user",
        "labelJa": "正規ユーザーが使用した TOTP コードを観測",
        "status": "success",
        "payload": { "type": "generic", "data": { "username": "seed_alice", "observedCode": "847291" } },
        "timestamp": 1745592000010
      },
      {
        "id": "step-2",
        "kind": "exploit",
        "label": "Replay the same OTP code (no used-OTP DB)",
        "labelJa": "同一 OTP コードを再送 (使用済み DB なし)",
        "status": "success",
        "payload": { "type": "http", "request": { "method": "POST", "url": "/api/mfa/attack/otp-replay", "body": { "code": "847291", "replayDefenseEnabled": false } }, "response": { "status": 200, "body": { "outcome": "succeeded" } } },
        "timestamp": 1745592000060
      }
    ],
    "summary": "Replayed OTP was accepted. No used-OTP record was found.",
    "summaryJa": "リプレイされた OTP が受理されました。使用済み記録が存在しません。"
  },
  "_trace": {
    "dbQueries": [
      {
        "sql": "SELECT secret FROM user_mfa WHERE user_id = ?",
        "params": [1],
        "rows": [{ "secret": "JBSWY3D..." }],
        "ms": 0.9
      },
      {
        "sql": "SELECT id FROM used_otps WHERE user_id = ? AND counter = ?",
        "params": [1, 58203],
        "rows": [],
        "ms": 0.4
      }
    ],
    "cryptoOps": [
      {
        "op": "totp.verify",
        "input": "code=\"847291\", counter_base=58203, window=±1",
        "output": "MATCH ✓ at counter=58203",
        "algo": "HMAC-SHA1 + Dynamic Truncation (RFC 6238)",
        "detail": "OTP validated. No used-OTP record checked — replay succeeds."
      }
    ],
    "attackSteps": [],
    "isAttackMode": true
  }
}
```

**レスポンス (防御あり、リプレイ阻止)**:

```json
{
  "success": true,
  "data": {
    "scenarioId": "mfa-otp-replay",
    "outcome": "blocked",
    "blockedBy": "used_otps DB record",
    "steps": [
      {
        "id": "step-3",
        "kind": "blocked",
        "label": "Replay blocked by used-OTP DB",
        "labelJa": "使用済み OTP DB がリプレイをブロック",
        "status": "blocked",
        "payload": { "type": "http", "response": { "status": 401, "body": { "error": "OTP already used. Please wait for the next code." } } },
        "timestamp": 1745592000080
      }
    ],
    "summary": "Replay blocked: OTP counter 58203 already recorded in used_otps.",
    "summaryJa": "リプレイがブロックされました: OTP カウンター 58203 は used_otps に記録済みです。"
  },
  "_trace": {
    "dbQueries": [
      {
        "sql": "SELECT id FROM used_otps WHERE user_id = ? AND counter = ?",
        "params": [1, 58203],
        "rows": [{ "id": 7, "user_id": 1, "counter": 58203 }],
        "ms": 0.5
      }
    ],
    "cryptoOps": [],
    "isAttackMode": true
  }
}
```

#### _trace 内訳

| trace 種別 | 内容 |
|-----------|------|
| `DbQuery` | `SELECT secret FROM user_mfa` — シークレット取得 / `SELECT id FROM used_otps` — 使用済み確認 (防御有効時は行が返る) |
| `CryptoOp` | `totp.verify` — HMAC-SHA1 検証結果と counter 値 |
| `SessionOp` | なし (攻撃ルートは challengeId なしで単体動作) |

#### UI フロー

```
[Attacker View 起動]
  ↓
[教育用バナー表示: 常時固定]
  ↓
[シナリオセレクタ: "OTP リプレイ攻撃" を選択]
  ↓
[設定エリア]
  - ターゲットユーザー: seed_alice (固定)
  - 使用済み OTP DB トグル: OFF (脆弱) / ON (防御済み) ← このトグルが教材の核心
  ↓
[「攻撃を実行」ボタン]
  ↓
[AttackStepTimeline アニメーション]
  step-1 intercept: OTP コードを観測 → 傍受表示 (オレンジ)
  step-2 exploit:   リプレイ送信 → 成立/ブロック (DB トグルにより変化)
  step-3 verify:    防御動作確認 (DB ON 時のみ表示)
  ↓
[AttackResultBanner]
  DB OFF: "この実装は脆弱です: 使用済み OTP が再度受理されました"
  DB ON:  "防御が機能しました: used_otps テーブルがリプレイを拒否しました"
  ↓
[AttackDefensePanel 自動展開: used_otps テーブル追加の実装例]
  ↓
[DataFlowPanel: HTTP / Trace (HMAC-SHA1 検証) / DB (used_otps 照合)]
```

---

### 4.2 `mfa-time-window-too-wide`

#### 概要

これは **CWE-208 / CAPEC-462** の概念実証である。
TOTP サーバーは通常、クロックドリフト (サーバーとクライアントの時刻のわずかなずれ) を吸収するため
±1 ステップ (±30 秒) の許容ウィンドウを設ける。
しかし設定ミスや「ユーザーの利便性のため」という理由でウィンドウを ±10 ステップ (±5 分) 等と
広くした実装では、攻撃者が観測した OTP を最大 10 分間 (前後5分) 使い回せることになる。
この「時計の窓」の設定値が攻撃耐性に直結することを体感させる。

このデモでは、同一の TOTP コードを「発行後 90 秒経過後」に再送する。
ウィンドウ ±1 (±30 秒) では拒否され、ウィンドウ ±10 (±5 分) では受理されることを並列比較する。

**実環境との差異の注記 (必須)**:
実環境では NTP によるサーバー時刻同期が普及しており、±30 秒を超えるクロックドリフトは
通常ほとんど発生しない。合理的なクロックドリフト対応としては ±1 ステップ (±30 秒) で十分である。

#### CWE / CAPEC / OSI 層

| 項目 | 値 |
|------|-----|
| CWE | CWE-208 (Observable Discrepancy) |
| CAPEC | CAPEC-462 (Cross-Channel Scripting) ※過剰な時刻窓による OTP 受理への適用 |
| OSI 層 | Layer 7 — Application |
| 深刻度 | Medium |

#### 前提条件 (脆弱な実装の例)

攻撃者は以下の条件を満たしている:

1. 正規ユーザーの TOTP コードを観測した (OTP リプレイと同様の前提)
2. サーバーの TOTP 検証ウィンドウが ±10 ステップ (±5 分) 以上に設定されている
3. 攻撃者は観測後 5 分以内にそのコードを再送できる

**脆弱な実装例** (このシナリオでシミュレーションする実装):

```typescript
// 脆弱な実装例 (教育用シミュレーション専用)
function vulnerableVerifyTotp(secret: string, code: string): boolean {
  const key = base32Decode(secret);
  const counter = currentCounter();
  const window = 10;   // ±10 ステップ = ±5 分 (過剰に広すぎる)
  for (let delta = -window; delta <= window; delta++) {
    if (timingSafeEqual(computeTotp(key, counter + delta), code)) {
      return true;
    }
  }
  return false;
}
```

#### 攻撃ステップ (AttackStep[] の具体例)

```typescript
const steps: AttackStep[] = [
  {
    id: "step-1",
    kind: "intercept",
    label: "Observe TOTP code valid at T+0s",
    labelJa: "T+0s 時点で有効な TOTP コードを観測",
    status: "success",
    payload: {
      type: "generic",
      data: {
        username: "seed_alice",
        observedCode: "382047",
        observedAt: "T+0s",
        windowNarrow: "Valid: T-30s to T+60s (±1 step)",
        windowWide: "Valid: T-5m to T+5m (±10 steps)",
      },
    },
    detail: "Attacker observes a TOTP code at T+0s. Window width determines how long it remains valid.",
    detailJa: "攻撃者は T+0s に TOTP コードを観測します。ウィンドウ幅により有効期間が変わります。",
    timestamp: Date.now(),
  },
  {
    id: "step-2",
    kind: "probe",
    label: "Replay at T+90s: rejected by ±1 window (narrow)",
    labelJa: "T+90s にリプレイ: ±1 窓 (狭い設定) では拒否される",
    status: "blocked",
    payload: {
      type: "http",
      request: {
        method: "POST",
        url: "/api/mfa/attack/time-window-wide",
        body: { username: "seed_alice", code: "382047", windowSize: 1, simulatedDelaySeconds: 90 },
      },
      response: {
        status: 401,
        body: { success: false, outcome: "blocked", detail: "Code expired: outside ±1 window (±30s)" },
      },
    },
    detail: "With ±1 window, the code is no longer valid 90 seconds later.",
    detailJa: "±1 窓では、90 秒後にコードの有効期限が切れて拒否されます。",
    timestamp: Date.now(),
  },
  {
    id: "step-3",
    kind: "exploit",
    label: "Replay at T+90s: accepted by ±10 window (wide — vulnerable)",
    labelJa: "T+90s にリプレイ: ±10 窓 (広い設定 — 脆弱) では受理される",
    status: "success",
    payload: {
      type: "http",
      request: {
        method: "POST",
        url: "/api/mfa/attack/time-window-wide",
        body: { username: "seed_alice", code: "382047", windowSize: 10, simulatedDelaySeconds: 90 },
      },
      response: {
        status: 200,
        body: { success: true, outcome: "succeeded", detail: "Code accepted: within ±10 window (±300s)" },
      },
    },
    detail: "With ±10 window (±5 min), the same code is accepted 90 seconds later.",
    detailJa: "±10 窓 (±5 分) では、90 秒後に同じコードが受理されてしまいます。",
    timestamp: Date.now(),
  },
  {
    id: "step-4",
    kind: "verify",
    label: "Summary: ±1 window is the recommended setting",
    labelJa: "まとめ: ±1 窓が推奨設定",
    status: "blocked",
    payload: {
      type: "generic",
      data: {
        windowSizes: [
          { window: 1, toleranceSec: 30, recommendation: "recommended — sufficient for clock drift" },
          { window: 2, toleranceSec: 60, recommendation: "acceptable if justified" },
          { window: 10, toleranceSec: 300, recommendation: "not recommended — 10-minute replay window" },
        ],
      },
    },
    detail: "NIST recommends ±1 time step as the maximum acceptable window for TOTP.",
    detailJa: "NIST は TOTP の最大許容ウィンドウとして ±1 タイムステップを推奨しています。",
    timestamp: Date.now(),
  },
];
```

#### 期待される結果 (AttackResult)

```typescript
const result: AttackResult = {
  scenarioId: "mfa-time-window-too-wide",
  outcome: "succeeded",   // ±10 窓では攻撃が成立
  startedAt: /* Unix ms */,
  finishedAt: /* Unix ms */,
  steps,
  blockedBy: "TOTP ウィンドウ ±1 設定",
  summary: "With ±10 time window, a 90-second-old OTP is accepted. ±1 window correctly rejects it.",
  summaryJa: "±10 時刻窓では 90 秒前の OTP が受理されます。±1 窓では正しく拒否されます。",
};
```

#### 防御策 (defenseRecommendation)

**既存実装ファイルへのリンク**:
- `server/utils/totp.ts` — `verifyTotpWithDetail` の `window = 1` 定数 (現行: 正しく ±1 に設定済み)

**防御策の要点**:

1. TOTP ウィンドウは原則 ±1 ステップ (±30 秒) に設定する
2. 環境変数でウィンドウを設定可能にする場合は上限を ±2 に制限し、広げすぎを防ぐ
3. ウィンドウを広げる必要がある場合は、それ以上に使用済み OTP 記録 (4.1 参照) の導入を優先する
4. NIST SP 800-63B §5.1.4.2 では OTP のタイムステップを 30 秒以上 120 秒以下とし、
   許容ウィンドウは最大 1 タイムステップとすることを勧告している

**codeHints の具体例**:

```typescript
// server/utils/totp.ts の推奨設定
export const TOTP_WINDOW = Number(process.env.TOTP_WINDOW ?? "1");
// 上限ガード — 環境変数で 10 等を設定しても ±2 以上にはならない
const safeWindow = Math.min(TOTP_WINDOW, 2);

export function verifyTotpWithDetail(secret: string, code: string) {
  const key = base32Decode(secret);
  const counter = currentCounter();
  for (let delta = -safeWindow; delta <= safeWindow; delta++) {
    // ...
  }
}
```

**参考リンク**:
- NIST SP 800-63B §5.1.4.2: https://pages.nist.gov/800-63-3/sp800-63b.html#sec5
- RFC 6238 §5: https://www.rfc-editor.org/rfc/rfc6238#section-5

#### API 契約

```
POST /api/mfa/attack/time-window-wide
```

**リクエスト**:

```json
{
  "username": "seed_alice",
  "code": "382047",
  "windowSize": 10,
  "simulatedDelaySeconds": 90
}
```

| フィールド | 型 | 必須 | 説明 |
|-----------|---|------|------|
| `username` | `string` | 必須 | 固定シードユーザー名 |
| `code` | `string` | 必須 | 6桁 OTP コード文字列 |
| `windowSize` | `number` | 必須 | 検証に使用する時刻ウィンドウ (ステップ数)。有効値: `1` / `2` / `5` / `10` |
| `simulatedDelaySeconds` | `number` | 任意 | OTP 観測から再送までの遅延をシミュレートする秒数 (デフォルト `90`) |

**レスポンス (windowSize=10、リプレイ成立)**:

```json
{
  "success": true,
  "data": {
    "scenarioId": "mfa-time-window-too-wide",
    "outcome": "succeeded",
    "startedAt": 1745592000000,
    "finishedAt": 1745592000100,
    "steps": [
      {
        "id": "step-3",
        "kind": "exploit",
        "label": "Replay at T+90s accepted by ±10 window",
        "labelJa": "T+90s のリプレイが ±10 窓で受理",
        "status": "success",
        "payload": {
          "type": "generic",
          "data": { "windowSize": 10, "simulatedDelaySeconds": 90, "effectiveDeltaSteps": 3 }
        },
        "timestamp": 1745592000080
      }
    ],
    "summary": "±10 window accepted a code issued 90s ago (3 steps away). Vulnerable.",
    "summaryJa": "±10 窓は 90 秒前 (3 ステップ前) に発行されたコードを受理しました。脆弱です。"
  },
  "_trace": {
    "cryptoOps": [
      {
        "op": "totp.verify (window=10)",
        "input": "code=\"382047\", counter_base=58203, window=±10, simulated_delta=+3",
        "output": "MATCH ✓ at counter=58200 (delta=-3, within ±10)",
        "algo": "HMAC-SHA1 + Dynamic Truncation (RFC 6238)",
        "detail": "Wide window ±10 accepted a code valid at counter=58200 (issued 90s ago, 3 steps back)"
      }
    ],
    "dbQueries": [],
    "isAttackMode": true
  }
}
```

#### _trace 内訳

| trace 種別 | 内容 |
|-----------|------|
| `CryptoOp` | `totp.verify (window=N)` — ウィンドウサイズごとの検証結果と有効 counter デルタ値 |
| `DbQuery` | なし (このシナリオは DB アクセス不要) |
| `SessionOp` | なし |

#### UI フロー

```
[Attacker View 起動]
  ↓
[教育用バナー表示: 常時固定]
  ↓
[シナリオセレクタ: "時刻同期ずれ攻撃" を選択]
  ↓
[設定エリア]
  - 時刻ウィンドウ選択: ±1 (推奨) / ±2 (許容) / ±5 (非推奨) / ±10 (脆弱)
  - 遅延シミュレーション: 90 秒 (固定デモ値)
  ↓
[「攻撃を実行」ボタン]
  ↓
[AttackStepTimeline アニメーション]
  step-1 intercept:  OTP 観測 (オレンジ)
  step-2 verify:     ±1 窓で拒否 (緑)
  step-3 exploit:    ±10 窓で受理 (赤、ウィンドウ選択が 10 の場合)
  step-4 verify:     推奨設定まとめ (緑)
  ↓
[ウィンドウ比較テーブル: ±1 / ±2 / ±5 / ±10 の有効期間を横断比較]
  ↓
[AttackResultBanner]
  ±1:  "防御が機能しました: ±1 窓が 90 秒前の OTP を拒否しました"
  ±10: "この実装は脆弱です: ±10 窓が 90 秒前の OTP を受理しました"
  ↓
[AttackDefensePanel: NIST 推奨設定と環境変数ガード実装例]
  ↓
[DataFlowPanel: HTTP / Trace (CryptoOp — ウィンドウサイズ別検証ログ)]
```

---

### 4.3 `mfa-sms-swap`

> **シミュレーション明示**: 本シナリオは SMS OTP の設計上の脆弱性を概念的に示す教育用シミュレーションである。
> 実際の SIM スワップには携帯キャリアへの Social Engineering が必要であり、
> このデモはその過程を完全に省略したシミュレーションに過ぎない。
> 実環境での SIM スワップ攻撃の実施を意図したものではない。

#### 概要

これは **CWE-308 / CWE-294 / CAPEC-115** の概念実証である。
SMS OTP は TOTP アプリに比べて広く普及しているが、電話番号が SIM スワップ攻撃等によって
攻撃者の端末に転送された場合、その後の SMS OTP はすべて攻撃者が受信できてしまう。
TOTP アプリや Push 通知型 MFA はデバイスバインドされているため、
電話番号の乗っ取りではなくデバイス自体への物理的アクセスが必要になる。

このデモでは「SMS OTP 経路」と「TOTP アプリ経路」を並列で示す。
SMS 経路では SIM スワップ後の攻撃者デバイスへの転送をシミュレーションし、
TOTP 経路では同じ攻撃が電話番号乗っ取りでは成立しないことを示す。

**実環境との差異の注記 (必須)**:
実際の SIM スワップには携帯キャリアへの Social Engineering が必要です。
このデモは SMS OTP の脆弱性の概念を示すもので、実際の SIM スワップ・SS7 攻撃手法は含みません。
実環境では SIM スワップ対策として、携帯キャリアへのアカウントロック PIN 設定や
SMS を使わない MFA 方式への移行が有効です。

#### CWE / CAPEC / OSI 層

| 項目 | 値 |
|------|-----|
| CWE | CWE-308 (Use of Single-factor Authentication) / CWE-294 (Authentication Bypass by Capture-replay) |
| CAPEC | CAPEC-115 (Authentication Abuse) |
| OSI 層 | Layer 7 — Application |
| 深刻度 | High |

#### 前提条件 (脆弱な実装の例)

攻撃者は以下の条件を満たしている:

1. 標的ユーザーの電話番号を特定している
2. SIM スワップ攻撃により電話番号を攻撃者の SIM に転送させた
   (このデモではその取得過程をシミュレーション表示のみとし、実手順は省略)
3. 標的ユーザーのパスワードを何らかの手段で取得済み (フィッシング等。本デモでは固定シード値を使用)

**脆弱な実装の前提**:

```
SMS OTP 方式では次の依存関係が存在する:
  電話番号 → SMS OTP → 認証成功

TOTP アプリ方式では:
  デバイス固有シークレット → TOTP コード → 認証成功

SMS OTP の「弱い輪」: 電話番号の所有権が変わると、その後の SMS OTP は全て攻撃者に届く。
TOTP アプリの利点: デバイスに紐付いたシークレットが攻撃者の端末に移転するには
                   デバイスへの物理的アクセスが必要。
```

#### 攻撃ステップ (AttackStep[] の具体例)

```typescript
const steps: AttackStep[] = [
  {
    id: "step-1",
    kind: "probe",
    label: "Obtain target phone number and compromised password",
    labelJa: "標的の電話番号と侵害済みパスワードを取得",
    status: "success",
    payload: {
      type: "generic",
      data: {
        username: "seed_alice",
        phoneNumber: "+81-90-XXXX-XXXX (masked)",
        password: "Passw0rd! (obtained via phishing simulation)",
        note: "Phone number obtained from leaked profile. Password from phishing simulation.",
        noteJa: "電話番号は漏洩プロフィールから取得。パスワードはフィッシングシミュレーション経由。",
      },
    },
    detail: "Attacker has collected phone number and password before SIM swap attempt.",
    detailJa: "攻撃者は SIM スワップ前に電話番号とパスワードを収集しています。",
    timestamp: Date.now(),
  },
  {
    id: "step-2",
    kind: "forge",
    label: "Simulate SIM swap: phone number forwarded to attacker device",
    labelJa: "SIM スワップをシミュレーション: 電話番号が攻撃者端末に転送される",
    status: "success",
    payload: {
      type: "generic",
      data: {
        simSwapSimulated: true,
        originalDevice: "seed_alice device (Tokyo)",
        attackerDevice: "attacker_charlie device (simulated)",
        note: "SIMULATION ONLY — actual SIM swap requires social engineering at carrier. Not reproduced here.",
        noteJa: "シミュレーションのみ — 実際の SIM スワップはキャリアへの Social Engineering を要する。ここでは再現しない。",
        smsRoutingChanged: true,
      },
    },
    detail: "[SIMULATION] Phone number routing redirected to attacker device. This is a concept demonstration only.",
    detailJa: "[シミュレーション] 電話番号の転送先が攻撃者端末に変更されました。概念的なデモです。",
    timestamp: Date.now(),
  },
  {
    id: "step-3",
    kind: "exploit",
    label: "SMS OTP delivered to attacker device; login completed",
    labelJa: "SMS OTP が攻撃者端末に届く; ログイン成立",
    status: "success",
    payload: {
      type: "http",
      request: {
        method: "POST",
        url: "/api/mfa/attack/sms-swap",
        body: {
          username: "seed_alice",
          password: "Passw0rd!",
          mfaChannel: "sms",
          simSwapSimulated: true,
        },
      },
      response: {
        status: 200,
        body: {
          outcome: "succeeded",
          detail: "SMS OTP sent to attacker device (SIM swap simulated). Login completed.",
          smsReceivedBy: "attacker_charlie (simulated)",
          otpCode: "573819",
        },
      },
    },
    detail: "This scenario demonstrates that SMS OTP is tied to phone number ownership, not device identity.",
    detailJa: "このシナリオは SMS OTP が電話番号の所有権に依存しており、デバイスの同一性には依存しないことを示しています。",
    timestamp: Date.now(),
  },
  {
    id: "step-4",
    kind: "verify",
    label: "TOTP app: same attack fails — device-bound secret not transferred",
    labelJa: "TOTP アプリ: 同じ攻撃が成立しない — デバイスにバインドされたシークレットは転送されない",
    status: "blocked",
    payload: {
      type: "http",
      request: {
        method: "POST",
        url: "/api/mfa/attack/sms-swap",
        body: {
          username: "seed_alice",
          password: "Passw0rd!",
          mfaChannel: "totp",
          simSwapSimulated: true,
        },
      },
      response: {
        status: 401,
        body: {
          outcome: "blocked",
          blockedBy: "device-bound TOTP secret",
          detail: "TOTP secret is stored in seed_alice device. SIM swap does not transfer the TOTP secret.",
        },
      },
    },
    detail: "TOTP secret remains on the legitimate user's device. SIM swap alone cannot compromise TOTP.",
    detailJa: "TOTP シークレットは正規ユーザーのデバイスに残ります。SIM スワップだけでは TOTP を侵害できません。",
    timestamp: Date.now(),
  },
];
```

#### 期待される結果 (AttackResult)

```typescript
const result: AttackResult = {
  scenarioId: "mfa-sms-swap",
  outcome: "succeeded",   // SMS OTP 経路では攻撃が成立
  startedAt: /* Unix ms */,
  finishedAt: /* Unix ms */,
  steps,
  blockedBy: "TOTP アプリのデバイスバインドシークレット",
  summary: "SMS OTP is vulnerable to SIM swap: once phone number is forwarded, all SMS OTPs go to attacker. TOTP apps resist this attack.",
  summaryJa: "SMS OTP は SIM スワップに脆弱です: 電話番号が転送されると以降の SMS OTP はすべて攻撃者に届きます。TOTP アプリはこの攻撃に耐性を持ちます。",
};
```

#### 防御策 (defenseRecommendation)

**既存実装ファイルへのリンク**:
- `server/routes/mfa-totp.ts:1-157` — TOTP ベースの MFA 実装 (デバイスバインドシークレット方式)

**防御策の要点**:

1. MFA に SMS OTP を使用することは推奨されない。NIST SP 800-63B §5.1.3 では、
   SMS OTP を使用する場合のリスクを明示し、より強固な方式への移行を推奨している
2. TOTP アプリ (Google Authenticator, Authy 等) はデバイスにバインドされたシークレットを使用するため、
   電話番号の乗っ取りでは侵害できない
3. さらに強固な方式として Push 通知型 MFA (デバイス認証済みのアプリへの承認要求) が有効
4. 最も強い方式として FIDO2/WebAuthn (パスキー) は origin バインドにより
   フィッシングおよびデバイス転送攻撃の両方に耐性を持つ

**codeHints の具体例**:

```typescript
// MFA チャネル選択の実装ガイドライン (概念)
type MfaChannel =
  | "totp"           // 推奨: デバイスバインドシークレット (RFC 6238)
  | "push"           // 推奨: デバイス認証済みアプリへの Push 承認
  | "fido2"          // 最推奨: origin バインド + 公開鍵暗号
  | "sms"            // 非推奨: 電話番号所有権依存 (NIST 800-63B §5.1.3)
  | "email";         // 非推奨: メールアカウント侵害に依存

// SMS を MFA に使う場合の最低限の対策
// (SMS を使わないことが最善だが、使わざるを得ない場合の緩和策)
// 1. OTP の有効期間を短く設定する (例: 5 分以内)
// 2. 使用済み OTP を記録する (4.1 参照)
// 3. ユーザーに SIM ロック PIN の設定を促す
// 4. アカウント侵害検知 (異常なログイン地域・デバイス) を実装する
```

**参考リンク**:
- NIST SP 800-63B §5.1.3 (Out-of-Band Authenticators): https://pages.nist.gov/800-63-3/sp800-63b.html#oob
- CWE-308: https://cwe.mitre.org/data/definitions/308.html
- CAPEC-115: https://capec.mitre.org/data/definitions/115.html

#### API 契約

```
POST /api/mfa/attack/sms-swap
```

**リクエスト**:

```json
{
  "username": "seed_alice",
  "password": "Passw0rd!",
  "mfaChannel": "sms",
  "simSwapSimulated": true
}
```

| フィールド | 型 | 必須 | 説明 |
|-----------|---|------|------|
| `username` | `string` | 必須 | 固定シードユーザー名 |
| `password` | `string` | 必須 | シードユーザーのパスワード (`Passw0rd!` 固定) |
| `mfaChannel` | `"sms" \| "totp"` | 必須 | MFA チャネルの選択。`sms` で攻撃成立、`totp` でブロックを示す |
| `simSwapSimulated` | `boolean` | 任意 | `true` の場合、SIM スワップが完了した状態をシミュレートする (デフォルト `true`) |

**レスポンス (mfaChannel=sms、攻撃成立)**:

```json
{
  "success": true,
  "data": {
    "scenarioId": "mfa-sms-swap",
    "outcome": "succeeded",
    "startedAt": 1745592000000,
    "finishedAt": 1745592000120,
    "steps": [
      {
        "id": "step-2",
        "kind": "forge",
        "label": "Simulate SIM swap: phone number forwarded to attacker device",
        "labelJa": "SIM スワップをシミュレーション: 電話番号が攻撃者端末に転送",
        "status": "success",
        "payload": {
          "type": "generic",
          "data": {
            "simSwapSimulated": true,
            "smsRoutingChanged": true,
            "note": "SIMULATION ONLY — not a reproduction of actual SIM swap technique"
          }
        },
        "timestamp": 1745592000040
      },
      {
        "id": "step-3",
        "kind": "exploit",
        "label": "SMS OTP delivered to attacker device",
        "labelJa": "SMS OTP が攻撃者端末に届く",
        "status": "success",
        "payload": {
          "type": "generic",
          "data": { "mfaChannel": "sms", "smsReceivedBy": "attacker_charlie (simulated)", "otpCode": "573819" }
        },
        "timestamp": 1745592000100
      }
    ],
    "summary": "SMS OTP is tied to phone number, not device. SIM swap simulation shows it can be redirected.",
    "summaryJa": "SMS OTP は電話番号に紐付いており、デバイスには紐付いていません。SIM スワップシミュレーションで転送可能なことを示します。"
  },
  "_trace": {
    "cryptoOps": [
      {
        "op": "bcrypt.compare",
        "input": "password=\"[REDACTED]\" vs stored_hash",
        "output": "MATCH ✓",
        "algo": "bcrypt",
        "detail": "Factor 1 (password) verified. Factor 2 (SMS OTP) now simulated as delivered to attacker."
      },
      {
        "op": "sms.generate_otp (simulated)",
        "input": "length=6, charset=numeric",
        "output": "573819 → delivered to: attacker_charlie (SIM swap simulation)",
        "algo": "CSPRNG (simulated)",
        "detail": "[SIMULATION] In real systems, SMS OTP is sent to the registered phone number. SIM swap redirects this delivery."
      }
    ],
    "dbQueries": [
      {
        "sql": "SELECT id, username, password_hash FROM users WHERE username = ? AND is_attack_sim = 0",
        "params": ["seed_alice"],
        "rows": [{ "id": 1, "username": "seed_alice", "password_hash": "$2a$10$..." }],
        "ms": 1.1
      }
    ],
    "sessionOps": [
      {
        "action": "SIM_SWAP_SIMULATION",
        "data": {
          "note": "Educational simulation — not an actual SIM swap. Demonstrates SMS OTP vulnerability concept.",
          "originalDevice": "seed_alice_device",
          "redirectedTo": "attacker_charlie_device (simulated)"
        }
      }
    ],
    "isAttackMode": true
  }
}
```

**レスポンス (mfaChannel=totp、ブロック)**:

```json
{
  "success": true,
  "data": {
    "scenarioId": "mfa-sms-swap",
    "outcome": "blocked",
    "blockedBy": "device-bound TOTP secret",
    "steps": [
      {
        "id": "step-4",
        "kind": "blocked",
        "label": "TOTP blocked: device-bound secret not transferred by SIM swap",
        "labelJa": "TOTP がブロック: デバイスバインドシークレットは SIM スワップで転送されない",
        "status": "blocked",
        "payload": {
          "type": "generic",
          "data": {
            "mfaChannel": "totp",
            "simSwapEffect": "none",
            "reason": "TOTP secret is stored in seed_alice's authenticator app. SIM swap only redirects SMS, not app secrets."
          }
        },
        "timestamp": 1745592000100
      }
    ],
    "summary": "TOTP resists SIM swap: device-bound secret cannot be redirected via phone number transfer.",
    "summaryJa": "TOTP は SIM スワップに耐性あり: デバイスバインドシークレットは電話番号転送では移動しません。"
  },
  "_trace": {
    "cryptoOps": [],
    "dbQueries": [],
    "sessionOps": [
      {
        "action": "SIM_SWAP_TOTP_RESISTANCE_CHECK",
        "data": {
          "mfaChannel": "totp",
          "result": "blocked",
          "reason": "TOTP secret bound to authenticator app on device, not to phone number"
        }
      }
    ],
    "isAttackMode": true
  }
}
```

#### _trace 内訳

| trace 種別 | 内容 |
|-----------|------|
| `CryptoOp` | `bcrypt.compare` (パスワード第1要素検証) / `sms.generate_otp (simulated)` (SMS OTP 生成・転送のシミュレーション記録) |
| `DbQuery` | `SELECT users WHERE username = ?` — パスワードハッシュ取得 |
| `SessionOp` | `SIM_SWAP_SIMULATION` — SIM 転送シミュレーションのログ (教育目的の注記付き) |

**注意**: `sms.generate_otp (simulated)` は実際の SMS 送信を行わない。
サーバー側でシミュレーション値として生成・ログ記録するだけである。外部 API 呼び出しなし。

#### UI フロー

```
[Attacker View 起動]
  ↓
[教育用バナー表示: 常時固定]
  + 追加バナー: "このシナリオは教育用シミュレーションです。SIM スワップの実手順は含まれていません。"
  ↓
[シナリオセレクタ: "SMS 乗っ取り (SIM スワップ シミュレーション)" を選択]
  ↓
[MFA チャネル選択: SMS (脆弱) / TOTP アプリ (耐性あり)]
  ↓
[「攻撃シミュレーションを実行」ボタン]
  ↓
[AttackStepTimeline アニメーション]
  step-1 probe:   電話番号とパスワードの収集 (オレンジ)
  step-2 forge:   SIM スワップシミュレーション (赤、★ 教育用ラベル常時表示)
  step-3 exploit: SMS OTP が攻撃者端末に届く (赤、SMS 選択時のみ)
  step-4 verify:  TOTP アプリは SIM スワップに耐性あり (緑、TOTP 選択時のみ)
  ↓
[SMS vs TOTP 比較パネル: 並列で脆弱性の差異を可視化]
  - SMS OTP: 電話番号依存 → SIM スワップで侵害可能
  - TOTP:  デバイスバインド → SIM スワップでは侵害不可
  ↓
[AttackResultBanner]
  SMS:  "この実装は脆弱です: SMS OTP は電話番号の所有権に依存するため SIM スワップで突破されます"
  TOTP: "防御が機能しました: TOTP のデバイスバインドシークレットは SIM スワップで転送されません"
  ↓
[AttackDefensePanel: NIST 推奨方式 (TOTP / Push / FIDO2) の説明]
  ↓
[DataFlowPanel: HTTP / Trace (CryptoOp: bcrypt + sms simulated) / DB (users)]
```

---

## 5. UI コンポーネント設計

### 5.1 ディレクトリ構成

```
src/components/auth/attacks/mfa/
├── MfaAttackPanel.tsx          ← 3シナリオを統括するメインパネル
├── OtpReplayScenario.tsx       ← シナリオ A: OTP リプレイ + 使用済み DB トグル
├── TimeWindowScenario.tsx      ← シナリオ B: 時刻窓幅選択 + ウィンドウ比較表示
├── SmsSwapScenario.tsx         ← シナリオ C: SMS vs TOTP 並列比較パネル
└── MfaAttack.css               ← 3シナリオ共通スタイル
```

### 5.2 `MfaAttackPanel.tsx` の責務

```typescript
// MfaFlow.tsx への組み込みイメージ
import MfaAttackPanel from "./attacks/mfa/MfaAttackPanel";
import { Show } from "solid-js";

// viewMode Signal を ViewModeToggle から受け取る
<Show when={viewMode() === "attacker"}>
  <MfaAttackPanel tabId="mfa" />
</Show>
```

`MfaAttackPanel` は以下を担当する:

1. `EducationalWarningBanner` の常時表示
2. `AttackScenarioSelector` で 3 シナリオの切り替え
3. 選択中シナリオに対応する `OtpReplayScenario` / `TimeWindowScenario` / `SmsSwapScenario` のレンダリング
4. `DataFlowPanel scopeId="attack-mfa"` の表示

### 5.3 各シナリオコンポーネントの props 設計

```typescript
// OtpReplayScenario.tsx
interface OtpReplayScenarioProps {
  onResult: (result: AttackResult) => void;
  onRunning: (running: boolean) => void;
}

// TimeWindowScenario.tsx
interface TimeWindowScenarioProps {
  onResult: (result: AttackResult) => void;
  onRunning: (running: boolean) => void;
}

// SmsSwapScenario.tsx
interface SmsSwapScenarioProps {
  onResult: (result: AttackResult) => void;
  onRunning: (running: boolean) => void;
}
```

各シナリオコンポーネントは `onResult` コールバックで `AttackResult` を親に渡し、
`MfaAttackPanel` が `AttackResultBanner` と `AttackDefensePanel` の展開を制御する。

### 5.4 SMS vs TOTP 並列比較パネル (シナリオ C 固有)

シナリオ C では、SMS と TOTP の脆弱性差異を視覚的に対比させるため、
左右2カラムのレイアウトを採用する。

```
┌──────────────────────────┬──────────────────────────┐
│  SMS OTP (脆弱)          │  TOTP アプリ (耐性あり)   │
│  ⚠ 教育用バナー          │  ✓ 防御実装済みバナー     │
│                          │                          │
│  電話番号 → SMS → OTP    │  シークレット → TOTP      │
│  SIM スワップ後:          │  SIM スワップ後:          │
│  攻撃者端末に転送 → 成立  │  デバイスにバインド → 阻止 │
└──────────────────────────┴──────────────────────────┘
```

この並列レイアウトは DESIGN/04-safety-guardrails.md §9.3 の「脆弱版 vs 防御版の並列比較」ガイドラインに準拠する。

---

## 6. テスト要件

### 6.1 ユニットテスト (バックエンドハンドラ単体)

対象ファイル: `server/routes/attack-mfa.ts`

| テスト ID | 検証内容 | 期待結果 |
|---------|---------|---------|
| `mfa-atk-01` | `POST /attack/otp-replay` に `replayDefenseEnabled: false` で送信 | `outcome: "succeeded"`, step-2 の `status: "success"` を含む |
| `mfa-atk-02` | `POST /attack/otp-replay` に `replayDefenseEnabled: true` で送信 | `outcome: "blocked"`, `blockedBy: "used_otps DB record"` |
| `mfa-atk-03` | `POST /attack/otp-replay` に存在しないユーザー名を送信 | `400 Bad Request`, バリデーションエラー |
| `mfa-atk-04` | `POST /attack/time-window-wide` に `windowSize: 1`, `simulatedDelaySeconds: 90` で送信 | `outcome: "blocked"`, step-2 の `status: "blocked"` を含む |
| `mfa-atk-05` | `POST /attack/time-window-wide` に `windowSize: 10`, `simulatedDelaySeconds: 90` で送信 | `outcome: "succeeded"`, step-3 の `status: "success"` を含む |
| `mfa-atk-06` | `POST /attack/time-window-wide` に無効な `windowSize: 100` を送信 | `400 Bad Request` (許容値: 1/2/5/10 のみ) |
| `mfa-atk-07` | `POST /attack/sms-swap` に `mfaChannel: "sms"`, `simSwapSimulated: true` で送信 | `outcome: "succeeded"`, `_trace.sessionOps` に `SIM_SWAP_SIMULATION` が含まれる |
| `mfa-atk-08` | `POST /attack/sms-swap` に `mfaChannel: "totp"`, `simSwapSimulated: true` で送信 | `outcome: "blocked"`, `blockedBy: "device-bound TOTP secret"` |
| `mfa-atk-09` | `POST /attack/sms-swap` に `simSwapSimulated: false` で送信 | `outcome: "blocked"`, SMS OTP が正規ユーザーデバイスに届くシミュレーション |
| `mfa-atk-10` | いずれかの攻撃エンドポイントに `NODE_ENV=production` で送信 | `403 Forbidden` |
| `mfa-atk-11` | `POST /api/reset` 実行後に再度攻撃シナリオを実行 | `used_otps` テーブルがクリアされ、シナリオが正常に動作する |

### 6.2 E2E テスト (UI フロー)

対象: `src/components/auth/attacks/mfa/MfaAttackPanel.tsx`

| テスト ID | 操作 | 期待結果 |
|---------|------|---------|
| `e2e-mfa-01` | MFA タブで Attacker View に切り替える | `EducationalWarningBanner` が最上部に固定表示される |
| `e2e-mfa-02` | シナリオ A を選択して「使用済み DB OFF」で実行 | step-2 が赤 SUCCESS、`AttackResultBanner` が赤で「この実装は脆弱です」 |
| `e2e-mfa-03` | シナリオ A を「使用済み DB ON」で実行 | step-3 が緑 BLOCKED、`AttackResultBanner` が緑で「防御が機能しました」 |
| `e2e-mfa-04` | シナリオ B を「ウィンドウ ±1」で実行 | step-2 が緑 BLOCKED、ウィンドウ比較テーブルが表示される |
| `e2e-mfa-05` | シナリオ B を「ウィンドウ ±10」で実行 | step-3 が赤 SUCCESS、`AttackResultBanner` が赤で表示される |
| `e2e-mfa-06` | シナリオ C で「SMS」を選択して実行 | 並列比較パネルが表示され、SMS カラムに攻撃成立が表示される |
| `e2e-mfa-07` | シナリオ C で「TOTP アプリ」を選択して実行 | TOTP カラムに「防御が機能しました」が表示される |
| `e2e-mfa-08` | 攻撃完了後に防御策パネルを確認 | `AttackDefensePanel` が自動展開されている |
| `e2e-mfa-09` | Defender View に切り替える | 通常の `MfaDemo` が表示され、攻撃バナーが消える |
| `e2e-mfa-10` | シナリオ C で教育用注記を確認 | 「このシナリオは教育用シミュレーションです」注記が表示されている |

---

## 7. i18n キー一覧表 (ja/en)

| # | キー概念 | 日本語 | English |
|---|---------|--------|---------|
| 1 | 攻撃者モード切替 | `攻撃者モード` | `Attacker Mode` |
| 2 | 防御者モード切替 | `防御者モード` | `Defender Mode` |
| 3 | 教育バナーテキスト | `教育用シミュレーション — 実環境を攻撃するためのコードではありません` | `Educational simulation — not for use against real systems` |
| 4 | シナリオ A 名 | `OTP リプレイ攻撃` | `OTP Replay Attack` |
| 5 | シナリオ B 名 | `時刻同期ずれ攻撃 (時計の窓を広げすぎ)` | `Time Window Misconfiguration Attack` |
| 6 | シナリオ C 名 | `SMS 乗っ取り (SIM スワップ シミュレーション)` | `SMS Hijack (SIM Swap Simulation)` |
| 7 | 攻撃実行ボタン | `攻撃を実行` | `Run Attack` |
| 8 | 攻撃シミュレーション実行ボタン (シナリオ C) | `攻撃シミュレーションを実行` | `Run Attack Simulation` |
| 9 | 実行中ラベル | `実行中...` | `Running...` |
| 10 | 攻撃成立バナー | `攻撃成立 — この実装は脆弱です` | `Attack succeeded — this implementation is vulnerable` |
| 11 | 防御成立バナー接頭辞 | `防御が機能しました:` | `Defense succeeded:` |
| 12 | 使用済み OTP DB トグルラベル | `使用済み OTP DB` | `Used-OTP Database` |
| 13 | 使用済み OTP DB OFF ラベル | `無効 (脆弱な実装)` | `Disabled (Vulnerable)` |
| 14 | 使用済み OTP DB ON ラベル | `有効 (防御済み)` | `Enabled (Protected)` |
| 15 | 時刻ウィンドウ選択ラベル | `TOTP 時刻ウィンドウ (ステップ数)` | `TOTP Time Window (steps)` |
| 16 | ウィンドウ ±1 ラベル | `±1 ステップ (±30秒) — 推奨` | `±1 step (±30s) — Recommended` |
| 17 | ウィンドウ ±2 ラベル | `±2 ステップ (±60秒) — 許容範囲` | `±2 steps (±60s) — Acceptable` |
| 18 | ウィンドウ ±5 ラベル | `±5 ステップ (±150秒) — 非推奨` | `±5 steps (±150s) — Not Recommended` |
| 19 | ウィンドウ ±10 ラベル | `±10 ステップ (±300秒) — 脆弱` | `±10 steps (±300s) — Vulnerable` |
| 20 | MFA チャネル選択ラベル | `MFA チャネル` | `MFA Channel` |
| 21 | SMS チャネルラベル | `SMS OTP (脆弱)` | `SMS OTP (Vulnerable)` |
| 22 | TOTP チャネルラベル | `TOTP アプリ (耐性あり)` | `TOTP App (Resistant)` |
| 23 | SIM スワップ注記 | `このシナリオは教育用シミュレーションです。SIM スワップの実手順は含まれていません。` | `This scenario is an educational simulation. Actual SIM swap techniques are not reproduced.` |
| 24 | シミュレーション専用バッジ | `シミュレーション専用` | `Simulation Only` |
| 25 | step-1 A ラベル | `正規ユーザーが使用した TOTP コードを観測` | `Observe TOTP code used by legitimate user` |
| 26 | step-2 A ラベル | `有効期間内に同一 OTP コードを再送 (使用済み DB なし)` | `Replay same OTP within valid window (no used-OTP DB)` |
| 27 | step-3 A ラベル | `使用済み OTP DB がリプレイをブロック` | `Used-OTP DB blocks the replay` |
| 28 | step-1 B ラベル | `T+0s 時点で有効な TOTP コードを観測` | `Observe TOTP code valid at T+0s` |
| 29 | step-2 B ラベル | `T+90s にリプレイ: ±1 窓では拒否` | `Replay at T+90s: rejected by ±1 window` |
| 30 | step-3 B ラベル | `T+90s にリプレイ: ±10 窓では受理 (脆弱)` | `Replay at T+90s: accepted by ±10 window (vulnerable)` |
| 31 | step-4 B ラベル | `まとめ: ±1 窓が推奨設定` | `Summary: ±1 window is recommended` |
| 32 | step-1 C ラベル | `標的の電話番号と侵害済みパスワードを取得` | `Obtain target phone number and compromised password` |
| 33 | step-2 C ラベル | `SIM スワップをシミュレーション: 電話番号が攻撃者端末に転送` | `Simulate SIM swap: phone number forwarded to attacker device` |
| 34 | step-3 C ラベル | `SMS OTP が攻撃者端末に届く: ログイン成立` | `SMS OTP delivered to attacker device: login completed` |
| 35 | step-4 C ラベル | `TOTP アプリ: SIM スワップに耐性あり` | `TOTP app: resistant to SIM swap` |
| 36 | 攻撃成立メッセージ A | `この実装は脆弱です: 使用済み OTP が再度受理されました` | `This implementation is vulnerable: used OTP was accepted again` |
| 37 | 防御成立メッセージ A | `防御が機能しました: used_otps テーブルがリプレイを拒否しました` | `Defense succeeded: used_otps table rejected the replay` |
| 38 | 攻撃成立メッセージ B | `この実装は脆弱です: ±{N} 窓が {D} 秒前の OTP を受理しました` | `This implementation is vulnerable: ±{N} window accepted an OTP issued {D}s ago` |
| 39 | 防御成立メッセージ B | `防御が機能しました: ±1 窓が {D} 秒前の OTP を拒否しました` | `Defense succeeded: ±1 window rejected the OTP issued {D}s ago` |
| 40 | 攻撃成立メッセージ C | `この実装は脆弱です: SMS OTP は電話番号の所有権に依存するため SIM スワップで突破されます` | `This implementation is vulnerable: SMS OTP relies on phone number ownership and can be bypassed by SIM swap` |
| 41 | 防御成立メッセージ C | `防御が機能しました: TOTP のデバイスバインドシークレットは SIM スワップで転送されません` | `Defense succeeded: TOTP device-bound secret is not transferred by SIM swap` |
| 42 | ウィンドウ比較テーブルヘッダ | `ウィンドウサイズ比較` | `Window Size Comparison` |
| 43 | 有効期間ラベル | `有効期間` | `Valid Duration` |
| 44 | 推奨レベルラベル | `推奨レベル` | `Recommendation` |
| 45 | NIST 推奨テキスト | `NIST SP 800-63B は最大 ±1 ステップ (±30 秒) を推奨しています` | `NIST SP 800-63B recommends a maximum of ±1 time step (±30 seconds)` |
| 46 | SMS 脆弱性ラベル | `SMS OTP の脆弱性` | `SMS OTP Vulnerability` |
| 47 | TOTP 耐性ラベル | `TOTP アプリの SIM スワップ耐性` | `TOTP App SIM Swap Resistance` |
| 48 | 電話番号依存説明 | `電話番号の所有権に依存` | `Depends on phone number ownership` |
| 49 | デバイスバインド説明 | `デバイスにバインドされたシークレット` | `Device-bound secret` |
| 50 | タイムラインARIAラベル | `攻撃ステップログ` | `Attack step log` |

---

## 8. 関連ファイル

### 8.1 基盤設計書

| ファイル | 参照目的 |
|---------|---------|
| [DESIGN/00-overview.md](./00-overview.md) | 全体目的・カタログマトリクス (mfa タブの行: #11) ・教育安全装置の4原則概要 |
| [DESIGN/01-architecture.md](./01-architecture.md) | バックエンドルート配置方針 / フロントエンドコンポーネント階層 |
| [DESIGN/02-ui-spec.md](./02-ui-spec.md) | `ViewModeToggle` / `AttackStepTimeline` / `AttackResultBanner` / `AttackDefensePanel` の詳細仕様 |
| [DESIGN/03-data-model.md](./03-data-model.md) | `AttackStep` / `AttackResult` / `AttackScenarioMeta` / `ServerTrace` 拡張の型定義 |
| [DESIGN/04-safety-guardrails.md](./04-safety-guardrails.md) | 禁止表現一覧 / ペイロード作成ルール / SMS SIM スワップの必須付記 (§3.3) / 開発レビューチェックリスト |

### 8.2 既存実装ファイル (変更・参照対象)

| ファイルパス | 変更種別 | 変更内容 |
|------------|---------|---------|
| `server/routes/mfa-totp.ts` | 参照 | TOTP 検証ロジック (`verifyTotpWithDetail`) の流用 / 攻撃ルートとの比較実装に参照 |
| `server/utils/totp.ts` | 参照 | `computeTotp`, `currentCounter`, `verifyTotpWithDetail` — 攻撃ルートの `windowSize` パラメータ分岐実装に参照 |
| `src/components/auth/MfaFlow.tsx` | 追加 | `ViewModeToggle` import + `<Show when={viewMode() === "attacker"}>` ブロックで `MfaAttackPanel` を条件表示 |
| `server/db/schema.ts` | 追加 | `used_otps` テーブル DDL (シナリオ A の防御デモ用) と `attack_log` テーブルを `initSchema()` に追加 / `seedDb()` にリセット処理を追加 |
| `shared/api-types.ts` | 参照 | `AttackStep`, `AttackResult`, `AttackScenarioMeta`, `ServerTrace` 型定義 (DESIGN/03 参照) |
| `server/index.ts` | 追加 | `attack-mfa.ts` ルートを `app.route("/api/mfa/attack", attackMfaRoutes)` でマウント |

### 8.3 新規作成ファイル

| ファイルパス | 役割 |
|------------|------|
| `server/routes/attack-mfa.ts` | MFA/TOTP タブ攻撃ルート (3エンドポイント: `otp-replay`, `time-window-wide`, `sms-swap`) |
| `src/components/auth/attacks/mfa/MfaAttackPanel.tsx` | 3シナリオを統括するメインパネル |
| `src/components/auth/attacks/mfa/OtpReplayScenario.tsx` | シナリオ A の実行ロジックと使用済み DB トグル |
| `src/components/auth/attacks/mfa/TimeWindowScenario.tsx` | シナリオ B の実行ロジックとウィンドウ比較テーブル |
| `src/components/auth/attacks/mfa/SmsSwapScenario.tsx` | シナリオ C の SMS vs TOTP 並列比較パネル |
| `src/components/auth/attacks/mfa/MfaAttack.css` | 3シナリオ共通スタイル (並列比較レイアウト含む) |
| `src/components/auth/attacks/scenarios/mfa-scenarios.ts` | `AttackScenarioMeta[]` の静的定義 (3シナリオ分) |

### 8.4 attack-mfa.ts 冒頭コメント規約 (04-safety-guardrails.md §8.2 に準拠)

```typescript
/**
 * 攻撃デモルート: MFA/TOTP
 *
 * 【教育目的専用】
 * このファイルは OSI 参照アプリの教材機能として、
 * ローカル環境の固定シードデータに対する攻撃シミュレーションを提供します。
 *
 * - 外部ネットワークへのリクエストは行いません
 * - 実 CVE のエクスプロイトコードは含みません
 * - SMS SIM スワップの実手順・実 SS7 攻撃手法は含みません
 * - 本番環境での使用は想定していません
 *
 * 対象 CWE: CWE-294, CWE-208, CWE-308
 * 対象 CAPEC: CAPEC-60, CAPEC-462, CAPEC-115
 * 関連設計書: DESIGN/04-safety-guardrails.md, DESIGN/20-attack-mfa.md
 */
```

---

*このドキュメントは `DESIGN/20-attack-mfa.md` に配置。
実装を開始する前に DESIGN/00 〜 04 の基盤設計書を読了し、
特に DESIGN/04-safety-guardrails.md §3.3 の SMS SIM スワップ必須付記と
§4 のレビューチェックリストを確認すること。
シナリオ C の SMS スワップシミュレーションは簡略化原則 (§1.3) を厳守し、
実際の SIM スワップ・SS7 攻撃手法を記述・実装しないこと。*
