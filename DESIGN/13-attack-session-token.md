---
title: 攻撃デモカタログ — Session vs Token 攻撃詳細
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

# 13. Session vs Token 攻撃詳細

## 1. 概要

本設計書は `session-vs-token` タブに追加する3つの攻撃シナリオを規定する。

既存の `AuthComparison.tsx` は、Cookie セッション認証と JWT Bearer トークン認証を
左右並列で比較するインタラクティブデモを提供している。Attacker View では
「その認証方式にはどのような脆弱性があるか」を同じ画面構成で対比させ、
防御策の有無による挙動の差を学習者が体感できるよう設計する。

### 1.1 学習目標

| 攻撃シナリオ | 学習者が得る理解 |
|------------|----------------|
| セッション固定 (A) | ログイン後のセッション ID 再生成が必須である理由 |
| XSS Cookie 窃取 (B) | HttpOnly 属性が XSS 経由の Cookie 漏洩を阻止する仕組み |
| トークンリプレイ (C) | アクセストークンの短寿命設計とリフレッシュトークン回転の意義 |

### 1.2 既存実装との関係

- **Defender View**: `AuthComparison.tsx` の `LiveComparisonDemo` が既に正常系を示している
- **Attacker View**: 本設計書で規定する UI / バックエンドを追加し、攻撃視点を併設する
- **DataFlowPanel**: 既存の `SCOPE_SESSION = "session-auth"` / `SCOPE_TOKEN = "token-auth"` と
  別スコープ `"attack-session"` / `"attack-token"` を使用して攻撃ログを分離する
  > **scopeId 例外**: 全タブで `scopeId = "attack-${tabId}"` が標準だが (DESIGN/04 §7.1)、
  > このタブは左右並列デモのため `"attack-session"` / `"attack-token"` と分割して管理する (例外ケース)。

---

## 2. 攻撃シナリオ一覧

| # | シナリオ ID | 名称 | CWE | CAPEC | OSI 層 | 深刻度 |
|---|------------|------|-----|-------|--------|--------|
| A | `session-fixation` | セッション固定攻撃 | CWE-384, CAPEC-61 | CAPEC-61 | L7 | High |
| B | `session-xss-cookie-theft` | XSS Cookie 窃取 (HttpOnly 比較) | CWE-79, CWE-1004 | CAPEC-86 | L7 | High |
| C | `token-replay` | トークンリプレイ攻撃 | CWE-294 | CAPEC-60 | L7 | Medium |

---

## 3. 既存防御側実装

### 3.1 `server/routes/session-auth.ts` の構成

| エンドポイント | 役割 |
|--------------|------|
| `POST /api/session/login` | bcrypt 照合後に `uuidv4()` で新規セッション ID を発行し DB に保存 |
| `GET  /api/session/profile` | Cookie の `session_id` を DB と照合して有効期限を確認 |
| `DELETE /api/session/logout` | DB からセッションレコードを削除し Cookie を消去 |
| `GET  /api/session/store` | デバッグ用セッション一覧 (本番環境無効) |

**Cookie 属性 (現行実装):**

```typescript
setCookie(c, "session_id", sessionId, {
  httpOnly: true,        // JS から document.cookie で読み取り不可
  sameSite: "Lax",       // CSRF 緩和 (Strict より緩いが第三者サイトから POST を防ぐ)
  secure: isProduction,  // 開発環境では false (localhost は HTTP)
  path: "/api",
  maxAge: 1800,          // 30 分
});
```

**セッション有効期限:** ログイン時に `Date.now() + 30 * 60 * 1000`（30分）で設定。
DB の `sessions.expires_at` カラムと Cookie の `Max-Age` の両方で制御。

**注意点 (攻撃シナリオ A の起点):**
現行の `session-auth.ts` は `/api/session/login` で `uuidv4()` を用いてログイン時に
必ず新規セッション ID を発行しているため、セッション固定攻撃に耐性がある。
攻撃シミュレーション (`/api/session/attack/fixation`) では、
あえてこの再生成を省略した「脆弱版」エンドポイントを別途用意してデモを実施する。

---

### 3.2 `server/routes/token-auth.ts` の構成

| エンドポイント | 役割 |
|--------------|------|
| `POST /api/token/login` | アクセストークン (15分) + リフレッシュトークン (7日) を発行 |
| `GET  /api/token/profile` | `Authorization: Bearer <token>` を `jwt.verify()` で検証 |
| `POST /api/token/refresh` | リフレッシュトークンを原子的に消費し新トークンペアを発行 (回転) |

**アクセストークン設定:**

```typescript
jwt.sign(
  { sub: user.id, username: user.username, type: "access" },
  JWT_SECRET,                // "osi-demo-token-auth-secret"
  { expiresIn: "15m" }       // 短寿命: 15 分
);
```

**リフレッシュトークンの回転 (token rotation):**

```typescript
// 旧 jti を 1 クエリで revoked=1 にマーク (TOCTOU 対策)
db.prepare("UPDATE refresh_tokens SET revoked = 1 WHERE jti = ? AND revoked = 0 AND expires_at > datetime('now')")
  .run(decoded.jti);
// consumeResult.changes === 0 なら「使用済みまたは期限切れ」として拒否
```

**DB テーブル:**

| テーブル | 関連カラム | 用途 |
|---------|----------|------|
| `sessions` | `id`, `user_id`, `expires_at` | Cookie セッションの server-side ストア |
| `refresh_tokens` | `jti`, `user_id`, `expires_at`, `revoked` | リフレッシュトークンの一覧・無効化管理 |

---

## 4. シナリオ詳細

---

### 4.1 シナリオ A: セッション固定攻撃 (`session-fixation`)

#### 4.1.1 概要

これは **CWE-384 (Session Fixation) / CAPEC-61** の概念実証である。

攻撃者が事前に取得したセッション ID を被害者に使わせ、被害者がログインした後も
攻撃者がそのセッション ID でリソースにアクセスできる状況をシミュレーションする。
**ログイン成功時に新しいセッション ID を再発行しない実装** が前提となる。

現行の `session-auth.ts` はログイン時に必ず新規 ID を発行するため耐性がある。
本シミュレーションでは `/api/session/attack/fixation` という「脆弱版」専用エンドポイントで
再生成を省略した動作を示す。

#### 4.1.2 攻撃フロー (AttackStep[])

```
Step 1 [intercept] 攻撃者: 未認証セッション ID を取得
  → GET /api/session/attack/fixation/setup
  → サーバー: "脆弱版" エンドポイントが未認証用セッション ID を発行し DB に保存
  → payload.type = "http"
  → response.body = { sessionId: "ATTACKER_KNOWN_SID" }

Step 2 [exploit] 攻撃者: 被害者に固定 session_id を使わせる (URL/フォーム埋め込みをシミュレーション)
  → POST /api/session/attack/fixation/inject
  → body = { victimUsername: "seed_alice", fixedSessionId: "ATTACKER_KNOWN_SID" }
  → サーバー: 被害者として seed_alice でログイン処理を実行するが、
              セッション ID の再生成を省略して ATTACKER_KNOWN_SID のまま DB を更新
  → payload.type = "http"
  → response.body = { success: true, sessionRegenerated: false, sessionId: "ATTACKER_KNOWN_SID" }

Step 3 [replay] 攻撃者: 固定済みセッション ID でプロフィールを取得
  → GET /api/session/attack/fixation/steal
  → headers = { Cookie: "session_id=ATTACKER_KNOWN_SID" }
  → サーバー: セッションが seed_alice に紐づいているため 200 OK を返す
  → outcome = "succeeded" (この実装は脆弱です)

Step 4 [blocked] 防御版比較: 正常実装ではログイン時に ID が変わり攻撃が失敗する
  → POST /api/session/attack/fixation/compare-defense
  → サーバー: ログイン後のセッション ID が変更されたことを確認し、
              旧 ATTACKER_KNOWN_SID でアクセスすると 401 を返す
  → outcome = "blocked"
```

#### 4.1.3 バックエンド API 仕様

**エンドポイント:** `POST /api/session/attack/fixation`

E-2 契約: 1 リクエストで両モード (脆弱+堅牢) を並列実行する単一エンドポイントに統合済み (Phase 2 第五コミット 126c4fd)。
- Request: `{}` (空 body — `sessionAttackFixationSchema = z.object({})`)
- Response: `{ data: AttackResult, _trace: ServerTrace }` — outcome 常に `"succeeded"`、HTTP 200 固定、5 ステップ完全形 (probe → tamper → forge → exploit → verify)
- 攻撃者用 SID 生成・被害者ログイン・固定 SID でのアクセス試行・新規 ID 再生成防御は全てハンドラ内で完結

**シードユーザー:** `seed_alice` (被害者), `attacker_charlie` (攻撃者)

**`_trace` 拡張:**
```typescript
trace.addSessionOp({
  action: "FIXATION_ATTACK_STEP",
  data: {
    isAttackMode: true,
    step: "inject",
    fixedSessionId: "ATTACKER_KNOWN_SID",
    victimUser: "seed_alice",
    sessionRegenerated: false,  // 脆弱版: false / 防御版: true
  },
});
```

#### 4.1.4 AttackResult

E-2 契約: outcome は常に `"succeeded"` 固定。`blockedBy` には堅牢側で発火した防御識別子を記録する。

| 項目 | 値 |
|------|-----|
| `outcome` | `"succeeded"` (常に) |
| HTTP ステータス | 200 (常に) |
| `blockedBy` | `"session_id_regenerated_after_login"` (堅牢側 step 5: uuidv4() で新規 ID 発行) |
| `steps[3].status` (脆弱側 exploit: 再生成なし) | `"success"` (固定 SID でアクセス成立) |
| `steps[4].status` (堅牢側 verify: 再生成あり) | `"blocked"` |
| `extra.victimSeedFound` | `boolean` (seed_alice 不在時は false で safe スキップ) |

#### 4.1.5 防御策 (AttackDefensePanel 用)

```typescript
// 防御実装: ログイン成功後に必ず新規セッション ID を発行する
const sessionId = uuidv4();  // 攻撃者が事前に知ることができない値
db.prepare("INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)")
  .run(sessionId, user.id, expiresAt);
// 旧セッション (もし存在すれば) は削除する
db.prepare("DELETE FROM sessions WHERE user_id = ? AND id != ?")
  .run(user.id, sessionId);
```

**codeHints:**
- `server/routes/session-auth.ts` L.32-43 — 現行の安全な実装 (`uuidv4()` 再生成)
- RFC 6265 Section 8.3 — Cookie の安全な管理
- OWASP Session Management Cheat Sheet — セッション固定対策

**実環境との差異 (必須付記):**
「現代のフレームワークは認証後に自動的にセッション ID を再生成します。
本デモは再生成を省略した独自実装でのみ成立するシナリオです。」

---

### 4.2 シナリオ B: XSS Cookie 窃取 (`session-xss-cookie-theft`)

#### 4.2.1 概要

これは **CWE-79 (XSS) / CWE-1004 (Sensitive Cookie Without HttpOnly Flag) / CAPEC-86**
の概念実証である。

XSS (クロスサイトスクリプティング) により攻撃者が `document.cookie` を読み取り、
セッション Cookie を窃取するシナリオをシミュレーションする。
**HttpOnly 属性が設定されている場合、JavaScript から Cookie を読み取れないため
このシナリオは成立しない。** 本デモは HttpOnly あり/なしの挙動を並列で示す。

本シミュレーションは **XSS の概念実証** であり、実際のスクリプトインジェクションは行わない。
サーバー側で「攻撃者の XSS ペイロードが実行された場合に相当する処理」を再現する。

#### 4.2.2 攻撃フロー (AttackStep[])

```
Step 1 [probe] 被害者のログイン状態を確立 (HttpOnly なし版)
  → POST /api/session/attack/xss-cookie-theft/login-vulnerable
  → body = { username: "seed_alice", password: "Passw0rd!" }
  → サーバー: HttpOnly なしの Cookie を発行
              Set-Cookie: session_id=SID_VALUE (HttpOnly 属性なし)
  → payload.type = "http"

Step 2 [exploit] 攻撃者が XSS で document.cookie を読み取る (シミュレーション)
  → POST /api/session/attack/xss-cookie-theft/simulate-xss
  → body = { cookieString: "session_id=SID_VALUE", payload: "document.cookie" }
  → サーバー: XSS ペイロードが実行された場合に相当する処理を再現
              (実際のスクリプト実行はしない — 教育用シミュレーション)
  → response.body = { 
      cookieValue: "session_id=SID_VALUE",
      readable: true,
      message: "この実装は脆弱です: HttpOnly が設定されていないため JS から読み取れました"
    }
  → outcome = "succeeded" (脆弱版)

Step 3 [verify] HttpOnly あり版でログインし、同じ操作を試みる
  → POST /api/session/attack/xss-cookie-theft/login-protected
  → サーバー: HttpOnly=true の Cookie を発行 (現行の正常実装と同等)
  → POST /api/session/attack/xss-cookie-theft/simulate-xss (再試行)
  → response.body = {
      cookieValue: null,
      readable: false,
      message: "防御が機能しました: HttpOnly 属性により JS からの Cookie 読み取りがブロックされました"
    }
  → outcome = "blocked"
```

#### 4.2.3 バックエンド API 仕様

**エンドポイント:** `POST /api/session/attack/xss-cookie-theft`

E-2 契約: 1 リクエストで HttpOnly なし (脆弱) と HttpOnly あり (堅牢) の両モードを in-memory simulation で並列比較する (DB 書き込みなし)。
- Request: `{}` (空 body — `sessionAttackXssCookieTheftSchema = z.object({})`)
- Response: `{ data: AttackResult, _trace: ServerTrace }` — outcome 常に `"succeeded"`、HTTP 200 固定、5 ステップ完全形

**重要:** ハンドラは、模擬 Cookie 文字列のサーバー側エコーバックで「JS が document.cookie を読めた」
状況を教育的に再現する。実際のスクリプト実行・DOM 操作は一切行わない (実装コメントで 4 箇所明示)。

**`_trace` 拡張:**
```typescript
trace.addSessionOp({
  action: "XSS_COOKIE_THEFT_SIMULATION",
  data: {
    isAttackMode: true,
    httpOnlyEnabled: false,   // 脆弱版: false / 防御版: true
    cookieReadable: true,     // 脆弱版: true (窃取成功) / 防御版: false
    simulationNote: "実際のスクリプト実行ではなく、サーバー側での概念実証です",
  },
});
```

#### 4.2.4 AttackResult

E-2 契約: outcome は常に `"succeeded"` 固定。

| 項目 | 値 |
|------|-----|
| `outcome` | `"succeeded"` (常に) |
| HTTP ステータス | 200 (常に) |
| `blockedBy` | `"cookie_httponly_attribute_enforced"` (堅牢側 step 5: HttpOnly で Cookie 読み取り不可) |
| `steps[3].status` (脆弱側 exploit: HttpOnly なし) | `"success"` (JS から Cookie 読み取り成立シミュレーション) |
| `steps[4].status` (堅牢側 verify: HttpOnly あり) | `"blocked"` |

#### 4.2.5 防御策 (AttackDefensePanel 用)

```typescript
// 防御実装: HttpOnly + SameSite + Secure の組み合わせ
setCookie(c, "session_id", sessionId, {
  httpOnly: true,          // JavaScript から読み取り不可 (XSS 対策)
  sameSite: "Strict",      // 第三者サイトからの Cookie 送信を完全に防ぐ (CSRF 対策)
  secure: true,            // HTTPS 通信時のみ送信 (盗聴対策)
  path: "/api",
  maxAge: 1800,
});
```

**codeHints:**
- `server/routes/session-auth.ts` L.51-57 — 現行の `httpOnly: true` 設定
- RFC 6265 Section 5.3 — HttpOnly 属性の仕様
- MDN: `HttpOnly` Cookie — ブラウザの Cookie アクセス制御
- OWASP XSS Prevention Cheat Sheet — Cookie 保護策

**実環境との差異 (必須付記):**
「XSS 自体は本デモのスコープ外であり、このシミュレーションは
HttpOnly の有無による Cookie の可視性の差を教育的に示すものです。
実際の XSS 攻撃の防止には Content Security Policy (CSP) や
入力値サニタイズが必要です。」

---

### 4.3 シナリオ C: トークンリプレイ攻撃 (`token-replay`)

#### 4.3.1 概要

これは **CWE-294 (Authentication Bypass by Capture-Replay)** の概念実証である。

Bearer トークンが盗まれた場合、有効期限が長いと攻撃者は何度でも
そのトークンを使用してリソースにアクセスできる。
短寿命のアクセストークン (15分) とリフレッシュトークン回転を組み合わせることで、
トークン漏洩時の被害を最小化できることを体感する。

本デモでは取得したアクセストークンを「30秒後」「16分後」の2時点でリプレイし、
設定された有効期限を過ぎたトークンが拒否されることを確認する。

#### 4.3.2 攻撃フロー (AttackStep[])

```
Step 1 [intercept] 攻撃者: 通信を傍受してアクセストークンを盗む (シミュレーション)
  → POST /api/token/attack/replay/setup
  → サーバー: seed_alice でログインし、アクセストークンを発行
              (攻撃者が MitM または XSS でこのトークンを取得したとする)
  → payload.type = "http"
  → response.body = {
      accessToken: "eyJ...",
      issuedAt: <ISO8601>,
      expiresIn: 900,   // 15 分 = 900 秒
    }

Step 2 [replay] 攻撃者: 盗んだトークンを即時リプレイ (有効期限内)
  → POST /api/token/attack/replay/use
  → body = { accessToken: "eyJ...", scenarioDelay: 0 }  // 0 秒後
  → サーバー: jwt.verify() で有効と判定。プロフィールデータを返す。
  → outcome = "succeeded" (この実装は脆弱です: トークンが有効期限内のため)
  → payload.type = "http"
  → response.body = { user: { username: "seed_alice" }, tokenAge: "0 秒" }

Step 3 [replay] 攻撃者: 16 分後にリプレイ (有効期限切れの確認)
  → POST /api/token/attack/replay/use
  → body = { accessToken: "eyJ...", scenarioDelay: 960 }  // 16 分後を模擬
  → サーバー: jwt.verify() で TokenExpiredError → 401
  → outcome = "blocked"
  → payload.type = "http"
  → response.body = { error: "jwt expired", tokenAge: "16 分 (有効期限: 15 分)" }

Step 4 [verify] 防御強化版: 短寿命 + リフレッシュトークン回転を確認
  → POST /api/token/attack/replay/refresh-rotation-demo
  → サーバー: リフレッシュトークンを使って新規アクセストークンを発行し、
              古いリフレッシュトークンは DB で revoked=1 になることを示す
  → response.body = {
      oldRefreshRevoked: true,
      newAccessTokenIssued: true,
      rotationNote: "盗まれた旧リフレッシュトークンの再使用は 401 になります"
    }
  → outcome = "blocked"
```

#### 4.3.3 バックエンド API 仕様

**エンドポイント:** `POST /api/token/attack/replay`

E-2 契約: 1 リクエストでトークン即時リプレイ (脆弱) と有効期限超過後の検証 (堅牢) を並列実行する単一エンドポイント (Phase 2 第五コミット 126c4fd)。
- Request: `{ scenarioDelay?: number }` (秒数、0=即時、960=16分=有効期限超過、デフォルト 960)
  - zod スキーマ: `tokenAttackReplaySchema = z.object({ scenarioDelay: z.number().int().min(0).max(86400).default(960) })`
  - handler 内で `Math.max(scenarioDelay, expiresInSec+1)` (expiresInSec=900) に正規化
- Response: `{ data: AttackResult, _trace: ServerTrace }` — outcome 常に `"succeeded"`、HTTP 200 固定、5 ステップ完全形

**`scenarioDelay` の扱い:**
`scenarioDelay` はフロントエンドから秒数として送り、サーバー側で
「現在時刻 + scenarioDelay 秒」を verify ステップでの仮想検証時刻として使用する。
実際に待機するのではなく、`jwt.verify` の `clockTimestamp` オプション (秒単位) で検証時刻を上書きして
TokenExpiredError を発火させる（教育上の簡略化）。

```typescript
// サーバー側での時刻オフセット検証 (概念)
const fakeNow = Math.floor(Date.now() / 1000) + scenarioDelay;
// jwt.verify の clockTimestamp オプションで検証時刻を上書き
jwt.verify(accessToken, JWT_SECRET, { clockTimestamp: fakeNow });
```

**`_trace` 拡張:**
```typescript
trace.addCryptoOp({
  op: "jwt.verify(replay-attack)",
  input: accessToken.substring(0, 30) + "...",
  output: isExpired ? "EXPIRED ✗ — TokenExpiredError" : "VALID ✓ (リプレイ成立)",
  algo: "HS256",
  detail: `scenarioDelay: ${scenarioDelay}s / expiresIn: 900s / isAttackMode: true`,
});
```

#### 4.3.4 AttackResult

E-2 契約: outcome は常に `"succeeded"` 固定。リフレッシュトークン回転防御は `extra.rotationNote` に補足記録される。

| 項目 | 値 |
|------|-----|
| `outcome` | `"succeeded"` (常に) |
| HTTP ステータス | 200 (常に) |
| `blockedBy` | `"jwt_expiry_validation_enforced"` (堅牢側 step 5: TokenExpiredError) |
| `steps[3].status` (脆弱側 exploit: scenarioDelay=0 即時リプレイ) | `"success"` |
| `steps[4].status` (堅牢側 verify: clockTimestamp で 16 分後検証) | `"blocked"` |
| `extra.rotationNote` | リフレッシュトークン回転防御 (`refresh_tokens.revoked` フラグ) の補足説明 |
| `extra.victimSeedFound` | `boolean` (seed_alice 不在時は sub:0 偽トークン残留を防ぐ) |

#### 4.3.5 防御策 (AttackDefensePanel 用)

```typescript
// 防御実装 1: アクセストークンを短寿命に設定する
const accessToken = jwt.sign(
  { sub: user.id, username: user.username, type: "access" },
  JWT_SECRET,
  { expiresIn: "15m" }  // 15 分: 漏洩リスクを最小化
);

// 防御実装 2: リフレッシュトークン回転 (使い捨て化)
// 旧 jti を原子的に revoked=1 にし、新 jti を発行
db.prepare(
  "UPDATE refresh_tokens SET revoked = 1 WHERE jti = ? AND revoked = 0"
).run(oldJti);
// consumeResult.changes === 0 → 再使用検出 → 401
```

**codeHints:**
- `server/routes/token-auth.ts` L.36-47 — アクセストークン発行 (`expiresIn: "15m"`)
- `server/routes/token-auth.ts` L.159-170 — リフレッシュトークン回転処理
- RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens
- RFC 6749 Section 10.4 — Refresh Token リプレイ防止

**実環境との差異 (必須付記):**
「実環境での Bearer トークン漏洩を完全に防ぐには、
短寿命に加えてトークン バインディング (DPoP / mTLS) や
Token Introspection (RFC 7662) によるリアルタイム無効化が必要です。
本デモは JWT の有効期限と回転の概念を示すものです。」

---

## 5. UI コンポーネント設計

### 5.1 ディレクトリ構成

```
src/components/auth/attacks/session-token/
├── SessionTokenAttackPanel.tsx   # Attacker View のルートコンポーネント
├── FixationAttack.tsx            # シナリオ A: セッション固定
├── XssCookieTheftAttack.tsx      # シナリオ B: XSS Cookie 窃取
├── TokenReplayAttack.tsx         # シナリオ C: トークンリプレイ
└── SessionTokenAttackPanel.css   # スタイル
```

### 5.2 `SessionTokenAttackPanel.tsx`

```typescript
// 教育用シミュレーション専用型 (AttackScenarioMeta)
const SCENARIOS: AttackScenarioMeta[] = [
  {
    id: "session-fixation",
    tabId: "session-vs-token",
    name: "Session Fixation",
    nameJa: "セッション固定攻撃",
    cweId: "CWE-384",
    capecId: "CAPEC-61",
    category: "A2:Broken Authentication",
    difficulty: 2,
    osiLayer: 7,
    severity: "high",
    description: "This is a proof-of-concept for CWE-384 / CAPEC-61.",
    descriptionJa: "これは CWE-384 / CAPEC-61 の概念実証です。",
    mitigation: "Regenerate session ID after login.",
    mitigationJa: "ログイン後にセッション ID を再生成する。",
  },
  {
    id: "session-xss-cookie-theft",
    tabId: "session-vs-token",
    name: "XSS Cookie Theft",
    nameJa: "XSS Cookie 窃取",
    cweId: "CWE-1004",
    capecId: "CAPEC-86",
    category: "A7:XSS",
    difficulty: 2,
    osiLayer: 7,
    severity: "high",
    description: "This is a proof-of-concept for CWE-79 / CWE-1004 / CAPEC-86.",
    descriptionJa: "これは CWE-79 / CWE-1004 / CAPEC-86 の概念実証です。",
    mitigation: "Set HttpOnly flag on session cookies.",
    mitigationJa: "セッション Cookie に HttpOnly フラグを設定する。",
  },
  {
    id: "token-replay",
    tabId: "session-vs-token",
    name: "Token Replay Attack",
    nameJa: "トークンリプレイ攻撃",
    cweId: "CWE-294",
    capecId: "CAPEC-60",
    category: "A2:Broken Authentication",
    difficulty: 2,
    osiLayer: 7,
    severity: "medium",
    description: "This is a proof-of-concept for CWE-294 / CAPEC-60.",
    descriptionJa: "これは CWE-294 / CAPEC-60 の概念実証です。",
    mitigation: "Use short-lived tokens with jti claim and replay counter.",
    mitigationJa: "短命トークン + jti クレーム + リプレイカウンターを使用する。",
  },
];
```

**コンポーネント構成:**
- `ViewModeToggle` (共有): Defender/Attacker モード切替
- `EducationalWarningBanner` (共有): 赤帯バナー (dismissable 禁止)
- `AttackScenarioSelector`: `SCENARIOS` からドロップダウン選択
- `<Show>` で選択されたシナリオに対応するサブコンポーネントを切り替え
- `AttackResultBanner` (共有): outcome に応じた結果表示
- `AttackDefensePanel` (共有): 攻撃完了後に自動展開
- `DataFlowPanel` (既存): `scopeId` で HTTP/_trace を表示

### 5.3 シナリオ A: `FixationAttack.tsx`

**UI 状態管理 (Signals):**
```typescript
const [phase, setPhase] = createSignal<"idle" | "setup" | "inject" | "steal" | "defense">("idle");
const [fixedSid, setFixedSid] = createSignal("");          // 攻撃者が事前に取得した SID
const [victimLoggedIn, setVictimLoggedIn] = createSignal(false);
const [stealResult, setStealResult] = createSignal<StealResult | null>(null);
const [defenseResult, setDefenseResult] = createSignal<DefenseResult | null>(null);
```

**4ステップのシーケンシャル実行:**
各ステップは前のステップ完了後にのみ有効になるボタンで起動する。
`<Show when={phase() === "setup"}>` パターンで UI を制御する。

### 5.4 シナリオ B: `XssCookieTheftAttack.tsx`

**並列表示 (左右比較):**
`AuthComparison.tsx` の左右並列レイアウト (`live-comp-grid`) を踏襲し、
- 左: HttpOnly なし (脆弱版) — 赤色の `EducationalWarningBanner`
- 右: HttpOnly あり (防御版) — 緑色の「防御実装済み」バナー

を並べて Cookie の可視性の違いをリアルタイムで対比する。

**シミュレーション文言の必須付記:**
```tsx
<p class="simulation-note">
  {t(
    "XSS ペイロードの実行はシミュレーションです。実際のスクリプト注入は行いません。",
    "XSS payload execution is simulated. No actual script injection occurs."
  )}
</p>
```

### 5.5 シナリオ C: `TokenReplayAttack.tsx`

**タイムライン表示:**
取得したトークンの発行時刻から現在までの経過をタイムバー + 現在位置インジケーターで示す。
「今すぐリプレイ」「16分後にリプレイ」の2ボタンを設置し、
`scenarioDelay` を変えながら同一トークンの運命を比較する。

```
トークン発行 ─────────────●─────────────────── 有効期限 (15min)
                          ↑ リプレイ 1 (有効)  ↑ リプレイ 2 (期限切れ)
                         0s                   960s
```

---

## 6. テスト要件

### 6.1 バックエンド API テスト

E-2 契約に準拠した不変条件ベースのテスト構成。各シナリオは 1 リクエストで両モード並列実行のため、`outcome === "succeeded"` 固定 + 5 ステップ完全形 + `blockedBy` で防御識別子を検証する。実装は `server/__tests__/session-token-attack.test.ts` (Phase 2 第五コミット 126c4fd)。

| テストカテゴリ | 対象 | 期待値 |
|------------|-----|--------|
| E-2 不変条件 (it.each で 3 シナリオ共通) | `fixation` / `xss-cookie-theft` / `replay` | `status === 200` / `outcome === "succeeded"` / `steps.length === 5` / `_trace.attackSteps.length === 5` |
| logId 一意性 | 全 3 シナリオを連続実行 | `attack_log` テーブルに 3 件の独立 logId を確認 |
| 本番ガード | `NODE_ENV=production` で全 3 ルート | `status === 403` |
| summaryJa prefix | 全 3 シナリオ | 「この実装は」または「このシナリオでは」で始まる |
| `_trace.isAttackMode` | 全攻撃エンドポイント | `true` |
| 外部 URL リクエスト | — | ネットワーク呼び出しなし |
| シナリオ A: extra.victimSeedFound | `fixation` | seed_alice 存在時 true / 不在時 false で safe スキップ |
| シナリオ A: blockedBy | `fixation` | `"session_id_regenerated_after_login"` |
| シナリオ A: HTTP status SSoT | `FIXATION_VULN_HTTP_STATUS=200` / `FIXATION_DEFENDED_HTTP_STATUS=401` を payload.response.status と extra で共有 |
| シナリオ B: extra.cookieReadable | `xss-cookie-theft` | 脆弱側 true / 堅牢側 false |
| シナリオ B: blockedBy | `xss-cookie-theft` | `"cookie_httponly_attribute_enforced"` |
| シナリオ C: scenarioDelay 正規化 | `replay` | handler 内で `Math.max(scenarioDelay, expiresInSec+1)` 適用 |
| シナリオ C: blockedBy | `replay` | `"jwt_expiry_validation_enforced"` |
| シナリオ C: extra.rotationNote | `replay` | リフレッシュトークン回転防御の補足あり |
| `delayedReplayValid` 不変条件 | `replay` | step 5 status === "blocked" のとき `delayedReplayValid === false` |

### 6.2 フロントエンド (Vitest) テスト要件

- `FixationAttack.tsx`: phase Signal の遷移が `idle→setup→inject→steal→defense` の順であること
- `XssCookieTheftAttack.tsx`: `EducationalWarningBanner` が脆弱版パネルで常時表示されること
- `TokenReplayAttack.tsx`: `scenarioDelay=960` のリクエストが正しく送信されること
- `SessionTokenAttackPanel.tsx`: シナリオ切替時に前シナリオの Signal がリセットされること

### 6.3 安全装置チェックリスト (PR 前)

- [ ] 全ての `apiPost` / `apiGet` の宛先が `/api/session/attack/*` または `/api/token/attack/*` のみ
- [ ] `EducationalWarningBanner` が Attacker View の最上部に固定 (`position: sticky`)
- [ ] バナーを `display: none` にするコード・CSS が存在しない
- [ ] 攻撃成立文言が「この実装は」または「このシナリオでは」で始まる
- [ ] XSS デモが「シミュレーション」と明示されており、実 DOM 操作を含まない
- [ ] `_trace.isAttackMode === true` が全攻撃ルートで設定されている
- [ ] `seed_alice`, `attacker_charlie` のシードユーザーのみ使用
- [ ] `POST /api/reset` 後にシナリオが正常動作することを確認

---

## 7. i18n キー一覧

`src/i18n/context.tsx` の `t(ja, en)` ヘルパーで使用するキー。

| 用途 | 日本語 (ja) | 英語 (en) |
|------|------------|-----------|
| シナリオ A タイトル | `セッション固定攻撃` | `Session Fixation Attack` |
| シナリオ A 説明 | `これは CWE-384 / CAPEC-61 の概念実証です。攻撃者が事前に取得したセッション ID を被害者に使わせ、ログイン後も乗り込める脆弱性です。` | `This is a proof-of-concept for CWE-384 / CAPEC-61. An attacker pre-establishes a session ID, forces the victim to use it, and can hijack the session after login.` |
| ステップ A-1 ラベル | `攻撃者: 事前セッション ID を取得` | `Attacker: Obtain pre-session ID` |
| ステップ A-2 ラベル | `攻撃者: 被害者のログインに固定 ID を使わせる` | `Attacker: Force victim to authenticate with fixed ID` |
| ステップ A-3 ラベル | `攻撃者: 固定済みセッション ID でアクセス` | `Attacker: Access resource using fixed session ID` |
| ステップ A-4 ラベル | `防御版: ログイン後に新規 ID を発行 → 攻撃失敗` | `Defense: New ID issued after login → attack blocked` |
| A 成立時メッセージ | `この実装は脆弱です: ログイン後にセッション ID が再生成されませんでした` | `This implementation is vulnerable: session ID was not regenerated after login` |
| A ブロック時メッセージ | `防御が機能しました: ログイン後のセッション ID 再生成が固定攻撃を阻止しました` | `Defense worked: session ID regeneration after login prevented fixation` |
| シナリオ B タイトル | `XSS Cookie 窃取 (HttpOnly 比較)` | `XSS Cookie Theft (HttpOnly Comparison)` |
| シナリオ B 説明 | `これは CWE-79 / CWE-1004 / CAPEC-86 の概念実証です (XSS は教育用シミュレーション)。HttpOnly 属性の有無で Cookie の JS 可視性がどう変わるかを示します。` | `This is a proof-of-concept for CWE-79 / CWE-1004 / CAPEC-86 (XSS is an educational simulation). Demonstrates how HttpOnly attribute affects JavaScript cookie visibility.` |
| ステップ B-1 ラベル | `HttpOnly なしでログイン (脆弱版)` | `Login without HttpOnly (vulnerable)` |
| ステップ B-2 ラベル | `XSS による Cookie 読み取りをシミュレーション` | `Simulate XSS cookie reading` |
| ステップ B-3 ラベル | `HttpOnly ありでログイン (防御版)` | `Login with HttpOnly (protected)` |
| B 脆弱版成立メッセージ | `この実装は脆弱です: HttpOnly が設定されていないため XSS で Cookie を読み取れる可能性があります` | `This implementation is vulnerable: missing HttpOnly allows XSS to read cookies` |
| B 防御版ブロックメッセージ | `防御が機能しました: HttpOnly 属性により JavaScript からの Cookie 読み取りがブロックされました` | `Defense worked: HttpOnly attribute prevents JavaScript from reading the cookie` |
| XSS シミュレーション注記 | `XSS ペイロードの実行はシミュレーションです。実際のスクリプト注入は行いません。` | `XSS payload execution is simulated. No actual script injection occurs.` |
| シナリオ C タイトル | `トークンリプレイ攻撃` | `Token Replay Attack` |
| シナリオ C 説明 | `これは CWE-294 / CAPEC-60 の概念実証です。Bearer トークンが盗まれた場合、有効期限が長いと攻撃者は繰り返しアクセスできます。短寿命設定とリフレッシュトークン回転で軽減できます。` | `This is a proof-of-concept for CWE-294 / CAPEC-60. A stolen Bearer token can be replayed if its lifetime is long. Short-lived tokens and refresh token rotation mitigate this risk.` |
| ステップ C-1 ラベル | `攻撃者: アクセストークンを傍受 (シミュレーション)` | `Attacker: Intercept access token (simulation)` |
| ステップ C-2 ラベル | `攻撃者: 即時リプレイ (有効期限内)` | `Attacker: Immediate replay (within expiry)` |
| ステップ C-3 ラベル | `攻撃者: 16 分後にリプレイ (有効期限切れ)` | `Attacker: Replay after 16 minutes (expired)` |
| ステップ C-4 ラベル | `防御確認: リフレッシュトークン回転` | `Defense: Refresh token rotation` |
| C 即時リプレイ成立メッセージ | `このシナリオでは有効期限内のため、盗んだトークンでアクセスが成立しました` | `In this scenario, the stolen token is still valid, allowing access` |
| C 期限切れブロックメッセージ | `防御が機能しました: JWT 有効期限検証が期限切れトークンを拒否しました` | `Defense worked: JWT expiry validation rejected the expired token` |
| C 回転ブロックメッセージ | `防御が機能しました: refresh_tokens.revoked フラグにより旧リフレッシュトークンの再使用を検出・拒否しました` | `Defense worked: refresh_tokens.revoked flag detected and rejected reuse of old refresh token` |
| 実環境差異: セッション固定 | `現代のフレームワークは認証後に自動的にセッション ID を再生成します` | `Modern frameworks automatically regenerate session IDs after authentication` |
| 実環境差異: XSS Cookie | `XSS 自体の防止には CSP や入力値サニタイズが必要です` | `Preventing XSS itself requires Content Security Policy and input sanitization` |
| 実環境差異: トークンリプレイ | `完全な対策にはトークンバインディング (DPoP / mTLS) や Token Introspection が必要です` | `Complete mitigation requires token binding (DPoP / mTLS) or Token Introspection` |

---

## 8. 関連ファイル

### 8.1 設計書 (必読)

| ファイル | 参照目的 |
|---------|---------|
| `DESIGN/00-overview.md` | 全体目的・攻撃カタログマトリクス・4原則の概要 |
| `DESIGN/01-architecture.md` | バックエンドルート配置方針 (各既存ファイルにサブパスを追加する方針) |
| `DESIGN/02-ui-spec.md` | ViewModeToggle / AttackStepTimeline / AttackResultBanner / AttackDefensePanel の UI 詳細仕様 |
| `DESIGN/03-data-model.md` | AttackScenarioMeta / AttackStep / AttackResult / AttackStepPayload 型定義 |
| `DESIGN/04-safety-guardrails.md` | 教育安全装置の実装方針・文言ルール・PR チェックリスト |

### 8.2 実装対象ファイル

| ファイルパス | 変更種別 | 説明 |
|------------|---------|------|
| `server/routes/session-auth.ts` | **攻撃サブルート追加** | `/attack/fixation/*` と `/attack/xss-cookie-theft/*` を追加 |
| `server/routes/token-auth.ts` | **攻撃サブルート追加** | `/attack/replay/*` を追加 |
| `src/components/auth/AuthComparison.tsx` | **ViewModeToggle 組み込み** | 上部にモード切替トグルを追加 |
| `src/components/auth/attacks/session-token/SessionTokenAttackPanel.tsx` | **新規作成** | Attacker View ルートコンポーネント |
| `src/components/auth/attacks/session-token/FixationAttack.tsx` | **新規作成** | シナリオ A コンポーネント |
| `src/components/auth/attacks/session-token/XssCookieTheftAttack.tsx` | **新規作成** | シナリオ B コンポーネント |
| `src/components/auth/attacks/session-token/TokenReplayAttack.tsx` | **新規作成** | シナリオ C コンポーネント |
| `src/components/auth/attacks/session-token/SessionTokenAttackPanel.css` | **新規作成** | スタイル定義 |
| `server/middleware/trace-logger.ts` | **isAttackMode 拡張** | 攻撃ルート自動検出フラグ追加 |
| `shared/api-types.ts` | **AttackScenarioMeta 等を追加** | `DESIGN/03-data-model.md` で定義された型を実装 |
| `src/data/attack-scenarios.ts` | **新規または更新** | session-vs-token タブの静的シナリオデータ追加 |

### 8.3 スコープ ID 一覧 (DataFlowPanel)

| シナリオ | `scopeId` | 備考 |
|---------|----------|------|
| 正常系 Session デモ | `"session-auth"` | 既存 (`AuthComparison.tsx` SCOPE_SESSION) |
| 正常系 Token デモ | `"token-auth"` | 既存 (`AuthComparison.tsx` SCOPE_TOKEN) |
| 攻撃 A: セッション固定 | `"attack-session"` | 攻撃ルートの HTTP/_trace をキャプチャ |
| 攻撃 B: XSS Cookie 窃取 | `"attack-session"` | 同上 (セッション関連として統合) |
| 攻撃 C: トークンリプレイ | `"attack-token"` | トークン攻撃ルートの HTTP/_trace をキャプチャ |

---

## 付録: 攻撃ルートファイル冒頭コメント規約

`server/routes/session-auth.ts` と `server/routes/token-auth.ts` に追加する
攻撃サブルートの先頭には以下のコメントを付与すること (`DESIGN/04-safety-guardrails.md` §8.2 準拠):

```typescript
/**
 * 攻撃デモルート: session-vs-token タブ
 *
 * 【教育目的専用】
 * このコードは OSI 参照アプリの教材機能として、
 * ローカル環境の固定シードデータに対する攻撃シミュレーションを提供します。
 *
 * - 外部ネットワークへのリクエストは行いません
 * - 実 CVE のエクスプロイトコードは含みません
 * - XSS シミュレーションは実際のスクリプト注入を行いません
 * - 本番環境での使用は想定していません
 *
 * 対象 CWE: CWE-384, CWE-79, CWE-1004, CWE-294
 * 対象 CAPEC: CAPEC-61, CAPEC-86, CAPEC-60
 * 関連設計書: DESIGN/13-attack-session-token.md
 * 安全装置: DESIGN/04-safety-guardrails.md
 */
```
