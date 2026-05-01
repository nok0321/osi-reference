---
title: 攻撃デモカタログ — FIDO2/WebAuthn フィッシング耐性実証
phase: design
last-updated: 2026-04-26
safety-reviewed: true
---

## 教育目的

本ファイルは **教育用シミュレーション** の実装設計である。
記載された攻撃手法は `localhost` 上の固定シードデータに対してのみ動作するよう設計されており、
実環境への攻撃を意図したものではない。

攻撃シミュレーションはすべて「この防御がなぜ必要か」を体感するための概念実証であり、
各シナリオには必ず防御策の解説と実装例が対になっている。

---

# 15. FIDO2/WebAuthn — フィッシング耐性実証設計

---

## 1. 概要

### 1.1 このタブの特殊性: 「攻撃が失敗することを見せる」

FIDO2/WebAuthn タブの攻撃デモカタログは、他の認証タブとは根本的に異なる教材目的を持つ。

他タブでは「防御がない場合に攻撃が成立し、防御を追加することで阻止される」という対比を示す。
本タブでは **「プロトコル設計そのものが攻撃を成立させない」** という事実を実証する。

FIDO2/WebAuthn はフィッシング攻撃に対して構造的な耐性を持つ。その根拠は次の2点にある。

1. **Origin バインディング**: クレデンシャルは登録時の `rpId` (Relying Party ID) に紐付けられる。攻撃者が別オリジンのページに誘導しても、そのオリジンでは署名が生成されないか、サーバー検証で拒否される。

2. **チャレンジの一回性 (one-time challenge)**: サーバーは毎回ランダムなチャレンジを発行し、使用済みのチャレンジは即座に廃棄する。過去の認証レスポンスを再送しても拒否される。

本デモが目指す学習効果:

| 学習目標 | 実証方法 |
|---------|---------|
| FIDO2 はフィッシングに耐性がある理由を理解する | シナリオ A: origin 検証失敗のステップ可視化 |
| パスワード認証がフィッシングに脆弱な理由と対比する | シナリオ B: 並列比較パネル |
| チャレンジの一回性がリプレイ攻撃を防ぐことを理解する | シナリオ C: 同一 attestationObject の再送拒否 |

### 1.2 UI モードの扱い

`AttackResult.outcome` は全シナリオで `"blocked"` が期待値となる。
`AttackResultBanner` は赤ではなく **緑系 (`var(--color-success)`)** で表示し、
「プロトコル設計により防御が機能しました」を強調する (04-safety-guardrails.md §9.1 に基づく)。

`EducationalWarningBanner` は Attacker View として常時表示するが、
このタブでは「攻撃が失敗することを確認するデモです」という補足テキストを加えることが望ましい。

---

## 2. 攻撃シナリオ一覧

| # | シナリオ ID | 攻撃名 | CWE | CAPEC | OSI 層 | 深刻度 | 期待 outcome |
|---|------------|--------|-----|-------|--------|--------|------------|
| A | `fido2-phishing-origin-rejection` | フィッシング: origin 検証による失敗 | CWE-290, CWE-346 | CAPEC-89, CAPEC-194 | 7 | Info | `blocked` |
| B | `fido2-vs-password-phishing` | パスワード vs FIDO2: フィッシング比較 | CWE-290 | CAPEC-89 | 7 | High (パスワード側) | `blocked` (FIDO2側) / `succeeded` (パスワード側) |
| C | `fido2-challenge-replay` | チャレンジリプレイ: 使い捨て検証 | CWE-294 | CAPEC-60 | 7 | Info | `blocked` |

### 2.1 シナリオ深刻度の解釈

本タブの「深刻度」は **「この防御がなかった場合の被害の大きさ」** を示す。
origin 検証がない世界では `critical` 相当の認証バイパスが発生する。
実際には防御が機能しているため、学習者に提示する深刻度は `Info` とする。

シナリオ B は並列比較のため、パスワード側は `High` で表示し、FIDO2 側は `Info` (防御成立) で表示する。

---

## 3. 既存防御側実装

本タブの攻撃シナリオは新たな「脆弱な実装」を作成するのではなく、
**既存の `webauthn.ts` が実装している防御機構** がどのように攻撃を阻止するかを可視化する。

### 3.1 @simplewebauthn/server の origin/rpId 検証

`server/routes/webauthn.ts` の `verifyRegistrationResponse` / `verifyAuthenticationResponse` において:

```typescript
// server/routes/webauthn.ts (既存実装 — 変更不要)
const RP_ID = "localhost";
const ORIGIN = "http://localhost:3000";

// 登録検証
const verification = await verifyRegistrationResponse({
  response: attResponse,
  expectedChallenge: stored.challenge,
  expectedOrigin: ORIGIN,     // ← この検証がフィッシングを阻止する
  expectedRPID: RP_ID,        // ← この検証がオリジン偽装を阻止する
});

// 認証検証
const verification = await verifyAuthenticationResponse({
  response: authResponse,
  expectedChallenge: stored.challenge,
  expectedOrigin: ORIGIN,     // ← 同様の検証
  expectedRPID: RP_ID,        // ← 同様の検証
  credential: { ... },
});
```

`@simplewebauthn/server` の内部実装では、クライアントから返される `clientDataJSON` の
`origin` フィールドを `expectedOrigin` と厳密比較する。不一致の場合は例外をスローし、
上位の `try/catch` が `400` を返す設計になっている。

### 3.2 チャレンジの使い捨て管理

```typescript
// server/routes/webauthn.ts (既存実装 — 変更不要)
const challenges = createTtlStore<{ challenge: string; username: string }>({ ttlMs: 5 * 60 * 1000 });

// 登録/認証オプション発行時: チャレンジを保存
challenges.set(sessionId, { challenge: options.challenge, username });

// 検証成功後: チャレンジを即座に削除 (one-time)
challenges.delete(sessionId);
```

- チャレンジは `sessionId` をキーに TTL 付きで管理される (5分で自動失効)
- **検証が成功した瞬間に `challenges.delete(sessionId)` が呼ばれる**
- 同一の `sessionId` + チャレンジは2回目以降 `"No challenge found"` エラーとなる

### 3.3 カウンターによるクローン検出 (補足)

認証時にはカウンター単調増加チェックも機能している (本タブのシナリオ C とは別の防御):

```typescript
// server/routes/webauthn.ts (既存実装)
if (newCounter > 0 && newCounter <= cred.counter) {
  // counterCloneDetection — クローン認証器の検出
  return c.json({ success: false, error: "Authenticator counter did not increment" }, 403);
}
```

---

## 4. シナリオ詳細

### 4.1 シナリオ A: フィッシング攻撃の origin 検証による失敗

**シナリオ ID**: `fido2-phishing-origin-rejection`

#### 4.1.1 教育的シナリオの前提

これは **CWE-290 (Authentication Bypass by Spoofing)** / **CWE-346 (Origin Validation Error)** / **CAPEC-89** の概念実証である。

攻撃者は `https://attacker.example/login` というフィッシングページを作成し、
正規サービス `http://localhost:3000` と見た目を完全に同一にする。
ユーザーをフィッシングページに誘導し、WebAuthn 認証を実行させようとする。

パスワード認証であれば、フィッシングページが入力されたパスワードを収集して
正規サービスにリレーできる (シナリオ B で対比)。
しかし WebAuthn では **ブラウザがクレデンシャルを `attacker.example` の origin で署名する** ため、
`localhost` の `rpId` 検証で拒否される。

#### 4.1.2 攻撃ステップ設計

| ステップ | `kind` | `status` | 説明 |
|---------|--------|----------|------|
| S1 | `forge` | `success` | 攻撃者フィッシングページが WebAuthn 認証を要求 (origin: `attacker.example`) |
| S2 | `probe` | `success` | サーバーからチャレンジを取得 (正規エンドポイントを中継) |
| S3 | `tamper` | `success` | フィッシングページが Authenticator に署名要求 → `clientDataJSON.origin = "attacker.example"` で署名生成 |
| S4 | `verify` | `blocked` | サーバーの `expectedOrigin = "http://localhost:3000"` との不一致で検証失敗 → `400 Bad Request` |

#### 4.1.3 API 設計

```
POST /api/webauthn/attack/phishing-origin
Content-Type: application/json

Request: {} (E-2: 両モードを並列実行するため body は空オブジェクト。
  攻撃者オリジン・正規 origin・challenge は全てサーバー側のシード値から生成される。
  zod スキーマ: webauthnAttackPhishingOriginSchema = z.object({}))

Response: { data: AttackResult, _trace: ServerTrace }
  // data.outcome: "succeeded" (常に — 5 ステップ完全形で両モードを並列観察)
  // data.steps: 5 ステップ完全形 (probe → tamper → forge → exploit → verify)
  // data.blockedBy: "webauthn_origin_validation_enforced" (堅牢側 verify で発火)
  // data.extra: シナリオ固有フィールド (attackerOrigin / expectedOrigin / clientDataJsonOrigin / vulnerablePathOutcome 等)
```

##### 期待結果

E-2 契約: 1 リクエストで両モード (脆弱: origin 検証なしと仮定、堅牢: expectedOrigin 厳密一致) を並列実行し、5 ステップ完全形を返す。`outcome` は常に `"succeeded"` 固定、HTTP ステータスは 200 固定。`blockedBy` には堅牢側で発火した防御識別子を記録する。

| 項目 | 値 |
|------|-----|
| `outcome` | `"succeeded"` (常に) |
| HTTP ステータス | 200 (常に) |
| `blockedBy` | `"webauthn_origin_validation_enforced"` (堅牢側 step 5: clientDataJSON.origin と expectedOrigin の不一致で拒否) |
| `steps[3].status` (脆弱側 exploit: origin 検証スキップ) | `"success"` (attacker.example origin の署名が受理される仮想シナリオ) |
| `steps[4].status` (堅牢側 verify: expectedOrigin 厳密一致) | `"blocked"` |

**サーバー側シミュレーション処理:**

このシナリオは「ブラウザが attacker.example origin で署名した clientDataJSON をサーバーに送る」
という状況をサーバー側でシミュレーションする。

実際のブラウザ WebAuthn API は同一オリジンポリシーにより `attacker.example` から
`localhost` の登録済みクレデンシャルへのアクセスを既にブロックするが、
教材目的として「仮にブラウザが署名を渡した場合のサーバー検証」を模倣する。

```typescript
// server/routes/webauthn.ts への追加: /attack/phishing-origin
// 【教育目的専用】対象 CWE: CWE-290, CWE-346, CAPEC-89, CAPEC-194
webauthnRoutes.post("/attack/phishing-origin", async (c) => {
  const trace = c.get("trace");
  const startedAt = Date.now();

  // S1: 攻撃者フィッシングページが rpId: attacker.example で WebAuthn 認証を要求
  trace.addAttackStep({ id: "s1", kind: "forge", status: "success",
    label: "Phishing page requests WebAuthn authentication",
    labelJa: "攻撃者フィッシングページが WebAuthn 認証を要求",
    payload: { type: "http", request: { method: "POST", url: "http://attacker.example/trigger-webauthn",
      body: { rpId: "attacker.example", challenge: "<random-bytes>" } } },
    detailJa: "攻撃者ページは rpId: attacker.example で WebAuthn 認証リクエストを構築します" });

  // S2: 正規サーバーからチャレンジを中継取得
  trace.addAttackStep({ id: "s2", kind: "probe", status: "success",
    label: "Relay challenge request to legitimate server",
    labelJa: "正規サーバーへチャレンジ要求を中継",
    payload: { type: "http",
      request: { method: "POST", url: "/api/webauthn/auth/options", body: { username: "seed_alice" } },
      response: { status: 200, body: { sessionId: "<uuid>", options: { challenge: "<base64url>", rpId: "localhost" } } } },
    detailJa: "攻撃者は正規サーバーのチャレンジを中継し、正規に見せかけます" });

  // S3: Authenticator が attacker.example origin で clientDataJSON に署名
  trace.addAttackStep({ id: "s3", kind: "tamper", status: "success",
    label: "Authenticator signs with attacker.example origin",
    labelJa: "Authenticator が attacker.example origin で署名",
    payload: { type: "generic", data: {
      clientDataJSON_origin: "http://attacker.example",
      expected_origin: "http://localhost:3000",
      mismatch: true } },
    detailJa: "Authenticator は origin: attacker.example を含む clientDataJSON を生成します。これはサーバーで拒否されます。" });

  // S4: verifyAuthenticationResponse が expectedOrigin 不一致で例外 → 400
  trace.addAttackStep({ id: "s4", kind: "blocked", status: "blocked",
    label: "Server origin validation rejects attacker.example",
    labelJa: "サーバーの origin 検証が attacker.example を拒否",
    payload: { type: "http", response: { status: 400, body: {
      error: "Origin mismatch: expected http://localhost:3000, got http://attacker.example" } } },
    detailJa: "verifyAuthenticationResponse() が clientDataJSON.origin を expectedOrigin と照合し、不一致のため 400 を返します。" });

  const result: AttackResult = {
    scenarioId: "fido2-phishing-origin-rejection",
    outcome: "blocked",
    startedAt,
    finishedAt: Date.now(),
    steps: trace.getTrace().attackSteps ?? [],
    blockedBy: "origin verification (expectedOrigin mismatch: attacker.example != localhost:3000)",
    blockedByJa: "origin 検証 (expectedOrigin 不一致: attacker.example != localhost:3000)",
    summaryJa: "防御が機能しました: origin バインディングがフィッシング攻撃を阻止しました。クレデンシャルの署名は RP ID に紐付いており、別オリジンから使用できません。",
  };
  return c.json({ success: true, data: result });
});
```

#### 4.1.4 防御解説パネルコンテンツ

`AttackDefensePanel` に表示する内容:

**なぜ防御が機能したか (1〜3 文):**
> FIDO2 の Authenticator はクレデンシャル生成時に `rpId` をバインドします。
> 認証時に生成される `clientDataJSON` には `origin` フィールドが含まれており、
> サーバーは `expectedOrigin` と厳密比較します。
> 攻撃者がフィッシングページに誘導しても、署名に含まれる `origin` は攻撃者ドメインになるため
> 正規サーバーの検証で必ず拒否されます。

**防御実装ファイル:**
`server/routes/webauthn.ts` — `verifyAuthenticationResponse({ expectedOrigin: ORIGIN, expectedRPID: RP_ID })`

**コードヒント:**

```typescript
// @simplewebauthn/server による origin 検証
await verifyAuthenticationResponse({
  response: authResponse,
  expectedChallenge: stored.challenge,
  expectedOrigin: "http://localhost:3000",  // ← 厳密一致検証
  expectedRPID: "localhost",               // ← rpId 不一致も拒否
  credential: { ... },
});
// origin 不一致 → Error: clientDataJSON.origin is not one of the expected values
```

**実環境との差異付記:**
> 実際のブラウザは同一オリジンポリシーにより、`attacker.example` から `localhost` の
> 登録済みクレデンシャルへのアクセス自体をブロックします。
> このデモは「サーバー側の二重防御」として origin 検証がどう機能するかを示す概念実証です。

---

### 4.2 シナリオ B: 同等比較 — パスワードならフィッシング成功する

**シナリオ ID**: `fido2-vs-password-phishing`

#### 4.2.1 教育的シナリオの前提

これは **CWE-290 (Authentication Bypass by Spoofing)** の概念実証である。

シナリオ A と全く同じ攻撃シナリオを、パスワード認証に対して実施した場合を並列比較する。
パスワード認証では攻撃者が入力フォームを中継するだけで認証情報を窃取・使用できる。

本シナリオは **左右並列パネル** で表示する (04-safety-guardrails.md §9.3 に基づく):

- **左パネル (パスワード側)**: 赤色の `EducationalWarningBanner` + 攻撃成立ステップ
- **右パネル (FIDO2 側)**: 緑色の「防御実装済み」バナー + 攻撃失敗ステップ

#### 4.2.2 攻撃ステップ設計

**左パネル (パスワード側) — 攻撃成立:**

| ステップ | `kind` | `status` | 説明 |
|---------|--------|----------|------|
| S1 | `forge` | `success` | 攻撃者フィッシングページがパスワードフォームを表示 |
| S2 | `intercept` | `success` | ユーザーがパスワードを入力 → 攻撃者サーバーに送信される |
| S3 | `replay` | `success` | 攻撃者が窃取したパスワードで正規サービスにログイン成功 |

**右パネル (FIDO2 側) — 攻撃失敗:**

| ステップ | `kind` | `status` | 説明 |
|---------|--------|----------|------|
| S1 | `forge` | `success` | 攻撃者フィッシングページが WebAuthn 認証を要求 |
| S2 | `tamper` | `success` | Authenticator が attacker.example origin で署名 |
| S3 | `blocked` | `blocked` | サーバーの origin 検証で拒否 |

#### 4.2.3 API 設計

```
POST /api/webauthn/attack/vs-password-phishing
Content-Type: application/json

Request: {} (E-2: 両モードを並列実行するため body は空オブジェクト。
  パスワード側 / FIDO2 側の中継型フィッシングは全てサーバー側のシード値から生成される。
  zod スキーマ: webauthnAttackVsPasswordPhishingSchema = z.object({}))

Response: { data: AttackResult, _trace: ServerTrace }
  // data.outcome: "succeeded" (常に)
  // data.steps: 5 ステップ完全形 (probe → tamper → forge → exploit → verify)
  // data.blockedBy: "webauthn_origin_phishing_blocked" (堅牢側 FIDO2 ステップで発火)
  // data.extra: シナリオ固有フィールド (passwordSidePhishingSucceeded / fido2SideOriginRejected / comparisonNote 等)
```

##### 期待結果

E-2 契約: 1 リクエストで両モード (脆弱: パスワード認証 — origin 拘束なし、堅牢: FIDO2 — origin 暗号バインディング) を並列実行し、5 ステップ完全形を返す。`outcome` は常に `"succeeded"` 固定、HTTP ステータスは 200 固定。`blockedBy` には堅牢側で発火した防御識別子を記録する。

| 項目 | 値 |
|------|-----|
| `outcome` | `"succeeded"` (常に) |
| HTTP ステータス | 200 (常に) |
| `blockedBy` | `"webauthn_origin_phishing_blocked"` (堅牢側 step 5: FIDO2 が attacker.example origin の署名を拒否) |
| `steps[3].status` (脆弱側 exploit: パスワード中継) | `"success"` (フィッシングページが収集したパスワードで正規ログイン成立) |
| `steps[4].status` (堅牢側 verify: FIDO2 origin 検証) | `"blocked"` |

#### 4.2.4 防御解説パネルコンテンツ

**なぜパスワードはフィッシングに脆弱か:**
> パスワードはユーザーの記憶に依存するシークレットです。
> 攻撃者がフィッシングページを通じてパスワードを収集し、正規サービスへ中継しても、
> サーバー側ではその入力が正規ページからのものかを区別する手段がありません。

**なぜ FIDO2 はフィッシングに耐性があるか:**
> FIDO2 の秘密鍵は認証器 (デバイス) から外に出ません。
> 攻撃者がフィッシングページを用意しても、`clientDataJSON.origin` が
> 登録時と異なるオリジンになるため、サーバー検証で必ず失敗します。
> 攻撃者が「収集」できるのは署名済みアサーションのみですが、
> そのアサーションは `attacker.example` origin に紐付いており、
> `localhost` サーバーで再利用することも不可能です。

**コードヒント:**

```typescript
// パスワード認証では origin 検証がない (脆弱な実装)
app.post("/login", async (c) => {
  const { username, password } = await c.req.json();
  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
  const valid = await bcrypt.compare(password, user.password_hash);
  // ← フィッシングサイトが中継しても valid === true になる
  return c.json({ success: valid });
});

// FIDO2 では origin が暗号的に検証される (防御済み実装)
await verifyAuthenticationResponse({
  response: authResponse,
  expectedOrigin: "http://localhost:3000",  // ← 一致しない場合は例外
  expectedRPID: "localhost",
  ...
});
```

---

### 4.3 シナリオ C: 登録時のリプレイ攻撃失敗 (チャレンジ使い捨て検証)

**シナリオ ID**: `fido2-challenge-replay`

#### 4.3.1 教育的シナリオの前提

これは **CWE-294 (Authentication Bypass by Capture-replay)** / **CAPEC-60** の概念実証である。

攻撃者が正規ユーザーの WebAuthn 登録時の `attestationObject` を傍受し、
別のユーザー名で同じ `attestationObject` を再送することで、
他者のクレデンシャルを自分のアカウントに紐付けようとする。

サーバーが `challenge` を一回のみ受理する設計 (`createTtlStore` + `challenges.delete(sessionId)`) を
持っていれば、2回目以降の `attestationObject` 送信は拒否される。

#### 4.3.2 攻撃ステップ設計

| ステップ | `kind` | `status` | 説明 |
|---------|--------|----------|------|
| S1 | `intercept` | `success` | 正規ユーザー seed_alice の登録オプション取得を観察し、sessionId を入手 |
| S2 | `intercept` | `success` | seed_alice の attestationObject (登録レスポンス) を傍受 |
| S3 | `replay` | `success` | 攻撃者が同じ attestationObject を別ユーザー名 `attacker_charlie` 名義で送信 (1回目) |
| S4 | `blocked` | `blocked` | チャレンジが存在しないため `400 No challenge found` — seed_alice のチャレンジは使用済み |
| S5 | `replay` | `success` | 攻撃者が正規ユーザーの sessionId を直接使用して再送 (2回目) |
| S6 | `blocked` | `blocked` | `challenges.delete(sessionId)` 済みのため再度 `400 No challenge found` |

#### 4.3.3 API 設計

```
POST /api/webauthn/attack/challenge-replay
Content-Type: application/json

Request: {} (E-2: 両モードを並列実行するため body は空オブジェクト。
  傍受 sessionId / 教育用 attestationObject / challenge は全てサーバー側のシード値から生成される。
  zod スキーマ: webauthnAttackChallengeReplaySchema = z.object({}))

Response: { data: AttackResult, _trace: ServerTrace }
  // data.outcome: "succeeded" (常に)
  // data.steps: 5 ステップ完全形 (probe → tamper → forge → exploit → verify)
  // data.blockedBy: "webauthn_challenge_one_time_consumed" (堅牢側 verify で発火)
  // data.extra: シナリオ固有フィールド (interceptedSessionId / replayAttempt1Status / replayAttempt2Status / challengeConsumedAt 等)
```

##### 期待結果

E-2 契約: 1 リクエストで両モード (脆弱: challenge 多重消費を許容、堅牢: challenges.delete 後の再使用拒否) を並列実行し、5 ステップ完全形を返す。`outcome` は常に `"succeeded"` 固定、HTTP ステータスは 200 固定。`blockedBy` には堅牢側で発火した防御識別子を記録する。

| 項目 | 値 |
|------|-----|
| `outcome` | `"succeeded"` (常に) |
| HTTP ステータス | 200 (常に) |
| `blockedBy` | `"webauthn_challenge_one_time_consumed"` (堅牢側 step 5: challenges.delete 後のリプレイで `No challenge found`) |
| `steps[3].status` (脆弱側 exploit: 傍受 attestationObject の再送) | `"success"` (1回目の verify が観察される) |
| `steps[4].status` (堅牢側 verify: 使い捨てチャレンジ設計) | `"blocked"` |

**サーバー側処理の流れ:**

1. `seed_alice` の登録オプションを内部で生成し、チャレンジを `challenges` に格納する
2. 正規の `attestationObject` を内部でシミュレーション (固定の教育用デモデータを使用)
3. `attacker_charlie` のセッション ID を使用して `attestationObject` を送信 → `seed_alice` のチャレンジと不一致 → `400`
4. `seed_alice` の sessionId を使用して `attestationObject` を送信 → 1回目は成立するが (教育的観察)、2回目は `challenges.delete` 済みで `400`

> **注意**: ステップ 4 の「1回目」については、実際に `verifyRegistrationResponse` を
> 呼び出すと実行環境の WebAuthn API が必要になる。このシミュレーションでは
> 実際の cryptographic verification は実施せず、「チャレンジルックアップの失敗」のみを示す。

```typescript
// server/routes/webauthn.ts への追加: /attack/challenge-replay
// 【教育目的専用】対象 CWE: CWE-294, CAPEC-60
webauthnRoutes.post("/attack/challenge-replay", async (c) => {
  const trace = c.get("trace");
  const startedAt = Date.now();

  // S1: seed_alice の登録オプション取得を観察し sessionId を入手
  const sessionId = `demo-replay-${Date.now()}`;
  const demoChallenge = "dGVzdENoYWxsZW5nZURlbW8";
  challenges.set(sessionId, { challenge: demoChallenge, username: "seed_alice" });
  trace.addAttackStep({ id: "s1", kind: "intercept", status: "success",
    label: "Observe registration options of seed_alice",
    labelJa: "seed_alice の登録オプション取得を観察し sessionId を入手",
    payload: { type: "generic", data: { sessionId, challenge: demoChallenge, captured_by: "attacker_charlie" } },
    detailJa: "攻撃者は seed_alice の登録時に発行された sessionId とチャレンジを観察します。" });

  // S2: seed_alice の attestationObject を傍受
  const demoAttestation = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVh...";
  trace.addAttackStep({ id: "s2", kind: "intercept", status: "success",
    label: "Capture seed_alice's attestationObject",
    labelJa: "seed_alice の attestationObject を傍受",
    payload: { type: "generic", data: { prefix: demoAttestation.substring(0, 40) + "...", note: "Bound to seed_alice's authenticator key" } },
    detailJa: "attackerは attestationObject を傍受。seed_alice の認証器秘密鍵の署名を含みます。" });

  // S3: attacker_charlie 名義で再送 → sessionId+username 不一致 → 拒否 (S4)
  trace.addAttackStep({ id: "s3", kind: "replay", status: "success",
    label: "Replay as attacker_charlie with different sessionId",
    labelJa: "attacker_charlie 名義・別 sessionId で再送 (1回目)",
    payload: { type: "http", request: { method: "POST", url: "/api/webauthn/register/verify",
      body: { sessionId: "different-session-id", username: "attacker_charlie" } } },
    detailJa: "別 sessionId では challenges ストアに一致エントリが存在しません。" });
  trace.addAttackStep({ id: "s4", kind: "blocked", status: "blocked",
    label: "No matching challenge — sessionId+username mismatch",
    labelJa: "一致するチャレンジなし — sessionId+username の不一致で拒否",
    payload: { type: "http", response: { status: 400, body: { error: "No challenge found or challenge expired" } } },
    detailJa: "チャレンジストアは sessionId をキーとし、username も照合します。不一致なら 400 を返します。" });

  // S5: seed_alice の本物の sessionId を使用して再送 → challenges.delete 済みで拒否 (S6)
  challenges.delete(sessionId);  // one-time: 1回目使用後に即削除
  trace.addAttackStep({ id: "s5", kind: "replay", status: "success",
    label: "Replay with seed_alice's correct sessionId (attempt 2)",
    labelJa: "seed_alice の正しい sessionId で再送 (2回目)",
    payload: { type: "http", request: { method: "POST", url: "/api/webauthn/register/verify",
      body: { sessionId, username: "seed_alice" } } },
    detailJa: "正しい sessionId を使用。しかし challenges.delete(sessionId) 呼び出し済みのため..." });
  trace.addAttackStep({ id: "s6", kind: "blocked", status: "blocked",
    label: "Challenge already consumed — replay rejected (one-time design)",
    labelJa: "チャレンジ使用済み — リプレイ拒否 (one-time 設計)",
    payload: { type: "http", response: { status: 400, body: { error: "No challenge found or challenge expired" } } },
    detailJa: "challenges.delete() 後は challenges.get(sessionId) が undefined を返し、リプレイを完全に阻止します。" });

  const result: AttackResult = {
    scenarioId: "fido2-challenge-replay",
    outcome: "blocked",
    startedAt,
    finishedAt: Date.now(),
    steps: trace.getTrace().attackSteps ?? [],
    blockedBy: "one-time challenge store (challenges.delete called after first use)",
    blockedByJa: "使い捨てチャレンジストア (challenges.delete が初回使用後に呼ばれる)",
    summaryJa: "防御が機能しました: サーバーの使い捨てチャレンジ設計がリプレイ攻撃を阻止しました。",
  };
  return c.json({ success: true, data: result });
});
```

#### 4.3.4 防御解説パネルコンテンツ

**なぜ防御が機能したか:**
> チャレンジはサーバー側の `createTtlStore` (TTL: 5分) で管理されます。
> 検証が完了すると `challenges.delete(sessionId)` が即座に呼ばれ、
> 同じ `sessionId` に対する2回目のリクエストは `undefined` を返します。
> これにより、正規の `attestationObject` を傍受して再送しても拒否されます。
> また、`attestationObject` 内の署名は元のチャレンジに対して生成されたものであり、
> 別のチャレンジに対しては暗号的に無効となります。

**防御実装ファイル:**
`server/routes/webauthn.ts` — `challenges.delete(sessionId)` (verifyRegistrationResponse 成功後)

**コードヒント:**

```typescript
// one-time チャレンジ設計の核心
const stored = challenges.get(sessionId);
if (!stored || stored.username !== username) {
  return c.json({ success: false, error: "No challenge found or challenge expired" }, 400);
}

// 検証成功後に即座に削除 → 再送不可
challenges.delete(sessionId);  // ← この1行がリプレイ攻撃を阻止する
```

**実環境との差異付記:**
> 実環境では attestationObject の暗号署名が特定のチャレンジ値に紐付いているため、
> 別のチャレンジに対して同じ署名を使い回すことは暗号的に不可能です。
> このデモは「チャレンジ管理の one-time 設計」という実装上の防御レイヤーを可視化します。

---

## 5. UI コンポーネント設計

### 5.1 ディレクトリ構成

```
src/components/auth/attacks/fido2/
├── Fido2AttackPanel.tsx          # FIDO2 攻撃デモのルートコンポーネント
├── PhishingOriginDemo.tsx        # シナリオ A: フィッシング origin 検証失敗
├── VsPasswordPhishingDemo.tsx    # シナリオ B: 並列比較パネル
├── ChallengeReplayDemo.tsx       # シナリオ C: チャレンジリプレイ阻止
└── Fido2Attack.css               # 攻撃デモ専用スタイル (緑系バナー、防御成立表示)
```

既存コンポーネントへの変更:
```
src/components/auth/Fido2WebAuthn.tsx  # ViewModeToggle + AttackPanel 接続を追加
```

### 5.2 Fido2WebAuthn.tsx への変更

既存コンポーネントへの変更は最小限 (01-architecture.md §3.3 参照):

```typescript
// src/components/auth/Fido2WebAuthn.tsx への追加分
import { Show } from "solid-js";
import ViewModeToggle from "../attacks/ViewModeToggle";
import Fido2AttackPanel from "../attacks/fido2/Fido2AttackPanel";

// 既存コンポーネントの return 末尾に追記
<ViewModeToggle />
<Show when={viewMode() === "attacker"}>
  <Fido2AttackPanel />
</Show>
```

### 5.3 Fido2AttackPanel.tsx の設計

```typescript
// src/components/auth/attacks/fido2/Fido2AttackPanel.tsx (概略)

import { createSignal } from "solid-js";
import { Show, For } from "solid-js";
import EducationalWarningBanner from "../../shared/EducationalWarningBanner";
import AttackScenarioSelector from "../AttackScenarioSelector";
import AttackStepTimeline from "../AttackStepTimeline";
import AttackResultBanner from "../AttackResultBanner";
import AttackDefensePanel from "../AttackDefensePanel";
import DataFlowPanel from "../../../shared/DataFlowPanel";
import { useI18n } from "../../../../i18n/context";
import { apiPost } from "../../../../api/client";
import type { AttackResult } from "../../../../../shared/api-types";

const SCOPE = "attack-fido2";

// このタブ特有の追加テキスト (FIDO2 は攻撃が成立しない旨を伝える)
const FIDO2_SPECIAL_NOTE = {
  ja: "このタブは「攻撃が失敗すること」を確認するデモです。FIDO2 のフィッシング耐性を体験してください。",
  en: "This tab demonstrates that attacks FAIL. Experience FIDO2's phishing resistance firsthand.",
};

const FIDO2_SCENARIOS = [
  {
    id: "fido2-phishing-origin-rejection",
    nameJa: "フィッシング: origin 検証による失敗",
    name: "Phishing: Blocked by Origin Validation",
    descriptionJa: "攻撃者が別オリジンにユーザーを誘導しても、WebAuthn の origin バインディングが阻止します。",
    description: "Even if an attacker lures a user to a different origin, WebAuthn's origin binding blocks the attack.",
    apiPath: "/api/webauthn/attack/phishing-origin",
    severity: "info" as const,
  },
  {
    id: "fido2-vs-password-phishing",
    nameJa: "並列比較: パスワード vs FIDO2 フィッシング耐性",
    name: "Side-by-Side: Password vs FIDO2 Phishing Resistance",
    descriptionJa: "同じフィッシング攻撃がパスワードでは成立し、FIDO2 では失敗することを並列表示します。",
    description: "The same phishing attack succeeds against passwords but fails against FIDO2. Shown side by side.",
    apiPath: "/api/webauthn/attack/vs-password-phishing",
    severity: "high" as const,
  },
  {
    id: "fido2-challenge-replay",
    nameJa: "チャレンジリプレイ: 使い捨て設計による阻止",
    name: "Challenge Replay: Blocked by One-Time Design",
    descriptionJa: "過去の attestationObject を再送しても、チャレンジの使い捨て管理が拒否します。",
    description: "Replaying a captured attestationObject is blocked by the server's one-time challenge store.",
    apiPath: "/api/webauthn/attack/challenge-replay",
    severity: "info" as const,
  },
];

export default function Fido2AttackPanel() {
  const { t } = useI18n();
  const [selectedScenario, setSelectedScenario] = createSignal(FIDO2_SCENARIOS[0]);
  const [currentResult, setCurrentResult] = createSignal<AttackResult | null>(null);
  const [running, setRunning] = createSignal(false);

  async function runAttack() {
    const scenario = selectedScenario();
    setRunning(true);
    setCurrentResult(null);

    const res = await apiPost<AttackResult>(scenario.apiPath, {
      username: "seed_alice",
      fakeOrigin: "http://attacker.example",
    }, SCOPE);

    if (res.data) setCurrentResult(res.data);
    setRunning(false);
  }

  return (
    <div class="fido2-attack-panel">
      {/* FIDO2 特有の補足テキスト付き EducationalWarningBanner */}
      <EducationalWarningBanner />
      <div class="fido2-special-note" role="note">
        {t(FIDO2_SPECIAL_NOTE.ja, FIDO2_SPECIAL_NOTE.en)}
      </div>

      <AttackScenarioSelector
        scenarios={FIDO2_SCENARIOS}
        selected={selectedScenario()}
        onSelect={setSelectedScenario}
      />

      <button
        class="attack-run-btn"
        disabled={running()}
        onClick={runAttack}
      >
        {t(
          running() ? "実行中..." : "攻撃シミュレーションを実行",
          running() ? "Running..." : "Run Attack Simulation"
        )}
      </button>

      <Show when={currentResult()}>
        {/* 全シナリオで outcome: "blocked" → 緑系バナー */}
        <AttackResultBanner result={currentResult()!} successColor="var(--color-success)" />
        <AttackStepTimeline steps={currentResult()!.steps} />
        <AttackDefensePanel scenarioId={selectedScenario().id} />
      </Show>

      <DataFlowPanel scopeId={SCOPE} />
    </div>
  );
}
```

### 5.4 AttackResultBanner の緑系表示 (CSS 要点)

FIDO2 タブでは `outcome: "blocked"` が常に期待値のため、バナーは緑系で表示する。

```css
/* Fido2Attack.css */
.attack-result-banner.blocked    { background-color: var(--color-success, #52c41a); color: #fff; font-weight: 700; }
.fido2-special-note              { background: rgba(82,196,26,0.12); border-left: 3px solid var(--color-success, #52c41a); padding: 8px 12px; }
.fido2-comparison-grid           { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
.fido2-comparison-grid .password-side { border-top: 3px solid var(--color-warning, #ff4d4f); }
.fido2-comparison-grid .fido2-side    { border-top: 3px solid var(--color-success, #52c41a); }
```

### 5.5 VsPasswordPhishingDemo.tsx の並列パネル設計

シナリオ B の並列比較 (04-safety-guardrails.md §9.3 準拠):

```typescript
// VsPasswordPhishingDemo.tsx (概略)

// 左パネル (パスワード側)
<div class="password-side">
  <EducationalWarningBanner />  {/* 赤帯 */}
  <h4>{t("パスワード認証", "Password Auth")}</h4>
  <AttackStepTimeline steps={passwordSteps()} />
  <AttackResultBanner
    result={passwordResult()}
    // outcome: "succeeded" → 赤色表示
  />
</div>

// 右パネル (FIDO2 側)
<div class="fido2-side">
  <div class="defense-badge">{t("防御実装済み", "Defense Active")}</div>
  <h4>{t("FIDO2/WebAuthn", "FIDO2/WebAuthn")}</h4>
  <AttackStepTimeline steps={fido2Steps()} />
  <AttackResultBanner
    result={fido2Result()}
    successColor="var(--color-success)"
    // outcome: "blocked" → 緑色表示
  />
</div>
```

---

## 6. テスト要件

### 6.1 バックエンドエンドポイントテスト

E-2 契約に準拠したテスト構成。各シナリオは 1 リクエストで両モード並列実行のため、`outcome === "succeeded"` 固定 + 5 ステップ完全形 + `blockedBy` で防御識別子を検証する。実装は `server/__tests__/webauthn-attack.test.ts`。

| テストカテゴリ | 対象 | 期待値 |
|------------|-----|--------|
| E-2 不変条件 (it.each で 3 シナリオ共通) | `phishing-origin` / `vs-password-phishing` / `challenge-replay` | `status === 200` / `outcome === "succeeded"` / `steps.length === 5` / `_trace.attackSteps.length === 5` / `_trace.isAttackMode === true` |
| logId 一意性 | 全 3 シナリオを連続実行 | `attack_log` テーブルに 3 件の独立 logId を確認 |
| 本番ガード | `NODE_ENV=production` で全 3 ルート | `status === 403` |
| summaryJa prefix | 全 3 シナリオ | 「この実装は」または「このシナリオでは」または「防御が機能しました」で始まる |
| シナリオ A: blockedBy | `phishing-origin` | `"webauthn_origin_validation_enforced"` |
| シナリオ A: extra フィールド | `phishing-origin` | `extra.attackerOrigin` / `extra.expectedOrigin` / `extra.clientDataJsonOrigin` を含む |
| シナリオ B: blockedBy | `vs-password-phishing` | `"webauthn_origin_phishing_blocked"` |
| シナリオ B: extra フィールド | `vs-password-phishing` | `extra.passwordSidePhishingSucceeded === true` / `extra.fido2SideOriginRejected === true` / `extra.comparisonNote` を含む |
| シナリオ C: blockedBy | `challenge-replay` | `"webauthn_challenge_one_time_consumed"` |
| シナリオ C: extra フィールド | `challenge-replay` | `extra.interceptedSessionId` / `extra.replayAttempt2Status === "blocked"` / `extra.challengeConsumedAt` を含む |

### 6.2 フロントエンド動作テスト

| テスト ID | テスト内容 | 検証方法 |
|----------|-----------|---------|
| T-F-01 | `EducationalWarningBanner` が Attacker View 切替後に常時表示される | DOM に `edu-warning-banner` が存在し `visibility: visible` |
| T-F-02 | `AttackResultBanner` が緑色で表示される (`outcome: "blocked"`) | `background-color` が `--color-success` 系 |
| T-F-03 | シナリオ B の並列パネル — 左は赤、右は緑 | 両パネルのヘッダーボーダーカラーを確認 |
| T-F-04 | `AttackDefensePanel` がシナリオ実行後に展開される | コンポーネントが DOM に追加される |
| T-F-05 | `DataFlowPanel` に Trace タブの `attackSteps` が表示される | パネルのテキストに `origin` / `challenge` が含まれる |

### 6.3 UI 文言チェックリスト (04-safety-guardrails.md §4.2 準拠)

- [ ] Attacker View のすべての画面で `EducationalWarningBanner` が最上部に固定表示されている
- [ ] バナーが `display: none` / `visibility: hidden` になるコード・CSS が存在しない
- [ ] 攻撃成立 (シナリオ B パスワード側) の文言が「このシナリオでは」で始まっている
- [ ] 禁止表現 (「ハッキング」「クラッキング」「簡単に破れる」等) が存在しない
- [ ] `AttackResult.blockedBy` に防御機能名が設定されている
- [ ] UI が `防御が機能しました: <blockedBy>` 形式で表示している

### 6.4 POST /api/reset 後の動作確認

```
1. POST /api/reset を実行
2. 各攻撃エンドポイントにリクエストを送信
3. 全エンドポイントが正常に `outcome: "blocked"` を返すことを確認
4. attack_log テーブルがクリアされていることを確認
```

---

## 7. i18n キー一覧

`src/i18n/context.tsx` の `t(ja, en)` ヘルパーで使用するキーと文言の対応表。

| キー (文言 — 日本語) | 文言 — English |
|---------------------|---------------|
| `このタブは「攻撃が失敗すること」を確認するデモです。FIDO2 のフィッシング耐性を体験してください。` | `This tab demonstrates that attacks FAIL. Experience FIDO2's phishing resistance firsthand.` |
| `攻撃シミュレーションを実行` | `Run Attack Simulation` |
| `フィッシング: origin 検証による失敗` | `Phishing: Blocked by Origin Validation` |
| `並列比較: パスワード vs FIDO2 フィッシング耐性` | `Side-by-Side: Password vs FIDO2 Phishing Resistance` |
| `チャレンジリプレイ: 使い捨て設計による阻止` | `Challenge Replay: Blocked by One-Time Design` |
| `攻撃者フィッシングページが WebAuthn 認証を要求` | `Phishing page requests WebAuthn authentication` |
| `正規サーバーへチャレンジ要求を中継` | `Relay challenge request to legitimate server` |
| `Authenticator が attacker.example origin で署名` | `Authenticator signs with attacker.example origin` |
| `サーバーの origin 検証が attacker.example を拒否` | `Server origin validation rejects attacker.example` |
| `seed_alice の登録オプション取得を観察し sessionId を入手` | `Observe registration options of seed_alice` |
| `seed_alice の attestationObject を傍受` | `Capture seed_alice's attestationObject` |
| `attacker_charlie 名義で attestationObject を再送 (1回目)` | `Replay attestationObject as attacker_charlie (attempt 1)` |
| `sessionId + username の組み合わせに一致するチャレンジが存在しない → 拒否` | `No matching challenge found for sessionId + username combination` |
| `seed_alice の sessionId を直接使用して再送 (2回目)` | `Replay with seed_alice's sessionId (attempt 2)` |
| `チャレンジ使用済み — リプレイ拒否 (one-time 設計)` | `Challenge already consumed — replay rejected` |
| `パスワード認証` | `Password Auth` |
| `防御実装済み` | `Defense Active` |
| `防御が機能しました: origin バインディングがフィッシング攻撃を阻止しました。クレデンシャルの署名は RP ID に紐付いており、別オリジンから使用できません。` | `Defense activated: Origin binding prevented the phishing attack. The credential signature is bound to the RP ID and cannot be used from a different origin.` |
| `防御が機能しました: サーバーの使い捨てチャレンジ設計がリプレイ攻撃を阻止しました。各チャレンジは一度しか消費できません。` | `Defense activated: The server's one-time challenge design prevented the replay attack. Each challenge can only be consumed once.` |

### 7.1 `AttackStep.labelJa` / `detailJa` のキー

バックエンドの `trace.addAttackStep()` で設定するフィールドは上記テーブルの日本語文言と一致させる。
フロントエンドは `useI18n()` の言語設定に応じて `label` / `labelJa` を切り替えて表示する。

---

## 8. 関連ファイル

### 8.1 新規作成ファイル

| ファイルパス | 役割 |
|------------|------|
| `src/components/auth/attacks/fido2/Fido2AttackPanel.tsx` | FIDO2 攻撃デモのルートコンポーネント |
| `src/components/auth/attacks/fido2/PhishingOriginDemo.tsx` | シナリオ A の詳細コンポーネント |
| `src/components/auth/attacks/fido2/VsPasswordPhishingDemo.tsx` | シナリオ B の並列比較コンポーネント |
| `src/components/auth/attacks/fido2/ChallengeReplayDemo.tsx` | シナリオ C のコンポーネント |
| `src/components/auth/attacks/fido2/Fido2Attack.css` | 攻撃デモ専用スタイル (緑系バナー等) |
| `src/components/auth/attacks/scenarios/fido2-scenarios.ts` | `AttackScenarioMeta[]` の静的定義 |

### 8.2 変更ファイル

| ファイルパス | 変更内容 | 変更規模 |
|------------|---------|---------|
| `server/routes/webauthn.ts` | `/attack/phishing-origin`, `/attack/vs-password-phishing`, `/attack/challenge-replay` の3エンドポイントを追加 | 小 (~120 行追加) |
| `src/components/auth/Fido2WebAuthn.tsx` | `ViewModeToggle` + `<Show>` + `Fido2AttackPanel` を追加 | 極小 (~10 行追加) |
| `src/components/shared/EducationalWarningBanner.tsx` | FIDO2 タブ向けの `additionalNote` props を追加 (オプション) | 極小 (~5 行追加) |
| `src/components/auth/attacks/AttackResultBanner.tsx` | `successColor` props で緑色バナーをサポート | 極小 (~5 行追加) |

### 8.3 既存ファイル (参照のみ、変更不要)

| ファイルパス | 参照理由 |
|------------|---------|
| `server/routes/webauthn.ts` | `RP_ID`, `ORIGIN`, `challenges` ストア、`verifyRegistrationResponse` / `verifyAuthenticationResponse` の防御実装を参照 |
| `server/db/schema.ts` | `webauthn_credentials` テーブル構造 (credential_id, user_id, public_key, counter, transports) を参照 |
| `src/components/auth/Fido2WebAuthn.tsx` | 既存 Defender View の実装を把握してから Attacker View を追加 |
| `src/components/shared/DataFlowPanel.tsx` | `scopeId="attack-fido2"` で使用。変更不要 |
| `src/api/client.ts` | `apiPost` / `apiGet` の使用パターン参照 |
| `shared/api-types.ts` | `AttackResult`, `AttackStep`, `AttackStepPayload` 型の参照 |
| `server/middleware/trace-logger.ts` | `trace.addAttackStep()` の呼び出しパターン参照 |
| `DESIGN/04-safety-guardrails.md` | 文言ルール・安全装置の実装方針 |
| `DESIGN/03-data-model.md` | `AttackResult`, `AttackStep` の型定義詳細 |

### 8.4 API エンドポイント一覧

| メソッド | パス | 役割 | 期待 outcome |
|---------|------|------|------------|
| POST | `/api/webauthn/attack/phishing-origin` | シナリオ A: フィッシング origin 検証失敗 | `blocked` |
| POST | `/api/webauthn/attack/vs-password-phishing` | シナリオ B: パスワード vs FIDO2 並列比較 | `blocked` (FIDO2) / `succeeded` (password) |
| POST | `/api/webauthn/attack/challenge-replay` | シナリオ C: チャレンジリプレイ阻止 | `blocked` |

---

## 付録 A: FIDO2 フィッシング耐性の技術的根拠

### A.1 プロトコルレベルの保証

WebAuthn 仕様 (W3C WebAuthn Level 2) は以下を要求する:

1. **clientDataHash**: 署名対象のデータには `clientDataJSON` のハッシュが含まれる。`clientDataJSON` には `origin` が含まれる。
2. **rpIdHash**: 認証器は `authenticatorData` に `rpId` の SHA-256 ハッシュを含める。サーバーはこれを `SHA-256(expectedRPID)` と比較する。
3. **challenge binding**: `clientDataJSON.challenge` が `expectedChallenge` と一致しなければ検証は失敗する。

これら3つの検証が合わさることで、別オリジンからの署名・過去のチャレンジの再利用・rpId 偽装のいずれも暗号的に不可能となる。

### A.2 @simplewebauthn/server の検証フロー

```
verifyAuthenticationResponse()
  → verifyClientData()
      → check clientDataJSON.type === "webauthn.get"
      → check clientDataJSON.origin in expectedOrigins       ← シナリオ A の防御ポイント
      → check clientDataJSON.challenge === expectedChallenge  ← シナリオ C の防御ポイント
  → verifyAuthenticatorData()
      → check authenticatorData.rpIdHash === SHA-256(expectedRPID)
      → check authenticatorData.flags.UP (user presence)
  → verifySignature()
      → verify ECDSA/RSA signature with stored public key
```

### A.3 文言・スタイル規約 (04-safety-guardrails.md 参照)

- 防御成立時: 「防御が機能しました: `<blockedBy>` が〜を拒否しました」(機能名を主語にする)
- 攻撃成立時 (シナリオ B パスワード側): 「このシナリオでは〜防御機構がないため攻撃が成立しました」
- シナリオ B 並列パネルの `EducationalWarningBanner` と `defense-badge` は `height: 44px` で高さを揃える
- 禁止表現: 「ハッキング」「簡単に盗める」「攻撃に成功しました」— 詳細は §4 禁止表現一覧を参照
