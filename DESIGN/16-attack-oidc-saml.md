---
title: 攻撃デモカタログ — OIDC & SAML 攻撃詳細
phase: design
tab-id: oidc-saml
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

# 16. OIDC & SAML 攻撃カタログ

## 1. 概要

「OIDC & SAML (oidc-saml)」タブは、OpenID Connect PKCE フローと SAML 2.0 IdP シミュレーションを
正常系で学ぶ既存の Defender View を持つ。このカタログは同タブに **Attacker View** を追加し、
SAML の XML 署名検証の落とし穴、リプレイ攻撃、OIDC の ID Token 検証不備が攻撃者に
どのように悪用されるかを体感的に理解させる。

### 1.1 防御側既存実装の参照

| ファイル | 役割 |
|---------|------|
| `server/routes/oidc-saml-sim.ts` | OIDC PKCE フロー (`/authorize` → `/token` → `/userinfo`) と SAML SSO シミュレーション (`/saml/sso`)。HMAC-SHA256 による簡略化アサーション署名を実装 |
| `src/components/auth/OidcSamlFlow.tsx` | `OidcSamlDemo` コンポーネント。OIDC/SAML の切替デモ + `DataFlowPanel` による HTTP/Trace 可視化 |
| `server/db/schema.ts` | `users`, `oauth_clients`, `oauth_codes` テーブル定義 |
| `shared/api-types.ts` | `OidcAuthorizeData`, `OidcTokenData`, `SamlSsoData` 等の共有型定義 |

### 1.2 攻撃デモの追加方針

既存の `OidcSamlFlow.tsx` に `ViewModeToggle` を追加し、Attacker View として
`OidcSamlAttackPanel` コンポーネントを条件表示する。
攻撃 API は新規ファイル `server/routes/attack-oidc-saml.ts` として追加する
(DESIGN/01-architecture.md §2.1 のルート配置方針に準拠)。

---

## 2. 攻撃シナリオ一覧

| # | シナリオ ID | 攻撃名 | CWE | CAPEC | OSI 層 | 深刻度 |
|---|------------|--------|-----|-------|--------|-------|
| A | `saml-xsw` | SAML XML Signature Wrapping (XSW) | CWE-345, CAPEC-475 | CAPEC-475 | L7 (Application) | Critical |
| B | `saml-assertion-replay` | SAML アサーションリプレイ | CWE-294 | CAPEC-60 | L7 (Application) | High |
| C | `oidc-id-token-spoofing` | ID Token なりすまし (aud/iss 検証省略) | CWE-345, CWE-1004 | CAPEC-196 | L7 (Application) | Critical |

---

## 3. 既存防御側実装

### 3.1 `server/routes/oidc-saml-sim.ts` の構造

```
oidcSamlSimRoutes
├── GET  /oidc/.well-known/openid-configuration   ← Discovery ドキュメント
├── POST /oidc/authorize                          ← PKCE + 認証コード発行
│   ├── bcrypt.compare(password, hash)            ← ユーザー認証
│   ├── code_challenge (S256) 検証               ← PKCE
│   └── oidcChallenges.set(code, { userId, nonce, codeChallenge })
├── POST /oidc/token                              ← コード → ID Token 交換
│   ├── oidcChallenges.get(code)                  ← 使用済みコード削除
│   ├── PKCE: SHA256(code_verifier) == code_challenge (timingSafeEqual)
│   └── jwt.sign({ iss, sub, aud, exp, iat, nonce }, OIDC_SECRET, { algorithm: "HS256" })
├── GET  /oidc/userinfo                           ← Bearer トークン検証
│   └── jwt.verify(token, OIDC_SECRET)
├── POST /oidc/saml/sso                           ← SAML アサーション生成
│   ├── bcrypt.compare(password, hash)            ← ユーザー認証
│   ├── assertion = { @ID, IssueInstant, Subject, Conditions, AuthnStatement, AttributeStatement }
│   └── signature = HMAC-SHA256(assertionJson, OIDC_SECRET)  ← 簡略化署名
└── GET  /oidc/saml/metadata
```

`trace.addCryptoOp()` により、署名生成・PKCE 検証・JWT 署名の操作詳細が
`_trace.cryptoOps` に記録され `DataFlowPanel` の Trace タブで可視化される。

### 3.2 既存実装の防御上の強み

| 防御要素 | 実装箇所 | 効果 |
|---------|---------|------|
| PKCE (S256) | `oidc-saml-sim.ts:117-136` | 認可コード傍受時のトークン詐取を防ぐ |
| nonce クレーム | `oidc-saml-sim.ts:148-156` | ID Token リプレイ攻撃を防ぐ |
| 認可コードの使い捨て | `oidcChallenges.delete(code)` | コードリプレイを防ぐ |
| HMAC-SHA256 アサーション署名 | `oidc-saml-sim.ts:274-281` | アサーション改竄の検出 (簡略化版) |
| NotOnOrAfter / NotBefore | `assertion.Conditions` | アサーションの有効期間制約 |

### 3.3 教育用簡略化の範囲

現行の SAML シミュレーションは以下を意図的に簡略化している (コメント行 220-234 参照)。
攻撃デモはこの簡略化の「ギャップ」を教材として活用する。

| 簡略化項目 | 現行実装 | 実際の SAML 2.0 |
|-----------|---------|---------------|
| 署名形式 | HMAC-SHA256 (JSON) | XML Digital Signature (RSA-SHA256 / ECDSA) |
| XPath 署名範囲 | JSON 全体を署名対象 | XML の `Assertion` 要素を特定 XPath で署名 |
| 証明書 | なし | X.509 証明書チェーン検証 |
| バインディング | JSON API | HTTP-POST (Base64 エンコード XML) |

攻撃シナリオ A (SAML XSW) は、この「XPath 署名範囲の曖昧さ」を体感させる教材である。

---

## 4. シナリオ詳細

---

### 4.1 `saml-xsw` — SAML XML Signature Wrapping

#### 概要

これは **CWE-345 / CAPEC-475** の概念実証である。
SAML の XML Digital Signature は、アサーション XML の特定要素のみを署名対象とする。
XML Signature Wrapping (XSW) 攻撃では、攻撃者が正規の署名済みアサーションを
「ラッパー」として別の場所に移動させ、偽のアサーション (署名対象外) を
SP (サービスプロバイダー) が実際に読み込む位置に挿入する。

素朴な SP 実装は「署名が正しければアサーション全体が正当」と誤って解釈するため、
改竄された偽アサーション (高権限ユーザーや別ユーザー) を受理してしまう。

XSW のシミュレーションは「2 層構造の簡略化された XML ペイロード」で表現し、
実際の XPath 操作は説明のみとする。

**実環境との差異の注記 (必須)**:
実環境の XSW 攻撃は XML 名前空間・XPath・XML Canonicalization の深い知識を要する。
このデモは「署名対象範囲」の概念を 2 層 JSON 構造で簡略表示したものであり、
実際の XML ペイロードの完全な生成は含まない。

#### CWE / CAPEC / OSI 層

| 項目 | 値 |
|------|-----|
| CWE | CWE-345 (Insufficient Verification of Data Authenticity) |
| CAPEC | CAPEC-475 (Signature Spoofing by Improper Validation) |
| OSI 層 | Layer 7 — Application |
| 深刻度 | Critical |

#### 前提条件 (脆弱な実装の例)

攻撃者は以下の条件を満たしている:

1. 正規ユーザー (`seed_alice`) として一度認証し、正当な SAML レスポンスを取得済み
2. SAML レスポンスの XML 構造を書き換えて再送信できる中間者ポジションにいる
3. SP がアサーション検証時に「署名対象の ID 属性と実際に処理するアサーション要素が
   同一であること」を確認していない (素朴なパーサを使用)

**脆弱な SP 実装の核心** (署名対象 ID と処理対象 ID の不一致を検出しない):

```typescript
// 脆弱 (教育用シミュレーション専用): 署名は確認するが処理対象との同一性を確認しない
function naiveVerify(parsed: SAMLResponse) {
  const signedEl = parsed.SignedAssertion;
  const valid = verifySignature(signedEl.assertion, signedEl.signature);  // true
  const processed = parsed.Assertion || signedEl.assertion;  // XSW: 外側の偽が選択される
  return { valid, subject: processed.Subject.NameID["#text"] }; // 偽の Subject が返る
}
```

#### XSW 改竄構造 (2 層簡略化 JSON)

```json
// 攻撃者が送信する XSW ペイロード (簡略化表現)
{
  "SAMLResponse": {
    "Assertion":        // ← 外側 (偽/未署名): SP が処理してしまう
      { "@ID": "_fake_assertion_001",
        "Subject": { "NameID": { "#text": "attacker_charlie@demo.example" } },
        "Conditions": { "@NotOnOrAfter": "2099-01-01T00:00:00Z" },
        "AttributeStatement": { "Attributes": [{ "Name": "role", "Value": "admin" }] } },
    "SignedAssertion":  // ← 内側 (正規/署名済み): 署名検証の対象
      { "assertion":
          { "@ID": "_real_assertion_abc123",
            "Subject": { "NameID": { "#text": "seed_alice@demo.example" } },
            "Conditions": { "@NotOnOrAfter": "2026-04-26T12:05:00Z" },
            "AttributeStatement": { "Attributes": [{ "Name": "role", "Value": "user" }] } },
        "signature": "HMAC-SHA256(正規アサーション) = 4a8f3c..." }
  }
}
```

**教育ポイント:** 署名 `4a8f3c...` は `_real_assertion_abc123` に対して正しい。しかし
素朴なパーサは「署名が通れば OK」と判断し、外側の偽アサーション `_fake_assertion_001`
の `role: admin` / `attacker_charlie` を処理してしまう。

#### 攻撃ステップ (AttackStep[])

```typescript
const steps: AttackStep[] = [
  {
    id: "step-1", kind: "intercept",
    label: "Obtain legitimate SAML assertion for seed_alice",
    labelJa: "seed_alice の正規 SAML アサーションを取得",
    status: "success",
    payload: { type: "http",
      request: { method: "POST", url: "/api/oidc/saml/sso",
        body: { username: "seed_alice", password: "Passw0rd!", sp_entity_id: "https://sp.example.com/metadata" } },
      response: { status: 200, body: {
        assertion: { "@ID": "_real_assertion_abc123", Subject: { NameID: { "#text": "seed_alice@demo.example" } },
                     Conditions: { "@NotOnOrAfter": "2026-04-26T12:05:00Z" },
                     AttributeStatement: { Attributes: [{ Name: "role", Value: "user" }] } },
        signature: "4a8f3c...(正規署名)" } } },
    detail: "The attacker obtains a valid SAML assertion by authenticating as seed_alice.",
    detailJa: "攻撃者は seed_alice として認証し、正当な SAML アサーションを取得します。",
    timestamp: Date.now(),
  },
  {
    id: "step-2", kind: "exploit",
    label: "Wrap legitimate assertion and inject fake admin assertion",
    labelJa: "正規アサーションをラップし偽管理者アサーションを挿入",
    status: "success",
    payload: { type: "generic", data: { xswStructure: "outer: fake admin (unsigned) / inner: real (signed)",
      fakeSubject: "attacker_charlie@demo.example", fakeRole: "admin",
      signedId: "_real_assertion_abc123", note: "署名は正規アサーション ID を参照。偽は署名対象外" } },
    detail: "Attacker constructs XSW payload: outer fake assertion (admin) wrapping inner signed (user).",
    detailJa: "攻撃者は XSW ペイロードを構築: 署名済み (user) を内側にラップし偽管理者アサーションを外側に配置。",
    timestamp: Date.now(),
  },
  {
    id: "step-3", kind: "probe",
    label: "Submit XSW payload to naive SP (no XPath scope check)",
    labelJa: "素朴な SP (XPath 範囲検証なし) に XSW ペイロードを送信",
    status: "success",
    payload: { type: "http",
      request: { method: "POST", url: "/api/saml/attack/xsw",
        body: { mode: "naive", xswPayload: "...XSW wrapped payload..." } },
      response: { status: 200, body: { outcome: "succeeded", processedSubject: "attacker_charlie@demo.example",
        processedRole: "admin", signatureValid: true,
        note: "この実装は脆弱です: 署名検証は通過しましたが、処理されたアサーションは偽物です" } } },
    detail: "Naive parser returns signature=valid but reads fake admin assertion.",
    detailJa: "素朴なパーサは署名=有効を返しますが、偽の管理者アサーションを読み込みます。",
    timestamp: Date.now(),
  },
  {
    id: "step-4", kind: "verify",
    label: "Submit same XSW payload to strict SP (XPath signature scope check)",
    labelJa: "厳密な SP (XPath 署名範囲検証あり) に同一 XSW ペイロードを送信",
    status: "blocked",
    payload: { type: "http",
      request: { method: "POST", url: "/api/saml/attack/xsw",
        body: { mode: "strict", xswPayload: "...XSW wrapped payload..." } },
      response: { status: 400, body: { outcome: "blocked",
        blockedBy: "XPath署名範囲検証: 署名対象IDと処理対象アサーションIDが不一致",
        detail: "Signature covers ID='_real_assertion_abc123' but processed ID='_fake_assertion_001'" } } },
    detail: "Strict parser detects ID mismatch between signed element and processed element.",
    detailJa: "厳密なパーサは署名済み要素と処理対象要素の ID 不一致を検出します。",
    timestamp: Date.now(),
  },
];
```

#### 期待される結果 (AttackResult)

E-2 契約: 1 リクエストで両モード (脆弱: naive パーサ — 署名対象 ID と処理対象 ID の照合なし、堅牢: strict — XPath 署名範囲厳密検証) を並列実行し、5 ステップ完全形 (probe → tamper → forge → exploit → verify) を返す。`outcome` は常に `"succeeded"` 固定、HTTP ステータスは 200 固定。`blockedBy` には堅牢側で発火した防御識別子を記録する。

| 項目 | 値 |
|------|-----|
| `outcome` | `"succeeded"` (常に) |
| HTTP ステータス | 200 (常に) |
| `blockedBy` | `"saml_xsw_signed_id_processed_id_match_enforced"` (堅牢側 step 5: 署名対象 ID と処理対象 ID の不一致を検出) |
| `steps[3].status` (脆弱側 exploit: naive パーサ) | `"success"` (XSW で attacker_charlie@demo.example のロール admin に成り代わり) |
| `steps[4].status` (堅牢側 verify: strict 検証) | `"blocked"` |

#### 防御策 (defenseRecommendation)

**既存実装ファイルへのリンク**:
- `server/routes/oidc-saml-sim.ts:274-281` — `signSAMLAssertion` の実装 (現行は HMAC 全体署名)

**防御策の要点**:

1. SAML アサーション検証時は、署名の対象 ID (`@ID` 属性が参照する要素) と
   実際に処理するアサーション要素が同一であることを確認する
2. 実装には `xml-crypto` 等の XML Digital Signature ライブラリを使用し、
   XPath による署名範囲の厳密な解決を行う
3. SAML ライブラリは最新バージョンを維持し、XSW に関するセキュリティパッチを適用する
4. SAML レスポンス全体ではなく、個別の `Assertion` 要素への署名を要求する

**codeHints の具体例**:

```typescript
// 防御: 署名対象 ID と処理対象アサーション ID の一致確認
function strictVerifySamlAssertion(samlResponse: SamlWrappedPayload): VerifyResult {
  const signed = samlResponse.SignedAssertion;
  const signedId = signed.assertion["@ID"];

  // XPath で署名が参照する要素 ID を取得し、
  // 実際に処理するアサーション要素の ID と比較する
  const processedId = samlResponse.Assertion?.["@ID"];

  if (processedId && processedId !== signedId) {
    // XSW 攻撃を検出: 署名対象と処理対象の ID が異なる
    throw new Error(
      `XSW detected: signed ID='${signedId}' !== processed ID='${processedId}'`
    );
  }

  // 署名検証は署名対象の要素 (signedId) に対してのみ行う
  const isValid = verifySignature(signed.assertion, signed.signature);
  return { valid: isValid, subject: signed.assertion.Subject.NameID["#text"] };
}
```

**参考リンク**:
- OWASP SAML Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html
- CWE-345: https://cwe.mitre.org/data/definitions/345.html
- CAPEC-475: https://capec.mitre.org/data/definitions/475.html

#### API 契約

```
POST /api/saml/attack/xsw
Content-Type: application/json

Request: {} (E-2: 両モードを並列実行するため body は空オブジェクト。
  正規ユーザー / 偽 Subject / 偽ロール / XSW ペイロード構造は全てサーバー側のシード値から生成される。
  zod スキーマ: samlAttackXswSchema = z.object({}))

Response: { data: AttackResult, _trace: ServerTrace }
  // data.outcome: "succeeded" (常に)
  // data.steps: 5 ステップ完全形 (probe → tamper → forge → exploit → verify)
  // data.blockedBy: "saml_xsw_signed_id_processed_id_match_enforced" (堅牢側 verify で発火)
  // data.extra: シナリオ固有フィールド (signedAssertionId / processedAssertionId / vulnerableProcessedSubject / fakeRole 等)
```

#### _trace 内訳

| trace 種別 | 内容 |
|-----------|------|
| `CryptoOp` | `signSAMLAssertion(legitimate)` — 正規アサーションへの署名生成 / `naiveVerify` vs `strictVerify` — 2 つの検証方式の比較結果 |
| `DbQuery` | `SELECT users WHERE username = seed_alice` — 正規ユーザーの認証 |
| `AttackStep` | intercept (正規取得) → exploit (XSW 構築) → probe (naive 送信) → blocked (strict 検証) |

#### UI フロー

```
[EducationalWarningBanner 常時固定] → シナリオセレクタ: "SAML XSW" を選択
[設定] SP モード: 素朴なパーサ(脆弱) / 厳密なパーサ(防御) ← 核心トグル
[「攻撃を実行 (最後のステップ: SP での検証結果を確認します)」ボタン]
[AttackStepTimeline]
  step-1 intercept: 正規アサーション取得 → SUCCESS
  step-2 exploit:   XSW ペイロード構築 → SUCCESS
  step-3 probe:     naive SP → SUCCESS / strict SP → BLOCKED
  step-4 verify:    XPath 検証 → BLOCKED (緑)
[XML 2層構造可視化: 外側(偽/赤) / 内側(正規/緑) を色分け]
[AttackResultBanner] naive: 脆弱メッセージ / strict: 防御メッセージ
[AttackDefensePanel 自動展開] → [DataFlowPanel: HTTP / Trace / DB]
```

---

### 4.2 `saml-assertion-replay` — SAML アサーションリプレイ

#### 概要

これは **CWE-294 / CAPEC-60** の概念実証である。
正規ユーザーが認証して取得した SAML アサーションは、有効期間内であれば
攻撃者が傍受・再送することで新しいセッションを確立できる。
`NotOnOrAfter` / `NotBefore` / `OneTimeUse` 条件が正しく検証されない実装や、
受理済みアサーション ID のキャッシュを持たない SP は
同一アサーションの再送 (リプレイ) を許してしまう。

このデモでは `OneTimeUse` チェックあり/なし、および有効期限超過アサーションの
受理/拒否を比較することで、アサーション検証要素の重要性を体感させる。

**実環境との差異の注記 (必須)**:
実環境での SAML リプレイには傍受経路 (TLS が正しく設定されていれば困難) が必要です。
このデモはサーバー側で「傍受済みアサーション」としてシミュレーションします。

#### CWE / CAPEC / OSI 層

| 項目 | 値 |
|------|-----|
| CWE | CWE-294 (Authentication Bypass by Capture-replay) |
| CAPEC | CAPEC-60 (Reusing Session IDs / Replay Attack) |
| OSI 層 | Layer 7 — Application |
| 深刻度 | High |

#### 前提条件

1. `seed_alice` の有効な SAML アサーションを傍受済み (TLS 未設定・ログ漏洩等。取得過程はデモ省略)
2. アサーションの `NotOnOrAfter` が現在時刻より未来 (有効期間内)
3. SP 側でアサーション ID の使用済みキャッシュがない

**脆弱な実装の核心** (OneTimeUse / リプレイキャッシュ不在):

```typescript
// 脆弱: 署名のみ検証、OneTimeUse / 使用済みIDキャッシュを確認しない
function vulnerableAssertionVerify(a: SamlAssertion) {
  return { ok: verifyHmac(a, SECRET), subject: a.Subject.NameID["#text"] };
}
```

#### 攻撃ステップ (AttackStep[])

```typescript
const steps: AttackStep[] = [
  {
    id: "step-1", kind: "intercept",
    label: "Capture seed_alice's SAML assertion (simulated interception)",
    labelJa: "seed_alice の SAML アサーションを傍受 (シミュレーション)",
    status: "success",
    payload: {
      type: "http",
      request: { method: "POST", url: "/api/oidc/saml/sso",
        body: { username: "seed_alice", password: "Passw0rd!", sp_entity_id: "https://sp.example.com/metadata" } },
      response: { status: 200, body: {
        assertionId: "_captured_assertion_xyz789", subject: "seed_alice@demo.example",
        notOnOrAfter: "2026-04-26T13:00:00Z", oneTimeUsePresent: false, signature: "7bde12..." } },
    },
    detail: "Attacker intercepts a valid SAML assertion during seed_alice's authentication.",
    detailJa: "攻撃者は seed_alice の認証中に有効な SAML アサーションを傍受します。",
    timestamp: Date.now(),
  },
  {
    id: "step-2", kind: "probe",
    label: "Replay assertion to SP without OneTimeUse check",
    labelJa: "OneTimeUse チェックなし SP にアサーションをリプレイ",
    status: "success",
    payload: {
      type: "http",
      request: { method: "POST", url: "/api/saml/attack/assertion-replay",
        body: { assertionId: "_captured_assertion_xyz789", mode: "no-one-time-use-check" } },
      response: { status: 200, body: {
        outcome: "succeeded", subject: "seed_alice@demo.example", newSession: "session_attacker_001",
        note: "この実装は脆弱です: 使用済みアサーション ID のキャッシュがなく、リプレイが成立しました" } },
    },
    detail: "Without replay cache, re-submitting the assertion creates a new session.",
    detailJa: "リプレイキャッシュがなければ、同一アサーションの再送で新しいセッションが作成されます。",
    timestamp: Date.now(),
  },
  {
    id: "step-3", kind: "probe",
    label: "Attempt replay with expired assertion",
    labelJa: "期限切れアサーションでのリプレイを試行",
    status: "blocked",
    payload: {
      type: "http",
      request: { method: "POST", url: "/api/saml/attack/assertion-replay",
        body: { assertionId: "_expired_assertion_old001", mode: "expired", notOnOrAfter: "2020-01-01T00:00:00Z" } },
      response: { status: 400, body: {
        outcome: "blocked", blockedBy: "NotOnOrAfter 検証: アサーションの有効期限切れ",
        notOnOrAfter: "2020-01-01T00:00:00Z", currentTime: "2026-04-26T12:00:00Z" } },
    },
    detail: "Expired assertion is rejected by NotOnOrAfter validation.",
    detailJa: "期限切れアサーションは NotOnOrAfter 検証によって拒否されます。",
    timestamp: Date.now(),
  },
  {
    id: "step-4", kind: "verify",
    label: "Replay blocked by OneTimeUse cache",
    labelJa: "OneTimeUse キャッシュがリプレイを阻止",
    status: "blocked",
    payload: {
      type: "http",
      request: { method: "POST", url: "/api/saml/attack/assertion-replay",
        body: { assertionId: "_captured_assertion_xyz789", mode: "with-one-time-use-check" } },
      response: { status: 400, body: {
        outcome: "blocked", blockedBy: "OneTimeUse キャッシュ: アサーション ID が使用済みです",
        assertionId: "_captured_assertion_xyz789", firstUsedAt: "2026-04-26T11:59:30Z" } },
    },
    detail: "OneTimeUse cache detects assertion ID already used and blocks replay.",
    detailJa: "OneTimeUse キャッシュがアサーション ID の再使用を検出し、リプレイをブロックします。",
    timestamp: Date.now(),
  },
];
```

#### 期待される結果 (AttackResult)

E-2 契約: 1 リクエストで両モード (脆弱: OneTimeUse キャッシュなし、堅牢: OneTimeUse + NotOnOrAfter 検証) を並列実行し、5 ステップ完全形を返す。`outcome` は常に `"succeeded"` 固定、HTTP ステータスは 200 固定。`blockedBy` には堅牢側で発火した防御識別子を記録する。

| 項目 | 値 |
|------|-----|
| `outcome` | `"succeeded"` (常に) |
| HTTP ステータス | 200 (常に) |
| `blockedBy` | `"saml_assertion_replay_one_time_use_cache_enforced"` (堅牢側 step 5: OneTimeUse + NotOnOrAfter で再使用拒否) |
| `steps[3].status` (脆弱側 exploit: キャッシュなし) | `"success"` (傍受アサーションのリプレイで session_attacker_001 が生成) |
| `steps[4].status` (堅牢側 verify: OneTimeUse キャッシュ + NotOnOrAfter) | `"blocked"` |

#### 防御策 (defenseRecommendation)

**既存実装ファイルへのリンク**:
- `server/routes/oidc-saml-sim.ts:251-265` — `assertion.Conditions` (NotBefore / NotOnOrAfter 設定)
- `server/db/schema.ts` — `sessions` テーブル (使用済みコードの管理パターン)

**防御策の要点**:

1. アサーション受信時に `NotOnOrAfter` / `NotBefore` を現在時刻と比較して有効期間を確認する
2. `Conditions` 要素内の `OneTimeUse` 要素が存在する場合、アサーション ID を使用済みキャッシュに記録し再使用を拒否する
3. `OneTimeUse` が存在しない場合も、アサーション ID を TTL 付きでキャッシュして再送を検知する
4. TTL はアサーションの `NotOnOrAfter` を基準に設定する

**codeHints の具体例**:

```typescript
// server/routes/attack-oidc-saml.ts での使用済みキャッシュ実装例 (概念)
const usedAssertionIds = createTtlStore<boolean>({ ttlMs: 10 * 60 * 1000 });

function strictAssertionVerify(assertion: SamlAssertion): SessionResult {
  // 1. 有効期間チェック
  const now = new Date();
  const notOnOrAfter = new Date(assertion.Conditions["@NotOnOrAfter"]);
  const notBefore = new Date(assertion.Conditions["@NotBefore"]);
  if (now > notOnOrAfter || now < notBefore) {
    throw new Error("Assertion is outside valid time window");
  }

  // 2. OneTimeUse / リプレイキャッシュチェック
  const assertionId = assertion["@ID"];
  if (usedAssertionIds.get(assertionId)) {
    throw new Error(`Replay detected: assertion ID '${assertionId}' already used`);
  }
  usedAssertionIds.set(assertionId, true);  // 使用済みとして記録

  return { authenticated: true, subject: assertion.Subject.NameID["#text"] };
}
```

```sql
-- オプション: DB ベースの永続的なリプレイキャッシュ
CREATE TABLE IF NOT EXISTS saml_used_assertions (
  assertion_id TEXT PRIMARY KEY,
  used_at      TEXT DEFAULT (datetime('now')),
  expires_at   TEXT NOT NULL
);
```

#### API 契約

```
POST /api/saml/attack/assertion-replay
Content-Type: application/json

Request: {} (E-2: 両モードを並列実行するため body は空オブジェクト。
  傍受アサーション・OneTimeUse キャッシュ・NotOnOrAfter 値は全てサーバー側のシード値から生成される。
  zod スキーマ: samlAttackAssertionReplaySchema = z.object({}))

Response: { data: AttackResult, _trace: ServerTrace }
  // data.outcome: "succeeded" (常に)
  // data.steps: 5 ステップ完全形
  // data.blockedBy: "saml_assertion_replay_one_time_use_cache_enforced" (堅牢側 verify で発火)
  // data.extra: シナリオ固有フィールド (capturedAssertionId / firstUsedAt / vulnerableSessionId / replayBlockedBy 等)
```

#### _trace 内訳

| trace 種別 | 内容 |
|-----------|------|
| `CryptoOp` | `verifyHmac(replayed_assertion)` — リプレイアサーションの署名検証 (成功) / `notOnOrAfterCheck` — 有効期間検証 |
| `SessionOp` | `createSession(replay)` — 不正なセッション生成 (攻撃成立時) / `rejectReplay` — OneTimeUse キャッシュによる拒否 (防御時) |
| `DbQuery` | `SELECT FROM saml_used_assertions WHERE assertion_id = ?` — 使用済みキャッシュ照合 |
| `AttackStep` | intercept → probe (no-check 成立) → probe (expired 拒否) → verify (OneTimeUse 拒否) |

#### UI フロー

```
[EducationalWarningBanner 常時固定] → シナリオセレクタ: "SAML アサーションリプレイ" を選択
[設定] OneTimeUse キャッシュ: 無効(脆弱) / 有効(防御) ← 核心トグル
      リプレイ種別: 有効期間内 / 期限切れ
[「攻撃を実行 (最後のステップ: 検証結果を確認します)」ボタン]
[AttackStepTimeline]
  step-1 intercept: アサーション傍受 → SUCCESS
  step-2 probe:     リプレイ送信 → SUCCESS (チェックなし) / BLOCKED (チェックあり)
  step-3 probe:     期限切れ → BLOCKED
  step-4 verify:    OneTimeUse キャッシュ → BLOCKED (緑)
[条件表示: NotOnOrAfter / NotBefore / OneTimeUse / AssertionID キャッシュ]
[AttackResultBanner] 攻撃成立/防御成立メッセージ
[AttackDefensePanel 自動展開] → [DataFlowPanel: HTTP / Trace (CryptoOp + SessionOp) / DB]
```

---

### 4.3 `oidc-id-token-spoofing` — ID Token なりすまし

#### 概要

これは **CWE-345 / CWE-1004 / CAPEC-196** の概念実証である。
OIDC の ID Token は JWT であり、発行元 (`iss`) とリライング・パーティ (`aud`) および
リプレイ防止値 (`nonce`) を含む。RP (リライング・パーティ) がこれらのクレームを
検証しない場合、攻撃者は「別の IdP (attacker.example) で自分のために発行した
ID Token」をターゲット RP に送り込み、ターゲット RP をだますことができる。

このデモでは攻撃者 IdP (`attacker.example`) が発行した ID Token を使い、
`aud` / `iss` / `nonce` 検証あり/なしの RP それぞれに送り込んで挙動差を比較する。

**実環境との差異の注記 (必須)**:
実環境では攻撃者は自分の IdP を制御できる状況が必要です。
このデモはサーバー側で「悪意ある IdP」として ID Token を発行し、
ターゲット RP への送信をシミュレーションします。

#### CWE / CAPEC / OSI 層

| 項目 | 値 |
|------|-----|
| CWE | CWE-345 (Insufficient Verification of Data Authenticity), CWE-1004 (Sensitive Credentials Insufficiently Protected) |
| CAPEC | CAPEC-196 (Session Credential Falsification through Forging) |
| OSI 層 | Layer 7 — Application |
| 深刻度 | Critical |

#### 前提条件

1. 攻撃者は自分の OIDC IdP (`attacker.example`) を制御し、任意クレームを持つ ID Token を発行できる
2. ターゲット RP が `aud` / `iss` / `nonce` を検証せず `sub` クレームをそのまま信用する
3. 攻撃者は `seed_alice` の `sub` (`"1"`) または名前クレームを知っている

**攻撃者 IdP が発行する偽 ID Token ペイロード**:

```json
{ "iss": "https://attacker.example/oidc", "sub": "1", "aud": "victim-rp-client",
  "exp": 9999999999, "nonce": "attacker_nonce", "name": "seed_alice", "role": "admin" }
```

**脆弱な RP 実装の核心** (iss/aud/nonce 検証なし):

```typescript
// 脆弱: jwt.decode のみ (署名検証・iss/aud/nonce チェックなし)
const payload = jwt.decode(idToken);  // attacker.example 発行トークンが通る
return { userId: payload.sub, role: payload.role };
```

#### 攻撃ステップ (AttackStep[])

```typescript
const steps: AttackStep[] = [
  {
    id: "step-1", kind: "exploit",
    label: "Attacker IdP issues spoofed ID Token targeting seed_alice's identity",
    labelJa: "攻撃者 IdP が seed_alice の身元を偽る ID Token を発行",
    status: "success",
    payload: {
      type: "http",
      request: { method: "POST", url: "/api/oidc/attack/id-token-spoof",
        body: { action: "issue-from-attacker-idp", targetSub: "1", targetName: "seed_alice" } },
      response: { status: 200, body: {
        spoofedToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...(attacker.example発行)",
        decoded: { header: { alg: "HS256" },
          payload: { iss: "https://attacker.example/oidc", sub: "1",
                     aud: "victim-rp-client", name: "seed_alice", role: "admin" } } } },
    },
    detail: "Attacker's own IdP issues a token claiming to be seed_alice with admin role.",
    detailJa: "攻撃者自身の IdP が seed_alice かつ admin ロールを主張する ID Token を発行します。",
    timestamp: Date.now(),
  },
  {
    id: "step-2", kind: "probe",
    label: "Submit spoofed token to RP without iss/aud/nonce validation",
    labelJa: "iss/aud/nonce 検証なし RP に偽トークンを送信",
    status: "success",
    payload: {
      type: "http",
      request: { method: "POST", url: "/api/oidc/attack/id-token-spoof",
        body: { action: "submit-to-vulnerable-rp", mode: "no-claims-check" } },
      response: { status: 200, body: { outcome: "succeeded", authenticatedAs: "seed_alice", role: "admin",
        note: "この実装は脆弱です: iss/aud/nonce を検証せず攻撃者の ID Token を受理しました" } },
    },
    detail: "Vulnerable RP accepts the attacker's ID Token, authenticating as seed_alice/admin.",
    detailJa: "脆弱な RP は攻撃者の ID Token を受理し、seed_alice/admin として認証します。",
    timestamp: Date.now(),
  },
  {
    id: "step-3", kind: "verify",
    label: "iss validation: reject token from attacker.example",
    labelJa: "iss 検証: attacker.example 発行のトークンを拒否",
    status: "blocked",
    payload: {
      type: "http",
      request: { method: "POST", url: "/api/oidc/attack/id-token-spoof",
        body: { action: "submit-to-strict-rp", mode: "iss-check" } },
      response: { status: 401, body: { outcome: "blocked",
        blockedBy: "iss 検証: 期待値=http://localhost:3001/api/oidc, 受信値=https://attacker.example/oidc" } },
    },
    detail: "iss validation rejects token from unknown issuer.",
    detailJa: "iss 検証が未知の発行元からのトークンを拒否します。",
    timestamp: Date.now(),
  },
  {
    id: "step-4", kind: "verify",
    label: "aud/nonce validation: reject token with wrong audience or nonce",
    labelJa: "aud/nonce 検証: 誤った受信者またはノンスのトークンを拒否",
    status: "blocked",
    payload: {
      type: "http",
      request: { method: "POST", url: "/api/oidc/attack/id-token-spoof",
        body: { action: "submit-to-strict-rp", mode: "aud-nonce-check" } },
      response: { status: 401, body: { outcome: "blocked",
        blockedBy: "aud 検証: 期待値=demo-oidc-app, 受信値=victim-rp-client / nonce 不一致" } },
    },
    detail: "aud and nonce validation rejects token issued for a different RP.",
    detailJa: "aud と nonce の検証が別の RP 向けトークンを拒否します。",
    timestamp: Date.now(),
  },
];
```

#### 期待される結果 (AttackResult)

E-2 契約: 1 リクエストで両モード (脆弱: iss/aud/nonce 検証なし RP、堅牢: OpenID Connect Core §3.1.3.7 準拠の strict RP) を並列実行し、5 ステップ完全形を返す。`outcome` は常に `"succeeded"` 固定、HTTP ステータスは 200 固定。`blockedBy` には堅牢側で発火した防御識別子を記録する。

| 項目 | 値 |
|------|-----|
| `outcome` | `"succeeded"` (常に) |
| HTTP ステータス | 200 (常に) |
| `blockedBy` | `"oidc_id_token_iss_aud_nonce_validation_enforced"` (堅牢側 step 5: iss / aud / nonce のいずれかの検証で攻撃者 IdP 発行トークンを拒否) |
| `steps[3].status` (脆弱側 exploit: 検証なし RP) | `"success"` (攻撃者 IdP 発行 ID Token で seed_alice / role: admin になりすまし) |
| `steps[4].status` (堅牢側 verify: iss/aud/nonce 検証 RP) | `"blocked"` |

#### 防御策 (defenseRecommendation)

**既存実装ファイルへのリンク**:
- `server/routes/oidc-saml-sim.ts:144-158` — ID Token 生成 (`iss`, `aud`, `nonce` クレームの設定)
- `server/routes/oidc-saml-sim.ts:194-217` — `jwt.verify` による UserInfo のトークン検証

**防御策の要点**:

1. `iss` (Issuer): RP は事前に登録した IdP の `iss` 値のみを受理する。他の `iss` は拒否
2. `aud` (Audience): ID Token の `aud` が自身の `client_id` と一致することを確認する
3. `nonce`: 認可リクエスト時に生成した `nonce` と ID Token の `nonce` クレームが一致することを確認する
4. `exp` (Expiration): ID Token の有効期限が現在時刻より未来であることを確認する

**codeHints の具体例**:

```typescript
// 正しい ID Token 検証 (OpenID Connect Core 1.0 Section 3.1.3.7 準拠)
function strictVerifyIdToken(
  idToken: string,
  expectedIss: string,   // 登録済み IdP の issuer URL
  expectedAud: string,   // 自身の client_id
  expectedNonce: string  // 認可リクエスト時に生成した nonce
): IdTokenClaims {
  // jwt.verify は署名検証 + exp チェックを自動実行
  const payload = jwt.verify(idToken, OIDC_PUBLIC_KEY, {
    algorithms: ["RS256"],  // 鍵アルゴリズムを明示 (alg=none バイパス防止)
    issuer: expectedIss,    // iss 検証
    audience: expectedAud,  // aud 検証
  }) as IdTokenClaims;

  // nonce 検証 (jwt.verify は nonce を自動検証しないため手動で確認)
  if (payload.nonce !== expectedNonce) {
    throw new Error(`nonce mismatch: expected '${expectedNonce}', got '${payload.nonce}'`);
  }

  return payload;
}
```

**RFC 参考**:
- OpenID Connect Core 1.0 §3.1.3.7 — ID Token Validation:
  https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation

#### API 契約

```
POST /api/oidc/attack/id-token-spoof
Content-Type: application/json

Request: {} (E-2: 両モードを並列実行するため body は空オブジェクト。
  攻撃者 IdP / 偽 sub / 偽 name / iss/aud/nonce クレームは全てサーバー側のシード値から生成される。
  zod スキーマ: oidcAttackIdTokenSpoofSchema = z.object({}))

Response: { data: AttackResult, _trace: ServerTrace }
  // data.outcome: "succeeded" (常に)
  // data.steps: 5 ステップ完全形
  // data.blockedBy: "oidc_id_token_iss_aud_nonce_validation_enforced" (堅牢側 verify で発火)
  // data.extra: シナリオ固有フィールド (attackerIssuer / forgedSub / vulnerableRpAuthAs / strictRpRejectionReason 等)
```

#### _trace 内訳

| trace 種別 | 内容 |
|-----------|------|
| `CryptoOp` | `jwt.sign(attacker_idp)` — 攻撃者 IdP による偽 ID Token 署名 / `jwt.decode(no-verify)` vs `jwt.verify(strict)` — 検証なし/厳密検証の比較 |
| `SessionOp` | なりすまし認証成功時のセッション生成 (攻撃成立時) |
| `DbQuery` | なし (攻撃 IdP はインメモリシミュレーション) |
| `AttackStep` | exploit (攻撃者 IdP 発行) → probe (脆弱 RP 送信) → verify (iss チェック) → verify (aud/nonce チェック) |

#### UI フロー

```
[EducationalWarningBanner 常時固定] → シナリオセレクタ: "ID Token なりすまし" を選択
[設定] RP 検証レベル: [ ] iss 検証  [ ] aud 検証  [ ] nonce 検証 (個別 ON/OFF)
      すべて OFF = 脆弱な RP / すべて ON = 安全な RP
[「攻撃を実行 (最後のステップ: 検証結果を確認します)」ボタン]
[AttackStepTimeline]
  step-1 exploit: 攻撃者 IdP が偽トークンを発行 → SUCCESS
  step-2 probe:   脆弱 RP へ送信 → SUCCESS / BLOCKED
  step-3 verify:  iss チェック → BLOCKED (ON 時)
  step-4 verify:  aud/nonce チェック → BLOCKED (ON 時)
[クレーム比較表: 正規 IdP vs attacker.example — iss/aud/nonce を赤ハイライト]
[AttackResultBanner] 攻撃成立/防御成立メッセージ
[AttackDefensePanel 自動展開: OIDC Core §3.1.3.7 チェックリスト + codeHints]
[DataFlowPanel: HTTP / Trace (CryptoOp 比較) / DB]
```

---

## 5. UI コンポーネント設計

### 5.1 ディレクトリ構成

```
src/components/auth/attacks/oidc-saml/
├── OidcSamlAttackPanel.tsx       ← 3シナリオを統括するメインパネル
├── SamlXswScenario.tsx           ← シナリオ A: XSW 攻撃 + 2層構造可視化
├── SamlReplayScenario.tsx        ← シナリオ B: アサーションリプレイ + 条件チェック表示
├── OidcSpoofScenario.tsx         ← シナリオ C: ID Token なりすまし + クレーム比較表
└── OidcSamlAttack.css            ← 3シナリオ共通スタイル (XSW 2層構造の色分けを含む)
```

### 5.2 `OidcSamlAttackPanel.tsx` の責務

```typescript
// OidcSamlFlow.tsx への組み込みイメージ
import OidcSamlAttackPanel from "./attacks/oidc-saml/OidcSamlAttackPanel";
import { Show } from "solid-js";

// ViewModeToggle の viewMode Signal
<Show when={viewMode() === "attacker"}>
  <OidcSamlAttackPanel tabId="oidc-saml" />
</Show>
```

`OidcSamlAttackPanel` は以下を担当する:

1. `EducationalWarningBanner` の常時表示 (dismissable 禁止)
2. `AttackScenarioSelector` で 3 シナリオの切り替え
3. 選択中シナリオに対応する `SamlXswScenario` / `SamlReplayScenario` / `OidcSpoofScenario` のレンダリング
4. `DataFlowPanel scopeId="attack-oidc-saml"` の表示
5. 各シナリオの攻撃完了後に `AttackDefensePanel` を自動展開

### 5.3 各シナリオコンポーネントの props 設計

全コンポーネント共通インターフェース:

```typescript
interface AttackScenarioProps {
  onResult: (result: AttackResult) => void;
  onRunning: (running: boolean) => void;
}
// SamlXswScenarioProps / SamlReplayScenarioProps / OidcSpoofScenarioProps はすべて上記と同一
```

### 5.4 特殊 UI 要素

**SamlXswScenario.tsx — 2 層構造可視化**: 外側ラッパー (赤枠: 署名対象外 / 偽 Subject・admin ロール) の中に内側
(緑枠: 署名済み / 正規 seed_alice・user ロール + Signature: 4a8f3c...) を入れ子表示する。
素朴なパーサが「外側」を処理することを視覚的に示す。

**OidcSpoofScenario.tsx — クレーム比較表**: 正規 IdP vs 攻撃者 IdP の主要クレームを
横並び表示。`iss` / `aud` / `nonce` が不一致の行を赤ハイライト、`sub` / `name` が一致する行を黄ハイライト。

---

## 6. テスト要件

### 6.1 ユニットテスト (バックエンドハンドラ単体)

対象ファイル: `server/routes/attack-oidc-saml.ts`

E-2 契約に準拠したテスト構成。各シナリオは 1 リクエストで両モード並列実行のため、`outcome === "succeeded"` 固定 + 5 ステップ完全形 + `blockedBy` で防御識別子を検証する。実装は `server/__tests__/oidc-saml-attack.test.ts`。

| テストカテゴリ | 対象 | 期待値 |
|------------|-----|--------|
| E-2 不変条件 (it.each で 3 シナリオ共通) | `saml-xsw` / `saml-assertion-replay` / `oidc-id-token-spoof` | `status === 200` / `outcome === "succeeded"` / `steps.length === 5` / `_trace.attackSteps.length === 5` / `_trace.isAttackMode === true` |
| logId 一意性 | 全 3 シナリオを連続実行 | `attack_log` テーブルに 3 件の独立 logId を確認 |
| 本番ガード | `NODE_ENV=production` で全 3 ルート | `status === 403` |
| summaryJa prefix | 全 3 シナリオ | 「この実装は」または「このシナリオでは」で始まる |
| シナリオ A: blockedBy | `saml-xsw` | `"saml_xsw_signed_id_processed_id_match_enforced"` |
| シナリオ A: extra フィールド | `saml-xsw` | `extra.signedAssertionId` / `extra.processedAssertionId` (脆弱側で異なる ID) / `extra.vulnerableProcessedSubject` を含む |
| シナリオ B: blockedBy | `saml-assertion-replay` | `"saml_assertion_replay_one_time_use_cache_enforced"` |
| シナリオ B: extra フィールド | `saml-assertion-replay` | `extra.capturedAssertionId` / `extra.firstUsedAt` / `extra.vulnerableSessionId` を含む |
| シナリオ C: blockedBy | `oidc-id-token-spoof` | `"oidc_id_token_iss_aud_nonce_validation_enforced"` |
| シナリオ C: extra フィールド | `oidc-id-token-spoof` | `extra.attackerIssuer` (`"https://attacker.example/oidc"`) / `extra.forgedSub` / `extra.vulnerableRpAuthAs === "seed_alice"` / `extra.strictRpRejectionReason` を含む |

### 6.2 E2E テスト (UI フロー)

対象: `src/components/auth/attacks/oidc-saml/OidcSamlAttackPanel.tsx`

| テスト ID | 操作 | 期待結果 |
|---------|------|---------|
| `e2e-oidcsaml-01` | OidcSaml タブで Attacker View に切り替える | `EducationalWarningBanner` が最上部に固定表示される |
| `e2e-oidcsaml-02` | シナリオ A (XSW) を選択して SP モード "naive" で実行 | step-3 が SUCCESS (オレンジ)、2層構造が可視化される |
| `e2e-oidcsaml-03` | シナリオ A で SP モード "strict" に変更して実行 | step-3 が BLOCKED (緑)、`AttackResultBanner` が緑表示 |
| `e2e-oidcsaml-04` | シナリオ B (リプレイ) で OneTimeUse チェック OFF で実行 | `AttackResultBanner` がオレンジ (攻撃成立) で表示される |
| `e2e-oidcsaml-05` | シナリオ B で OneTimeUse チェック ON に変更して実行 | `AttackResultBanner` が緑 (防御成立) で表示される |
| `e2e-oidcsaml-06` | シナリオ C (ID Token なりすまし) でクレーム検証すべて OFF で実行 | クレーム比較表が表示され、`authenticatedAs: seed_alice / admin` が確認できる |
| `e2e-oidcsaml-07` | シナリオ C で iss 検証のみ ON にして実行 | step-3 が BLOCKED、"iss 検証が attacker.example を拒否" と表示 |
| `e2e-oidcsaml-08` | 各シナリオの攻撃完了後 | `AttackDefensePanel` が自動展開されている |
| `e2e-oidcsaml-09` | Defender View に切り替える | 通常の `OidcSamlFlow` デモが表示され、赤バナーが消える |

---

## 7. i18n キー一覧表

| # | キー概念 | 日本語 | English |
|---|---------|--------|---------|
| 1 | 攻撃者モード切替 | `攻撃者モード` | `Attacker Mode` |
| 2 | 防御者モード切替 | `防御者モード` | `Defender Mode` |
| 3 | 教育バナーテキスト | `教育用シミュレーション — 実環境を攻撃するためのコードではありません` | `Educational simulation — not for use against real systems` |
| 4 | シナリオ A 名 | `SAML XSW (XML署名ラッピング)` | `SAML XML Signature Wrapping (XSW)` |
| 5 | シナリオ B 名 | `SAML アサーションリプレイ` | `SAML Assertion Replay` |
| 6 | シナリオ C 名 | `ID Token なりすまし (aud/iss 検証省略)` | `ID Token Spoofing (Missing aud/iss Validation)` |
| 7 | 攻撃実行ボタン | `攻撃を実行` | `Run Attack` |
| 8 | 最終ステップボタン | `最後のステップです。攻撃成立結果を確認します` | `Final step. Confirm attack outcome.` |
| 9 | 実行中ラベル | `実行中...` | `Running...` |
| 10 | 攻撃成立バナー | `攻撃成立 — この実装は脆弱です` | `Attack succeeded — this implementation is vulnerable` |
| 11 | 防御成立バナー | `防御が機能しました:` | `Defense succeeded:` |
| 12 | SP モードラベル | `SP 検証モード` | `SP Validation Mode` |
| 13 | 素朴なパーサラベル | `素朴なパーサ (XPath 署名範囲検証なし)` | `Naive parser (no XPath scope check)` |
| 14 | 厳密なパーサラベル | `厳密なパーサ (XPath 署名範囲検証あり)` | `Strict parser (with XPath scope check)` |
| 15 | OneTimeUse ラベル | `OneTimeUse キャッシュ` | `OneTimeUse Cache` |
| 16 | OneTimeUse OFF ラベル | `無効 (脆弱な実装)` | `Disabled (Vulnerable)` |
| 17 | OneTimeUse ON ラベル | `有効 (防御済み)` | `Enabled (Protected)` |
| 18 | リプレイ種別ラベル | `リプレイアサーション種別` | `Replay Assertion Type` |
| 19 | 有効期間内ラベル | `有効期間内` | `Valid (within time window)` |
| 20 | 期限切れラベル | `有効期限切れ` | `Expired` |
| 21 | RP 検証レベルラベル | `RP クレーム検証` | `RP Claims Validation` |
| 22 | iss チェックラベル | `iss (発行元) を検証` | `Validate iss (Issuer)` |
| 23 | aud チェックラベル | `aud (受信者) を検証` | `Validate aud (Audience)` |
| 24 | nonce チェックラベル | `nonce (リプレイ防止) を検証` | `Validate nonce (Replay Prevention)` |
| 25 | 偽発行元ラベル | `攻撃者 IdP (attacker.example)` | `Attacker IdP (attacker.example)` |
| 26 | 正規発行元ラベル | `正規 IdP (localhost:3001)` | `Legitimate IdP (localhost:3001)` |
| 27 | XSW 構造ラベル (外側) | `外側 (偽アサーション — 署名対象外)` | `Outer (fake assertion — not signed)` |
| 28 | XSW 構造ラベル (内側) | `内側 (正規アサーション — 署名対象)` | `Inner (legitimate assertion — signed)` |
| 29 | 署名範囲説明 | `署名は内側 ID を参照。素朴なパーサは外側を処理する` | `Signature covers inner ID. Naive parser processes outer element.` |
| 30 | XSW 攻撃成立メッセージ | `この実装は脆弱です: XSW が成立し、偽の管理者アサーションが受理されました` | `This implementation is vulnerable: XSW succeeded, fake admin assertion was accepted` |
| 31 | XSW 防御成立メッセージ | `防御が機能しました: XPath署名範囲検証が署名対象IDと処理対象IDの不一致を検出しました` | `Defense succeeded: XPath scope check detected mismatch between signed and processed assertion IDs` |
| 32 | リプレイ攻撃成立メッセージ | `この実装は脆弱です: OneTimeUse チェックがなく、アサーションのリプレイが成立しました` | `This implementation is vulnerable: without OneTimeUse check, assertion replay succeeded` |
| 33 | リプレイ防御成立メッセージ | `防御が機能しました: OneTimeUse キャッシュがアサーション ID の再使用を検出しました` | `Defense succeeded: OneTimeUse cache detected assertion ID reuse` |
| 34 | ID Token 攻撃成立メッセージ | `この実装は脆弱です: iss/aud/nonce を検証せず攻撃者の ID Token を受理しました` | `This implementation is vulnerable: attacker's ID Token was accepted without iss/aud/nonce validation` |
| 35 | ID Token iss 防御メッセージ | `防御が機能しました: iss 検証が attacker.example 発行のトークンを拒否しました` | `Defense succeeded: iss validation rejected token from attacker.example` |
| 36 | ID Token aud 防御メッセージ | `防御が機能しました: aud 検証がトークンの受信者不一致を検出しました` | `Defense succeeded: aud validation detected audience mismatch` |
| 37 | クレーム比較ラベル | `クレーム比較: 正規 IdP vs 攻撃者 IdP` | `Claims Comparison: Legitimate IdP vs Attacker IdP` |
| 38 | XSW 実環境注記 | `注: 実際の XSW は XML XPath と名前空間の深い知識を要します。このデモは概念を簡略表示します` | `Note: Real XSW requires deep XML XPath and namespace knowledge. This demo shows a simplified concept.` |
| 39 | リプレイ実環境注記 | `注: 実環境では TLS が正しく設定されていれば傍受は困難です` | `Note: In real environments, proper TLS makes interception difficult` |
| 40 | タイムライン ARIA ラベル | `攻撃ステップログ` | `Attack step log` |

---

## 8. 関連ファイル

### 8.1 基盤設計書

| ファイル | 参照目的 |
|---------|---------|
| [DESIGN/00-overview.md](./00-overview.md) | 全体目的・カタログマトリクス (Row 19-21: oidc-saml タブ) |
| [DESIGN/01-architecture.md](./01-architecture.md) | バックエンドルート配置方針 / フロントエンドコンポーネント階層 |
| [DESIGN/02-ui-spec.md](./02-ui-spec.md) | `ViewModeToggle` / `AttackStepTimeline` / `AttackResultBanner` / `AttackDefensePanel` の詳細仕様 |
| [DESIGN/03-data-model.md](./03-data-model.md) | `AttackStep` / `AttackResult` / `AttackScenarioMeta` / `ServerTrace` 拡張の型定義 |
| [DESIGN/04-safety-guardrails.md](./04-safety-guardrails.md) | 禁止表現一覧 / ペイロード作成ルール / 開発レビューチェックリスト |

### 8.2 既存実装ファイル (変更・参照対象)

| ファイルパス | 変更種別 | 変更内容 |
|------------|---------|---------|
| `server/routes/oidc-saml-sim.ts` | 参照のみ | OIDC PKCE / SAML SSO の正常系実装。攻撃デモは別ファイルに隔離 |
| `src/components/auth/OidcSamlFlow.tsx` | 追加 | `ViewModeToggle` import + `<Show when={viewMode() === "attacker"}>` ブロックで `OidcSamlAttackPanel` を条件表示 |
| `shared/api-types.ts` | 追加 | `AttackStep`, `AttackResult`, `AttackScenarioMeta` (DESIGN/03 参照) |
| `server/db/schema.ts` | 追加 (オプション) | `saml_used_assertions` テーブル (アサーション ID 使用済みキャッシュ、TTL 付き) |

### 8.3 新規作成ファイル

| ファイルパス | 役割 |
|------------|------|
| `server/routes/attack-oidc-saml.ts` | 3 攻撃エンドポイント (`/api/saml/attack/xsw`, `/api/saml/attack/assertion-replay`, `/api/oidc/attack/id-token-spoof`) を実装 |
| `src/components/auth/attacks/oidc-saml/OidcSamlAttackPanel.tsx` | 3 シナリオを統括するメインパネル |
| `src/components/auth/attacks/oidc-saml/SamlXswScenario.tsx` | シナリオ A: XSW 攻撃 + 2 層構造可視化コンポーネント |
| `src/components/auth/attacks/oidc-saml/SamlReplayScenario.tsx` | シナリオ B: アサーションリプレイ + 条件チェック切替コンポーネント |
| `src/components/auth/attacks/oidc-saml/OidcSpoofScenario.tsx` | シナリオ C: ID Token なりすまし + クレーム比較表コンポーネント |
| `src/components/auth/attacks/oidc-saml/OidcSamlAttack.css` | 3 シナリオ共通スタイル (XSW 2 層構造の赤/緑色分けを含む) |
| `src/components/auth/attacks/scenarios/oidc-saml-scenarios.ts` | `AttackScenarioMeta[]` の静的定義 (3 シナリオ分) |

---

*このドキュメントは `DESIGN/16-attack-oidc-saml.md` に配置。
実装を開始する前に DESIGN/00 〜 04 の基盤設計書を読了し、
特に DESIGN/04-safety-guardrails.md §4 のレビューチェックリストを確認すること。*
