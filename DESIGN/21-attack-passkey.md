---
title: 攻撃デモカタログ — Passkey 攻撃詳細
phase: design
tab-id: passkey
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

# 21. Passkey — 攻撃デモカタログ設計

---

## 1. 概要

### 1.1 FIDO2/WebAuthn との関係

Passkey は FIDO2/WebAuthn をベースとした認証方式であり、`DESIGN/15-attack-fido2.md` で扱った
origin バインディング・チャレンジの一回性といった防御機構をそのまま継承する。

本タブの攻撃デモが **FIDO2 タブと共有する防御原理**:

| 防御原理 | 詳細 |
|---------|------|
| origin バインディング | `clientDataJSON.origin` が `expectedOrigin` と厳密一致しない場合に拒否 |
| rpId 検証 | `authenticatorData.rpIdHash` が `SHA-256(expectedRPID)` と一致しない場合に拒否 |
| チャレンジの使い捨て | `challenges.delete(sessionId)` により同一チャレンジの再利用を阻止 |
| カウンターによるクローン検出 | `newCounter <= oldCounter` で認証器のクローンを検出 |

ただし Passkey は **同期パスキー** という概念を持つ点で FIDO2 の物理認証器 (YubiKey 等) と
攻撃面が大きく異なる。この設計書では FIDO2 タブとの重複を最小化し、
Passkey 固有の論点を中心に扱う。

### 1.2 同期パスキー固有の攻撃面

`server/routes/passkey.ts` の登録検証処理は以下の2種類のクレデンシャルを区別している:

```typescript
// passkey.ts: 登録検証後のデバイスタイプ判定
const deviceType = verification.registrationInfo?.credentialDeviceType || "unknown";
const backedUp  = verification.registrationInfo?.credentialBackedUp    || false;
// deviceType === "multiDevice" → iCloud Keychain / Google Password Manager 等で同期可能
// deviceType === "singleDevice" → YubiKey 等、このデバイスにのみ存在
```

この判定が教材上の重要な分岐点となる。

| クレデンシャル種別 | 利便性 | 攻撃面 |
|-----------------|--------|-------|
| **singleDevice** (デバイス固有) | デバイスが手元にある必要がある | 物理デバイス窃取が前提 — 高いハードル |
| **multiDevice** (同期パスキー) | iCloud/Google/1Password 等でデバイス間共有 | **クラウドアカウントが侵害されると複製される** |

同期パスキーは「利便性とセキュリティのトレードオフ」の典型例であり、
クラウドアカウント保護の重要性を体感させる教材として適している。

### 1.3 Cross-device Authentication (ハイブリッドフロー) の概要

ハイブリッドフローは「PC ブラウザで QR コードを表示し、スマートフォンのパスキーで認証する」
フローである。実装上の接続は以下の 2 段階で保護される:

1. **BLE 近接要件**: PC と スマートフォンが Bluetooth Low Energy 圏内にある必要がある
2. **Tunnel Key 暗号化**: CTAP2.2 のトンネルプロトコルで end-to-end 暗号化された通信路が確立される

攻撃者が QR コードを物理的・デジタル的に傍受しても、BLE 近接チェックと
tunnel key の暗号化により MITM が阻止される概念を本タブで示す。

### 1.4 このタブの教材的位置付け

本タブのすべての攻撃シナリオは **攻撃が失敗することを示す** か、
**防御に必要な前提条件 (クラウドアカウント保護) を理解させる** ことが目的である。

| 深刻度の解釈 |
|------------|
| 本カタログの深刻度は「**この防御がなかった場合の被害の大きさ**」を示す。実際には防御が機能している (または防御の前提条件を強調する) ため、学習者に提示する体験は「攻撃阻止の確認」となる。 |

`AttackResult.outcome` は全シナリオで `"blocked"` が期待値となる。
`AttackResultBanner` は赤ではなく **緑系 (`var(--color-success)`)** で表示し、
「プロトコル設計または防御実装により阻止されました」を強調する (04-safety-guardrails.md §9.1 準拠)。

---

## 2. 攻撃シナリオ一覧

| # | シナリオ ID | 攻撃名 | CWE | CAPEC | OSI 層 | 深刻度 | 期待 outcome |
|---|------------|--------|-----|-------|--------|--------|-------------|
| A | `passkey-phishing-origin-binding` | フィッシング耐性デモ (origin binding) | CWE-290, CWE-346 | CAPEC-89, CAPEC-194 | 7 | critical (防御なし想定) | `blocked` |
| B | `passkey-cloud-sync-compromise` | クラウド同期経路の侵害 (シミュレーション) | CWE-287 | CAPEC-560 | 7 | high | `blocked` |
| C | `passkey-cross-device-mitm` | Cross-device 経路の中間者 (シミュレーション) | CWE-300 | CAPEC-94 | 5 / 7 | high (防御なし想定) | `blocked` |

### 2.1 深刻度の解釈

| シナリオ | 深刻度の根拠 |
|---------|------------|
| A | origin 検証がない仮想の実装では認証バイパスが直接可能 → `critical`。実際の実装では防御が機能 → `Info` 相当の体験 |
| B | クラウドアカウントの乗っ取りは同期パスキーの全クローンへのアクセスを与える可能性がある → `high`。クラウドアカウント保護 (強パスワード + MFA) の重要性を示す |
| C | BLE 近接保護と tunnel key がなければ QR 中継 MITM が成立しうる → `high`。プロトコル設計による防御を可視化 |

---

## 3. 既存防御側実装

### 3.1 `server/routes/passkey.ts` の構成

`passkeyRoutes` は Hono インスタンスに登録された 5 エンドポイントで構成される。

```
POST /api/passkey/register/options   — 登録チャレンジ発行 (residentKey: "required")
POST /api/passkey/register/verify    — 登録レスポンス検証 (origin/rpId/challenge を検証)
POST /api/passkey/auth/options       — 認証チャレンジ発行 (allowCredentials: [] — ユーザー名なし)
POST /api/passkey/auth/verify        — 認証レスポンス検証 + カウンター確認
GET  /api/passkey/credentials        — 登録済みクレデンシャル一覧
```

### 3.2 origin / rpId 検証 (シナリオ A の防御ポイント)

```typescript
// server/routes/passkey.ts (既存実装 — 変更不要)
const RP_ID  = "localhost";
const ORIGIN = "http://localhost:3000";

// 登録検証
const verification = await verifyRegistrationResponse({
  response:          attResponse as any,
  expectedChallenge,
  expectedOrigin:    ORIGIN,   // ← この検証がフィッシングを阻止する
  expectedRPID:      RP_ID,    // ← この検証がオリジン偽装を阻止する
});

// 認証検証
const verification = await verifyAuthenticationResponse({
  response:          authResponse as any,
  expectedChallenge,
  expectedOrigin:    ORIGIN,   // ← 同様の検証
  expectedRPID:      RP_ID,    // ← 同様の検証
  credential: { ... },
});
```

### 3.3 チャレンジの使い捨て管理 (分離ストア構成)

`passkey.ts` は FIDO2 (`webauthn.ts`) とは独立した 2 つのチャレンジストアを持つ。

```typescript
// server/routes/passkey.ts (既存実装 — 変更不要)
// 登録: ユーザー名をキーに管理 (FIDO2 と同様)
const registerChallenges = createTtlStore<string>({ ttlMs: 5 * 60 * 1000 });
// 認証: sessionId (uuid) をキーに管理 — ユーザー名なし認証対応
const authChallenges     = createTtlStore<string>({ ttlMs: 5 * 60 * 1000 });

// 検証成功後は即座に削除 (one-time)
registerChallenges.delete(username);   // 登録完了時
authChallenges.delete(sessionId);      // 認証完了時 (失敗時も削除)
```

### 3.4 デバイスタイプ判定 (シナリオ B の教育ポイント)

登録検証後に `credentialDeviceType` と `credentialBackedUp` フラグを取得し、
同期パスキーかデバイス固有かを判定する。

```typescript
// server/routes/passkey.ts (既存実装)
const deviceType = verification.registrationInfo?.credentialDeviceType || "unknown";
const backedUp   = verification.registrationInfo?.credentialBackedUp    || false;

// DeviceType 判定の根拠
// "multiDevice": WebAuthn Level 2 フラグ BE (Backup Eligible) = 1, BS (Backup State) = 1
//   → クラウドアカウント (iCloud/Google) を通じて別デバイスに複製可能
// "singleDevice": BE = 0, BS = 0
//   → このデバイスの認証器にのみ存在。クラウド複製は発生しない
```

### 3.5 カウンターによるクローン検出 (補足)

```typescript
// server/routes/passkey.ts (既存実装)
if (newCounter > 0 && newCounter <= cred.counter) {
  return c.json({ success: false, error: "Counter did not increment — possible clone" }, 403);
}
```

### 3.6 PasskeyFlow.tsx の構成

`src/components/auth/PasskeyFlow.tsx` は以下の2コンポーネントで構成される:

- **`PasskeyDemo`**: 実際の WebAuthn API (`startRegistration`, `startAuthentication`) を呼び出す Live デモ。Conditional UI (ブラウザオートフィル) にも対応。
- **`PasskeyFlow`** (デフォルトエクスポート): 登録フロー/認証フローのステップビジュアライザ + Key Concepts パネル。

Attacker View は `PasskeyFlow` のルートに `ViewModeToggle` を追加し、
`PasskeyAttackPanel` を `<Show>` で条件表示する形で統合する (FIDO2 タブと同パターン)。

---

## 4. シナリオ詳細

---

### 4.1 シナリオ A: フィッシング耐性デモ (origin binding)

**シナリオ ID**: `passkey-phishing-origin-binding`

#### 4.1.1 教育的シナリオの前提

これは **CWE-290 (Authentication Bypass by Spoofing)** / **CWE-346 (Origin Validation Error)** /
**CAPEC-89** / **CAPEC-194** の概念実証である。

`DESIGN/15-attack-fido2.md` のシナリオ A (`fido2-phishing-origin-rejection`) と
同一の根本原理 (origin バインディング) を、Passkey 文脈で再演する。
重複を避けるため、本シナリオは FIDO2 との違いを明示しつつ、
**同期パスキーがフィッシングに対して追加の保護を提供しない** (origin 検証は同じ) 点を強調する。

**Passkey 文脈での追加論点:**

- 同期パスキーはクラウドアカウントを通じて複数デバイスに複製されているが、
  クレデンシャルの origin バインディング自体はデバイス間で変わらない。
  攻撃者がフィッシングページに誘導しても、どのデバイスの Passkey を使おうとも、
  `clientDataJSON.origin` は攻撃者ドメインになるため拒否される。
- Passkey の「ユーザー名なし認証」(`allowCredentials: []`) でも、
  チャレンジと origin の検証は同様に機能する。

**教材ポイント:** 「Passkey を複数デバイスで同期していても、フィッシング耐性は失われない」

#### 4.1.2 攻撃ステップ設計

| ステップ | `kind` | `status` | 説明 |
|---------|--------|----------|------|
| S1 | `forge` | `success` | 攻撃者フィッシングページが Passkey 認証を要求 (origin: `attacker.example`) |
| S2 | `probe` | `success` | 正規サーバーからチャレンジを中継取得 (sessionId を入手) |
| S3 | `tamper` | `success` | ブラウザが `attacker.example` origin で `clientDataJSON` に署名 |
| S4 | `verify` | `blocked` | `verifyAuthenticationResponse` が `expectedOrigin` 不一致で拒否 → `400` |

#### 4.1.3 API 設計

```
POST /api/passkey/attack/phishing-origin-binding
Content-Type: application/json

Request: {} (E-2: 両モードを並列実行するため body は空オブジェクト。
  攻撃者オリジン / 正規 origin / multiDevice/singleDevice の両分岐は全てサーバー側のシード値から生成される。
  zod スキーマ: passkeyAttackPhishingOriginBindingSchema = z.object({}))

Response: { data: AttackResult, _trace: ServerTrace }
  // data.outcome: "succeeded" (常に — 5 ステップ完全形で両モードを並列観察)
  // data.steps: 5 ステップ完全形 (probe → tamper → forge → exploit → verify)
  // data.blockedBy: "passkey_origin_validation_enforced" (堅牢側 verify で発火)
  // data.extra: シナリオ固有フィールド (attackerOrigin / expectedOrigin / multiDeviceOriginRejected / singleDeviceOriginRejected 等)
```

##### 期待結果

E-2 契約: 1 リクエストで両モード (脆弱: origin 検証スキップを仮定、堅牢: expectedOrigin 厳密一致) を並列実行し、5 ステップ完全形を返す。`outcome` は常に `"succeeded"` 固定、HTTP ステータスは 200 固定。`blockedBy` には堅牢側で発火した防御識別子を記録する。

| 項目 | 値 |
|------|-----|
| `outcome` | `"succeeded"` (常に) |
| HTTP ステータス | 200 (常に) |
| `blockedBy` | `"passkey_origin_validation_enforced"` (堅牢側 step 5: clientDataJSON.origin と expectedOrigin の不一致で拒否 — multiDevice/singleDevice 共通) |
| `steps[3].status` (脆弱側 exploit: origin 検証スキップ) | `"success"` (attacker.example origin の Passkey 署名が受理される仮想シナリオ) |
| `steps[4].status` (堅牢側 verify: expectedOrigin 厳密一致) | `"blocked"` |

#### 4.1.4 防御解説パネルコンテンツ

**なぜ防御が機能したか (1〜3 文):**

> Passkey は FIDO2/WebAuthn の仕様に従い、クレデンシャル生成時に `rpId` をバインドします。
> 認証時に生成される `clientDataJSON` には `origin` フィールドが含まれており、
> `passkey.ts` の `verifyAuthenticationResponse` が `expectedOrigin: "http://localhost:3000"` と
> 厳密比較します。
> 攻撃者がフィッシングページに誘導しても、署名に含まれる `origin` は攻撃者ドメインになるため
> 正規サーバーの検証で必ず拒否されます。
> **同期パスキー (multiDevice) であっても、この保護は変わりません。**

**防御実装ファイル:**
`server/routes/passkey.ts` — `verifyAuthenticationResponse({ expectedOrigin: ORIGIN, expectedRPID: RP_ID })`

**コードヒント:**

```typescript
// @simplewebauthn/server による origin 検証 (passkey.ts)
await verifyAuthenticationResponse({
  response:          authResponse as any,
  expectedChallenge,
  expectedOrigin:    "http://localhost:3000",  // ← 厳密一致検証
  expectedRPID:      "localhost",              // ← rpIdHash 不一致も拒否
  credential: { ... },
});
// origin 不一致 → Error: clientDataJSON.origin is not one of the expected values
```

**実環境との差異付記:**
> 実際のブラウザは同一オリジンポリシーにより、`attacker.example` から `localhost` の
> 登録済み Passkey へのアクセス自体をブロックします。
> このデモは「サーバー側の origin 検証」という二重防御がどう機能するかを示す概念実証です。

---

### 4.2 シナリオ B: クラウド同期経路の侵害 (シミュレーション)

**シナリオ ID**: `passkey-cloud-sync-compromise`

#### 4.2.1 教育的シナリオの前提

これは **CWE-287 (Improper Authentication)** / **CAPEC-560** の概念実証である。

**これはシミュレーションです。** 実際の iCloud Keychain / Google Password Manager の
内部実装・暗号鍵管理には触れず、「クラウドアカウントのセキュリティが同期パスキーの
セキュリティの前提条件である」という概念的な論点を示す。

同期パスキーの便利さ (複数デバイスで利用可能) の裏面:

- `multiDevice` パスキーは、登録した認証器のベンダーが管理するクラウドサービス
  (Apple iCloud Keychain, Google Password Manager, 1Password 等) に暗号化されて同期される
- クラウドアカウントが侵害されると、攻撃者はそのアカウントに紐付いた同期パスキーを
  別デバイスに複製して使用できる可能性がある
- これは **Passkey 自体の設計上の欠陥ではなく**、クラウドアカウント保護の重要性を示す論点である

本シナリオでは「弱いクラウドアカウント保護 vs 強いクラウドアカウント保護」の比較を示し、
**クラウドアカウントへの強パスワード + MFA 適用が Passkey のセキュリティを維持する前提条件**
であることを教える。

**教材ポイント:** Passkey はクラウドアカウントのセキュリティを前提とする。
クラウドアカウントに強パスワード + MFA を設定することで、同期パスキーのセキュリティが保たれる。

#### 4.2.2 攻撃ステップ設計 (左右比較パネル)

**左パネル (弱いクラウドアカウント保護 — リスクあり):**

| ステップ | `kind` | `status` | 説明 |
|---------|--------|----------|------|
| S1 | `probe` | `success` | 攻撃者がクラウドアカウントの弱パスワードをブルートフォース |
| S2 | `intercept` | `success` | クラウドアカウントにログイン (MFA なしのため即座に侵害) |
| S3 | `replay` | `success` | 同期パスキーを攻撃者デバイスに複製 |
| S4 | `blocked_by_server` | `warning` | ただし、パスキー自体の origin 検証は依然として機能する |

**右パネル (強いクラウドアカウント保護 — 防御済み):**

| ステップ | `kind` | `status` | 説明 |
|---------|--------|----------|------|
| S1 | `probe` | `success` | 攻撃者がクラウドアカウントへの侵害を試みる |
| S2 | `blocked` | `blocked` | 強パスワード + MFA がクラウドアカウントへのアクセスを阻止 |
| S3 | `skipped` | `blocked` | 同期パスキーへのアクセスなし — 複製不可能 |

#### 4.2.3 API 設計

```
POST /api/passkey/attack/cloud-sync-compromise
Content-Type: application/json

Request: {} (E-2: 両モードを並列実行するため body は空オブジェクト。
  cloudAccountProtection の weak/strong 分岐 / 同期パスキー / multiDevice デバイスタイプは全てサーバー側のシード値から生成される。
  zod スキーマ: passkeyAttackCloudSyncCompromiseSchema = z.object({}))

Response: { data: AttackResult, _trace: ServerTrace }
  // data.outcome: "succeeded" (常に — 5 ステップ完全形で両モードを並列観察)
  // data.steps: 5 ステップ完全形 (probe → tamper → forge → exploit → verify)
  // data.blockedBy: "cloud_account_strong_password_and_mfa_enforced" (堅牢側 verify で発火)
  // data.extra: シナリオ固有フィールド (vulnerableCloudCompromised / strongCloudResisted / mfaEnabled / multiDeviceFlag 等)
```

##### 期待結果

E-2 契約: 1 リクエストで両モード (脆弱: クラウドアカウント弱パスワード + MFA なし、堅牢: 強パスワード + MFA (TOTP/FIDO2)) を並列実行し、5 ステップ完全形を返す。`outcome` は常に `"succeeded"` 固定、HTTP ステータスは 200 固定。`blockedBy` には堅牢側で発火した防御識別子を記録する。

| 項目 | 値 |
|------|-----|
| `outcome` | `"succeeded"` (常に) |
| HTTP ステータス | 200 (常に) |
| `blockedBy` | `"cloud_account_strong_password_and_mfa_enforced"` (堅牢側 step 5: 強パスワード + MFA がクラウドアカウント侵害を阻止) |
| `steps[3].status` (脆弱側 exploit: 弱パスワード + MFA なし) | `"success"` (クラウドアカウント侵害により同期パスキー領域に到達 — ただし RP origin バインディングは依然有効) |
| `steps[4].status` (堅牢側 verify: 強パスワード + MFA) | `"blocked"` |

#### 4.2.4 防御解説パネルコンテンツ

**なぜクラウドアカウント保護が重要か (1〜3 文):**

> 同期パスキー (`multiDevice` タイプ) は、クラウドサービスを通じてデバイス間で複製されます。
> このため、クラウドアカウント自体のセキュリティが Passkey のセキュリティの前提条件となります。
> クラウドアカウントに強パスワードと MFA を設定することで、
> 同期パスキーへの不正アクセスを防ぎ、Passkey の利便性とセキュリティを両立できます。

**防御実装のポイント:**
クラウドアカウント保護は `passkey.ts` の実装範囲外だが、`credentialDeviceType` と
`credentialBackedUp` フラグをユーザーに提示することで、リスクの認識を促せる。

**コードヒント:**

```typescript
// passkey.ts: deviceType を利用者に提示してリスク認識を促す
return c.json({
  success: true,
  data: {
    credentialDeviceType: deviceType,  // "multiDevice" | "singleDevice"
    credentialBackedUp:   backedUp,    // true → クラウド同期済み
    // フロントエンドはこれを見て適切な警告を表示できる
  },
});
// クライアント側での表示例
// multiDevice → "☁ クラウド同期パスキー: クラウドアカウントの保護が重要です"
// singleDevice → "🔒 デバイス固有パスキー: このデバイスにのみ存在します"
```

**実環境との差異付記:**

> このシミュレーションは概念的なリスクを示します。
> 実際の iCloud Keychain / Google Password Manager は暗号化されたバックアップを提供しており、
> クラウドアカウント侵害だけでパスキーが直接利用可能になるとは限りません。
> このデモは「クラウドアカウントのセキュリティが Passkey の信頼チェーンに組み込まれている」
> という概念を理解するためのものです。

---

### 4.3 シナリオ C: Cross-device 経路の中間者 (シミュレーション)

**シナリオ ID**: `passkey-cross-device-mitm`

#### 4.3.1 教育的シナリオの前提

これは **CWE-300 (Channel Accessible by Non-Endpoint)** / **CAPEC-94** の概念実証である。

**これはシミュレーションです。** CTAP2.2 のハイブリッドプロトコルの詳細実装には触れず、
防御の概念的仕組みを示す。

Cross-device authentication (ハイブリッドフロー) は以下の流れで動作する:

```
[PC ブラウザ]                           [スマートフォン]
    |                                        |
    |-- QR コード表示 (FIDO2 hybrid URL) -->|
    |                                        |-- BLE アドバタイズ (近接確認)
    |<--- BLE 応答 (同一空間にいることを確認) |
    |                                        |
    |-- Tunnel URL 経由で challenge 送信 --->|
    |                                        |-- Passkey で署名
    |<--- 署名済みアサーション (暗号化) ------|
    |                                        |
    |-- /api/passkey/auth/verify に提出 ---->|
```

攻撃者が QR コードを傍受して「中間に入る」シナリオでは:

- **BLE 近接要件** が物理的な近接を要求するため、リモート攻撃者はこの経路を通じた認証を実行できない
- **Tunnel Key 暗号化** により、ネットワーク経路上の盗聴・改竄が阻止される

**教材ポイント:** ハイブリッドフローは BLE 近接 + tunnel key 暗号化の二層防御により、
QR 中継 MITM を設計上阻止している。

#### 4.3.2 攻撃ステップ設計

| ステップ | `kind` | `status` | 説明 |
|---------|--------|----------|------|
| S1 | `intercept` | `success` | 攻撃者が PC ブラウザの QR コードを傍受 (スクリーンショット/画面盗み見) |
| S2 | `forge` | `success` | 攻撃者デバイスが QR コードの FIDO2 hybrid URL を読み取り、認証を試みる |
| S3 | `blocked` | `blocked` | BLE アドバタイズと近接確認: 攻撃者デバイスが PC と BLE 圏外 → ハンドシェイク失敗 |
| S4 | `blocked` | `blocked` | Tunnel Key 検証: 攻撃者は tunnel key を保持していないため、暗号化通信路を確立できない |

#### 4.3.3 API 設計

```
POST /api/passkey/attack/cross-device-mitm
Content-Type: application/json

Request: {} (E-2: 両モードを並列実行するため body は空オブジェクト。
  attackerLocation の remote/proximity 分岐 / BLE 近接要件 / tunnel key 暗号化は全てサーバー側のシード値から生成される。
  zod スキーマ: passkeyAttackCrossDeviceMitmSchema = z.object({}))

Response: { data: AttackResult, _trace: ServerTrace }
  // data.outcome: "succeeded" (常に — 5 ステップ完全形で両モードを並列観察)
  // data.steps: 5 ステップ完全形 (probe → tamper → forge → exploit → verify)
  // data.blockedBy: "ctap22_ble_proximity_and_tunnel_key_enforced" (堅牢側 verify で発火)
  // data.extra: シナリオ固有フィールド (remoteBleOutOfRange / proximityTunnelKeyMismatch / qrInterceptedPrefix / hybridFlowOutcome 等)
```

##### 期待結果

E-2 契約: 1 リクエストで両モード (脆弱: ハイブリッドフローを bypass する仮想シナリオ、堅牢: BLE 近接 + tunnel key 暗号化) を並列実行し、5 ステップ完全形を返す。`outcome` は常に `"succeeded"` 固定、HTTP ステータスは 200 固定。`blockedBy` には堅牢側で発火した防御識別子を記録する。

| 項目 | 値 |
|------|-----|
| `outcome` | `"succeeded"` (常に) |
| HTTP ステータス | 200 (常に) |
| `blockedBy` | `"ctap22_ble_proximity_and_tunnel_key_enforced"` (堅牢側 step 5: BLE 近接要件と CTAP2.2 tunnel key 暗号化が remote/proximity の両攻撃を阻止) |
| `steps[3].status` (脆弱側 exploit: ハイブリッドフロー bypass 仮定) | `"success"` (QR 傍受で MITM 経路に到達する仮想シナリオ) |
| `steps[4].status` (堅牢側 verify: BLE 近接 + tunnel key) | `"blocked"` |

#### 4.3.4 防御解説パネルコンテンツ

**なぜ防御が機能したか (1〜3 文):**

> FIDO2 ハイブリッドフローは、BLE 近接確認と tunnel key 暗号化の二層防御を持ちます。
> リモート攻撃者は BLE 近接確認を通過できず、物理的に近くにいる攻撃者も
> tunnel key を持たないため暗号化通信路を確立できません。
> QR コードを傍受しても、正規ブラウザとスマートフォン間の tunnel key は
> ECDH 鍵交換によって確立されるものであり、攻撃者が複製することは暗号的に困難です。

**コードヒント:**

```typescript
// CTAP2.2 ハイブリッドプロトコルの防御層 (概念的表現)
// 1. BLE 近接: デバイスが物理的に近くにある必要がある
const bleProximityOk = await checkBleProximity(qrContactId);
// 2. Tunnel key: ECDH で確立 — QR の傍受だけでは導出不可
const tunnelKey = await deriveSharedSecret(qrEphemeralKey, devicePrivateKey);
// どちらも成立しないと challenge の受け渡しが不可能

// passkey.ts の verifyAuthenticationResponse は
// challenge と origin を検証 — トンネルが確立された場合でも
// 正規 RP でなければ最終的に拒否される
```

**実環境との差異付記:**

> CTAP2.2 のハイブリッドプロトコルの完全な暗号実装はこのデモには含まれていません。
> このデモは BLE 近接要件と tunnel key 暗号化という防御層の概念を示す教育用シミュレーションです。
> 実際のハイブリッドフローは W3C WebAuthn Level 3 および FIDO CTAP2.2 の仕様に従います。

---

## 5. UI コンポーネント設計

### 5.1 ディレクトリ構成

```
src/components/auth/attacks/passkey/
├── PasskeyAttackPanel.tsx          # パスキー攻撃デモのルートコンポーネント
├── PhishingOriginBindingDemo.tsx   # シナリオ A: フィッシング origin 検証失敗
├── CloudSyncCompromiseDemo.tsx     # シナリオ B: クラウド同期リスク比較パネル
├── CrossDeviceMitmDemo.tsx         # シナリオ C: Cross-device MITM 阻止
└── PasskeyAttack.css               # 攻撃デモ専用スタイル (緑系バナー、比較パネル)
```

既存コンポーネントへの変更:
```
src/components/auth/PasskeyFlow.tsx  # ViewModeToggle + AttackPanel 接続を追加 (最小変更)
```

### 5.2 PasskeyFlow.tsx への変更 (最小変更)

```typescript
// src/components/auth/PasskeyFlow.tsx への追加分 (既存 return の末尾に追記)
import { Show } from "solid-js";
import ViewModeToggle from "../attacks/ViewModeToggle";
import PasskeyAttackPanel from "../attacks/passkey/PasskeyAttackPanel";

// viewMode Signal を既存コンポーネントに追加
const [viewMode, setViewMode] = createSignal<"defender" | "attacker">("defender");

// JSX の末尾に追加
<ViewModeToggle mode={viewMode()} onChange={setViewMode} />
<Show when={viewMode() === "attacker"}>
  <PasskeyAttackPanel />
</Show>
```

### 5.3 PasskeyAttackPanel.tsx の設計

```typescript
// src/components/auth/attacks/passkey/PasskeyAttackPanel.tsx (概略)
import { createSignal, Show } from "solid-js";
import EducationalWarningBanner from "../../../shared/EducationalWarningBanner";
import AttackScenarioSelector from "../AttackScenarioSelector";
import AttackStepTimeline from "../AttackStepTimeline";
import AttackResultBanner from "../AttackResultBanner";
import AttackDefensePanel from "../AttackDefensePanel";
import DataFlowPanel from "../../../shared/DataFlowPanel";
import { useI18n } from "../../../../i18n/context";
import { apiPost } from "../../../../api/client";
import type { AttackResult } from "../../../../../shared/api-types";

const SCOPE = "attack-passkey";

// このタブ特有の補足テキスト
const PASSKEY_SPECIAL_NOTE = {
  ja: "このタブは「攻撃が阻止されること」を確認するデモです。Passkey の多層防御と、同期パスキーに固有のリスク前提条件を体験してください。",
  en: "This tab demonstrates how attacks are BLOCKED. Experience Passkey's layered defenses and the cloud-sync-specific risk preconditions.",
};

const PASSKEY_SCENARIOS = [
  {
    id: "passkey-phishing-origin-binding",
    nameJa: "フィッシング耐性: origin binding (同期パスキーでも有効)",
    name:   "Phishing Resistance: Origin Binding (effective even with synced passkeys)",
    descriptionJa: "これは CWE-290 / CWE-346 の概念実証です。同期パスキーを使用していても、origin バインディングがフィッシング攻撃を阻止することを示します。",
    description:   "This is a proof-of-concept for CWE-290 / CWE-346. Demonstrates that origin binding prevents phishing even with synced passkeys.",
    apiPath: "/api/passkey/attack/phishing-origin-binding",
    severity: "info" as const,
  },
  {
    id: "passkey-cloud-sync-compromise",
    nameJa: "クラウド同期リスク: クラウドアカウント保護の重要性 (シミュレーション)",
    name:   "Cloud Sync Risk: Importance of Cloud Account Protection (Simulation)",
    descriptionJa: "これは CWE-287 の概念実証です。弱いクラウドアカウント保護が同期パスキーのセキュリティ前提を崩すリスクを示します。",
    description:   "This is a proof-of-concept for CWE-287. Shows the risk of weak cloud account protection undermining synced passkey security.",
    apiPath: "/api/passkey/attack/cloud-sync-compromise",
    severity: "high" as const,
  },
  {
    id: "passkey-cross-device-mitm",
    nameJa: "Cross-device MITM: BLE 近接 + tunnel key が阻止 (シミュレーション)",
    name:   "Cross-device MITM: Blocked by BLE Proximity + Tunnel Key (Simulation)",
    descriptionJa: "これは CWE-300 の概念実証です。QR コードを傍受した攻撃者が BLE 近接要件と tunnel key 暗号化により阻止される過程を示します。",
    description:   "This is a proof-of-concept for CWE-300. Shows how an attacker intercepting the QR code is blocked by BLE proximity and tunnel key encryption.",
    apiPath: "/api/passkey/attack/cross-device-mitm",
    severity: "high" as const,
  },
];

export default function PasskeyAttackPanel() {
  const { t } = useI18n();
  const [selectedScenario, setSelectedScenario] = createSignal(PASSKEY_SCENARIOS[0]);
  const [currentResult, setCurrentResult] = createSignal<AttackResult | null>(null);
  const [running, setRunning] = createSignal(false);

  async function runAttack() {
    const scenario = selectedScenario();
    setRunning(true);
    setCurrentResult(null);

    const body = scenario.id === "passkey-phishing-origin-binding"
      ? { username: "seed_alice", fakeOrigin: "http://attacker.example", deviceType: "multiDevice" }
      : scenario.id === "passkey-cloud-sync-compromise"
      ? { cloudAccountProtection: "weak" }
      : { attackerLocation: "remote" };

    const res = await apiPost<AttackResult>(scenario.apiPath, body, SCOPE);
    if (res.data) setCurrentResult(res.data);
    setRunning(false);
  }

  return (
    <div class="passkey-attack-panel">
      <EducationalWarningBanner />
      <div class="passkey-special-note" role="note">
        {t(PASSKEY_SPECIAL_NOTE.ja, PASSKEY_SPECIAL_NOTE.en)}
      </div>

      <AttackScenarioSelector
        scenarios={PASSKEY_SCENARIOS}
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

### 5.4 CloudSyncCompromiseDemo.tsx の比較パネル設計 (シナリオ B)

シナリオ B は「弱い保護 vs 強い保護」の左右比較 (04-safety-guardrails.md §9.3 準拠):

```typescript
// CloudSyncCompromiseDemo.tsx (概略)

// 左パネル (弱いクラウドアカウント保護)
<div class="cloud-risky-side">
  <EducationalWarningBanner />   {/* 赤帯 */}
  <h4>{t("弱いクラウドアカウント保護", "Weak Cloud Account Protection")}</h4>
  <p class="cloud-config">{t("パスワード: 弱 / MFA: なし", "Password: weak / MFA: none")}</p>
  <AttackStepTimeline steps={weakResult()?.steps ?? []} />
  <AttackResultBanner result={weakResult()} />
</div>

// 右パネル (強いクラウドアカウント保護)
<div class="cloud-safe-side">
  <div class="defense-badge">{t("防御実装済み", "Defense Active")}</div>
  <h4>{t("強いクラウドアカウント保護", "Strong Cloud Account Protection")}</h4>
  <p class="cloud-config">{t("パスワード: 強 (16文字+) / MFA: あり", "Password: strong (16+ chars) / MFA: enabled")}</p>
  <AttackStepTimeline steps={strongResult()?.steps ?? []} />
  <AttackResultBanner result={strongResult()} successColor="var(--color-success)" />
</div>
```

### 5.5 PasskeyAttack.css の要点

```css
/* src/components/auth/attacks/passkey/PasskeyAttack.css */
.passkey-attack-panel .attack-result-banner.blocked {
  background-color: var(--color-success, #52c41a);
  color: #fff;
  font-weight: 700;
}
.passkey-special-note {
  background: rgba(82, 196, 26, 0.12);
  border-left: 3px solid var(--color-success, #52c41a);
  padding: 8px 12px;
  margin-bottom: 16px;
}
.cloud-comparison-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}
.cloud-comparison-grid .cloud-risky-side  { border-top: 3px solid var(--color-warning, #ff4d4f); }
.cloud-comparison-grid .cloud-safe-side   { border-top: 3px solid var(--color-success, #52c41a); }
/* シナリオ B のバナー高さを揃える */
.cloud-risky-side .edu-warning-banner,
.cloud-safe-side  .defense-badge         { min-height: 44px; }
```

---

## 6. テスト要件

### 6.1 バックエンドエンドポイントテスト

E-2 契約に準拠したテスト構成。各シナリオは 1 リクエストで両モード並列実行のため、`outcome === "succeeded"` 固定 + 5 ステップ完全形 + `blockedBy` で防御識別子を検証する。実装は `server/__tests__/passkey-attack.test.ts` (Phase 2 第七コミット 714589e)。

| テストカテゴリ | 対象 | 期待値 |
|------------|-----|--------|
| E-2 不変条件 (it.each で 3 シナリオ共通) | `phishing-origin-binding` / `cloud-sync-compromise` / `cross-device-mitm` | `status === 200` / `outcome === "succeeded"` / `steps.length === 5` / `_trace.attackSteps.length === 5` / `_trace.isAttackMode === true` |
| logId 一意性 | 全 3 シナリオを連続実行 | `attack_log` テーブルに 3 件の独立 logId を確認 |
| 本番ガード | `NODE_ENV=production` で全 3 ルート | `status === 403` |
| summaryJa prefix | 全 3 シナリオ | 「この実装は」または「このシナリオでは」または「防御が機能しました」で始まる |
| シナリオ A: blockedBy | `phishing-origin-binding` | `"passkey_origin_validation_enforced"` |
| シナリオ A: extra フィールド | `phishing-origin-binding` | `extra.attackerOrigin` / `extra.expectedOrigin` / `extra.multiDeviceOriginRejected === true` / `extra.singleDeviceOriginRejected === true` を含む (deviceType に依存しない origin 検証) |
| シナリオ B: blockedBy | `cloud-sync-compromise` | `"cloud_account_strong_password_and_mfa_enforced"` |
| シナリオ B: extra フィールド | `cloud-sync-compromise` | `extra.vulnerableCloudCompromised` (脆弱側) / `extra.strongCloudResisted` (堅牢側) / `extra.mfaEnabled` / `extra.multiDeviceFlag` を含む |
| シナリオ C: blockedBy | `cross-device-mitm` | `"ctap22_ble_proximity_and_tunnel_key_enforced"` |
| シナリオ C: extra フィールド | `cross-device-mitm` | `extra.remoteBleOutOfRange === true` / `extra.proximityTunnelKeyMismatch === true` / `extra.qrInterceptedPrefix` / `extra.hybridFlowOutcome` を含む |

### 6.2 フロントエンド動作テスト

| テスト ID | テスト内容 | 検証方法 |
|----------|-----------|---------|
| T-F-01 | `EducationalWarningBanner` が Attacker View 切替後に常時表示される | DOM に `edu-warning-banner` が存在し `visibility: visible` |
| T-F-02 | 全シナリオの `AttackResultBanner` が緑色で表示される (`outcome: "blocked"`) | `background-color` が `--color-success` 系 |
| T-F-03 | シナリオ B の比較パネル — 左 (弱) は赤帯、右 (強) は緑バッジ | 両パネルのヘッダーボーダーカラーを確認 |
| T-F-04 | `AttackDefensePanel` がシナリオ実行後に展開される | コンポーネントが DOM に追加される |
| T-F-05 | `DataFlowPanel` の Trace タブに `attackSteps` が表示される | "origin" / "BLE" / "tunnel key" / "cloud" のいずれかが含まれる |
| T-F-06 | シナリオ A の `deviceType` セレクタが動作する | `multiDevice` / `singleDevice` の選択が API パラメータに反映される |
| T-F-07 | シナリオ C の `attackerLocation` セレクタが動作する | `remote` / `proximity` の選択でステップ数が変わる (両方 4 ステップ) |

### 6.3 UI 文言チェックリスト (04-safety-guardrails.md §4.2 準拠)

- [ ] Attacker View のすべての画面で `EducationalWarningBanner` が最上部に固定表示されている
- [ ] バナーが `display: none` / `visibility: hidden` になるコード・CSS が存在しない
- [ ] シナリオ B の弱い保護側の文言が「このシナリオでは」で始まっている
- [ ] 防御成立の文言が「防御が機能しました: <blockedBy>」形式になっている
- [ ] 禁止表現 (「ハッキング」「クラッキング」「簡単に破れる」「攻撃に成功しました」等) が存在しない
- [ ] シナリオ B の「シミュレーション」である旨が解説パネルに記載されている
- [ ] シナリオ C の「シミュレーション」である旨が解説パネルに記載されている
- [ ] 実環境との差異付記がシナリオ B・C の防御解説パネルに含まれている

---

## 7. i18n キー一覧表

`src/i18n/context.tsx` の `t(ja, en)` ヘルパーで使用するキーと文言の対応表。

| キー (文言 — 日本語) | 文言 — English |
|---------------------|---------------|
| `このタブは「攻撃が阻止されること」を確認するデモです。Passkey の多層防御と、同期パスキーに固有のリスク前提条件を体験してください。` | `This tab demonstrates how attacks are BLOCKED. Experience Passkey's layered defenses and the cloud-sync-specific risk preconditions.` |
| `フィッシング耐性: origin binding (同期パスキーでも有効)` | `Phishing Resistance: Origin Binding (effective even with synced passkeys)` |
| `クラウド同期リスク: クラウドアカウント保護の重要性 (シミュレーション)` | `Cloud Sync Risk: Importance of Cloud Account Protection (Simulation)` |
| `Cross-device MITM: BLE 近接 + tunnel key が阻止 (シミュレーション)` | `Cross-device MITM: Blocked by BLE Proximity + Tunnel Key (Simulation)` |
| `攻撃シミュレーションを実行` | `Run Attack Simulation` |
| `攻撃者フィッシングページが Passkey 認証を要求` | `Phishing page requests Passkey authentication` |
| `正規サーバーへチャレンジ要求を中継 (ユーザー名なし認証)` | `Relay challenge request to legitimate server (usernameless)` |
| `ブラウザが attacker.example origin で clientDataJSON に署名` | `Browser signs clientDataJSON with attacker.example origin` |
| `サーバーの origin 検証が attacker.example を拒否` | `Server origin validation rejects attacker.example` |
| `攻撃者がクラウドアカウントの弱パスワードを試行` | `Attacker attempts weak cloud account password` |
| `クラウドアカウントへのログイン成功 (MFA なし)` | `Cloud account login succeeded (no MFA)` |
| `同期パスキーを攻撃者デバイスに複製` | `Synced passkey cloned to attacker's device` |
| `ただし、パスキー使用時の origin 検証は依然として機能` | `Passkey usage still requires matching origin on use` |
| `攻撃者がクラウドアカウントへの侵害を試みる` | `Attacker attempts to compromise cloud account` |
| `強パスワード + MFA がクラウドアカウントへのアクセスを阻止` | `Strong password + MFA blocks cloud account access` |
| `攻撃者が PC ブラウザの QR コードを傍受` | `Attacker intercepts QR code from PC browser` |
| `攻撃者デバイスが QR コードを読み取り認証を試みる` | `Attacker device reads QR code and attempts authentication` |
| `BLE 近接確認: 攻撃者デバイスが BLE 圏外 → ハンドシェイク失敗` | `BLE proximity check: attacker device out of range → handshake failed` |
| `Tunnel Key 確立不可 — 暗号化通信路なし` | `Tunnel key cannot be established — no encrypted channel` |
| `BLE 近接確認: 攻撃者が物理的に近く、BLE を通過` | `BLE proximity: attacker is nearby, BLE phase passed` |
| `Tunnel Key 検証: 攻撃者は tunnel key を保持せず → 暗号化通信路確立不可` | `Tunnel key verification: attacker lacks tunnel key → encrypted channel unavailable` |
| `弱いクラウドアカウント保護` | `Weak Cloud Account Protection` |
| `強いクラウドアカウント保護` | `Strong Cloud Account Protection` |
| `パスワード: 弱 / MFA: なし` | `Password: weak / MFA: none` |
| `パスワード: 強 (16文字+) / MFA: あり` | `Password: strong (16+ chars) / MFA: enabled` |
| `防御が機能しました: origin バインディングがフィッシング攻撃を阻止しました。同期パスキーでもシングルデバイスパスキーでも、クレデンシャルの署名は RP ID に暗号的に紐付いており、別オリジンからは使用できません。` | `Defense activated: Origin binding prevented the phishing attack. For both synced and single-device passkeys, the credential signature is cryptographically bound to the RP ID and cannot be used from a different origin.` |
| `このシナリオでは 弱パスワード + MFA なし のクラウドアカウント設定が同期パスキー複製のリスクを生じさせます。` | `In this scenario, weak password + no MFA on the cloud account creates the risk of synced passkey cloning.` |
| `防御が機能しました: クラウドアカウントの強パスワード + MFA が侵害を阻止し、同期パスキーへのアクセスを保護しました。` | `Defense activated: Strong password + MFA on the cloud account blocked the compromise and protected access to synced passkeys.` |
| `防御が機能しました: BLE 近接要件がリモート攻撃者を阻止しました。` | `Defense activated: BLE proximity requirement blocked the remote attacker.` |
| `防御が機能しました: CTAP2.2 の tunnel key 暗号化が物理的近接攻撃者の MITM を阻止しました。` | `Defense activated: CTAP2.2 tunnel key encryption blocked the MITM attempt by a physically nearby attacker.` |

### 7.1 `AttackStep.labelJa` / `detailJa` のキー

バックエンドの `trace.addAttackStep()` で設定するフィールドは上記テーブルの日本語文言と一致させる。
フロントエンドは `useI18n()` の言語設定に応じて `label` / `labelJa` を切り替えて表示する。

---

## 8. 関連ファイル

### 8.1 新規作成ファイル

| ファイルパス | 役割 |
|------------|------|
| `src/components/auth/attacks/passkey/PasskeyAttackPanel.tsx` | パスキー攻撃デモのルートコンポーネント |
| `src/components/auth/attacks/passkey/PhishingOriginBindingDemo.tsx` | シナリオ A: フィッシング耐性デモ |
| `src/components/auth/attacks/passkey/CloudSyncCompromiseDemo.tsx` | シナリオ B: クラウド同期リスク比較パネル |
| `src/components/auth/attacks/passkey/CrossDeviceMitmDemo.tsx` | シナリオ C: Cross-device MITM 阻止デモ |
| `src/components/auth/attacks/passkey/PasskeyAttack.css` | 攻撃デモ専用スタイル |
| `src/components/auth/attacks/scenarios/passkey-scenarios.ts` | `AttackScenarioMeta[]` 静的定義 |
| `server/routes/attack-passkey.ts` | パスキータブ攻撃ルート (3エンドポイント) |

### 8.2 変更ファイル

| ファイルパス | 変更内容 | 変更規模 |
|------------|---------|---------|
| `src/components/auth/PasskeyFlow.tsx` | `ViewModeToggle` + `<Show>` + `PasskeyAttackPanel` を追加 | 極小 (~10 行追加) |
| `server/index.ts` | `attack-passkey.ts` のルートを `/api/passkey` に登録 | 極小 (~3 行追加) |

### 8.3 既存ファイル (参照のみ、変更不要)

| ファイルパス | 参照理由 |
|------------|---------|
| `server/routes/passkey.ts` | `RP_ID`, `ORIGIN`, `registerChallenges`, `authChallenges`, `verifyRegistrationResponse`, `verifyAuthenticationResponse`, `credentialDeviceType` の防御実装を参照 |
| `server/db/schema.ts` | `webauthn_credentials` テーブル (credential_id, user_id, public_key, counter, transports) を参照 |
| `src/components/auth/PasskeyFlow.tsx` | 既存 Defender View の PasskeyDemo / PasskeyFlow 構造を把握してから Attacker View を追加 |
| `src/components/shared/DataFlowPanel.tsx` | `scopeId="attack-passkey"` で使用。変更不要 |
| `src/api/client.ts` | `apiPost` の使用パターン参照 |
| `shared/api-types.ts` | `AttackResult`, `AttackStep` 型の参照 |
| `server/middleware/trace-logger.ts` | `trace.addAttackStep()` 呼び出しパターン参照 |
| `DESIGN/04-safety-guardrails.md` | 文言ルール・安全装置の実装方針 |
| `DESIGN/15-attack-fido2.md` | FIDO2 タブとの原理共有部分 (origin 検証) の参照元 |
| `DESIGN/03-data-model.md` | `AttackResult`, `AttackStep` 型定義詳細 |

### 8.4 API エンドポイント一覧

| メソッド | パス | 役割 | 期待 outcome |
|---------|------|------|------------|
| POST | `/api/passkey/attack/phishing-origin-binding` | シナリオ A: フィッシング origin 検証失敗 | `blocked` |
| POST | `/api/passkey/attack/cloud-sync-compromise` | シナリオ B: クラウド同期リスク比較 | `blocked` |
| POST | `/api/passkey/attack/cross-device-mitm` | シナリオ C: Cross-device MITM 阻止 | `blocked` |

---

## 付録 A: FIDO2 タブとの設計上の相違点まとめ

| 観点 | FIDO2 タブ (15-attack-fido2.md) | Passkey タブ (本ファイル) |
|------|--------------------------------|--------------------------|
| 認証器の種類 | 主に物理認証器 (YubiKey 等) / プラットフォーム認証器 | プラットフォーム認証器 + 同期パスキーを中心 |
| クレデンシャルの複製 | singleDevice が前提 (デバイス固有) | multiDevice (クラウド同期) が主要ユースケース |
| クラウドアカウントとの依存関係 | 基本的になし | **同期パスキーはクラウドアカウントのセキュリティに依存** |
| Cross-device 認証 | 標準 WebAuthn (same-device が主) | ハイブリッドフロー (QR + BLE + tunnel key) |
| 攻撃シナリオ数 | 3 (origin 拒否 / パスワード比較 / チャレンジリプレイ) | 3 (origin binding / cloud sync / cross-device MITM) |
| 固有の学習目標 | origin 検証・チャレンジ一回性の理解 | 同期パスキーのリスク前提・ハイブリッドフロー保護の理解 |

どちらのタブも「攻撃が阻止されることを示す」設計であるが、
Passkey タブは **クラウドアカウント保護という人的・運用的な防御の重要性** を加えている点が固有の教材価値である。
