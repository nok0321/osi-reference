---
title: TLS 詳細 攻撃カタログ
phase: design
tab-id: tls-deep
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

# 18. TLS 詳細 攻撃カタログ

## 1. 概要

「TLS 詳細 (tls-deep)」タブは、TLS 1.3 ハンドシェイクの各フェーズ
(ClientHello → ServerHello → 鍵交換 → Finished) と ECDHE 鍵交換・証明書検証フローを
正常系で学ぶ既存の Defender View を持つ。このカタログは同タブに **Attacker View** を追加し、
TLS プロトコルの設計上の欠陥や実装上の誤りが攻撃者にどのように悪用されるかを体感的に理解させる。

TLS は OSI 第5層 (セッション層) 相当のプロトコルとして位置付けられ、上位層の HTTP 通信全体を
保護する根幹となる。TLS の弱点が突かれると第7層の認証機構がすべて意味を失うため、
TLS の防御設計は認証セキュリティの基盤として最も重要な要素の一つである。

### 1.1 防御側既存実装の参照

| ファイル | 役割 |
|---------|------|
| `server/routes/tls-sim.ts` | TLS 1.3 ハンドシェイクシミュレーション。`POST /api/tls/client-hello`、`POST /api/tls/server-hello`、`POST /api/tls/key-exchange`、`POST /api/tls/finish`、`GET /api/tls/certificate` の5エンドポイント |
| `src/components/auth/TlsDeepDive.tsx` | `TlsHandshakeDemo` コンポーネント。4ステップのハンドシェイクUI + DataFlowPanel による可視化 |
| `src/data/auth-flows.ts` | `TLS_DEEP_STEPS` 静的データ。OSI 層・方向・暗号詳細を含む |

### 1.2 攻撃デモの追加方針

既存の `TlsDeepDive.tsx` に `ViewModeToggle` を追加し、Attacker View として
`TlsAttackPanel` コンポーネントを条件表示する。
攻撃 API は `server/routes/tls-sim.ts` にサブパス `/attack/*` として追加する
(DESIGN/01-architecture.md §2.1 のルート配置方針に準拠)。

---

## 2. 攻撃シナリオ一覧

| # | シナリオ ID | 攻撃名 | CWE | CAPEC | OSI 層 | 深刻度 |
|---|------------|--------|-----|-------|--------|-------|
| A | `tls-version-downgrade` | バージョンダウングレード攻撃 (TLS 1.0 強制) | CWE-757 | CAPEC-220 | L5 (Session) | High |
| B | `tls-self-signed-mitm` | 自己署名証明書による MITM | CWE-295, CWE-300 | CAPEC-94 | L5 (Session) | High |
| C | `tls-weak-cipher-negotiation` | 弱い暗号スイートネゴシエーション (RC4/3DES 強制) | CWE-327 | CAPEC-220 | L5 (Session) | High |

---

## 3. 既存防御側実装

### 3.1 `server/routes/tls-sim.ts` の構造

```
tlsSimRoutes
├── POST /client-hello
│   ├── crypto.randomBytes(32)           ← clientRandom 生成 (CSPRNG)
│   ├── crypto.createECDH("prime256v1")  ← クライアント ECDHE 鍵ペア生成
│   └── 提示する暗号スイート: AES_256_GCM_SHA384, AES_128_GCM_SHA256, CHACHA20_POLY1305
│       (TLS 1.3 規定の認証付き暗号 (AEAD) のみ。RC4/3DES/NULL は含まない)
├── POST /server-hello
│   ├── selectCipherSuite: "TLS_AES_256_GCM_SHA384" を選択      ← 強度優先
│   └── serverECDH.getPublicKey()        ← サーバー ECDHE 公開鍵送付
├── POST /key-exchange
│   ├── serverECDH.computeSecret()       ← ECDHE 共有シークレット計算
│   ├── HMAC-SHA384(sharedSecret + randoms) → handshakeSecret  ← 簡略 HKDF
│   └── HMAC-SHA384(handshakeSecret)       → masterSecret
├── POST /finish
│   └── deriveApplicationKeys(masterSecret) → clientWriteKey / serverWriteKey
└── GET /certificate
    └── 教育用自己署名証明書を生成
        subject: "CN=localhost, O=OSI Demo, C=JP"
        issuer:  "CN=OSI Demo CA, O=OSI Demo, C=JP"
```

`trace.addCryptoOp()` により、ECDHE 鍵生成・共有シークレット計算・HKDF 導出の
操作詳細が `_trace.cryptoOps` に記録され `DataFlowPanel` の Trace タブで可視化される。

### 3.2 既存実装の防御上の強み

| 防御要素 | 実装箇所 | 効果 |
|---------|---------|------|
| TLS 1.3 専用暗号スイート | `client-hello`: `supportedCipherSuites` | RC4・3DES・NULL 等の廃止された暗号スイートを提示しない |
| ECDHE 鍵交換 (前方秘匿性) | `key-exchange`: `crypto.createECDH("prime256v1")` | エフェメラル鍵のため、将来の秘密鍵漏洩から過去セッションを保護する |
| 強い乱数生成 | `crypto.randomBytes(32)` | clientRandom/serverRandom が予測不能、リプレイ攻撃を防ぐ |
| 証明書の表示 | `/certificate`: subject/issuer/fingerprint を表示 | 学習者が証明書チェーン検証の重要性を視覚的に確認できる |

### 3.3 既存実装の教材上の制限 (攻撃デモで補完する箇所)

| 項目 | 現状 | 攻撃デモが補完する内容 |
|------|------|----------------------|
| ダウングレード保護 | TLS_FALLBACK_SCSV の説明なし | シナリオ A でダウングレード有/無を比較体験する |
| 証明書検証フロー | 自己署名証明書の生成のみ | シナリオ B でクライアント検証 ON/OFF の差を体験する |
| 暗号スイート選択 | 強い暗号のみ提示 | シナリオ C で脆弱なサーバーとの交渉結果を比較する |

---

## 4. シナリオ詳細

---

### 4.1 `tls-version-downgrade`

#### 概要

これは **CWE-757 / CAPEC-220** の概念実証である。
MITM (中間者攻撃者) がクライアントとサーバーの間でTLS ネゴシエーションを傍受し、
ClientHello メッセージの `supported_versions` フィールドから TLS 1.2/1.3 を削除して
TLS 1.0 や TLS 1.1 へ強制的にダウングレードさせる攻撃である。
TLS 1.0 は BEAST 攻撃 (CBC ブロック暗号の IV 予測) や POODLE 攻撃の影響を受ける
古い暗号スイートを使用するため、盗聴・解読されるリスクが生じる。

RFC 7507 が定義する **TLS_FALLBACK_SCSV (Signaling Cipher Suite Value)** は、
クライアントがダウングレード後の再試行時にこの特別な値を ClientHello に含めることで、
サーバーがダウングレードの強制を検知して接続を拒否できる仕組みである。
このシナリオでは SCSV なし/あり の2パターンを比較し、ダウングレード保護の効果を体感させる。

**実環境との差異の注記 (必須)**:
実環境では TLS 1.0/1.1 はほとんどの主要ブラウザ・サーバーで無効化されており、
このデモはダウングレード保護が設定されていない古いサーバーを想定した概念実証です。

#### CWE / CAPEC / OSI 層

| 項目 | 値 |
|------|-----|
| CWE | CWE-757 (Selection of Less-Secure Algorithm During Negotiation) |
| CAPEC | CAPEC-220 (Client-Server Protocol Manipulation) |
| OSI 層 | Layer 5 — Session |
| 深刻度 | High |

#### 前提条件

攻撃者は以下の条件を満たしている:

1. クライアントとサーバーの間のネットワーク経路に MITM として介入可能
2. サーバーが TLS 1.0/1.1 との後方互換性のためにこれらのバージョンを引き続き受け付けている
3. サーバーが TLS_FALLBACK_SCSV を実装していない (または無視している)

**脆弱な実装例** (このシナリオでシミュレーションする実装):

```typescript
// 脆弱なサーバー設定例 (教育用シミュレーション専用 — 実装しない)
// TLS_FALLBACK_SCSV を確認せずに、クライアントが提示した最高バージョンで接続する
function selectTlsVersion(offeredVersions: string[]): string {
  // SCSV チェックなし: ダウングレードを検知できない
  if (offeredVersions.includes("TLS 1.0")) return "TLS 1.0";
  return offeredVersions[0] ?? "TLS 1.0";
}
```

#### 攻撃ステップ (AttackStep[] の具体例)

```typescript
const steps: AttackStep[] = [
  {
    id: "step-1",
    kind: "intercept",
    label: "Intercept ClientHello (client offers TLS 1.0–1.3)",
    labelJa: "ClientHello を傍受 — クライアントは TLS 1.0-1.3 を提示",
    status: "success",
    payload: {
      type: "tls",
      version: "TLS 1.3",
      cipherSuite: "TLS_AES_256_GCM_SHA384",
    },
    detail: "The attacker intercepts the ClientHello. The client legitimately supports TLS 1.3.",
    detailJa: "攻撃者は ClientHello を傍受します。クライアントは正規に TLS 1.3 をサポートしています。",
    timestamp: Date.now(),
  },
  {
    id: "step-2",
    kind: "tamper",
    label: "MITM removes TLS 1.2/1.3 from supported_versions",
    labelJa: "MITM が supported_versions から TLS 1.2/1.3 を削除",
    status: "success",
    payload: {
      type: "tls",
      version: "TLS 1.3",
      downgradedTo: "TLS 1.0",
      cipherSuite: "TLS_AES_256_GCM_SHA384",
      weakCipherSuite: "TLS_RSA_WITH_RC4_128_MD5",
    },
    detail: "The attacker modifies the ClientHello, leaving only TLS 1.0 in the version list.",
    detailJa: "攻撃者は ClientHello を改竄し、バージョンリストに TLS 1.0 のみを残します。",
    timestamp: Date.now(),
  },
  {
    id: "step-3",
    kind: "probe",
    label: "Server accepts TLS 1.0 (no SCSV check) — weak cipher negotiated",
    labelJa: "サーバーが TLS 1.0 を受け入れる (SCSV チェックなし) — 弱い暗号でネゴシエーション完了",
    status: "success",
    payload: {
      type: "tls",
      downgradedTo: "TLS 1.0",
      weakCipherSuite: "TLS_RSA_WITH_RC4_128_MD5",
    },
    detail: "Without SCSV check, the server accepts TLS 1.0. RC4 cipher is negotiated — susceptible to BEAST-like attacks.",
    detailJa: "SCSV チェックなしのサーバーは TLS 1.0 を受け入れます。RC4 暗号がネゴシエーションされ、BEAST 攻撃の影響を受けます。",
    timestamp: Date.now(),
  },
  {
    id: "step-4",
    kind: "verify",
    label: "Server with TLS_FALLBACK_SCSV detects downgrade and aborts",
    labelJa: "TLS_FALLBACK_SCSV を実装したサーバーがダウングレードを検知し接続を中断",
    status: "blocked",
    payload: {
      type: "tls",
      version: "TLS 1.0",
      cipherSuite: "TLS_FALLBACK_SCSV",
    },
    detail: "When SCSV is present, the server recognizes a forced downgrade and responds with a fatal alert (inappropriate_fallback).",
    detailJa: "SCSV が存在する場合、サーバーは強制ダウングレードを認識し、致命的アラート (inappropriate_fallback) を返して接続を中断します。",
    timestamp: Date.now(),
  },
];
```

#### 期待される結果 (AttackResult)

```typescript
const result: AttackResult = {
  scenarioId: "tls-version-downgrade",
  outcome: "succeeded",   // SCSV なし実装では攻撃が成立
  startedAt: /* Unix ms */,
  finishedAt: /* Unix ms */,
  steps,
  blockedBy: "TLS_FALLBACK_SCSV による inappropriate_fallback アラート",
  summary: "Without TLS_FALLBACK_SCSV, MITM forced TLS 1.0 with RC4. With SCSV, the server detected the downgrade and aborted.",
  summaryJa: "TLS_FALLBACK_SCSV がない場合、MITM が TLS 1.0+RC4 に強制ダウングレードしました。SCSV があれば、サーバーがダウングレードを検知し接続を中断しました。",
};
```

UI 上の表示:
- step-1〜3: 攻撃成立 (SCSV なし時) → オレンジ
- step-4: 防御成立 (SCSV あり時) → 緑
- 結果バナー: 「この実装は脆弱です: TLS_FALLBACK_SCSV がないため、MITM によるバージョンダウングレードが成立しました」

#### 防御策 (defenseRecommendation)

**既存実装ファイルへのリンク**:
- `server/routes/tls-sim.ts:84-93` — `supportedCipherSuites` で TLS 1.3 専用 AEAD のみ提示

**防御策の要点**:

1. TLS 1.0 / TLS 1.1 をサーバー設定から完全に無効化する (最優先)
2. TLS_FALLBACK_SCSV (RFC 7507) を実装し、ダウングレードの強制を拒否する
3. サポートする最低バージョンを TLS 1.2 以上 (推奨: TLS 1.3 のみ) に設定する

**codeHints の具体例**:

```typescript
// Node.js の tls.createServer でのバージョン制限例 (概念)
import tls from "tls";

const server = tls.createServer({
  // TLS 1.3 のみ許可 (TLS 1.0/1.1/1.2 を無効化)
  minVersion: "TLSv1.3",
  // 強い暗号スイートのみ許可
  ciphers: [
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256",
  ].join(":"),
});

// FALLBACK_SCSV の検証 (概念実装)
function checkFallbackSCSV(offeredCiphers: string[], negotiatedVersion: string, serverMaxVersion: string): boolean {
  const hasFallbackSCSV = offeredCiphers.includes("TLS_FALLBACK_SCSV");
  if (hasFallbackSCSV && negotiatedVersion < serverMaxVersion) {
    // inappropriate_fallback アラートを送信して接続を中断する
    throw new Error("inappropriate_fallback: TLS downgrade detected");
  }
  return true;
}
```

**参考リンク**:
- RFC 7507 (TLS Fallback SCSV): https://tools.ietf.org/html/rfc7507
- CWE-757: https://cwe.mitre.org/data/definitions/757.html
- CAPEC-220: https://capec.mitre.org/data/definitions/220.html

#### API 契約

```
POST /api/tls/attack/version-downgrade
```

**リクエスト**:

```json
{
  "mitmEnabled": true,
  "fallbackScsvEnabled": false
}
```

| フィールド | 型 | 必須 | 説明 |
|-----------|---|------|------|
| `mitmEnabled` | `boolean` | 必須 | `true` の場合、ClientHello のダウングレード改竄をシミュレート |
| `fallbackScsvEnabled` | `boolean` | 任意 | `true` の場合、サーバー側で TLS_FALLBACK_SCSV を確認してダウングレードを拒否する (デフォルト `false`) |

**レスポンス (MITM 有効、SCSV なし — 攻撃成立)**:

```json
{
  "success": true,
  "data": {
    "scenarioId": "tls-version-downgrade",
    "outcome": "succeeded",
    "startedAt": 1745592000000,
    "finishedAt": 1745592000120,
    "steps": [
      {
        "id": "step-1",
        "kind": "intercept",
        "label": "Intercept ClientHello (client offers TLS 1.0–1.3)",
        "labelJa": "ClientHello を傍受 — クライアントは TLS 1.0-1.3 を提示",
        "status": "success",
        "payload": { "type": "tls", "version": "TLS 1.3", "cipherSuite": "TLS_AES_256_GCM_SHA384" },
        "timestamp": 1745592000020
      },
      {
        "id": "step-2",
        "kind": "tamper",
        "label": "MITM removes TLS 1.2/1.3 from supported_versions",
        "labelJa": "MITM が supported_versions から TLS 1.2/1.3 を削除",
        "status": "success",
        "payload": { "type": "tls", "version": "TLS 1.3", "downgradedTo": "TLS 1.0", "weakCipherSuite": "TLS_RSA_WITH_RC4_128_MD5" },
        "timestamp": 1745592000050
      },
      {
        "id": "step-3",
        "kind": "probe",
        "label": "Server accepts TLS 1.0 (no SCSV check)",
        "labelJa": "サーバーが TLS 1.0 を受け入れる (SCSV チェックなし)",
        "status": "success",
        "payload": { "type": "tls", "downgradedTo": "TLS 1.0", "weakCipherSuite": "TLS_RSA_WITH_RC4_128_MD5" },
        "timestamp": 1745592000090
      }
    ],
    "summary": "MITM forced TLS 1.0 with RC4. No downgrade protection was in place.",
    "summaryJa": "MITM が TLS 1.0+RC4 に強制ダウングレードしました。ダウングレード保護が存在しませんでした。"
  },
  "_trace": {
    "cryptoOps": [
      {
        "op": "tls.negotiateVersion (vulnerable)",
        "input": "offered=[TLS 1.0] (downgraded by MITM)",
        "output": "TLS 1.0 accepted",
        "algo": "TLS version negotiation",
        "detail": "No TLS_FALLBACK_SCSV check. Server accepted the MITM-downgraded version."
      }
    ],
    "attackSteps": [ /* AttackStep[] */ ]
  }
}
```

**レスポンス (SCSV 有効 — ブロック)**:

```json
{
  "success": true,
  "data": {
    "scenarioId": "tls-version-downgrade",
    "outcome": "blocked",
    "blockedBy": "TLS_FALLBACK_SCSV",
    "steps": [
      {
        "id": "step-4",
        "kind": "blocked",
        "label": "Server with TLS_FALLBACK_SCSV detects downgrade and aborts",
        "labelJa": "TLS_FALLBACK_SCSV を実装したサーバーがダウングレードを検知し接続を中断",
        "status": "blocked",
        "payload": { "type": "tls", "version": "TLS 1.0", "cipherSuite": "TLS_FALLBACK_SCSV" },
        "timestamp": 1745592000100
      }
    ],
    "summary": "TLS_FALLBACK_SCSV detected the forced downgrade. Server sent inappropriate_fallback alert.",
    "summaryJa": "TLS_FALLBACK_SCSV が強制ダウングレードを検知し、サーバーが inappropriate_fallback アラートを送信しました。"
  },
  "_trace": { /* ... */ }
}
```

#### _trace 内訳

| trace 種別 | 内容 |
|-----------|------|
| `CryptoOp` | `tls.negotiateVersion (vulnerable)` — SCSV なしでの TLS 1.0 受け入れ、または SCSV ありでのダウングレード検知 |
| `AttackStep` | intercept → tamper → probe (攻撃成立) / intercept → tamper → blocked (防御成立) |
| `DbQuery` | なし (このシナリオは DB アクセス不要) |

#### UI フロー

```
[Attacker View 起動]
  ↓
[教育用バナー表示: 常時固定]
  ↓
[シナリオセレクタ: "バージョンダウングレード攻撃" を選択]
  ↓
[設定エリア]
  - MITM モード: ON (固定 — このシナリオの前提)
  - TLS_FALLBACK_SCSV トグル: OFF (脆弱) / ON (防御済み) ← 教材の核心
  ↓
[「攻撃を実行」ボタン]
  ↓
[AttackStepTimeline アニメーション]
  step-1 intercept: ClientHello 傍受 → SUCCESS
  step-2 tamper:    TLS 1.2/1.3 削除 → SUCCESS (オレンジ)
  step-3 probe:     SCSV OFF → TLS 1.0 受け入れ SUCCESS / SCSV ON → BLOCKED (緑)
  step-4 blocked:   SCSV による検知 (SCSV ON 時のみ)
  ↓
[AttackResultBanner]
  SCSV OFF: "この実装は脆弱です: TLS_FALLBACK_SCSV がないため、ダウングレードが成立しました"
  SCSV ON:  "防御が機能しました: TLS_FALLBACK_SCSV がダウングレードを検知し接続を中断しました"
  ↓
[AttackDefensePanel: TLS_FALLBACK_SCSV の仕組みと設定方法]
  ↓
[DataFlowPanel: HTTP / Trace (CryptoOp) ]
```

---

### 4.2 `tls-self-signed-mitm`

#### 概要

これは **CWE-295 / CWE-300 / CAPEC-94** の概念実証である。
攻撃者がクライアントとサーバーの間に割り込み、自身が作成した **自己署名証明書** を
サーバーの証明書に見せかけてクライアントに提示する MITM (中間者) 攻撃をシミュレーションする。

証明書の **CA チェーン検証** が正しく行われている場合、クライアントは攻撃者の証明書が
信頼された CA によって署名されていないことを検知し、接続を拒否する。
しかし、クライアントの証明書検証が無効化されていたり、ユーザーが警告を無視して
例外を追加した場合、攻撃者はクライアントとの TLS 通信を傍受・復号できる。

既存の `TlsDeepDive` は `GET /api/tls/certificate` で教育用の自己署名証明書を生成している。
このシナリオでは、攻撃者が同様の自己署名証明書を偽造して提示した場合、
クライアントがどのように（すべきか / 実際にどう）反応するかを比較する。

**実環境との差異の注記 (必須)**:
実環境の MITM 攻撃では ARP スプーフィングや DNS ポイズニング等でネットワーク経路への
割り込みが必要です。このデモはその手順を省略し、証明書検証の ON/OFF の差を概念的に示します。

#### CWE / CAPEC / OSI 層

| 項目 | 値 |
|------|-----|
| CWE | CWE-295 (Improper Certificate Validation), CWE-300 (Channel Accessible by Non-Endpoint) |
| CAPEC | CAPEC-94 (Adversary in the Middle) |
| OSI 層 | Layer 5 — Session |
| 深刻度 | High |

#### 前提条件

攻撃者は以下の条件を満たしている:

1. クライアントとサーバーの間のネットワーク経路に MITM として介入可能
2. 攻撃者は標的サーバー名 (CN) を持つ自己署名証明書を生成済み
3. クライアントが証明書の CA チェーン検証を無効化している、またはユーザーが警告を無視している

**脆弱な実装例** (このシナリオでシミュレーションする実装):

```typescript
// 脆弱なクライアント設定例 (教育用シミュレーション専用)
// NODE_TLS_REJECT_UNAUTHORIZED=0 相当の設定
const vulnerableHttpsAgent = new https.Agent({
  rejectUnauthorized: false,  // 証明書検証を完全無効化 — 絶対に本番で使用しない
});

// または fetch の場合
const res = await fetch("https://example.com", {
  // @ts-ignore
  agent: vulnerableHttpsAgent,  // 自己署名証明書を含むあらゆる証明書を受け入れる
});
```

#### 攻撃ステップ (AttackStep[] の具体例)

```typescript
const steps: AttackStep[] = [
  {
    id: "step-1",
    kind: "forge",
    label: "Attacker creates self-signed certificate for target domain",
    labelJa: "攻撃者が標的ドメイン向けの自己署名証明書を作成",
    status: "success",
    payload: {
      type: "tls",
      fakeCertificate: {
        subject: "CN=localhost, O=Attacker Corp",
        issuer: "CN=localhost, O=Attacker Corp",  // 自己署名: subject = issuer
        selfSigned: true,
      },
    },
    detail: "The attacker generates a self-signed certificate impersonating the legitimate server.",
    detailJa: "攻撃者は正規サーバーになりすます自己署名証明書を生成します。",
    timestamp: Date.now(),
  },
  {
    id: "step-2",
    kind: "intercept",
    label: "MITM intercepts TLS handshake and presents fake certificate",
    labelJa: "MITM が TLS ハンドシェイクを傍受し偽証明書を提示",
    status: "success",
    payload: {
      type: "tls",
      certificate: {
        subject: "CN=localhost, O=OSI Demo, C=JP",
        issuer: "CN=OSI Demo CA, O=OSI Demo, C=JP",
        validFrom: new Date().toISOString(),
        validTo: new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString(),
        selfSigned: false,
      },
      fakeCertificate: {
        subject: "CN=localhost, O=Attacker Corp",
        issuer: "CN=localhost, O=Attacker Corp",
        selfSigned: true,
      },
    },
    detail: "The attacker substitutes the legitimate certificate with their self-signed one.",
    detailJa: "攻撃者は正規の証明書を自己署名証明書に差し替えます。",
    timestamp: Date.now(),
  },
  {
    id: "step-3",
    kind: "exploit",
    label: "Client with validation disabled accepts fake cert — MITM established",
    labelJa: "証明書検証を無効化したクライアントが偽証明書を受け入れ — MITM 成立",
    status: "success",
    payload: {
      type: "generic",
      data: {
        certValidationEnabled: false,
        fakeCertAccepted: true,
        mitmEstablished: true,
        interceptedData: "HTTP GET /api/auth... (plaintext to attacker)",
        interceptedDataJa: "HTTP GET /api/auth... (攻撃者に対して平文)",
      },
    },
    detail: "With certificate validation disabled, the client establishes a TLS connection with the attacker. All data is readable by the MITM.",
    detailJa: "証明書検証が無効の場合、クライアントは攻撃者と TLS 接続を確立します。すべてのデータが MITM に読まれます。",
    timestamp: Date.now(),
  },
  {
    id: "step-4",
    kind: "blocked",
    label: "Client with CA validation rejects self-signed cert",
    labelJa: "CA 検証を有効にしたクライアントが自己署名証明書を拒否",
    status: "blocked",
    payload: {
      type: "tls",
      fakeCertificate: {
        subject: "CN=localhost, O=Attacker Corp",
        issuer: "CN=localhost, O=Attacker Corp",
        selfSigned: true,
      },
    },
    detail: "Certificate chain validation fails: the issuer is not in the trusted root store. Connection is aborted with certificate_unknown alert.",
    detailJa: "証明書チェーン検証が失敗: 発行者が信頼されたルートストアに存在しません。certificate_unknown アラートで接続が中断されます。",
    timestamp: Date.now(),
  },
];
```

#### 期待される結果 (AttackResult)

```typescript
const result: AttackResult = {
  scenarioId: "tls-self-signed-mitm",
  outcome: "succeeded",  // 証明書検証無効時は攻撃が成立
  startedAt: /* Unix ms */,
  finishedAt: /* Unix ms */,
  steps,
  blockedBy: "クライアント CA チェーン検証 (rejectUnauthorized: true)",
  summary: "With certificate validation disabled, the self-signed MITM cert was accepted. With validation enabled, the connection was aborted.",
  summaryJa: "証明書検証が無効の場合、自己署名 MITM 証明書が受け入れられました。検証が有効の場合は接続が中断されました。",
};
```

#### 防御策 (defenseRecommendation)

**既存実装ファイルへのリンク**:
- `server/routes/tls-sim.ts:206-244` — `GET /certificate` での証明書表示
  (`explanation.chain`, `explanation.verification` フィールドで CA チェーンの概念を説明)

**防御策の要点**:

1. クライアントの証明書検証を絶対に無効化しない (`NODE_TLS_REJECT_UNAUTHORIZED=0` は厳禁)
2. CA チェーン検証: 信頼されたルート CA の署名が連鎖していることを確認する
3. Certificate Pinning: 特定の証明書または公開鍵のフィンガープリントを事前に固定する
4. 証明書の有効期限・ドメイン名 (CN/SAN) の一致を確認する

**codeHints の具体例**:

```typescript
import https from "https";
import fs from "fs";

// 安全な実装: 信頼するルート CA 証明書を明示指定
const secureAgent = new https.Agent({
  // rejectUnauthorized: true (デフォルト — 変更禁止)
  ca: fs.readFileSync("/path/to/trusted-ca.crt"),  // 信頼する CA を明示
});

// Certificate Pinning の概念実装
function verifyCertPin(cert: tls.PeerCertificate, expectedPin: string): boolean {
  const publicKeyDer = cert.raw;
  const actualPin = crypto
    .createHash("sha256")
    .update(publicKeyDer)
    .digest("base64");
  return actualPin === expectedPin;
}
```

#### API 契約

```
POST /api/tls/attack/self-signed-mitm
```

**リクエスト**:

```json
{
  "certValidationEnabled": false
}
```

| フィールド | 型 | 必須 | 説明 |
|-----------|---|------|------|
| `certValidationEnabled` | `boolean` | 必須 | `false` の場合、クライアントが証明書検証を無効化した状態をシミュレート |

**レスポンス (検証無効 — 攻撃成立)**:

```json
{
  "success": true,
  "data": {
    "scenarioId": "tls-self-signed-mitm",
    "outcome": "succeeded",
    "startedAt": 1745592000000,
    "finishedAt": 1745592000200,
    "steps": [ /* step-1〜3 */ ],
    "summary": "Certificate validation was disabled. Self-signed MITM cert accepted.",
    "summaryJa": "証明書検証が無効でした。自己署名 MITM 証明書が受け入れられました。"
  },
  "_trace": {
    "cryptoOps": [
      {
        "op": "generateSelfSignedCert (attacker)",
        "input": "subject=CN=localhost, O=Attacker Corp",
        "output": "selfSigned=true, issuer=self",
        "algo": "RSA-2048 (self-signed)",
        "detail": "Attacker generates a self-signed certificate impersonating the legitimate server."
      },
      {
        "op": "certChainValidation (disabled)",
        "input": "rejectUnauthorized=false",
        "output": "SKIPPED — any certificate accepted",
        "algo": "X.509 chain validation",
        "detail": "Certificate validation was disabled. Self-signed cert accepted without CA verification."
      }
    ],
    "attackSteps": [ /* AttackStep[] */ ]
  }
}
```

**レスポンス (検証有効 — ブロック)**:

```json
{
  "success": true,
  "data": {
    "scenarioId": "tls-self-signed-mitm",
    "outcome": "blocked",
    "blockedBy": "ca_chain_validation",
    "steps": [ /* step-1〜2 + step-4 */ ],
    "summary": "CA chain validation rejected the self-signed certificate.",
    "summaryJa": "CA チェーン検証が自己署名証明書を拒否しました。"
  },
  "_trace": {
    "cryptoOps": [
      {
        "op": "certChainValidation",
        "input": "cert=CN=localhost O=Attacker Corp (self-signed)",
        "output": "FAILED: issuer not in trusted root store",
        "algo": "X.509 chain validation",
        "detail": "The certificate issuer was not found in the trusted CA store. Connection aborted."
      }
    ],
    "attackSteps": [ /* AttackStep[] */ ]
  }
}
```

#### _trace 内訳

| trace 種別 | 内容 |
|-----------|------|
| `CryptoOp` | `generateSelfSignedCert (attacker)` — 攻撃者による偽証明書生成 (RSA-2048, 自己署名) |
| `CryptoOp` | `certChainValidation` — クライアント側の CA チェーン検証結果 (SKIPPED / FAILED) |
| `AttackStep` | forge → intercept → exploit (検証無効時) / forge → intercept → blocked (検証有効時) |
| `DbQuery` | なし |

#### UI フロー

```
[Attacker View 起動]
  ↓
[教育用バナー表示: 常時固定]
  ↓
[シナリオセレクタ: "自己署名証明書 MITM" を選択]
  ↓
[設定エリア]
  - 証明書検証: OFF (脆弱) / ON (防御済み) ← 教材の核心
  ↓
[「攻撃を実行」ボタン]
  ↓
[AttackStepTimeline アニメーション]
  step-1 forge:     偽証明書作成 → SUCCESS (オレンジ)
  step-2 intercept: ハンドシェイク傍受・偽証明書提示 → SUCCESS
  step-3 exploit:   検証 OFF → MITM 成立 (オレンジ) / step-4 blocked: 検証 ON → 拒否 (緑)
  ↓
[正規証明書 vs 偽証明書の比較表示]
  legitimate: subject=CN=localhost, O=OSI Demo, issuer=CN=OSI Demo CA (CA 署名)
  fake:       subject=CN=localhost, O=Attacker Corp, issuer=CN=localhost (自己署名)
  ↓
[AttackResultBanner]
  検証 OFF: "この実装は脆弱です: 証明書検証が無効のため MITM が成立しました"
  検証 ON:  "防御が機能しました: CA チェーン検証が自己署名証明書を拒否しました"
  ↓
[AttackDefensePanel: CA チェーン検証・Certificate Pinning の実装方法]
  ↓
[DataFlowPanel: HTTP / Trace (CryptoOp) ]
```

---

### 4.3 `tls-weak-cipher-negotiation`

#### 概要

これは **CWE-327 / CAPEC-220** の概念実証である。
サーバーが TLS 1.3 に加えて古い暗号スイート
(RC4, 3DES/TDEA, NULL 暗号, EXPORT 暗号等) を引き続きサポートしている場合、
MITM 攻撃者が ClientHello を改竄して弱い暗号スイートのみを提示することで、
安全でない暗号でのネゴシエーションを強制できる。

RC4 は統計的バイアスによる既知平文攻撃 (RC4 Biases Attack)、
3DES は Sweet32 攻撃 (誕生日境界攻撃による CBC の IV 衝突) の対象となり、
通信内容の解読やセッションの復号が可能になる。

TLS 1.3 は設計上これらの問題を解消しているが、後方互換性のために弱い暗号スイートを
残したままのサーバー設定は重大なリスクをはらんでいる。

このシナリオでは「弱い暗号スイートのみをサポートするサーバー」と
「推奨暗号スイートのみをサポートするサーバー」への接続を比較し、暗号スイート選択の重要性を示す。

**実環境との差異の注記 (必須)**:
実環境では古い暗号スイートの無効化により、RC4/3DES を使った攻撃の成立は
現代の設定では非常に困難です。このデモは古い設定を残したレガシーサーバーへの
攻撃を概念的に示します。

#### CWE / CAPEC / OSI 層

| 項目 | 値 |
|------|-----|
| CWE | CWE-327 (Use of a Broken or Risky Cryptographic Algorithm) |
| CAPEC | CAPEC-220 (Client-Server Protocol Manipulation) |
| OSI 層 | Layer 5 — Session |
| 深刻度 | High |

#### 前提条件

攻撃者は以下の条件を満たしている:

1. クライアントとサーバーの間のネットワーク経路に MITM として介入可能
2. サーバーが後方互換性のために RC4/3DES 等の廃止された暗号スイートをサポートしている
3. 攻撃者は ClientHello の `cipher_suites` リストを書き換えられる

**脆弱な実装例** (このシナリオでシミュレーションする実装):

```typescript
// 脆弱なサーバー設定例 (教育用シミュレーション専用)
// 廃止された暗号スイートを後方互換性のために残した場合
const weakServerCiphers = [
  "RC4-MD5",           // RC4 + MD5 (統計バイアス攻撃に脆弱)
  "DES-CBC3-SHA",      // 3DES-CBC (Sweet32 攻撃に脆弱)
  "NULL-SHA",          // NULL 暗号 (暗号化なし)
  "TLS_AES_256_GCM_SHA384",  // 強い暗号も一応サポート
].join(":");

// 攻撃者が弱い暗号スイートのみを提示 → サーバーが受け入れる
const tamperedClientHello = {
  cipherSuites: ["RC4-MD5"],  // 強い暗号を削除し、弱い暗号のみ提示
};
```

#### 攻撃ステップ (AttackStep[] の具体例)

```typescript
const steps: AttackStep[] = [
  {
    id: "step-1",
    kind: "probe",
    label: "Enumerate server-supported cipher suites (includes weak ciphers)",
    labelJa: "サーバーがサポートする暗号スイートを列挙 (弱い暗号スイートを含む)",
    status: "success",
    payload: {
      type: "generic",
      data: {
        serverSupportedCiphers: [
          "TLS_AES_256_GCM_SHA384",
          "TLS_RSA_WITH_RC4_128_MD5",
          "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
          "TLS_NULL_WITH_NULL_NULL",
        ],
        weakCiphersPresent: true,
        probeMethod: "ClientHello with comprehensive cipher list",
        probeMethodJa: "包括的な暗号リストを持つ ClientHello での列挙",
      },
    },
    detail: "The attacker probes the server to discover which cipher suites it accepts, including weak ones.",
    detailJa: "攻撃者はサーバーがどの暗号スイートを受け入れるかを調べ、弱い暗号スイートの存在を確認します。",
    timestamp: Date.now(),
  },
  {
    id: "step-2",
    kind: "tamper",
    label: "MITM strips strong ciphers from ClientHello — only RC4 remains",
    labelJa: "MITM が ClientHello から強い暗号スイートを削除 — RC4 のみ残す",
    status: "success",
    payload: {
      type: "tls",
      cipherSuite: "TLS_AES_256_GCM_SHA384",
      weakCipherSuite: "TLS_RSA_WITH_RC4_128_MD5",
    },
    detail: "MITM modifies the ClientHello, removing all strong cipher suites and leaving only RC4.",
    detailJa: "MITM は ClientHello を改竄し、すべての強い暗号スイートを削除して RC4 のみを残します。",
    timestamp: Date.now(),
  },
  {
    id: "step-3",
    kind: "exploit",
    label: "Server negotiates RC4 — weak cipher session established",
    labelJa: "サーバーが RC4 でネゴシエーション — 弱い暗号スイートのセッション確立",
    status: "success",
    payload: {
      type: "tls",
      downgradedTo: "TLS 1.2",
      weakCipherSuite: "TLS_RSA_WITH_RC4_128_MD5",
    },
    detail: "The server accepts RC4 for backward compatibility. Session data is encrypted with a broken algorithm.",
    detailJa: "サーバーは後方互換性のために RC4 を受け入れます。セッションデータは破られた暗号アルゴリズムで暗号化されます。",
    timestamp: Date.now(),
  },
  {
    id: "step-4",
    kind: "verify",
    label: "Server with cipher allowlist rejects RC4 — strong cipher enforced",
    labelJa: "暗号スイートの許可リストを持つサーバーが RC4 を拒否 — 強い暗号を強制",
    status: "blocked",
    payload: {
      type: "generic",
      data: {
        serverPolicy: "allowlist: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256 only",
        serverPolicyJa: "許可リスト: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256 のみ",
        rc4Rejected: true,
        negotiationResult: "handshake_failure alert (no common cipher suite)",
        negotiationResultJa: "handshake_failure アラート (共通の暗号スイートなし)",
      },
    },
    detail: "With a strict cipher allowlist, the server finds no acceptable common cipher and rejects the handshake.",
    detailJa: "厳格な暗号許可リストにより、サーバーは受け入れ可能な共通暗号スイートを見つけられず、ハンドシェイクを拒否します。",
    timestamp: Date.now(),
  },
];
```

#### 期待される結果 (AttackResult)

```typescript
const result: AttackResult = {
  scenarioId: "tls-weak-cipher-negotiation",
  outcome: "succeeded",  // 弱い暗号スイートを許可するサーバーでは攻撃が成立
  startedAt: /* Unix ms */,
  finishedAt: /* Unix ms */,
  steps,
  blockedBy: "暗号スイート許可リスト (AEAD のみ許可)",
  summary: "Server supporting RC4 negotiated a weak cipher when forced by MITM. Strict allowlist blocked the attack.",
  summaryJa: "RC4 をサポートするサーバーは MITM に強制されて弱い暗号でネゴシエーションしました。厳格な許可リストで攻撃は阻止されました。",
};
```

#### 防御策 (defenseRecommendation)

**既存実装ファイルへのリンク**:
- `server/routes/tls-sim.ts:84-93` — `supportedCipherSuites` で `TLS_AES_256_GCM_SHA384`,
  `TLS_AES_128_GCM_SHA256`, `TLS_CHACHA20_POLY1305_SHA256` のみ提示 (RC4/3DES を含まない)
- `server/routes/tls-sim.ts:118-122` — `selectCipherSuite` で最強の暗号スイートを選択

**防御策の要点**:

1. RC4・3DES (TDEA)・NULL 暗号・EXPORT 暗号・DES を暗号スイートから完全に除外する
2. TLS 1.3 の AEAD 暗号スイートのみを許可する (AES-GCM, ChaCha20-Poly1305)
3. `SSLCipherSuite` (Apache) / `ssl_ciphers` (nginx) / `ciphers` (Node.js tls) で明示的な許可リストを設定する
4. Qualys SSL Labs 等のツールで定期的に暗号スイート設定を検証する

**codeHints の具体例**:

```typescript
import tls from "tls";

// 安全な暗号スイート設定 (TLS 1.3 AEAD のみ)
const secureServer = tls.createServer({
  minVersion: "TLSv1.3",
  // TLS 1.3 では ciphers オプションは限定的。実質的に以下の3つのみが有効
  // TLS_AES_256_GCM_SHA384 / TLS_CHACHA20_POLY1305_SHA256 / TLS_AES_128_GCM_SHA256
  // ← OpenSSL はこれらをデフォルトで有効化する
});

// TLS 1.2 も許可する場合の安全な設定 (後方互換性が必要な場合)
const compatServer = tls.createServer({
  minVersion: "TLSv1.2",
  ciphers: [
    // TLS 1.3 スイート
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256",
    // TLS 1.2 の安全なスイート (ECDHE + AEAD)
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    // 以下は含めない: RC4, 3DES, DES, NULL, EXPORT, anon
  ].join(":"),
  honorCipherOrder: true,  // サーバー側の優先順位を強制する
});
```

#### API 契約

```
POST /api/tls/attack/weak-cipher
```

**リクエスト**:

```json
{
  "mitmEnabled": true,
  "serverAllowWeakCiphers": true
}
```

| フィールド | 型 | 必須 | 説明 |
|-----------|---|------|------|
| `mitmEnabled` | `boolean` | 必須 | `true` の場合、ClientHello から強い暗号スイートを削除する改竄をシミュレート |
| `serverAllowWeakCiphers` | `boolean` | 必須 | `true` の場合、脆弱なサーバー (RC4/3DES を許可) としてシミュレート。`false` の場合、強い暗号のみ許可するサーバー |

**レスポンス (弱い暗号許可サーバー — 攻撃成立)**:

```json
{
  "success": true,
  "data": {
    "scenarioId": "tls-weak-cipher-negotiation",
    "outcome": "succeeded",
    "startedAt": 1745592000000,
    "finishedAt": 1745592000150,
    "steps": [ /* step-1〜3 */ ],
    "summary": "Server supporting RC4 negotiated a weak cipher when MITM stripped strong ciphers.",
    "summaryJa": "RC4 をサポートするサーバーは MITM が強い暗号を削除した後、弱い暗号でネゴシエーションしました。"
  },
  "_trace": {
    "cryptoOps": [
      {
        "op": "cipherSuiteNegotiation (vulnerable server)",
        "input": "client offered: [RC4-MD5] (MITM stripped strong ciphers)",
        "output": "negotiated: TLS_RSA_WITH_RC4_128_MD5",
        "algo": "RC4-MD5 (BROKEN)",
        "detail": "Server accepted RC4 for backward compatibility. RC4 has known statistical biases enabling plaintext recovery."
      }
    ],
    "attackSteps": [ /* AttackStep[] */ ]
  }
}
```

**レスポンス (強い暗号のみ許可サーバー — ブロック)**:

```json
{
  "success": true,
  "data": {
    "scenarioId": "tls-weak-cipher-negotiation",
    "outcome": "blocked",
    "blockedBy": "cipher_allowlist",
    "steps": [ /* step-1〜2 + step-4 */ ],
    "summary": "Strict cipher allowlist found no common cipher suite. Handshake failed.",
    "summaryJa": "厳格な暗号許可リストにより共通の暗号スイートが見つからず、ハンドシェイクが失敗しました。"
  },
  "_trace": {
    "cryptoOps": [
      {
        "op": "cipherSuiteNegotiation (strict server)",
        "input": "client offered: [RC4-MD5], server accepts: [AES_256_GCM_SHA384, CHACHA20_POLY1305_SHA256]",
        "output": "FAILED: no common cipher suite (handshake_failure)",
        "algo": "cipher allowlist enforcement",
        "detail": "Server's strict allowlist does not include RC4. Handshake aborted with handshake_failure alert."
      }
    ],
    "attackSteps": [ /* AttackStep[] */ ]
  }
}
```

#### _trace 内訳

| trace 種別 | 内容 |
|-----------|------|
| `CryptoOp` | `cipherSuiteNegotiation` — 脆弱サーバーでの RC4 受け入れ / 厳格サーバーでの handshake_failure |
| `CryptoOp` | `probe.enumerateCiphers` — サーバーがサポートする暗号スイートの列挙結果 |
| `AttackStep` | probe → tamper → exploit (弱い暗号許可時) / probe → tamper → blocked (許可リスト時) |
| `DbQuery` | なし |

#### UI フロー

```
[Attacker View 起動]
  ↓
[教育用バナー表示: 常時固定]
  ↓
[シナリオセレクタ: "弱い暗号スイートネゴシエーション" を選択]
  ↓
[設定エリア]
  - MITM モード: ON (固定)
  - サーバー暗号ポリシー: 弱い暗号を許可 (脆弱) / 推奨暗号のみ (防御済み) ← 教材の核心
  ↓
[「攻撃を実行」ボタン]
  ↓
[AttackStepTimeline アニメーション]
  step-1 probe:   暗号スイート列挙 → SUCCESS
  step-2 tamper:  強い暗号スイートを削除 → SUCCESS (オレンジ)
  step-3 exploit: 弱い暗号許可 → RC4 ネゴシエーション (オレンジ) / step-4 blocked: 許可リスト → 拒否 (緑)
  ↓
[暗号スイート比較テーブル]
  攻撃者が提示: RC4-MD5 のみ
  脆弱サーバー: RC4-MD5 を受け入れ → 暗号化強度の評価: 非常に弱い
  安全なサーバー: handshake_failure (共通の暗号スイートなし)
  ↓
[AttackResultBanner]
  弱い暗号許可: "この実装は脆弱です: RC4 等の廃止された暗号スイートがネゴシエーションを受け入れました"
  許可リスト:   "防御が機能しました: 暗号スイート許可リストが RC4 を拒否し、ハンドシェイクを中断しました"
  ↓
[AttackDefensePanel: 推奨暗号スイートの設定方法・Qualys SSL Labs でのテスト]
  ↓
[DataFlowPanel: HTTP / Trace (CryptoOp) ]
```

---

## 5. UI コンポーネント設計

### 5.1 ディレクトリ構成

```
src/components/auth/attacks/tls-deep/
├── TlsAttackPanel.tsx               ← 3シナリオを統括するメインパネル
├── VersionDowngradeScenario.tsx     ← シナリオ A の実行ロジックと SCSV トグル
├── SelfSignedMitmScenario.tsx       ← シナリオ B の実行ロジックと証明書比較表示
├── WeakCipherScenario.tsx           ← シナリオ C の実行ロジックと暗号スイート比較テーブル
└── TlsAttack.css                    ← 3シナリオ共通スタイル
```

### 5.2 `TlsAttackPanel.tsx` の責務

```typescript
// TlsDeepDive.tsx への組み込みイメージ
import TlsAttackPanel from "./attacks/tls-deep/TlsAttackPanel";
import { Show } from "solid-js";

// viewMode Signal で Attacker View を管理
<Show when={viewMode() === "attacker"}>
  <TlsAttackPanel tabId="tls-deep" />
</Show>
```

`TlsAttackPanel` は以下を担当する:

1. `EducationalWarningBanner` の常時表示
2. `AttackScenarioSelector` で3シナリオの切り替え
3. 選択中シナリオに対応する各シナリオコンポーネントのレンダリング
4. `DataFlowPanel scopeId="attack-tls-deep"` の表示

### 5.3 各シナリオコンポーネントの props 設計

```typescript
// VersionDowngradeScenario.tsx
interface VersionDowngradeScenarioProps {
  onResult: (result: AttackResult) => void;
  onRunning: (running: boolean) => void;
}
// 入力: mitmEnabled (固定 ON), fallbackScsvEnabled (トグル)

// SelfSignedMitmScenario.tsx
interface SelfSignedMitmScenarioProps {
  onResult: (result: AttackResult) => void;
  onRunning: (running: boolean) => void;
}
// 入力: certValidationEnabled (トグル), 証明書比較表示パネル

// WeakCipherScenario.tsx
interface WeakCipherScenarioProps {
  onResult: (result: AttackResult) => void;
  onRunning: (running: boolean) => void;
}
// 入力: mitmEnabled (固定 ON), serverAllowWeakCiphers (トグル), 暗号スイート一覧表示
```

### 5.4 証明書比較パネルの設計 (シナリオ B 専用)

シナリオ B では、正規証明書と偽証明書を並列表示するパネルを設ける。

```
┌─────────────────────┐   ┌─────────────────────┐
│  正規証明書 ✓       │   │  攻撃者の偽証明書 ✗  │
│  Subject: CN=...    │   │  Subject: CN=...     │
│  Issuer: OSI Demo CA│   │  Issuer: Attacker    │  ← 発行者が自分自身
│  CA署名: あり       │   │  CA署名: なし        │
│  ルートCA連鎖: あり  │   │  ルートCA連鎖: なし   │
└─────────────────────┘   └─────────────────────┘
```

---

## 6. テスト要件

### 6.1 ユニットテスト (バックエンドハンドラ単体)

対象ファイル: `server/routes/tls-sim.ts` への攻撃サブパス追加分

| テスト ID | 検証内容 | 期待結果 |
|---------|---------|---------|
| `tls-atk-01` | `POST /attack/version-downgrade` に `mitmEnabled: true, fallbackScsvEnabled: false` を送信 | `outcome: "succeeded"`, step-3 の `status: "success"`, `weakCipherSuite: "TLS_RSA_WITH_RC4_128_MD5"` を含む |
| `tls-atk-02` | `POST /attack/version-downgrade` に `fallbackScsvEnabled: true` を送信 | `outcome: "blocked"`, `blockedBy: "TLS_FALLBACK_SCSV"`, step-4 の `status: "blocked"` を含む |
| `tls-atk-03` | `POST /attack/self-signed-mitm` に `certValidationEnabled: false` を送信 | `outcome: "succeeded"`, step-3 に `mitmEstablished: true` を含む |
| `tls-atk-04` | `POST /attack/self-signed-mitm` に `certValidationEnabled: true` を送信 | `outcome: "blocked"`, `blockedBy: "ca_chain_validation"`, step-4 の `status: "blocked"` を含む |
| `tls-atk-05` | `POST /attack/weak-cipher` に `serverAllowWeakCiphers: true` を送信 | `outcome: "succeeded"`, `_trace.cryptoOps` に `RC4-MD5` ネゴシエーション記録を含む |
| `tls-atk-06` | `POST /attack/weak-cipher` に `serverAllowWeakCiphers: false` を送信 | `outcome: "blocked"`, `blockedBy: "cipher_allowlist"`, `handshake_failure` を含む |
| `tls-atk-07` | `POST /attack/version-downgrade` にボディなしで送信 | `400 Bad Request` (バリデーションエラー) |
| `tls-atk-08` | 本番環境 (`NODE_ENV=production`) でいずれかの攻撃エンドポイントに送信 | `403 Forbidden` |
| `tls-atk-09` | すべての攻撃レスポンスに `_trace.attackSteps` が含まれることを確認 | `_trace.attackSteps.length >= 2` |

### 6.2 E2E テスト (UI フロー)

対象: `src/components/auth/attacks/tls-deep/TlsAttackPanel.tsx`

| テスト ID | 操作 | 期待結果 |
|---------|------|---------|
| `e2e-tls-01` | TlsDeepDive タブで Attacker View に切り替える | `EducationalWarningBanner` が表示される、通常の TLS ハンドシェイクデモが非表示になる |
| `e2e-tls-02` | シナリオ A を選択、SCSV OFF で「攻撃を実行」を押す | step-3 がオレンジ色の SUCCESS で表示される |
| `e2e-tls-03` | シナリオ A で SCSV ON にして「攻撃を実行」を押す | `AttackResultBanner` が緑色 (防御成立) で表示される |
| `e2e-tls-04` | シナリオ B を選択、証明書検証 OFF で「攻撃を実行」を押す | 正規証明書 vs 偽証明書の比較パネルが表示される |
| `e2e-tls-05` | シナリオ B で証明書検証 ON にして「攻撃を実行」を押す | `AttackResultBanner` が緑色、step-4 が BLOCKED で表示される |
| `e2e-tls-06` | シナリオ C で弱い暗号許可 ON で「攻撃を実行」を押す | 暗号スイート比較テーブルに RC4 がオレンジ色でハイライトされる |
| `e2e-tls-07` | 攻撃完了後に防御策パネルを確認する | `AttackDefensePanel` が自動展開されている |
| `e2e-tls-08` | Defender View に切り替える | 通常の TLS ハンドシェイクデモが表示され、攻撃バナーが消える |

---

## 7. i18n キー一覧表 (ja/en)

| # | キー概念 | 日本語 | English |
|---|---------|--------|---------|
| 1 | 攻撃者モード切替 | `攻撃者モード` | `Attacker Mode` |
| 2 | 防御者モード切替 | `防御者モード` | `Defender Mode` |
| 3 | 教育バナーテキスト | `教育用シミュレーション — 実環境を攻撃するためのコードではありません` | `Educational simulation — not for use against real systems` |
| 4 | シナリオ A 名 | `バージョンダウングレード攻撃 (TLS 1.0 強制)` | `Version Downgrade Attack (Force TLS 1.0)` |
| 5 | シナリオ B 名 | `自己署名証明書による MITM` | `Self-Signed Certificate MITM` |
| 6 | シナリオ C 名 | `弱い暗号スイートネゴシエーション (RC4/3DES)` | `Weak Cipher Suite Negotiation (RC4/3DES)` |
| 7 | 攻撃実行ボタン | `攻撃を実行` | `Run Attack` |
| 8 | 実行中ラベル | `実行中...` | `Running...` |
| 9 | 攻撃成立バナー | `攻撃成立 — この実装は脆弱です` | `Attack succeeded — this implementation is vulnerable` |
| 10 | 防御成立バナー | `防御が機能しました:` | `Defense succeeded:` |
| 11 | SCSV トグルラベル | `TLS_FALLBACK_SCSV` | `TLS_FALLBACK_SCSV` |
| 12 | SCSV OFF ラベル | `無効 (ダウングレード保護なし)` | `Disabled (no downgrade protection)` |
| 13 | SCSV ON ラベル | `有効 (ダウングレード保護あり)` | `Enabled (downgrade protection)` |
| 14 | 証明書検証トグル | `証明書検証` | `Certificate Validation` |
| 15 | 証明書検証 OFF | `無効 (脆弱な設定)` | `Disabled (vulnerable)` |
| 16 | 証明書検証 ON | `有効 (CA チェーン検証)` | `Enabled (CA chain validation)` |
| 17 | 暗号ポリシートグル | `サーバー暗号ポリシー` | `Server Cipher Policy` |
| 18 | 弱い暗号許可ラベル | `弱い暗号スイートを許可 (脆弱)` | `Allow weak cipher suites (vulnerable)` |
| 19 | 強い暗号のみラベル | `推奨暗号スイートのみ (防御済み)` | `Recommended ciphers only (protected)` |
| 20 | 正規証明書ラベル | `正規サーバー証明書` | `Legitimate Server Certificate` |
| 21 | 偽証明書ラベル | `攻撃者の偽証明書` | `Attacker's Fake Certificate` |
| 22 | 自己署名ラベル | `自己署名 (信頼できない)` | `Self-Signed (untrusted)` |
| 23 | CA 署名ラベル | `CA 署名 (信頼された)` | `CA-Signed (trusted)` |
| 24 | ダウングレード先ラベル | `ダウングレード先` | `Downgraded to` |
| 25 | ネゴシエーション結果ラベル | `ネゴシエーション結果` | `Negotiation result` |
| 26 | handshake_failure ラベル | `ハンドシェイク失敗 (共通暗号スイートなし)` | `Handshake failure (no common cipher suite)` |
| 27 | 暗号強度ラベル | `暗号化強度` | `Encryption strength` |
| 28 | シミュレーション注記 (ダウングレード) | `注: 実環境では TLS 1.0/1.1 はほとんどのサーバーで無効化されています` | `Note: In real environments, TLS 1.0/1.1 is disabled on most modern servers` |
| 29 | シミュレーション注記 (MITM) | `注: 実環境の MITM にはネットワーク経路への介入 (ARP スプーフィング等) が必要です` | `Note: Real MITM requires network path interception (ARP spoofing etc.)` |
| 30 | シミュレーション注記 (RC4) | `注: 実環境では RC4/3DES は現代のサーバー設定では無効化されています` | `Note: In real environments, RC4/3DES are disabled in modern server configurations` |
| 31 | ダウングレード保護説明 | `TLS_FALLBACK_SCSV (RFC 7507) はクライアントの再試行時に含まれる特別な値で、サーバーがダウングレード強制を検知できます` | `TLS_FALLBACK_SCSV (RFC 7507) is a sentinel value included in fallback ClientHello, enabling servers to detect forced downgrades` |
| 32 | forward secrecy ラベル | `前方秘匿性 (Forward Secrecy)` | `Forward Secrecy` |
| 33 | タイムラインARIAラベル | `TLS 攻撃ステップログ` | `TLS attack step log` |
| 34 | 攻撃成立メッセージ A | `この実装は脆弱です: TLS_FALLBACK_SCSV がないため、MITM によるダウングレードが成立しました` | `This implementation is vulnerable: without TLS_FALLBACK_SCSV, MITM downgrade succeeded` |
| 35 | 防御成立メッセージ A | `防御が機能しました: TLS_FALLBACK_SCSV がダウングレードを検知し接続を中断しました` | `Defense succeeded: TLS_FALLBACK_SCSV detected the downgrade and aborted the connection` |
| 36 | 攻撃成立メッセージ B | `この実装は脆弱です: 証明書検証が無効のため、自己署名 MITM 証明書が受け入れられました` | `This implementation is vulnerable: certificate validation was disabled, self-signed MITM cert was accepted` |
| 37 | 防御成立メッセージ B | `防御が機能しました: CA チェーン検証が自己署名証明書を拒否しました` | `Defense succeeded: CA chain validation rejected the self-signed certificate` |
| 38 | 攻撃成立メッセージ C | `この実装は脆弱です: RC4 等の廃止された暗号スイートがネゴシエーションで受け入れられました` | `This implementation is vulnerable: deprecated cipher suites like RC4 were accepted during negotiation` |
| 39 | 防御成立メッセージ C | `防御が機能しました: 暗号スイート許可リストが RC4 を拒否し、ハンドシェイクを中断しました` | `Defense succeeded: cipher suite allowlist rejected RC4 and aborted the handshake` |

---

## 8. 関連ファイル

### 8.1 基盤設計書

| ファイル | 参照目的 |
|---------|---------|
| [DESIGN/00-overview.md](./00-overview.md) | 全体目的・攻撃カタログマトリクス (`tls-deep` タブ行) |
| [DESIGN/01-architecture.md](./01-architecture.md) | バックエンドルート配置方針 (サブパス `/attack/*` 追加) / フロントエンドコンポーネント階層 |
| [DESIGN/02-ui-spec.md](./02-ui-spec.md) | `ViewModeToggle` / `AttackStepTimeline` / `AttackResultBanner` / `AttackDefensePanel` の UI 詳細仕様 |
| [DESIGN/03-data-model.md](./03-data-model.md) | `AttackStep` / `AttackResult` / `AttackStepPayload` (`type: "tls"` フィールド詳細) / `ServerTrace` 拡張 |
| [DESIGN/04-safety-guardrails.md](./04-safety-guardrails.md) | 禁止表現一覧 / ペイロード作成ルール / 開発レビューチェックリスト |

### 8.2 既存実装ファイル (変更・参照対象)

| ファイルパス | 変更種別 | 変更内容 |
|------------|---------|---------|
| `server/routes/tls-sim.ts` | 追加 | `POST /attack/version-downgrade`, `POST /attack/self-signed-mitm`, `POST /attack/weak-cipher` の3エンドポイントを追加 |
| `src/components/auth/TlsDeepDive.tsx` | 追加 | `ViewModeToggle` import + `<Show when={viewMode() === "attacker"}>` ブロックで `TlsAttackPanel` を条件表示 |
| `shared/api-types.ts` | 確認 | `AttackStepPayload` の `type: "tls"` 定義が `DESIGN/03-data-model.md §1.3` で定義済みであることを確認 (`version`, `downgradedTo`, `cipherSuite`, `weakCipherSuite`, `certificate`, `fakeCertificate` フィールドを使用) |
| `server/middleware/trace-logger.ts` | 確認 | `addAttackStep()` メソッドが `DESIGN/03-data-model.md §5.1` の仕様で追加済みであることを確認 |

### 8.3 新規作成ファイル

| ファイルパス | 役割 |
|------------|------|
| `src/components/auth/attacks/tls-deep/TlsAttackPanel.tsx` | 3シナリオを統括するメインパネル |
| `src/components/auth/attacks/tls-deep/VersionDowngradeScenario.tsx` | シナリオ A の実行ロジックと SCSV トグル |
| `src/components/auth/attacks/tls-deep/SelfSignedMitmScenario.tsx` | シナリオ B の実行ロジックと証明書比較パネル |
| `src/components/auth/attacks/tls-deep/WeakCipherScenario.tsx` | シナリオ C の実行ロジックと暗号スイート比較テーブル |
| `src/components/auth/attacks/tls-deep/TlsAttack.css` | 3シナリオ共通スタイル (証明書比較パネル・暗号スイートテーブルを含む) |

### 8.4 `AttackStepPayload` の `type: "tls"` フィールド使用マップ

| フィールド | 使用シナリオ | 用途 |
|-----------|------------|------|
| `version` | A, C | クライアントが本来提示した TLS バージョン |
| `downgradedTo` | A, C | MITM によるダウングレード後のバージョン |
| `cipherSuite` | A, B, C | 元の (強い) 暗号スイート |
| `weakCipherSuite` | A, C | ダウングレードまたは強制された弱い暗号スイート |
| `certificate` | B | 正規サーバーの証明書情報 |
| `fakeCertificate` | B | 攻撃者が作成した自己署名偽証明書 |

---

*このドキュメントは `DESIGN/18-attack-tls.md` に配置。
実装を開始する前に DESIGN/00 〜 04 の基盤設計書を読了し、
特に DESIGN/04-safety-guardrails.md §4 のレビューチェックリストを確認すること。
既存の `server/routes/tls-sim.ts` における ECDHE 鍵交換・証明書生成の実装を参照し、
攻撃エンドポイントと整合させること。*
