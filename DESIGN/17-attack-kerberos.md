---
title: Kerberos 攻撃カタログ
phase: design
tab-id: kerberos
safety-reviewed: true
last-updated: 2026-04-26
---

## 教育目的

本ファイルは **教育用シミュレーション** の実装設計である。
記載された攻撃手法は `localhost` 上の固定シードデータに対してのみ動作するよう設計されており、
実環境への攻撃を意図したものではない。

攻撃シミュレーションはすべて「この防御がなぜ必要か」を体感するための概念実証であり、
各シナリオには必ず防御策の解説と実装例が対になっている。

---

# 17. Kerberos 攻撃カタログ

## 1. 概要

「Kerberos (kerberos)」タブは、KDC (鍵配布センター) が TGT/TGS チケットを AES-256-CBC で
暗号化して発行する正常系フロー (AS-REQ → TGS-REQ → AP-REQ) をインタラクティブに学ぶ
既存の Defender View を持つ。このカタログは同タブに **Attacker View** を追加し、
Kerberos プロトコルの設計上の特性が攻撃者にどのように悪用されるかを体感的に理解させる。

Kerberos は Windows Active Directory 環境で広く使われており、
チケット窃取・サービスアカウントへの総当り・KDC 鍵の偽造という 3 系統の攻撃が実環境でも
実際に観測されている。教材としてその仕組みを安全な隔離環境で体験できる構成とする。

### 1.1 防御側既存実装の参照

| ファイル | 役割 |
|---------|------|
| `server/routes/kerberos-sim.ts` | AS-REQ (`POST /api/kerberos/as-req`)、TGS-REQ (`POST /api/kerberos/tgs-req`)、AP-REQ (`POST /api/kerberos/ap-req`) のルートハンドラ。AES-256-CBC によるチケット暗号化と復号を実装 |
| `src/components/auth/KerberosFlow.tsx` | `KerberosDemo` コンポーネント。3ステップフォーム + スイムレーン図 + `DataFlowPanel` による HTTP/Trace 可視化 |
| `server/db/schema.ts` | `kerberos_tickets` テーブル定義: `id`, `ticket_type`, `principal`, `realm`, `encrypted_data`, `session_key`, `valid_until`, `created_at` |

### 1.2 攻撃デモの追加方針

既存の `KerberosFlow.tsx` に `ViewModeToggle` を追加し、Attacker View として
`KerberosAttackPanel` コンポーネントを条件表示する。
攻撃 API は既存の `server/routes/kerberos-sim.ts` に `/attack/<scenario>` サブパスとして追加し、
既存の `app.route("/api/kerberos", kerberoSimRoutes)` をそのまま活用する
(DESIGN/01-architecture.md §2.1 採用案 A のルート配置方針に準拠)。

---

## 2. 攻撃シナリオ一覧

| # | シナリオ ID | 攻撃名 | CWE | CAPEC | OSI 層 | 深刻度 |
|---|------------|--------|-----|-------|--------|-------|
| A | `kerberos-pass-the-ticket` | Pass-the-Ticket (TGS 窃取・再利用) | CWE-294 | CAPEC-555 | L5/L7 (Session/Application) | High |
| B | `kerberos-kerberoasting` | Kerberoasting (SPN ハッシュ抽出・弱パスワード総当り) | CWE-326 | CAPEC-509 | L7 (Application) | High |
| C | `kerberos-golden-ticket` | Golden Ticket (KDC 長期鍵偽造 TGT) | CWE-345 | CAPEC-196 | L7 (Application) | Critical |

---

## 3. 既存防御側実装

### 3.1 `server/routes/kerberos-sim.ts` の構造

```
kerberoSimRoutes
├── POST /as-req
│   ├── SHA-256(password) → clientKey (32 bytes)
│   ├── crypto.randomBytes(32) → sessionKey
│   ├── encrypt(tgtData, KDC_SECRET)  ← AES-256-CBC でTGT暗号化 (KDCのみ復号可)
│   ├── encrypt(sessionKey, clientKey) ← セッション鍵をクライアント鍵で暗号化
│   └── INSERT INTO kerberos_tickets (ticket_type='TGT', ...)
├── POST /tgs-req
│   ├── decrypt(tgt, KDC_SECRET)      ← KDC がTGTを検証
│   ├── 有効期限チェック (validUntil)
│   ├── crypto.randomBytes(32) → serviceSessionKey
│   ├── encrypt(serviceTicketData, KDC_SECRET) ← サービスチケット暗号化
│   └── INSERT INTO kerberos_tickets (ticket_type='ServiceTicket', ...)
├── POST /ap-req
│   ├── decrypt(serviceTicket, KDC_SECRET) ← サービスが検証
│   ├── 有効期限チェック
│   └── 認証成功レスポンス
└── GET /ticket-cache   ← デバッグ用 (開発環境のみ)
```

`trace.addCryptoOp()` により、TGT 暗号化・セッション鍵生成・サービスチケット暗号化などの
操作詳細が `_trace.cryptoOps` に記録され、`DataFlowPanel` の Trace タブで可視化される。

### 3.2 AES 暗号化チケット構造 (ASCII 図)

```
  TGT (KDC_SECRET で暗号化)
  ┌──────────────────────────────────────────────────────────┐
  │ Encrypted Blob (AES-256-CBC)                             │
  │ ┌────────────────────────────────────────────────────┐   │
  │ │ {                                                  │   │
  │ │   "principal":   "alice@OSI-DEMO.LOCAL",           │   │
  │ │   "sessionKey":  "<base64: 32 random bytes>",      │   │
  │ │   "validUntil":  "2026-04-26T18:00:00.000Z",       │   │
  │ │   "flags":       ["FORWARDABLE","RENEWABLE",        │   │
  │ │                   "INITIAL"]                        │   │
  │ │ }                                                  │   │
  │ └────────────────────────────────────────────────────┘   │
  │ + IV (16 bytes, base64)                                  │
  └──────────────────────────────────────────────────────────┘
          ↑ KDC_SECRET (SHA-256("osi-demo-kdc-master-key"))
          ↑ のみ復号可 — クライアント・サービスは内容を見られない

  Service Ticket (KDC_SECRET で暗号化)
  ┌──────────────────────────────────────────────────────────┐
  │ Encrypted Blob (AES-256-CBC)                             │
  │ ┌────────────────────────────────────────────────────┐   │
  │ │ {                                                  │   │
  │ │   "principal":        "alice@OSI-DEMO.LOCAL",      │   │
  │ │   "servicePrincipal": "http/web-server@OSI-DEMO",  │   │
  │ │   "sessionKey":       "<base64: 32 random bytes>", │   │
  │ │   "validUntil":       "2026-04-26T12:00:00.000Z"   │   │
  │ │ }                                                  │   │
  │ └────────────────────────────────────────────────────┘   │
  │ + IV (16 bytes, base64)                                  │
  └──────────────────────────────────────────────────────────┘
          ↑ 実環境ではサービス固有の長期鍵で暗号化するが、
          ↑ このデモでは KDC_SECRET で代替 (簡略化注記を表示)

  暗号化されたセッション鍵 (クライアント鍵で暗号化)
  ┌──────────────────────────────────────────────────────────┐
  │ Encrypted Blob (AES-256-CBC)                             │
  │ ┌────────────────────────────────────────────────────┐   │
  │ │ <base64: TGT の sessionKey>                        │   │
  │ └────────────────────────────────────────────────────┘   │
  │ + IV (16 bytes, base64)                                  │
  └──────────────────────────────────────────────────────────┘
          ↑ SHA-256(password) = clientKey でのみ復号可
```

### 3.3 `server/db/schema.ts` の kerberos_tickets テーブル

```sql
CREATE TABLE IF NOT EXISTS kerberos_tickets (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  ticket_type   TEXT NOT NULL,          -- 'TGT' or 'ServiceTicket'
  principal     TEXT NOT NULL,          -- ユーザーまたはサービスのプリンシパル名
  realm         TEXT DEFAULT 'OSI-DEMO.LOCAL',
  encrypted_data TEXT NOT NULL,         -- base64 エンコードの暗号文
  session_key   TEXT NOT NULL,          -- base64 エンコードのセッション鍵
  valid_until   TEXT NOT NULL,          -- ISO 8601 有効期限
  created_at    TEXT DEFAULT (datetime('now'))
);
```

攻撃シミュレーション専用のシードチケットには `is_attack_sim` フラグを追加し、
正常系クエリから除外する (DESIGN/04-safety-guardrails.md §5.3 に準拠)。

### 3.4 既存実装の防御上の特性

| 防御要素 | 実装箇所 | 効果 |
|---------|---------|------|
| TGT は KDC_SECRET のみ復号可 | `kerberos-sim.ts: encrypt(tgtData, KDC_SECRET)` | クライアントは TGT の内容を改ざんできない |
| セッション鍵はクライアント鍵で暗号化 | `encrypt(sessionKey, clientKey)` | セッション鍵はパスワードを知るクライアントのみ取得可能 |
| 有効期限チェック | `new Date(tgtData.validUntil) < new Date()` | 期限切れチケットは拒否される |
| AES-256-CBC 使用 | `createCipheriv("aes-256-cbc", key, iv)` | 現行標準暗号強度を確保 |

### 3.5 既存実装の改善余地 (教材として指摘する設計上の注意点)

| 項目 | 現状 | 改善案 |
|------|------|--------|
| HMAC なし | AES-CBC のみで認証なし (AEAD 非使用) | AES-GCM または AES-CBC + HMAC-SHA256 (Encrypt-then-MAC) |
| リプレイ防止なし | 提示されたチケットを再利用できる | Authenticator (タイムスタンプ + ランダム値) による nonce 検証 |
| サービス固有鍵なし | 全チケットを KDC_SECRET で暗号化 | 本来はサービスの長期鍵で暗号化し、KDC はサービス鍵のみに渡す |
| PAC (特権属性証明書) なし | グループ情報を含まない | 実 Kerberos では PAC でユーザーのグループ情報を署名付きで含める |

---

## 4. シナリオ詳細

---

### 4.1 `kerberos-pass-the-ticket`

#### 概要

これは **CWE-294 (Replay) / CAPEC-555** の概念実証である。
Kerberos のサービスチケット (TGS) はクライアントが KDC から受け取り、ローカルの「チケットキャッシュ」
に保存される。攻撃者がメモリや端末からこのチケットを窃取した場合、
KDC への再認証なしにそのチケットをサービスにそのまま提示して認証できる。

このデモでは「被害者 (seed_alice) が正規フローで取得したサービスチケット」を
攻撃者 (attacker_charlie) が参照し、同一チケットを使ってサービス認証を試みる。
実際の環境では LSASS プロセスのメモリダンプや Mimikatz ツールによる窃取が行われるが、
このデモは同一プロセス内でシミュレーション変数として参照するのみであり、
実際のメモリ操作は行わない。

**実環境との差異の注記 (必須)**:
実環境での Pass-the-Ticket は LSASS プロセスへのアクセス権限取得が前提であり、
エンドポイント上での管理者権限または特権昇格が必要です。
このデモは同一プロセス内での参照シミュレーションです。

#### CWE / CAPEC / OSI 層

| 項目 | 値 |
|------|-----|
| CWE | CWE-294 (Authentication Bypass by Capture-replay) |
| CAPEC | CAPEC-555 (Remote Services with Stolen Credentials) |
| OSI 層 | Layer 5 (Session) / Layer 7 (Application) |
| 深刻度 | High |

#### 前提条件

攻撃者は以下の条件を満たしている:

1. seed_alice が正規の Kerberos フロー (AS-REQ → TGS-REQ) を完了し、サービスチケットを取得済み
2. 攻撃者がそのサービスチケット (`encrypted_data` + `iv`) を窃取済み
   (このデモでは KDC の `kerberos_tickets` テーブルから `is_attack_sim=0` の最新チケットを参照)
3. 窃取したチケットがまだ有効期限内である

#### 攻撃ステップ (AttackStep[])

```typescript
const steps: AttackStep[] = [
  {
    id: "step-1",
    kind: "intercept",
    label: "Victim (seed_alice) obtains a Service Ticket via normal TGS-REQ",
    labelJa: "被害者 (seed_alice) が正規の TGS-REQ でサービスチケットを取得",
    status: "success",
    payload: {
      type: "ticket",
      ticketType: "ServiceTicket",
      principal: "alice@OSI-DEMO.LOCAL",
      servicePrincipal: "http/web-server@OSI-DEMO.LOCAL",
      encryptedData: "<base64 暗号化サービスチケット>",
      iv: "<base64 IV>",
      validUntil: "2026-04-26T13:00:00.000Z",
    },
    detail: "The victim authenticates normally and receives an encrypted Service Ticket stored in the local ticket cache.",
    detailJa: "被害者が正常認証し、暗号化されたサービスチケットをローカルのチケットキャッシュに取得します。",
    timestamp: Date.now(),
  },
  {
    id: "step-2",
    kind: "intercept",
    label: "Attacker extracts the Service Ticket from victim's ticket cache (simulated)",
    labelJa: "攻撃者が被害者のチケットキャッシュからサービスチケットを窃取 (シミュレーション)",
    status: "success",
    payload: {
      type: "ticket",
      ticketType: "ServiceTicket",
      principal: "alice@OSI-DEMO.LOCAL",
      servicePrincipal: "http/web-server@OSI-DEMO.LOCAL",
      encryptedData: "<同一の base64 暗号化サービスチケット>",
      iv: "<同一の base64 IV>",
      note: "実際のメモリ操作は行いません — 同一プロセス内でのシミュレーション参照です",
      noteEn: "No actual memory operations — this is an in-process simulation reference",
    },
    detail: "The attacker reads the Service Ticket from the simulated ticket cache. In real attacks, tools like Mimikatz extract this from LSASS memory.",
    detailJa: "攻撃者がシミュレーションされたチケットキャッシュからサービスチケットを読み取ります。実際の攻撃では Mimikatz 等のツールが LSASS メモリから抽出します。",
    timestamp: Date.now(),
  },
  {
    id: "step-3",
    kind: "exploit",
    label: "Attacker submits stolen Service Ticket to AP-REQ (no new TGS-REQ needed)",
    labelJa: "攻撃者が窃取したサービスチケットを AP-REQ で提示 (TGS-REQ 不要)",
    status: "success",
    payload: {
      type: "http",
      request: {
        method: "POST",
        url: "/api/kerberos/ap-req",
        headers: { "X-Attack-Sim": "pass-the-ticket" },
        body: {
          serviceTicket: "<窃取したチケットの暗号化データ>",
          serviceTicketIv: "<同一の IV>",
        },
      },
      response: {
        status: 200,
        body: {
          success: true,
          data: {
            step: "AP-REP",
            authenticated: true,
            principal: "alice@OSI-DEMO.LOCAL",
            service: "http/web-server@OSI-DEMO.LOCAL",
            message: "Client authenticated to service via Kerberos ticket",
          },
        },
      },
    },
    detail: "The service accepts the stolen ticket because it is still valid and correctly encrypted. The attacker is authenticated as seed_alice without knowing the password.",
    detailJa: "サービスは窃取されたチケットが有効かつ正しく暗号化されているため受け入れます。攻撃者はパスワードを知らずに seed_alice として認証されます。",
    timestamp: Date.now(),
  },
  {
    id: "step-4",
    kind: "verify",
    label: "Defense: replay detection via authenticator nonce (not implemented in current sim)",
    labelJa: "防御: Authenticator nonce によるリプレイ検出 (現行シミュレーションでは未実装)",
    status: "blocked",
    payload: {
      type: "generic",
      data: {
        defense: "Authenticator (timestamp + random nonce) bundled with AP-REQ",
        defenseJa: "AP-REQ に Authenticator (タイムスタンプ + ランダム nonce) を同梱",
        result: "Service verifies nonce has not been seen before → replay rejected",
        resultJa: "サービスが nonce の再利用を検出 → リプレイを拒否",
      },
    },
    detail: "Real Kerberos mandates an Authenticator in AP-REQ encrypted with the session key, containing a unique timestamp and nonce. The service rejects any duplicate nonce within the clock skew window (5 minutes).",
    detailJa: "本物の Kerberos では AP-REQ にセッション鍵で暗号化した Authenticator (ユニークなタイムスタンプ + nonce) が必須です。サービスはクロックスキュー窓内 (5分) で nonce の重複を検出し拒否します。",
    timestamp: Date.now(),
  },
];
```

#### 期待される結果 (AttackResult)

E-2 契約: 1 リクエストで両モード (脆弱: Authenticator nonce 検証なし、堅牢: replay cache + Authenticator nonce 検証) を並列実行し、5 ステップ完全形 (probe → tamper → forge → exploit → verify) を返す。`outcome` は常に `"succeeded"` 固定、HTTP ステータスは 200 固定。`blockedBy` には堅牢側で発火した防御識別子を記録する。

| 項目 | 値 |
|------|-----|
| `outcome` | `"succeeded"` (常に) |
| HTTP ステータス | 200 (常に) |
| `blockedBy` | `"kerberos_authenticator_nonce_replay_cache_enforced"` (堅牢側 step 5: nonce キャッシュで再使用検出) |
| `steps[3].status` (脆弱側 exploit: nonce 検証なし) | `"success"` (盗まれたサービスチケットを再利用できる) |
| `steps[4].status` (堅牢側 verify: nonce replay cache) | `"blocked"` |

#### 防御策

**既存実装ファイルへのリンク**:
- `server/routes/kerberos-sim.ts:194-228` — AP-REQ ハンドラ (現状リプレイ検出なし)
- `server/db/schema.ts:127-136` — `kerberos_tickets` テーブル

**防御策の要点**:

1. AP-REQ には Authenticator を必須とする (RFC 4120 §3.2.3)
2. Authenticator はセッション鍵で暗号化し、タイムスタンプとランダム nonce を含める
3. サービスはクロックスキュー窓 (通常 5 分) 内で受信した Authenticator の nonce を記録し、重複を拒否する
4. クロックスキューは KDC が管理するため、クロックの同期も防御の前提となる

**codeHints の具体例**:

```typescript
// AP-REQ に Authenticator を追加する概念例 (実装案)
const authenticator = {
  clientName: "alice@OSI-DEMO.LOCAL",
  timestamp: new Date().toISOString(),
  nonce: crypto.randomBytes(8).toString("hex"),
};
const encAuthenticator = encrypt(
  JSON.stringify(authenticator),
  Buffer.from(sessionKey, "base64")  // サービスセッション鍵で暗号化
);

// サービス側: nonce のキャッシュで重複チェック
const replayCache = new Set<string>(); // 実装では TTL 付きストアを使用
if (replayCache.has(authenticator.nonce)) {
  return c.json({ success: false, error: "Replay detected" }, 401);
}
replayCache.add(authenticator.nonce);
```

#### API 契約

```
POST /api/kerberos/attack/pass-the-ticket
Content-Type: application/json

Request: {} (E-2: 両モードを並列実行するため body は空オブジェクト。
  被害者プリンシパル / サービスプリンシパル / 盗まれたチケット / Authenticator nonce は全てサーバー側のシード値から生成される。
  zod スキーマ: kerberosAttackPassTheTicketSchema = z.object({}))

Response: { data: AttackResult, _trace: ServerTrace }
  // data.outcome: "succeeded" (常に)
  // data.steps: 5 ステップ完全形
  // data.blockedBy: "kerberos_authenticator_nonce_replay_cache_enforced" (堅牢側 verify で発火)
  // data.extra: シナリオ固有フィールド (stolenTicketPrefix / authenticatorNonce / vulnerableAuthSucceeded / replayCacheHit 等)
```

#### _trace 内訳

| trace 種別 | 内容 |
|-----------|------|
| `CryptoOp` | `decryptServiceTicket (stolen)` — AES-256-CBC 復号によるチケット検証 (リプレイ検出なしで成功) |
| `DbQuery` | `SELECT kerberos_tickets WHERE principal=seed_alice` — 被害者のサービスチケット参照 |
| `AttackStep` | intercept (TGT取得) → intercept (チケット窃取) → exploit (AP-REQ提示) → blocked (防御案の説明) |

#### UI フロー

```
[Attacker View 起動]
  ↓
[教育用バナー表示: 常時固定]
  ↓
[シナリオセレクタ: "Pass-the-Ticket (TGS 窃取)" を選択]
  ↓
[被害者プリンシパル選択: seed_alice / seed_bob]
  ↓
[「攻撃を実行」ボタン]
  ↓
[AttackStepTimeline アニメーション]
  step-1 intercept: 被害者がサービスチケット取得 → SUCCESS (オレンジ)
  step-2 intercept: チケットキャッシュから窃取 → SUCCESS (オレンジ)
    ↪ チケット構造の ASCII 図を折りたたみ表示
  step-3 exploit:   窃取チケットで AP-REQ → SUCCESS (赤)
    ↪ TGT/TGS の関係図: 「TGS を使えば TGT は不要」を可視化
  step-4 verify:    Authenticator nonce が防御 → BLOCKED (緑、未実装を注記)
  ↓
[AttackResultBanner: "この実装は脆弱です: リプレイ防止 (Authenticator nonce) が実装されていません"]
  ↓
[AttackDefensePanel: RFC 4120 §3.2.3 Authenticator と nonce キャッシュの解説]
  ↓
[DataFlowPanel: HTTP タブ / Trace タブ (CryptoOp + AttackStep) / DB タブ (チケットキャッシュ参照)]
```

---

### 4.2 `kerberos-kerberoasting`

#### 概要

これは **CWE-326 (Inadequate Encryption Strength) / CAPEC-509** の概念実証である。
Kerberos では任意のドメインユーザーが SPN (Service Principal Name) に対して TGS を要求できる。
サービスチケットの暗号化鍵はサービスアカウントのパスワードから導出されるため、
攻撃者はオフラインでサービスチケットのハッシュを辞書攻撃して解読できる。
サービスアカウントのパスワードが短い辞書語の場合、数秒〜数分で解読される。

このデモでは「弱パスワード (辞書語)」と「強パスワード (ランダム 20 文字以上)」の
2 種類のサービスアカウントに対して TGS を要求し、サーバー側で辞書照合シミュレーションを実行する。
弱パスワードは即座に一致し、強パスワードは照合不能であることを比較表示する。

**実環境との差異の注記 (必須)**:
実環境では攻撃者は Hashcat / John the Ripper 等のツールを用いてオフラインで大量試行します。
このデモでは Hashcat の実装は省略し、サーバー側に埋め込んだ 20 件の固定辞書との照合を
「Hashcat シミュレーション」として表示します。
また、実環境では強力なパスワードポリシーおよびサービスアカウントの管理策により
Kerberoasting は成立しにくくなります。

#### CWE / CAPEC / OSI 層

| 項目 | 値 |
|------|-----|
| CWE | CWE-326 (Inadequate Encryption Strength) |
| CAPEC | CAPEC-509 (Kerberoasting) |
| OSI 層 | Layer 7 — Application |
| 深刻度 | High |

#### 前提条件

攻撃者は以下の条件を満たしている:

1. ドメインの一般ユーザーとして認証済み (seed_alice — KDC への TGS 要求権限あり)
2. SPN が登録されたサービスアカウントが存在する
   (このデモでは `http/weak-service` と `http/strong-service` の 2 アカウントを固定シードとして用意)
3. `http/weak-service` のパスワードが辞書語 (例: `service123`) で設定されている

**シードサービスアカウントの設定** (server/db/schema.ts への追加対象):

```sql
-- kerberoasting_services: Kerberoasting 攻撃用教育専用シードテーブル
CREATE TABLE IF NOT EXISTS kerberoasting_services (
  spn         TEXT PRIMARY KEY,                     -- 例: 'http/weak-service'
  password    TEXT NOT NULL,                        -- 平文 (教育用: 本来は保存しない)
  strength    TEXT NOT NULL CHECK(strength IN ('weak','strong')),
  description TEXT,
  is_attack_sim INTEGER NOT NULL DEFAULT 1
);
-- 固定シード
INSERT OR IGNORE INTO kerberoasting_services VALUES
  ('http/weak-service',   'service123',  'weak',   '辞書語パスワード — Kerberoasting で即解読されます', 1),
  ('http/strong-service', 'xK9#mP2$vQ7@nR4!jL8', 'strong', '20文字ランダムパスワード — 辞書照合は不可能です', 1);
```

#### 攻撃ステップ (AttackStep[])

```typescript
const steps: AttackStep[] = [
  {
    id: "step-1",
    kind: "probe",
    label: "Request TGS for weak-password service SPN (no special privilege needed)",
    labelJa: "弱パスワードのサービス SPN に TGS を要求 (特権不要)",
    status: "success",
    payload: {
      type: "ticket",
      ticketType: "ServiceTicket",
      spn: "http/weak-service@OSI-DEMO.LOCAL",
      note: "Any domain user can request a TGS for any registered SPN — this is by design in Kerberos",
      noteJa: "ドメインの一般ユーザーはすべての SPN に対して TGS を要求できます — これは Kerberos の設計です",
    },
    detail: "A Service Ticket is issued for the SPN. Its encryption key is derived from the service account password.",
    detailJa: "SPN に対してサービスチケットが発行されます。その暗号化鍵はサービスアカウントのパスワードから導出されます。",
    timestamp: Date.now(),
  },
  {
    id: "step-2",
    kind: "probe",
    label: "Extract ticket hash and run offline dictionary attack (Hashcat simulation)",
    labelJa: "チケットハッシュを抽出し辞書攻撃を実行 (Hashcat シミュレーション)",
    status: "success",
    payload: {
      type: "generic",
      data: {
        ticketHashFormat: "$krb5tgs$23$*...",
        dictionarySize: 20,
        hashcatMode: "13100 (KerberosV5 TGS-REP etype 23 — 教育用簡略表示)",
        crackedPassword: "service123",
        crackedAt: 7,
        elapsedMs: 120,
        note: "Hashcat の実装は省略 — 固定辞書との照合シミュレーションです",
        noteEn: "Hashcat implementation is omitted — this is a fixed-dictionary simulation",
      },
    },
    detail: "The ticket hash matches 'service123' at dictionary entry #7. A real Hashcat run would test billions of candidates per second.",
    detailJa: "チケットハッシュが辞書の 7 件目 'service123' に一致しました。実際の Hashcat は毎秒数十億候補を試行します。",
    timestamp: Date.now(),
  },
  {
    id: "step-3",
    kind: "verify",
    label: "Attempt same attack on strong-password service SPN",
    labelJa: "強パスワードのサービス SPN に同じ攻撃を試行",
    status: "blocked",
    payload: {
      type: "generic",
      data: {
        spn: "http/strong-service@OSI-DEMO.LOCAL",
        dictionarySize: 20,
        crackedAt: null,
        result: "No match found in 20-entry dictionary",
        resultJa: "20 件の辞書で一致なし",
        note: "20文字以上のランダムパスワードは辞書攻撃に対して実質的に耐性があります",
        noteEn: "Random passwords of 20+ characters are practically immune to dictionary attacks",
      },
    },
    detail: "The strong-password service account cannot be cracked with a dictionary. Offline brute-force would require infeasible time.",
    detailJa: "強パスワードのサービスアカウントは辞書攻撃では解読できません。総当りには現実的でない時間が必要です。",
    timestamp: Date.now(),
  },
];
```

#### 期待される結果 (AttackResult)

E-2 契約: 1 リクエストで両モード (脆弱: 弱パスワード SPN サービスアカウント、堅牢: 20+ 文字ランダム + AES のみ + ローテーション運用) を並列実行し、5 ステップ完全形を返す。`outcome` は常に `"succeeded"` 固定、HTTP ステータスは 200 固定。`blockedBy` には堅牢側で発火した防御識別子を記録する。

| 項目 | 値 |
|------|-----|
| `outcome` | `"succeeded"` (常に) |
| HTTP ステータス | 200 (常に) |
| `blockedBy` | `"kerberos_kerberoasting_strong_service_account_password_enforced"` (堅牢側 step 5: gMSA 相当の強パスワードで辞書照合が成立しない) |
| `steps[3].status` (脆弱側 exploit: 弱パスワード SPN) | `"success"` (固定辞書 20 件中 7 番目で `service123` を解読) |
| `steps[4].status` (堅牢側 verify: 強パスワード SPN) | `"blocked"` |

#### 防御策

**防御策の要点**:

1. サービスアカウントのパスワードは 20 文字以上のランダム文字列を使用する
2. 定期的 (90 日以内) にサービスアカウントのパスワードをローテーションする
3. Windows 環境では gMSA (Group Managed Service Accounts) を使用し、
   パスワードを OS が自動管理する (複雑度・ローテーションを強制)
4. etype 17/18 (AES128/AES256) のみを許可し、RC4 (etype 23) を無効化する
   (RC4 は Kerberoasting に最も悪用されやすい)
5. TGS 要求の異常検知: 短時間に大量の TGS 要求が発生した場合にアラートを上げる

**codeHints の具体例**:

```typescript
// サービスアカウントパスワードの強度検証例 (教育用)
function isKerberoastResistant(password: string): boolean {
  // 20 文字以上、英大小文字 + 数字 + 記号を含む
  return (
    password.length >= 20 &&
    /[A-Z]/.test(password) &&
    /[a-z]/.test(password) &&
    /[0-9]/.test(password) &&
    /[^A-Za-z0-9]/.test(password)
  );
}

// gMSA 相当: ランダム 32 バイトをパスワードとして使用
import crypto from "crypto";
const strongServicePassword = crypto.randomBytes(32).toString("base64");
// → 43 文字 base64、文字種を含む → 辞書攻撃に対して実質的に耐性あり
```

#### API 契約

```
POST /api/kerberos/attack/kerberoasting
Content-Type: application/json

Request: {} (E-2: 両モードを並列実行するため body は空オブジェクト。
  TGS 要求 / 弱・強パスワード SPN / 固定辞書 20 件 / ハッシュ照合は全てサーバー側のシード値から生成される。
  zod スキーマ: kerberosAttackKerberoastingSchema = z.object({}))

Response: { data: AttackResult, _trace: ServerTrace }
  // data.outcome: "succeeded" (常に)
  // data.steps: 5 ステップ完全形
  // data.blockedBy: "kerberos_kerberoasting_strong_service_account_password_enforced" (堅牢側 verify で発火)
  // data.extra: シナリオ固有フィールド (weakSpn / strongSpn / crackedPlaintext / dictionaryHitIndex / strongPasswordEntropy 等)
```

#### _trace 内訳

| trace 種別 | 内容 |
|-----------|------|
| `CryptoOp` | `kerberoasting_hash_sim` — ハッシュ抽出と辞書照合シミュレーション (Hashcat は省略) |
| `DbQuery` | `kerberoasting_services` テーブルへのパスワード参照 (シミュレーション用) |
| `AttackStep` | probe (TGS 要求) → probe (辞書照合) → blocked (強パスワード耐性) |

#### UI フロー

```
[Attacker View 起動]
  ↓
[教育用バナー表示: 常時固定]
  ↓
[シナリオセレクタ: "Kerberoasting (SPN ハッシュ抽出)" を選択]
  ↓
[SPN 選択ラジオ: "http/weak-service (弱パスワード)" / "http/strong-service (強パスワード)"]
  ↓
[「攻撃を実行」ボタン]
  ↓
[AttackStepTimeline アニメーション]
  step-1 probe: TGS 要求 → SUCCESS
    ↪ 「ドメインユーザーは SPN への TGS を誰でも要求できます」の注釈
  step-2 probe: 辞書照合シミュレーション
    弱パスワード → SUCCESS + 解読結果表示 (オレンジ)
    強パスワード → BLOCKED + 「辞書照合不可」(緑)
  step-3 verify: 強パスワード耐性確認 → BLOCKED (緑)
  ↓
[弱/強パスワード比較テーブル: パスワード長・文字種・辞書ヒット可否]
  ↓
[AttackResultBanner]
  弱パスワード: "この実装は脆弱です: 弱パスワードのサービスアカウントが辞書攻撃で解読されました"
  強パスワード: "防御が機能しました: 20文字以上のランダムパスワードが辞書攻撃を阻止しました"
  ↓
[AttackDefensePanel: gMSA / パスワード複雑度 / etype 制限の解説]
  ↓
[DataFlowPanel: HTTP / Trace / DB タブ]
```

---

### 4.3 `kerberos-golden-ticket`

#### 概要

これは **CWE-345 (Insufficient Verification of Data Authenticity) / CAPEC-196** の概念実証である。
Kerberos の TGT は KDC の長期鍵 (`krbtgt` アカウントのパスワードハッシュ) で暗号化されている。
攻撃者が `krbtgt` の鍵を入手すると、KDC を通さずに任意のユーザー名・グループ・権限を持つ
正規の TGT を偽造できる (Golden Ticket)。
偽造された TGT でサービスチケットを要求すると、KDC はそれが偽造であることを検知できない。

このデモでは `krbtgt` 鍵を「漏洩済み」と仮定し、`administrator` を名乗る偽造 TGT を作成して
サービスチケットの取得を試みる。
教材として `krbtgt` の定期ローテーション・最小権限・PAC 検証の重要性を解説する。

**実環境との差異の注記 (必須)**:
実環境での Golden Ticket 攻撃には krbtgt アカウントのハッシュ取得が前提であり、
ドメインコントローラー (DC) への侵害 (Domain Admin 権限またはそれに相当) が必要です。
このデモは krbtgt 鍵が既知であるという仮定の上での概念シミュレーションです。
実環境では krbtgt の取得自体が困難であり、DC への侵害が検知された時点で
krbtgt のリセットを2回実施することで Golden Ticket を無効化できます。

#### CWE / CAPEC / OSI 層

| 項目 | 値 |
|------|-----|
| CWE | CWE-345 (Insufficient Verification of Data Authenticity) |
| CAPEC | CAPEC-196 (Session Credential Falsification through Forging) |
| OSI 層 | Layer 7 — Application |
| 深刻度 | Critical |

#### 前提条件

攻撃者は以下の条件を満たしている:

1. `krbtgt` の長期鍵を取得済み
   (このデモでは教育用シミュレーションとして `KDC_SECRET` 相当の鍵を既知と仮定)
2. 偽造したいユーザー名 (例: `administrator`) とドメイン (`OSI-DEMO.LOCAL`) を知っている
3. 任意のサービスプリンシパルが存在する

**注意**: 現行シミュレーションの `KDC_SECRET` は
`crypto.createHash("sha256").update("osi-demo-kdc-master-key").digest()` で固定生成される。
実環境との混同を防ぐため、この鍵は `SEED_KDC_MASTER_KEY_DEMO` として明示的に命名する。

#### 攻撃ステップ (AttackStep[])

```typescript
const steps: AttackStep[] = [
  {
    id: "step-1",
    kind: "intercept",
    label: "Attacker obtains krbtgt key (assumed leaked — prerequisite of Golden Ticket)",
    labelJa: "攻撃者が krbtgt 鍵を取得済みと仮定 (Golden Ticket の前提条件)",
    status: "success",
    payload: {
      type: "generic",
      data: {
        krbtgtKeySource: "SEED_KDC_MASTER_KEY_DEMO (教育用固定値)",
        realWorldNote: "実環境では krbtgt の取得に DC への侵害が必要です",
        realWorldNoteEn: "In real environments, obtaining krbtgt requires Domain Controller compromise",
        prerequisiteOmitted: true,
      },
    },
    detail: "The Golden Ticket attack begins after the attacker has already obtained the krbtgt key. The process of obtaining it is out of scope for this simulation.",
    detailJa: "Golden Ticket 攻撃は攻撃者が既に krbtgt 鍵を取得した後から始まります。取得プロセスはこのシミュレーションのスコープ外です。",
    timestamp: Date.now(),
  },
  {
    id: "step-2",
    kind: "exploit",
    label: "Forge a TGT for 'administrator' using the stolen krbtgt key",
    labelJa: "盗んだ krbtgt 鍵を使って 'administrator' の偽造 TGT を生成",
    status: "success",
    payload: {
      type: "ticket",
      ticketType: "TGT",
      principal: "administrator@OSI-DEMO.LOCAL",
      forged: true,
      flags: ["FORWARDABLE", "RENEWABLE", "INITIAL", "FORGED_BY_ATTACKER"],
      validUntil: "2030-12-31T23:59:59.000Z",
      note: "KDC が発行したものではない偽造チケット — validUntil を遠未来に設定できる",
      noteEn: "Forged ticket not issued by KDC — validUntil can be set arbitrarily far in the future",
    },
    detail: "Using the krbtgt key, the attacker creates a valid-looking TGT for 'administrator' with arbitrary expiry and flags. The KDC cannot distinguish this from a legitimate TGT.",
    detailJa: "krbtgt 鍵を使用して、攻撃者は任意の有効期限とフラグを持つ 'administrator' の正規に見える TGT を作成します。KDC はこれを正規の TGT と区別できません。",
    timestamp: Date.now(),
  },
  {
    id: "step-3",
    kind: "exploit",
    label: "Submit forged TGT to KDC TGS and obtain Service Ticket for 'administrator'",
    labelJa: "偽造 TGT を KDC TGS に提示し 'administrator' のサービスチケットを取得",
    status: "success",
    payload: {
      type: "http",
      request: {
        method: "POST",
        url: "/api/kerberos/tgs-req",
        headers: { "X-Attack-Sim": "golden-ticket" },
        body: {
          tgt: "<偽造 TGT の暗号化データ>",
          tgtIv: "<偽造 TGT の IV>",
          servicePrincipal: "http/web-server",
        },
      },
      response: {
        status: 200,
        body: {
          success: true,
          data: {
            step: "TGS-REP",
            decryptedServiceTicket: {
              principal: "administrator@OSI-DEMO.LOCAL",
              servicePrincipal: "http/web-server@OSI-DEMO.LOCAL",
            },
          },
        },
      },
    },
    detail: "The KDC decrypts the forged TGT successfully (because it uses the correct krbtgt key) and issues a Service Ticket for 'administrator'. The KDC cannot detect the forgery.",
    detailJa: "KDC は偽造 TGT を正常に復号し (正しい krbtgt 鍵が使われているため)、'administrator' のサービスチケットを発行します。KDC は偽造を検出できません。",
    timestamp: Date.now(),
  },
  {
    id: "step-4",
    kind: "verify",
    label: "Defense: krbtgt rotation invalidates existing Golden Tickets",
    labelJa: "防御: krbtgt のローテーションが既存の Golden Ticket を無効化する",
    status: "blocked",
    payload: {
      type: "generic",
      data: {
        defense: "Double krbtgt password reset (within 10 hours) invalidates all forged TGTs",
        defenseJa: "krbtgt パスワードの二重リセット (10時間以内) がすべての偽造 TGT を無効化",
        defense2: "PAC (Privilege Attribute Certificate) validation by domain controllers",
        defense2Ja: "DC による PAC (特権属性証明書) の検証",
      },
    },
    detail: "Resetting the krbtgt password twice (to prevent use of old password) forces re-authentication and invalidates all Golden Tickets. PAC validation by DCs can also detect forged attributes.",
    detailJa: "krbtgt パスワードを2回リセットすること (古いパスワードの使用を防ぐ) で再認証が強制され、すべての Golden Ticket が無効化されます。DC による PAC 検証で偽造属性を検出することも可能です。",
    timestamp: Date.now(),
  },
];
```

#### 期待される結果 (AttackResult)

E-2 契約: 1 リクエストで両モード (脆弱: PAC 検証なし + krbtgt 単発リセット未実施、堅牢: krbtgt 2回リセット + PAC 検証 + DC Tier 0 分離) を並列実行し、5 ステップ完全形を返す。`outcome` は常に `"succeeded"` 固定、HTTP ステータスは 200 固定。`blockedBy` には堅牢側で発火した防御識別子を記録する。

| 項目 | 値 |
|------|-----|
| `outcome` | `"succeeded"` (常に) |
| HTTP ステータス | 200 (常に) |
| `blockedBy` | `"kerberos_krbtgt_double_reset_and_pac_validation_enforced"` (堅牢側 step 5: krbtgt 2 回リセットと PAC 検証で偽造 TGT を無効化) |
| `steps[3].status` (脆弱側 exploit: PAC 検証なし) | `"success"` ('administrator' の偽造 TGT が KDC に受理され、サービスチケット取得まで成立) |
| `steps[4].status` (堅牢側 verify: krbtgt rotation + PAC validation) | `"blocked"` |

#### 防御策

**防御策の要点**:

1. **krbtgt の定期ローテーション**: 侵害が疑われる場合は krbtgt パスワードを 2 回リセットする
   (1 回目では古い鍵での認証がまだ可能なため、10 時間以内に 2 回目が必要)
2. **最小権限**: `administrator` などの高権限アカウントへのアクセスを最小化し、
   DC へのアクセスは特権 PAW (Privileged Access Workstation) 経由に限定する
3. **PAC 検証の有効化**: サービスが KDC に対して PAC を検証するよう設定し (MS-KILE §3.4.5.3)、
   偽造された PAC (グループ情報など) を検出できるようにする
4. **DC Tier 0 分離**: ドメインコントローラーを Tier 0 として完全分離し、
   krbtgt ハッシュの取得に必要なアクセスを原則不可能にする

**krbtgt 運用ガイド (教材テキスト)**:

```
krbtgt アカウントの管理
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. 定期ローテーション
   - 侵害が検知・疑われた場合: 10 時間以内に 2 回パスワードリセット
   - 定期的なリセット: 180 日以内を推奨 (NIST SP 800-228)
   - 理由: Golden Ticket は有効期限を無期限に設定可能なため、
     krbtgt がリセットされるまで無効化できない

2. DC 侵害の防止
   - Tier 0 (DC) へのアクセスは PAW (Privileged Access Workstation) 経由のみ
   - DC 上での一般業務 (メール・Web 閲覧) は禁止
   - DC への RDP/SMB アクセスは特定のジャンプサーバーのみに制限

3. PAC 検証
   - KerberosValidation を有効にし、サービスが DC に PAC 検証リクエストを送信する
   - PAC 改ざんは DC が保持する署名で検出される

4. 監視・検知
   - 通常範囲を超えた krbtgt の TGS 要求を異常検知
   - Ticket 有効期限が異常に長い (> 10 時間) リクエストをアラート
```

#### API 契約

```
POST /api/kerberos/attack/golden-ticket
Content-Type: application/json

Request: {} (E-2: 両モードを並列実行するため body は空オブジェクト。
  偽造プリンシパル / 偽造 TGT の AES 暗号化 / KDC マスター鍵は全てサーバー側のシード値から生成される。
  zod スキーマ: kerberosAttackGoldenTicketSchema = z.object({}))

Response: { data: AttackResult, _trace: ServerTrace }
  // data.outcome: "succeeded" (常に)
  // data.steps: 5 ステップ完全形
  // data.blockedBy: "kerberos_krbtgt_double_reset_and_pac_validation_enforced" (堅牢側 verify で発火)
  // data.extra: シナリオ固有フィールド (forgedPrincipal / forgedTgtValidUntil / krbtgtRotationCount / pacValidationResult 等)
```

#### _trace 内訳

| trace 種別 | 内容 |
|-----------|------|
| `CryptoOp` | `forgeGoldenTicket` — AES-256-CBC による偽造 TGT 生成 + KDC での復号 (成功) |
| `DbQuery` | `INSERT kerberos_tickets` — 偽造 TGT の記録 (is_attack_sim=1) |
| `AttackStep` | intercept (krbtgt 取得前提) → exploit (偽造 TGT 生成) → exploit (サービスチケット取得) → blocked (防御案) |

#### UI フロー

```
[Attacker View 起動]
  ↓
[教育用バナー表示: 常時固定]
  ↓
[シナリオセレクタ: "Golden Ticket (KDC 長期鍵偽造 TGT)" を選択]
  ↓
[前提条件ボックス (赤色背景)]
  "このシナリオは krbtgt 鍵が既に漏洩していると仮定します。
   実環境では krbtgt の取得自体が困難であり、DC への侵害が前提です。"
  ↓
[偽造プリンシパル選択: administrator / seed_admin]
  ↓
[「Golden Ticket を偽造する」ボタン (ステップ数: 4 / 4)]
  ↓
[AttackStepTimeline アニメーション]
  step-1 intercept: krbtgt 鍵取得仮定 → SUCCESS + "前提条件省略" 注記 (オレンジ)
  step-2 exploit:   偽造 TGT 生成 → SUCCESS (赤)
    ↪ 偽造 TGT の JSON 構造を折りたたみ表示 (FORGED_BY_ATTACKER フラグ強調)
  step-3 exploit:   偽造 TGT で TGS-REQ → SUCCESS (赤)
    ↪ 「KDC は偽造を検出できない」の説明
  step-4 verify:    krbtgt ローテーションが防御 → BLOCKED (緑)
  ↓
[krbtgt 運用ガイドパネル (自動展開)]
  ・2回リセットの必要性
  ・PAC 検証の有効化
  ・DC Tier 0 分離
  ↓
[AttackResultBanner (Critical): "この実装は脆弱です: PAC 検証なしに偽造 TGT が受け入れられました"]
  ↓
[AttackDefensePanel: krbtgt 管理・PAC 検証・DC 保護の実装解説]
  ↓
[DataFlowPanel: HTTP / Trace / DB タブ]
```

---

## 5. UI コンポーネント設計

### 5.1 ディレクトリ構成

```
src/components/auth/attacks/kerberos/
├── KerberosAttackPanel.tsx          ← 3シナリオを統括するメインパネル
├── PassTheTicketScenario.tsx        ← シナリオ A の実行ロジックとチケット構造表示
├── KerberoastingScenario.tsx        ← シナリオ B の SPN 選択と辞書照合比較表示
├── GoldenTicketScenario.tsx         ← シナリオ C の偽造 TGT 生成と前提条件パネル
└── KerberosAttack.css               ← 3シナリオ共通スタイル
```

### 5.2 `KerberosAttackPanel.tsx` の責務

```typescript
// KerberosFlow.tsx への組み込みイメージ
import KerberosAttackPanel from "./attacks/kerberos/KerberosAttackPanel";
import { Show } from "solid-js";

// useSearchParams から viewMode を取得 (または createSignal)
<Show when={viewMode() === "attacker"}>
  <KerberosAttackPanel tabId="kerberos" />
</Show>
```

`KerberosAttackPanel` は以下を担当する:

1. `EducationalWarningBanner` の常時表示
2. `AttackScenarioSelector` で 3 シナリオの切り替え
3. 選択中シナリオに対応するコンポーネントのレンダリング
4. `DataFlowPanel scopeId="attack-kerberos"` の表示

### 5.3 各シナリオコンポーネントの props 設計

```typescript
// PassTheTicketScenario.tsx
interface PassTheTicketScenarioProps {
  onResult: (result: AttackResult) => void;
  onRunning: (running: boolean) => void;
}

// KerberoastingScenario.tsx
interface KerberoastingScenarioProps {
  onResult: (result: AttackResult) => void;
  onRunning: (running: boolean) => void;
}

// GoldenTicketScenario.tsx
interface GoldenTicketScenarioProps {
  onResult: (result: AttackResult) => void;
  onRunning: (running: boolean) => void;
}
```

### 5.4 チケット構造表示コンポーネント

シナリオ A・C では暗号化チケットの構造を可視化するために専用の表示ブロックを使用する。

```typescript
// KerberosTicketVisualizer: チケット構造の ASCII 図表示
interface KerberosTicketVisualizerProps {
  ticketType: "TGT" | "ServiceTicket";
  principal: string;
  encrypted: string;  // base64 暗号化データ (先頭 40 文字 + "...")
  isForged?: boolean;  // Golden Ticket シナリオで強調表示
}
```

`isForged=true` の場合、チケット表示に赤色枠 + `[FORGED]` バッジを表示し、
正規チケットとの視覚的差異を明確にする。

---

## 6. テスト要件

### 6.1 ユニットテスト (バックエンドハンドラ)

E-2 契約に準拠したテスト構成。各シナリオは 1 リクエストで両モード並列実行のため、`outcome === "succeeded"` 固定 + 5 ステップ完全形 + `blockedBy` で防御識別子を検証する。実装は `server/__tests__/kerberos-attack.test.ts`。

| テストカテゴリ | 対象 | 期待値 |
|------------|-----|--------|
| E-2 不変条件 (it.each で 3 シナリオ共通) | `pass-the-ticket` / `kerberoasting` / `golden-ticket` | `status === 200` / `outcome === "succeeded"` / `steps.length === 5` / `_trace.attackSteps.length === 5` / `_trace.isAttackMode === true` |
| logId 一意性 | 全 3 シナリオを連続実行 | `attack_log` テーブルに 3 件の独立 logId を確認 |
| 本番ガード | `NODE_ENV=production` で全 3 ルート | `status === 403` |
| summaryJa prefix | 全 3 シナリオ | 「この実装は」または「このシナリオでは」で始まる |
| シナリオ A: blockedBy | `pass-the-ticket` | `"kerberos_authenticator_nonce_replay_cache_enforced"` |
| シナリオ A: extra フィールド | `pass-the-ticket` | `extra.stolenTicketPrefix` / `extra.authenticatorNonce` / `extra.replayCacheHit === true` を含む |
| シナリオ B: blockedBy | `kerberoasting` | `"kerberos_kerberoasting_strong_service_account_password_enforced"` |
| シナリオ B: extra フィールド | `kerberoasting` | `extra.weakSpn` / `extra.strongSpn` / `extra.crackedPlaintext` / `extra.dictionaryHitIndex` / `extra.strongPasswordEntropy` を含む |
| シナリオ C: blockedBy | `golden-ticket` | `"kerberos_krbtgt_double_reset_and_pac_validation_enforced"` |
| シナリオ C: extra フィールド | `golden-ticket` | `extra.forgedPrincipal` / `extra.forgedTgtValidUntil` / `extra.krbtgtRotationCount` / `extra.pacValidationResult === "rejected"` を含む |

### 6.2 E2E テスト (UI フロー)

対象: `src/components/auth/attacks/kerberos/KerberosAttackPanel.tsx`

| テスト ID | 操作 | 期待結果 |
|---------|------|---------|
| `e2e-kerb-01` | Kerberos タブで Attacker View に切り替える | `EducationalWarningBanner` が表示され、閉じるボタンが存在しない |
| `e2e-kerb-02` | シナリオ A (Pass-the-Ticket) を実行する | `AttackStepTimeline` が 4 ステップを表示し、step-3 が赤 SUCCESS になる |
| `e2e-kerb-03` | シナリオ B で SPN "http/weak-service" を選択して実行 | step-2 の辞書照合が SUCCESS、`AttackResultBanner` がオレンジ (攻撃成立) |
| `e2e-kerb-04` | シナリオ B で SPN "http/strong-service" を選択して実行 | step-2 の辞書照合が BLOCKED (緑)、`AttackResultBanner` が緑 (防御成立) |
| `e2e-kerb-05` | シナリオ C (Golden Ticket) を実行する | step-2 で偽造 TGT の JSON が `[FORGED]` バッジ付きで表示される |
| `e2e-kerb-06` | シナリオ C 実行後に krbtgt 運用ガイドパネルが自動展開される | `AttackDefensePanel` が表示されている |
| `e2e-kerb-07` | 攻撃完了後に Defender View に切り替える | 通常の `KerberosDemo` が表示され、攻撃バナーが消える |

---

## 7. i18n キー一覧表

| # | キー概念 | 日本語 | English |
|---|---------|--------|---------|
| 1 | 攻撃者モード切替 | `攻撃者モード` | `Attacker Mode` |
| 2 | 防御者モード切替 | `防御者モード` | `Defender Mode` |
| 3 | 教育バナーテキスト | `教育用シミュレーション — 実環境を攻撃するためのコードではありません` | `Educational simulation — not for use against real systems` |
| 4 | シナリオ A 名 | `Pass-the-Ticket (TGS 窃取・再利用)` | `Pass-the-Ticket (Service Ticket Theft & Replay)` |
| 5 | シナリオ B 名 | `Kerberoasting (SPN ハッシュ抽出・辞書攻撃)` | `Kerberoasting (SPN Hash Extraction & Dictionary Attack)` |
| 6 | シナリオ C 名 | `Golden Ticket (KDC 長期鍵偽造 TGT)` | `Golden Ticket (Forged TGT via krbtgt Key)` |
| 7 | 攻撃実行ボタン | `攻撃を実行` | `Run Attack` |
| 8 | 実行中ラベル | `実行中...` | `Running...` |
| 9 | 攻撃成立バナー | `攻撃成立 — この実装は脆弱です` | `Attack succeeded — this implementation is vulnerable` |
| 10 | 防御成立バナー | `防御成立 —` | `Defense succeeded —` |
| 11 | 被害者プリンシパルラベル | `被害者プリンシパル` | `Victim Principal` |
| 12 | 対象 SPN ラベル | `対象 SPN` | `Target SPN` |
| 13 | 弱パスワード SPN ラベル | `http/weak-service (弱パスワード — 辞書語)` | `http/weak-service (Weak Password — Dictionary Word)` |
| 14 | 強パスワード SPN ラベル | `http/strong-service (強パスワード — 20文字ランダム)` | `http/strong-service (Strong Password — 20-char Random)` |
| 15 | 偽造プリンシパルラベル | `偽造するプリンシパル` | `Principal to forge` |
| 16 | チケット窃取注記 | `注: 実際のメモリ操作は行いません — 同一プロセス内のシミュレーションです` | `Note: No actual memory operations — in-process simulation` |
| 17 | Hashcat 省略注記 | `注: Hashcat の実装は省略 — 固定辞書 20 件との照合シミュレーションです` | `Note: Hashcat implementation is omitted — fixed 20-entry dictionary simulation` |
| 18 | Golden Ticket 前提注記 | `このシナリオは krbtgt 鍵が既に漏洩していると仮定します` | `This scenario assumes the krbtgt key has already been compromised` |
| 19 | krbtgt 実環境注記 | `実環境では krbtgt の取得自体が困難であり、DC への侵害が前提です` | `In real environments, obtaining krbtgt requires Domain Controller compromise` |
| 20 | 辞書照合結果 (弱) | `{N} 件目で一致: {password}` | `Match found at entry #{N}: {password}` |
| 21 | 辞書照合結果 (強) | `辞書 {N} 件で一致なし — 解読不可` | `No match in {N}-entry dictionary — cannot be cracked` |
| 22 | 偽造チケットバッジ | `[偽造]` | `[FORGED]` |
| 23 | チケット構造タイトル | `チケット構造` | `Ticket Structure` |
| 24 | TGT ラベル | `TGT (チケット発行チケット)` | `TGT (Ticket-Granting Ticket)` |
| 25 | TGS ラベル | `TGS (サービスチケット)` | `TGS (Service Ticket)` |
| 26 | Authenticator 説明 | `Authenticator: リプレイ防止用の nonce と タイムスタンプ` | `Authenticator: nonce and timestamp for replay prevention` |
| 27 | krbtgt ローテーション | `krbtgt の2回リセットで Golden Ticket を無効化` | `Double krbtgt reset invalidates all Golden Tickets` |
| 28 | PAC 検証説明 | `PAC (特権属性証明書) 検証: DC がグループ情報の改ざんを検出` | `PAC (Privilege Attribute Certificate) validation: DC detects forged group memberships` |
| 29 | Kerberoasting 実環境注記 | `実環境では強力なパスワードポリシーおよびサービスアカウントの管理策により成立しにくくなります` | `In real environments, strong password policies and service account management make this difficult` |
| 30 | タイムラインARIAラベル | `攻撃ステップログ` | `Attack step log` |

---

## 8. 関連ファイル

### 8.1 基盤設計書

| ファイル | 参照目的 |
|---------|---------|
| [DESIGN/00-overview.md](./00-overview.md) | 全体目的・カタログマトリクス・教育安全装置の4原則概要 |
| [DESIGN/01-architecture.md](./01-architecture.md) | バックエンドルート配置方針 (新規ファイル `kerberos-sim.ts (attack サブパス追加)`) |
| [DESIGN/02-ui-spec.md](./02-ui-spec.md) | `ViewModeToggle` / `AttackStepTimeline` / `AttackResultBanner` / `AttackDefensePanel` の詳細仕様 |
| [DESIGN/03-data-model.md](./03-data-model.md) | `AttackStep` / `AttackResult` / `AttackScenarioMeta` / `ServerTrace` 拡張の型定義 |
| [DESIGN/04-safety-guardrails.md](./04-safety-guardrails.md) | 禁止表現一覧 / ペイロード作成ルール / 開発レビューチェックリスト |

### 8.2 既存実装ファイル (変更・参照対象)

| ファイルパス | 変更種別 | 変更内容 |
|------------|---------|---------|
| `server/routes/kerberos-sim.ts` | 参照のみ | AP-REQ ハンドラを攻撃シナリオ A (Pass-the-Ticket) でそのまま呼び出す。変更不要 |
| `src/components/auth/KerberosFlow.tsx` | 追加 | `ViewModeToggle` import + `<Show when={viewMode() === "attacker"}>` ブロックで `KerberosAttackPanel` を条件表示 |
| `server/index.ts` | 変更なし | 既存の `app.route("/api/kerberos", kerberoSimRoutes)` をそのまま利用 (新規ファイル不要、attack サブパスは kerberos-sim.ts 内に追加) |
| `server/db/schema.ts` | 追加 | `kerberoasting_services` テーブル (教育専用 2 件シード) の DDL を `initSchema()` に追加 / `is_attack_sim` 列を `kerberos_tickets` に追加 |
| `shared/api-types.ts` | 参照 | `AttackStep`, `AttackResult` 型 (DESIGN/03 参照、変更不要であれば参照のみ) |

### 8.3 新規作成ファイル

| ファイルパス | 役割 |
|------------|------|
| `server/routes/kerberos-sim.ts` | 既存ファイルに 3 攻撃エンドポイント (`/attack/pass-the-ticket`, `/attack/kerberoasting`, `/attack/golden-ticket`) のサブパスを追加 |
| `src/components/auth/attacks/kerberos/KerberosAttackPanel.tsx` | 3 シナリオを統括するメインパネル |
| `src/components/auth/attacks/kerberos/PassTheTicketScenario.tsx` | シナリオ A の実行ロジックとチケット構造表示 |
| `src/components/auth/attacks/kerberos/KerberoastingScenario.tsx` | シナリオ B の SPN 選択と辞書照合比較表示 |
| `src/components/auth/attacks/kerberos/GoldenTicketScenario.tsx` | シナリオ C の偽造 TGT 生成と krbtgt 運用ガイド |
| `src/components/auth/attacks/kerberos/KerberosAttack.css` | 3 シナリオ共通スタイル (偽造チケット強調表示含む) |
| `src/components/auth/attacks/scenarios/kerberos-scenarios.ts` | `AttackScenarioMeta[]` の静的定義 (3 シナリオ分) |

---

*このドキュメントは `DESIGN/17-attack-kerberos.md` に配置。
実装を開始する前に DESIGN/00 〜 04 の基盤設計書を読了し、
特に DESIGN/04-safety-guardrails.md §4 のレビューチェックリストと
§3.3 の Kerberoasting / Golden Ticket に関する必須付記を確認すること。*
