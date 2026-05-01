---
title: 攻撃デモカタログ — データモデル
phase: design
last-updated: 2026-04-26
---

# 03. データモデル

本ドキュメントは「攻撃デモカタログ」機能で使用する共有型・DBスキーマ・ペイロード規約を完全定義する。
実装先は `shared/api-types.ts`（型定義）、`server/db/schema.ts`（DBスキーマ）、
`server/middleware/trace-logger.ts`（trace 拡張）の3ファイルに集中する。

---

## 1. 共有型 (`shared/api-types.ts` に追加)

### 1.1 AttackStepKind

攻撃ステップの種別を表す文字列リテラル型。各ステップが何をしているかを UI に伝えるための分類子。

```typescript
/**
 * 攻撃ステップの操作種別。
 * DataFlowPanel および AttackStepTimeline コンポーネントでアイコン・色の選択に使用される。
 *
 * - intercept : ネットワーク通信や認証フローを傍受・盗聴する操作
 *               例: MitM でパケットキャプチャ、トークンをスニッフィング
 * - tamper    : 傍受したデータを改竄する操作
 *               例: JWT ペイロードの書き換え、Cookie の改ざん
 * - replay    : 過去に取得した正規トークン/チケットを再送する操作
 *               例: セッション固定攻撃、Pass-the-Ticket
 * - forge     : 正規の署名・資格情報を持たない偽造データを作成する操作
 *               例: alg=none JWT、自己署名 SAML アサーション
 * - probe     : システムの応答を観察して情報を収集する操作
 *               例: ユーザー列挙、タイミング攻撃の計測
 * - verify    : 攻撃対象システムが防御しているかどうかを確認する操作
 *               例: state 検証、signature 検証、リプレイ検出
 * - exploit   : 脆弱性を利用して不正アクセス・権限昇格を行う操作
 *               例: IDOR で他ユーザーデータ取得、CSRF で意図しない操作実行
 * - blocked   : 防御機構がトリガーされ攻撃がブロックされたことを示す操作
 *               例: HMAC 検証失敗、replay counter 不一致
 */
export type AttackStepKind =
  | "intercept"
  | "tamper"
  | "replay"
  | "forge"
  | "probe"
  | "verify"
  | "exploit"
  | "blocked";
```

### 1.2 AttackStep

1回の攻撃シナリオを構成する個々のステップ。シナリオは複数の `AttackStep` の配列として表現される。

```typescript
/**
 * 攻撃シナリオを構成する1ステップ。
 * ServerTrace.attackSteps[] に格納され、DataFlowPanel の「攻撃」タブで時系列表示される。
 */
export interface AttackStep {
  /** ステップの一意識別子。シナリオスコープ内で重複しない UUID v4 またはインクリメント文字列。 */
  id: string;

  /** ステップの操作種別 (AttackStepKind 参照)。 */
  kind: AttackStepKind;

  /** 英語ラベル。DataFlowPanel のヘッダーおよびログ出力に使用。 */
  label: string;

  /** 日本語ラベル。i18n 切替時に使用。 */
  labelJa: string;

  /**
   * ステップの実行状態。
   * - pending  : 未実行 (UI では灰色)
   * - running  : 実行中 (UI ではスピナー)
   * - success  : 攻撃成功 (UI では赤)
   * - failed   : 攻撃失敗 / エラー (UI ではオレンジ)
   * - blocked  : 防御機構により阻止された (UI では緑)
   */
  status: "pending" | "running" | "success" | "failed" | "blocked";

  /**
   * このステップで送受信・改竄・生成されたデータの詳細。
   * タグ付きユニオン型 AttackStepPayload を参照。
   * undefined の場合、DataFlowPanel はペイロードカラムを省略表示する。
   */
  payload?: AttackStepPayload;

  /** 英語の補足説明。攻撃手法の詳細や防御のヒントを含む。 */
  detail?: string;

  /** 日本語の補足説明。 */
  detailJa?: string;

  /** Unix ミリ秒タイムスタンプ。ステップ作成時点の Date.now()。 */
  timestamp: number;
}
```

### 1.3 AttackStepPayload (タグ付きユニオン)

`AttackStep.payload` の型。`type` フィールドで判別する Tagged Union。
各攻撃タブで必要なペイロード種別を網羅的に定義する。

```typescript
/**
 * 攻撃ステップが保持するペイロードデータ。
 * `type` フィールドで TypeScript の型絞り込みが可能なタグ付きユニオン。
 *
 * 利用タブとペイロード種別の対応:
 *   jwt           → token    (alg=none, 改竄, 有効期限切れ)
 *   oauth         → http     (state CSRF, 偽コールバック)
 *   session-token → http     (セッション固定, Bearer リプレイ)
 *   rbac          → http + generic (IDOR, 権限昇格)
 *   webauthn      → credential + http (クレデンシャルフィッシング)
 *   oidc-saml     → token + http (SAML アサーション偽造)
 *   kerberos      → ticket   (Pass-the-Ticket, Golden Ticket)
 *   tls           → http + generic (ダウングレード, BEAST)
 *   sso-apikey    → credential + http (APIキー漏洩, HMACバイパス)
 *   password      → credential (クレデンシャルスタッフィング, レインボーテーブル)
 */
export type AttackStepPayload =
  // HTTP リクエスト/レスポンスの傍受・改竄・偽造
  | {
      type: "http";
      request?: {
        method: string;
        url: string;
        headers?: Record<string, string>;
        body?: unknown;
      };
      response?: {
        status: number;
        headers?: Record<string, string>;
        body?: unknown;
      };
      /** MitM 攻撃での改竄箇所のハイライト用フィールド名リスト。 */
      tamperedFields?: string[];
    }
  // JWT トークンの改竄・偽造
  | {
      type: "token";
      /** 改竄前の元トークン (Base64url エンコード済み完全文字列)。 */
      before?: string;
      /** 改竄後のトークン。 */
      after?: string;
      /** 使用アルゴリズム (例: "HS256", "RS256", "none")。 */
      algo?: string;
      /** デコード済みヘッダー。教育表示用。 */
      decodedHeader?: Record<string, unknown>;
      /** デコード済みペイロード。 */
      decodedPayload?: Record<string, unknown>;
      /** 署名検証結果。 */
      signatureValid?: boolean;
    }
  // パスワード/APIキーなどの資格情報
  | {
      type: "credential";
      /** 対象ユーザー名 (存在確認・列挙攻撃での観測値)。 */
      username?: string;
      /** 使用されているパスワードハッシュアルゴリズム (例: "bcrypt", "md5", "plain")。 */
      passwordHashAlgo?: string;
      /** 辞書攻撃やクレデンシャルスタッフィングで試行したパスワード候補。 */
      triedPasswords?: string[];
      /** レインボーテーブルでクラックされた元のパスワード文字列。 */
      crackedPassword?: string;
      /** APIキーのプレフィックス (漏洩時の特定に使用)。 */
      apiKeyPrefix?: string;
      /** APIキーのフルシークレット (教育目的表示のみ)。 */
      apiKeySecret?: string;
      /** HMAC 検証をスキップするために操作されたフラグ名。 */
      clearedFlag?: string;
    }
  // Kerberos チケット (TGT / サービスチケット)
  | {
      type: "ticket";
      /** チケットの DB ID (kerberos_tickets.id)。 */
      ticketId?: string;
      /** チケットの種別 ("TGT" | "ServiceTicket")。 */
      ticketType?: "TGT" | "ServiceTicket";
      /** チケット所有プリンシパル (例: "alice@OSI-DEMO.LOCAL")。 */
      principal?: string;
      /** チケットの暗号化対象 (例: "krbtgt/OSI-DEMO.LOCAL")。 */
      encryptedFor?: string;
      /** レルム名。 */
      realm?: string;
      /** 盗まれた/偽造されたチケットの暗号化データ (Base64)。 */
      encryptedData?: string;
      /** 復号済みフィールド (教育表示用)。 */
      decryptedFields?: Record<string, string>;
      /** セッションキー (教育表示用)。 */
      sessionKey?: string;
      /** 有効期限 ISO8601。 */
      validUntil?: string;
      /** Pass-the-Ticket 攻撃で使用された元チケットの principal。 */
      stolenFrom?: string;
    }
  // SAML アサーション
  | {
      type: "saml";
      /** アサーション XML (raw)。 */
      assertionXml?: string;
      /** 署名検証結果。 */
      signatureValid?: boolean;
      /** 対象 SP エンティティ ID。 */
      spEntityId?: string;
      /** サブジェクト NameID。 */
      nameId?: string;
      /** 属性マップ (attribute -> value)。 */
      attributes?: Record<string, string>;
      /** アサーション有効期限 ISO8601。 */
      notOnOrAfter?: string;
    }
  // TLS ハンドシェイク操作
  | {
      type: "tls";
      /** TLS バージョン (例: "TLS 1.0", "TLS 1.2", "TLS 1.3")。 */
      version?: string;
      /** ダウングレード後のバージョン。 */
      downgradedTo?: string;
      /** 使用された暗号スイート。 */
      cipherSuite?: string;
      /** ダウングレードされた暗号スイート。 */
      weakCipherSuite?: string;
      /** 証明書情報。 */
      certificate?: {
        subject: string;
        issuer: string;
        validFrom: string;
        validTo: string;
        selfSigned: boolean;
      };
      /** 中間者証明書 (偽造)。 */
      fakeCertificate?: {
        subject: string;
        issuer: string;
        selfSigned: boolean;
      };
    }
  // 汎用データ (上記に当てはまらない場合のフォールバック)
  | {
      type: "generic";
      /** 任意の Key-Value データ。DataFlowPanel で表形式表示。 */
      data: Record<string, unknown>;
    };
```

### 1.4 AttackResult

1回の攻撃シナリオ実行全体の結果を表す型。フロントエンドへのレスポンス `data` フィールドに含まれる。

E-1 (Phase 2 第一コミット) で `TExtra` ジェネリックを導入し、シナリオ固有の追加フィールドを `extra` に格納する。
デフォルト型 `Record<string, never>` は extra 不要なシナリオ向け。

E-2 (Phase 2 第一コミット) で「5 ステップ完全形 + 両モード並列実行」設計に変更したため、
`outcome` は実装上常に `"succeeded"` を返す (1 リクエストで脆弱+堅牢の両モードを実行し、
ステップ 4=脆弱の `status: "success"` とステップ 5=堅牢の `status: "blocked"` の両方を返すため)。
`outcome === "blocked"` / `"error"` は将来の単一モードシナリオ向けに型として残す。

```typescript
/**
 * 攻撃シナリオ実行の全体結果。
 * POST /api/<area>/attack/<scenario-id> の成功レスポンスの data フィールドに格納される。
 *
 * @template TExtra  シナリオ固有の追加フィールド型 (E-1)。デフォルトは extra なし。
 *                   利用例:
 *                   - jwt-alg-none / jwt-signature-stripping → AttackResult (extra なし)
 *                   - jwt-weak-secret-bruteforce → AttackResult<{ crackedSecret: string | null; attemptCount: number }>
 *                   - jwt-kid-injection → AttackResult<{ kidResolved: string }>
 */
export interface AttackResult<TExtra = Record<string, never>> {
  /** シナリオ ID (命名規則は §3 を参照)。 */
  scenarioId: string;

  /**
   * 攻撃の最終判定。
   * - succeeded : シナリオ実行が完了 (E-2 では両モード実行のため常にこの値)
   * - blocked   : 防御機構により阻止された (将来の単一モードシナリオ向け予約)
   * - error     : サーバーエラーや入力不正で実行不能
   */
  outcome: "succeeded" | "blocked" | "error";

  /** 攻撃開始 Unix ミリ秒。 */
  startedAt: number;

  /** 攻撃終了 Unix ミリ秒。 */
  finishedAt: number;

  /** 実行されたすべてのステップ (時系列順、5 ステップ完全形)。 */
  steps: AttackStep[];

  /**
   * 堅牢モード (ステップ 5) で発動した防御識別子。
   * 例: "jwt_signature_mismatch", "jwt_algorithms_allowlist", "jwt_kid_not_in_allowlist"
   */
  blockedBy?: string;

  /** 教育用サマリーメッセージ (英語、両モード結果の比較)。 */
  summary?: string;

  /** 教育用サマリーメッセージ (日本語、両モード結果の比較)。 */
  summaryJa?: string;

  /** attack_log テーブルに挿入された行の ID。 */
  logId?: number;

  /** シナリオ固有の追加フィールド (E-1 ジェネリック)。extra 不要シナリオでは undefined。 */
  extra?: TExtra;
}
```

**ヘルパー経由での生成**: 全攻撃ルートは `server/utils/attack-runner.ts` の `runAttackScenario(c, { schema, scenarioId, tabId, handler })` を使い、
ハンドラは 5 ステップ recordStep + `AttackRunResult<TExtra>` メタデータ ({ blockedBy, summary, summaryJa, extra?, payload? }) を返却する。
ヘルパーが `AttackResult<TExtra>` への組み立て・finalize・二重例外保護を担う (SEC-12 / ROB-FIND-011 統合)。

### 1.5 AttackScenarioMeta

フロントエンドの攻撃カタログ一覧表示で使用するメタ情報。静的データとして `src/data/attack-scenarios.ts` に定義し、API からも取得できる。

```typescript
/**
 * 攻撃シナリオのメタ情報。
 * 攻撃カタログ一覧 (GET /api/attacks) のレスポンスおよび
 * src/data/attack-scenarios.ts の静的定義で使用。
 */
export interface AttackScenarioMeta {
  /** シナリオ ID (命名規則は §3 を参照)。 */
  id: string;

  /**
   * 対応する認証タブ ID。
   * src/types/security.ts の AuthSubView 型と一致させる。
   * 例: "jwt", "oauth", "rbac", "kerberos", "fido2"
   */
  tabId: AuthSubView;

  /** 攻撃名 (英語)。例: "Algorithm None Attack" */
  name: string;

  /** 攻撃名 (日本語)。例: "アルゴリズム None 攻撃" */
  nameJa: string;

  /**
   * MITRE ATT&CK / OWASP カテゴリ。
   * 例: "T1552.004", "A2:Broken Authentication"
   */
  category: string;

  /**
   * CWE (Common Weakness Enumeration) ID。省略可。
   * 例: "CWE-347", "CWE-384"
   */
  cweId?: string;

  /**
   * CAPEC (Common Attack Pattern Enumeration and Classification) ID。省略可。
   * 例: "CAPEC-196", "CAPEC-61"
   */
  capecId?: string;

  /** 難易度 1(易)〜5(難)。 */
  difficulty: 1 | 2 | 3 | 4 | 5;

  /**
   * 主に影響する OSI 層。
   * 単一層は数値 (例: 7)、複合層は文字列 (例: "5/7") で表現する。
   */
  osiLayer: number | string;

  /** 深刻度。 */
  severity: "info" | "low" | "medium" | "high" | "critical";

  /** 攻撃の簡潔な説明 (英語)。100文字以内推奨。 */
  description: string;

  /** 攻撃の簡潔な説明 (日本語)。 */
  descriptionJa: string;

  /**
   * 対策・防御方法の概要 (英語)。
   * 攻撃成功 / blocked 問わずパネルに表示される教育コンテンツ。
   */
  mitigation: string;

  /** 対策・防御方法の概要 (日本語)。 */
  mitigationJa: string;

  /**
   * 参考リンク。RFC、OWASP チートシート等。
   * 例: ["https://tools.ietf.org/html/rfc7519", "https://owasp.org/..."]
   */
  references?: string[];
}
```

### 1.6 ServerTrace 拡張

既存の `ServerTrace` インターフェースに `attackSteps` および `isAttackMode` フィールドを追加する。
両フィールドとも省略可能なため、攻撃デモ以外のルートに影響を与えない。

```typescript
/**
 * 既存の ServerTrace に attackSteps と isAttackMode を追加。
 * 全フィールドは省略可能 (攻撃デモ以外のルートは attackSteps / isAttackMode を返さない)。
 */
export interface ServerTrace {
  dbQueries?: DbQuery[];
  cryptoOps?: CryptoOp[];
  sessionOps?: SessionOp[];
  /** 攻撃シナリオのステップ一覧。攻撃デモエンドポイントのみ付与。 */
  attackSteps?: AttackStep[];
  /** 攻撃デモエンドポイント (/attack/) から発生したトレースの場合 true。middleware が自動セット。 */
  isAttackMode?: boolean;
}
```

> **注意**: `api-types.ts` の既存 `ServerTrace` 定義を上記で置き換える。
> 既存フィールドはすべて `?` (省略可能) のままであるため後方互換性は維持される。

**`addAttackStep` の timestamp 共有規約 (ROB-FIND-009)**:
`TraceCollector.addAttackStep()` は `timestamp` を含む `AttackStep` を受け取れば既存値を尊重し、
`Omit<AttackStep, "timestamp">` であれば `Date.now()` を自動付与する。
`runAttackScenario` ヘルパーは 1 度計算した timestamp を `_trace.attackSteps` と
`AttackResult.steps` の両方に同じ値で格納し、UI 上の時系列突合を容易にする。

---

## 2. DB スキーマ追加 (`server/db/schema.ts`)

### 2.1 attack_log テーブル

攻撃デモの実行履歴を保持する専用テーブル。教材的な再現・比較用途に限定し、セキュリティ監査ログとしての使用は意図しない。

```sql
-- 攻撃デモ実行履歴テーブル
CREATE TABLE IF NOT EXISTS attack_log (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  -- シナリオ識別子 (例: "jwt-alg-none", "oauth-state-csrf")
  scenario_id      TEXT    NOT NULL,
  -- 対応するタブID (例: "jwt", "oauth", "rbac")
  tab_id           TEXT    NOT NULL,
  -- 攻撃開始 Unix ミリ秒タイムスタンプ
  started_at       INTEGER NOT NULL,
  -- 攻撃終了 Unix ミリ秒タイムスタンプ (NULL = 未完了)
  finished_at      INTEGER,
  -- 最終判定: 1=攻撃成功 (succeeded), 0=阻止/エラー
  success          INTEGER NOT NULL DEFAULT 0,
  -- 攻撃を阻止した機構の識別子 (例: "jwt_signature_mismatch")
  -- success=0 かつ error でない場合に設定される
  blocked_by       TEXT,
  -- AttackStep[] の JSON シリアライズ
  -- NULL でも可 (ステップを個別保持しない軽量モード用)
  steps_json       TEXT,
  -- 攻撃に使用された主ペイロードの JSON シリアライズ (AttackStepPayload)
  payload_json     TEXT,
  -- 実行時のセッション ID (sessions.id への参照。NULL 可)
  -- 外部キー制約は設けない (セッション削除後も履歴を保持するため)
  user_session_id  TEXT
);

-- シナリオ別の集計・絞り込みに使用
CREATE INDEX IF NOT EXISTS idx_attack_log_scenario
  ON attack_log(scenario_id);

-- タブ別の集計・絞り込みに使用
CREATE INDEX IF NOT EXISTS idx_attack_log_tab
  ON attack_log(tab_id);

-- 時系列ソートに使用
CREATE INDEX IF NOT EXISTS idx_attack_log_started_at
  ON attack_log(started_at DESC);
```

**TypeScript 行型** (`shared/api-types.ts` に追加):

```typescript
/** attack_log テーブルの行型。 */
export interface AttackLogRow {
  id: number;
  scenario_id: string;
  tab_id: string;
  started_at: number;
  finished_at: number | null;
  success: 0 | 1;
  blocked_by: string | null;
  steps_json: string | null;    // JSON string: AttackStep[]
  payload_json: string | null;  // JSON string: AttackStepPayload
  user_session_id: string | null;
}
```

### 2.2 用途

| 用途 | 説明 |
|------|------|
| 教材としての履歴保持 | 同じ攻撃を複数回実行したときの結果を比較表示できる |
| AttackMap.tsx との統合 | 将来の攻撃マップビューが `GET /api/attack-log` を参照してヒートマップ表示 |
| 統計サマリー表示 | `成功 N 回 / 阻止 M 回` をデモ UI に表示する用途 |
| リセット後のクリア | `POST /api/reset` 呼び出し時に他テーブルと同様にクリアされる |

### 2.3 既存テーブルへの影響

`attack_log` テーブルは他の既存テーブルへの `FOREIGN KEY` を持たない設計とする。
これは次の理由による:

- `sessions` テーブルのレコードはリセット時に削除されるが、攻撃ログは履歴として保持したい
- 攻撃デモは既存テーブル (`webauthn_credentials`, `sessions`, `kerberos_tickets` 等) のレコードを
  意図的に改竄・汚染することがあるが、`POST /api/reset` で全テーブルが初期化されるため問題ない

**`seedDb()` への追記内容** (`server/db/schema.ts` の `DELETE FROM` ブロックに以下を追加):

```sql
DELETE FROM attack_log;
```

---

## 3. シナリオ ID の命名規則

### 3.1 形式

```
<tab-id>-<attack-kebab-name>
```

- `<tab-id>`: 認証タブの ID (`src/types/security.ts` の `AuthSubView` 型)
- `<attack-kebab-name>`: 攻撃名の kebab-case 表記
- 全体を小文字、ハイフン区切りとする

### 3.2 一覧 (各 DESIGN/10-21 ファイルで詳細定義)

各シナリオ ID は DESIGN/10-21 を正とする。以下は DESIGN/10-21 から抽出した実確認済み一覧。

| シナリオ ID | タブ (AuthSubView) | 攻撃手法 |
|------------|-------------------|---------|
| `password-rainbow-vs-bcrypt` | `auth-methods` | bcrypt vs レインボーテーブル比較 |
| `password-timing-string-compare` | `auth-methods` | タイミング攻撃 (文字列比較) |
| `password-bruteforce-no-rate-limit` | `auth-methods` | レート制限なしブルートフォース |
| `jwt-alg-none` | `jwt` | alg=none 署名バイパス |
| `jwt-weak-secret-bruteforce` | `jwt` | HS256 弱秘密鍵ブルートフォース |
| `jwt-signature-stripping` | `jwt` | 署名ストリッピング |
| `jwt-kid-injection` | `jwt` | kid ヘッダインジェクション |
| `oauth-state-csrf` | `oauth` | state パラメータ欠落 CSRF |
| `oauth-redirect-uri-bypass` | `oauth` | redirect_uri 検証バイパス |
| `oauth-code-via-referer` | `oauth` | 認可コード傍受 (Referer 漏洩) |
| `session-fixation` | `session-vs-token` | セッション固定攻撃 |
| `session-xss-cookie-theft` | `session-vs-token` | XSS Cookie 窃取 (HttpOnly 比較) |
| `token-replay` | `session-vs-token` | トークンリプレイ攻撃 |
| `rbac-idor` | `rbac` | IDOR (直接オブジェクト参照) |
| `rbac-horizontal-privilege-escalation` | `rbac` | 水平権限昇格 |
| `rbac-vertical-privilege-escalation` | `rbac` | 垂直権限昇格 |
| `rbac-abac-attribute-tampering` | `rbac` | ABAC 属性改竄 |
| `fido2-phishing-origin-rejection` | `fido2` | フィッシング耐性 (origin 検証失敗) |
| `fido2-vs-password-phishing` | `fido2` | パスワード認証との並列フィッシング比較 |
| `fido2-challenge-replay` | `fido2` | チャレンジリプレイ攻撃 |
| `saml-xsw` | `oidc-saml` | SAML XSW (XML署名ラッピング) |
| `saml-assertion-replay` | `oidc-saml` | SAMLアサーションリプレイ |
| `oidc-id-token-spoofing` | `oidc-saml` | ID Token なりすまし (aud 検証省略) |
| `kerberos-pass-the-ticket` | `kerberos` | Pass-the-Ticket |
| `kerberos-kerberoasting` | `kerberos` | Kerberoasting (SPN ハッシュ抽出) |
| `kerberos-golden-ticket` | `kerberos` | Golden Ticket (シミュレーション) |
| `tls-version-downgrade` | `tls-deep` | バージョンダウングレード |
| `tls-self-signed-mitm` | `tls-deep` | 自己署名証明書 MITM |
| `tls-weak-cipher-negotiation` | `tls-deep` | 弱い暗号スイートネゴシエーション |
| `apikey-leakage` | `sso-idp-apikey` | API キー漏洩 (ログ・URL 経由) |
| `apikey-hmac-bypass` | `sso-idp-apikey` | HMAC バイパス (署名検証省略) |
| `apikey-replay-no-timestamp` | `sso-idp-apikey` | タイムスタンプなしリプレイ |
| `mfa-otp-replay` | `mfa` | OTP リプレイ (同一コードの再使用) |
| `mfa-time-window-too-wide` | `mfa` | 時刻同期ずれによる OTP 拒否 (DoS) |
| `mfa-sms-swap` | `mfa` | SMS 乗っ取り (SIM スワップ シミュレーション) |
| `passkey-phishing-origin-binding` | `passkey` | フィッシング耐性 (origin binding で失敗) |
| `passkey-cloud-sync-compromise` | `passkey` | クラウド同期パスキーの侵害シミュレーション |
| `passkey-cross-device-mitm` | `passkey` | クロスデバイス認証の MITM シミュレーション |

---

## 4. AttackStepPayload の利用例 (タブ別)

### 4.1 パスワード認証 (`password-rainbow-table`)

```typescript
// ステップ1: hash を傍受
const step1: AttackStep = {
  id: "1",
  kind: "intercept",
  label: "Intercept password hash from DB",
  labelJa: "DBからパスワードハッシュを傍受",
  status: "success",
  payload: {
    type: "credential",
    username: "alice",
    passwordHashAlgo: "md5",  // bcrypt ではなく弱いアルゴリズムを想定
  },
  timestamp: Date.now(),
};

// ステップ2: レインボーテーブルでクラック
const step2: AttackStep = {
  id: "2",
  kind: "exploit",
  label: "Crack hash using rainbow table",
  labelJa: "レインボーテーブルでハッシュをクラック",
  status: "success",
  payload: {
    type: "credential",
    username: "alice",
    passwordHashAlgo: "md5",
    crackedPassword: "password123",
  },
  timestamp: Date.now(),
};
```

### 4.2 JWT (`jwt-alg-none`)

```typescript
// ステップ1: 元トークンを傍受
const step1: AttackStep = {
  id: "1",
  kind: "intercept",
  label: "Intercept JWT token",
  labelJa: "JWT トークンを傍受",
  status: "success",
  payload: {
    type: "token",
    before: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMSIsInJvbGUiOiJ2aWV3ZXIifQ.xxxx",
    algo: "HS256",
    decodedHeader: { alg: "HS256", typ: "JWT" },
    decodedPayload: { sub: "user1", role: "viewer" },
  },
  timestamp: Date.now(),
};

// ステップ2: alg=none に改竄・role=admin に昇格
const step2: AttackStep = {
  id: "2",
  kind: "forge",
  label: "Forge token with alg=none and role=admin",
  labelJa: "alg=none かつ role=admin でトークンを偽造",
  status: "success",
  payload: {
    type: "token",
    before: "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoidmlld2VyIn0.xxxx",
    after:  "eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.",
    algo: "none",
    decodedHeader: { alg: "none" },
    decodedPayload: { sub: "user1", role: "admin" },
    signatureValid: false,
  },
  timestamp: Date.now(),
};
```

### 4.3 OAuth 2.0 (`oauth-state-csrf`)

```typescript
// ステップ1: state パラメータを省略した偽コールバック URL を被害者に踏ませる
const step1: AttackStep = {
  id: "1",
  kind: "forge",
  label: "Craft malicious callback URL without state",
  labelJa: "state なしの悪意あるコールバック URL を作成",
  status: "success",
  payload: {
    type: "http",
    request: {
      method: "GET",
      url: "http://localhost:3000/auth/oauth/callback?code=ATTACKER_CODE&state=",
      headers: {},
    },
  },
  timestamp: Date.now(),
};

// ステップ2: state 検証で阻止される
const step2: AttackStep = {
  id: "2",
  kind: "blocked",
  label: "State validation blocks CSRF",
  labelJa: "state 検証により CSRF が阻止される",
  status: "blocked",
  payload: {
    type: "http",
    response: {
      status: 400,
      body: { error: "invalid_state", message: "State parameter mismatch" },
    },
  },
  detail: "The authorization server rejects callbacks with missing or mismatched state.",
  detailJa: "認可サーバーは state が欠落または不一致のコールバックを拒否します。",
  timestamp: Date.now(),
};
```

### 4.4 セッション / トークン認証 (`session-fixation`)

```typescript
// ステップ1: 攻撃者がセッション ID を事前に仕込む
const step1: AttackStep = {
  id: "1",
  kind: "tamper",
  label: "Inject pre-known session ID via URL param",
  labelJa: "URL パラメータで既知セッション ID を注入",
  status: "success",
  payload: {
    type: "http",
    request: {
      method: "GET",
      url: "http://localhost:3000/login?sessionid=FIXED_SESSION_ID",
      headers: { "Cookie": "sessionid=FIXED_SESSION_ID" },
    },
    tamperedFields: ["Cookie"],
  },
  timestamp: Date.now(),
};
```

### 4.5 RBAC (`rbac-idor-horizontal`)

```typescript
// ステップ1: 自分のユーザー ID (2) ではなく他ユーザー ID (1) のデータを取得試行
const step1: AttackStep = {
  id: "1",
  kind: "probe",
  label: "Attempt to access another user's resource",
  labelJa: "他ユーザーのリソースへアクセス試行",
  status: "success",
  payload: {
    type: "http",
    request: {
      method: "GET",
      url: "/api/users/1/profile",
      headers: { "Authorization": "Bearer <token-of-user-2>" },
    },
    response: {
      status: 200,
      body: { id: 1, username: "alice", email: "alice@example.com" },
    },
    tamperedFields: [],
  },
  timestamp: Date.now(),
};

// ステップ2: RBAC 評価結果の詳細
const step2: AttackStep = {
  id: "2",
  kind: "exploit",
  label: "IDOR: Resource ownership not verified",
  labelJa: "IDOR: リソース所有者チェックなし → データ漏洩",
  status: "success",
  payload: {
    type: "generic",
    data: {
      requestedUserId: 1,
      authenticatedUserId: 2,
      ownershipCheckPerformed: false,
      rbacPolicyChecked: true,
      rbacResult: "allowed (role=editor has users:read)",
      idorVulnerable: true,
    },
  },
  timestamp: Date.now(),
};
```

### 4.6 WebAuthn (`webauthn-replay`)

```typescript
// ステップ1: 認証レスポンスを傍受
const step1: AttackStep = {
  id: "1",
  kind: "intercept",
  label: "Capture authentication response",
  labelJa: "認証レスポンスを傍受",
  status: "success",
  payload: {
    type: "http",
    request: {
      method: "POST",
      url: "/api/webauthn/authenticate/verify",
      body: { id: "cred-id-xxx", response: { authenticatorData: "...", signature: "..." } },
    },
  },
  timestamp: Date.now(),
};

// ステップ2: 同じレスポンスを再送 → カウンター検証で阻止
const step2: AttackStep = {
  id: "2",
  kind: "blocked",
  label: "Replay blocked by signature counter check",
  labelJa: "署名カウンター検証によりリプレイが阻止される",
  status: "blocked",
  payload: {
    type: "http",
    response: {
      status: 401,
      body: { error: "Counter mismatch: possible cloning attack" },
    },
  },
  detail: "WebAuthn authenticators increment a counter on each use. Reuse of the same counter value is rejected.",
  detailJa: "WebAuthn 認証器は使用ごとにカウンターをインクリメントします。同一カウンター値の再使用は拒否されます。",
  timestamp: Date.now(),
};
```

### 4.7 OIDC & SAML (`saml-assertion-forgery`)

```typescript
// ステップ1: IdP 署名なしの SAML アサーションを偽造
const step1: AttackStep = {
  id: "1",
  kind: "forge",
  label: "Create unsigned SAML assertion with admin role",
  labelJa: "admin ロール付きの未署名 SAML アサーションを偽造",
  status: "success",
  payload: {
    type: "saml",
    assertionXml: `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Subject><saml:NameID>attacker</saml:NameID></saml:Subject>
  <saml:AttributeStatement>
    <saml:Attribute Name="role"><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>`,
    signatureValid: false,
    nameId: "attacker",
    attributes: { role: "admin" },
  },
  timestamp: Date.now(),
};
```

### 4.8 Kerberos (`kerberos-pass-the-ticket`)

```typescript
// ステップ1: TGT を盗む (メモリダンプシミュレーション)
const step1: AttackStep = {
  id: "1",
  kind: "intercept",
  label: "Extract TGT from memory (mimikatz simulation)",
  labelJa: "メモリから TGT を抽出 (mimikatz シミュレーション)",
  status: "success",
  payload: {
    type: "ticket",
    ticketType: "TGT",
    principal: "alice@OSI-DEMO.LOCAL",
    encryptedFor: "krbtgt/OSI-DEMO.LOCAL",
    realm: "OSI-DEMO.LOCAL",
    encryptedData: "AQIDBDKHGjkl...(Base64)",
    sessionKey: "xK8mN2pQ...(Base64)",
    validUntil: "2026-04-26T10:00:00Z",
    stolenFrom: "alice@OSI-DEMO.LOCAL",
  },
  timestamp: Date.now(),
};

// ステップ2: 盗んだ TGT で別プリンシパルとして認証
const step2: AttackStep = {
  id: "2",
  kind: "replay",
  label: "Inject stolen TGT into attacker session",
  labelJa: "盗んだ TGT を攻撃者セッションに注入",
  status: "success",
  payload: {
    type: "ticket",
    ticketType: "TGT",
    principal: "attacker@OSI-DEMO.LOCAL",
    encryptedFor: "krbtgt/OSI-DEMO.LOCAL",
    encryptedData: "AQIDBDKHGjkl...(Base64)",
    stolenFrom: "alice@OSI-DEMO.LOCAL",
  },
  timestamp: Date.now(),
};
```

### 4.9 TLS (`tls-downgrade`)

```typescript
// ステップ1: Client Hello で TLS 1.3 を提示
const step1: AttackStep = {
  id: "1",
  kind: "intercept",
  label: "Intercept TLS ClientHello",
  labelJa: "TLS ClientHello を傍受",
  status: "success",
  payload: {
    type: "tls",
    version: "TLS 1.3",
    cipherSuite: "TLS_AES_256_GCM_SHA384",
  },
  timestamp: Date.now(),
};

// ステップ2: 攻撃者が TLS 1.0 に書き換える
const step2: AttackStep = {
  id: "2",
  kind: "tamper",
  label: "Downgrade to TLS 1.0 with weak cipher",
  labelJa: "TLS 1.0 と弱い暗号スイートへダウングレード",
  status: "success",
  payload: {
    type: "tls",
    version: "TLS 1.3",
    downgradedTo: "TLS 1.0",
    weakCipherSuite: "TLS_RSA_WITH_RC4_128_MD5",
  },
  timestamp: Date.now(),
};
```

### 4.10 SSO / API Key (`apikey-hmac-bypass`)

```typescript
// ステップ1: API キーの漏洩
const step1: AttackStep = {
  id: "1",
  kind: "intercept",
  label: "Obtain leaked API key from public repository",
  labelJa: "公開リポジトリから漏洩した API キーを取得",
  status: "success",
  payload: {
    type: "credential",
    apiKeyPrefix: "osk_live_",
    apiKeySecret: "osk_live_xK8mN2pQjR4...",
  },
  timestamp: Date.now(),
};

// ステップ2: HMAC 署名なしのリクエストで検証バイパス試行
const step2: AttackStep = {
  id: "2",
  kind: "forge",
  label: "Send request without HMAC signature",
  labelJa: "HMAC 署名なしでリクエスト送信",
  status: "success",
  payload: {
    type: "http",
    request: {
      method: "POST",
      url: "/api/sso-apikey/verify",
      headers: {
        "X-API-Key": "osk_live_xK8mN2pQjR4...",
        // X-HMAC-Signature ヘッダーを意図的に省略
      },
      body: { action: "transfer", amount: 10000 },
    },
    tamperedFields: ["X-HMAC-Signature"],
  },
  timestamp: Date.now(),
};

// ステップ3: HMAC 検証で阻止
const step3: AttackStep = {
  id: "3",
  kind: "blocked",
  label: "HMAC validation rejects unsigned request",
  labelJa: "HMAC 検証が未署名リクエストを拒否",
  status: "blocked",
  payload: {
    type: "http",
    response: {
      status: 401,
      body: { error: "Missing or invalid HMAC signature" },
    },
  },
  timestamp: Date.now(),
};
```

---

## 5. trace-logger 拡張 API

### 5.1 TraceCollector インターフェース拡張

`server/middleware/trace-logger.ts` の `TraceCollector` インターフェースと `createTraceCollector` 関数に
`addAttackStep` メソッドを追加する。

```typescript
// server/middleware/trace-logger.ts

import type {
  ServerTrace,
  DbQuery,
  CryptoOp,
  SessionOp,
  AttackStep,            // ← 追加インポート
} from "../../shared/api-types.js";

export interface TraceCollector {
  addDbQuery(q: DbQuery): void;
  addCryptoOp(op: CryptoOp): void;
  addSessionOp(op: SessionOp): void;
  /** 攻撃ステップを追加する。timestamp は自動付与されるため省略可。 */
  addAttackStep(step: Omit<AttackStep, "timestamp">): void;
  getTrace(): ServerTrace;
}

function createTraceCollector(): TraceCollector {
  const dbQueries: DbQuery[] = [];
  const cryptoOps: CryptoOp[] = [];
  const sessionOps: SessionOp[] = [];
  const attackSteps: AttackStep[] = [];        // ← 追加

  return {
    addDbQuery(q) { dbQueries.push(q); },
    addCryptoOp(op) { cryptoOps.push(op); },
    addSessionOp(op) { sessionOps.push(op); },
    /** timestamp を自動付与して attackSteps に追加する。 */
    addAttackStep(step) {
      attackSteps.push({ ...step, timestamp: Date.now() });
    },
    getTrace() {
      const trace: ServerTrace = {};
      if (dbQueries.length)   trace.dbQueries   = dbQueries;
      if (cryptoOps.length)   trace.cryptoOps   = cryptoOps;
      if (sessionOps.length)  trace.sessionOps  = sessionOps;
      if (attackSteps.length) trace.attackSteps = attackSteps; // ← 追加
      return trace;
    },
  };
}
```

### 5.1.1 attackSteps アクセスパターン規約

全 DESIGN/10-21 の攻撃ルートで統一すべき `getTrace().attackSteps` のアクセスパターン:

```typescript
// 正しいパターン (全 1X DESIGN で統一)
const steps = trace.getTrace().attackSteps ?? [];
// result.steps への代入
const result: AttackResult = {
  scenarioId: "xxx",
  outcome: "succeeded",
  startedAt,
  finishedAt: Date.now(),
  steps: trace.getTrace().attackSteps ?? [],  // undefined 時は空配列
};
```

- `attackSteps` が存在しない場合 (攻撃ステップなしのルート) は `?? []` で空配列を保証すること
- `result.steps` フィールドに代入する際は必ずこのパターンを使用すること (DESIGN/03 §1.4 の `steps: AttackStep[]`)

### 5.2 ルートからの呼び出しパターン

攻撃デモルート (`server/routes/attack-*.ts`) での使用例:

```typescript
// server/routes/attack-jwt.ts (例)
import { Hono } from "hono";
import type { AttackStep } from "../../shared/api-types.js";

const app = new Hono();

jwtOpsRoutes.post("/attack/alg-none", async (c) => {
  const trace = c.get("trace");

  // ステップ1: 傍受
  trace.addAttackStep({
    id: "step-1",
    kind: "intercept",
    label: "Intercept JWT token",
    labelJa: "JWT トークンを傍受",
    status: "success",
    payload: { type: "token", before: "...", algo: "HS256" },
  });

  // ステップ2: 偽造
  trace.addAttackStep({
    id: "step-2",
    kind: "forge",
    label: "Forge alg=none token",
    labelJa: "alg=none トークンを偽造",
    status: "success",
    payload: {
      type: "token",
      after: "eyJhbGciOiJub25lIn0.xxx.",
      algo: "none",
      signatureValid: false,
    },
  });

  // attack_log への INSERT は別途 logAttack ヘルパー経由
  const logId = logAttack(c, { scenarioId: "jwt-alg-none", tabId: "jwt", outcome: "succeeded", steps: trace.getTrace().attackSteps ?? [] });

  return c.json({ success: true, data: { outcome: "succeeded", logId }, _trace: trace.getTrace() });
});
```

---

## 6. JSON シリアライゼーション規約

### 6.1 トークン・秘密情報の表示方針

本アプリは教育目的のため、以下の方針で**平文表示**を許容する:

| フィールド | 方針 | 理由 |
|-----------|------|------|
| JWT トークン全文 | 平文表示 | アルゴリズム・ペイロード構造の学習のため |
| JWT シークレット | 平文表示 (教育用注釈付き) | 署名検証の仕組みを示すため |
| Kerberos セッションキー | 平文表示 | 暗号化チケット構造の学習のため |
| API キーシークレット | 平文表示 (demo 環境限定) | API キー漏洩のリスクを体験させるため |
| パスワード (平文) | 漏洩シナリオのみ表示 | 弱いハッシュのリスクを示すため |
| bcrypt ハッシュ | 平文表示 | ハッシュの一方向性を学ぶため |

**本番環境への適用禁止**: `server/index.ts` に `NODE_ENV !== "production"` ガードを設け、
本番ビルドでは全 attack エンドポイントを無効化することを推奨する。

### 6.2 `attack_log.steps_json` のシリアライゼーション

```typescript
// INSERT 時
const stepsJson = JSON.stringify(attackSteps);

// SELECT 後のデシリアライズ
const steps: AttackStep[] = JSON.parse(row.steps_json ?? "[]");
```

- `undefined` フィールドは `JSON.stringify` で除外されるため、省略フィールドは DB に保存されない
- `payload` が `undefined` のステップも正常に保存・復元できる

### 6.3 機微フィールドの命名規約

`AttackStepPayload` に将来フィールドを追加する場合、以下の命名規約を推奨:

| プレフィックス | 意味 | 例 |
|--------------|------|-----|
| `test_` | テスト・デモ専用フィールド | `test_secret`, `test_key` |
| `fake_` | 偽造・攻撃者が作成したデータ | `fakeCertificate`, `fakeToken` |
| `stolen_` | 盗まれたデータ | `stolenFrom` (既定義) |
| `cracked_` | クラックされたデータ | `crackedPassword` (既定義) |

---

## 7. バリデーション (zod スキーマ)

`server/validation.ts` (新規作成) または既存の入力バリデーションファイルへ以下を追加する。

```typescript
// server/validation.ts
import { z } from "zod";

/** 攻撃シナリオ実行リクエストのバリデーションスキーマ。 */
export const attackRunSchema = z.object({
  /**
   * 実行するシナリオ ID。§3 の命名規則に従う。
   * 例: "jwt-alg-none", "oauth-state-csrf"
   */
  scenarioId: z
    .string()
    .min(1)
    .max(64)
    .regex(/^[a-z0-9-]+$/, "scenarioId must be kebab-case"),

  /**
   * 追加パラメータ。シナリオによっては対象ユーザー名や
   * 対象リソース ID を渡す場合に使用。
   */
  params: z.record(z.unknown()).optional(),
});

export type AttackRunRequest = z.infer<typeof attackRunSchema>;

/** attack_log への INSERT 入力のバリデーション。 */
export const attackLogInsertSchema = z.object({
  scenario_id:     z.string().min(1).max(64),
  tab_id:          z.string().min(1).max(32),
  started_at:      z.number().int().positive(),
  finished_at:     z.number().int().positive().optional(),
  success:         z.union([z.literal(0), z.literal(1)]),
  blocked_by:      z.string().max(128).optional(),
  steps_json:      z.string().optional(),
  payload_json:    z.string().optional(),
  user_session_id: z.string().max(128).optional(),
});

/** 攻撃ログ取得クエリパラメータのバリデーション。 */
export const attackLogQuerySchema = z.object({
  scenario_id: z.string().optional(),
  tab_id:      z.string().optional(),
  limit:       z.coerce.number().int().min(1).max(100).default(20),
  offset:      z.coerce.number().int().min(0).default(0),
});
```

> **依存関係**: `zod` が `package.json` に未追加の場合、`npm install zod` を実行する。
> 既存コードに zod が使われていない場合は `server/routes/attack-*.ts` 内でのみインポートし、
> 他ルートへの影響をゼロにする。

---

## 8. 関連ファイル

設計書が直接参照・修正対象とするファイル一覧:

| ファイルパス | 変更種別 | 変更内容 |
|------------|---------|---------|
| `shared/api-types.ts` | 追加 | `AttackStepKind`, `AttackStep`, `AttackStepPayload`, `AttackResult`, `AttackScenarioMeta`, `AttackLogRow` 型定義 / `ServerTrace` へ `attackSteps?` フィールド追加 |
| `server/db/schema.ts` | 追加 | `attack_log` テーブル + 3インデックスの DDL / `seedDb()` の DELETE リストに `attack_log` を追加 |
| `server/middleware/trace-logger.ts` | 修正 | `TraceCollector` に `addAttackStep()` 追加 / `createTraceCollector()` に `attackSteps` 配列と実装追加 |
| `server/validation.ts` | 新規 | `attackRunSchema`, `attackLogInsertSchema`, `attackLogQuerySchema` |
| `src/data/attack-scenarios.ts` | 新規 | `AttackScenarioMeta[]` の静的定義 (§3 シナリオ ID 一覧を元に定義) |

設計書が間接的に影響する既存ファイル一覧:

| ファイルパス | 影響内容 |
|------------|---------|
| `server/routes/` 配下の各ルート | 攻撃デモルート追加時に `trace.addAttackStep()` を呼び出す |
| `src/components/shared/DataFlowPanel.tsx` | `attackSteps` を新しいタブとして表示するための拡張が必要 |
| `src/api/client.ts` | `AttackResult` 型を使用した `apiPost` の型引数として利用 |
| `server/index.ts` | 新規攻撃ルートの登録 + `NODE_ENV` ガードの追加 |

---

## 付録 A: 型依存関係図

```
shared/api-types.ts
├── AttackStepKind          (string literal union)
├── AttackStepPayload       (tagged union, kind: http | token | credential | ticket | saml | tls | generic)
├── AttackStep              (uses AttackStepKind, AttackStepPayload)
├── AttackResult            (uses AttackStep[])
├── AttackScenarioMeta      (standalone)
├── AttackLogRow            (DB row, standalone)
└── ServerTrace             (extends existing: adds attackSteps?: AttackStep[])
    ├── DbQuery             (既存)
    ├── CryptoOp            (既存)
    └── SessionOp           (既存)
```

## 付録 B: attack_log ER 図 (テキスト表現)

```
attack_log
  id               PK
  scenario_id      NOT NULL  ← §3 の命名規則に従う
  tab_id           NOT NULL  ← src/types/security.ts の AuthSubView 型 と一致
  started_at       NOT NULL
  finished_at      NULL可
  success          NOT NULL DEFAULT 0
  blocked_by       NULL可
  steps_json       NULL可    ← JSON: AttackStep[]
  payload_json     NULL可    ← JSON: AttackStepPayload
  user_session_id  NULL可    ← 参照のみ (FK なし)

INDEX: scenario_id, tab_id, started_at DESC
```

`sessions` テーブルとの論理的な参照関係はあるが、リセット時の整合性維持のため物理的な外部キーは設けない。
`user_session_id` は履歴追跡の補助情報として保持する。

---

*このドキュメントは `DESIGN/03-data-model.md` に配置。次フェーズの設計書 (DESIGN/04-*.md) では
各攻撃シナリオの具体的な API 設計・フロー図を定義する。*
