---
title: 攻撃デモカタログ — 全体概要
phase: design
audience: 開発者・教材執筆者
last-updated: 2026-04-26
---

# 00. 攻撃デモカタログ — 全体概要

## 1. 目的と教材としての位置付け

### 1.1 教材として何を解決するか

現行の OSI 参照アプリは、認証・認可の「正常系」をインタラクティブに学ぶことができる。しかし教材として次の課題が残っている。

- 「なぜこの防御策が必要なのか」を体感として示せていない
- 攻撃者がどのような操作をするのかが抽象論にとどまっている
- 防御の実装が「あって当たり前」のものとして見過ごされやすい

本機能「攻撃デモカタログ」は、各認証タブに **Attacker View** モードを追加し、攻撃者の視点からリクエストを組み立て・送信する対話的シミュレーションを提供する。学習者は次の3ステップで理解を深める。

1. **Defender View** (通常): 正常な認証フローと防御策の実装を確認する
2. **Attacker View**: 防御を無効化・回避する攻撃リクエストを構築・実行し、失敗結果または（意図的に脆弱にした）成功結果を観察する
3. **解説パネル**: なぜ攻撃が成立するか・しないかを防御策と紐付けて理解する

### 1.2 教育上の設計方針

| 方針 | 説明 |
|------|------|
| 体感優先 | 正常フローとの差分を同一 UI で比較できるようにする |
| 対応関係の明示 | 各攻撃シナリオには必ず「この防御実装がなかったら成功する」の対が存在する |
| 安全隔離 | 攻撃はすべてローカル Hono サーバー内でシミュレート。外部通信なし |
| 段階的難易度 | Critical 攻撃は step-by-step アニメーション付き、Info 相当は静的解説で十分 |

---

## 2. 既存機能との関係

### 2.1 認証タブとの統合

既存の 12 認証タブ (`AuthSubView` 型で管理: `oauth`, `jwt`, `tls-deep`, `session-vs-token`, `rbac`, `auth-methods`, `oidc-saml`, `fido2`, `mfa`, `passkey`, `kerberos`, `sso-idp-apikey`) に対し、タブコンテンツ内に「モードトグル」を追加する。

- **変更範囲**: 各タブコンポーネント (`OAuthFlow.tsx`, `JwtInspector.tsx` など) 内部にトグル UI を追加
- **ルーティング変更なし**: `/auth/:subtab` のパスは変更しない。Attacker View はタブ内の Signal で管理
- `AuthView.tsx` の `<Switch>/<Match>` 構造には手を加えない

### 2.2 既存 `AttackMap.tsx` との違い

| 観点 | AttackMap.tsx (View 6 / security) | 攻撃デモカタログ (View 5 / auth タブ内) |
|------|-----------------------------------|---------------------------------------|
| 目的 | OSI 7層全体の脅威を俯瞰マップで把握 | 認証プロトコル別の攻撃を対話的に実行 |
| 粒度 | 脅威の種類・層・深刻度の一覧 | 具体的な攻撃リクエスト・レスポンスの詳細 |
| インタラクション | カード展開 + 簡易シミュレーション (3秒タイムアウト) | ステップタイムライン + DataFlowPanel で HTTP/_trace を可視化 |
| データソース | `src/data/security-attacks.ts` の静的 `OsiAttack[]` | 新規 `server/routes/attack-*.ts` が動的生成する `AttackResult` |
| 統合 | View 6 の `SecurityView` 内コンポーネント | View 5 の各認証タブ内コンポーネント |
| スコープ | Layer 1〜7 の汎用脅威 (SQL Injection, ARP Spoofing など) | 認証・認可プロトコル固有の攻撃 (alg=none, IDOR など) |

### 2.3 View 6 (security) との統合

今回スコープ外。将来的に `AttackMap.tsx` が認証タブ攻撃への深掘りリンクを持つ設計は考慮するが、本フェーズでは独立実装とする。

---

## 3. 教育安全装置の原則

詳細は `DESIGN/04-safety-guardrails.md` にて規定する。ここでは4原則の概要のみ示す。

| # | 原則 | 実装方針 |
|---|------|---------|
| 1 | **隔離 (Isolation)** | 攻撃リクエストの宛先は `/api/<area>/attack/<scenario-id>` 形式のみ。外部 URL へのリクエストは生成しない |
| 2 | **明示 (Labeling)** | Attacker View は赤帯バナー「教育用シミュレーション — 実環境での使用禁止」を常時表示 |
| 3 | **簡略化 (Simplification)** | 実際のエクスプロイトコードは含まない。バイナリ操作・RCE・実CVEの再現は行わない |
| 4 | **防御策提示 (Defense Pairing)** | すべての攻撃シナリオは最低1つの「防御策パネル」と対になる。攻撃成功後は自動で防御解説を表示 |

---

## 4. 全体ナビゲーション

### 4.1 UI フロー概要

```
[認証タブ上部]
  ┌─────────────────────────────────────────┐
  │  ○ Defender View  |  ● Attacker View   │  ← ViewModeToggle コンポーネント
  └─────────────────────────────────────────┘

[Attacker View アクティブ時]
  ┌─────────────────────────────────────────┐
  │  [!] 教育用シミュレーション             │  ← 赤帯バナー (常時表示)
  ├─────────────────────────────────────────┤
  │  シナリオセレクタ                        │  ← AttackScenarioMeta[] からドロップダウン
  │  ┌────────────────────────────────────┐ │
  │  │ タイムライン (AttackStep[])         │ │  ← ステップ実行アニメーション
  │  │  Step 1: [実行] ──→ レスポンス     │ │
  │  │  Step 2: [実行] ──→ レスポンス     │ │
  │  └────────────────────────────────────┘ │
  │  結果バナー (AttackResult)              │  ← 成功/失敗 + 理由
  │  防御策解説パネル                       │  ← 攻撃完了後に展開
  ├─────────────────────────────────────────┤
  │  DataFlowPanel (HTTP / _trace / DB)    │  ← 既存コンポーネント流用
  └─────────────────────────────────────────┘
```

### 4.2 既存 DataFlowPanel との接続

各攻撃ステップは `apiPost` / `apiGet` (`src/api/client.ts`) を通じて実行されるため、既存の `DataFlowPanel` が scopeId ベースで HTTP exchange を自動キャプチャする。追加実装不要。攻撃デモ専用のスコープ ID は `"attack-{tabId}"` 形式とする。

---

## 5. 攻撃カタログ全体像

### 5.1 タブ × 攻撃 マトリクス

| # | タブ ID | タブ名 | 攻撃シナリオ | CWE | CAPEC | OSI層 | 深刻度 |
|---|---------|--------|-------------|-----|-------|-------|-------|
| 1 | `auth-methods` | 認証方式 | bcrypt vs レインボーテーブル比較 | CWE-916 | CAPEC-49 | L7 | High |
| 1 | `auth-methods` | 認証方式 | タイミング攻撃 (timing attack) | CWE-208 | CAPEC-462 | L7 | Medium |
| 1 | `auth-methods` | 認証方式 | ブルートフォース (レート制限なし vs あり) | CWE-307 | CAPEC-112 | L7 | High |
| 2 | `jwt` | JWT | alg=none 署名バイパス | CWE-347 | CAPEC-196 | L7 | Critical |
| 2 | `jwt` | JWT | HS256 弱秘密鍵ブルートフォース | CWE-326 | CAPEC-20 | L7 | High |
| 2 | `jwt` | JWT | 署名ストリッピング | CWE-345 | CAPEC-196 | L7 | Critical |
| 2 | `jwt` | JWT | kid ヘッダインジェクション | CWE-74 | CAPEC-88 | L7 | Critical |
| 3 | `oauth` | OAuth 2.0 | state パラメータ欠落 CSRF | CWE-352 | CAPEC-62 | L7 | High |
| 3 | `oauth` | OAuth 2.0 | redirect_uri 検証バイパス | CWE-601 | CAPEC-194 | L7 | High |
| 3 | `oauth` | OAuth 2.0 | 認可コード傍受 (Referer 漏洩) | CWE-598 | CAPEC-94 | L7 | Medium |
| 4 | `session-vs-token` | セッション vs トークン | セッション固定攻撃 | CWE-384 | CAPEC-61 | L5/L7 | High |
| 4 | `session-vs-token` | セッション vs トークン | XSS Cookie 窃取 (HttpOnly 有/無比較) | CWE-1004 | CAPEC-86 | L7 | High |
| 4 | `session-vs-token` | セッション vs トークン | トークンリプレイ攻撃 | CWE-294 | CAPEC-60 | L7 | High |
| 5 | `rbac` | アクセス制御 | IDOR (直接オブジェクト参照) | CWE-639 | CAPEC-1 | L7 | High |
| 5 | `rbac` | アクセス制御 | 水平権限昇格 | CWE-284 | CAPEC-122 | L7 | High |
| 5 | `rbac` | アクセス制御 | 垂直権限昇格 | CWE-269 | CAPEC-122 | L7 | Critical |
| 5 | `rbac` | アクセス制御 | ABAC 属性改竄 | CWE-807 | CAPEC-1 | L7 | High |
| 6 | `fido2` | FIDO2/WebAuthn | フィッシング耐性 (origin 検証で失敗を見せる) | CWE-346 | CAPEC-194 | L7 | Info |
| 6 | `fido2` | FIDO2/WebAuthn | パスワード vs FIDO2 フィッシング比較 (`fido2-vs-password-phishing`) | CWE-290 | CAPEC-89 | L7 | High |
| 6 | `fido2` | FIDO2/WebAuthn | チャレンジリプレイ阻止 (`fido2-challenge-replay`) | CWE-294 | CAPEC-60 | L7 | Info |
| 7 | `oidc-saml` | OIDC & SAML | SAML XSW (XML署名ラッピング) | CWE-347 | CAPEC-196 | L7 | Critical |
| 7 | `oidc-saml` | OIDC & SAML | SAMLアサーションリプレイ | CWE-294 | CAPEC-60 | L7 | High |
| 7 | `oidc-saml` | OIDC & SAML | ID Token なりすまし (aud 検証省略) | CWE-345 | CAPEC-196 | L7 | Critical |
| 8 | `kerberos` | Kerberos | Pass-the-Ticket | CWE-522 | CAPEC-196 | L5/L7 | Critical |
| 8 | `kerberos` | Kerberos | Kerberoasting (SPN ハッシュ抽出) | CWE-916 | CAPEC-20 | L7 | High |
| 8 | `kerberos` | Kerberos | Golden Ticket (シミュレーション) | CWE-522 | CAPEC-196 | L7 | Critical |
| 9 | `tls-deep` | TLS 詳細 | バージョンダウングレード (TLS 1.0 強制) | CWE-757 | CAPEC-220 | L6 | High |
| 9 | `tls-deep` | TLS 詳細 | 自己署名証明書 MITM | CWE-295 | CAPEC-94 | L6 | High |
| 9 | `tls-deep` | TLS 詳細 | 弱い暗号スイートネゴシエーション | CWE-326 | CAPEC-220 | L6 | High |
| 10 | `sso-idp-apikey` | SSO / API Key | API キー漏洩 (ログ・URL 経由) | CWE-312 | CAPEC-37 | L7 | High |
| 10 | `sso-idp-apikey` | SSO / API Key | HMAC バイパス (署名検証省略) | CWE-347 | CAPEC-196 | L7 | Critical |
| 10 | `sso-idp-apikey` | SSO / API Key | タイムスタンプなしリプレイ | CWE-294 | CAPEC-60 | L7 | High |
| 11 | `mfa` | MFA/TOTP | OTP リプレイ (同一コードの再使用) | CWE-294 | CAPEC-60 | L7 | High |
| 11 | `mfa` | MFA/TOTP | 時刻同期ずれによる OTP 拒否 (DoS) | CWE-362 | CAPEC-25 | L7 | Medium |
| 11 | `mfa` | MFA/TOTP | SMS 乗っ取り (SIM スワップ シミュレーション) | CWE-308 | CAPEC-151 | L7 | High |
| 12 | `passkey` | パスキー | フィッシング耐性 (origin binding で失敗) | CWE-346 | CAPEC-194 | L7 | Info |
| 12 | `passkey` | パスキー | クラウド同期侵害シミュレーション (`passkey-cloud-sync-compromise`) | CWE-287 | CAPEC-560 | L7 | High |
| 12 | `passkey` | パスキー | Cross-device MITM 阻止 (`passkey-cross-device-mitm`) | CWE-300 | CAPEC-94 | L5/L7 | High |

### 5.2 深刻度の定義

本カタログにおける深刻度は CVSS v3.1 の Base Score レンジに準拠して4段階で定義する。

| 深刻度 | 定義 | 色 | 教材上の扱い |
|--------|------|-----|-------------|
| Critical | 認証バイパス・アカウント完全奪取が直接可能 | `#ff4d4f` | step-by-step アニメーション + 防御実装コード表示 |
| High | 情報漏洩・権限昇格が可能 | `#ff7a45` | タイムライン実行 + 防御策解説 |
| Medium | 攻撃条件が複数必要、または影響範囲が限定的 | `#faad14` | 単一ステップ実行 + 解説テキスト |
| Info | プロトコル設計で攻撃が成立しないことを示す | `#52c41a` | 失敗デモ (防御動作の確認) |

---

## 6. 設計書の構成と読み方

### 6.1 設計書ファイル一覧

```
DESIGN/
├── 00-overview.md          ← 本ファイル: 全体概要・目的・カタログ一覧
├── 01-architecture.md      ← バックエンド/フロントエンドの追加構成、新規ルート・型定義
├── 02-ui-spec.md           ← ViewModeToggle / AttackStepTimeline / AttackResultBanner の UI 仕様
├── 03-data-model.md        ← AttackScenarioMeta / AttackStep / AttackResult 型定義・DB スキーマ拡張
├── 04-safety-guardrails.md ← 教育安全装置の詳細実装方針
├── 10-auth-methods.md      ← auth-methods タブ攻撃詳細 (3シナリオ)
├── 11-jwt.md               ← jwt タブ攻撃詳細 (4シナリオ)
├── 12-oauth.md             ← oauth タブ攻撃詳細 (3シナリオ)
├── 13-session-vs-token.md  ← session-vs-token タブ攻撃詳細 (3シナリオ)
├── 14-rbac.md              ← rbac タブ攻撃詳細 (4シナリオ)
├── 15-fido2.md             ← fido2 タブ攻撃詳細 (1シナリオ)
├── 16-oidc-saml.md         ← oidc-saml タブ攻撃詳細 (3シナリオ)
├── 17-kerberos.md          ← kerberos タブ攻撃詳細 (3シナリオ)
├── 18-tls-deep.md          ← tls-deep タブ攻撃詳細 (3シナリオ)
├── 19-sso-idp-apikey.md    ← sso-idp-apikey タブ攻撃詳細 (3シナリオ)
├── 20-mfa.md               ← mfa タブ攻撃詳細 (3シナリオ)
└── 21-passkey.md           ← passkey タブ攻撃詳細 (1シナリオ)
```

### 6.2 推奨読み順

実装を担当する開発者は以下の順に読むことを推奨する。

```
00-overview.md          ← 全体目的・カタログ把握 (本ファイル)
  ↓
01-architecture.md      ← 追加するファイル・ルート・型の全体像
  ↓
02-ui-spec.md           ← 共有 UI コンポーネントの仕様
  ↓
03-data-model.md        ← 型定義の確定 (実装前に必読)
  ↓
04-safety-guardrails.md ← 安全装置の実装方針
  ↓
担当タブの 10-21 ファイル
```

教材執筆者・レビュアーは `00-overview.md` → 担当タブの詳細ファイル のみで概要把握が可能。

---

## 7. スコープ

### 7.1 本フェーズに含むもの

| カテゴリ | 内容 |
|---------|------|
| フロントエンド | `ViewModeToggle`, `AttackStepTimeline`, `AttackResultBanner`, `AttackDefensePanel` の 4 共有コンポーネント |
| フロントエンド | 12 タブ各コンポーネントへのトグル・シナリオセレクタ組み込み |
| バックエンド | `server/routes/attack-*.ts` (タブごとの攻撃シミュレーションルート) |
| バックエンド | `server/middleware/trace-logger.ts` への攻撃フラグ拡張 (`isAttackMode: boolean`) |
| 型定義 | `shared/api-types.ts` への `AttackScenarioMeta`, `AttackStep`, `AttackResult` 追加 |
| データ | `src/data/attack-scenarios.ts` (フロントエンド用静的シナリオデータ) |
| i18n | 新規テキストの `t(ja, en)` ヘルパー適用 |
| 安全装置 | 赤帯バナー、ローカル限定リクエスト、免責テキスト |

### 7.2 本フェーズに含まないもの

| カテゴリ | 除外理由 |
|---------|---------|
| 既存 `AttackMap.tsx` との統合 | 別途設計が必要。本フェーズは独立実装 |
| 実 CVE のエクスプロイトコード | 教育目的の範囲を超えるため |
| リアルタイム外部攻撃の検出 | 外部通信を含むため隔離原則と矛盾 |
| FIDO2/Passkey の攻撃「成功」シナリオ | プロトコル設計上、origin binding により不可能 (失敗デモが正しい) |
| バイナリ操作・メモリ破壊・RCE | 教育安全装置の簡略化原則に違反 |
| 本番環境向けスキャナ・ペネトレーションツール | スコープ外 |

---

## 8. 用語集

本設計書群で使用する固有名詞・型名の定義。

| 用語 | 型名 / 識別子 | 定義 |
|------|-------------|------|
| **Defender View** | `viewMode = "defender"` | 既存の正常系デモ画面。攻撃デモ追加後も変更なし |
| **Attacker View** | `viewMode = "attacker"` | 攻撃シナリオを選択・実行するモード。赤帯バナーを常時表示 |
| **AttackScenarioMeta** | `interface AttackScenarioMeta` | タブ内1つの攻撃シナリオのメタ情報 (例: "alg=none bypass")。CWE/CAPEC ID・深刻度・ステップ列を含む (→ DESIGN/03 §1.5 を参照) |
| **AttackStep** | `interface AttackStep` | シナリオ内の1操作 (例: "JWT header の alg を none に書き換える")。実行ボタンと対応する API エンドポイントを持つ |
| **AttackResult** | `interface AttackResult` | AttackStep 実行後の結果。`outcome: "succeeded" \| "blocked" \| "error"` (DESIGN/03 §1.4), HTTP ステータス, 解説テキストを含む |
| **AttackDefensePanel** | コンポーネント名 | 攻撃完了後に展開される防御策解説パネル。既存 Defender View の実装箇所へのリンクを含む |
| **_trace** | `ServerTrace` (shared/api-types.ts) | 全 API レスポンスに付与される教育用メタデータ。`DbQuery[]`, `CryptoOp[]`, `SessionOp[]` を含む。攻撃ルートでも同様に付与する |
| **scopeId** | `"attack-{tabId}"` | DataFlowPanel がキャプチャ対象を識別するスコープ ID。例: `"attack-jwt"`。`tabId` は `AuthSubView` の値。`session-vs-token` タブのみ左右並列デモのため `"attack-session"` / `"attack-token"` と分割する (例外; DESIGN/13 §1.2 参照) |
| **ViewModeToggle** | コンポーネント名 | 各認証タブ上部に配置する Defender/Attacker 切替トグル。現在のモードを Signal で管理 |
| **isAttackMode** | `boolean` フラグ | `_trace` ミドルウェア拡張フィールド。攻撃ルート呼び出し時に `true` となり、フロントエンドで赤色ハイライト表示のトリガーとなる |

---

## 9. 関連ファイル

### 9.1 設計書

- [DESIGN/01-architecture.md](./01-architecture.md) — 追加バックエンドルート・フロントエンドコンポーネント構成
- [DESIGN/02-ui-spec.md](./02-ui-spec.md) — ViewModeToggle / AttackStepTimeline / AttackResultBanner / AttackDefensePanel の UI 詳細仕様
- [DESIGN/03-data-model.md](./03-data-model.md) — AttackScenarioMeta / AttackStep / AttackResult 型定義・DBスキーマ拡張
- [DESIGN/04-safety-guardrails.md](./04-safety-guardrails.md) — 教育安全装置の詳細実装方針・レビューチェックリスト
- [DESIGN/10-auth-methods.md](./10-auth-methods.md) ～ [DESIGN/21-passkey.md](./21-passkey.md) — タブ別攻撃詳細設計

### 9.2 既存実装ファイル (参照・変更対象)

| ファイルパス | 役割 | 変更種別 |
|------------|------|---------|
| `src/components/auth/AuthView.tsx` | 12タブのルーティング・`<Switch>/<Match>` | 変更なし |
| `src/components/auth/{各タブ}.tsx` | タブ個別コンポーネント | **ViewModeToggle 追加** |
| `src/components/shared/DataFlowPanel.tsx` | HTTP/_trace/DB 可視化パネル | 変更なし (流用) |
| `src/api/client.ts` | fetch ラッパー・exchange キャプチャ | 変更なし (流用) |
| `shared/api-types.ts` | 共有型定義 | **AttackScenarioMeta 等を追加** |
| `src/types/security.ts` | フロント用型定義 | **AttackViewMode 等を追加** |
| `server/middleware/trace-logger.ts` | _trace 付与ミドルウェア | **isAttackMode フラグ追加** |
| `server/index.ts` | ルート登録エントリポイント | **attack-*.ts ルート登録追加** |
| `server/db/schema.ts` | SQLite スキーマ + seed | **attack_log テーブル追加 (オプション)** |

### 9.3 新規作成ファイル

| ファイルパス | 役割 |
|------------|------|
| `src/components/shared/ViewModeToggle.tsx` | Defender/Attacker モード切替トグル |
| `src/components/shared/AttackStepTimeline.tsx` | ステップ実行タイムラインコンポーネント |
| `src/components/shared/AttackResultBanner.tsx` | 攻撃結果バナー (成功/ブロック) |
| `src/components/shared/AttackDefensePanel.tsx` | 防御策解説パネル |
| `src/components/shared/EducationalWarningBanner.tsx` | 赤帯教育警告バナー (Attacker View 常時表示、dismissable 禁止) |
| `src/data/attack-scenarios.ts` | 全タブ分の静的シナリオデータ |
| `server/routes/attack-auth-methods.ts` | auth-methods タブ攻撃ルート |
| `server/routes/attack-jwt.ts` | jwt タブ攻撃ルート |
| `server/routes/attack-oauth.ts` | oauth タブ攻撃ルート |
| ~~`server/routes/attack-session.ts`~~ (新規ファイル不要) | session-auth.ts と token-auth.ts にサブパス `/attack/*` を追加することで対応 (既存ファイルへの追加のみ) |
| `server/routes/attack-rbac.ts` | rbac タブ攻撃ルート |
| `server/routes/attack-fido2.ts` | fido2 タブ攻撃ルート |
| `server/routes/attack-oidc-saml.ts` | oidc-saml タブ攻撃ルート |
| `server/routes/attack-kerberos.ts` | kerberos タブ攻撃ルート |
| `server/routes/attack-tls.ts` | tls-deep タブ攻撃ルート |
| `server/routes/attack-sso-apikey.ts` | sso-idp-apikey タブ攻撃ルート |
| `server/routes/attack-mfa.ts` | mfa タブ攻撃ルート |
| `server/routes/attack-passkey.ts` | passkey タブ攻撃ルート |
