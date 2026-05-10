# OSI Reference App

OSI参照モデルのインタラクティブ学習ツール。認証・認可・セキュリティの可視化機能を拡張。

## 技術スタック
- **UI**: SolidJS 1.9 (Signals, `<Show>`, `<For>`, props デストラクチャリング禁止)
- **バックエンド**: Hono 4 + better-sqlite3 (port 3001)、@simplewebauthn/server、jsonwebtoken、bcryptjs
- **ビルド**: Vite 6 + TypeScript、concurrently でフロント+バックエンド同時起動
- **ビジュアル**: D3.js 7 (SVGダイアグラム/アニメーション) + solid-motionone (コンポーネント出入り)
- **スタイル**: CSS変数 + スコープ付きCSS (Tailwindなし)、PCB(回路基板)テーマ
- **i18n**: `src/i18n/context.tsx` の `t(ja, en)` ヘルパーでバイリンガル切替

## コマンド
- `npm run dev` — Vite (port 3000) + Hono (port 3001) 同時起動
- `npm run dev:client` — フロントエンドのみ
- `npm run dev:server` — バックエンドのみ
- `npm run build` — プロダクションビルド

## Solid.js 必須ルール
- コンポーネント関数は1回だけ実行される（Reactのように再実行されない）
- Signal は `count()` のようにゲッター関数として呼び出す
- Props は `props.name` でアクセス（デストラクチャリング禁止）
- 条件描画: `<Show when={...}>` / リスト: `<For each={...}>`
- 早期リターン禁止（`<Show>` で代替）
- 配列更新は `setItems(prev => [...prev, newItem])` で新配列生成

## D3 + Solid 統合パターン
- `ref` で SVG コンテナ取得 → `onMount` 内で D3 初期化
- `createEffect` 内で Signal 変更を監視 → D3 transition をトリガー
- `onCleanup` で `selection.interrupt()` によるトランジションキャンセル
- D3 が管理する SVG 内部に Solid は介入しない

## ディレクトリ構造

### 現状 (becc5fc 時点)

```
osi-reference/
├── server/                          # Hono バックエンド (port 3001) — Phase 1 で orchestrator 役に進化
│   ├── index.ts                     # エントリポイント、全ルート登録
│   ├── db/schema.ts                 # SQLite スキーマ + seed
│   ├── middleware/trace-logger.ts   # _trace ミドルウェア (DB/暗号/セッション操作を記録)
│   └── routes/
│       ├── password-auth.ts         # 登録/ログイン (bcrypt) + 攻撃ルート /attack/*
│       ├── jwt-ops.ts               # JWT 署名/検証 + 攻撃ルート /attack/* (Phase 1 で live 版を orchestrator/exec 経由に)
│       ├── session-auth.ts          # セッション認証 (Cookie + DB) + /attack/*
│       ├── token-auth.ts            # トークン認証 (JWT Bearer) + /attack/*
│       ├── oauth-sim.ts             # OAuth 2.0 + /attack/*
│       ├── rbac.ts                  # RBAC/ABAC/ACL + /attack/*
│       ├── webauthn.ts              # FIDO2 + /attack/*
│       ├── kerberos-sim.ts          # Kerberos KDC + /attack/*
│       ├── oidc-saml-sim.ts         # OIDC (PKCE) + SAML IdP + /attack/*
│       ├── sso-apikey.ts            # SSO + API キー + /attack/*
│       ├── mfa-totp.ts              # MFA/TOTP + /attack/*
│       ├── passkey.ts               # パスキー + /attack/*
│       └── tls-sim.ts               # TLS 1.3 ハンドシェイク + /attack/*
├── shared/
│   └── api-types.ts                 # 共有型 (ServerTrace, AttackScenarioMeta, AttackResult<TExtra>, AttackStep 等)
├── src/
│   ├── api/client.ts                # fetch ラッパー (リクエスト/レスポンス自動キャプチャ)
│   ├── i18n/context.tsx             # 言語切替 Signal + Provider
│   ├── types/{index,security}.ts    # 型定義
│   ├── data/*.ts                    # 静的データ
│   ├── state/{app,security,attack}-state.ts # グローバル Signal
│   ├── utils/{colors,animation,security-colors}.ts
│   └── components/
│       ├── shared/
│       │   ├── DataFlowPanel.tsx    # HTTP/Trace/DB 折りたたみパネル
│       │   ├── AttackPanel.tsx      # 攻撃デモ統合 (現状ナレーション型、Phase 1 で live モード追加)
│       │   ├── AttackStepTimeline.tsx, AttackResultBanner.tsx, AttackDefensePanel.tsx
│       │   ├── AttackScenarioSelector.tsx, EducationalWarningBanner.tsx
│       │   └── (TabBar, StepControl, etc.)
│       ├── overview/                # View 1: 7層ダイアグラム
│       ├── encapsulation/           # View 2: ヘッダ追加/除去アニメーション
│       ├── scenario/                # View 3: HTTP/DNS/TLS パケットフロー
│       ├── comparison/              # View 4: OSI⇔TCP/IP マッピング
│       ├── auth/                    # View 5: 12 タブ × 38 攻撃シナリオ
│       │   └── attacks/scenarios/*.ts # タブ別攻撃メタデータ (12 ファイル)
│       └── security/                # View 6: パケットモニター/証明書/FW/攻撃マップ
└── DESIGN/                          # 攻撃カタログ設計書 (00-04 共通 + 10-21 タブ別)
```

### Phase 1 で追加予定 (live attack 化 — `live_attack_architecture` メモリ参照)

```
osi-reference/
├── services/                        # 新規: 独立コンテナサービス群 (npm workspaces)
│   ├── victim-web/                  # 脆弱 Hono アプリ (orchestrator から実 HTTP で叩く対象)
│   │   ├── package.json             # 独立 package
│   │   ├── Dockerfile
│   │   ├── src/
│   │   └── tsconfig.json
│   ├── attacker-shell/              # alpine + curl/openssl/nc (--read-only --cap-drop=ALL)
│   │   └── Dockerfile
│   └── README.md                    # サービス追加手順テンプレ
├── docker-compose.yml               # victim-net (internal=true) で外部 egress 遮断
└── package.json                     # workspaces: ["services/*"] 化
```

`server/` は **orchestrator** 役に追加進化 (`POST /api/orchestrator/exec` で raw HTTP プロキシ + `_trace` 整形)。既存ナレーション型 `/attack/*` は Phase 5 まで残置 → C/D 群シナリオで継続使用。

### 将来計画 (L1/L2 深掘り — NAND → ブレッドボード → NBIT CPU)

```
osi-reference/
├── src/components/circuits/         # 将来: Blender Node 風 + ブレッドボード UI
├── packages/                        # 将来: 共有ライブラリ
│   └── nand-sim-core/               # 必要になったら WASM ベース sim core 等
└── services/                        # ハーネス系外部連携サービスもここに追加
```

実装は未着手。`services/` 構造は L1/L2 教材の追加にも適合 (1 PJ N サービス)。

## 認証・認可インタラクティブデモ (実装済み)
全12タブに正常系デモ + 攻撃シナリオ (計 38 シナリオ、PR #6 = becc5fc) を実装。各デモは `DataFlowPanel` で HTTP リクエスト/レスポンスと `_trace` (DB操作・暗号処理・セッション操作) をリアルタイム表示。

| タブ | 正常系デモ | 攻撃シナリオ | バックエンドルート |
|------|---------|------|-------------------|
| 認証方式 | パスワード登録/ログイン、bcryptハッシュ可視化 | bcrypt vs rainbow / timing / bruteforce | password-auth.ts |
| JWT | サーバー署名 (HS256/RS256)、検証、改竄検出 | alg=none / 弱秘密鍵 / 署名ストリッピング / kid injection | jwt-ops.ts |
| OAuth 2.0 | ライブフロー (認可コード → トークン交換) | state CSRF / redirect_uri バイパス / コード傍受 | oauth-sim.ts |
| Session vs Token | 左右並列 (Cookie 認証 vs Bearer) | セッション固定 / XSS Cookie 窃取 / リプレイ | session-auth.ts, token-auth.ts |
| アクセス制御 | RBAC/ABAC/ACL 評価ステップ可視化 | IDOR / 水平・垂直権限昇格 / ABAC 改竄 | rbac.ts |
| FIDO2/WebAuthn | 実 `navigator.credentials.*` 呼び出し | フィッシング耐性 / vs パスワード / チャレンジリプレイ | webauthn.ts |
| OIDC & SAML | OIDC PKCE + ID Token、SAML アサーション | SAML XSW / アサーションリプレイ / aud 検証省略 | oidc-saml-sim.ts |
| Kerberos | KDC シミュ、AES 暗号化チケット | Pass-the-Ticket / Kerberoasting / Golden Ticket | kerberos-sim.ts |
| TLS詳細 | ハンドシェイク (ECDHE、証明書) | ダウングレード / 自己署名 MITM / 弱 cipher | tls-sim.ts |
| SSO/API Key | SSO セッション伝播、HMAC 検証 | API キー漏洩 / HMAC バイパス / リプレイ | sso-apikey.ts |
| MFA/TOTP | TOTP コード生成/検証 | OTP リプレイ / 時刻ずれ DoS / SIM スワップ | mfa-totp.ts |
| パスキー | プラットフォーム/クロスデバイス | フィッシング耐性 / クラウド同期侵害 / cross-device MITM | passkey.ts |

攻撃シナリオは現状「サーバ側ナレーション生成型」。Phase 1 以降で順次 live 化 (実 HTTP + Docker 隔離 victim) — 詳細は本ファイル「ロードマップ」section 参照。

## バックエンド設計パターン
- **_trace レスポンス**: 全API レスポンスに `_trace` フィールドで教育用メタデータ (DbQuery[], CryptoOp[], SessionOp[]) を自動付与
- **Vite proxy**: `/api/*` → `http://localhost:3001` (vite.config.ts)
- **デモデータはエフェメラル**: `server/db/data.sqlite` は gitignored、`POST /api/reset` でリセット
- **JWT シークレットは表示**: 教育用のため秘密鍵も見せる (本番非公開の注意付き)
- **WebAuthn は実API優先**: `navigator.credentials.create/get` 呼び出し、非対応時フォールバック

## API クライアントパターン
```typescript
import { apiPost, apiGet } from "../../api/client";
import DataFlowPanel from "../shared/DataFlowPanel";
const SCOPE = "my-scope"; // DataFlowPanel のスコープID
// API 呼び出し → 自動的に HTTP exchange をキャプチャ
const res = await apiPost<ResponseType>("/api/endpoint", body, SCOPE);
// DataFlowPanel で HTTP/Trace/DB を表示
<DataFlowPanel scopeId={SCOPE} />
```

## DESIGN ⇄ 実装 対応表 (Component Mapping)

DESIGN/30-34 と Phase 1 で生成された実装ファイルの対応関係。
PR レビュー時の「仕様 ↔ 実装」往復に使う。Phase 2+ で新規ファイルを足すたびに本表を更新する。

| DESIGN セクション | 実装ファイル | 役割 |
|---|---|---|
| DESIGN/30 §2-3 (アーキ・データフロー) | `docker-compose.yml`, root `package.json` (workspaces) | コンテナ構成・サービス起動 |
| DESIGN/30 §7.1 (npm scripts) | root `package.json` の `dev` / `dev:no-docker` / `dev:victim` / `victim:reset` / `victim:logs` | DX (Docker / no-docker フォールバック) |
| DESIGN/31 §3 (Request スキーマ) | `server/routes/orchestrator-exec.ts` (zod schema) | バリデーション・エラーコード |
| DESIGN/31 §4 (Response 型) | `shared/api-types.ts` (`OrchestratorExecResponse`, `RawExchange`, `RawHttpRequest/Response`) | 双方向 raw bytes 型 |
| DESIGN/31 §5 (VICTIM_ALLOWLIST) | `server/routes/orchestrator-exec.ts` (`VICTIM_ALLOWLIST`), `shared/api-types.ts` (`VictimTarget`, `VictimEntry`) | URL 偽造防止 |
| DESIGN/31 §6 (raw HTTP プロキシ) | `server/routes/orchestrator-exec.ts` (`proxyToVictim`) | Node `http.request` + Host 強制上書き |
| DESIGN/31 §7 (`_trace` 拡張) | `server/middleware/trace-logger.ts` (`setLiveMode`, `mode`, `victimNote`, `isAttackPath` の orchestrator 追加) | live/narration の区別 |
| DESIGN/31 §8 (Production guard) | `server/middleware/production-guard.ts` | `NODE_ENV==="production"` で 503 |
| DESIGN/32 §2 (services/victim-web 構造) | `services/victim-web/{package.json,tsconfig.json,Dockerfile,src/index.ts,src/routes/jwt-vuln.ts}` | 脆弱 victim アプリ |
| DESIGN/32 §4.1 (JWT 脆弱エンドポイント) | `services/victim-web/src/routes/jwt-vuln.ts` | `POST /jwt/verify` (alg=none 受理) |
| DESIGN/32 §4.4 (OAuth 脆弱エンドポイント) | `services/victim-web/src/routes/oauth-vuln.ts` | `GET /oauth/authorize` (state 未検証で code 発行) |
| DESIGN/32 §4.5 (RBAC 脆弱エンドポイント) | `services/victim-web/src/routes/rbac-vuln.ts` | `POST /rbac/users/profile` (owner_id チェックなしで全フィールド返却) |
| DESIGN/32 §4.6 (Session 脆弱エンドポイント) | `services/victim-web/src/routes/session-vuln.ts` | `POST /session/login` (ログイン後 SID を再生成せず Cookie の session_id をそのまま echo) |
| DESIGN/32 §6 (Dockerfile + compose 安全設定) | `services/victim-web/Dockerfile`, `docker-compose.yml` (victim-web セクション) | tmpfs / cap_drop / read_only |
| DESIGN/33 §2 (RawHttpComposer) | `src/components/shared/RawHttpComposer.tsx`, `RawHttpComposer.css` (Headers / Body / Raw タブ) | 生 HTTP リクエスト編集 UI |
| DESIGN/33 §3 (SequenceDiagramView) | `src/components/shared/SequenceDiagramView.tsx`, `SequenceDiagramView.css` | D3 SVG シーケンス図 + raw bytes ポップアップ |
| DESIGN/33 §4 (AttackPanel 統合) | `src/components/shared/AttackPanel.tsx` (`isLiveMode()`, `onRunLiveScenario`, `rawExchange` Signal), `DataFlowPanel.tsx` (Sequence タブ + `isLiveMode` / `rawExchange` props) | 排他 `<Show>` + Sequence タブ |
| DESIGN/33 §4.1 (AttackStepTimeline live 派生) | (実装なし) | **PR-1 後 obsolete**: orchestrator が live 経路でも 3 段 AttackStep を返すため不要。raw bytes は SequenceDiagramView 担当。 |
| DESIGN/33 §5 (mode バッジ) | `RawHttpComposer.tsx` `.raw-http-composer-live-badge`, `EducationalWarningBanner.tsx` (`mode` prop + `.edu-warning-live-badge`), `AttackScenarioSelector.tsx` (`ModeBadge` + `.scenario-mode-badge`) | LIVE/NARRATION 表示 |
| DESIGN/34 §6 (PR テンプレート) | `.github/pull_request_template.md` | live モード PR チェックリスト |
| DESIGN/30 §7.2 (CI Docker) | `.github/workflows/ci.yml` の `docker-smoke` job | victim-web image build + healthcheck + /jwt/verify smoke |
| DESIGN/31 §11 (テスト要件) | `server/__tests__/orchestrator-live.test.ts` (12 tests = 10 spec + 2 extra) | スキーマ違反 / target 不在 / 502 / 504 / production / Host 強制 / mode / victimNote / phase ガード |
| DESIGN/32 §8.1 (victim 単体テスト) | `services/victim-web/__tests__/oauth-vuln.test.ts`, `services/victim-web/__tests__/rbac-vuln.test.ts` | OAuth: state なし code 発行 / state echo / client_id 欠如 400 ／ RBAC: victimId 任意改竄で 200 / 不在 id 404 / 型バリデーション 400 |
| DESIGN/30 §5.3 (シナリオ e2e) | `server/__tests__/scenarios/oauth-state-csrf.test.ts`, `server/__tests__/scenarios/rbac-idor.test.ts` | OAuth: orchestrator → victim-web で 200 / state echo / 3 段 AttackStep / 400 → blocked ／ RBAC: 任意 id でフルレコード漏洩 / leakedFields / 3 段 AttackStep / victimId 欠如 → blocked |
| DESIGN/34 §4 (新規安全装置) | `victim-net: internal: true`, `productionGuard`, `Host` 強制上書き, `cap_drop`, `read_only`, `tmpfs` | OS レイヤ防御 |
| DESIGN/30 §6.2 (`mode` フィールド) | `shared/api-types.ts` (`AttackScenarioMeta.mode`, `liveTemplate`) | live/narration 切替 |
| DESIGN/30 §5.3 (Phase 2 PoC 第 1 号) | `src/components/auth/attacks/scenarios/jwt-scenarios.ts` (`jwt-alg-none` の `mode: "live"`) + `src/components/auth/JwtInspector.tsx` (`onRunLiveScenario` 配線) | 学習者検証経路 |
| DESIGN/30 §5.3 (Phase 2 PoC 第 2 号) | `src/components/auth/attacks/scenarios/oauth-scenarios.ts` (`oauth-state-csrf` の `mode: "live"`) + `src/components/auth/OAuthFlow.tsx` (`onRunLiveScenario` 配線) | 学習者検証経路 |
| DESIGN/30 §5.3 (Phase 2 PoC 第 3 号) | `src/components/auth/attacks/scenarios/rbac-scenarios.ts` (`rbac-idor` の `mode: "live"`) + `src/components/auth/PermissionModel.tsx` (`onRunLiveScenario` 配線) | 学習者検証経路 |
| DESIGN/30 §5.3 (Phase 2 PoC 第 4 号) | `src/components/auth/attacks/scenarios/session-token-scenarios.ts` (`session-fixation` の `mode: "live"`) + `src/components/auth/AuthComparison.tsx` (`onRunLiveScenario` 配線) | 学習者検証経路 |
| DESIGN/32 §4.7 (TOTP 脆弱エンドポイント) | `services/victim-web/src/routes/totp-vuln.ts` + `services/victim-web/src/utils/totp.ts` | `POST /totp/login-replay` (used_otps 記録なしで同一 OTP 2 連続認証 + leakedToAttacker 漏えい体験) |
| DESIGN/32 §8.1 (victim 単体テスト) | `services/victim-web/__tests__/totp-vuln.test.ts` | TOTP: 同一 OTP 2 連続認証 / secret 学習者上書き / 不在 user 401 / username 欠如 400 / invalid JSON 400 |
| DESIGN/30 §5.3 (シナリオ e2e — mfa-otp-replay) | `server/__tests__/scenarios/mfa-otp-replay.test.ts` | mfa-otp-replay: orchestrator → victim-web で 200 / X-Computed-OTP ヘッダ / leakedToAttacker / 3 段 AttackStep / ghost user → blocked |
| DESIGN/30 §5.3 (Phase 2 PoC 第 5 号 = Phase 2 完結) | `src/components/auth/attacks/scenarios/mfa-scenarios.ts` (`mfa-otp-replay` の `mode: "live"` + 7 シーン story) + `src/components/auth/MfaFlow.tsx` (`onRunLiveScenario` 配線) | 学習者検証経路 + 紙芝居化 |
| DESIGN/35 §2 (AttackStoryScene 型) | `shared/api-types.ts` (`AttackStoryScene`, `AttackStoryActor`, `AttackStoryVisual`, `RawExchangeRef`, `HttpHighlight`) + `AttackScenarioMeta.story?` 追加 | 紙芝居データモデル |
| DESIGN/35 §3 (UI コンポーネント分割) | `src/components/shared/AttackStoryView.{tsx,css}` + `AttackStoryScene.{tsx,css}` + `AttackStoryControls.{tsx,css}` + `StoryActorAvatar.tsx` | 統合コンテナ + シーン描画 + ナビ + キャラアバター |
| DESIGN/35 §4 (AttackPanel 統合) | `src/components/shared/AttackPanel.tsx` (`hasStory()` メモ + AttackStoryView 表示 + `<details>` 折りたたみの classic timeline) + `AttackPanel.css` (`.attack-classic-timeline-fold`) | 共存方式 (story 持ちは新 UI、未対応は従来 timeline 展開) |
| DESIGN/35 §7 (raw exchange リンク方式) | `src/utils/story-resolver.ts` (`resolveRawRef` case-insensitive header lookup) + `src/utils/__tests__/story-resolver.test.ts` | 構造体参照ヘルパー |
| DESIGN/35 §11.2-§11.6 (テスト要件) | `src/components/shared/__tests__/AttackStoryView.test.tsx` (11 cases) + `AttackStoryScene.test.tsx` (8 cases) + `src/utils/__tests__/story-resolver.test.ts` (7 cases) | UI navigation / variant 描画 / a11y / resolver helper |
| DESIGN/35 §10.2 (PR-A 波及 — jwt-alg-none) | `src/components/auth/attacks/scenarios/jwt-scenarios.ts` (`jwt-alg-none.story` 7 シーン + `storyDefaultDurationMs`) + `services/victim-web/src/routes/jwt-vuln.ts` (`leakedToAttacker` + X-Token-Alg / X-Forged-Sub / X-Forged-Role ヘッダ + SEED_USER_PROFILES) + `services/victim-web/__tests__/jwt-vuln.test.ts` (6 tests) | 既存 PoC への storyboard + leakedToAttacker 波及 (auth プロトコル系 1/2) |
| DESIGN/35 §10.2 (PR-A 波及 — oauth-state-csrf) | `src/components/auth/attacks/scenarios/oauth-scenarios.ts` (`oauth-state-csrf.story` 7 シーン + `storyDefaultDurationMs`) + `services/victim-web/src/routes/oauth-vuln.ts` (`leakedToAttacker` + X-Authorization-Code / X-Csrf-Risk / X-State-Validated ヘッダ + VICTIM_PROFILE_AT_RISK) + `services/victim-web/__tests__/oauth-vuln.test.ts` (+2 tests = 6 tests) + `server/__tests__/scenarios/oauth-state-csrf.test.ts` (+1 test = 5 tests) | 既存 PoC への storyboard + leakedToAttacker 波及 (auth プロトコル系 2/2) |

## ロードマップ: 攻撃デモの live 化 (Phase 1-5, 約 11 週)

| Phase | 内容 | 期間 |
|---|---|---|
| 1 | docker-compose + `services/victim-web/` + orchestrator/exec + RawHttpComposer 共通基盤 | 1-2 週 |
| 2 | PoC 5 件 (jwt-alg-none, oauth-state-csrf, rbac-idor, session-fixation, mfa-otp-replay) | 2 週 |
| 3 | A 群残り 13 件 | 4 週 |
| 4 | B 群 5 件 (TLS / SAML XSW) → victim-tls-proxy / victim-saml-idp 追加 | 3 週 |
| 5 | C/D 群バッジ整理、`is_attack_sim` 削除検討 | 1 週 |

詳細 (38 シナリオ分類、安全制約への影響、意思決定履歴) は `CHECKPOINT.md` および `live_attack_architecture` メモリを参照。Phase 1-2 は `dev:no-docker` フォールバック維持、Phase 3+ から Docker 必須。

正式仕様化は Step A (`design-phase` スキル) で `DESIGN/30-live-attack-architecture.md` 以降に書き起こす予定。

## セッション引き継ぎ手順
1. `git status` / `git log --oneline -5` で進捗確認
2. `CHECKPOINT.md` および `live_attack_architecture` / `phase35_backlog` メモリを確認
3. `npm run dev` で現状動作確認 (フロント:3000, バックエンド:3001)
4. `curl http://localhost:3001/api/health` でバックエンド疎通確認
5. 認証タブ (`/auth/*`) で各デモ動作確認、必要に応じて `server/routes/*.ts` と `src/components/auth/*.tsx` を修正

## 並行残課題 (live 化計画と独立)
`phase35_backlog` メモリ参照:
- GitGuardian 永続化 (`.gitguardian.yaml` で test/demo 系 secret 7 件 ignore) — CI ノイズ削減効果大
- SEC-13 (`setInterval` クリーンアップ + `attack_log` TTL)、SEC-6、SEC-FIDO2-1 等 Tier 3
- D07/D09/D10/D13/D14/D15/D16: AttackStep payload 文言調整
- ROB-FIND-005/012: `AttackResult.extra` optional / outcome リテラル型分割
