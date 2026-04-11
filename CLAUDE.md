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
```
server/                           # Hono バックエンド (port 3001)
├── index.ts                      # エントリポイント、全ルート登録
├── db/schema.ts                  # SQLite スキーマ (12テーブル) + seed
├── middleware/trace-logger.ts    # _trace ミドルウェア (DB/暗号/セッション操作を記録)
└── routes/
    ├── password-auth.ts          # 登録/ログイン (bcrypt)
    ├── jwt-ops.ts                # JWT 署名/検証/デコード (HS256/RS256)
    ├── session-auth.ts           # セッション認証 (Cookie + DB)
    ├── token-auth.ts             # トークン認証 (JWT Bearer)
    ├── oauth-sim.ts              # OAuth 2.0 認可サーバーシミュレーション
    ├── rbac.ts                   # RBAC/ABAC/ACL アクセス制御評価
    ├── webauthn.ts               # FIDO2 登録/認証 (@simplewebauthn/server)
    ├── kerberos-sim.ts           # Kerberos KDC シミュレーション (AES暗号化チケット)
    ├── oidc-saml-sim.ts          # OIDC (PKCE) + SAML IdP シミュレーション
    ├── sso-apikey.ts             # SSO セッション伝播 + API キー生成/HMAC
    └── tls-sim.ts                # TLS 1.3 ハンドシェイク (ECDHE鍵交換)
shared/
└── api-types.ts                  # サーバー/クライアント共有型 (ServerTrace等)
src/
├── api/client.ts                 # fetch ラッパー (リクエスト/レスポンス自動キャプチャ)
├── i18n/context.tsx              # 言語切替 Signal + Provider
├── types/{index,security}.ts     # 型定義
├── data/*.ts                     # 静的データ (layers, protocols, scenarios, auth, security)
├── state/{app,security}-state.ts # グローバル Signal
├── utils/{colors,animation,security-colors}.ts
└── components/
    ├── shared/
    │   ├── DataFlowPanel.tsx      # HTTP/Trace/DB タブ付き折りたたみパネル
    │   └── (TabBar, StepControl, etc.)
    ├── overview/       # View 1: 7層ダイアグラム
    ├── encapsulation/  # View 2: ヘッダ追加/除去アニメーション
    ├── scenario/       # View 3: HTTP/DNS/TLS パケットフロー
    ├── comparison/     # View 4: OSI⇔TCP/IP マッピング
    ├── auth/           # View 5: 全10方式にインタラクティブデモ追加済み
    └── security/       # View 6: パケットモニター/証明書/FW/攻撃マップ
```

## 認証・認可インタラクティブデモ (実装済み)
全10タブに実動作デモを追加完了。各デモは `DataFlowPanel` で HTTP リクエスト/レスポンスと `_trace` (DB操作・暗号処理・セッション操作) をリアルタイム表示。

| タブ | デモ内容 | バックエンドルート |
|------|---------|-------------------|
| 認証方式 | パスワード登録/ログイン、bcryptハッシュ可視化、usersテーブル表示 | password-auth.ts |
| JWT | サーバーサイド署名 (HS256/RS256)、検証、改竄検出、有効期限カウントダウン | jwt-ops.ts |
| OAuth 2.0 | ライブフロー (認可コード → トークン交換 → リソースアクセス) | oauth-sim.ts |
| Session vs Token | 左右並列デモ (Cookie認証 vs Bearer トークン) | session-auth.ts, token-auth.ts |
| アクセス制御 | RBAC/ABAC/ACL アクセスチェック、評価ステップ可視化 | rbac.ts |
| FIDO2/WebAuthn | 実WebAuthn API呼び出し、チャレンジ/レスポンス可視化 | webauthn.ts |
| OIDC & SAML | OIDC PKCE付きフロー + ID Token、SAML アサーション生成 | oidc-saml-sim.ts |
| Kerberos | KDCシミュレーション、AES暗号化チケット生成/復号 | kerberos-sim.ts |
| TLS詳細 | ハンドシェイクシミュレーション (ECDHE、証明書、セッションキー) | tls-sim.ts |
| SSO/API Key | SSO セッション伝播、API キー生成・HMAC検証 | sso-apikey.ts |

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

## 実装計画
詳細な Phase 別実装手順は `PLAN.md` を参照。

## セッション引き継ぎ手順
1. `cd osi-reference && npm run dev` で現状確認 (フロント+バックエンド同時起動)
2. `curl http://localhost:3001/api/health` でバックエンド動作確認
3. 認証タブ (`/auth/*`) で各デモの動作確認
4. 改善が必要な場合は該当する `server/routes/*.ts` と `src/components/auth/*.tsx` を修正

## 今後の改善候補
- i18n: デモ部分の日英テキスト充実
- PCBテーマ: デモUI部分のテーマ統一性向上
- エラーハンドリング: サーバー接続失敗時のグレースフルフォールバック
- テスト: バックエンドAPI のVitestテスト追加
