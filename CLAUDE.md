# OSI Reference App

OSI参照モデルのインタラクティブ学習ツール。認証・認可・セキュリティの可視化機能を拡張。

## 技術スタック
- **UI**: SolidJS 1.9 (Signals, `<Show>`, `<For>`, props デストラクチャリング禁止)
- **ビルド**: Vite 6 + TypeScript
- **ビジュアル**: D3.js 7 (SVGダイアグラム/アニメーション) + solid-motionone (コンポーネント出入り)
- **スタイル**: CSS変数 + スコープ付きCSS (Tailwindなし)、PCB(回路基板)テーマ
- **i18n**: `src/i18n/context.tsx` の `t(ja, en)` ヘルパーでバイリンガル切替

## コマンド
- `npm run dev` — 開発サーバー起動 (port 3000)
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
src/
├── i18n/context.tsx          # 言語切替 Signal + Provider
├── types/{index,security}.ts # 型定義
├── data/*.ts                 # 静的データ (layers, protocols, scenarios, auth, security)
├── state/{app,security}-state.ts  # グローバル Signal
├── utils/{colors,animation,security-colors}.ts
└── components/
    ├── shared/     # TabBar, LayerStrip, LayerStack, ProtocolBadge, Tooltip, etc.
    ├── overview/   # View 1: 7層ダイアグラム + 詳細パネル
    ├── encapsulation/  # View 2: ヘッダ追加/除去アニメーション
    ├── scenario/   # View 3: HTTP/DNS/TLS パケットフロー
    ├── comparison/ # View 4: OSI⇔TCP/IP マッピング
    ├── auth/       # View 5: OAuth/JWT/TLS/Session比較/RBAC-ABAC
    └── security/   # View 6: パケットモニター/証明書/FW/攻撃マップ
```

## 実装計画
詳細な Phase 別実装手順は `PLAN.md` を参照。

## セッション引き継ぎ手順
1. `cd osi-reference && npm run dev` で現状確認
2. `ls src/components/` でどの Phase まで完了か判定
3. `PLAN.md` の該当 Phase を参照して実装
4. Phase 完了後に `git commit` + メモリ更新
