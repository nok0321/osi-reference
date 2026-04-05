# OSI Reference App + Auth/Security Visualization — 実装計画

## Context

`osi-reference-app-solidjs-design.md` をベースに、OSI参照モデルのインタラクティブ学習ツールを実装する。
元設計の4ビュー（レイヤー概要、カプセル化、シナリオ、TCP/IP比較）に加え、
認証・認可フロー可視化（View 5）とセキュリティダッシュボード（View 6）を追加し、
実践的かつビジュアルに優れたアプリケーションに拡張する。

- **ディレクトリ**: `C:\Users\monum\work\private\NodeJS\osi-reference`（新規作成）
- **言語**: バイリンガル切替（日本語/英語トグル）
- **進め方**: セッション引き継ぎ方式（Phase 1→8 を順に実装、各Phase完了後コミット）

---

## 拡張ディレクトリ構造

```
osi-reference/
├── src/
│   ├── App.tsx
│   ├── index.tsx
│   ├── app.css
│   │
│   ├── i18n/
│   │   └── context.tsx              # 言語切替 Signal + Provider
│   │
│   ├── types/
│   │   ├── index.ts                 # 元設計の型 + ViewType拡張(6ビュー)
│   │   └── security.ts             # Auth/Security 関連型
│   │
│   ├── data/
│   │   ├── layers.ts
│   │   ├── protocols.ts
│   │   ├── encapsulation.ts
│   │   ├── scenarios.ts
│   │   ├── tcpip-mapping.ts
│   │   ├── auth-flows.ts           # OAuth, JWT, TLS Deep, 比較, RBAC/ABAC
│   │   ├── security-attacks.ts     # 各層の攻撃手法
│   │   └── certificate-data.ts     # 証明書チェーン、FWルール
│   │
│   ├── state/
│   │   ├── app-state.ts
│   │   └── security-state.ts
│   │
│   ├── components/
│   │   ├── shared/          (9) TabBar, LayerStrip, LayerStack, ProtocolBadge,
│   │   │                         HeaderBlock, StepControl, Tooltip, SecurityBadge, AnimatedPath
│   │   ├── overview/        (3) OverviewView, LayerDiagram, LayerDetail
│   │   ├── encapsulation/   (4) EncapsulationView, DataUnit, EncapAnimation, HeaderInspector
│   │   ├── scenario/        (5) ScenarioView, ScenarioSelector, DualStackDiagram, PacketFlow, StepNarration
│   │   ├── comparison/      (3) ComparisonView, DualModel, MappingLines
│   │   ├── auth/            (6) AuthView, OAuthFlow, JwtInspector, TlsDeepDive, AuthComparison, PermissionModel
│   │   └── security/        (5) SecurityView, PacketMonitor, CertChain, FirewallRules, AttackMap
│   │
│   └── utils/
│       ├── colors.ts
│       ├── animation.ts
│       └── security-colors.ts
```

合計コンポーネント: **35** (shared 9 + views 26)

---

## Phase 1: プロジェクト基盤 + 共有コンポーネント + View 1（レイヤー概要）

**ゴール**: PCBテーマの動くアプリ。7層ダイアグラムをクリックで詳細表示。言語切替動作。

**作成ファイル** (~22):
1. `npx degit solidjs/templates/ts osi-reference` でスキャフォールド
2. `npm install d3 solid-motionone` / `npm install -D @types/d3`
3. `src/app.css` — CSS変数、フォント読み込み、PCBテーマ、リセット
4. `src/types/index.ts` — ViewType(6種), LayerNumber, ScenarioType, OsiLayer, Protocol, HeaderField, EncapStep, ScenarioStep, TcpIpMapping
5. `src/types/security.ts` — AuthSubView, OAuthStep, JwtSection, TlsStep, SecurityPacket, CertificateNode, FirewallRule, OsiAttack 等（スタブ）
6. `src/i18n/context.tsx` — `createSignal<"ja"|"en">("ja")` + `I18nProvider` + `useLang()` + `t()` ヘルパー
7. `src/data/layers.ts` — 7層の完全定義（name/nameJa 両方）
8. `src/data/protocols.ts` — 各層のプロトコル詳細
9. `src/utils/colors.ts` — LAYER_COLORS (L1=#D4380D 〜 L7=#C41D7F)
10. `src/utils/animation.ts` — D3ヘルパー（traceDrawEffect, glowPulse, moveAlongPath）
11. `src/utils/security-colors.ts` — safe/warning/threat/encrypted カラー定数
12. `src/state/app-state.ts` — activeView, selectedLayer 等
13. `src/state/security-state.ts` — スタブSignal（後フェーズで実装）
14. `src/App.tsx` — TabBar + Switch/Match 6ビュー（2〜6はプレースホルダー）+ 言語切替ボタン
15. `src/index.tsx` — render エントリポイント
16-22. `src/components/shared/` — TabBar, LayerStrip, LayerStack, ProtocolBadge, Tooltip + `src/components/overview/` — OverviewView, LayerDiagram(D3 SVG), LayerDetail

**検証**:
- `npm run dev` で起動、PCBダークテーマ表示
- 6タブ表示（2〜6はcoming soon）
- 7層SVGダイアグラム、クリックで詳細パネル、ホバーでグロー
- 言語切替ボタンで日本語/英語が切り替わる

---

## Phase 2: View 2（カプセル化）+ View 4（TCP/IP比較）

**ゴール**: ヘッダ追加/除去のステップアニメーション + TCP/IP対応マッピング。

**作成ファイル** (~11):
1. `src/data/encapsulation.ts` — L7→L1 の5段階データ（ヘッダバイト数、フィールド定義）
2. `src/data/tcpip-mapping.ts` — TCP/IP 4層⇔OSI 7層マッピング
3-4. `src/components/shared/` — HeaderBlock, StepControl
5-8. `src/components/encapsulation/` — EncapsulationView, DataUnit, EncapAnimation(solid-motionone), HeaderInspector
9-11. `src/components/comparison/` — ComparisonView, DualModel, MappingLines(SVGベジェ)

**修正**: `src/App.tsx`（View 2, 4 をワイヤリング）

**検証**:
- ステップ送り/戻しでヘッダブロックがアニメーション付きで追加/除去
- ヘッダクリックでフィールド詳細（TCP: src port/dst port/seq/ack 等）
- OSI⇔TCP/IP のベジェ接続線、ホバーで連動ハイライト

---

## Phase 3: View 3（通信シナリオ）

**ゴール**: HTTP/DNS/TLS/TLS-Deep の4シナリオでパケットフローアニメーション。

**作成ファイル** (~6):
1. `src/data/scenarios.ts` — HTTP(12ステップ), DNS(8), TLS(6), TLS-Deep(8, 暗号詳細付き)
2-6. `src/components/scenario/` — ScenarioView, ScenarioSelector, DualStackDiagram, PacketFlow(D3パスアニメーション), StepNarration

**修正**: `src/App.tsx`, `src/types/index.ts`（ScenarioType に 'tls-deep' 追加）

**検証**:
- 4シナリオ切替、D3パスに沿ったパケットドットのアニメーション
- 各ステップでレイヤーハイライト + ナレーション更新
- TLS-Deep は暗号スイートや鍵交換の詳細を表示

---

## Phase 4: View 5 Part A — OAuth 2.0 + JWT Inspector

**ゴール**: Auth ビューのフレームワーク + OAuth スイムレーン + JWT デコーダー。

**作成ファイル** (~4):
1. `src/data/auth-flows.ts` — OAuth 8ステップ（User/Client/AuthServer/ResourceServer間）、サンプルJWT
2. `src/components/auth/AuthView.tsx` — 5サブタブコンテナ（残り3つはプレースホルダー）
3. `src/components/auth/OAuthFlow.tsx` — D3 SVG: 4列スイムレーン、矢印アニメーション、SecurityBadge(HTTPS)、StepControl連動
4. `src/components/auth/JwtInspector.tsx` — 3色セグメント(header=赤/payload=紫/signature=青)、クリックでデコード、フィールド編集→署名無効化表示

**修正**: `src/App.tsx`, `src/state/security-state.ts`（authSubView, oauthStep, jwtActiveSection Signal 有効化）

**検証**:
- OAuth 8ステップのスイムレーンアニメーション
- JWT 3セクションのクリック展開/デコード
- ペイロード編集で "INVALID SIGNATURE" スタンプ表示

---

## Phase 5: View 5 Part B — TLS Deep-Dive + Session vs Token + RBAC/ABAC

**ゴール**: Auth ビューの全5サブタブ完成。

**作成ファイル** (~3):
1. `src/components/auth/TlsDeepDive.tsx` — Client/Server 縦タイムライン、展開可能なメッセージカード、暗号化閾値ライン（amber=平文/green=暗号化）
2. `src/components/auth/AuthComparison.tsx` — 分割画面: Session(cookie)フロー vs Token(JWT)フロー、比較テーブル(~8観点)、クリックでダイアグラム部分ハイライト
3. `src/components/auth/PermissionModel.tsx` — RBAC/ABACトグル。RBAC: D3 force/treeグラフ(User→Role→Permission)。ABAC: 判定ツリーのアニメーション評価

**修正**: `src/data/auth-flows.ts`（TLS/比較/RBAC/ABACデータ追加）

**検証**:
- TLS タイムラインの展開カード + 暗号詳細
- Session vs Token の比較テーブル、クリック連動
- RBAC/ABAC 切替、D3グラフのインタラクション
- 5サブタブ間の状態保持

---

## Phase 6: View 6 Part A — パケットモニター + 証明書チェーン

**ゴール**: セキュリティダッシュボード（4パネルCSS Grid、上2パネル実装）。

**作成ファイル** (~4):
1. `src/data/certificate-data.ts` — 証明書チェーン（Root CA→中間→リーフ）、FWルールテンプレート、パケット生成テンプレート
2. `src/components/security/SecurityView.tsx` — 2x2 CSS Gridダッシュボード（下2パネルはプレースホルダー）
3. `src/components/security/PacketMonitor.tsx` — setInterval パケット生成(500ms)、スクロールリスト(上限100 FIFO)、色分け行(green/amber/red)、再生/一時停止、レイヤー/ステータス/プロトコルフィルタ、D3スパークライン
4. `src/components/security/CertChain.tsx` — D3 tree レイアウト(d3-hierarchy)、ノードクリックで詳細展開、信頼チェーンのグローアニメーション、期限切れ証明書トグル

**修正**: `src/App.tsx`, `src/state/security-state.ts`

**検証**:
- パケットがリアルタイムストリーミング、色分け/フィルタ動作
- 証明書ツリーのレンダリング、ノード展開、信頼チェーンアニメーション

---

## Phase 7: View 6 Part B — ファイアウォールルール + 攻撃マップ

**ゴール**: セキュリティダッシュボード完成（全4パネル）。

**作成ファイル** (~3):
1. `src/data/security-attacks.ts` — 各層の攻撃（L1:ケーブルタップ, L2:ARPスプーフィング, L3:IPスプーフィング, L4:SYNフラッド, L5:セッションハイジャック, L6:SSL Strip, L7:XSS/SQLi/CSRF）+ 重要度 + 緩和策
2. `src/components/security/FirewallRules.tsx` — OSI層スタック+ルールカード、パケット通過アニメーション(allow=緑チェック/deny=赤X)、プリセットシナリオ
3. `src/components/security/AttackMap.tsx` — 7層スタック+重要度色分けバッジ、クリックで詳細展開、攻撃シミュレーションモード、緩和策パネル

**修正**: `src/components/security/SecurityView.tsx`（下2パネル置換）

**検証**:
- FWルール通過アニメーション、allow/deny 判定表示
- 攻撃マップの全7層バッジ、シミュレーション動作
- ダッシュボード全4パネルの統合動作

---

## Phase 8: 統合・ポリッシュ・クロスビュー連携

**ゴール**: ビュー間リンク、レスポンシブ、キーボードナビゲーション、最終QA。

**修正のみ**:
1. `LayerDetail` — セキュリティセクション追加（各層の攻撃/防御/FW適用性）
2. `ScenarioView` — TLS Deep Dive ボタン → Auth View TLS サブタブへ遷移
3. `ScenarioSelector` — TLS系にシールドアイコン
4. `TabBar` — アクティブタブPCBグロー、アニメーション下線トレース
5. `app.css` — レスポンシブ (1200px+, 900-1200px, <900px), focus-visible, ダークスクロールバー
6. 全ビュー — キーボード: 1-6 ビュー切替, 矢印 レイヤー/ステップ, Tab サブビュー, Esc 閉じる, Space 再生/一時停止
7. `App.tsx` — グローバルキーボードリスナー、ErrorBoundary

**検証**:
- Overview の各層にセキュリティ情報表示
- TLS Deep Dive リンクがクロスビュー遷移
- キーボードショートカット全動作
- 3ブレークポイントでレスポンシブ
- `npm run build` クリーン、コンソールエラーなし

---

## Phase 依存関係

```
Phase 1 (基盤) ──→ Phase 2 (カプセル化+比較) ──→ Phase 3 (シナリオ)
    │
    └──→ Phase 4 (OAuth+JWT) ──→ Phase 5 (TLS+RBAC)
                                      │
                                      └──→ Phase 6 (パケット+証明書) ──→ Phase 7 (FW+攻撃)

すべて ──→ Phase 8 (統合)
```

## セッション引き継ぎ手順

各セッション開始時:
1. `cd osi-reference && npm run dev` で現状確認
2. `ls src/components/` でどのPhaseまで完了か判定:
   - shared + overview のみ → Phase 2 から
   - + encapsulation + comparison → Phase 3 から
   - + scenario → Phase 4 から
   - + auth (OAuthFlow, JwtInspector) → Phase 5 から
   - + auth (全6ファイル) → Phase 6 から
   - + security (PacketMonitor, CertChain) → Phase 7 から
   - + security (全5ファイル) → Phase 8 から
3. この計画ファイルの該当Phaseを参照して実装
4. Phase 完了後 `git commit` して終了

## i18n 設計

```tsx
// src/i18n/context.tsx
const [lang, setLang] = createSignal<"ja" | "en">("ja");
const t = (ja: string, en: string) => lang() === "ja" ? ja : en;
// データ: { name: "Application", nameJa: "アプリケーション" }
// 使用: t(layer.nameJa, layer.name)
```

ヘッダー右上に 🌐 EN / JA トグルボタン。

## 技術的注意事項

- **D3 + Solid**: `onMount` で D3 初期化、`onCleanup` で `selection.interrupt()`、`createEffect` で Signal → D3 transition トリガー
- **Props デストラクチャリング禁止**: `props.xxx` でアクセス
- **条件描画**: `<Show>` / `<For>` を使用（早期リターン禁止）
- **パケットモニター性能**: 表示は10/秒にスロットル、FIFO 100件上限
- **D3 サブモジュール import**: `d3-selection`, `d3-transition`, `d3-shape`, `d3-hierarchy`, `d3-force` のみ（バンドルサイズ最適化）
- **solid-motionone 互換性**: フォールバックとして CSS animation + class トグル
