---
title: 攻撃デモカタログ — UI 仕様
phase: design
last-updated: 2026-04-26
---

# 02. UI 仕様

## 1. ビュー構造概観

攻撃デモカタログは既存の `AuthView` コンポーネントと同一ルート階層に統合する。
各認証タブ（oauth / jwt / tls-deep / ... 全12種）の内部構造を次のように拡張する。

```
AuthView
├── <nav class="auth-subtabs" role="tablist">  ← 既存タブナビ（変更なし）
└── <div class="auth-content" role="tabpanel">
    └── <現タブコンポーネント (JwtInspector 等)>
        ├── [既存の学習コンテンツ]
        ├── ViewModeToggle                     ← NEW: Defender/Attacker 切替トグル
        └── <Show when={viewMode() === "defender"}>
            │   [既存の Defender デモ (DataFlowPanel など)]
            └── <Show when={viewMode() === "attacker"}>
                    AttackPanel                ← NEW: 攻撃シナリオパネル
```

`viewMode` は `src/state/attack-state.ts` に格納する全タブ共有のグローバル Signal。
URL クエリパラメータ `?view=attacker` と双方向同期し、ページリロード後も状態を復元する。

---

## 2. ViewModeToggle コンポーネント

### 2.1 配置

`AuthView.tsx` の `auth-content` 内、各タブコンポーネントの先頭 JSX ブロック直下（`DataFlowPanel` の直上）に置く。
各タブコンポーネントファイル（例: `JwtInspector.tsx`）の内部で `<ViewModeToggle tabId="jwt" />` として呼び出す。

### 2.2 視覚デザイン

```
┌──────────────────────────────────────────────────────────┐
│  [DEFENDER モード]  ←  ⟵  切替ボタン  ⟶  → [ATTACKER モード] │
└──────────────────────────────────────────────────────────┘
```

- コンテナ: `background: var(--bg-card)`, `border: 1px solid var(--border-subtle)`, `border-radius: var(--radius-md)`
- **Defender 側アクティブ時**: 左ボタンが `background: var(--color-success-muted)`, `color: var(--color-success)`, `border-color: var(--color-success-border)` で強調。テキスト: `DEFENDER` (英) / `防御者モード` (日)
- **Attacker 側アクティブ時**: 右ボタンが `background: var(--color-attack-bg)`, `color: var(--color-attack-accent)`, `border-color: var(--color-attack-accent)` で強調。テキスト: `ATTACKER` (英) / `攻撃者モード` (日)
- アイコン: テキスト前に Unicode シンボルを付与。Defender = `[D]`、Attacker = `[A]` の装飾文字（絵文字は使わない）
- トグル中央の区切り: `|` 文字（`var(--text-muted)` 色）
- フォント: `var(--font-mono)`, `font-size: 0.75rem`
- ホバー時: `border-color: var(--border-active)` で視覚フィードバック

### 2.3 a11y

```typescript
<button
  role="switch"
  aria-checked={viewMode() === "attacker"}
  aria-label={t("攻撃者モードに切り替え", "Switch to Attacker mode")}
  tabIndex={0}
  onKeyDown={(e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      toggleViewMode();
    }
  }}
>
```

- `role="switch"` + `aria-checked` でスクリーンリーダーに on/off 状態を伝える
- `tabIndex={0}` でキーボードフォーカス可能
- フォーカスリング: `:focus-visible { outline: 2px solid var(--glow-color); outline-offset: 2px; }` (app.css の既存ルールが自動適用)
- ラベルテキストを `aria-label` で明示（アイコンのみに依存しない）

### 2.4 状態管理

**ファイル**: `src/state/attack-state.ts`

```typescript
import { createSignal, createEffect } from "solid-js";
import { useLocation, useNavigate } from "@solidjs/router";

export type ViewMode = "defender" | "attacker";

const [viewMode, setViewMode] = createSignal<ViewMode>("defender");

// URL クエリ ?view=attacker と双方向同期する初期化関数
// （コンポーネント内の createEffect から呼び出す）
export { viewMode, setViewMode };

export function initViewModeSync(): void {
  // useLocation().search を監視し、?view=attacker なら setViewMode("attacker")
  // setViewMode 変更時に useNavigate で URL を更新
}
```

---

## 3. AttackPanel.tsx — 責務と props

### 3.1 型定義

> **型定義の唯一の真実源は DESIGN/03-data-model.md §1 を参照すること。**
> 本セクションでは型の全定義を重複管理しない。

**ファイル**: `src/types/security.ts` に追記する型は以下の通り。実際の定義は `shared/api-types.ts` の DESIGN/03 §1 実装から import すること。

- `AttackStepKind` (旧 `AttackKind`) — DESIGN/03 §1.1 を参照 (`"intercept" | "tamper" | "replay" | "forge" | "probe" | "verify" | "exploit" | "blocked"`)
- `AttackStep` — DESIGN/03 §1.2 を参照 (`kind: AttackStepKind`, `timestamp: number`)
- `AttackResult` — DESIGN/03 §1.4 を参照 (`outcome: "succeeded" | "blocked" | "error"`, `steps: AttackStep[]`)
- `AttackScenarioMeta` — DESIGN/03 §1.5 を参照 (`tabId: AuthSubView`, `severity: "info" | "low" | "medium" | "high" | "critical"`, `osiLayer: number | string`)
- `SeverityLevel` = `"info" | "low" | "medium" | "high" | "critical"`

### 3.2 AttackPanel コンポーネント props

**ファイル**: `src/components/shared/AttackPanel.tsx`

```typescript
interface AttackPanelProps {
  tabId: AuthSubView;
  /** このタブで提供する攻撃シナリオ一覧 */
  scenarios: AttackScenarioMeta[];
  /** 選択中のシナリオを実行するコールバック（親コンポーネントが API 呼び出しを担当） */
  onRunScenario: (scenario: AttackScenarioMeta) => Promise<AttackResult>;
}
```

### 3.3 内部責務

AttackPanel は純粋な表示コンポーネントとして機能し、API 呼び出しの詳細は親（各タブコンポーネント）が `onRunScenario` に実装する。

内部 Signal:

```typescript
const [selectedScenarioId, setSelectedScenarioId] = createSignal<string>(
  props.scenarios[0]?.id ?? ""
);
const [attackResult, setAttackResult] = createSignal<AttackResult | null>(null);
const [running, setRunning] = createSignal(false);
const [defenseOpen, setDefenseOpen] = createSignal(false);
```

処理フロー:

1. `AttackScenarioSelector` でシナリオを選択 → `selectedScenarioId` 更新
2. 選択済みシナリオの前提条件・深刻度バッジを表示
3. 「実行」ボタン押下で `setRunning(true)` → `props.onRunScenario(scenario)` 呼び出し
4. 完了後 `setAttackResult(result)` → `AttackStepTimeline` を描画
5. `AttackResultBanner` で最終結果を表示
6. `AttackDefensePanel` の折りたたみ表示

---

## 4. AttackScenarioSelector

### 4.1 用途

タブが複数の攻撃シナリオを持つ場合（例: JWT タブでは「署名改竄」「alg=none 攻撃」「リプレイ」など）に選択 UI を提供する。

### 4.2 シナリオが1件の場合

セレクタを描画せず、シナリオ名と説明を静的に表示するだけにする（不要な操作 UI を排除）。

### 4.3 シナリオが複数件の場合

```
┌─────────────────────────────────────────────┐
│ シナリオを選択:                               │
│  ● JWT 署名改竄       [CRITICAL]             │
│  ○ alg=none 攻撃      [HIGH]                 │
│  ○ トークンリプレイ   [MEDIUM]               │
└─────────────────────────────────────────────┘
```

- ラジオボタン形式のチップ群（横並び、折り返し可）
- 各チップに深刻度バッジを付与（後述 §4.4）
- フォント: `var(--font-mono)`, `font-size: 0.7rem`

### 4.4 深刻度バッジ

| 深刻度 | 背景色変数 | テキスト色変数 | ラベル |
|--------|-----------|--------------|--------|
| critical | `var(--color-danger-muted)` | `var(--color-danger)` | `CRITICAL` |
| high | `var(--color-attack-bg)` | `var(--color-attack-accent)` | `HIGH` |
| medium | `var(--color-warning-dim)` | `var(--color-warning)` | `MEDIUM` |
| low | `var(--color-info-dim)` | `var(--color-info)` | `LOW` |
| info | `var(--color-success-muted)` | `var(--color-success)` | `INFO` |

<!-- AUDIT-21: severity 定義順は "info" | "low" | "medium" | "high" | "critical" (DESIGN/03 §1.5 SSoT) -->

バッジは `<span class="severity-badge" data-severity={scenario.severity}>` で実装し、CSS の `[data-severity="critical"]` セレクタで色を制御する。

### 4.5 外部リファレンスリンク

選択中シナリオの CWE/CAPEC が存在する場合、バッジの横に `<a href={ref.url} target="_blank" rel="noopener noreferrer">` でリンクを表示する。

```
[CRITICAL] CWE-347  CAPEC-60
```

リンクは `color: var(--glow-color)`, `font-size: 0.65rem` で小さく表示。

---

## 5. AttackStepTimeline

### 5.1 レイアウト

縦方向のタイムライン。各ステップはカード形式で表示し、左端に縦線（PCB の回路トレース風）を設ける。

```
  │
  ●── [◉] 通信傍受          RUNNING  ████░░░░
  │
  ●── [✎] ペイロード改竄     SUCCESS  ⚠
  │       ▶ payload を展開
  │
  ●── [✓] サーバー検証       BLOCKED  ✓ 防御成立
  │
```

縦線: `border-left: 2px solid var(--border-subtle)`, ノード(●): `background: var(--step-color)` を CSS 変数で動的に切替。

### 5.2 kind アイコンと対応

| kind | アイコン文字 | 説明 |
|------|------------|------|
| intercept | `◉` | 傍受 |
| tamper | `✎` | 改竄 |
| replay | `↻` | リプレイ |
| forge | `⚒` | 偽造 |
| probe | `?` | 探索 |
| verify | `✓` | 検証 |
| exploit | `!` | エクスプロイト (`⚡` は絵文字のため回避) |
| blocked | `[x]` | ブロック |

アイコンは `aria-hidden="true"` を付与し、状態テキストと常に併記することで色覚多様性対応とする。

### 5.3 status 表示色

CSS カスタムプロパティ `--step-color` を各ステップカードの `style` prop で注入する。

| status | --step-color | ラベルテキスト |
|--------|------------|--------------|
| pending | `var(--text-muted)` | `PENDING` |
| running | `var(--glow-color)` | `RUNNING` (点滅アニメーション) |
| success | `var(--color-attack-accent)` | `SUCCESS` (攻撃成功 = 警告色) |
| failed | `var(--color-danger)` | `FAILED` |
| blocked | `var(--color-success)` | `BLOCKED` (防御成立 = 緑) |

`running` 状態のラベルには `animation: stepPulse 1s ease infinite` を適用:

```css
@keyframes stepPulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.4; }
}
```

### 5.4 payload 展開トグル

`payload` フィールドが存在するステップにのみ展開ボタンを表示する。

```typescript
const [payloadOpen, setPayloadOpen] = createSignal(false);
// ...
<Show when={step.payload}>
  <button
    class="step-payload-toggle"
    aria-expanded={payloadOpen()}
    onClick={() => setPayloadOpen(!payloadOpen())}
  >
    {t("ペイロード", "Payload")} {payloadOpen() ? "▾" : "▸"}
  </button>
  <Show when={payloadOpen()}>
    <pre class="step-payload-code">{step.payload}</pre>
  </Show>
</Show>
```

展開エリアは `animation: decodedFade 300ms ease both` (JwtInspector.css 既存アニメーション名を流用)。

### 5.5 aria-live によるスクリーンリーダー対応

タイムライン全体を `<div role="log" aria-live="polite" aria-label={t("攻撃ステップログ", "Attack step log")}>` でラップし、ステップが追加されるたびに読み上げが発火するようにする。

---

## 6. AttackResultBanner

### 6.1 表示条件

`attackResult()` が非 null のときのみ表示する（`<Show when={attackResult()}>` で制御）。

### 6.2 攻撃成立時 (outcome === "succeeded")

```
┌─────────────────────────────────────────────────────────┐
│  WARNING  攻撃成立 — この実装は脆弱です                   │
│  Attack succeeded — this implementation is vulnerable    │
└─────────────────────────────────────────────────────────┘
```

- `background: var(--color-attack-bg)`
- `border: 2px solid var(--color-attack-accent)`
- `color: var(--color-attack-accent)`
- 左端に太い縦帯（`border-left: 4px solid var(--color-attack-accent)`）
- テキスト前に `[!]` プレフィックス（`font-weight: 700`）

### 6.3 防御成立時 (outcome === "blocked")

```
┌─────────────────────────────────────────────────────────┐
│  SECURE  防御成立 — <blockedBy の内容>                    │
│  Defense succeeded — <blockedBy in English>              │
└─────────────────────────────────────────────────────────┘
```

- `background: var(--color-success-subtle)`
- `border: 2px solid var(--color-success-border)`
- `color: var(--color-success)`
- 左端縦帯: `border-left: 4px solid var(--color-success)`
- テキスト前に `[OK]` プレフィックス

### 6.4 型定義

```typescript
interface AttackResultBannerProps {
  result: AttackResult;
}
```

### 6.5 i18n

```typescript
// 攻撃成立
const MSG_VULN_JA = "攻撃成立 — この実装は脆弱です";
const MSG_VULN_EN = "Attack succeeded — this implementation is vulnerable";
// 防御成立
const MSG_BLOCKED_JA = (by: string) => `防御成立 — ${by}`;
const MSG_BLOCKED_EN = (by: string) => `Defense succeeded — ${by}`;
```

---

## 7. AttackDefensePanel

### 7.1 概要

選択された攻撃シナリオの `defenseRecommendation` を折りたたみ可能なパネルで表示する。
`AttackResultBanner` の直下に配置し、攻撃実行後に自動展開する（`setDefenseOpen(true)` を呼び出す）。

### 7.2 折りたたみヘッダ

```
▶ 防御策を見る / Show Defense Recommendation     [折りたたみボタン]
```

ヘッダ: `background: var(--bg-card)`, `border: 1px solid var(--border-subtle)`, `border-radius: var(--radius-md)`
展開時にヘッダの `border-color` を `var(--color-success-border)` に変化させる。

```typescript
<button
  class="defense-toggle"
  aria-expanded={defenseOpen()}
  onClick={() => setDefenseOpen(!defenseOpen())}
>
  <span>{t("防御策を見る", "Show Defense Recommendation")}</span>
  <span aria-hidden="true">{defenseOpen() ? "▾" : "▸"}</span>
</button>
```

### 7.3 展開コンテンツ

展開時のレイアウト（デスクトップ: 2カラム / モバイル: 縦積み）:

```
左カラム                        右カラム
─────────────────────────────────────────────
概要テキスト                    コード例 (コードブロック)
外部リファレンス一覧             既存ファイルリンク
```

#### 概要テキスト

```typescript
<p class="defense-summary">{t(rec.summary, rec.summaryEn)}</p>
```

#### コードヒント

```typescript
<For each={rec.codeHints}>
  {(hint) => (
    <div class="defense-code-block">
      <div class="defense-code-label mono">{hint.lang.toUpperCase()} — {hint.label}</div>
      <pre class="json-block">{hint.code}</pre>
    </div>
  )}
</For>
```

`json-block` クラスは `DataFlowPanel.css` で既に定義済みのスタイルを流用する。
シンタックスハイライトは CSS カラーリングのみで対応（外部ライブラリ導入なし）。

#### 外部リファレンス

```typescript
<For each={rec.references}>
  {(ref) => (
    <a
      class="defense-ref-link"
      href={ref.url}
      target="_blank"
      rel="noopener noreferrer"
    >
      {ref.type}-{ref.id}
    </a>
  )}
</For>
```

#### 既存ファイルリンク

```typescript
<For each={rec.existingFileLinks}>
  {(link) => (
    <div class="defense-file-link">
      <span class="defense-file-path mono">{link.path}</span>
      <span class="defense-file-desc">{link.description}</span>
    </div>
  )}
</For>
```

`link.path` は実際のファイルパス文字列（クリックしても GitHub 遷移は行わない）。実装フェーズで GitHub URL の組み立てを検討する。

---

## 8. 教育用バナー（固定表示）

### 8.1 配置

`AttackPanel` の最上部（シナリオセレクタより上）に常時表示する。
`dismissable` は設けず、常にビューポート内に表示する。

### 8.2 文言

| 言語 | テキスト |
|------|--------|
| 日本語 | 教育用シミュレーション — 実環境を攻撃するためのコードではありません |
| English | Educational simulation — not for use against real systems |

### 8.3 視覚デザイン

```
┌══════════════════════════════════════════════════════════╗
║  [!]  教育用シミュレーション                              ║
║       実環境を攻撃するためのコードではありません             ║
║       Educational simulation — not for use against real  ║
║       systems                                            ║
╚══════════════════════════════════════════════════════════╝
```

- `border: 2px solid var(--color-warning)`
- `background: var(--color-warning-dim)`
- `color: var(--color-warning)`
- `border-radius: var(--radius-md)`
- `padding: 0.6rem 1rem`
- `font-family: var(--font-mono)`, `font-size: 0.7rem`
- `font-weight: 600`
- 左端に `border-left: 4px solid var(--color-warning)` で強調

### 8.4 a11y

```typescript
<div
  class="edu-warning-banner"
  role="note"
  aria-live="polite"
  aria-label={t("教育用シミュレーション注意事項", "Educational simulation notice")}
>
```

`role="note"` は補助的情報として認識され、スクリーンリーダーが適切に扱う。

---

## 9. PCB テーマ準拠

### 9.1 既存 CSS 変数の流用

`src/app.css` で定義済みの以下の変数をそのまま使用する:

| 変数 | 用途 |
|-----|------|
| `--bg-primary`, `--bg-secondary`, `--bg-card` | 背景 |
| `--text-primary`, `--text-secondary`, `--text-muted` | テキスト |
| `--border-subtle`, `--border-active` | ボーダー |
| `--glow-color`, `--glow-color-dim` | シアン系アクセント |
| `--trace-color`, `--trace-color-dim` | オレンジ系アクセント |
| `--color-success`, `--color-success-*` | 防御成立 |
| `--color-danger`, `--color-danger-*` | エラー |
| `--color-warning`, `--color-warning-dim` | 警告 |
| `--font-mono`, `--font-body` | フォント |
| `--radius-sm`, `--radius-md`, `--radius-lg` | 角丸 |
| `--transition-fast`, `--transition-normal` | トランジション |

### 9.2 攻撃モード専用 CSS 変数（追加）

`src/app.css` の `:root` ブロック末尾に追記する:

```css
/* Attack Demo Catalog */
--color-attack-bg: rgba(255, 140, 0, 0.08);     /* 攻撃者モード背景 (オレンジ系) */
--color-attack-accent: #ff8c00;                   /* 攻撃アクセント色 */
--color-attack-accent-dim: rgba(255, 140, 0, 0.2);
--color-attack-accent-border: rgba(255, 140, 0, 0.35);
--color-defense-accent: #52c41a;                  /* 防御アクセント (= --color-success 相当) */
```

ライトテーマ用の上書きは `[data-theme="light"]` ブロックに追記:

```css
[data-theme="light"] {
  --color-attack-bg: rgba(180, 80, 0, 0.06);
  --color-attack-accent: #b45200;
  --color-attack-accent-dim: rgba(180, 82, 0, 0.15);
  --color-attack-accent-border: rgba(180, 82, 0, 0.3);
}
```

### 9.3 スコープ付き CSS ファイル

新規コンポーネントとそれぞれの CSS ファイルの対応:

| コンポーネントファイル | CSS ファイル |
|---------------------|------------|
| `src/components/shared/AttackPanel.tsx` | `src/components/shared/AttackPanel.css` |
| `src/components/shared/ViewModeToggle.tsx` | `src/components/shared/ViewModeToggle.css` |
| `src/components/shared/AttackStepTimeline.tsx` | `src/components/shared/AttackStepTimeline.css` |
| `src/components/shared/AttackResultBanner.tsx` | `src/components/shared/AttackResultBanner.css` |
| `src/components/shared/AttackDefensePanel.tsx` | `src/components/shared/AttackDefensePanel.css` |
| `src/components/shared/AttackScenarioSelector.tsx` | `src/components/shared/AttackScenarioSelector.css` |

各 CSS ファイルは対応する TSX ファイルと隣接配置し、`import "./ComponentName.css"` でインポートする。グローバルなクラス名汚染を避けるため、クラス名プレフィックスで名前空間を管理する（例: `.attack-panel-*`, `.view-mode-toggle-*`）。

---

## 10. レスポンシブ

### 10.1 ブレークポイント

既存 `app.css` に合わせて同一ブレークポイントを使用:

| ブレークポイント | 幅 | 対応 |
|-------------|---|-----|
| デスクトップ | >= 768px | 2カラムレイアウト |
| モバイル | < 768px | 縦積み、コラプシブル UI |

### 10.2 デスクトップ (>= 768px)

- `AttackStepTimeline` と `AttackDefensePanel` を横並び 2カラムで表示:
  ```css
  .attack-panel-body {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
  }
  ```
- タイムラインが左カラム、防御策説明が右カラム
- `AttackScenarioSelector` はチップ群横並びで全幅表示

### 10.3 モバイル (< 768px)

```css
@media (max-width: 767px) {
  .attack-panel-body {
    grid-template-columns: 1fr;
  }
  .attack-scenario-chips {
    display: none;
  }
  .attack-scenario-select {
    display: block; /* ネイティブ <select> に切り替え */
  }
}
```

- `AttackScenarioSelector`: チップ群を非表示にし、`<select>` 要素に切り替える（コンポーネント内部で Signal により表示を切り替え）
- `AttackStepTimeline`: 縦積みのまま全幅で表示
- `AttackDefensePanel`: タイムラインの下に続けて表示

### 10.4 画面幅適応のための Signal

```typescript
const [isMobile, setIsMobile] = createSignal(window.innerWidth < 768);
// ResizeObserver or matchMedia を onMount 内で登録
```

`window.innerWidth` への直接アクセスは SSR 非対応だが、このプロジェクトは CSR のみのため許容。

---

## 11. アニメーション

### 11.1 方針

- D3.js は新規コンポーネントには使用しない（既存 Overview/Encapsulation ビュー専用）
- `solid-motionone` を使用してコンポーネントの出入りアニメーションを実装
- CSS keyframe アニメーションも併用（軽量なステータス点滅など）

### 11.2 ステップ追加時の slide-in

`AttackStepTimeline` の各ステップカードに `solid-motionone` の `Motion` コンポーネントを適用:

```typescript
import { Motion } from "solid-motionone";

// ステップカードのラッパー
<Motion
  initial={{ opacity: 0, x: -16 }}
  animate={{ opacity: 1, x: 0 }}
  transition={{ duration: 0.25, easing: "ease-out" }}
>
  <div class="attack-step-card" style={{ "--step-color": statusColor(step.status) }}>
    {/* ... */}
  </div>
</Motion>
```

### 11.3 ViewModeToggle 切り替えトランジション

モード切り替え時にコンテンツエリアがフェード:

```typescript
<Motion
  key={viewMode()}
  initial={{ opacity: 0 }}
  animate={{ opacity: 1 }}
  transition={{ duration: 0.2 }}
>
  <Show when={viewMode() === "defender"}>
    {/* Defender コンテンツ */}
  </Show>
  <Show when={viewMode() === "attacker"}>
    {/* Attacker コンテンツ */}
  </Show>
</Motion>
```

### 11.4 バナー表示アニメーション

`AttackResultBanner` の初出時:

```css
@keyframes bannerSlideDown {
  from { opacity: 0; transform: translateY(-8px); }
  to   { opacity: 1; transform: translateY(0); }
}
.attack-result-banner {
  animation: bannerSlideDown 300ms var(--transition-normal) both;
}
```

---

## 12. a11y

### 12.1 キーボードナビゲーション

| 操作対象 | キー操作 |
|--------|--------|
| ViewModeToggle | `Tab` でフォーカス → `Enter` / `Space` で切替 |
| AttackScenarioSelector (チップ群) | `Tab` でチップ間移動、`Enter` / `Space` で選択 |
| AttackScenarioSelector (select) | ネイティブ `<select>` のキーボード操作をそのまま利用 |
| 実行ボタン | `Tab` でフォーカス、`Enter` で実行 |
| payload 展開トグル | `Tab` でフォーカス、`Enter` / `Space` で展開/折りたたみ |
| 防御策展開トグル | 同上 |

### 12.2 フォーカスリング

全インタラクティブ要素で `:focus-visible` が発火するようにする。
`app.css` に既定義の `outline: 2px solid var(--glow-color); outline-offset: 2px;` が適用される。

### 12.3 aria-live によるライブリージョン

- タイムラインログ全体: `role="log" aria-live="polite"`
- `AttackResultBanner` の出現: `role="status" aria-live="polite"` (alert/assertive は過剰であり、polite で十分)
- ステップの `running` 状態への遷移: 上記ログリージョン経由で自動読み上げ

### 12.4 色だけに依存しない状態表示

すべての状態（running / success / blocked など）はテキストラベルとアイコン文字を色と同時に表示し、色覚多様性に対応する。

具体例:
- `○ PENDING` (灰色テキスト + 丸文字)
- `◉ RUNNING` (シアン + 丸文字) ← 点滅
- `✎ SUCCESS [!]` (オレンジ + アイコン)
- `[x] BLOCKED [OK]` (緑 + アイコン)

### 12.5 教育用バナーの役割

```typescript
<div role="note" aria-label="...">
```

`role="note"` は補足情報として扱われ、スクリーンリーダーが自動的に読み上げはしないが、ページ内をナビゲートする際に発見される。`dismissable` を設けないことで、常に DOM に存在し続け、a11y ツリーから除外されない。

---

## 13. i18n

### 13.1 方針

全文言は `useI18n()` から取得した `t(ja, en)` ヘルパー経由で記述する。ハードコードした日本語・英語文字列を直接 JSX に書かない。

### 13.2 AttackPanel 固定文言一覧

| key (概念) | 日本語 | English |
|-----------|------|---------|
| 攻撃者モードラベル | `攻撃者モード` | `Attacker Mode` |
| 防御者モードラベル | `防御者モード` | `Defender Mode` |
| 教育バナー行1 | `教育用シミュレーション` | `Educational Simulation` |
| 教育バナー行2 | `実環境を攻撃するためのコードではありません` | `Not for use against real systems` |
| 実行ボタン | `攻撃を実行` | `Run Attack` |
| 実行中ラベル | `実行中...` | `Running...` |
| 攻撃成立メッセージ | `攻撃成立 — この実装は脆弱です` | `Attack succeeded — implementation is vulnerable` |
| 防御成立メッセージ | `防御成立 —` | `Defense succeeded —` |
| 前提条件ラベル | `前提条件:` | `Prerequisite:` |
| 深刻度ラベル | `深刻度:` | `Severity:` |
| ペイロード展開ラベル | `ペイロード` | `Payload` |
| 防御策展開ラベル | `防御策を見る` | `Show Defense Recommendation` |
| ステップログARIA | `攻撃ステップログ` | `Attack step log` |
| 攻撃シナリオ選択ラベル | `攻撃シナリオを選択` | `Select attack scenario` |
| 結果バナーARIA (成功) | `攻撃成立通知` | `Attack success notification` |
| 結果バナーARIA (防御) | `防御成立通知` | `Defense success notification` |

### 13.3 動的文言

`blockedBy` フィールドのように動的な値を含む文言は、テンプレートリテラルを使用する:

```typescript
t(`防御成立 — ${result.blockedBy}`, `Defense succeeded — ${result.blockedBy}`)
```

---

## 14. ワイヤーフレーム (ASCII)

### 14.1 Defender モード（既存）

```
┌─────────────────────────────────────────────────────────────┐
│ AuthView                                                     │
│  [OAuth][JWT][TLS][Session][RBAC][Auth][OIDC]...            │ ← auth-subtabs
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────┐    │
│  │  [D] DEFENDER MODE  |  [A] ATTACKER MODE            │    │ ← ViewModeToggle
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│  [既存の JwtInspector / OAuthFlow etc. のコンテンツ]          │
│  ...                                                         │
│  ┌──────────────────────────────────────┐                   │
│  │ DataFlowPanel (HTTP/Trace/DB タブ)   │                   │
│  └──────────────────────────────────────┘                   │
└─────────────────────────────────────────────────────────────┘
```

### 14.2 Attacker モード（新規 AttackPanel）

```
┌─────────────────────────────────────────────────────────────┐
│ AuthView                                                     │
│  [OAuth][JWT][TLS][Session][RBAC][Auth][OIDC]...            │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────┐    │
│  │  [D] DEFENDER MODE  |  [A] ATTACKER MODE  ←active   │    │ ← ViewModeToggle
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│  ╔═════════════════════════════════════════════════════╗    │
│  ║ [!] 教育用シミュレーション                           ║    │ ← 教育バナー (常時)
│  ║     実環境を攻撃するためのコードではありません         ║    │
│  ╚═════════════════════════════════════════════════════╝    │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ シナリオ:                                            │    │ ← AttackScenarioSelector
│  │  ● JWT 署名改竄 [CRITICAL] CWE-347                  │    │
│  │  ○ alg=none 攻撃 [HIGH]   CAPEC-60                  │    │
│  │  ○ トークンリプレイ [MEDIUM]                         │    │
│  │                                                      │    │
│  │ 前提条件: 攻撃者は通信を傍受できる位置にいる          │    │
│  │                                                      │    │
│  │  [  攻撃を実行  ]                                    │    │ ← 実行ボタン
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│  ┌──────────────────────┐  ┌──────────────────────────┐    │ ← 2カラム (desktop)
│  │ タイムライン          │  │ 防御策解説               │    │
│  │  │                   │  │  ▶ 防御策を見る           │    │
│  │  ●── [◉] 傍受  ✓    │  │  ┌──────────────────────┐ │    │
│  │  │                   │  │  │ 概要: HMAC 署名検証  │ │    │
│  │  ●── [✎] 改竄  ⚠    │  │  │ コード例:           │ │    │
│  │  │                   │  │  │  jwt.verify(...)    │ │    │
│  │  ●── [✓] 検証 [OK]  │  │  └──────────────────────┘ │    │
│  └──────────────────────┘  └──────────────────────────┘    │
│                                                              │
│  ┌─════════════════════════════════════════════════════┐    │
│  │ [!] 攻撃成立 — この実装は脆弱です                    │    │ ← AttackResultBanner
│  └─════════════════════════════════════════════════════┘    │
└─────────────────────────────────────────────────────────────┘
```

### 14.3 モバイルレイアウト (< 768px)

```
┌─────────────────────────────────┐
│  [D] MODE  |  [A] MODE          │ ← ViewModeToggle (全幅)
├─────────────────────────────────┤
│  ╔═══════════════════════════╗  │
│  ║ [!] 教育用シミュレーション ║  │
│  ╚═══════════════════════════╝  │
│                                 │
│  シナリオ: [▼ 署名改竄▾]        │ ← <select> に切替
│  前提条件: ...                  │
│  [ 攻撃を実行 ]                 │
│                                 │
│  タイムライン                   │ ← 縦積み
│   ●── [◉] 傍受       ✓         │
│   ●── [✎] 改竄       ⚠         │
│   ●── [✓] 検証      [OK]       │
│                                 │
│  ┌─══════════════════════════┐  │
│  │ [!] 攻撃成立              │  │
│  └─══════════════════════════┘  │
│                                 │
│  ▶ 防御策を見る                  │ ← 縦積みで続く
│  ┌─────────────────────────┐   │
│  │ 概要: ...               │   │
│  │ コード例: ...           │   │
│  └─────────────────────────┘   │
└─────────────────────────────────┘
```

---

## 15. 関連ファイル

### 15.1 新規作成ファイル

| ファイルパス | 役割 |
|-----------|-----|
| `src/state/attack-state.ts` | `viewMode` Signal と URL 同期ロジック |
| `src/components/shared/ViewModeToggle.tsx` | Defender/Attacker 切替トグル |
| `src/components/shared/ViewModeToggle.css` | トグルのスコープ付きスタイル |
| `src/components/shared/EducationalWarningBanner.tsx` | 赤帯教育警告バナー (Attacker View 常時表示、dismissable 禁止) |
| `src/components/shared/AttackPanel.tsx` | 攻撃パネル全体のオーケストレーター |
| `src/components/shared/AttackPanel.css` | パネルのスコープ付きスタイル |
| `src/components/shared/AttackScenarioSelector.tsx` | シナリオ選択 UI |
| `src/components/shared/AttackScenarioSelector.css` | セレクタのスコープ付きスタイル |
| `src/components/shared/AttackStepTimeline.tsx` | 縦タイムライン |
| `src/components/shared/AttackStepTimeline.css` | タイムラインのスコープ付きスタイル |
| `src/components/shared/AttackResultBanner.tsx` | 攻撃成立/防御成立バナー |
| `src/components/shared/AttackResultBanner.css` | バナーのスコープ付きスタイル |
| `src/components/shared/AttackDefensePanel.tsx` | 防御策折りたたみ解説 |
| `src/components/shared/AttackDefensePanel.css` | 解説のスコープ付きスタイル |
| `src/data/attack-scenarios.ts` | 全タブ分の `AttackScenarioMeta[]` 静的データ |

### 15.2 既存ファイルの変更

| ファイルパス | 変更内容 |
|-----------|--------|
| `src/app.css` | `:root` に `--color-attack-*` / `--color-defense-accent` 変数を追記 |
| `src/types/security.ts` | `AttackStepKind`, `AttackStep`, `AttackResult`, `AttackScenarioMeta` 等を追記 |
| `src/components/auth/JwtInspector.tsx` | `<ViewModeToggle>` と `<AttackPanel>` を組み込み、`onRunScenario` の実装を追加 |
| 他タブコンポーネント (OAuthFlow.tsx 等 全12ファイル) | 同様に `<ViewModeToggle>` と `<AttackPanel>` を組み込み |

### 15.3 変更なしの参照ファイル

| ファイルパス | 参照理由 |
|-----------|--------|
| `src/components/shared/DataFlowPanel.tsx` | `json-block`, `trace-section`, `crypto-viz` クラスをスタイル参照のみ流用 |
| `src/components/auth/AuthView.tsx` | タブナビ構造・`auth-content` への挿入位置の確認 |
| `src/components/auth/AuthView.css` | `.subtab`, `.auth-content` スタイルとの整合性確認 |
| `src/components/auth/JwtInspector.css` | `decodedFade` キーフレーム流用、`demo-result` スタイルパターン参照 |
| `src/api/client.ts` | `apiPost`, `apiGet` 呼び出しパターンの踏襲 |
| `src/i18n/context.tsx` | `t(ja, en)` ヘルパーの使用パターン確認 |
