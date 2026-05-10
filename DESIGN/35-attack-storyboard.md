---
title: 攻撃デモカタログ — AttackStoryboard (紙芝居型攻撃可視化) UI 仕様
phase: design
audience: フロントエンド開発者・教材執筆者・UI レビュアー
last-updated: 2026-05-10
safety-reviewed: false
---

# 35. AttackStoryboard (紙芝居型攻撃可視化) UI 仕様

## 1. 目的とスコープ

### 1.1 解決する課題

PR #6 (becc5fc) でリリース、PR #14/#17/#18/#19 で順次 live 化された攻撃デモカタログ (38 シナリオ) は、
`AttackPanel` が「実行ボタン → 結果一括ドン」型 UI のため、攻撃の **時系列の物語** が立ち上がらない。
具体的な不足点は以下の通り。

| 課題 | 現状の挙動 | 学習者への影響 |
|---|---|---|
| 攻撃者・被害者・サーバの視点が混ざる | `AttackStepTimeline` が probe/exploit/verify の機械的 3 段カードのみ | 「誰が」「いつ」攻撃を仕掛けたかの人物視点が欠ける |
| 漏えいデータが平文 JSON として埋もれる | `AttackResultBanner` の summary に短文表示 | 「攻撃で何が奪取されたか」が一目で分からない |
| 攻撃成立の瞬間が点で表現される | 1 リクエスト = 1 結果で時系列がない | 「いつ・どう成立したか」のドラマが体感できない |

ユーザー評価: 「攻撃側がどういう攻撃で何をとれてしまうのかがわかりずらい」(2026-05-10)

### 1.2 解決方針

攻撃シナリオ (`AttackScenarioMeta`) に `story?: AttackStoryScene[]` を持たせ、
共通コンポーネント `AttackStoryView` が紙芝居 (キャラ + 吹き出し + ◄ ► + auto-play) として再生する。

| 提供する体験 | 説明 |
|---|---|
| シーン進行 | 5–7 シーンを ◄ ► で手動進行、または auto-play で自動再生 |
| キャラクター | 😈 attacker / 👤 victim / 🖥️ server 等のアバターと吹き出し |
| ビジュアル variants | http-request/http-response/data-leak/code-defense/sequence-arrow/ascii |
| raw exchange リンク | live モードで `RawExchange` 内のフィールドをハイライト参照 |
| 既存 UI との共存 | `AttackStepTimeline` は折りたたみで残置、フォールバック互換 |

### 1.3 スコープ外

- 大量の SVG/Canvas 凝ったアニメーション (PCB テーマと干渉)
- raw HTTP の編集 UI (それは `RawHttpComposer` の責務、DESIGN/33)
- `SequenceDiagramView` の置換 (機械的事実は SequenceDiagram、物語的解釈は本仕様で棲み分け)
- 音声効果・BGM (silent 原則を維持)

### 1.4 既存 DESIGN との関係

- 本仕様は `DESIGN/30` の Phase 戦略に乗り、Phase 2 PR-4 (mfa-otp-replay) で初導入し Phase 3 で他 13 件に波及
- `DESIGN/33` (RawHttpComposer / SequenceDiagramView) と棲み分け (詳細 §14)
- `DESIGN/04` (safety guardrails) の「明示」「防御策併記」原則を継承 (story 末尾に防御発動シーン必須化)
- `DESIGN/02` (UI spec) のコンポーネント仕様スタイルを継承

---

## 2. データモデル (`AttackStoryScene` 型)

### 2.1 中核型 (推奨案)

```typescript
// shared/api-types.ts に追加

/** 攻撃シナリオの 1 シーン (紙芝居の 1 ページ) */
export interface AttackStoryScene {
  /** 安定 ID (story 配列内ユニーク)。テスト・キーボード遷移・ディープリンクで使用 */
  id: string;
  /** シーンタイトル (例: "アリスの OTP を肩越しに観測") */
  title: string;
  titleJa: string;
  /** 吹き出し speech と背景説明 narration の主軸を持つアクター */
  actor: AttackStoryActor;
  /** 吹き出しテキスト。キャラ視点の一人称 (常体)。null=吹き出しなし (純ナレーション) */
  speech?: { ja: string; en: string } | null;
  /** 第三者ナレーション (敬体)。シーン下部に表示 */
  narration?: { ja: string; en: string } | null;
  /** 中央の図解。type 別のタグ付きユニオン (§2.2) */
  visual?: AttackStoryVisual;
  /** 同時にハイライトする他アクター (例: attacker speech 中、victim/server を薄表示) */
  highlightActors?: AttackStoryActor[];
  /** auto-play 時のシーン表示時間 (ms)。未指定は story 全体のデフォルト (3000ms) */
  durationMs?: number;
}

export type AttackStoryActor =
  | "attacker"   // 攻撃者 (😈 / 橙)
  | "victim"     // 被害者ユーザ (👤 / 青)
  | "server"     // 認証サーバ / orchestrator (🖥️ / 緑)
  | "victim-srv" // victim コンテナ自体 (live モード) (🔓 / 橙赤)
  | "narrator"   // 第三者解説 (📢 / グレー)
  | "system";    // ブラウザ・ネットワーク・generic (🌐 / シアン)
```

### 2.2 ビジュアル variants (タグ付きユニオン)

```typescript
export type AttackStoryVisual =
  /** raw HTTP リクエスト/レスポンス。highlight でフィールド強調 */
  | { type: "http-request"; sourceRef: RawExchangeRef; highlight?: HttpHighlight[] }
  | { type: "http-response"; sourceRef: RawExchangeRef; highlight?: HttpHighlight[] }
  /** 漏えい/取得データの強調表示 (赤囲い + ラベル) */
  | {
      type: "data-leak";
      label: string;
      labelJa: string;
      valueRef: RawExchangeRef;
      severity?: "info" | "high" | "critical";
    }
  /** 防御コードのハイライト (codeHints から抜粋) */
  | { type: "code-defense"; codeHintIndex: number; lineHighlight?: [number, number] }
  /** シーケンス矢印の単発表示 (SequenceDiagramView を再利用しない簡易版) */
  | {
      type: "sequence-arrow";
      from: AttackStoryActor;
      to: AttackStoryActor;
      label: string;
      labelJa: string;
      direction: "request" | "response";
    }
  /** 自由テキスト/ASCII 図 (簡易フォールバック) */
  | { type: "ascii"; content: string };
```

### 2.3 raw exchange への参照 (`RawExchangeRef`)

```typescript
/** raw exchange 内の特定フィールドへの参照 (§7 で詳細議論) */
export interface RawExchangeRef {
  /** どのペアか */
  pair: "browserToOrchestrator" | "orchestratorToVictim";
  /** request か response か */
  side: "request" | "response";
  /** どこを参照するか (case-insensitive header name 含む) */
  field: "line" | "body" | { header: string };
}

export interface HttpHighlight {
  /** 強調する部位 */
  target: "header" | "body-fragment" | "status";
  /** ヘッダ名 or 検索文字列 */
  match: string;
  /** ホバー説明 (省略可) */
  tooltipJa?: string;
  tooltip?: string;
}
```

### 2.4 既存 `AttackScenarioMeta` への追加フィールド

```typescript
// shared/api-types.ts の AttackScenarioMeta 末尾に追加
export interface AttackScenarioMeta {
  /* ... 既存フィールド (id, tabId, name, ..., codeHints, modes, mode, liveTemplate) ... */

  /** 紙芝居型物語シーン。未指定/空配列のシナリオは AttackStoryView を非表示 */
  story?: AttackStoryScene[];

  /** auto-play デフォルト ms (省略時 3000)。シナリオ単位で上書き可能 */
  storyDefaultDurationMs?: number;
}
```

### 2.5 設計判断 (代替案との比較)

| 案 | 内容 | メリット | デメリット | 採否 |
|---|---|---|---|---|
| A | discriminated union (上記) | 型安全、IDE 補完が効く | variant 追加で型膨張 | **採用** |
| B | 自由形式 `Record<string, unknown>` | 柔軟 | 型安全性ゼロ、テスト不能 | 不採用 |
| C | visual を別ファイル化 (`AttackStoryVisualSpec`) | 関心の分離 | scenario 1 ファイルで完結しない | Phase 3 で再評価 |

---

## 3. UI コンポーネント分割

### 3.1 ファイル構成 (推奨案)

```
src/components/shared/
├── AttackStoryView.tsx       統合コンテナ (シーン状態管理・auto-play・◄ ► 配線)
├── AttackStoryView.css
├── AttackStoryScene.tsx      1 シーンの描画 (キャラ + 吹き出し + ビジュアル)
├── AttackStoryScene.css
├── AttackStoryControls.tsx   ◄ ► / dot indicator / auto-play toggle
├── AttackStoryControls.css
└── StoryActorAvatar.tsx      内部用 (emoji ベースのアクターアバター)
```

### 3.2 案比較

| 案 | ファイル数 | 評価 |
|---|---|---|
| A | 1 ファイル (`AttackStoryView.tsx` のみ) | △ シーン描画ロジックが肥大化、テスト困難 |
| B | **4 ファイル分割 (上記)** | **採用**: 各責務明確、個別テスト可能 |
| C | visual variant ごとに別ファイル | × 過剰 (`<Switch><Match>` で十分) |

### 3.3 各ファイルの責務

#### `AttackStoryView.tsx`

```typescript
interface AttackStoryViewProps {
  story: AttackStoryScene[];
  /** live モードでの raw exchange。null/undefined でも動作 (visual がフォールバック) */
  rawExchange?: import("../../../shared/api-types").RawExchange | null;
  /** auto-play デフォルト ms (props 未指定時は 3000) */
  defaultDurationMs?: number;
}
```

- 内部 signal: `currentIndex: number`, `autoPlay: boolean`, `paused: boolean`
- `createEffect` で auto-play タイマ管理 + `prefers-reduced-motion` 判定
- キーボードイベント (← → Space Esc Home End) を root 要素にバインド
- `<AttackStoryScene>` と `<AttackStoryControls>` を構成

#### `AttackStoryScene.tsx`

```typescript
interface AttackStorySceneProps {
  scene: AttackStoryScene;
  rawExchange?: RawExchange | null;
}
```

- `<Switch><Match>` で `visual.type` を分岐描画
- `solid-motionone` の `<Motion.div>` でフェードイン (200ms)
- アクターアバターを左/中/右に配置 (CSS Grid)
- 吹き出しは `clip-path` の三角 + border 枠

#### `AttackStoryControls.tsx`

```typescript
interface AttackStoryControlsProps {
  current: number;
  total: number;
  autoPlay: boolean;
  onPrev: () => void;
  onNext: () => void;
  onJump: (index: number) => void;
  onToggleAutoPlay: () => void;
}
```

- `StepControl.tsx` の DNA を継承しつつ dot indicator + auto-play toggle を追加
- (note) 既存 `StepControl.tsx` には dot 機能がないため流用ではなく類型コンポーネントとする。DRY 化は Phase 3 で再評価

#### `StoryActorAvatar.tsx` (内部用)

```typescript
interface StoryActorAvatarProps {
  actor: AttackStoryActor;
  active?: boolean;
}
```

- emoji ベースの描画。Phase 1 では emoji 直接、将来 SVG コンポーネントに置換可能 (シナリオデータは無変更)

### 3.4 SolidJS 1.9 規約遵守 (必須)

- props は常に `props.xxx` (デストラクチャ禁止)
- 早期 return 禁止 → `<Show fallback={...}>`
- 配列更新は `setX(prev => ...)` パターン
- `for` ループは `<For each={}>`

---

## 4. AttackPanel との統合

### 4.1 統合方針 (3 案比較)

| 案 | 内容 | 採否 |
|---|---|---|
| A | **置換**: AttackStoryView が AttackStepTimeline + AttackResultBanner を完全置換 | △ 全シナリオ story 完成まで実施不可、退行リスク高 |
| B | **共存**: story を持つシナリオは story 表示、既存 timeline は折りたたみで残置 | **採用** (Phase 1-3 の全期間で安全) |
| C | **タブ追加**: DataFlowPanel に "Story" タブを追加 | × story は攻撃の主役 UI、tab 内では弱い |

### 4.2 統合レイアウト (案 B)

```
AttackPanel
├── 1. EducationalWarningBanner
├── 2. AttackScenarioSelector
├── 3. mode labels (両モード並列表示ラベル)
├── 4a. <Show when={isLiveMode()}> RawHttpComposer </Show>
├── 4b. <Show when={!isLiveMode()}> AttackRunButton </Show>
│
├── ★NEW★ 5. <Show when={hasStory() && hasRunResult()}>
│              AttackStoryView (story={selectedScenario().story} rawExchange={rawExchange()})
│            </Show>
│
├── 6. <details class="attack-classic-timeline-fold">  ← 既存 timeline を折りたたみ
│        <summary>{t("詳細ステップを見る", "Show detailed steps")}</summary>
│        AttackStepTimeline
│      </details>
│
├── 7. AttackDefensePanel
├── 8. AttackResultBanner       ← story 終了後の機械的事実として最下段に残す (§15 O1)
└── 9. DataFlowPanel
```

### 4.3 fallback 挙動 (story 未定義シナリオ)

- `story` が `undefined` または `[]` のとき AttackStoryView 自体を非表示 (`<Show when={hasStory()}>`)
- AttackStepTimeline を `<details open>` (展開状態) で表示し、現状 UX を維持
- Phase 3 で全シナリオに story が揃ったら `<details>` を default closed に切替 (DESIGN/35 改訂で対応)

### 4.4 attackResult との連動

- `attackResult` が `null` (未実行) の間は AttackStoryView を非表示 (空状態を見せない)
- `attackResult` が更新されたタイミングで `AttackStoryView` の `currentIndex` を 0 にリセット
- `outcome === "succeeded"` のシナリオは story 末尾に「攻撃成立」シーンを挟む規約 (§8.3)
- `outcome === "blocked"` のシナリオは末尾に「防御発動」シーンを挟む規約 (§8.3)
- `outcome === "error"` のシナリオは story 非表示 + AttackStepTimeline 表示にフォールバック (§15 O2)

---

## 5. インタラクション仕様

### 5.1 ナビゲーション

| 操作 | 動作 |
|---|---|
| ► (進む) | `currentIndex + 1`、最終シーンで disabled |
| ◄ (戻る) | `currentIndex - 1`、最初のシーンで disabled |
| dot クリック | `currentIndex = i` にジャンプ |
| キーボード `→` / `Space` | 進む (auto-play 中は pause) |
| キーボード `←` | 戻る |
| キーボード `Esc` | auto-play 停止 |
| キーボード `Home` / `End` | 最初/最後のシーンへ |

### 5.2 auto-play 挙動

- toggle ボタン (▶ Auto-play / ⏸ Pause)
- ON 時、`scene.durationMs ?? story.defaultDurationMs ?? 3000` ごとに `currentIndex + 1`
- 最終シーン到達で auto-play 自動停止
- `prefers-reduced-motion: reduce` 検出時は **default OFF** (`createEffect` で初期化)
- ユーザが手動操作 (◄ ► / dot ジャンプ) したら auto-play 一時停止

### 5.3 a11y 要件

- root 要素に `role="region"` + `aria-label="攻撃ストーリーボード / Attack storyboard"`
- 現在シーン番号の dot に `aria-current="step"`
- シーン切替時に `aria-live="polite"` ステータス領域へ「シーン X / Y: タイトル」をアナウンス
- 各 dot ボタンに `aria-label="シーン X へジャンプ / Jump to scene X"`
- auto-play ボタンに `aria-pressed={autoPlay()}`
- キーボード focus は ◄ ► のいずれかにデフォルト配置、tab で controls → scene の順

---

## 6. アニメーション

### 6.1 シーン間遷移 (案比較)

| 案 | 実装 | 採否 |
|---|---|---|
| A | cut (なし) | △ 紙芝居らしさ薄い |
| B | **fade** | **採用**: solid-motionone で `opacity 0→1` 200ms、シンプル、reduced-motion 対応容易 |
| C | slide | △ 演出強いがレイアウトずれリスク |
| D | variant ごとに変える (`scene.transition` 導入) | × 過剰、authoring 負担増 |

### 6.2 アクターハイライト切替

- CSS class 切替で `box-shadow` / `border-color` を変える (`transition: 200ms ease`)
- highlight 中のアクターに `data-active="true"` 属性 (CSS セレクタ用)
- 非 highlight アクターは `opacity: 0.4`、色相変化は使わない (色弱配慮)

### 6.3 reduced-motion 対応

```typescript
const prefersReduced = () =>
  window.matchMedia("(prefers-reduced-motion: reduce)").matches;
// Motion 適用時に prefersReduced() ? 0 : 200 で transition 無効化
```

- AttackStoryView 全体で reduce 検出時は `transition: none` のクラスを root に付与
- auto-play は **default OFF**、ただしユーザが ON にすれば動作 (尊重するが選択を奪わない)

---

## 7. raw exchange リンク方式

### 7.1 案比較

| 案 | 例 | メリット | デメリット | 採否 |
|---|---|---|---|---|
| A | **構造体参照** (`RawExchangeRef`) | `{ pair: "orchestratorToVictim", side: "request", field: { header: "Cookie" } }` | 型安全、補完、テスト容易、シリアライズ可 | やや冗長 | **採用** |
| B | JSON pointer (`"/orchestratorToVictim/request/headers/Cookie"`) | 標準仕様 (RFC 6901) | string 検証必要、補完なし、case-sensitive | 不採用 |
| C | resolver 関数 (`(ex) => ex.orchestratorToVictim.request.headers["Cookie"]`) | 最も柔軟 | シリアライズ不能、テスト DB に保存不可 | 不採用 |

### 7.2 ヘルパー実装

```typescript
// src/utils/story-resolver.ts (新規)
import type { RawExchange } from "../../shared/api-types";
import type { RawExchangeRef } from "../../shared/api-types";

/**
 * RawExchangeRef を実値に解決する。
 * - header 検索は case-insensitive (HTTP 仕様準拠)
 * - 解決失敗 (パスが無い等) は undefined を返し、UI でプレースホルダ "—" を表示
 */
export function resolveRawRef(
  ref: RawExchangeRef,
  exchange: RawExchange | null | undefined,
): string | undefined {
  if (!exchange) return undefined;
  const pair = exchange[ref.pair];
  if (!pair) return undefined;
  const sideObj = pair[ref.side] as
    | { line: string; headers: Record<string, string>; body: string | null }
    | undefined;
  if (!sideObj) return undefined;
  if (ref.field === "line") return sideObj.line;
  if (ref.field === "body") return sideObj.body ?? undefined;
  if (typeof ref.field === "object" && "header" in ref.field) {
    const target = ref.field.header.toLowerCase();
    for (const [k, v] of Object.entries(sideObj.headers)) {
      if (k.toLowerCase() === target) return v;
    }
  }
  return undefined;
}
```

### 7.3 表現例

```typescript
// シーン例: 「攻撃者は被害者の OTP を盗む」
{
  id: "scene-3-otp-leak",
  title: "OTP intercepted",
  titleJa: "OTP が漏えい",
  actor: "attacker",
  speech: { ja: "OTPを観測した。123456だ。", en: "Got the OTP: 123456." },
  visual: {
    type: "data-leak",
    label: "TOTP code",
    labelJa: "TOTP コード",
    valueRef: { pair: "orchestratorToVictim", side: "response", field: { header: "X-Computed-OTP" } },
    severity: "high",
  },
}
```

### 7.4 raw exchange 不在時の挙動

- narration 型 (`mode !== "live"`) では `rawExchange` は常に `null`
- `valueRef` 解決失敗時は visual を fallback 表示 (label のみ + プレースホルダ "—")
- 警告ログは出さない (シナリオ作者の意図的選択もありうる)

---

## 8. シナリオ作成ガイドライン

### 8.1 推奨シーン数

**5–7 シーン**

- 4 以下: すぐ終わる紙芝居感、物語性が薄い
- 8 以上: 学習者の集中切れ、auto-play で 24 秒超
- 上限: 10 (`durationMs` 短縮で吸収可能)

### 8.2 標準テンプレ (5 シーン版)

```
Scene 1: setup       誰が・何を狙うか (attacker speech + 自身のアバター)
Scene 2: probe       攻撃者がサーバを観察・偵察 (sequence-arrow visual)
Scene 3: exploit     攻撃の核 (http-request visual + 強調 highlight)
Scene 4: leak        漏えい・成立の瞬間 (data-leak visual)
Scene 5: outcome     成立 or 防御発動 (code-defense visual or banner)
```

### 8.3 標準テンプレ (7 シーン版 — mfa-otp-replay 等の複雑系)

```
Scene 1: setup       (attacker)  目的設定
Scene 2: observation (attacker)  OTP 観測 (肩越し / フィッシング中継 / 録画)
Scene 3: victim-act  (victim)    被害者が正規ログインを試みる
Scene 4: replay      (attacker)  攻撃者が同じ OTP をリプレイ
Scene 5: server      (server)    サーバが OTP を再受理してしまう (used 記録なし)
Scene 6: leak        (attacker)  攻撃者がアカウント乗っ取り成立 (data-leak)
Scene 7: defense     (narrator)  used_otps 記録があれば防げた (code-defense)
```

### 8.4 文量・トーン規約

| 要素 | 推奨 | 上限 |
|---|---|---|
| `title` / `titleJa` | 短い名詞句 (3–6 語) | 全角 20 字 |
| `speech` (キャラ吹き出し) | 1–2 文の常体・口語 (例: 「OTPを盗んだ」) | 全角 60 字 |
| `narration` (第三者) | 1–2 文の敬体・解説 (例: 「サーバは...しません」) | 全角 100 字 |
| `visual.label` | 短い名詞 | 全角 20 字 |

### 8.5 ja/en 必須ルール

- すべての表示テキストは `{ ja, en }` 両建て (`useI18n().t()` 経由で表示)
- 例外: `id`, `actor` 等の機械フィールドは英語のみ
- `code-defense` visual は `codeHints[].code` から参照のため、コード内コメントは ja のまま既存慣習を維持

### 8.6 authoring チェックリスト (テストで自動検査)

- [ ] `id` がストーリ内ユニーク
- [ ] `actor` が `AttackStoryActor` enum 値
- [ ] `speech` または `narration` のいずれかが必ず存在
- [ ] `visual.type` が enum 値、対応する fields が揃う
- [ ] `valueRef` の `pair` / `side` / `field` が型として有効
- [ ] シーン総数 4–8 (推奨 5–7)
- [ ] outcome シーン (最終) で attack 成立 or 防御発動が明示される

---

## 9. キャラクター表現

### 9.1 emoji ベース (Phase 1 採用)

| actor | emoji | CSS 変数 (色相) | 役割 |
|---|---|---|---|
| `attacker` | 😈 | `--color-attack-accent` (橙) | 悪意のある攻撃者 |
| `victim` | 👤 | `--color-info` (青) | 被害者ユーザ |
| `server` | 🖥️ | `--color-success` (緑) | 正規サーバ (orchestrator) |
| `victim-srv` | 🔓 | `--color-attack-accent` (橙赤) | live モードの脆弱 victim コンテナ |
| `narrator` | 📢 | `--text-muted` (グレー) | 第三者解説 |
| `system` | 🌐 | `--glow-color` (シアン) | ブラウザ・ネットワーク |

### 9.2 視覚デザイン

- アバター: 直径 56px の角丸正方形 (PCB タイル風)、emoji を中央配置
- 吹き出し: アバターの右側 (LTR) / 下側 (狭幅)、CSS `border` + `clip-path` 三角形
- monospace フォント (`var(--font-mono)`) は attacker 吹き出しのみ、他は body フォント
- アクティブアクターは `box-shadow: 0 0 12px var(--actor-color)` で発光 (PCB テーマ整合)

### 9.3 抽象化レイヤ (将来 SVG 化への配慮)

```typescript
function StoryActorAvatar(props: { actor: AttackStoryActor; active?: boolean }) {
  // Phase 1: emoji map で描画
  // Phase 3+: actor → SVG component の switch に拡張可能
  // シナリオデータ側は無変更で差し替え可能
}
```

### 9.4 PCB テーマ統合

- `--actor-attacker-color: var(--color-attack-accent)` 等のセマンティック CSS 変数を `app.css` に追加
- アバター背景: `var(--bg-card)`、border: `var(--border-active)`
- 攻撃成立シーンでは attacker アバターに `glow-strong` クラス併用 (既存 glow effect 流用)

### 9.5 emoji 使用の例外規約 (重要)

CLAUDE.md / DESIGN/04 では `AttackStep` の icon (▶◉✎ 等) について絵文字禁止としているが、
本仕様の **キャラ表現は明示的に例外** とする。

| 用途 | 絵文字 | 理由 |
|---|---|---|
| `AttackStep` の status icon | ✗ 禁止 | 機械的・記号的表現が望ましい (CLAUDE.md / DESIGN/04) |
| `StoryActorAvatar` の人物表現 | ✓ **本仕様で許可** | 人物視点の物語性を出すため不可欠 |

`StoryActorAvatar` 以外のコンポーネントへの emoji 使用波及は禁止する。

---

## 10. Phase 戦略 (波及計画)

### 10.1 Phase 1 (本 PR / mfa-otp-replay)

- 共通基盤 (AttackStoryView / AttackStoryScene / AttackStoryControls / StoryActorAvatar / types) 実装
- `mfa-otp-replay` シナリオに 7 シーン story 執筆 (§8.3 テンプレ)
- AttackPanel への統合 (案 B 共存方式)
- 既存 4 件 (jwt-alg-none, oauth-state-csrf, rbac-idor, session-fixation) の story は **未着手**
  → これらは story 未定義のためフォールバック挙動 (timeline のみ表示) で動作

### 10.2 Phase 2 (波及 PR、別 PR)

| 案 | 内容 | 採否 |
|---|---|---|
| A | 既存 4 件を 1 つの PR で一括 story 化 | △ レビュー集中、UX 一貫性確保だが大 PR |
| B | 1 シナリオ = 1 PR で 4 PR 化 | △ 段階的、レビュー軽量だが調整コスト |
| C | **2 件ずつ 2 PR** (auth 系: jwt + oauth / app 系: rbac + session) | **採用**: バランス + ドメイン同質性 |

### 10.3 Phase 3 (A 群残り 13 件)

- 1 PR / シナリオを基本 (PR 細分化、レビュー軽量化)
- 共通テンプレ (§8.2 / §8.3) を `DESIGN/35-templates/` に置いて authoring 高速化
- Phase 3 完了時点で AttackStepTimeline を default closed に切替 (DESIGN/35 改訂)
- A 群完了基準: 全 17 件のシナリオに `story.length >= 4`

### 10.4 narration 型シナリオへの波及

- C/D 群 (15 件) もポテンシャル対象
- ただし narration 型は `rawExchange` を持たないため visual の `http-request` / `data-leak` で valueRef が常に解決失敗
- → narration 用 visual variant `narration-only` (text + ASCII のみ) を将来追加検討 (§15 O11)

---

## 11. テスト要件

### 11.1 構造テスト (`*-scenarios.test.ts`)

全シナリオ走査:

- story が存在する場合 §8.6 の authoring チェックリストを自動検証
- `valueRef.field.header` が有効な header name か (case-insensitive 重複チェック)
- `codeHintIndex` が `codeHints[]` のインデックスとして有効
- vitest の `describe.each(scenarios)` パターン

### 11.2 UI 単体テスト (`AttackStoryView.test.tsx`)

- ◄ ► ボタンの enabled/disabled (端での)
- dot クリックで `currentIndex` が変わる
- キーボード ← → Space Esc Home End の動作
- auto-play toggle で `setInterval` が走る (`vi.useFakeTimers`)
- `prefers-reduced-motion: reduce` 環境で auto-play default OFF
- aria-live のシーン切替アナウンス

### 11.3 visual variant 描画テスト (`AttackStoryScene.test.tsx`)

- `<AttackStoryScene>` を各 variant で render し、想定 DOM が出る
- `data-leak` variant: severity 別 CSS class 付与
- `code-defense` variant: 範囲ハイライト DOM 範囲

### 11.4 a11y 検証

- `role="region"` 存在
- `aria-current="step"` が現在シーンの dot のみに付く
- focus trap なし (region 外への tab 移動可能)
- 既存テスト基盤 (`@solidjs/testing-library` + `@testing-library/jest-dom`) 流用

### 11.5 snapshot テストは使わない方針

- visual variant は構造的、文字列は i18n 依存で変動
- assertion-based テストのほうが意図が明確

### 11.6 resolver ヘルパー単体テスト (`story-resolver.test.ts`)

- header lookup の case-insensitive 検証
- 不在パス → undefined
- 不正な field → undefined
- `body: null` の正しい扱い

---

## 12. i18n / a11y

### 12.1 i18n

- 既存 `useI18n().t(ja, en)` を継承
- scene 内 `speech.ja` / `speech.en` を直接読む (`t(scene.speech.ja, scene.speech.en)`)
- 共通文言 (◄/► ラベル, "Auto-play" 等) は AttackStoryControls 内で `t()` 呼び出し
- 想定文言一覧 (抜粋):

| 概念 | ja | en |
|---|---|---|
| 進む | 次のシーン | Next scene |
| 戻る | 前のシーン | Previous scene |
| dot ラベル | シーン {n} へ | Jump to scene {n} |
| auto-play ON | 自動再生中 | Auto-playing |
| auto-play OFF | 自動再生開始 | Start auto-play |
| シーン位置 | シーン {current} / {total} | Scene {current} of {total} |

### 12.2 a11y 必須事項 (再掲 + 追加)

- `prefers-reduced-motion` 尊重 (§6.3)
- キーボード操作完備 (§5.3)
- 全 emoji に `aria-hidden="true"` + 隣接ラベル (`aria-label`) でスクリーンリーダ向け代替テキスト
- 吹き出しの色相だけに依存しない (アバター内に actor 名テキストも含める)

---

## 13. ファイル配置

### 13.1 推奨配置 (新規ディレクトリは作らない)

```
src/components/shared/
├── AttackStoryView.tsx          ★新規
├── AttackStoryView.css          ★新規
├── AttackStoryScene.tsx         ★新規
├── AttackStoryScene.css         ★新規
├── AttackStoryControls.tsx      ★新規
├── AttackStoryControls.css      ★新規
├── StoryActorAvatar.tsx         ★新規 (内部用)
└── __tests__/
    ├── AttackStoryView.test.tsx ★新規
    └── AttackStoryScene.test.tsx ★新規

src/utils/
├── story-resolver.ts            ★新規
└── __tests__/
    └── story-resolver.test.ts   ★新規

shared/
└── api-types.ts                 既存に AttackStoryScene 等を追加

src/components/auth/attacks/scenarios/
└── mfa-scenarios.ts             既存の mfa-otp-replay に story 追加

src/components/shared/
└── AttackPanel.tsx              既存。§4.2 の統合レイアウトを反映
```

### 13.2 案比較

| 案 | 配置 | 採否 |
|---|---|---|
| A | **`src/components/shared/` にフラット展開 (上記)** | **採用**: 既存 AttackPanel 兄弟と並ぶ自然な配置 |
| B | `src/components/shared/storyboard/` 新規ディレクトリ | △ 既存パターン (フラット展開) と不一致 |
| C | `src/components/auth/attacks/storyboard/` (auth 配下) | × 共有コンポーネントとして他 view で再利用不能 |

---

## 14. 既存 DESIGN/33 (RawHttpComposer / SequenceDiagram) との関係

### 14.1 棲み分け

| 観点 | DESIGN/33 | DESIGN/35 (本仕様) |
|---|---|---|
| 対象モード | live のみ | live + narration 両モード |
| 焦点 | raw HTTP の編集と網目図 | 攻撃の物語進行 |
| 主役 | byte / arrow | actor / scene |
| 依存 | rawExchange 必須 | rawExchange optional |
| ユーザ操作 | 編集 + 送信 | ◄ ► / auto-play / dot ジャンプ |

両者は補完関係:

- **SequenceDiagramView**: 「機械的な事実」(byte 単位の HTTP exchange)
- **AttackStoryView**: 「物語的な解釈」(誰が・何を・どう奪取したか)

`AttackStoryVisual.type === "sequence-arrow"` は SequenceDiagramView の簡易再表現 (依存しない、独自 SVG 1 本)。

### 14.2 DESIGN/33 への変更必要性

- AttackPanel の統合レイアウト (§4.2) は DESIGN/33 §4.2 と矛盾しない (story パネルが追加されるだけ)
- DESIGN/33 §1.3 の「既存コンポーネントとの統合方針」表に「`AttackStoryView` 共存」の 1 行追加が必要 (本 PR スコープ)

### 14.3 DESIGN/35 の独立性

- 本仕様は DESIGN/33 を前提としない (narration シナリオでも動く)
- DESIGN/02 (UI spec) のコンポーネント仕様スタイルを継承
- DESIGN/04 (safety guardrails) の「明示」「防御策併記」原則を継承 (story 末尾に防御発動シーンを必須化する規約 §8.3)

---

## 15. オープン課題 (実装中に決めること)

| # | 課題 | 影響 | 推奨アプローチ |
|---|---|---|---|
| O1 | `AttackResultBanner` を story 最終シーンに統合するか、別表示で残すか | UI 重複の可能性 | 残す (story 終了後に表示)。banner=機械的事実、story=物語表現で役割分担 |
| O2 | story が `outcome === "error"` の attackResult のときどう挙動するか | error 時の物語が不在 | 専用 visual `type: "error"` を Phase 3 で追加。Phase 1 では story 非表示 + AttackStepTimeline 表示にフォールバック |
| O3 | `data-leak` の `severity: critical` で audio cue を入れるか | a11y / 体験 | 入れない (silent 原則)。視覚的 pulse のみ |
| O4 | dot indicator の最大数 (10 シーン超のシナリオ対応) | UI overflow | 8 dot で省略表示 (`... 5/12 ...`)。Phase 1 では §8.1 の 7 シーン推奨で運用 |
| O5 | story データが大きくなった場合の lazy loading | bundle サイズ | Phase 3 で再評価。Phase 1 は同期 import で問題なし (1 シナリオ < 5KB) |
| O6 | story 内で `attackResult.steps[]` を refer したいケース | データ重複 | `RawExchangeRef` を拡張し `{ source: "attackStep"; stepId: string; field: ... }` を Phase 3 で追加 |
| O7 | i18n が ja/en 以外に拡張された場合 | 文言データ構造 | 既存 `t()` ヘルパーが lang 配列対応済み、本仕様は影響なし |
| O8 | `narrator` actor のデザイン (擬人化しないキャラ) | キャラ表現の一貫性 | アバターを「📢」マイクアイコンに、`speech` ではなく必ず `narration` フィールドを使う規約 |
| O9 | story preview (シナリオ選択前にホバーで一覧表示) | UX 拡張 | Phase 3 で検討。Phase 1 は実行後のみ表示 |
| O10 | スマホ縦持ち時のレイアウト | レスポンシブ | アバター + 吹き出しを縦積み、controls をボトムバー化。CSS Grid で対応 |
| O11 | narration 型シナリオ (C/D 群 15 件) への波及 visual variant | DESIGN/35 v2 範囲 | Phase 3 完了後に再評価。`narration-only` variant を追加して story を narration にも使えるようにするか検討 |

---

## 付録 A. 主要ファイル参照 (実装着手用)

### 中核ファイル (絶対パス)

- `shared/api-types.ts` — 型追加
- `src/components/shared/AttackPanel.tsx` — 統合レイアウト変更
- `src/components/shared/AttackStepTimeline.tsx` — 折りたたみ化
- `src/components/auth/attacks/scenarios/mfa-scenarios.ts` — mfa-otp-replay に story 追加
- `DESIGN/33-raw-http-composer.md` — §1.3 表に 1 行追加

### 参照ファイル (パターン継承)

- `src/components/shared/SequenceDiagramView.tsx` — raw exchange 参照パターン
- `src/components/shared/StepControl.tsx` — controls の DNA
- `src/i18n/context.tsx` — `t()` ヘルパー
- `src/app.css` — CSS 変数 (`--color-attack-accent` 等)

---

## 改訂履歴

| 日付 | 改訂内容 | 担当 |
|---|---|---|
| 2026-05-10 | 初版 (Plan agent ベースで起草、Phase 2 PR-4 = mfa-otp-replay live 化と同時着手) | Claude Opus 4.7 |
