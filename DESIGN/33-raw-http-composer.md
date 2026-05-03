---
title: 攻撃デモカタログ — RawHttpComposer / SequenceDiagram UI 仕様
phase: design
audience: フロントエンド開発者・UI レビュアー
last-updated: 2026-05-02
safety-reviewed: false
---

# 33. RawHttpComposer / SequenceDiagram UI 仕様

## 1. 目的とスコープ

### 1.1 概要

本仕様は `AttackPanel` を `mode: "live"` シナリオ向けに拡張するための新規 2 コンポーネントと、
既存コンポーネントへの変更点を定義する。
学習者が生 HTTP リクエストを自ら編集し、Docker 隔離された victim コンテナと実通信することで、
「攻撃者がどのリクエストを組み立てるか」を体感できる UI を提供する。

教育目的の範囲内に留まるため、DESIGN/04 の 4 原則 (隔離・明示・簡略化・防御策併記) は
ナレーション型と同等以上の強度で維持する。

### 1.2 新規コンポーネント

| コンポーネント | ファイルパス | 役割 |
|---|---|---|
| `RawHttpComposer` | `src/components/shared/RawHttpComposer.tsx` | 生 HTTP リクエスト編集 UI。target・method・path・headers・body を組み立てて orchestrator に送信 |
| `SequenceDiagramView` | `src/components/shared/SequenceDiagramView.tsx` | Browser / Orchestrator / Victim の 3 アクター間シーケンス図を D3 SVG で描画 |

### 1.3 既存コンポーネントとの統合方針

- `EducationalWarningBanner`: `mode: "live"` 選択時に右端へ `LIVE` バッジを追加 (子要素追加のみ)
- `AttackScenarioSelector`: 各シナリオ名右側に `[LIVE]` / `[NARRATION]` バッジを追加
- `AttackPanel`: `meta.mode` を読んで `RawHttpComposer` / 既存実行ボタン を排他表示
- `DataFlowPanel`: 4 番目のタブ "Sequence" を追加し `SequenceDiagramView` を内包
- ~~`AttackStepTimeline`: `mode: "live"` では orchestrator レスポンスの `rawExchange` から steps を生成~~ → **PR-1 で obsolete**: orchestrator が live 経路でも probe/exploit|blocked/verify の 3 ステップを生成し `result.steps[]` に詰めて返すため、フロント派生は冗長。raw bytes の視覚化は `SequenceDiagramView` が担当する。詳細は §4.1 参照。
- `AttackResultBanner` / `AttackDefensePanel`: 変更なし (両モード共通)

---

## 2. `RawHttpComposer` コンポーネント

### 2.1 配置

- ファイル: `src/components/shared/RawHttpComposer.tsx`
- CSS: `src/components/shared/RawHttpComposer.css`
- `AttackPanel` 内: `AttackScenarioSelector` の直下、既存実行ボタンの代替として配置
- `<Show when={props.meta?.mode === "live"}>` で囲み、`mode !== "live"` のときは非表示

### 2.2 視覚レイアウト (ASCII)

```
┌─ RawHttpComposer ─────────────────────────────────────────────────────┐
│  Target: [victim-web ▼]                           [LIVE]              │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │  Method: [POST ▼]   Path: [/jwt/verify                       ]  │  │
│  ├──────────────────────────────────────────────────────────────────┤  │
│  │  [Headers]  [Body]  [Raw]        ← タブ                          │  │
│  │                                                                   │  │
│  │  ┌── Headers タブ ──────────────────────────────────────────┐   │  │
│  │  │  Host:          [victim-web:4001 (orchestrator が設定)]  │   │  │
│  │  │                  ← disabled / opacity: 0.6               │   │  │
│  │  │  Content-Type:  [application/json                    ] [×] │  │
│  │  │  [+ ヘッダを追加]                                         │   │  │
│  │  └──────────────────────────────────────────────────────────┘   │  │
│  │  (jwt-alg-none: token は Body タブの JSON body 内に配置。         │  │
│  │   Authorization ヘッダではなく {"token": "<偽造 JWT>"} を送信)  │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                        │
│  [SEND ATTACK]                         ← background: --color-attack-accent │
└────────────────────────────────────────────────────────────────────────┘
```

**Body タブ:**
```
│  ┌── Body タブ ─────────────────────────────────────────────────┐   │  │
│  │  <textarea rows="6" spellcheck="false" font-family: mono>   │   │  │
│  │  {                                                           │   │  │
│  │    "token": "eyJhbGciOiJub25lIn0.eyJzdWIiOiJzZWVkX2FsaWNlIn0."  │   │  │
│  │  }  ← jwt-alg-none: alg=none + 空署名の偽造 JWT を body で送信   │   │  │
│  └──────────────────────────────────────────────────────────────┘   │  │
```

**Raw タブ (編集不可):**
```
│  ┌── Raw タブ ──────────────────────────────────────────────────┐   │  │
│  │  POST /jwt/verify HTTP/1.1                                   │   │  │
│  │  Host: victim-web:4001                                       │   │  │
│  │  Content-Type: application/json                              │   │  │
│  │                                                              │   │  │
│  │  {"token":"eyJhbGciOiJub25lIn0.eyJzdWIiOiJzZWVkX2FsaWNlIn0."}  │   │  │
│  │                            ← readonly, cursor: default       │   │  │
│  └──────────────────────────────────────────────────────────────┘   │  │
```

### 2.3 Props および内部 State

```typescript
// shared/api-types.ts からの再利用型
import type { OrchestratorExecRequest, OrchestratorExecResponse, VictimTarget } from "../../../shared/api-types";

type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

interface RawHttpComposerProps {
  scenarioId: string;
  /** VICTIM_ALLOWLIST 由来のターゲット一覧 (orchestrator から取得済み) (`VictimTarget` は string リテラル union — DESIGN/31 §5.1) */
  allowedTargets: VictimTarget[];
  /** シナリオ固有の初期値テンプレート。未指定なら空リクエスト */
  templateRequest?: {
    method: HttpMethod;
    path: string;
    headers: Record<string, string>;
    body?: string;
  };
  /** 送信コールバック。AttackPanel の handleRunAttack から呼ばれる */
  onSend: (
    request: OrchestratorExecRequest["request"]
  ) => Promise<OrchestratorExecResponse>;
}
```

**内部 Signal 一覧:**

```typescript
// RawHttpComposer 内部 (コンポーネント本体)
const [target, setTarget] = createSignal<string>(
  props.allowedTargets[0] ?? "victim-web"
);
const [method, setMethod] = createSignal<HttpMethod>(
  props.templateRequest?.method ?? "GET"
);
const [path, setPath] = createSignal<string>(
  props.templateRequest?.path ?? "/"
);
// key-value ペアの配列 (Host は含まない — orchestrator が上書き)
const [headers, setHeaders] = createSignal<{ key: string; value: string }[]>(
  Object.entries(props.templateRequest?.headers ?? {})
    .filter(([k]) => k.toLowerCase() !== "host")
    .map(([key, value]) => ({ key, value }))
);
const [body, setBody] = createSignal<string>(
  props.templateRequest?.body ?? ""
);
const [activeTab, setActiveTab] = createSignal<"headers" | "body" | "raw">(
  "headers"
);
const [sending, setSending] = createSignal(false);
```

**rawText 派生値 (Raw タブ用):**

```typescript
const rawText = () => {
  const reqHeaders = [
    `Host: victim-web:4001`,   // orchestrator 決定値を表示
    ...headers().map((h) => `${h.key}: ${h.value}`),
  ].join("\r\n");
  const bodyStr = body().trim();
  return [
    `${method()} ${path()} HTTP/1.1`,
    reqHeaders,
    "",
    bodyStr,
  ].join("\r\n");
};
```

### 2.4 安全制約 (DESIGN/04 §1.1 強化)

| 制約 | 実装方法 |
|---|---|
| **target は dropdown 選択のみ** | `<select>` に `props.allowedTargets` を `<For>` で列挙。自由入力フィールドなし |
| **Host ヘッダ編集不可** | `<input disabled>` + `opacity: 0.6` + `cursor: not-allowed`。テキスト: `orchestrator が victim-web:4001 に設定` |
| **export / copy / download ボタンなし** | Raw タブは `<textarea readonly>` の表示のみ。クリップボード API 呼び出し禁止 |
| **localStorage / sessionStorage 書き込みなし** | 全状態は Signal のみ。ページリロードで `templateRequest` に戻る |
| **`console.log` 出力なし** | DESIGN/04 §7.1 準拠。全可視化は DataFlowPanel 経由 |

### 2.5 視覚デザイン (PCB テーマ準拠)

```css
/* RawHttpComposer.css */

.raw-http-composer {
  border: 1px solid var(--color-attack-accent);   /* 赤縁: 攻撃モード明示 */
  border-radius: var(--radius-md);
  background: var(--bg-card);
  padding: 1rem;
  position: relative;
}

/* 右上 LIVE バッジ */
.raw-http-composer-live-badge {
  position: absolute;
  top: 0.5rem;
  right: 0.75rem;
  background: var(--color-attack-bg);
  color: var(--color-attack-accent);
  border: 1px solid var(--color-attack-accent);
  border-radius: var(--radius-sm);
  font-family: var(--font-mono);
  font-size: 0.65rem;
  font-weight: 700;
  padding: 2px 6px;
  letter-spacing: 0.05em;
}

/* Target + Method + Path 行 */
.raw-http-composer-topbar {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 0.75rem;
  font-family: var(--font-mono);
  font-size: 0.8rem;
}

.raw-http-composer-topbar select,
.raw-http-composer-topbar input {
  font-family: var(--font-mono);
  background: var(--bg-secondary);
  color: var(--text-primary);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-sm);
  padding: 3px 6px;
}

/* 内部タブ */
.raw-http-composer-tabs {
  display: flex;
  gap: 0;
  border-bottom: 1px solid var(--border-subtle);
  margin-bottom: 0.5rem;
}

.raw-http-composer-tab {
  font-family: var(--font-mono);
  font-size: 0.7rem;
  padding: 4px 10px;
  background: none;
  border: none;
  color: var(--text-muted);
  cursor: pointer;
  border-bottom: 2px solid transparent;
}

.raw-http-composer-tab[data-active="true"] {
  color: var(--color-attack-accent);
  border-bottom-color: var(--color-attack-accent);
}

/* 編集不可フィールド */
.raw-http-composer-disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

/* SEND ボタン */
.raw-http-composer-send {
  margin-top: 0.75rem;
  background: var(--color-attack-accent);
  color: #fff;
  border: none;
  border-radius: var(--radius-sm);
  font-family: var(--font-mono);
  font-size: 0.8rem;
  font-weight: 700;
  padding: 6px 16px;
  cursor: pointer;
  transition: transform var(--transition-fast);
}

.raw-http-composer-send:hover:not(:disabled) {
  transform: scale(1.02);
}

.raw-http-composer-send:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
```

### 2.6 a11y

```typescript
// RawHttpComposer.tsx の JSX 抜粋 (Solid.js 必須ルール準拠)

// target dropdown
<label for="rhc-target">{t("送信先", "Target")}</label>
<select
  id="rhc-target"
  value={target()}
  onChange={(e) => setTarget(e.currentTarget.value)}
  aria-label={t("攻撃対象の victim を選択", "Select attack target")}
>
  <For each={props.allowedTargets}>
    {(tgt) => <option value={tgt}>{tgt}</option>}
  </For>
</select>

// target 変更時の aria-live アナウンス
<div aria-live="polite" class="sr-only">
  <Show when={target()}>
    {t(
      `送信先が ${target()} に変更されました`,
      `Target changed to ${target()}`
    )}
  </Show>
</div>

// SEND ボタン
<button
  class="raw-http-composer-send"
  disabled={sending() || props.allowedTargets.length === 0}
  aria-busy={sending()}
  aria-describedby="rhc-send-desc"
  onClick={handleSend}
>
  <Show when={sending()} fallback={t("送信", "Send Attack")}>
    {t("送信中...", "Sending...")}
  </Show>
</button>
<span id="rhc-send-desc" class="sr-only">
  {t(
    "実際の HTTP リクエストを victim コンテナに送信します",
    "Sends a real HTTP request to the victim container"
  )}
</span>

// Host ヘッダ (disabled)
<label for="rhc-host-header">{t("Host ヘッダ", "Host header")}</label>
<input
  id="rhc-host-header"
  class="raw-http-composer-disabled"
  disabled
  value={t("victim-web:4001 (orchestrator が設定)", "victim-web:4001 (set by orchestrator)")}
  aria-label={t("Host ヘッダは orchestrator が強制設定します", "Host header is overridden by orchestrator")}
/>
```

フォーカスリングは `app.css` の `:focus-visible` ルール (既存) が自動適用される。

### 2.7 i18n 文言一覧

| 概念 | 日本語 | English |
|---|---|---|
| 送信先ラベル | `送信先` | `Target` |
| メソッドラベル | `メソッド` | `Method` |
| パスラベル | `パス` | `Path` |
| ヘッダタブ | `ヘッダー` | `Headers` |
| ボディタブ | `ボディ` | `Body` |
| Raw タブ | `Raw` | `Raw` |
| ヘッダ追加ボタン | `+ ヘッダを追加` | `+ Add header` |
| ヘッダ削除 | `削除` | `Remove` |
| 送信ボタン | `送信` | `Send Attack` |
| 送信中 | `送信中...` | `Sending...` |
| LIVE バッジ | `LIVE 攻撃モード` | `LIVE attack mode` |
| Host 無効説明 | `orchestrator が victim-web:4001 に設定` | `set by orchestrator` |
| target 変更告知 | `送信先が ${x} に変更されました` | `Target changed to ${x}` |

---

## 3. `SequenceDiagramView` コンポーネント

### 3.1 配置

- ファイル: `src/components/shared/SequenceDiagramView.tsx`
- CSS: `src/components/shared/SequenceDiagramView.css`
- `DataFlowPanel` 内の 4 番目のタブ `"Sequence"` に格納
- タブ一覧: `HTTP` / `Trace` / `DB` / `Sequence`
- `mode: "live"` のときのみ Sequence タブを表示 (`<Show when={isLiveMode()}>`)

### 3.2 描画方針

D3 ベースの自前 SVG を採用する (Mermaid は bundle 増加・テーマ統一性の問題がある)。
CLAUDE.md の「D3 + Solid 統合パターン」を厳守する。

```typescript
// SequenceDiagramView.tsx の骨格
import { onMount, onCleanup, createEffect } from "solid-js";
import * as d3 from "d3";

function SequenceDiagramView(props: SequenceDiagramViewProps) {
  let svgRef: SVGSVGElement | undefined;

  // D3 初期化は onMount のみ (コンポーネント関数は 1 回だけ実行)
  onMount(() => {
    const svg = d3.select(svgRef!);
    initDiagram(svg);
  });

  // exchange 変更を監視して D3 transition をトリガー
  createEffect(() => {
    const ex = props.exchange;
    if (!svgRef || !ex) return;
    const svg = d3.select(svgRef!);
    updateArrows(svg, ex);  // 400ms transition
  });

  // トランジションキャンセル (コンポーネント破棄時)
  onCleanup(() => {
    if (svgRef) {
      d3.select(svgRef!).selectAll("*").interrupt();
    }
  });

  return (
    <div class="sequence-diagram-view">
      <svg ref={svgRef} class="sequence-diagram-svg" aria-label={/* ... */} />
      {/* popup は Solid で管理: D3 が管理する SVG 内部に Solid は介入しない */}
      <Show when={popupArrow() !== null}>
        <RawBytesPopup arrow={popupArrow()!} onClose={() => setPopupArrow(null)} />
      </Show>
    </div>
  );
}
```

D3 が管理する SVG 内部には Solid の JSX を挿入しない。
クリック popup は SVG 外の `<Show>` コンポーネントで管理する。

### 3.3 視覚レイアウト (ASCII)

3 アクター (Browser, Orchestrator, Victim) のスイムレーン:

```
  Browser              Orchestrator              Victim (victim-web)
    │                      │                          │
    │                      │                          │
  ──●──────────────────────●──────────────────────────●──   ← ライフライン
    │                      │                          │
    │── POST /api/exec ───▶│                          │       (→ 400ms)
    │                      │── POST /jwt/verify ─────▶│       (→ 400ms)
    │                      │                          │ [脆弱: alg=none 受理]
    │                      │◀── 200 OK ───────────────│       (← 400ms, 青)
    │◀── AttackResult ─────│                          │       (← 400ms, 青)
    │                      │                          │
    [矢印クリック] → RawBytesPopup (request/response raw bytes)
```

**凡例:**

| 表示 | 意味 |
|---|---|
| 橙色矢印 (→) | リクエスト方向 (Browser→Orchestrator, Orchestrator→Victim) |
| 青色矢印 (←) | レスポンス方向 |
| `[脆弱: ...]` ラベル | victim 応答の横注釈 (成功時は橙、ブロック時は緑) |
| クリック可能矢印 | `cursor: pointer`, hover で `stroke-width` を 3 に変化 |

### 3.4 Props

```typescript
interface RawArrow {
  from: "browser" | "orchestrator" | "victim";
  to: "browser" | "orchestrator" | "victim";
  label: string;         // "POST /jwt/verify HTTP/1.1" など
  direction: "request" | "response";
  rawBytes: string;      // クリック popup で表示する生テキスト
  elapsedMs?: number;
}

interface SequenceDiagramViewProps {
  /** orchestrator レスポンスの rawExchange をそのまま渡す */
  exchange: OrchestratorExecResponse["rawExchange"];
  scenarioId: string;
}
```

内部で `exchange` から `RawArrow[]` を派生させ、D3 に渡す:

```typescript
/**
 * RawExchange の階層構造からシーケンス図用の平坦なフィールドを導出するヘルパー。
 * RawExchange 構造: { browserToOrchestrator: { request, response }, orchestratorToVictim: { request, response, targetResolvedTo }, elapsedMs }
 */
function deriveArrows(ex: RawExchange): RawArrow[] {
  const b2o = ex.browserToOrchestrator;
  const o2v = ex.orchestratorToVictim;

  // orchestrator→victim リクエスト行から method と path を分割
  // 例: "POST /jwt/verify HTTP/1.1" → method="POST", path="/jwt/verify"
  const [victimMethod, victimPath] = o2v.request.line.split(" ");

  return [
    {
      from: "browser",
      to: "orchestrator",
      label: "POST /api/orchestrator/exec",
      direction: "request",
      rawBytes: [
        b2o.request.line,
        ...Object.entries(b2o.request.headers).map(([k, v]) => `${k}: ${v}`),
        "",
        b2o.request.body ?? "",
      ].join("\r\n"),
    },
    {
      from: "orchestrator",
      to: "victim",
      label: `${victimMethod} ${victimPath} HTTP/1.1`,
      direction: "request",
      rawBytes: [
        o2v.request.line,
        ...Object.entries(o2v.request.headers).map(([k, v]) => `${k}: ${v}`),
        "",
        o2v.request.body ?? "",
      ].join("\r\n"),
      elapsedMs: ex.elapsedMs,
    },
    {
      from: "victim",
      to: "orchestrator",
      label: o2v.response.line,
      direction: "response",
      rawBytes: [
        o2v.response.line,
        ...Object.entries(o2v.response.headers).map(([k, v]) => `${k}: ${v}`),
        "",
        o2v.response.body ?? "",
      ].join("\r\n"),
    },
    {
      from: "orchestrator",
      to: "browser",
      label: "AttackResult",
      direction: "response",
      rawBytes: [
        b2o.response.line,
        ...Object.entries(b2o.response.headers).map(([k, v]) => `${k}: ${v}`),
        "",
        b2o.response.body ?? "",
      ].join("\r\n"),
    },
  ];
}

const arrows = (): RawArrow[] => {
  const ex = props.exchange;
  if (!ex) return [];
  return deriveArrows(ex);
};
```

### 3.5 RawBytesPopup

矢印クリックで表示するモーダル (Solid JSX で管理):

```typescript
// SVG 外に配置
function RawBytesPopup(props: { arrow: RawArrow; onClose: () => void }) {
  const { t } = useI18n();
  return (
    <div
      class="raw-bytes-popup"
      role="dialog"
      aria-modal="true"
      aria-label={t("生バイト表示", "Raw bytes")}
    >
      <div class="raw-bytes-popup-header">
        <span class="raw-bytes-popup-title">{props.arrow.label}</span>
        <button
          class="raw-bytes-popup-close"
          aria-label={t("閉じる", "Close")}
          onClick={props.onClose}
        >
          [×]
        </button>
      </div>
      <pre class="raw-bytes-popup-body mono">{props.arrow.rawBytes}</pre>
    </div>
  );
}
```

### 3.6 アニメーション

```typescript
// D3 transition (solid-motionone は使わない)
function drawArrow(
  svg: d3.Selection<SVGSVGElement, unknown, null, undefined>,
  arrow: RawArrow,
  index: number,
  xMap: Record<string, number>,
  yBase: number
) {
  const y = yBase + index * 60;
  const fromX = xMap[arrow.from];
  const toX = xMap[arrow.to];
  const color = arrow.direction === "request" ? "var(--color-attack-accent)" : "#1677ff";

  const line = svg.append("line")
    .attr("class", "seq-arrow")
    .attr("x1", fromX)
    .attr("y1", y)
    .attr("x2", fromX)  // 初期値: 折れ点なし
    .attr("y2", y)
    .attr("stroke", color)
    .attr("stroke-width", 2)
    .attr("marker-end", `url(#arrow-${arrow.direction})`);

  // 400ms で fromX → toX
  line.transition()
    .duration(400)
    .ease(d3.easeLinear)
    .attr("x2", toX);
}

// onCleanup でキャンセル
onCleanup(() => {
  d3.select(svgRef!).selectAll("*").interrupt();
});
```

---

## 4. 既存 `AttackPanel` への統合

### 4.1 変更点

> **注 (PR-1 後 obsolete セクションの統合)**: 当初本仕様には「`AttackStepTimeline` に `liveSteps()` 派生値を追加し `rawExchange` から steps を生成する」という拡張を予定していたが、PR-1 (#14) の実装で `orchestrator-exec.ts` が live 経路でも probe/exploit|blocked/verify の 3 段ステップを `OrchestratorExecResponse.steps[]` に詰めて返す形になったため、フロント側での派生は冗長となった。`AttackStepTimeline` は両モードで `attackResult()?.steps ?? []` を受け取れば十分機能する。raw bytes の視覚化は `SequenceDiagramView` が独立して担当する。本セクションの下記 `AttackPanel` の変更点のみ有効。

`AttackPanel.tsx` に `mode` 判定を追加する。シナリオの `meta.mode` を参照して
`RawHttpComposer` / 既存実行ボタンを排他表示に切り替える。

```typescript
// AttackPanel.tsx への追加
const isLiveMode = () => selectedScenario()?.mode === "live";

async function handleLiveSend(
  request: OrchestratorExecRequest["request"]
): Promise<OrchestratorExecResponse> {
  setSending(true);
  setAttackResult(null);
  setDefenseOpen(false);
  try {
    const res = await apiPost<OrchestratorExecResponse>(
      "/api/orchestrator/exec",
      { scenarioId: selectedId(), target: target(), request },
      `attack-${props.tabId}`
    );
    setAttackResult(res);
    setRawExchange(res.rawExchange ?? null);  // SequenceDiagramView へ伝播
    return res;
  } finally {
    setSending(false);
  }
}

// `AttackPanel` は `target: Signal<VictimTarget>` を保持し、`RawHttpComposer` の dropdown 変更時に更新する
```

追加 Signal:

```typescript
const [rawExchange, setRawExchange] =
  createSignal<OrchestratorExecResponse["rawExchange"] | null>(null);
```

### 4.2 統合後のレイアウト構造

```
AttackPanel
├── EducationalWarningBanner           (常時表示 + live 時は LIVE バッジ付与)
├── AttackScenarioSelector             (常時表示 + 各シナリオに [LIVE]/[NARRATION] バッジ)
├── <Show when={isLiveMode()}>
│     RawHttpComposer                  ← NEW (live モードのみ)
│     onSend={handleLiveSend}
│   </Show>
├── <Show when={!isLiveMode()}>
│     <div class="attack-mode-labels"> (既存 mode ラベル)
│     <button class="attack-run-button"> (既存実行ボタン)
│   </Show>
├── AttackStepTimeline                 (両モード共通)
├── AttackResultBanner                 (両モード共通)
├── AttackDefensePanel                 (両モード共通、攻撃完了後自動展開)
└── DataFlowPanel                      (scopeId="attack-{tabId}")
    ├── HTTP タブ
    ├── Trace タブ
    ├── DB タブ
    └── <Show when={isLiveMode()}>
          Sequence タブ (SequenceDiagramView)
        </Show>
```

### 4.3 DataFlowPanel の Sequence タブ追加

`DataFlowPanel.tsx` の `tab` Signal に `"sequence"` を追加する:

```typescript
// DataFlowPanel.tsx 変更箇所
const [tab, setTab] = createSignal<"http" | "trace" | "db" | "sequence">("http");

// タブボタン追加
<Show when={props.isLiveMode}>
  <button
    class="data-flow-tab"
    role="tab"
    aria-selected={tab() === "sequence"}
    data-active={tab() === "sequence"}
    onClick={() => setTab("sequence")}
  >
    {t("シーケンス", "Sequence")}
  </button>
</Show>

// tabpanel 追加
<Show when={tab() === "sequence" && props.isLiveMode}>
  <SequenceDiagramView
    exchange={props.rawExchange}
    scenarioId={props.scopeId}
  />
</Show>
```

`DataFlowPanel` に追加される Props:

```typescript
interface DataFlowPanelProps {
  scopeId: string;
  defaultOpen?: boolean;
  // live モード拡張 (未指定時は false / undefined で既存挙動を維持)
  isLiveMode?: boolean;
  rawExchange?: OrchestratorExecResponse["rawExchange"] | null;
}
```

---

## 5. `mode: "live"` バッジ表示

### 5.1 EducationalWarningBanner への追加

`EducationalWarningBanner` に `mode` prop を追加し、`mode === "live"` 時に右端バッジを表示する。

```typescript
// EducationalWarningBanner.tsx 変更
interface EducationalWarningBannerProps {
  mode?: "live" | "narration";
}

function EducationalWarningBanner(props: EducationalWarningBannerProps) {
  const { t } = useI18n();
  return (
    <div class="edu-warning-banner" role="note" aria-live="polite"
      aria-label={t("教育用シミュレーション警告", "Educational simulation warning")}
    >
      <span class="edu-warning-icon" aria-hidden="true">⚠</span>
      <span class="edu-warning-text">
        {t(
          "教育用シミュレーション — 実環境を攻撃するためのコードではありません",
          "Educational simulation — not for use against real systems"
        )}
      </span>
      <Show when={props.mode === "live"}>
        <span
          class="edu-warning-live-badge"
          aria-label={t("LIVE 攻撃モード", "LIVE attack mode")}
        >
          LIVE
        </span>
      </Show>
    </div>
  );
}
```

**LIVE バッジ CSS:**

```css
.edu-warning-live-badge {
  margin-left: auto;
  background: var(--color-attack-bg);
  color: var(--color-attack-accent);
  border: 2px solid var(--color-attack-accent);
  border-radius: var(--radius-sm);
  font-family: var(--font-mono);
  font-size: 0.65rem;
  font-weight: 700;
  padding: 2px 8px;
  letter-spacing: 0.1em;
  flex-shrink: 0;
}
```

### 5.2 AttackScenarioSelector へのモードバッジ

各シナリオチップ右側に `[LIVE]` / `[NARRATION]` バッジを追加する:

```typescript
// AttackScenarioSelector.tsx のチップ JSX 内
<Show when={scenario.mode === "live"}>
  <span class="scenario-mode-badge" data-mode="live">LIVE</span>
</Show>
<Show when={scenario.mode === "narration"}>
  <span class="scenario-mode-badge" data-mode="narration">NARRATION</span>
</Show>
```

```css
.scenario-mode-badge[data-mode="live"] {
  background: var(--color-attack-bg);
  color: var(--color-attack-accent);
  border: 1px solid var(--color-attack-accent);
}

.scenario-mode-badge[data-mode="narration"] {
  background: var(--bg-secondary);
  color: var(--text-muted);
  border: 1px solid var(--border-subtle);
}
```

---

## 6. エラーハンドリング

### 6.1 orchestrator からのエラー応答

| HTTP ステータス | 原因 | UI 表示 |
|---|---|---|
| `502 Bad Gateway` | victim-web 未起動 | トースト: `t("victim-web が起動していません。docker compose up -d victim-web を実行してください", "victim-web is not running. Run: docker compose up -d victim-web")` + 「防御者モードに戻る」ボタン |
| `503 Service Unavailable` | `NODE_ENV === "production"` または Phase 未到達 | トースト: `t("このシナリオは現在の Phase では未実装です", "This scenario is not yet available in the current phase")` |
| `504 Gateway Timeout` | victim 応答タイムアウト | エラーバナー表示。自動リトライなし |
| `400 Bad Request` | 入力値検証失敗 | インラインエラー。どのフィールドが原因かを `errorField` で特定し対象フィールドに `border-color: var(--color-danger)` + エラーテキスト表示 |
| `403 Forbidden` | VICTIM_ALLOWLIST 違反 | インラインエラー: `t("この target は許可されていません", "Target is not in the allowlist")` |

### 6.2 トースト実装

```typescript
const [toastMessage, setToastMessage] = createSignal<string | null>(null);

// 502 ハンドリング例
if (res.status === 502) {
  setToastMessage(t(
    "victim-web が起動していません。docker compose up -d victim-web を実行してください",
    "victim-web is not running. Run: docker compose up -d victim-web"
  ));
}

// JSX
<Show when={toastMessage() !== null}>
  <div
    class="rhc-toast"
    role="alert"
    aria-live="assertive"
  >
    <span>{toastMessage()}</span>
    <button onClick={() => setToastMessage(null)} aria-label={t("閉じる", "Close")}>
      [×]
    </button>
  </div>
</Show>
```

---

## 7. 既存コンポーネントへの影響

| コンポーネント | 変更内容 | 影響度 |
|---|---|---|
| `AttackPanel.tsx` | `mode` 判定追加。`isLiveMode()` で `RawHttpComposer` / 既存ボタンを排他 `<Show>`。`rawExchange` Signal 追加 | 中 (条件分岐追加) |
| `EducationalWarningBanner.tsx` | `mode` prop 追加。`mode === "live"` 時の LIVE バッジ表示 | 小 (子要素追加のみ) |
| `AttackScenarioSelector.tsx` | `scenario.mode` を読んで `[LIVE]` / `[NARRATION]` バッジ表示 | 小 |
| `DataFlowPanel.tsx` | `tab` Signal に `"sequence"` 追加。`isLiveMode` / `rawExchange` prop 追加。Sequence タブボタン + `SequenceDiagramView` 表示 | 中 |
| ~~`AttackStepTimeline.tsx`~~ | ~~`mode: "live"` では orchestrator レスポンスの `rawExchange` から `steps[]` を変換する `liveSteps()` 派生値を追加~~ → **PR-1 後 obsolete**: orchestrator が steps を返すため不要 | なし |
| `AttackResultBanner.tsx` | 変更なし (両モードで `AttackResult` を受ける) | なし |
| `AttackDefensePanel.tsx` | 変更なし | なし |

---

## 8. テスト要件

- [ ] `RawHttpComposer` の target dropdown が `allowedTargets` 以外を選択不可
- [ ] `RawHttpComposer` の Host ヘッダ入力フィールドが `disabled` 属性を持ち操作できない
- [ ] headers Signal が `setHeaders(prev => [...prev, newHeader])` パターンで不変更新されている
- [ ] SEND ボタン押下で `onSend` が正しい payload `{ method, path, headers: Object, body }` で呼ばれる
- [ ] Raw タブのテキストエリアが `readonly` であり、クリップボード書き込みを行わない
- [ ] `localStorage.setItem` / `sessionStorage.setItem` が一切呼ばれないこと
- [ ] `SequenceDiagramView` が 3 アクター (Browser, Orchestrator, Victim) のライフラインを SVG に描画する
- [ ] `SequenceDiagramView` の矢印クリックで `RawBytesPopup` が表示され、`onClose` で閉じる
- [ ] `AttackPanel` で `mode === "live"` のとき `RawHttpComposer` が描画され、既存実行ボタンが描画されない
- [ ] `AttackPanel` で `mode === "narration"` のとき `RawHttpComposer` が描画されない
- [ ] `EducationalWarningBanner` の LIVE バッジが `mode === "live"` のときのみ表示される
- [ ] `DataFlowPanel` の Sequence タブが `isLiveMode === false` のとき非表示
- [ ] `orchestrator` から 502 を受け取ったときトーストが表示される
- [ ] `orchestrator` から 503 を受け取ったときフェーズ未実装トーストが表示される
- [ ] D3 transition が `onCleanup` で `interrupt()` キャンセルされる

---

## 9. Solid.js 規約準拠

本セクションは CLAUDE.md `## Solid.js 必須ルール` の要点を RawHttpComposer / SequenceDiagramView に
特化して確認するチェックリストである。

### 9.1 コンポーネント規約

- [ ] `props.scenarioId`, `props.allowedTargets` など props は常に `props.xxx` 形式でアクセスし、デストラクチャリングしない
- [ ] 関数コンポーネント内に早期 `return` を置かない。条件分岐は `<Show when={...}>` で代替
- [ ] コンポーネント関数内のトップレベルに副作用コードを書かない (副作用は `onMount` / `createEffect` / `onCleanup` のみ)

### 9.2 Signal 更新

```typescript
// OK: 新配列生成
setHeaders(prev => [...prev, { key: "", value: "" }]);
setHeaders(prev => prev.filter((_, i) => i !== removeIdx));

// NG: 直接ミューテーション (Signal が再評価されない)
// headers().push(...)
// headers()[idx].value = "..."
```

### 9.3 D3 + Solid 統合

```typescript
// OK: ref で SVG コンテナ取得 → onMount で D3 初期化
let svgRef: SVGSVGElement | undefined;
onMount(() => { d3.select(svgRef!).append("g"); });

// OK: createEffect で Signal 監視 → D3 transition
createEffect(() => { const ex = props.exchange; /* D3 update */ });

// OK: onCleanup でキャンセル
onCleanup(() => { d3.select(svgRef!).selectAll("*").interrupt(); });

// NG: D3 が管理する SVG 内部に Solid JSX を挿入
// <svg ref={svgRef}><circle class="solid-managed" /></svg>  ← 禁止
```

---

## 10. 関連ファイル

### 上流設計書

| ファイル | 関係 |
|---|---|
| `DESIGN/30-live-attack-architecture.md` | live 化全体設計・案 C ハイブリッド採用・コンテナ構成 |
| `DESIGN/31-orchestrator-spec.md` | `POST /api/orchestrator/exec` リクエスト/レスポンス型・VICTIM_ALLOWLIST 定義 |

### 同列設計書

| ファイル | 関係 |
|---|---|
| `DESIGN/32-victim-web-spec.md` | `RawHttpComposer` の target dropdown 候補先エンドポイント定義 |
| `DESIGN/34-safety-guardrails-live.md` | 本仕様の安全制約 (§2.4) の根拠・live 差分詳細 |

### 既存設計書 (フォーマット参照)

| ファイル | 関係 |
|---|---|
| `DESIGN/02-ui-spec.md` | コンポーネント仕様スタイル・ASCII レイアウト・a11y・CSS 変数の参照元 |
| `DESIGN/04-safety-guardrails.md` | 4 原則・禁止表現 §2.3・バナー要件の基盤 |

### 既存実装ファイル (拡張対象)

| ファイルパス | 変更内容 |
|---|---|
| `src/components/shared/AttackPanel.tsx` | `isLiveMode()` 追加、`RawHttpComposer` 組み込み、`rawExchange` Signal |
| `src/components/shared/EducationalWarningBanner.tsx` | `mode` prop + LIVE バッジ追加 |
| `src/components/shared/AttackScenarioSelector.tsx` | `[LIVE]` / `[NARRATION]` バッジ追加 |
| `src/components/shared/DataFlowPanel.tsx` | Sequence タブ + `isLiveMode` / `rawExchange` prop 追加 |
| `src/components/shared/AttackStepTimeline.tsx` | `liveSteps()` 派生値追加 |

### 新規作成ファイル (本仕様)

| ファイルパス | 役割 |
|---|---|
| `src/components/shared/RawHttpComposer.tsx` | リクエスト編集 UI コンポーネント |
| `src/components/shared/RawHttpComposer.css` | スコープ付きスタイル |
| `src/components/shared/SequenceDiagramView.tsx` | D3 SVG シーケンス図コンポーネント |
| `src/components/shared/SequenceDiagramView.css` | スコープ付きスタイル |

### i18n

| ファイルパス | 用途 |
|---|---|
| `src/i18n/context.tsx` | `t(ja, en)` ヘルパー。全文言はこれ経由で記述 |
