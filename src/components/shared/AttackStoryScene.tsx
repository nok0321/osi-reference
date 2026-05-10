/**
 * AttackStoryScene (DESIGN/35 §3.3) — 紙芝居の 1 シーン描画。
 *
 * 構成: タイトル → アクター + 吹き出し → ビジュアル (variant 別) → ナレーション。
 * 各 visual は `<Switch><Match>` で分岐し、raw exchange 不在時は label + "—" にフォールバック。
 */
import { Show, Switch, Match, For, createMemo } from "solid-js";
import { Motion } from "solid-motionone";
import { useI18n } from "../../i18n/context";
import StoryActorAvatar from "./StoryActorAvatar";
import { resolveRawRef } from "../../utils/story-resolver";
import type {
  AttackStoryScene,
  AttackStoryActor,
  AttackStoryVisual,
  RawExchange,
} from "../../../shared/api-types";
import "./AttackStoryScene.css";

interface AttackStorySceneProps {
  scene: AttackStoryScene;
  rawExchange?: RawExchange | null;
  /** code-defense visual で参照する codeHints (シナリオ単位)。 */
  codeHints?: { lang: string; label: string; code: string }[];
  /** visible actors (highlight 計算用)。空配列なら全アクター候補をデフォルト表示。 */
  visibleActors?: AttackStoryActor[];
}

const ALL_ACTORS_ORDER: AttackStoryActor[] = [
  "attacker",
  "system",
  "server",
  "victim-srv",
  "victim",
  "narrator",
];

export default function AttackStoryScene(props: AttackStorySceneProps) {
  const { t } = useI18n();

  const actorsToShow = createMemo<AttackStoryActor[]>(() => {
    const set = new Set<AttackStoryActor>();
    set.add(props.scene.actor);
    for (const a of props.scene.highlightActors ?? []) set.add(a);
    if (props.visibleActors) {
      for (const a of props.visibleActors) set.add(a);
    }
    return ALL_ACTORS_ORDER.filter((a) => set.has(a));
  });

  const isActive = (actor: AttackStoryActor) =>
    actor === props.scene.actor ||
    (props.scene.highlightActors ?? []).includes(actor);

  return (
    <Motion
      class="story-scene"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.2, easing: "ease-out" }}
    >
      <div class="story-scene-title-row">
        <h4 class="story-scene-title">
          {t(props.scene.titleJa, props.scene.title)}
        </h4>
      </div>

      {/* アクター列 + 主役の吹き出し */}
      <div class="story-scene-actors">
        <For each={actorsToShow()}>
          {(a) => (
            <div
              class="story-scene-actor-cell"
              data-active={isActive(a) ? "true" : "false"}
              data-primary={a === props.scene.actor ? "true" : "false"}
            >
              <StoryActorAvatar actor={a} active={isActive(a)} />
              <Show when={a === props.scene.actor && props.scene.speech}>
                <div
                  class="story-scene-speech-bubble"
                  data-actor={a}
                  role="note"
                >
                  {t(props.scene.speech!.ja, props.scene.speech!.en)}
                </div>
              </Show>
            </div>
          )}
        </For>
      </div>

      {/* 中央ビジュアル */}
      <Show when={props.scene.visual}>
        <div class="story-scene-visual">
          <SceneVisual
            visual={props.scene.visual!}
            rawExchange={props.rawExchange ?? null}
            codeHints={props.codeHints}
          />
        </div>
      </Show>

      {/* 第三者ナレーション */}
      <Show when={props.scene.narration}>
        <p class="story-scene-narration">
          {t(props.scene.narration!.ja, props.scene.narration!.en)}
        </p>
      </Show>
    </Motion>
  );
}

interface SceneVisualProps {
  visual: AttackStoryVisual;
  rawExchange: RawExchange | null;
  codeHints?: { lang: string; label: string; code: string }[];
}

function SceneVisual(props: SceneVisualProps) {
  return (
    <Switch>
      <Match when={props.visual.type === "http-request" || props.visual.type === "http-response"}>
        <HttpVisual
          visual={props.visual as Extract<AttackStoryVisual, { type: "http-request" | "http-response" }>}
          rawExchange={props.rawExchange}
        />
      </Match>

      <Match when={props.visual.type === "data-leak"}>
        <DataLeakVisual
          visual={props.visual as Extract<AttackStoryVisual, { type: "data-leak" }>}
          rawExchange={props.rawExchange}
        />
      </Match>

      <Match when={props.visual.type === "code-defense"}>
        <CodeDefenseVisual
          visual={props.visual as Extract<AttackStoryVisual, { type: "code-defense" }>}
          codeHints={props.codeHints}
        />
      </Match>

      <Match when={props.visual.type === "sequence-arrow"}>
        <SequenceArrowVisual
          visual={props.visual as Extract<AttackStoryVisual, { type: "sequence-arrow" }>}
        />
      </Match>

      <Match when={props.visual.type === "ascii"}>
        <pre class="story-visual-ascii">
          {(props.visual as Extract<AttackStoryVisual, { type: "ascii" }>).content}
        </pre>
      </Match>
    </Switch>
  );
}

function HttpVisual(props: {
  visual: Extract<AttackStoryVisual, { type: "http-request" | "http-response" }>;
  rawExchange: RawExchange | null;
}) {
  const { t } = useI18n();
  const lineRef = createMemo(() => ({
    ...props.visual.sourceRef,
    field: "line" as const,
  }));
  const bodyRef = createMemo(() => ({
    ...props.visual.sourceRef,
    field: "body" as const,
  }));

  const line = createMemo(() => resolveRawRef(lineRef(), props.rawExchange));
  const body = createMemo(() => resolveRawRef(bodyRef(), props.rawExchange));

  const isRequest = () => props.visual.type === "http-request";

  return (
    <div class="story-visual-http" data-kind={isRequest() ? "request" : "response"}>
      <div class="story-visual-http-label mono">
        {isRequest() ? t("HTTP リクエスト", "HTTP request") : t("HTTP レスポンス", "HTTP response")}
      </div>

      <Show when={line()} fallback={<div class="story-visual-http-fallback">—</div>}>
        <pre class="story-visual-http-line mono">{line()}</pre>
      </Show>

      <Show when={(props.visual.highlight ?? []).length > 0}>
        <div class="story-visual-http-highlights">
          <For each={props.visual.highlight}>
            {(h) => {
              const value = createMemo(() =>
                h.target === "header"
                  ? resolveRawRef(
                      { ...props.visual.sourceRef, field: { header: h.match } },
                      props.rawExchange,
                    )
                  : undefined,
              );
              return (
                <div class="story-visual-http-highlight" data-target={h.target}>
                  <span class="story-visual-http-highlight-label mono">
                    {h.target === "header" ? `${h.match}:` : h.match}
                  </span>
                  <Show when={h.target === "header"} fallback={null}>
                    <span class="story-visual-http-highlight-value mono">{value() ?? "—"}</span>
                  </Show>
                  <Show when={h.tooltipJa || h.tooltip}>
                    <span class="story-visual-http-highlight-tip">
                      {t(h.tooltipJa ?? "", h.tooltip ?? "")}
                    </span>
                  </Show>
                </div>
              );
            }}
          </For>
        </div>
      </Show>

      <Show when={body()}>
        <details class="story-visual-http-body">
          <summary class="story-visual-http-body-summary">
            {t("ボディを表示", "Show body")}
          </summary>
          <pre class="story-visual-http-body-content mono">{body()}</pre>
        </details>
      </Show>
    </div>
  );
}

function DataLeakVisual(props: {
  visual: Extract<AttackStoryVisual, { type: "data-leak" }>;
  rawExchange: RawExchange | null;
}) {
  const { t } = useI18n();
  const value = createMemo(() => resolveRawRef(props.visual.valueRef, props.rawExchange));

  return (
    <div
      class="story-visual-data-leak"
      data-severity={props.visual.severity ?? "info"}
      role="alert"
    >
      <div class="story-visual-data-leak-label">
        {t(props.visual.labelJa, props.visual.label)}
      </div>
      <div class="story-visual-data-leak-value mono">
        {value() ?? "—"}
      </div>
      <Show when={!value()}>
        <div class="story-visual-data-leak-fallback">
          {t("値が解決できませんでした (rawExchange 不在)", "Value unresolved (rawExchange missing)")}
        </div>
      </Show>
    </div>
  );
}

function CodeDefenseVisual(props: {
  visual: Extract<AttackStoryVisual, { type: "code-defense" }>;
  codeHints?: { lang: string; label: string; code: string }[];
}) {
  const { t } = useI18n();
  const hint = createMemo(() => props.codeHints?.[props.visual.codeHintIndex]);
  const lines = createMemo(() => (hint()?.code ?? "").split("\n"));
  const hiRange = createMemo<[number, number]>(
    () => props.visual.lineHighlight ?? [-1, -1],
  );

  return (
    <Show
      when={hint()}
      fallback={
        <div class="story-visual-code-defense-empty">
          {t("対応する codeHint が見つかりません", "Corresponding codeHint not found")}
        </div>
      }
    >
      <div class="story-visual-code-defense">
        <div class="story-visual-code-defense-label mono">
          {hint()!.label}
          <span class="story-visual-code-defense-lang">[{hint()!.lang}]</span>
        </div>
        <pre class="story-visual-code-defense-code mono">
          <For each={lines()}>
            {(line, i) => {
              const [s, e] = hiRange();
              const isHi = s >= 0 && i() >= s && i() <= e;
              return (
                <div class="story-visual-code-defense-line" data-highlight={isHi ? "true" : "false"}>
                  <span class="story-visual-code-defense-line-num">{(i() + 1).toString().padStart(2, " ")}</span>
                  <span class="story-visual-code-defense-line-text">{line}</span>
                </div>
              );
            }}
          </For>
        </pre>
      </div>
    </Show>
  );
}

function SequenceArrowVisual(props: {
  visual: Extract<AttackStoryVisual, { type: "sequence-arrow" }>;
}) {
  const { t } = useI18n();
  return (
    <div
      class="story-visual-sequence-arrow"
      data-direction={props.visual.direction}
    >
      <StoryActorAvatar actor={props.visual.from} active />
      <div class="story-visual-sequence-arrow-line">
        <span class="story-visual-sequence-arrow-label mono">
          {t(props.visual.labelJa, props.visual.label)}
        </span>
        <span class="story-visual-sequence-arrow-shaft" aria-hidden="true">
          {props.visual.direction === "request" ? "──────►" : "◄──────"}
        </span>
      </div>
      <StoryActorAvatar actor={props.visual.to} />
    </div>
  );
}
