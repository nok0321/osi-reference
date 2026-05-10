/**
 * AttackStoryView (DESIGN/35 §3.3, §4) — 攻撃シナリオ紙芝居の統合コンテナ。
 *
 * - シーン状態管理 (currentIndex, autoPlay)
 * - キーボード操作 (← → Space Esc Home End)
 * - prefers-reduced-motion 尊重 (auto-play デフォルト OFF)
 * - aria-live="polite" でシーン切替アナウンス
 * - story 末尾シーン到達で auto-play 自動停止
 *
 * 親 (AttackPanel) は scenario.story を渡すだけ。codeHints と rawExchange は
 * code-defense / http-* / data-leak visual の解決に使われる (任意)。
 */
import {
  createSignal,
  createEffect,
  createMemo,
  onCleanup,
  onMount,
  Show,
} from "solid-js";
import { useI18n } from "../../i18n/context";
import AttackStoryScene from "./AttackStoryScene";
import AttackStoryControls from "./AttackStoryControls";
import type {
  AttackStoryScene as AttackStorySceneType,
  RawExchange,
} from "../../../shared/api-types";
import "./AttackStoryView.css";

interface AttackStoryViewProps {
  story: AttackStorySceneType[];
  /** live モードでの raw exchange。null/undefined でも動作 (visual がフォールバック) */
  rawExchange?: RawExchange | null;
  /** code-defense visual の解決に使う codeHints */
  codeHints?: { lang: string; label: string; code: string }[];
  /** auto-play デフォルト ms (props 未指定時 3000) */
  defaultDurationMs?: number;
  /** シナリオ切替時のリセットトリガ (id 等を渡す) */
  resetKey?: string | number;
}

export default function AttackStoryView(props: AttackStoryViewProps) {
  const { t } = useI18n();
  const [currentIndex, setCurrentIndex] = createSignal(0);
  const [autoPlay, setAutoPlay] = createSignal(false);

  let rootRef: HTMLDivElement | undefined;

  const total = createMemo(() => props.story.length);
  const currentScene = createMemo<AttackStorySceneType | undefined>(
    () => props.story[currentIndex()],
  );

  const defaultDuration = () => props.defaultDurationMs ?? 3000;

  function clampIndex(i: number): number {
    if (total() === 0) return 0;
    return Math.max(0, Math.min(total() - 1, i));
  }

  function goTo(i: number) {
    setCurrentIndex(clampIndex(i));
  }

  function next() {
    if (currentIndex() < total() - 1) {
      setCurrentIndex(currentIndex() + 1);
    }
  }

  function prev() {
    if (currentIndex() > 0) {
      setCurrentIndex(currentIndex() - 1);
    }
  }

  function toggleAutoPlay() {
    setAutoPlay(!autoPlay());
  }

  // resetKey 変更時に最初のシーンに戻す + auto-play 停止
  createEffect(() => {
    props.resetKey;
    setCurrentIndex(0);
    setAutoPlay(false);
  });

  // story が変わったとき currentIndex が範囲外なら 0 にリセット
  createEffect(() => {
    const len = total();
    if (currentIndex() >= len) {
      setCurrentIndex(0);
    }
  });

  // auto-play timer 管理
  createEffect(() => {
    if (!autoPlay()) return;
    const scene = currentScene();
    if (!scene) return;
    const ms = scene.durationMs ?? defaultDuration();
    const timer = window.setTimeout(() => {
      if (currentIndex() < total() - 1) {
        setCurrentIndex(currentIndex() + 1);
      } else {
        setAutoPlay(false); // 末尾到達で自動停止
      }
    }, ms);
    onCleanup(() => window.clearTimeout(timer));
  });

  // prefers-reduced-motion 検出 (auto-play default OFF)
  onMount(() => {
    if (typeof window === "undefined" || !window.matchMedia) return;
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    if (mq.matches) {
      setAutoPlay(false);
      rootRef?.classList.add("reduced-motion");
    }
  });

  // キーボード操作
  function handleKeyDown(e: KeyboardEvent) {
    switch (e.key) {
      case "ArrowRight":
      case " ":
      case "Space":
        e.preventDefault();
        if (autoPlay()) setAutoPlay(false);
        next();
        break;
      case "ArrowLeft":
        e.preventDefault();
        if (autoPlay()) setAutoPlay(false);
        prev();
        break;
      case "Escape":
        if (autoPlay()) {
          e.preventDefault();
          setAutoPlay(false);
        }
        break;
      case "Home":
        e.preventDefault();
        setAutoPlay(false);
        setCurrentIndex(0);
        break;
      case "End":
        e.preventDefault();
        setAutoPlay(false);
        setCurrentIndex(total() - 1);
        break;
    }
  }

  // dot ジャンプ等の手動操作で auto-play を一時停止
  function jump(i: number) {
    if (autoPlay()) setAutoPlay(false);
    goTo(i);
  }

  return (
    <div
      ref={rootRef}
      class="attack-story-view"
      role="region"
      aria-label={t("攻撃ストーリーボード", "Attack storyboard")}
      tabindex="0"
      onKeyDown={handleKeyDown}
    >
      <Show when={total() === 0}>
        <div class="attack-story-empty">
          {t("ストーリーが定義されていません", "No story defined for this scenario")}
        </div>
      </Show>

      <Show when={total() > 0 && currentScene()}>
        <div
          class="attack-story-live"
          aria-live="polite"
          aria-atomic="true"
        >
          {/* スクリーンリーダー向けのみ。視覚的には invisible */}
          <span class="attack-story-sr-only">
            {t(
              `シーン ${currentIndex() + 1} / ${total()}: ${currentScene()!.titleJa}`,
              `Scene ${currentIndex() + 1} of ${total()}: ${currentScene()!.title}`,
            )}
          </span>

          <AttackStoryScene
            scene={currentScene()!}
            rawExchange={props.rawExchange}
            codeHints={props.codeHints}
          />
        </div>

        <AttackStoryControls
          current={currentIndex()}
          total={total()}
          autoPlay={autoPlay()}
          onPrev={() => {
            if (autoPlay()) setAutoPlay(false);
            prev();
          }}
          onNext={() => {
            if (autoPlay()) setAutoPlay(false);
            next();
          }}
          onJump={jump}
          onToggleAutoPlay={toggleAutoPlay}
        />
      </Show>
    </div>
  );
}
