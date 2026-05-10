/**
 * AttackStoryControls (DESIGN/35 §3, §5) — 攻撃ストーリーボードのナビゲーション UI。
 *
 * - ◄ ► ボタン (端で disabled)
 * - dot indicator (シーン間ジャンプ + aria-current="step")
 * - auto-play toggle (▶ / ⏸)
 *
 * StepControl.tsx の DNA を継承しつつ dot indicator + auto-play toggle を追加。
 * DRY 化は Phase 3 以降で再評価。
 */
import { For } from "solid-js";
import { useI18n } from "../../i18n/context";
import "./AttackStoryControls.css";

interface AttackStoryControlsProps {
  current: number;
  total: number;
  autoPlay: boolean;
  onPrev: () => void;
  onNext: () => void;
  onJump: (index: number) => void;
  onToggleAutoPlay: () => void;
}

export default function AttackStoryControls(props: AttackStoryControlsProps) {
  const { t } = useI18n();

  return (
    <div class="story-controls" role="group" aria-label={t("ストーリーボード操作", "Storyboard controls")}>
      <button
        type="button"
        class="story-controls-btn story-controls-prev"
        disabled={props.current <= 0}
        onClick={() => props.onPrev()}
        aria-label={t("前のシーン", "Previous scene")}
      >
        ◄
      </button>

      <div class="story-controls-dots" role="tablist" aria-label={t("シーン一覧", "Scene list")}>
        <For each={Array.from({ length: props.total })}>
          {(_, i) => (
            <button
              type="button"
              class="story-controls-dot"
              data-active={i() === props.current ? "true" : "false"}
              data-past={i() < props.current ? "true" : "false"}
              role="tab"
              aria-selected={i() === props.current}
              aria-current={i() === props.current ? "step" : undefined}
              aria-label={t(`シーン ${i() + 1} へ`, `Jump to scene ${i() + 1}`)}
              onClick={() => props.onJump(i())}
            />
          )}
        </For>
      </div>

      <span class="story-controls-position mono" aria-live="off">
        {t(
          `シーン ${props.current + 1} / ${props.total}`,
          `Scene ${props.current + 1} of ${props.total}`,
        )}
      </span>

      <button
        type="button"
        class="story-controls-btn story-controls-autoplay"
        data-on={props.autoPlay ? "true" : "false"}
        onClick={() => props.onToggleAutoPlay()}
        aria-pressed={props.autoPlay}
        aria-label={
          props.autoPlay ? t("自動再生を停止", "Pause auto-play") : t("自動再生を開始", "Start auto-play")
        }
      >
        {props.autoPlay ? "⏸" : "▶"}
      </button>

      <button
        type="button"
        class="story-controls-btn story-controls-next"
        disabled={props.current >= props.total - 1}
        onClick={() => props.onNext()}
        aria-label={t("次のシーン", "Next scene")}
      >
        ►
      </button>
    </div>
  );
}
