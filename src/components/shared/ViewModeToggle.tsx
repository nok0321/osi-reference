import { onMount, untrack } from "solid-js";
import { useI18n } from "../../i18n/context";
import {
  viewMode,
  setViewMode,
  useViewModeSync,
  type ViewMode,
} from "../../state/attack-state";
import type { AuthSubView } from "../../types/security";
import "./ViewModeToggle.css";

interface ViewModeToggleProps {
  /** 将来の拡張用: タブ固有のトグル動作が必要な場合に使用する。現時点では未使用。 */
  tabId: AuthSubView;
}

function ViewModeToggle(props: ViewModeToggleProps) {
  const { t } = useI18n();
  const { params, setParams } = useViewModeSync();

  /* 初回マウント時のみ URL → Signal を片方向同期 */
  onMount(() => {
    const initial = untrack(() => params.view);
    const view = Array.isArray(initial) ? initial[0] : initial;
    if (view === "attacker") setViewMode("attacker");
  });

  /* ボタン操作時に Signal と URL を同期更新 */
  function changeMode(next: ViewMode) {
    setViewMode(next);
    setParams({ view: next === "attacker" ? "attacker" : undefined });
  }

  return (
    <div class="view-mode-toggle" role="group" aria-label={t("表示モード切替", "View mode toggle")}>
      <button
        class="view-mode-btn"
        data-active={viewMode() === "defender"}
        role="switch"
        aria-checked={viewMode() === "defender"}
        aria-label={t("防御者モードに切り替え", "Switch to Defender mode")}
        tabIndex={0}
        onClick={() => changeMode("defender")}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            changeMode("defender");
          }
        }}
      >
        <span class="view-mode-icon" aria-hidden="true">[D]</span>
        {t("防御者モード", "DEFENDER")}
      </button>

      <span class="view-mode-sep" aria-hidden="true">|</span>

      <button
        class="view-mode-btn view-mode-btn--attacker"
        data-active={viewMode() === "attacker"}
        role="switch"
        aria-checked={viewMode() === "attacker"}
        aria-label={t("攻撃者モードに切り替え", "Switch to Attacker mode")}
        tabIndex={0}
        onClick={() => changeMode("attacker")}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            changeMode("attacker");
          }
        }}
      >
        <span class="view-mode-icon" aria-hidden="true">[A]</span>
        {t("攻撃者モード", "ATTACKER")}
      </button>
    </div>
  );
}

export default ViewModeToggle;
