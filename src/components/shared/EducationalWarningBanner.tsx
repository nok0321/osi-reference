import { Show } from "solid-js";
import { useI18n } from "../../i18n/context";
import "./EducationalWarningBanner.css";

interface EducationalWarningBannerProps {
  /**
   * `"live"` のとき右端に LIVE バッジを表示する (DESIGN/33 §5.1)。
   * 未指定または `"narration"` の場合はバッジ非表示。
   */
  mode?: "live" | "narration";
}

/**
 * 攻撃者モード (Attacker View) で常時表示する教育用バナー。
 * dismissable 禁止: 閉じるボタンなし、display:none/visibility:hidden 実装禁止。
 * DESIGN/04 §6 完全準拠。
 */
function EducationalWarningBanner(props: EducationalWarningBannerProps) {
  const { t } = useI18n();
  return (
    <div
      class="edu-warning-banner"
      data-mode={props.mode ?? "narration"}
      role="note"
      aria-live="polite"
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
          aria-label={t("LIVE 攻撃モード — 実 HTTP を Docker victim に送信します", "LIVE attack mode — sends real HTTP to the Docker victim")}
        >
          LIVE
        </span>
      </Show>
    </div>
  );
}

export default EducationalWarningBanner;
