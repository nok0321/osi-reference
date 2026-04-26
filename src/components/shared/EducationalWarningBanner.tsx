import { useI18n } from "../../i18n/context";
import "./EducationalWarningBanner.css";

/**
 * 攻撃者モード (Attacker View) で常時表示する教育用バナー。
 * dismissable 禁止: 閉じるボタンなし、display:none/visibility:hidden 実装禁止。
 * DESIGN/04 §6 完全準拠。
 */
function EducationalWarningBanner() {
  const { t } = useI18n();
  return (
    <div
      class="edu-warning-banner"
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
    </div>
  );
}

export default EducationalWarningBanner;
