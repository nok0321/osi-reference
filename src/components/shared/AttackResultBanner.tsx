import { Show } from "solid-js";
import { useI18n } from "../../i18n/context";
import type { AttackResult } from "../../../shared/api-types";
import "./AttackResultBanner.css";

interface AttackResultBannerProps {
  result: AttackResult;
}

function AttackResultBanner(props: AttackResultBannerProps) {
  const { t } = useI18n();

  return (
    <div
      class="attack-result-banner"
      data-outcome={props.result.outcome}
      role="status"
      aria-live="polite"
      aria-label={
        props.result.outcome === "succeeded"
          ? t("攻撃成立通知", "Attack success notification")
          : t("防御成立通知", "Defense success notification")
      }
    >
      <Show when={props.result.outcome === "succeeded"}>
        <span class="attack-result-prefix" aria-hidden="true">[!]</span>
        <span class="attack-result-message">
          {t(
            "攻撃成立 — この実装は脆弱です",
            "Attack succeeded — this implementation is vulnerable"
          )}
        </span>
      </Show>
      <Show when={props.result.outcome === "blocked"}>
        <span class="attack-result-prefix" aria-hidden="true">[OK]</span>
        <span class="attack-result-message">
          {t("防御成立 — ", "Defense succeeded — ")}{props.result.blockedBy ?? ""}
        </span>
      </Show>
      <Show when={props.result.outcome === "error"}>
        <span class="attack-result-prefix" aria-hidden="true">[?]</span>
        <span class="attack-result-message">
          {t("実行エラー", "Execution error")}
        </span>
      </Show>
    </div>
  );
}

export default AttackResultBanner;
