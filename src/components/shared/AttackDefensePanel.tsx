import { Show, For } from "solid-js";
import { useI18n } from "../../i18n/context";
import type { AttackScenarioMeta } from "../../../shared/api-types";
import "./AttackDefensePanel.css";

interface AttackDefensePanelProps {
  scenario: AttackScenarioMeta | null;
  open: boolean;
  onToggle: () => void;
}

/**
 * 攻撃完了後に展開される防御策解説パネル。
 * codeHints は Phase 1 で AttackScenarioMeta に追加予定のため、現フェーズでは
 * mitigation テキストと references のみ表示する。
 */
function AttackDefensePanel(props: AttackDefensePanelProps) {
  const { t } = useI18n();

  return (
    <div class="attack-defense-panel" data-open={props.open}>
      <button
        class="attack-defense-toggle"
        aria-expanded={props.open}
        onClick={props.onToggle}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            props.onToggle();
          }
        }}
      >
        <span>{t("防御策を見る", "Show Defense Recommendation")}</span>
        <span aria-hidden="true">{props.open ? "▾" : "▸"}</span>
      </button>

      <Show when={props.open && props.scenario !== null}>
        <div class="attack-defense-content">
          <div class="attack-defense-body">
            <div class="attack-defense-summary">
              <p class="attack-defense-text">
                {t(props.scenario!.mitigationJa, props.scenario!.mitigation)}
              </p>
            </div>

            <Show when={(props.scenario!.references ?? []).filter(r => /^https?:\/\//.test(r)).length > 0}>
              <div class="attack-defense-refs">
                <div class="attack-defense-refs-label">
                  {t("参考リンク", "References")}
                </div>
                <div class="attack-defense-refs-list">
                  <For each={(props.scenario!.references ?? []).filter(r => /^https?:\/\//.test(r))}>
                    {(ref) => (
                      <a
                        class="attack-defense-ref-link"
                        href={ref}
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        {ref}
                      </a>
                    )}
                  </For>
                </div>
              </div>
            </Show>
          </div>
        </div>
      </Show>
    </div>
  );
}

export default AttackDefensePanel;
