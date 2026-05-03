import { Show, For } from "solid-js";
import { useI18n } from "../../i18n/context";
import type { AttackScenarioMeta } from "../../../shared/api-types";
import "./AttackScenarioSelector.css";

interface AttackScenarioSelectorProps {
  scenarios: AttackScenarioMeta[];
  selectedId: string;
  onSelect: (id: string) => void;
}

function AttackScenarioSelector(props: AttackScenarioSelectorProps) {
  const { t } = useI18n();
  const selected = () =>
    props.scenarios.find((s) => s.id === props.selectedId) ?? props.scenarios[0];

  return (
    <div class="attack-scenario-selector">
      <div class="attack-scenario-label">
        {t("攻撃シナリオを選択", "Select attack scenario")}
      </div>

      {/* 1件の場合: 静的表示 */}
      <Show when={props.scenarios.length === 1}>
        <div class="attack-scenario-single">
          <div class="attack-scenario-name">
            {t(selected()?.nameJa ?? "", selected()?.name ?? "")}
          </div>
          <div class="attack-scenario-desc">
            {t(selected()?.descriptionJa ?? "", selected()?.description ?? "")}
          </div>
          <div class="attack-scenario-badges">
            <SeverityBadge severity={selected()?.severity ?? "info"} />
            <ModeBadge mode={selected()?.mode} />
          </div>
        </div>
      </Show>

      {/* 複数件 (デスクトップ): チップ群 */}
      <Show when={props.scenarios.length > 1}>
        <div class="attack-scenario-chips" role="radiogroup" aria-label={t("攻撃シナリオ", "Attack scenarios")}>
          <For each={props.scenarios}>
            {(scenario) => (
              <button
                class="attack-scenario-chip"
                role="radio"
                aria-checked={props.selectedId === scenario.id}
                data-selected={props.selectedId === scenario.id}
                tabIndex={0}
                onClick={() => props.onSelect(scenario.id)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    props.onSelect(scenario.id);
                  }
                }}
              >
                <span class="attack-chip-name">
                  {t(scenario.nameJa, scenario.name)}
                </span>
                <SeverityBadge severity={scenario.severity} />
                <ModeBadge mode={scenario.mode} />
                <Show when={scenario.cweId && /^CWE-\d+$/.test(scenario.cweId)}>
                  <a
                    class="attack-chip-ref"
                    href={`https://cwe.mitre.org/data/definitions/${scenario.cweId!.slice(4)}.html`}
                    target="_blank"
                    rel="noopener noreferrer"
                    onClick={(e) => e.stopPropagation()}
                  >
                    {scenario.cweId}
                  </a>
                </Show>
                <Show when={scenario.capecId && /^CAPEC-\d+$/.test(scenario.capecId)}>
                  <a
                    class="attack-chip-ref"
                    href={`https://capec.mitre.org/data/definitions/${scenario.capecId!.slice(6)}.html`}
                    target="_blank"
                    rel="noopener noreferrer"
                    onClick={(e) => e.stopPropagation()}
                  >
                    {scenario.capecId}
                  </a>
                </Show>
              </button>
            )}
          </For>
        </div>

        {/* モバイル: ネイティブ select */}
        <select
          class="attack-scenario-select"
          aria-label={t("攻撃シナリオを選択", "Select attack scenario")}
          value={props.selectedId}
          onChange={(e) => props.onSelect(e.currentTarget.value)}
        >
          <For each={props.scenarios}>
            {(scenario) => (
              <option value={scenario.id}>
                {t(scenario.nameJa, scenario.name)} [{scenario.severity.toUpperCase()}]
              </option>
            )}
          </For>
        </select>
      </Show>

      {/* 選択中シナリオの前提条件・深刻度 */}
      <Show when={props.scenarios.length > 1 && selected()}>
        <div class="attack-scenario-meta">
          <div class="attack-scenario-desc">
            {t(selected()!.descriptionJa, selected()!.description)}
          </div>
        </div>
      </Show>
    </div>
  );
}

function SeverityBadge(badgeProps: { severity: string }) {
  return (
    <span class="severity-badge" data-severity={badgeProps.severity}>
      {badgeProps.severity.toUpperCase()}
    </span>
  );
}

/**
 * シナリオの実行モード (`live` / `narration`) を示すバッジ。
 * 未指定の場合は `narration` 扱い。DESIGN/33 §5.2 準拠。
 */
function ModeBadge(badgeProps: { mode?: "live" | "narration" }) {
  const resolved = badgeProps.mode ?? "narration";
  return (
    <span
      class="scenario-mode-badge"
      data-mode={resolved}
      aria-label={resolved === "live"
        ? "LIVE attack mode (real HTTP)"
        : "Narration mode (server-rendered simulation)"
      }
    >
      {resolved === "live" ? "LIVE" : "NARRATION"}
    </span>
  );
}

export default AttackScenarioSelector;
