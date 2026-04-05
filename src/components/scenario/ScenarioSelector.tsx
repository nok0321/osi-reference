import { For } from "solid-js";
import { useI18n } from "../../i18n/context";
import { SCENARIOS } from "../../data/scenarios";
import type { ScenarioType } from "../../types";
import "./ScenarioSelector.css";

interface ScenarioSelectorProps {
  active: ScenarioType;
  onChange: (id: ScenarioType) => void;
}

const SCENARIO_ICONS: Record<ScenarioType, string> = {
  http: "↔",
  dns: "⊕",
  tls: "⊛",
  "tls-deep": "⊚",
};

export default function ScenarioSelector(props: ScenarioSelectorProps) {
  const { t } = useI18n();

  return (
    <div class="scenario-selector">
      <For each={SCENARIOS}>
        {(scenario) => (
          <button
            class="scenario-btn"
            classList={{ active: props.active === scenario.id }}
            onClick={() => props.onChange(scenario.id)}
          >
            <span class="scenario-icon">{SCENARIO_ICONS[scenario.id]}</span>
            <span class="scenario-label">{t(scenario.nameJa, scenario.name)}</span>
          </button>
        )}
      </For>
    </div>
  );
}
