import { Show, createMemo } from "solid-js";
import { useI18n } from "../../i18n/context";
import { activeScenario, setActiveScenario, scenarioStep, setScenarioStep } from "../../state/app-state";
import { getScenario } from "../../data/scenarios";
import type { ScenarioType } from "../../types";
import StepControl from "../shared/StepControl";
import ScenarioSelector from "./ScenarioSelector";
import DualStackDiagram from "./DualStackDiagram";
import PacketFlow from "./PacketFlow";
import StepNarration from "./StepNarration";
import "./ScenarioView.css";

export default function ScenarioView() {
  const { t } = useI18n();

  const scenario = createMemo(() => getScenario(activeScenario())!);
  const steps = createMemo(() => scenario().steps);
  const currentStep = createMemo(() => steps()[scenarioStep()]);

  function handleScenarioChange(id: ScenarioType) {
    setActiveScenario(id);
    setScenarioStep(0);
  }

  return (
    <div class="scenario-view">
      <div class="scenario-header">
        <h2 class="view-title">
          {t("通信シナリオ", "Communication Scenarios")}
        </h2>
        <div class="scenario-controls">
          <ScenarioSelector
            active={activeScenario()}
            onChange={handleScenarioChange}
          />
          <StepControl
            current={scenarioStep()}
            total={steps().length}
            onPrev={() => setScenarioStep(prev => Math.max(0, prev - 1))}
            onNext={() => setScenarioStep(prev => Math.min(steps().length - 1, prev + 1))}
          />
        </div>
      </div>

      <div class="scenario-desc">
        <span class="desc-label mono">{t(scenario().nameJa, scenario().name)}</span>
        <span class="desc-text">{t(scenario().descriptionJa, scenario().description)}</span>
      </div>

      <div class="scenario-content">
        <div class="scenario-left">
          <DualStackDiagram
            highlightLayers={currentStep().highlight}
            activeSide={currentStep().side}
          />
        </div>
        <div class="scenario-right">
          <Show when={currentStep()}>
            <PacketFlow
              step={currentStep()}
              totalSteps={steps().length}
            />
            <StepNarration
              step={currentStep()}
              stepIndex={scenarioStep()}
              totalSteps={steps().length}
            />
          </Show>
        </div>
      </div>
    </div>
  );
}
