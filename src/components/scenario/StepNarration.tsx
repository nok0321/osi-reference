import { Show } from "solid-js";
import { useI18n } from "../../i18n/context";
import { getLayerColor } from "../../utils/colors";
import type { ScenarioStep } from "../../types";
import "./StepNarration.css";

interface StepNarrationProps {
  step: ScenarioStep;
  stepIndex: number;
  totalSteps: number;
}

export default function StepNarration(props: StepNarrationProps) {
  const { t } = useI18n();
  const color = () => getLayerColor(props.step.layerNumber);

  const sideLabel = () => {
    switch (props.step.side) {
      case "sender": return t("送信側", "Sender");
      case "receiver": return t("受信側", "Receiver");
      case "both": return t("双方", "Both");
    }
  };

  return (
    <div
      class="step-narration"
      style={{
        "--narr-color": color().bg,
        "--narr-color-dim": `${color().bg}22`,
      }}
    >
      <div class="narr-header">
        <div class="narr-meta">
          <span class="narr-step mono">
            {props.stepIndex + 1}/{props.totalSteps}
          </span>
          <span class="narr-layer" style={{ color: color().bg }}>
            L{props.step.layerNumber}
          </span>
          <span class="narr-side">{sideLabel()}</span>
        </div>
        <h3 class="narr-title">{t(props.step.titleJa, props.step.title)}</h3>
      </div>
      <p class="narr-desc">{t(props.step.descriptionJa, props.step.description)}</p>
      <div class="narr-protocol mono">{props.step.protocolAction}</div>
    </div>
  );
}
