import { Show, createMemo } from "solid-js";
import { useI18n } from "../../i18n/context";
import { encapStep, setEncapStep, encapDirection, setEncapDirection } from "../../state/app-state";
import { ENCAP_STEPS_DOWN, ENCAP_STEPS_UP } from "../../data/encapsulation";
import StepControl from "../shared/StepControl";
import DataUnit from "./DataUnit";
import EncapAnimation from "./EncapAnimation";
import HeaderInspector from "./HeaderInspector";
import "./EncapsulationView.css";

export default function EncapsulationView() {
  const { t } = useI18n();

  const steps = createMemo(() =>
    encapDirection() === "down" ? ENCAP_STEPS_DOWN : ENCAP_STEPS_UP
  );

  const currentStep = createMemo(() => steps()[encapStep()]);

  function handleDirectionToggle() {
    setEncapStep(0);
    setEncapDirection(prev => (prev === "down" ? "up" : "down"));
  }

  return (
    <div class="encapsulation-view">
      <div class="encap-header">
        <h2 class="view-title">
          {t("カプセル化 / 非カプセル化", "Encapsulation / De-encapsulation")}
        </h2>
        <div class="encap-controls">
          <button
            class="direction-toggle"
            classList={{ active: encapDirection() === "down" }}
            onClick={handleDirectionToggle}
          >
            <span class="direction-icon">{encapDirection() === "down" ? "▼" : "▲"}</span>
            {encapDirection() === "down"
              ? t("カプセル化 (送信)", "Encapsulation (Send)")
              : t("非カプセル化 (受信)", "De-encapsulation (Receive)")}
          </button>
          <StepControl
            current={encapStep()}
            total={steps().length}
            onPrev={() => setEncapStep(prev => Math.max(0, prev - 1))}
            onNext={() => setEncapStep(prev => Math.min(steps().length - 1, prev + 1))}
          />
        </div>
      </div>

      <div class="encap-content">
        <div class="encap-left">
          <EncapAnimation
            steps={steps()}
            currentStep={encapStep()}
            direction={encapDirection()}
          />
        </div>
        <div class="encap-right">
          <DataUnit steps={steps()} currentStep={encapStep()} />
          <Show when={currentStep()}>
            <HeaderInspector step={currentStep()!} />
          </Show>
        </div>
      </div>
    </div>
  );
}
