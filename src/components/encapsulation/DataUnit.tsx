import { For, createMemo } from "solid-js";
import { useI18n } from "../../i18n/context";
import { getLayerColor } from "../../utils/colors";
import type { EncapStep } from "../../types";
import "./DataUnit.css";

interface DataUnitProps {
  steps: EncapStep[];
  currentStep: number;
}

export default function DataUnit(props: DataUnitProps) {
  const { t } = useI18n();

  const visibleSteps = createMemo(() =>
    props.steps.slice(0, props.currentStep + 1)
  );

  return (
    <div class="data-unit-stack">
      <div class="stack-title mono">
        {t("データユニット構造", "Data Unit Structure")}
      </div>
      <div class="pdu-visualization">
        <For each={visibleSteps()}>
          {(step: EncapStep, i) => {
            const color = () => getLayerColor(step.layerNumber);
            const isLatest = () => i() === props.currentStep;
            return (
              <div
                class="pdu-segment"
                classList={{ latest: isLatest() }}
                style={{
                  "--seg-color": color().bg,
                  "--seg-color-dim": `${color().bg}33`,
                }}
              >
                <div class="seg-header-part">
                  <span class="seg-layer">L{step.layerNumber}</span>
                  <span class="seg-name">{step.headerName}</span>
                </div>
              </div>
            );
          }}
        </For>
        <div class="pdu-payload">
          <span class="payload-label">{t("ペイロード (データ)", "Payload (Data)")}</span>
        </div>
      </div>
      <div class="pdu-result mono">
        {t("現在のPDU: ", "Current PDU: ")}
        {t(
          props.steps[props.currentStep]?.resultPduJa ?? "",
          props.steps[props.currentStep]?.resultPdu ?? ""
        )}
      </div>
    </div>
  );
}
