import { For, createMemo } from "solid-js";
import { useI18n } from "../../i18n/context";
import { getLayerColor } from "../../utils/colors";
import type { EncapStep, EncapDirection, LayerNumber } from "../../types";
import "./EncapAnimation.css";

interface EncapAnimationProps {
  steps: EncapStep[];
  currentStep: number;
  direction: EncapDirection;
}

export default function EncapAnimation(props: EncapAnimationProps) {
  const { t } = useI18n();

  const allLayers = createMemo((): LayerNumber[] => {
    const layers: LayerNumber[] = [7, 4, 3, 2, 1];
    return props.direction === "up" ? [...layers].reverse() : layers;
  });

  return (
    <div class="encap-animation">
      <div class="layer-tower">
        <For each={allLayers()}>
          {(layerNum, i) => {
            const color = () => getLayerColor(layerNum);
            const step = () => props.steps.find(s => s.layerNumber === layerNum);
            const isPassed = () => {
              const stepIdx = props.steps.findIndex(s => s.layerNumber === layerNum);
              return stepIdx >= 0 && stepIdx <= props.currentStep;
            };
            const isCurrent = () => {
              const stepIdx = props.steps.findIndex(s => s.layerNumber === layerNum);
              return stepIdx === props.currentStep;
            };

            return (
              <div
                class="tower-layer"
                classList={{
                  passed: isPassed(),
                  current: isCurrent(),
                }}
                style={{
                  "--layer-bg": color().bg,
                  "--layer-bg-dim": `${color().bg}22`,
                }}
              >
                <div class="tower-label">
                  <span class="tower-num">L{layerNum}</span>
                  <span class="tower-name">
                    {t(
                      getLayerColor(layerNum).labelJa,
                      getLayerColor(layerNum).label
                    )}
                  </span>
                </div>
                <div class="tower-action">
                  {isCurrent() && step() ? (
                    <span class="action-badge" classList={{
                      "add": step()!.action === "add-header",
                      "remove": step()!.action === "remove-header",
                    }}>
                      {step()!.action === "add-header"
                        ? t("＋ ヘッダ追加", "+ Add Header")
                        : t("－ ヘッダ除去", "- Remove Header")}
                    </span>
                  ) : isPassed() && step() ? (
                    <span class="action-done">✓</span>
                  ) : null}
                </div>
                {isCurrent() && (
                  <div class="tower-packet-indicator">
                    <div class="packet-dot" />
                  </div>
                )}
              </div>
            );
          }}
        </For>
      </div>

      <div class="encap-description">
        <div class="desc-step mono">
          {t("ステップ", "Step")} {props.currentStep + 1}/{props.steps.length}
        </div>
        <p class="desc-text">
          {t(
            props.steps[props.currentStep]?.descriptionJa ?? "",
            props.steps[props.currentStep]?.description ?? ""
          )}
        </p>
      </div>
    </div>
  );
}
