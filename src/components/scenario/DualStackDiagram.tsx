import { For } from "solid-js";
import { useI18n } from "../../i18n/context";
import { getLayerColor } from "../../utils/colors";
import { OSI_LAYERS } from "../../data/layers";
import type { LayerNumber } from "../../types";
import "./DualStackDiagram.css";

interface DualStackDiagramProps {
  highlightLayers: LayerNumber[];
  activeSide: "sender" | "receiver" | "both";
}

export default function DualStackDiagram(props: DualStackDiagramProps) {
  const { t } = useI18n();

  const layers = () => [...OSI_LAYERS]; // 7→1

  function isHighlighted(layerNum: LayerNumber): boolean {
    return props.highlightLayers.includes(layerNum);
  }

  return (
    <div class="dual-stack">
      <div class="stack-side sender-stack">
        <div class="stack-header mono">{t("送信側", "Sender")}</div>
        <For each={layers()}>
          {(layer) => {
            const color = () => getLayerColor(layer.number);
            return (
              <div
                class="stack-layer"
                classList={{
                  highlighted: isHighlighted(layer.number) && (props.activeSide === "sender" || props.activeSide === "both"),
                }}
                style={{
                  "--sl-color": color().bg,
                  "--sl-color-dim": `${color().bg}22`,
                }}
              >
                <span class="sl-num">L{layer.number}</span>
                <span class="sl-name">{t(layer.nameJa, layer.name)}</span>
              </div>
            );
          }}
        </For>
      </div>

      <div class="stack-middle">
        <div class="network-line" />
        <span class="network-label mono">{t("ネットワーク", "Network")}</span>
      </div>

      <div class="stack-side receiver-stack">
        <div class="stack-header mono">{t("受信側", "Receiver")}</div>
        <For each={layers()}>
          {(layer) => {
            const color = () => getLayerColor(layer.number);
            return (
              <div
                class="stack-layer"
                classList={{
                  highlighted: isHighlighted(layer.number) && (props.activeSide === "receiver" || props.activeSide === "both"),
                }}
                style={{
                  "--sl-color": color().bg,
                  "--sl-color-dim": `${color().bg}22`,
                }}
              >
                <span class="sl-num">L{layer.number}</span>
                <span class="sl-name">{t(layer.nameJa, layer.name)}</span>
              </div>
            );
          }}
        </For>
      </div>
    </div>
  );
}
