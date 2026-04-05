import { For } from "solid-js";
import { useI18n } from "../../i18n/context";
import { getLayerColor } from "../../utils/colors";
import { hoveredMapping, setHoveredMapping } from "../../state/app-state";
import { OSI_LAYERS } from "../../data/layers";
import type { TcpIpMapping, LayerNumber } from "../../types";
import "./DualModel.css";

interface DualModelProps {
  mappings: TcpIpMapping[];
}

const TCPIP_COLORS = [
  "#C41D7F", // Application (maps to L7,6,5)
  "#08979C", // Transport (maps to L4)
  "#7CB305", // Internet (maps to L3)
  "#CF8B00", // Network Access (maps to L1,2)
];

export default function DualModel(props: DualModelProps) {
  const { t } = useI18n();

  const osiLayers = () => [...OSI_LAYERS]; // already sorted 7→1

  function isLayerHighlighted(layerNum: LayerNumber): boolean {
    const hovered = hoveredMapping();
    if (hovered === null) return false;
    const mapping = props.mappings.find(m => m.osiLayers.includes(hovered));
    return mapping ? mapping.osiLayers.includes(layerNum) : false;
  }

  function isTcpIpHighlighted(index: number): boolean {
    const hovered = hoveredMapping();
    if (hovered === null) return false;
    return props.mappings[index].osiLayers.includes(hovered);
  }

  return (
    <>
      {/* OSI Column */}
      <div class="model-column osi-column">
        <div class="column-header mono">OSI Model</div>
        <div class="layer-list">
          <For each={osiLayers()}>
            {(layer) => {
              const color = () => getLayerColor(layer.number);
              return (
                <div
                  class="model-layer osi-layer"
                  classList={{ highlighted: isLayerHighlighted(layer.number) }}
                  style={{
                    "--m-color": color().bg,
                    "--m-color-dim": `${color().bg}22`,
                  }}
                  onMouseEnter={() => setHoveredMapping(layer.number)}
                  onMouseLeave={() => setHoveredMapping(null)}
                  data-layer={layer.number}
                >
                  <span class="m-num">L{layer.number}</span>
                  <span class="m-name">{t(layer.nameJa, layer.name)}</span>
                </div>
              );
            }}
          </For>
        </div>
      </div>

      {/* TCP/IP Column */}
      <div class="model-column tcpip-column">
        <div class="column-header mono">TCP/IP Model</div>
        <div class="layer-list">
          <For each={props.mappings}>
            {(mapping, i) => {
              const spanCount = () => mapping.osiLayers.length;
              return (
                <div
                  class="model-layer tcpip-layer"
                  classList={{ highlighted: isTcpIpHighlighted(i()) }}
                  style={{
                    "--m-color": TCPIP_COLORS[i()],
                    "--m-color-dim": `${TCPIP_COLORS[i()]}22`,
                    flex: spanCount(),
                  }}
                  onMouseEnter={() => setHoveredMapping(mapping.osiLayers[0])}
                  onMouseLeave={() => setHoveredMapping(null)}
                  data-tcpip={i()}
                >
                  <span class="m-name">{t(mapping.tcpIpLayerJa, mapping.tcpIpLayer)}</span>
                  <span class="m-span mono">
                    {mapping.osiLayers.length > 1
                      ? `L${mapping.osiLayers[mapping.osiLayers.length - 1]}-L${mapping.osiLayers[0]}`
                      : `L${mapping.osiLayers[0]}`}
                  </span>
                </div>
              );
            }}
          </For>
        </div>
      </div>
    </>
  );
}
