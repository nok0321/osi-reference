import { For } from "solid-js";
import { OSI_LAYERS } from "../../data/layers";
import type { LayerNumber } from "../../types";
import LayerStrip from "./LayerStrip";
import "./LayerStack.css";

interface LayerStackProps {
  direction?: "down" | "up";
  activeLayer: LayerNumber | null;
  onLayerClick?: (layer: LayerNumber) => void;
  onLayerHover?: (layer: LayerNumber | null) => void;
}

export default function LayerStack(props: LayerStackProps) {
  const layers = () => {
    const sorted = [...OSI_LAYERS];
    return props.direction === "up" ? sorted.reverse() : sorted;
  };

  return (
    <div class="layer-stack">
      <For each={layers()}>
        {(layer) => (
          <LayerStrip
            layer={layer}
            isActive={props.activeLayer === layer.number}
            onClick={() => props.onLayerClick?.(layer.number)}
            onMouseEnter={() => props.onLayerHover?.(layer.number)}
            onMouseLeave={() => props.onLayerHover?.(null)}
          />
        )}
      </For>
    </div>
  );
}
