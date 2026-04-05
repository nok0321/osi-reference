import { selectedLayer, setSelectedLayer } from "../../state/app-state";
import type { LayerNumber } from "../../types";
import LayerDiagram from "./LayerDiagram";
import LayerDetail from "./LayerDetail";
import "./OverviewView.css";

export default function OverviewView() {
  const handleLayerClick = (layer: LayerNumber) => {
    setSelectedLayer(prev => prev === layer ? null : layer);
  };

  return (
    <div class="overview-view">
      <LayerDiagram
        selectedLayer={selectedLayer()}
        onLayerClick={handleLayerClick}
        onLayerHover={() => {}}
      />
      <LayerDetail layerNumber={selectedLayer()} />
    </div>
  );
}
