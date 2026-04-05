import { createEffect, onMount, onCleanup } from "solid-js";
import { getLayerColor } from "../../utils/colors";
import type { ScenarioStep } from "../../types";
import "./PacketFlow.css";

interface PacketFlowProps {
  step: ScenarioStep;
  totalSteps: number;
}

export default function PacketFlow(props: PacketFlowProps) {
  let canvasRef: HTMLDivElement | undefined;

  const sidePosition = () => {
    switch (props.step.side) {
      case "sender": return 0;
      case "receiver": return 100;
      case "both": return 50;
    }
  };

  const layerPosition = () => {
    // Map L7→0%, L1→100%
    return ((7 - props.step.layerNumber) / 6) * 100;
  };

  const primaryColor = () => getLayerColor(props.step.layerNumber).bg;

  return (
    <div class="packet-flow" ref={canvasRef}>
      <div class="flow-track">
        <div
          class="flow-dot"
          style={{
            left: `${sidePosition()}%`,
            top: `${layerPosition()}%`,
            "--dot-color": primaryColor(),
          }}
        >
          <div class="dot-ring" />
          <div class="dot-core" />
        </div>

        {/* Flow trail */}
        <svg class="flow-svg" viewBox="0 0 100 100" preserveAspectRatio="none">
          <line
            x1={sidePosition()}
            y1={layerPosition()}
            x2="50"
            y2="50"
            stroke={primaryColor()}
            stroke-width="0.5"
            stroke-dasharray="2 2"
            opacity="0.3"
          />
        </svg>
      </div>

      <div class="flow-info">
        <span class="flow-protocol mono">{props.step.protocolAction}</span>
      </div>
    </div>
  );
}
