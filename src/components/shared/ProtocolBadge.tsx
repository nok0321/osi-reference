import { Show } from "solid-js";
import { getLayerColor } from "../../utils/colors";
import type { LayerNumber } from "../../types";
import "./ProtocolBadge.css";

interface ProtocolBadgeProps {
  name: string;
  layer?: LayerNumber;
  note?: string;
}

export default function ProtocolBadge(props: ProtocolBadgeProps) {
  const color = () => props.layer ? getLayerColor(props.layer).bg : "var(--text-secondary)";

  return (
    <span
      class="protocol-badge"
      classList={{ "has-note": !!props.note }}
      style={{ "--badge-color": color() }}
      title={props.note || undefined}
    >
      {props.name}
      <Show when={props.note}>
        <span class="badge-note">*</span>
      </Show>
    </span>
  );
}
