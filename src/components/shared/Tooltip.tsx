import { Show, type ParentProps } from "solid-js";
import "./Tooltip.css";

interface TooltipProps extends ParentProps {
  content: string;
  position?: "top" | "bottom" | "left" | "right";
  visible?: boolean;
}

export default function Tooltip(props: TooltipProps) {
  return (
    <div class="tooltip-wrapper">
      {props.children}
      <Show when={props.visible !== false && props.content}>
        <div class="tooltip-content" classList={{ [props.position || "top"]: true }}>
          {props.content}
        </div>
      </Show>
    </div>
  );
}
