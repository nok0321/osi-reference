import { Show, For } from "solid-js";
import { useI18n } from "../../i18n/context";
import { getLayerColor } from "../../utils/colors";
import type { EncapStep, HeaderField, LayerNumber } from "../../types";
import "./HeaderBlock.css";

interface HeaderBlockProps {
  step: EncapStep;
  isActive: boolean;
  isNew: boolean;
  onClick?: () => void;
}

export default function HeaderBlock(props: HeaderBlockProps) {
  const { t } = useI18n();
  const color = () => getLayerColor(props.step.layerNumber);

  return (
    <div
      class="header-block"
      classList={{
        active: props.isActive,
        "new-block": props.isNew,
      }}
      style={{
        "--block-color": color().bg,
        "--block-color-dim": `${color().bg}33`,
      }}
      onClick={() => props.onClick?.()}
      role="button"
      tabIndex={0}
    >
      <div class="block-label">
        <span class="block-layer">L{props.step.layerNumber}</span>
        <span class="block-name">{props.step.headerName}</span>
        <Show when={props.step.headerBytes > 0}>
          <span class="block-bytes mono">{props.step.headerBytes}B</span>
        </Show>
      </div>
      <div class="block-pdu mono">
        {t(props.step.resultPduJa, props.step.resultPdu)}
      </div>
    </div>
  );
}

interface HeaderInspectorPanelProps {
  step: EncapStep;
}

export function HeaderInspectorPanel(props: HeaderInspectorPanelProps) {
  const { t } = useI18n();
  const color = () => getLayerColor(props.step.layerNumber);

  return (
    <div class="header-inspector" style={{ "--block-color": color().bg }}>
      <h3 class="inspector-title">
        {props.step.headerName}
        <Show when={props.step.headerBytes > 0}>
          <span class="inspector-bytes mono"> ({props.step.headerBytes} bytes)</span>
        </Show>
      </h3>
      <p class="inspector-desc">{t(props.step.descriptionJa, props.step.description)}</p>
      <div class="inspector-fields">
        <For each={props.step.fields}>
          {(field: HeaderField) => (
            <div class="field-row">
              <span class="field-name mono">{field.name}</span>
              <Show when={field.bits > 0}>
                <span class="field-bits">{field.bits} bits</span>
              </Show>
              <span class="field-desc">{t(field.descriptionJa, field.description)}</span>
            </div>
          )}
        </For>
      </div>
    </div>
  );
}
