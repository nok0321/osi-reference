import { useI18n } from "../../i18n/context";
import { getLayerColor } from "../../utils/colors";
import type { OsiLayer } from "../../types";
import "./LayerStrip.css";

interface LayerStripProps {
  layer: OsiLayer;
  isActive: boolean;
  onClick?: () => void;
  onMouseEnter?: () => void;
  onMouseLeave?: () => void;
}

export default function LayerStrip(props: LayerStripProps) {
  const { t } = useI18n();
  const color = () => getLayerColor(props.layer.number);

  return (
    <div
      class="layer-strip"
      classList={{ active: props.isActive }}
      style={{
        "--layer-color": color().bg,
        "--layer-color-dim": `${color().bg}33`,
      }}
      onClick={() => props.onClick?.()}
      onMouseEnter={() => props.onMouseEnter?.()}
      onMouseLeave={() => props.onMouseLeave?.()}
      role="button"
      tabIndex={0}
    >
      <span class="layer-number">L{props.layer.number}</span>
      <span class="layer-name">{t(props.layer.nameJa, props.layer.name)}</span>
      <span class="layer-pdu mono">{t(props.layer.pduJa, props.layer.pdu)}</span>
    </div>
  );
}
