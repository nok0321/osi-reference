import { Show, For } from "solid-js";
import { getLayer } from "../../data/layers";
import { getLayerColor } from "../../utils/colors";
import { useI18n } from "../../i18n/context";
import ProtocolBadge from "../shared/ProtocolBadge";
import type { LayerNumber } from "../../types";
import "./LayerDetail.css";

interface LayerDetailProps {
  layerNumber: LayerNumber | null;
}

export default function LayerDetail(props: LayerDetailProps) {
  const { t } = useI18n();
  const layer = () => props.layerNumber ? getLayer(props.layerNumber) : undefined;
  const color = () => props.layerNumber ? getLayerColor(props.layerNumber) : null;

  return (
    <div class="layer-detail">
      <Show
        when={layer()}
        fallback={
          <div class="detail-empty">
            <div class="detail-empty-icon">◇</div>
            <p>{t("レイヤーをクリックして詳細を表示", "Click a layer to view details")}</p>
          </div>
        }
      >
        {(l) => (
          <div class="detail-content" style={{ "--detail-color": color()!.bg }}>
            <div class="detail-header">
              <span class="detail-layer-num">L{l().number}</span>
              <div class="detail-titles">
                <h2 class="detail-name">{l().name}</h2>
                <span class="detail-name-ja">{l().nameJa}</span>
              </div>
            </div>

            <div class="detail-section">
              <h3>{t("役割", "Role")}</h3>
              <p>{t(l().roleJa, l().role)}</p>
            </div>

            <div class="detail-section">
              <h3>PDU</h3>
              <p class="mono">{t(l().pduJa, l().pdu)}</p>
            </div>

            <div class="detail-section">
              <h3>{t("プロトコル", "Protocols")}</h3>
              <div class="protocol-list">
                <For each={l().protocols}>
                  {(proto) => (
                    <ProtocolBadge
                      name={proto.name}
                      layer={l().number}
                      note={t(proto.layerNoteJa || "", proto.layerNote || "")}
                    />
                  )}
                </For>
              </div>
            </div>

            <Show when={l().protocols.length > 0}>
              <div class="detail-section">
                <h3>{t("プロトコル詳細", "Protocol Details")}</h3>
                <div class="protocol-details">
                  <For each={l().protocols.slice(0, 4)}>
                    {(proto) => (
                      <div class="proto-detail-row">
                        <span class="proto-name mono">{proto.name}</span>
                        <span class="proto-desc">{t(proto.descriptionJa, proto.description)}</span>
                        <Show when={proto.port}>
                          <span class="proto-port mono">:{proto.port}</span>
                        </Show>
                      </div>
                    )}
                  </For>
                </div>
              </div>
            </Show>

            <div class="detail-section">
              <h3>{t("関連デバイス", "Devices")}</h3>
              <div class="device-list">
                <For each={t(l().devicesJa, l().devices) === l().devicesJa ? l().devicesJa : l().devices}>
                  {(device) => <span class="device-badge">{device}</span>}
                </For>
              </div>
            </div>

            <Show when={l().headerFields && l().headerFields!.length > 0}>
              <div class="detail-section">
                <h3>{t("ヘッダフィールド", "Header Fields")}</h3>
                <div class="header-fields">
                  <For each={l().headerFields}>
                    {(field) => (
                      <div class="field-row">
                        <span class="field-name mono">{field.name}</span>
                        <span class="field-bits mono">{field.bits}bit</span>
                        <span class="field-desc">{t(field.descriptionJa, field.description)}</span>
                      </div>
                    )}
                  </For>
                </div>
              </div>
            </Show>
          </div>
        )}
      </Show>
    </div>
  );
}
