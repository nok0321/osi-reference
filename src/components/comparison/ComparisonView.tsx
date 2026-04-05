import { useI18n } from "../../i18n/context";
import { TCPIP_MAPPINGS, MODEL_COMPARISON } from "../../data/tcpip-mapping";
import { hoveredMapping, setHoveredMapping } from "../../state/app-state";
import DualModel from "./DualModel";
import MappingLines from "./MappingLines";
import { For } from "solid-js";
import type { ComparisonItem } from "../../data/tcpip-mapping";
import "./ComparisonView.css";

export default function ComparisonView() {
  const { t } = useI18n();

  return (
    <div class="comparison-view">
      <h2 class="view-title">
        {t("OSI モデル ⇔ TCP/IP モデル", "OSI Model ⇔ TCP/IP Model")}
      </h2>

      <div class="model-diagram">
        <DualModel mappings={TCPIP_MAPPINGS} />
        <MappingLines mappings={TCPIP_MAPPINGS} />
      </div>

      <div class="comparison-table">
        <div class="table-title mono">
          {t("モデル比較", "Model Comparison")}
        </div>
        <div class="table-header">
          <span class="th aspect">{t("観点", "Aspect")}</span>
          <span class="th osi">OSI</span>
          <span class="th tcpip">TCP/IP</span>
        </div>
        <For each={MODEL_COMPARISON}>
          {(item: ComparisonItem) => (
            <div class="table-row">
              <span class="td aspect">{t(item.aspectJa, item.aspect)}</span>
              <span class="td osi">{t(item.osiJa, item.osi)}</span>
              <span class="td tcpip">{t(item.tcpIpJa, item.tcpIp)}</span>
            </div>
          )}
        </For>
      </div>
    </div>
  );
}
