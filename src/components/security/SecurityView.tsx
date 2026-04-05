import { useI18n } from "../../i18n/context";
import PacketMonitor from "./PacketMonitor";
import CertChain from "./CertChain";
import FirewallRules from "./FirewallRules";
import AttackMap from "./AttackMap";
import "./SecurityView.css";

export default function SecurityView() {
  const { t } = useI18n();

  return (
    <div class="security-view">
      <h2 class="view-title">
        {t("セキュリティダッシュボード", "Security Dashboard")}
      </h2>
      <div class="security-grid">
        <div class="grid-panel panel-tl">
          <PacketMonitor />
        </div>
        <div class="grid-panel panel-tr">
          <CertChain />
        </div>
        <div class="grid-panel panel-bl">
          <FirewallRules />
        </div>
        <div class="grid-panel panel-br">
          <AttackMap />
        </div>
      </div>
    </div>
  );
}
