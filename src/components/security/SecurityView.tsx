import { useI18n } from "../../i18n/context";
import PacketMonitor from "./PacketMonitor";
import CertChain from "./CertChain";
import "./SecurityView.css";

function PlaceholderPanel(props: { name: string }) {
  return (
    <div class="security-placeholder">
      <span class="sp-icon">◇</span>
      <span>{props.name}</span>
      <span class="sp-note">Coming in Phase 7...</span>
    </div>
  );
}

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
          <PlaceholderPanel name={t("ファイアウォールルール", "Firewall Rules")} />
        </div>
        <div class="grid-panel panel-br">
          <PlaceholderPanel name={t("攻撃マップ", "Attack Map")} />
        </div>
      </div>
    </div>
  );
}
