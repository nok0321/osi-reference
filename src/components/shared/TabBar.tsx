import { For } from "solid-js";
import type { ViewType } from "../../types";
import { useI18n } from "../../i18n/context";
import ProgressIndicator from "./ProgressIndicator";
import "./TabBar.css";

interface Tab {
  id: ViewType;
  label: string;
  labelJa: string;
  icon: string;
}

const TABS: Tab[] = [
  { id: "overview", label: "Overview", labelJa: "概要", icon: "layers" },
  { id: "encapsulation", label: "Encapsulation", labelJa: "カプセル化", icon: "package" },
  { id: "scenario", label: "Scenario", labelJa: "シナリオ", icon: "activity" },
  { id: "comparison", label: "TCP/IP", labelJa: "TCP/IP比較", icon: "columns" },
  { id: "auth", label: "Auth", labelJa: "認証・認可", icon: "shield" },
  { id: "security", label: "Security", labelJa: "セキュリティ", icon: "lock" },
];

const ICONS: Record<string, string> = {
  layers: "◇",
  package: "◈",
  activity: "◆",
  columns: "⊞",
  shield: "⛨",
  lock: "⊙",
};

interface TabBarProps {
  activeTab: ViewType;
  onTabChange: (tab: ViewType) => void;
}

export default function TabBar(props: TabBarProps) {
  const { t } = useI18n();

  return (
    <nav class="tab-bar" role="tablist">
      <For each={TABS}>
        {(tab) => (
          <button
            class="tab-item"
            classList={{ active: props.activeTab === tab.id }}
            onClick={() => props.onTabChange(tab.id)}
            aria-selected={props.activeTab === tab.id}
            role="tab"
          >
            <span class="tab-icon">{ICONS[tab.icon]}</span>
            <span class="tab-label">{t(tab.labelJa, tab.label)}</span>
            <ProgressIndicator view={tab.id} />
          </button>
        )}
      </For>
    </nav>
  );
}
