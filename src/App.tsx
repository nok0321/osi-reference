import { Match, Switch } from "solid-js";
import { activeView, setActiveView } from "./state/app-state";
import { useI18n } from "./i18n/context";
import type { ViewType } from "./types";
import TabBar from "./components/shared/TabBar";
import OverviewView from "./components/overview/OverviewView";
import EncapsulationView from "./components/encapsulation/EncapsulationView";
import ComparisonView from "./components/comparison/ComparisonView";
import "./app.css";

function PlaceholderView(props: { name: string; icon: string }) {
  return (
    <div class="placeholder-view">
      <div class="icon">{props.icon}</div>
      <div>{props.name}</div>
      <div style={{ "font-size": "0.75rem", "opacity": "0.5" }}>Coming soon...</div>
    </div>
  );
}

export default function App() {
  const { lang, toggle, t } = useI18n();

  return (
    <div class="app">
      <header class="app-header">
        <h1 class="app-title">
          {">"} OSI Reference
        </h1>
        <button class="lang-toggle" onClick={toggle}>
          {lang() === "ja" ? "EN" : "JA"}
        </button>
      </header>

      <TabBar
        activeTab={activeView()}
        onTabChange={(tab: ViewType) => setActiveView(tab)}
      />

      <div class="view-container">
        <Switch>
          <Match when={activeView() === "overview"}>
            <OverviewView />
          </Match>
          <Match when={activeView() === "encapsulation"}>
            <EncapsulationView />
          </Match>
          <Match when={activeView() === "scenario"}>
            <PlaceholderView name={t("シナリオ", "Scenario")} icon="◆" />
          </Match>
          <Match when={activeView() === "comparison"}>
            <ComparisonView />
          </Match>
          <Match when={activeView() === "auth"}>
            <PlaceholderView name={t("認証・認可", "Auth")} icon="⛨" />
          </Match>
          <Match when={activeView() === "security"}>
            <PlaceholderView name={t("セキュリティ", "Security")} icon="⊙" />
          </Match>
        </Switch>
      </div>
    </div>
  );
}
