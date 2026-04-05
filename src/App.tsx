import { Match, Switch } from "solid-js";
import { activeView, setActiveView } from "./state/app-state";
import { useI18n } from "./i18n/context";
import type { ViewType } from "./types";
import TabBar from "./components/shared/TabBar";
import OverviewView from "./components/overview/OverviewView";
import EncapsulationView from "./components/encapsulation/EncapsulationView";
import ScenarioView from "./components/scenario/ScenarioView";
import ComparisonView from "./components/comparison/ComparisonView";
import AuthView from "./components/auth/AuthView";
import SecurityView from "./components/security/SecurityView";
import "./app.css";

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
            <ScenarioView />
          </Match>
          <Match when={activeView() === "comparison"}>
            <ComparisonView />
          </Match>
          <Match when={activeView() === "auth"}>
            <AuthView />
          </Match>
          <Match when={activeView() === "security"}>
            <SecurityView />
          </Match>
        </Switch>
      </div>
    </div>
  );
}
