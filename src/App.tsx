import { Match, Switch, onMount, onCleanup, ErrorBoundary } from "solid-js";
import { activeView, setActiveView, selectedLayer, setSelectedLayer,
  encapStep, setEncapStep, encapDirection,
  scenarioStep, setScenarioStep, activeScenario } from "./state/app-state";
import { packetFlowRunning, setPacketFlowRunning } from "./state/security-state";
import { ENCAP_STEPS_DOWN, ENCAP_STEPS_UP } from "./data/encapsulation";
import { getScenario } from "./data/scenarios";
import { useI18n } from "./i18n/context";
import type { ViewType, LayerNumber } from "./types";
import TabBar from "./components/shared/TabBar";
import OverviewView from "./components/overview/OverviewView";
import EncapsulationView from "./components/encapsulation/EncapsulationView";
import ScenarioView from "./components/scenario/ScenarioView";
import ComparisonView from "./components/comparison/ComparisonView";
import AuthView from "./components/auth/AuthView";
import SecurityView from "./components/security/SecurityView";
import "./app.css";

const VIEW_ORDER: ViewType[] = ["overview", "encapsulation", "scenario", "comparison", "auth", "security"];

function ErrorFallback(props: { error: Error }) {
  return (
    <div class="error-fallback">
      <h2>Something went wrong</h2>
      <pre class="mono">{props.error.message}</pre>
    </div>
  );
}

export default function App() {
  const { lang, toggle, t } = useI18n();

  function handleKeyDown(e: KeyboardEvent) {
    // Don't capture when typing in inputs
    const tag = (e.target as HTMLElement)?.tagName;
    if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;

    // 1-6: Switch views
    if (e.key >= "1" && e.key <= "6" && !e.ctrlKey && !e.metaKey && !e.altKey) {
      e.preventDefault();
      setActiveView(VIEW_ORDER[parseInt(e.key) - 1]);
      return;
    }

    // Arrow keys: step control (encapsulation & scenario views)
    if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
      const view = activeView();
      if (view === "encapsulation") {
        e.preventDefault();
        const steps = encapDirection() === "down" ? ENCAP_STEPS_DOWN : ENCAP_STEPS_UP;
        if (e.key === "ArrowRight") {
          setEncapStep(prev => Math.min(steps.length - 1, prev + 1));
        } else {
          setEncapStep(prev => Math.max(0, prev - 1));
        }
      } else if (view === "scenario") {
        e.preventDefault();
        const scenario = getScenario(activeScenario());
        if (scenario) {
          if (e.key === "ArrowRight") {
            setScenarioStep(prev => Math.min(scenario.steps.length - 1, prev + 1));
          } else {
            setScenarioStep(prev => Math.max(0, prev - 1));
          }
        }
      }
      return;
    }

    // Arrow up/down: select layer in overview
    if ((e.key === "ArrowUp" || e.key === "ArrowDown") && activeView() === "overview") {
      e.preventDefault();
      const current = selectedLayer() ?? 0;
      if (e.key === "ArrowUp") {
        setSelectedLayer(Math.min(7, current + 1) as LayerNumber);
      } else {
        setSelectedLayer(Math.max(1, current - 1) as LayerNumber);
      }
      return;
    }

    // Space: toggle packet monitor play/pause
    if (e.key === " " && activeView() === "security") {
      e.preventDefault();
      setPacketFlowRunning(prev => !prev);
      return;
    }

    // Escape: deselect layer
    if (e.key === "Escape") {
      setSelectedLayer(null);
      return;
    }
  }

  onMount(() => {
    document.addEventListener("keydown", handleKeyDown);
  });

  onCleanup(() => {
    document.removeEventListener("keydown", handleKeyDown);
  });

  return (
    <ErrorBoundary fallback={(err: Error) => <ErrorFallback error={err} />}>
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
    </ErrorBoundary>
  );
}
