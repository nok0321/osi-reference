import { Match, Switch, Suspense, lazy, onMount, onCleanup, createMemo, createEffect, ErrorBoundary } from "solid-js";
import { useNavigate, useLocation } from "@solidjs/router";
import { markViewVisited } from "./utils/progress";
import { selectedLayer, setSelectedLayer,
  encapStep, setEncapStep, encapDirection,
  scenarioStep, setScenarioStep, activeScenario } from "./state/app-state";
import { packetFlowRunning, setPacketFlowRunning } from "./state/security-state";
import { ENCAP_STEPS_DOWN, ENCAP_STEPS_UP } from "./data/encapsulation";
import { getScenario } from "./data/scenarios";
import { useI18n } from "./i18n/context";
import { useTheme } from "./theme/context";
import type { ViewType, LayerNumber } from "./types";
import TabBar from "./components/shared/TabBar";
import SearchBar from "./components/shared/SearchBar";
import QuizPanel from "./components/shared/QuizPanel";
import OverviewView from "./components/overview/OverviewView";
import EncapsulationView from "./components/encapsulation/EncapsulationView";
import ScenarioView from "./components/scenario/ScenarioView";
import ComparisonView from "./components/comparison/ComparisonView";
const AuthView = lazy(() => import("./components/auth/AuthView"));
const SecurityView = lazy(() => import("./components/security/SecurityView"));
import "./app.css";

const VIEW_ORDER: ViewType[] = ["overview", "encapsulation", "scenario", "comparison", "auth", "security"];

const PATH_TO_VIEW: Record<string, ViewType> = {
  "/overview": "overview",
  "/encapsulation": "encapsulation",
  "/scenario": "scenario",
  "/comparison": "comparison",
  "/auth": "auth",
  "/security": "security",
};

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
  const { theme, toggle: toggleTheme } = useTheme();
  const navigate = useNavigate();
  const location = useLocation();

  const activeView = createMemo<ViewType>(() => {
    const path = location.pathname;
    // Match exact or prefix (e.g. /auth/jwt → auth)
    for (const [prefix, view] of Object.entries(PATH_TO_VIEW)) {
      if (path === prefix || path.startsWith(prefix + "/")) return view;
    }
    return "overview";
  });

  // Track view visits for progress
  createEffect(() => {
    markViewVisited(activeView());
  });

  function navigateToView(view: ViewType) {
    if (view === "auth") {
      navigate("/auth/oauth");
    } else {
      navigate(`/${view}`);
    }
  }

  function handleKeyDown(e: KeyboardEvent) {
    const tag = (e.target as HTMLElement)?.tagName;
    if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;

    // 1-6: Switch views
    if (e.key >= "1" && e.key <= "6" && !e.ctrlKey && !e.metaKey && !e.altKey) {
      e.preventDefault();
      navigateToView(VIEW_ORDER[parseInt(e.key) - 1]);
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
    // Redirect root to /overview
    if (location.pathname === "/" || location.pathname === "") {
      navigate("/overview", { replace: true });
    }
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
          <div class="header-controls">
            <SearchBar />
            <button class="theme-toggle" onClick={toggleTheme} title={t("テーマ切替", "Toggle theme")} aria-label={t("テーマ切替", "Toggle theme")}>
              {theme() === "dark" ? "\u2600" : "\u263E"}
            </button>
            <button class="lang-toggle" onClick={toggle} aria-label={lang() === "ja" ? "Switch to English" : "日本語に切替"}>
              {lang() === "ja" ? "EN" : "JA"}
            </button>
          </div>
        </header>

        <TabBar
          activeTab={activeView()}
          onTabChange={navigateToView}
        />

        <div class="view-container">
          <Suspense fallback={<div class="view-loading mono">Loading...</div>}>
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
          </Suspense>
        </div>
        <QuizPanel />
      </div>
    </ErrorBoundary>
  );
}
