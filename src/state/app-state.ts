import { createSignal } from "solid-js";
import type { ViewType, LayerNumber, ScenarioType, EncapDirection } from "../types";

export const [activeView, setActiveView] = createSignal<ViewType>("overview");
export const [selectedLayer, setSelectedLayer] = createSignal<LayerNumber | null>(null);
export const [encapStep, setEncapStep] = createSignal(0);
export const [encapDirection, setEncapDirection] = createSignal<EncapDirection>("down");
export const [activeScenario, setActiveScenario] = createSignal<ScenarioType>("http");
export const [scenarioStep, setScenarioStep] = createSignal(0);
export const [hoveredMapping, setHoveredMapping] = createSignal<LayerNumber | null>(null);
