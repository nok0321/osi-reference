import { createSignal } from "solid-js";
import { useSearchParams } from "@solidjs/router";
import type { AttackScenarioMeta, AttackResult } from "../../shared/api-types";
import type { AuthSubView } from "../types/security";

export type ViewMode = "defender" | "attacker";

const [viewModeMap, setViewModeMap] = createSignal<Record<string, ViewMode>>({});

export function getViewMode(tabId: AuthSubView): ViewMode {
  return viewModeMap()[tabId] ?? "defender";
}

export function setViewMode(tabId: AuthSubView, mode: ViewMode): void {
  setViewModeMap((prev) => ({ ...prev, [tabId]: mode }));
}

export const [selectedScenario, setSelectedScenario] = createSignal<AttackScenarioMeta | null>(null);
export const [currentResult, setCurrentResult] = createSignal<AttackResult | null>(null);
export const [attackRunning, setAttackRunning] = createSignal(false);

export function resetAttackState(): void {
  setSelectedScenario(null);
  setCurrentResult(null);
  setAttackRunning(false);
}

export function useViewModeSync() {
  const [params, setParams] = useSearchParams();
  return { params, setParams };
}
