import { createSignal } from "solid-js";
import { useSearchParams } from "@solidjs/router";
import type { AttackScenarioMeta, AttackResult } from "../../shared/api-types";

export type ViewMode = "defender" | "attacker";

export const [viewMode, setViewMode] = createSignal<ViewMode>("defender");
export const [selectedScenario, setSelectedScenario] = createSignal<AttackScenarioMeta | null>(null);
export const [currentResult, setCurrentResult] = createSignal<AttackResult | null>(null);
export const [attackRunning, setAttackRunning] = createSignal(false);

export function resetAttackState(): void {
  setSelectedScenario(null);
  setCurrentResult(null);
  setAttackRunning(false);
}

/**
 * ViewModeToggle コンポーネント内の createEffect で URL ?view= と双方向同期するためのヘルパー。
 * useSearchParams はコンポーネント内でのみ呼べるため、このファイルでは返すだけにする。
 */
export function useViewModeSync() {
  const [params, setParams] = useSearchParams();
  return { params, setParams };
}
