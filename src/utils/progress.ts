import type { ViewType } from "../types";

const STORAGE_KEY = "osi-progress";

export interface ViewProgress {
  visited: boolean;
  sections: string[];
  lastVisited?: number;
}

export type ProgressData = Record<ViewType, ViewProgress>;

const DEFAULT_PROGRESS: ProgressData = {
  overview: { visited: false, sections: [] },
  encapsulation: { visited: false, sections: [] },
  scenario: { visited: false, sections: [] },
  comparison: { visited: false, sections: [] },
  auth: { visited: false, sections: [] },
  security: { visited: false, sections: [] },
};

export function getProgress(): ProgressData {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      return { ...DEFAULT_PROGRESS, ...parsed };
    }
  } catch {}
  return { ...DEFAULT_PROGRESS };
}

function saveProgress(data: ProgressData) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
  } catch {}
}

export function markViewVisited(view: ViewType) {
  const data = getProgress();
  data[view] = {
    ...data[view],
    visited: true,
    lastVisited: Date.now(),
  };
  saveProgress(data);
}

export function markSectionViewed(view: ViewType, section: string) {
  const data = getProgress();
  const current = data[view];
  if (!current.sections.includes(section)) {
    data[view] = {
      ...current,
      visited: true,
      sections: [...current.sections, section],
      lastVisited: Date.now(),
    };
    saveProgress(data);
  }
}

export function getViewCompletionPercent(view: ViewType, totalSections: number): number {
  if (totalSections === 0) return 0;
  const data = getProgress();
  return Math.round((data[view].sections.length / totalSections) * 100);
}

export function resetProgress() {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {}
}
