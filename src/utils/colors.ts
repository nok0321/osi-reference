import type { LayerNumber } from "../types";

export interface LayerColor {
  bg: string;
  text: string;
  label: string;
  labelJa: string;
}

export const LAYER_COLORS: Record<LayerNumber, LayerColor> = {
  1: { bg: "#D4380D", text: "#FFF", label: "Physical", labelJa: "物理" },
  2: { bg: "#CF8B00", text: "#FFF", label: "Data Link", labelJa: "データリンク" },
  3: { bg: "#7CB305", text: "#FFF", label: "Network", labelJa: "ネットワーク" },
  4: { bg: "#08979C", text: "#FFF", label: "Transport", labelJa: "トランスポート" },
  5: { bg: "#1677FF", text: "#FFF", label: "Session", labelJa: "セッション" },
  6: { bg: "#531DAB", text: "#FFF", label: "Presentation", labelJa: "プレゼンテーション" },
  7: { bg: "#C41D7F", text: "#FFF", label: "Application", labelJa: "アプリケーション" },
} as const;

export function getLayerColor(layer: LayerNumber): LayerColor {
  return LAYER_COLORS[layer];
}
