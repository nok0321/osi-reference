import { describe, it, expect } from "vitest";
import { LAYER_COLORS, getLayerColor } from "../colors";
import type { LayerNumber } from "../../types";

describe("LAYER_COLORS", () => {
  it("has all 7 layers", () => {
    for (let i = 1; i <= 7; i++) {
      expect(LAYER_COLORS[i as LayerNumber]).toBeDefined();
    }
  });

  it("each layer has valid hex bg color", () => {
    for (let i = 1; i <= 7; i++) {
      expect(LAYER_COLORS[i as LayerNumber].bg).toMatch(/^#[0-9a-fA-F]{6}$/);
    }
  });

  it("each layer has text, label, and labelJa", () => {
    for (let i = 1; i <= 7; i++) {
      const color = LAYER_COLORS[i as LayerNumber];
      expect(color.text).toBeTruthy();
      expect(color.label).toBeTruthy();
      expect(color.labelJa).toBeTruthy();
    }
  });
});

describe("getLayerColor", () => {
  it("returns the correct color for each layer", () => {
    expect(getLayerColor(1).label).toBe("Physical");
    expect(getLayerColor(4).label).toBe("Transport");
    expect(getLayerColor(7).label).toBe("Application");
  });
});
