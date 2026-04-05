import { describe, it, expect } from "vitest";
import { ENCAP_STEPS_DOWN, ENCAP_STEPS_UP } from "../encapsulation";

describe("ENCAP_STEPS_DOWN", () => {
  it("has 5 steps", () => {
    expect(ENCAP_STEPS_DOWN).toHaveLength(5);
  });

  it("starts at L7 and ends at L1", () => {
    expect(ENCAP_STEPS_DOWN[0].layerNumber).toBe(7);
    expect(ENCAP_STEPS_DOWN[ENCAP_STEPS_DOWN.length - 1].layerNumber).toBe(1);
  });

  it("layer numbers are in descending order", () => {
    for (let i = 1; i < ENCAP_STEPS_DOWN.length; i++) {
      expect(ENCAP_STEPS_DOWN[i].layerNumber).toBeLessThan(ENCAP_STEPS_DOWN[i - 1].layerNumber);
    }
  });

  it("each step has required fields", () => {
    for (const step of ENCAP_STEPS_DOWN) {
      expect(step.layerNumber).toBeGreaterThanOrEqual(1);
      expect(step.layerNumber).toBeLessThanOrEqual(7);
      expect(step.action).toBe("add-header");
      expect(step.headerName).toBeTruthy();
      expect(typeof step.headerBytes).toBe("number");
      expect(step.description).toBeTruthy();
      expect(step.descriptionJa).toBeTruthy();
      expect(step.resultPdu).toBeTruthy();
      expect(step.resultPduJa).toBeTruthy();
      expect(Array.isArray(step.fields)).toBe(true);
      expect(step.fields.length).toBeGreaterThan(0);
    }
  });

  it("each field has required properties", () => {
    for (const step of ENCAP_STEPS_DOWN) {
      for (const field of step.fields) {
        expect(field.name).toBeTruthy();
        expect(typeof field.bits).toBe("number");
        expect(field.description).toBeTruthy();
        expect(field.descriptionJa).toBeTruthy();
      }
    }
  });
});

describe("ENCAP_STEPS_UP", () => {
  it("has same number of steps as DOWN", () => {
    expect(ENCAP_STEPS_UP).toHaveLength(ENCAP_STEPS_DOWN.length);
  });

  it("starts at L1 and ends at L7", () => {
    expect(ENCAP_STEPS_UP[0].layerNumber).toBe(1);
    expect(ENCAP_STEPS_UP[ENCAP_STEPS_UP.length - 1].layerNumber).toBe(7);
  });

  it("all steps have remove-header action", () => {
    for (const step of ENCAP_STEPS_UP) {
      expect(step.action).toBe("remove-header");
    }
  });

  it("layer numbers are in ascending order", () => {
    for (let i = 1; i < ENCAP_STEPS_UP.length; i++) {
      expect(ENCAP_STEPS_UP[i].layerNumber).toBeGreaterThan(ENCAP_STEPS_UP[i - 1].layerNumber);
    }
  });
});
