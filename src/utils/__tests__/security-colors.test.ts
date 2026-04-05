import { describe, it, expect } from "vitest";
import { SECURITY_COLORS, getStatusColor, getStatusDimColor } from "../security-colors";
import type { SecurityStatus } from "../security-colors";

describe("SECURITY_COLORS", () => {
  it("has all expected keys", () => {
    expect(SECURITY_COLORS.safe).toBeTruthy();
    expect(SECURITY_COLORS.warning).toBeTruthy();
    expect(SECURITY_COLORS.threat).toBeTruthy();
    expect(SECURITY_COLORS.encrypted).toBeTruthy();
    expect(SECURITY_COLORS.safeDim).toBeTruthy();
    expect(SECURITY_COLORS.warningDim).toBeTruthy();
    expect(SECURITY_COLORS.threatDim).toBeTruthy();
    expect(SECURITY_COLORS.encryptedDim).toBeTruthy();
  });

  it("primary colors are valid hex", () => {
    expect(SECURITY_COLORS.safe).toMatch(/^#[0-9a-fA-F]{6}$/);
    expect(SECURITY_COLORS.warning).toMatch(/^#[0-9a-fA-F]{6}$/);
    expect(SECURITY_COLORS.threat).toMatch(/^#[0-9a-fA-F]{6}$/);
    expect(SECURITY_COLORS.encrypted).toMatch(/^#[0-9a-fA-F]{6}$/);
  });

  it("dim colors are valid rgba", () => {
    expect(SECURITY_COLORS.safeDim).toMatch(/^rgba\(/);
    expect(SECURITY_COLORS.warningDim).toMatch(/^rgba\(/);
    expect(SECURITY_COLORS.threatDim).toMatch(/^rgba\(/);
    expect(SECURITY_COLORS.encryptedDim).toMatch(/^rgba\(/);
  });
});

describe("getStatusColor", () => {
  it("returns correct color for each status", () => {
    const statuses: SecurityStatus[] = ["safe", "warning", "threat"];
    for (const status of statuses) {
      expect(getStatusColor(status)).toBe(SECURITY_COLORS[status]);
    }
  });
});

describe("getStatusDimColor", () => {
  it("returns correct dim color for each status", () => {
    const statuses: SecurityStatus[] = ["safe", "warning", "threat"];
    for (const status of statuses) {
      expect(getStatusDimColor(status)).toBe(SECURITY_COLORS[`${status}Dim`]);
    }
  });
});
