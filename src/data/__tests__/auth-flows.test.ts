import { describe, it, expect } from "vitest";
import { OAUTH_STEPS, JWT_SECTIONS, TLS_DEEP_STEPS, AUTH_COMPARISON, RBAC_ROLES, ALL_PERMISSIONS } from "../auth-flows";

describe("OAUTH_STEPS", () => {
  it("has 8 steps", () => {
    expect(OAUTH_STEPS).toHaveLength(8);
  });

  it("step numbers are sequential 1-8", () => {
    OAUTH_STEPS.forEach((step, i) => {
      expect(step.stepNumber).toBe(i + 1);
    });
  });

  it("each step has valid actors", () => {
    const validActors = ["user", "client", "auth-server", "resource-server"];
    for (const step of OAUTH_STEPS) {
      expect(validActors).toContain(step.from);
      expect(validActors).toContain(step.to);
    }
  });

  it("each step has OSI layers in valid range", () => {
    for (const step of OAUTH_STEPS) {
      for (const layer of step.osiLayers) {
        expect(layer).toBeGreaterThanOrEqual(1);
        expect(layer).toBeLessThanOrEqual(7);
      }
    }
  });

  it("has bilingual descriptions", () => {
    for (const step of OAUTH_STEPS) {
      expect(step.description.length).toBeGreaterThan(0);
      expect(step.descriptionJa.length).toBeGreaterThan(0);
      expect(step.action.length).toBeGreaterThan(0);
      expect(step.actionJa.length).toBeGreaterThan(0);
    }
  });
});

describe("JWT_SECTIONS", () => {
  it("has exactly 3 sections (header, payload, signature)", () => {
    expect(JWT_SECTIONS).toHaveLength(3);
    expect(JWT_SECTIONS.map(s => s.name)).toEqual(["header", "payload", "signature"]);
  });

  it("each section has valid hex color", () => {
    for (const section of JWT_SECTIONS) {
      expect(section.color).toMatch(/^#[0-9a-fA-F]{6}$/);
    }
  });

  it("each section has non-empty encoded and decoded strings", () => {
    for (const section of JWT_SECTIONS) {
      expect(section.encoded.length).toBeGreaterThan(0);
      expect(section.decoded.length).toBeGreaterThan(0);
    }
  });

  it("each section has at least one field", () => {
    for (const section of JWT_SECTIONS) {
      expect(section.fields.length).toBeGreaterThan(0);
      for (const field of section.fields) {
        expect(field.key).toBeTruthy();
        expect(field.description).toBeTruthy();
        expect(field.descriptionJa).toBeTruthy();
      }
    }
  });
});

describe("TLS_DEEP_STEPS", () => {
  it("has 8 steps", () => {
    expect(TLS_DEEP_STEPS).toHaveLength(8);
  });

  it("step numbers are sequential", () => {
    TLS_DEEP_STEPS.forEach((step, i) => {
      expect(step.stepNumber).toBe(i + 1);
    });
  });

  it("each step has valid direction", () => {
    const validDirections = ["client-to-server", "server-to-client", "both"];
    for (const step of TLS_DEEP_STEPS) {
      expect(validDirections).toContain(step.direction);
    }
  });
});

describe("AUTH_COMPARISON", () => {
  it("has 6 comparison aspects", () => {
    expect(AUTH_COMPARISON).toHaveLength(6);
  });

  it("each aspect has session and token sides with pros/cons", () => {
    for (const item of AUTH_COMPARISON) {
      expect(item.aspect).toBeTruthy();
      expect(item.aspectJa).toBeTruthy();
      expect(item.session.value).toBeTruthy();
      expect(item.session.pros).toBeTruthy();
      expect(item.session.cons).toBeTruthy();
      expect(item.token.value).toBeTruthy();
      expect(item.token.pros).toBeTruthy();
      expect(item.token.cons).toBeTruthy();
    }
  });
});

describe("RBAC_ROLES", () => {
  it("has 4 roles", () => {
    expect(RBAC_ROLES).toHaveLength(4);
  });

  it("all permissions referenced by roles exist in ALL_PERMISSIONS", () => {
    for (const role of RBAC_ROLES) {
      for (const perm of role.permissions) {
        expect(ALL_PERMISSIONS).toContain(perm);
      }
    }
  });

  it("Admin has the most permissions", () => {
    const admin = RBAC_ROLES.find(r => r.name === "Admin")!;
    for (const role of RBAC_ROLES) {
      expect(admin.permissions.length).toBeGreaterThanOrEqual(role.permissions.length);
    }
  });
});
