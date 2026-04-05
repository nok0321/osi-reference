import { describe, it, expect } from "vitest";
import { evaluatePacket } from "../firewall-eval";
import type { SecurityPacket, FirewallRule } from "../../types/security";

function makePacket(overrides: Partial<SecurityPacket> = {}): SecurityPacket {
  return {
    id: "test-1",
    protocol: "HTTP",
    sourceIp: "192.168.1.10",
    destIp: "93.184.216.34",
    port: 80,
    encrypted: false,
    osiLayer: 7,
    status: "safe",
    timestamp: Date.now(),
    ...overrides,
  };
}

const RULES: FirewallRule[] = [
  { id: "r1", osiLayer: 7, direction: "inbound", protocol: "HTTP", port: 80, action: "allow", description: "", descriptionJa: "" },
  { id: "r2", osiLayer: 7, direction: "inbound", protocol: "HTTPS", port: 443, action: "allow", description: "", descriptionJa: "" },
  { id: "r3", osiLayer: 4, direction: "inbound", protocol: "TCP", port: 25, action: "deny", description: "", descriptionJa: "" },
  { id: "r4", osiLayer: 3, direction: "inbound", protocol: "ICMP", action: "allow", description: "", descriptionJa: "" },
  { id: "r5", osiLayer: 4, direction: "outbound", protocol: "TCP", action: "allow", description: "", descriptionJa: "" },
];

describe("evaluatePacket", () => {
  it("matches HTTP on port 80 → allow", () => {
    expect(evaluatePacket(makePacket({ protocol: "HTTP", port: 80 }), RULES)).toBe("allow");
  });

  it("matches HTTPS on port 443 → allow", () => {
    expect(evaluatePacket(makePacket({ protocol: "HTTPS", port: 443 }), RULES)).toBe("allow");
  });

  it("matches TCP port 25 → deny", () => {
    expect(evaluatePacket(makePacket({ protocol: "TCP", port: 25 }), RULES)).toBe("deny");
  });

  it("ICMP matches rule with no port constraint → allow", () => {
    expect(evaluatePacket(makePacket({ protocol: "ICMP", port: 0 }), RULES)).toBe("allow");
  });

  it("returns deny when no rule matches (default deny)", () => {
    // DNS port 53 matches TCP catch-all rule (r5), so use a rule set without it
    const strictRules = RULES.filter(r => r.id !== "r5");
    expect(evaluatePacket(makePacket({ protocol: "DNS", port: 53 }), strictRules)).toBe("deny");
  });

  it("first match wins (rule ordering)", () => {
    const orderedRules: FirewallRule[] = [
      { id: "deny-first", osiLayer: 7, direction: "inbound", protocol: "HTTP", port: 80, action: "deny", description: "", descriptionJa: "" },
      { id: "allow-second", osiLayer: 7, direction: "inbound", protocol: "HTTP", port: 80, action: "allow", description: "", descriptionJa: "" },
    ];
    expect(evaluatePacket(makePacket({ protocol: "HTTP", port: 80 }), orderedRules)).toBe("deny");
  });

  it("TCP catch-all matches any protocol on matching port", () => {
    // TCP rule with no port constraint (r5) should match protocols that are TCP-based
    // but only after specific rules are checked first
    expect(evaluatePacket(makePacket({ protocol: "SSH", port: 22 }), RULES)).toBe("allow");
  });

  it("returns deny with empty rules", () => {
    expect(evaluatePacket(makePacket(), [])).toBe("deny");
  });
});
