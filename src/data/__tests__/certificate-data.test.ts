import { describe, it, expect } from "vitest";
import { generatePacket, DEFAULT_FW_RULES } from "../certificate-data";

describe("generatePacket", () => {
  it("returns a valid SecurityPacket shape", () => {
    const pkt = generatePacket();
    expect(pkt).toHaveProperty("id");
    expect(pkt).toHaveProperty("protocol");
    expect(pkt).toHaveProperty("sourceIp");
    expect(pkt).toHaveProperty("destIp");
    expect(pkt).toHaveProperty("port");
    expect(typeof pkt.encrypted).toBe("boolean");
    expect(pkt).toHaveProperty("osiLayer");
    expect(pkt).toHaveProperty("status");
    expect(pkt).toHaveProperty("timestamp");
  });

  it("generates unique IDs", () => {
    const ids = new Set(Array.from({ length: 50 }, () => generatePacket().id));
    expect(ids.size).toBe(50);
  });

  it("returns valid status values", () => {
    const validStatuses = ["safe", "warning", "threat"];
    for (let i = 0; i < 100; i++) {
      expect(validStatuses).toContain(generatePacket().status);
    }
  });

  it("marks encrypted protocols correctly", () => {
    const encryptedProtos = ["HTTPS", "TLS", "SSH"];
    for (let i = 0; i < 200; i++) {
      const pkt = generatePacket();
      if (encryptedProtos.includes(pkt.protocol)) {
        expect(pkt.encrypted).toBe(true);
      } else {
        expect(pkt.encrypted).toBe(false);
      }
    }
  });

  it("maps protocols to correct OSI layers", () => {
    const expectedLayers: Record<string, number> = {
      TCP: 4, UDP: 4, HTTP: 7, HTTPS: 7, DNS: 7, SSH: 7, TLS: 6, ICMP: 3,
    };
    for (let i = 0; i < 200; i++) {
      const pkt = generatePacket();
      expect(pkt.osiLayer).toBe(expectedLayers[pkt.protocol]);
    }
  });

  it("produces roughly expected status distribution over 1000 packets", () => {
    const counts = { safe: 0, warning: 0, threat: 0 };
    const n = 1000;
    for (let i = 0; i < n; i++) {
      counts[generatePacket().status]++;
    }
    // Allow wide tolerance for randomness
    expect(counts.safe).toBeGreaterThan(n * 0.45);
    expect(counts.safe).toBeLessThan(n * 0.85);
    expect(counts.warning).toBeGreaterThan(n * 0.08);
    expect(counts.threat).toBeGreaterThan(n * 0.01);
  });
});

describe("DEFAULT_FW_RULES", () => {
  it("has 6 rules", () => {
    expect(DEFAULT_FW_RULES).toHaveLength(6);
  });

  it("has unique IDs", () => {
    const ids = DEFAULT_FW_RULES.map(r => r.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("each rule has required fields", () => {
    for (const rule of DEFAULT_FW_RULES) {
      expect(rule).toHaveProperty("id");
      expect(rule).toHaveProperty("osiLayer");
      expect(rule).toHaveProperty("direction");
      expect(rule).toHaveProperty("protocol");
      expect(rule).toHaveProperty("action");
      expect(rule).toHaveProperty("description");
      expect(rule).toHaveProperty("descriptionJa");
      expect(["allow", "deny"]).toContain(rule.action);
      expect(["inbound", "outbound"]).toContain(rule.direction);
    }
  });
});
