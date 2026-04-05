import type { SecurityPacket, FirewallRule } from "../types/security";

/**
 * Evaluate a packet against firewall rules (first-match wins).
 * Returns "deny" if no rule matches (default deny policy).
 */
export function evaluatePacket(
  packet: SecurityPacket,
  rules: FirewallRule[],
): "allow" | "deny" {
  const match = rules.find(rule => {
    // Protocol match: exact match, or TCP/UDP matches any TCP/UDP-based protocol
    if (rule.protocol !== packet.protocol && rule.protocol !== "TCP" && rule.protocol !== "UDP") {
      return false;
    }
    // Port match: skip if rule has no port constraint
    if (rule.port !== undefined && rule.port !== packet.port) {
      return false;
    }
    return true;
  });

  return match ? match.action : "deny";
}
