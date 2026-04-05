import type { CertificateNode, SecurityPacket, FirewallRule } from "../types/security";
import type { LayerNumber } from "../types";

export const CERTIFICATE_CHAIN: CertificateNode = {
  subject: "Root CA",
  issuer: "Root CA (Self-signed)",
  validFrom: "2020-01-01",
  validTo: "2035-12-31",
  type: "root",
  algorithm: "RSA-SHA256",
  keySize: 4096,
  children: [
    {
      subject: "Intermediate CA",
      issuer: "Root CA",
      validFrom: "2022-01-01",
      validTo: "2030-12-31",
      type: "intermediate",
      algorithm: "ECDSA-SHA384",
      keySize: 384,
      children: [
        {
          subject: "*.example.com",
          issuer: "Intermediate CA",
          validFrom: "2026-01-01",
          validTo: "2027-01-01",
          type: "leaf",
          algorithm: "ECDSA-SHA256",
          keySize: 256,
        },
      ],
    },
  ],
};

export const EXPIRED_CERTIFICATE_CHAIN: CertificateNode = {
  subject: "Root CA",
  issuer: "Root CA (Self-signed)",
  validFrom: "2020-01-01",
  validTo: "2035-12-31",
  type: "root",
  algorithm: "RSA-SHA256",
  keySize: 4096,
  children: [
    {
      subject: "Intermediate CA",
      issuer: "Root CA",
      validFrom: "2022-01-01",
      validTo: "2030-12-31",
      type: "intermediate",
      algorithm: "ECDSA-SHA384",
      keySize: 384,
      children: [
        {
          subject: "*.example.com",
          issuer: "Intermediate CA",
          validFrom: "2023-01-01",
          validTo: "2024-01-01",
          type: "leaf",
          algorithm: "ECDSA-SHA256",
          keySize: 256,
        },
      ],
    },
  ],
};

// Packet generation templates
const PROTOCOLS = ["TCP", "UDP", "HTTP", "HTTPS", "DNS", "SSH", "TLS", "ICMP"];
const SOURCE_IPS = ["192.168.1.10", "192.168.1.25", "10.0.0.5", "172.16.0.100", "203.0.113.50"];
const DEST_IPS = ["93.184.216.34", "8.8.8.8", "1.1.1.1", "151.101.1.140", "104.26.10.78"];
const PORTS = [80, 443, 53, 22, 8080, 3000, 25, 993];

const STATUS_WEIGHTS: Array<{ status: SecurityPacket["status"]; weight: number }> = [
  { status: "safe", weight: 0.65 },
  { status: "warning", weight: 0.25 },
  { status: "threat", weight: 0.10 },
];

const LAYER_BY_PROTOCOL: Record<string, LayerNumber> = {
  TCP: 4, UDP: 4, HTTP: 7, HTTPS: 7, DNS: 7, SSH: 7, TLS: 6, ICMP: 3,
};

let packetCounter = 0;

function weightedRandom<T>(items: Array<{ status: T; weight: number }>): T {
  const r = Math.random();
  let cum = 0;
  for (const item of items) {
    cum += item.weight;
    if (r < cum) return item.status;
  }
  return items[items.length - 1].status;
}

export function generatePacket(): SecurityPacket {
  const protocol = PROTOCOLS[Math.floor(Math.random() * PROTOCOLS.length)];
  const encrypted = ["HTTPS", "TLS", "SSH"].includes(protocol);
  return {
    id: `pkt-${++packetCounter}`,
    protocol,
    sourceIp: SOURCE_IPS[Math.floor(Math.random() * SOURCE_IPS.length)],
    destIp: DEST_IPS[Math.floor(Math.random() * DEST_IPS.length)],
    port: PORTS[Math.floor(Math.random() * PORTS.length)],
    encrypted,
    osiLayer: LAYER_BY_PROTOCOL[protocol] ?? 4,
    status: weightedRandom(STATUS_WEIGHTS),
    timestamp: Date.now(),
  };
}

// Firewall rule presets
export const DEFAULT_FW_RULES: FirewallRule[] = [
  {
    id: "fw-1", osiLayer: 7, direction: "inbound", protocol: "HTTP",
    port: 80, action: "allow",
    description: "Allow inbound HTTP traffic", descriptionJa: "受信HTTPトラフィックを許可",
  },
  {
    id: "fw-2", osiLayer: 7, direction: "inbound", protocol: "HTTPS",
    port: 443, action: "allow",
    description: "Allow inbound HTTPS traffic", descriptionJa: "受信HTTPSトラフィックを許可",
  },
  {
    id: "fw-3", osiLayer: 7, direction: "inbound", protocol: "SSH",
    port: 22, sourceRange: "10.0.0.0/8", action: "allow",
    description: "Allow SSH from internal network", descriptionJa: "内部ネットワークからのSSHを許可",
  },
  {
    id: "fw-4", osiLayer: 4, direction: "inbound", protocol: "TCP",
    port: 25, action: "deny",
    description: "Block inbound SMTP (anti-spam)", descriptionJa: "受信SMTPをブロック (スパム対策)",
  },
  {
    id: "fw-5", osiLayer: 3, direction: "inbound", protocol: "ICMP",
    action: "allow",
    description: "Allow ICMP (ping)", descriptionJa: "ICMP (ping) を許可",
  },
  {
    id: "fw-6", osiLayer: 4, direction: "outbound", protocol: "TCP",
    action: "allow",
    description: "Allow all outbound TCP", descriptionJa: "すべての送信TCPを許可",
  },
];
