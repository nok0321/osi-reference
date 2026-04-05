import type { LayerNumber } from "./index";

export type AuthSubView = "oauth" | "jwt" | "tls-deep" | "session-vs-token" | "rbac";

export interface OAuthStep {
  stepNumber: number;
  from: "user" | "client" | "auth-server" | "resource-server";
  to: "user" | "client" | "auth-server" | "resource-server";
  action: string;
  actionJa: string;
  description: string;
  descriptionJa: string;
  dataPayload?: string;
  osiLayers: LayerNumber[];
  isSecure: boolean;
}

export interface JwtSection {
  name: "header" | "payload" | "signature";
  color: string;
  fields: JwtField[];
  encoded: string;
  decoded: string;
}

export interface JwtField {
  key: string;
  value: string;
  description: string;
  descriptionJa: string;
}

export interface TlsStep {
  stepNumber: number;
  name: string;
  nameJa: string;
  direction: "client-to-server" | "server-to-client" | "both";
  description: string;
  descriptionJa: string;
  cryptoDetails?: string;
  cryptoDetailsJa?: string;
  osiLayer: LayerNumber;
  dataFields: { name: string; value: string }[];
}

export interface AuthMethodComparison {
  aspect: string;
  aspectJa: string;
  session: { value: string; valueJa: string; pros: string; prosJa: string; cons: string; consJa: string };
  token: { value: string; valueJa: string; pros: string; prosJa: string; cons: string; consJa: string };
}

export interface RbacRole {
  name: string;
  nameJa: string;
  permissions: string[];
  color: string;
}

export interface AbacPolicy {
  subject: string;
  resource: string;
  action: string;
  condition: string;
  conditionJa: string;
  result: "allow" | "deny";
}

export interface SecurityPacket {
  id: string;
  protocol: string;
  sourceIp: string;
  destIp: string;
  port: number;
  encrypted: boolean;
  osiLayer: LayerNumber;
  status: "safe" | "warning" | "threat";
  timestamp: number;
}

export interface CertificateNode {
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  type: "root" | "intermediate" | "leaf";
  algorithm: string;
  keySize: number;
  children?: CertificateNode[];
}

export interface FirewallRule {
  id: string;
  osiLayer: LayerNumber;
  direction: "inbound" | "outbound";
  protocol: string;
  port?: number;
  sourceRange?: string;
  action: "allow" | "deny";
  description: string;
  descriptionJa: string;
}

export interface OsiAttack {
  name: string;
  nameJa: string;
  layer: LayerNumber;
  category: string;
  categoryJa: string;
  description: string;
  descriptionJa: string;
  mitigation: string;
  mitigationJa: string;
  severity: "low" | "medium" | "high" | "critical";
}
