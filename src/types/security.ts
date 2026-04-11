import type { LayerNumber } from "./index";

export type AuthSubView =
  | "oauth" | "jwt" | "tls-deep" | "session-vs-token" | "rbac"
  | "auth-methods" | "oidc-saml" | "fido2" | "kerberos" | "sso-idp-apikey"
  | "mfa" | "passkey";

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

export interface AuthMethodInfo {
  id: string;
  name: string;
  nameJa: string;
  category: "knowledge" | "possession" | "inherence" | "multi";
  categoryLabel: string;
  categoryLabelJa: string;
  description: string;
  descriptionJa: string;
  strengths: string[];
  strengthsJa: string[];
  weaknesses: string[];
  weaknessesJa: string[];
  osiLayers: LayerNumber[];
  icon: string;
}

export interface ProtocolFlowStep {
  stepNumber: number;
  from: string;
  to: string;
  action: string;
  actionJa: string;
  description: string;
  descriptionJa: string;
  dataPayload?: string;
  osiLayer: LayerNumber;
}

export interface ProtocolActor {
  id: string;
  name: string;
  nameJa: string;
  color: string;
}

export interface KerberosStep {
  stepNumber: number;
  from: "client" | "kdc-as" | "kdc-tgs" | "service";
  to: "client" | "kdc-as" | "kdc-tgs" | "service";
  action: string;
  actionJa: string;
  description: string;
  descriptionJa: string;
  ticket?: string;
  osiLayer: LayerNumber;
}

export interface AclEntry {
  subject: string;
  resource: string;
  permissions: ("read" | "write" | "execute" | "delete")[];
  effect: "allow" | "deny";
}

export interface PolicyRule {
  id: string;
  name: string;
  nameJa: string;
  effect: "allow" | "deny";
  principal: string;
  action: string;
  resource: string;
  condition: string;
  conditionJa: string;
}

export interface SsoPattern {
  id: string;
  name: string;
  nameJa: string;
  description: string;
  descriptionJa: string;
  flow: string[];
  flowJa: string[];
}

export interface IdpInfo {
  id: string;
  name: string;
  nameJa: string;
  protocol: string;
  description: string;
  descriptionJa: string;
  examples: string[];
  color: string;
}

export interface ApiKeyPattern {
  id: string;
  name: string;
  nameJa: string;
  method: string;
  description: string;
  descriptionJa: string;
  example: string;
  security: "low" | "medium" | "high";
}
