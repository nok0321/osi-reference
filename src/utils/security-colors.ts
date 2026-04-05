export const SECURITY_COLORS = {
  safe: "#52c41a",
  safeDim: "rgba(82, 196, 26, 0.15)",
  warning: "#faad14",
  warningDim: "rgba(250, 173, 20, 0.15)",
  threat: "#ff4d4f",
  threatDim: "rgba(255, 77, 79, 0.15)",
  encrypted: "#1677ff",
  encryptedDim: "rgba(22, 119, 255, 0.15)",
} as const;

export type SecurityStatus = "safe" | "warning" | "threat";

export function getStatusColor(status: SecurityStatus): string {
  return SECURITY_COLORS[status];
}

export function getStatusDimColor(status: SecurityStatus): string {
  return SECURITY_COLORS[`${status}Dim` as keyof typeof SECURITY_COLORS] as string;
}
