export const SECURITY_COLORS = {
  safe: "#22C55E",
  safeDim: "rgba(34, 197, 94, 0.15)",
  warning: "#F59E0B",
  warningDim: "rgba(245, 158, 11, 0.15)",
  threat: "#EF4444",
  threatDim: "rgba(239, 68, 68, 0.15)",
  encrypted: "#3B82F6",
  encryptedDim: "rgba(59, 130, 246, 0.15)",
} as const;

export type SecurityStatus = "safe" | "warning" | "threat";

export function getStatusColor(status: SecurityStatus): string {
  return SECURITY_COLORS[status];
}

export function getStatusDimColor(status: SecurityStatus): string {
  return SECURITY_COLORS[`${status}Dim` as keyof typeof SECURITY_COLORS] as string;
}
