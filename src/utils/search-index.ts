import type { ViewType } from "../types";
import { OSI_LAYERS } from "../data/layers";
import { OAUTH_STEPS, TLS_DEEP_STEPS, RBAC_ROLES, ABAC_POLICIES } from "../data/auth-flows";
import { OSI_ATTACKS } from "../data/security-attacks";

export interface SearchResult {
  title: string;
  titleJa: string;
  description: string;
  descriptionJa: string;
  view: ViewType;
  path: string;
}

let cachedIndex: SearchResult[] | null = null;

function buildIndex(): SearchResult[] {
  const results: SearchResult[] = [];

  // OSI Layers
  for (const layer of OSI_LAYERS) {
    results.push({
      title: `L${layer.number}: ${layer.name}`,
      titleJa: `L${layer.number}: ${layer.nameJa}`,
      description: layer.role,
      descriptionJa: layer.roleJa,
      view: "overview",
      path: "/overview",
    });
  }

  // OAuth steps
  for (const step of OAUTH_STEPS) {
    results.push({
      title: `OAuth: ${step.action}`,
      titleJa: `OAuth: ${step.actionJa}`,
      description: step.description,
      descriptionJa: step.descriptionJa,
      view: "auth",
      path: "/auth/oauth",
    });
  }

  // TLS steps
  for (const step of TLS_DEEP_STEPS) {
    results.push({
      title: `TLS: ${step.name}`,
      titleJa: `TLS: ${step.nameJa}`,
      description: step.description,
      descriptionJa: step.descriptionJa,
      view: "auth",
      path: "/auth/tls-deep",
    });
  }

  // RBAC roles
  for (const role of RBAC_ROLES) {
    results.push({
      title: `RBAC: ${role.name}`,
      titleJa: `RBAC: ${role.nameJa}`,
      description: `Permissions: ${role.permissions.join(", ")}`,
      descriptionJa: `権限: ${role.permissions.join(", ")}`,
      view: "auth",
      path: "/auth/rbac",
    });
  }

  // Security attacks
  for (const attack of OSI_ATTACKS) {
    results.push({
      title: `L${attack.layer}: ${attack.name}`,
      titleJa: `L${attack.layer}: ${attack.nameJa}`,
      description: attack.description,
      descriptionJa: attack.descriptionJa,
      view: "security",
      path: "/security",
    });
  }

  return results;
}

export function getSearchIndex(): SearchResult[] {
  if (!cachedIndex) {
    cachedIndex = buildIndex();
  }
  return cachedIndex;
}

export function search(query: string): SearchResult[] {
  if (!query.trim()) return [];
  const lower = query.toLowerCase();
  return getSearchIndex().filter(item =>
    item.title.toLowerCase().includes(lower) ||
    item.titleJa.includes(lower) ||
    item.description.toLowerCase().includes(lower) ||
    item.descriptionJa.includes(lower)
  );
}
