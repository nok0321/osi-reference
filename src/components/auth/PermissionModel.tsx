import { For, Show, createSignal } from "solid-js";
import { useI18n } from "../../i18n/context";
import { RBAC_ROLES, ALL_PERMISSIONS, ABAC_POLICIES } from "../../data/auth-flows";
import type { RbacRole, AbacPolicy } from "../../types/security";
import "./PermissionModel.css";

export default function PermissionModel() {
  const { t } = useI18n();
  const [mode, setMode] = createSignal<"rbac" | "abac">("rbac");
  const [selectedRole, setSelectedRole] = createSignal<string | null>(null);

  function hasPermission(role: RbacRole, perm: string): boolean {
    return role.permissions.includes(perm);
  }

  return (
    <div class="permission-model">
      <div class="perm-toggle">
        <button
          class="perm-mode-btn"
          classList={{ active: mode() === "rbac" }}
          onClick={() => setMode("rbac")}
        >
          RBAC
        </button>
        <button
          class="perm-mode-btn"
          classList={{ active: mode() === "abac" }}
          onClick={() => setMode("abac")}
        >
          ABAC
        </button>
      </div>

      <Show when={mode() === "rbac"}>
        <div class="rbac-view">
          <div class="rbac-desc">
            <p>
              {t(
                "ロールベースアクセス制御: ユーザーにロールを割り当て、ロールに権限を付与。シンプルで管理しやすい。",
                "Role-Based Access Control: Assign roles to users, grant permissions to roles. Simple and manageable."
              )}
            </p>
          </div>

          {/* Role cards */}
          <div class="rbac-roles">
            <For each={RBAC_ROLES}>
              {(role: RbacRole) => (
                <div
                  class="role-card"
                  classList={{ selected: selectedRole() === role.name }}
                  style={{ "--role-color": role.color }}
                  onClick={() => setSelectedRole(prev => prev === role.name ? null : role.name)}
                >
                  <div class="role-header">
                    <span class="role-dot" style={{ background: role.color }} />
                    <span class="role-name">{t(role.nameJa, role.name)}</span>
                    <span class="role-count mono">{role.permissions.length}</span>
                  </div>
                  <div class="role-perms">
                    <For each={role.permissions}>
                      {(perm: string) => (
                        <span class="role-perm mono">{perm}</span>
                      )}
                    </For>
                  </div>
                </div>
              )}
            </For>
          </div>

          {/* Permission matrix */}
          <div class="rbac-matrix">
            <div class="matrix-title mono">{t("権限マトリクス", "Permission Matrix")}</div>
            <div class="matrix-grid">
              <div class="matrix-header">
                <span class="matrix-corner" />
                <For each={RBAC_ROLES}>
                  {(role: RbacRole) => (
                    <span
                      class="matrix-role-label mono"
                      style={{ color: role.color }}
                    >
                      {t(role.nameJa, role.name)}
                    </span>
                  )}
                </For>
              </div>
              <For each={ALL_PERMISSIONS}>
                {(perm: string) => (
                  <div class="matrix-row">
                    <span class="matrix-perm mono">{perm}</span>
                    <For each={RBAC_ROLES}>
                      {(role: RbacRole) => (
                        <span
                          class="matrix-cell"
                          classList={{
                            granted: hasPermission(role, perm),
                            highlighted: selectedRole() === role.name && hasPermission(role, perm),
                          }}
                        >
                          {hasPermission(role, perm) ? "✓" : "·"}
                        </span>
                      )}
                    </For>
                  </div>
                )}
              </For>
            </div>
          </div>
        </div>
      </Show>

      <Show when={mode() === "abac"}>
        <div class="abac-view">
          <div class="abac-desc">
            <p>
              {t(
                "属性ベースアクセス制御: サブジェクト、リソース、アクション、環境の属性に基づいてポリシーを評価。きめ細かな制御が可能。",
                "Attribute-Based Access Control: Evaluate policies based on attributes of subject, resource, action, and environment. Enables fine-grained control."
              )}
            </p>
          </div>

          <div class="abac-policies">
            <For each={ABAC_POLICIES}>
              {(policy: AbacPolicy) => (
                <div
                  class="abac-policy-card"
                  classList={{
                    "policy-allow": policy.result === "allow",
                    "policy-deny": policy.result === "deny",
                  }}
                >
                  <div class="policy-result-badge mono">
                    {policy.result === "allow" ? "ALLOW" : "DENY"}
                  </div>
                  <div class="policy-details">
                    <div class="policy-row">
                      <span class="policy-label mono">{t("主体", "Subject")}</span>
                      <span class="policy-value">{policy.subject}</span>
                    </div>
                    <div class="policy-row">
                      <span class="policy-label mono">{t("リソース", "Resource")}</span>
                      <span class="policy-value">{policy.resource}</span>
                    </div>
                    <div class="policy-row">
                      <span class="policy-label mono">{t("アクション", "Action")}</span>
                      <span class="policy-value">{policy.action}</span>
                    </div>
                    <div class="policy-condition">
                      <span class="cond-label mono">{t("条件", "Condition")}</span>
                      <code class="cond-code">{policy.condition}</code>
                    </div>
                  </div>
                </div>
              )}
            </For>
          </div>

          {/* RBAC vs ABAC comparison */}
          <div class="model-compare">
            <div class="mc-title mono">{t("RBAC vs ABAC", "RBAC vs ABAC")}</div>
            <div class="mc-grid">
              <div class="mc-item">
                <span class="mc-label">RBAC</span>
                <span class="mc-val">{t("ロールで制御。シンプル。", "Role-based. Simple.")}</span>
              </div>
              <div class="mc-item">
                <span class="mc-label">ABAC</span>
                <span class="mc-val">{t("属性で制御。柔軟。", "Attribute-based. Flexible.")}</span>
              </div>
              <div class="mc-item">
                <span class="mc-label">{t("粒度", "Granularity")}</span>
                <span class="mc-val">{t("RBAC: 粗い → ABAC: 細かい", "RBAC: Coarse → ABAC: Fine")}</span>
              </div>
              <div class="mc-item">
                <span class="mc-label">{t("複雑さ", "Complexity")}</span>
                <span class="mc-val">{t("RBAC: 低い → ABAC: 高い", "RBAC: Low → ABAC: High")}</span>
              </div>
            </div>
          </div>
        </div>
      </Show>
    </div>
  );
}
