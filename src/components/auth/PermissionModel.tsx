import { For, Show, createSignal, onMount, onCleanup } from "solid-js";
import { useI18n } from "../../i18n/context";
import { RBAC_ROLES, ALL_PERMISSIONS, ABAC_POLICIES, ACL_ENTRIES, ACL_SUBJECTS, ACL_RESOURCES, POLICY_RULES } from "../../data/auth-flows";
import type { RbacRole, AbacPolicy, AclEntry, PolicyRule } from "../../types/security";
import { apiPost, apiGet } from "../../api/client";
import DataFlowPanel from "../shared/DataFlowPanel";
import ViewModeToggle from "../shared/ViewModeToggle";
import AttackPanel from "../shared/AttackPanel";
import { getViewMode } from "../../state/attack-state";
import { rbacScenarios } from "./attacks/scenarios/rbac-scenarios";
import type { AttackResult, AttackScenarioMeta, OrchestratorExecResponse } from "../../../shared/api-types";
import "./PermissionModel.css";

const SCOPE = "rbac-check";

function AccessCheckDemo(props: { mode: () => "rbac" | "abac" | "acl" | "policy" }) {
  const { t } = useI18n();
  const ac = new AbortController();
  onCleanup(() => ac.abort());

  const [subject, setSubject] = createSignal("alice");
  const [resource, setResource] = createSignal("documents");
  const [action, setAction] = createSignal("read");
  const [context, setContext] = createSignal("{}");
  interface EvalStep { rule: string; result: string | boolean; detail: string; reason?: string }
  interface CheckResult { allowed: boolean; reason?: string; evaluationSteps?: EvalStep[]; steps?: EvalStep[]; error?: string }
  interface RoleDisplay { id: number; name: string; permissions?: string }
  const [result, setResult] = createSignal<CheckResult | null>(null);
  const [loading, setLoading] = createSignal(false);
  const [roles, setRoles] = createSignal<RoleDisplay[]>([]);
  const [assignUser, setAssignUser] = createSignal("");
  const [assignRole, setAssignRole] = createSignal("");
  const [assignResult, setAssignResult] = createSignal<{ ok: boolean; message: string } | null>(null);

  async function fetchRoles() {
    const res = await apiGet<{ roles: RoleDisplay[] }>("/api/rbac/roles", SCOPE, ac.signal);
    if (ac.signal.aborted) return;
    if (res.data) setRoles(res.data.roles ?? []);
  }

  async function handleCheck() {
    setLoading(true);
    setResult(null);

    const m = props.mode();
    let endpoint: string;
    let body: Record<string, unknown>;

    if (m === "rbac") {
      endpoint = "/api/rbac/check";
      body = { subject: subject(), resource: resource(), action: action() };
    } else if (m === "abac") {
      endpoint = "/api/rbac/abac/check";
      let ctx = {};
      try { ctx = JSON.parse(context()); } catch { /* ignore */ }
      body = { subject: subject(), resource: resource(), action: action(), context: ctx };
    } else if (m === "acl") {
      endpoint = "/api/rbac/acl/check";
      body = { subject: subject(), resource: resource(), action: action() };
    } else {
      endpoint = "/api/rbac/check";
      body = { subject: subject(), resource: resource(), action: action() };
    }

    const res = await apiPost<CheckResult>(endpoint, body, SCOPE, undefined, ac.signal);
    if (ac.signal.aborted) return;
    setLoading(false);

    if (res.error) {
      setResult({ allowed: false, error: res.error });
    } else if (res.data) {
      setResult(res.data);
    }
  }

  async function handleAssignRole() {
    if (!assignUser() || !assignRole()) return;
    setAssignResult(null);
    const res = await apiPost<{ message: string }>("/api/rbac/assign", {
      username: assignUser(),
      roleName: assignRole(),
    }, SCOPE, undefined, ac.signal);
    if (ac.signal.aborted) return;
    if (res.error) {
      setAssignResult({ ok: false, message: res.error });
    } else {
      setAssignResult({ ok: true, message: t("ロール割り当て成功！", "Role assigned successfully!") });
      fetchRoles();
    }
  }

  onMount(() => fetchRoles());

  return (
    <div class="password-demo">
      <h4 class="demo-title">
        {t("アクセスチェック デモ", "Access Check Demo")}
        <span class="demo-badge">{t("実動作", "Live")}</span>
      </h4>

      <div class="demo-layout">
        <div class="demo-form-area">
          <form class="demo-form" onSubmit={(e) => { e.preventDefault(); handleCheck(); }}>
            <div class="form-field">
              <label class="form-label mono">{t("主体", "Subject")}</label>
              <input
                type="text"
                class="form-input"
                value={subject()}
                onInput={(e) => setSubject(e.currentTarget.value)}
                placeholder="alice"
              />
            </div>
            <div class="form-field">
              <label class="form-label mono">{t("リソース", "Resource")}</label>
              <input
                type="text"
                class="form-input"
                value={resource()}
                onInput={(e) => setResource(e.currentTarget.value)}
                placeholder="documents"
              />
            </div>
            <div class="form-field">
              <label class="form-label mono">{t("アクション", "Action")}</label>
              <input
                type="text"
                class="form-input"
                value={action()}
                onInput={(e) => setAction(e.currentTarget.value)}
                placeholder="read"
              />
            </div>
            <Show when={props.mode() === "abac"}>
              <div class="form-field">
                <label class="form-label mono">{t("コンテキスト (JSON)", "Context (JSON)")}</label>
                <input
                  type="text"
                  class="form-input"
                  value={context()}
                  onInput={(e) => setContext(e.currentTarget.value)}
                  placeholder='{"time": "09:00", "ip": "10.0.0.1"}'
                />
              </div>
            </Show>
            <button type="submit" class="demo-submit" disabled={loading()}>
              {loading()
                ? t("評価中...", "Evaluating...")
                : t("アクセスチェック", "Test Access")
              }
            </button>
          </form>

          <Show when={result()}>
            <div
              class="demo-result"
              role="alert"
              classList={{ success: result()!.allowed, error: !result()!.allowed }}
            >
              {result()!.allowed ? "✓ ALLOWED" : "✗ DENIED"}
              <Show when={result()!.error}>
                <span> — {result()!.error}</span>
              </Show>
            </div>
            <Show when={result()!.steps}>
              <div class="db-table-wrap" style={{ "margin-top": "8px" }}>
                <table class="db-table">
                  <thead>
                    <tr>
                      <th>{t("ルール", "Rule")}</th>
                      <th>{t("結果", "Result")}</th>
                      <th>{t("詳細", "Detail")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    <For each={result()!.steps}>
                      {(step: EvalStep) => (
                        <tr>
                          <td class="mono">{step.rule || "—"}</td>
                          <td>
                            <span
                              classList={{
                                "policy-result-badge": true,
                                "policy-allow": step.result === "allow" || step.result === true,
                                "policy-deny": step.result === "deny" || step.result === false,
                              }}
                              style={{ "font-size": "0.75rem", padding: "2px 6px" }}
                            >
                              {String(step.result).toUpperCase()}
                            </span>
                          </td>
                          <td>{step.detail || step.reason || "—"}</td>
                        </tr>
                      )}
                    </For>
                  </tbody>
                </table>
              </div>
            </Show>
          </Show>
        </div>

        <Show when={props.mode() === "rbac"}>
          <div class="demo-db-area">
            <div class="db-panel-title mono">
              {t("ロール割り当て", "Assign Role")}
            </div>
            <div class="demo-form" style={{ padding: "8px" }}>
              <div class="form-field">
                <label class="form-label mono">{t("ユーザー", "User")}</label>
                <input
                  type="text"
                  class="form-input"
                  value={assignUser()}
                  onInput={(e) => setAssignUser(e.currentTarget.value)}
                  placeholder="alice"
                />
              </div>
              <div class="form-field">
                <label class="form-label mono">{t("ロール", "Role")}</label>
                <input
                  type="text"
                  class="form-input"
                  value={assignRole()}
                  onInput={(e) => setAssignRole(e.currentTarget.value)}
                  placeholder="admin"
                />
              </div>
              <button
                type="button"
                class="demo-submit"
                disabled={!assignUser() || !assignRole()}
                onClick={handleAssignRole}
              >
                {t("割り当てる", "Assign Role")}
              </button>
              <Show when={assignResult()}>
                <div
                  class="demo-result"
                  role="alert"
                  classList={{ success: assignResult()!.ok, error: !assignResult()!.ok }}
                >
                  {assignResult()!.ok ? "✓" : "✗"} {assignResult()!.message}
                </div>
              </Show>
            </div>

            <div class="db-panel-title mono" style={{ "margin-top": "12px" }}>
              {t("ロール一覧", "Roles")}
              <button class="db-refresh" onClick={fetchRoles}>↻</button>
            </div>
            <Show when={roles().length > 0} fallback={
              <div class="db-empty">{t("ロールなし", "No roles")}</div>
            }>
              <div class="db-table-wrap">
                <table class="db-table">
                  <thead>
                    <tr>
                      <th>{t("ロール名", "Role")}</th>
                      <th>{t("権限", "Permissions")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    <For each={roles()}>
                      {(r: RoleDisplay) => (
                        <tr>
                          <td class="mono">{r.name}</td>
                          <td>{r.permissions || "—"}</td>
                        </tr>
                      )}
                    </For>
                  </tbody>
                </table>
              </div>
            </Show>
          </div>
        </Show>
      </div>

      <DataFlowPanel scopeId={SCOPE} />
    </div>
  );
}

function PermissionModelDefender() {
  const { t } = useI18n();
  const [mode, setMode] = createSignal<"rbac" | "abac" | "acl" | "policy">("rbac");
  const [selectedRole, setSelectedRole] = createSignal<string | null>(null);

  function hasPermission(role: RbacRole, perm: string): boolean {
    return role.permissions.includes(perm);
  }

  return (
    <div class="perm-toggle-wrapper">
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
        <button
          class="perm-mode-btn"
          classList={{ active: mode() === "acl" }}
          onClick={() => setMode("acl")}
        >
          ACL
        </button>
        <button
          class="perm-mode-btn"
          classList={{ active: mode() === "policy" }}
          onClick={() => setMode("policy")}
        >
          {t("ポリシー", "Policy")}
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

      {/* ACL View */}
      <Show when={mode() === "acl"}>
        <div class="acl-view">
          <div class="acl-desc">
            <p>
              {t(
                "アクセス制御リスト (ACL): 各リソースに対して、どのサブジェクトがどの権限を持つかを明示的に定義。ファイルシステムやネットワーク機器で広く使用。",
                "Access Control List (ACL): Explicitly defines which subjects have which permissions on each resource. Widely used in file systems and network devices."
              )}
            </p>
          </div>

          <div class="acl-matrix">
            <div class="matrix-title mono">{t("ACL マトリクス", "ACL Matrix")}</div>
            <div class="acl-table">
              <div class="acl-table-header">
                <span class="acl-corner" />
                <For each={ACL_RESOURCES}>
                  {(resource: string) => (
                    <span class="acl-res-label mono">{resource}</span>
                  )}
                </For>
              </div>
              <For each={ACL_SUBJECTS}>
                {(subject: string) => (
                  <div class="acl-table-row">
                    <span class="acl-subj-label mono">{subject}</span>
                    <For each={ACL_RESOURCES}>
                      {(resource: string) => {
                        const entries = ACL_ENTRIES.filter((e: AclEntry) => e.subject === subject && e.resource === resource);
                        return (
                          <div class="acl-cell">
                            <For each={entries}>
                              {(entry: AclEntry) => (
                                <div class="acl-perms">
                                  <For each={entry.permissions}>
                                    {(perm: string) => (
                                      <span
                                        class="acl-perm-chip mono"
                                        classList={{
                                          "perm-allow": entry.effect === "allow",
                                          "perm-deny": entry.effect === "deny",
                                        }}
                                      >
                                        {perm.charAt(0).toUpperCase()}
                                      </span>
                                    )}
                                  </For>
                                  <span
                                    class="acl-effect mono"
                                    classList={{
                                      "effect-allow": entry.effect === "allow",
                                      "effect-deny": entry.effect === "deny",
                                    }}
                                  >
                                    {entry.effect}
                                  </span>
                                </div>
                              )}
                            </For>
                            <Show when={entries.length === 0}>
                              <span class="acl-empty">—</span>
                            </Show>
                          </div>
                        );
                      }}
                    </For>
                  </div>
                )}
              </For>
            </div>
          </div>

          <div class="acl-legend">
            <span class="acl-legend-item"><span class="acl-perm-chip perm-allow mono">R</span> = Read</span>
            <span class="acl-legend-item"><span class="acl-perm-chip perm-allow mono">W</span> = Write</span>
            <span class="acl-legend-item"><span class="acl-perm-chip perm-allow mono">E</span> = Execute</span>
            <span class="acl-legend-item"><span class="acl-perm-chip perm-allow mono">D</span> = Delete</span>
          </div>
        </div>
      </Show>

      {/* Policy-Based View */}
      <Show when={mode() === "policy"}>
        <div class="policy-view">
          <div class="policy-desc-text">
            <p>
              {t(
                "ポリシーベース認可: Cedar/OPA スタイルの宣言的ルールでアクセス制御。プリンシパル、アクション、リソース、コンテキスト条件を組み合わせた柔軟なポリシー定義。",
                "Policy-Based Authorization: Declarative rules (Cedar/OPA style) for access control. Flexible policy definitions combining principal, action, resource, and context conditions."
              )}
            </p>
          </div>

          <div class="policy-rules-list">
            <For each={POLICY_RULES}>
              {(rule: PolicyRule) => (
                <div
                  class="policy-rule-card"
                  classList={{
                    "policy-allow": rule.effect === "allow",
                    "policy-deny": rule.effect === "deny",
                  }}
                >
                  <div class="policy-rule-header">
                    <span class="policy-result-badge mono">
                      {rule.effect.toUpperCase()}
                    </span>
                    <span class="policy-rule-name">{t(rule.nameJa, rule.name)}</span>
                  </div>
                  <div class="policy-rule-body">
                    <div class="policy-row">
                      <span class="policy-label mono">{t("プリンシパル", "Principal")}</span>
                      <code class="policy-code">{rule.principal}</code>
                    </div>
                    <div class="policy-row">
                      <span class="policy-label mono">{t("アクション", "Action")}</span>
                      <code class="policy-code">{rule.action}</code>
                    </div>
                    <div class="policy-row">
                      <span class="policy-label mono">{t("リソース", "Resource")}</span>
                      <code class="policy-code">{rule.resource}</code>
                    </div>
                    <div class="policy-condition">
                      <span class="cond-label mono">{t("条件", "Condition")}</span>
                      <code class="cond-code">{t(rule.conditionJa, rule.condition)}</code>
                    </div>
                  </div>
                </div>
              )}
            </For>
          </div>

          <div class="model-compare">
            <div class="mc-title mono">{t("認可モデル比較", "Authorization Model Comparison")}</div>
            <div class="mc-grid mc-grid-4">
              <div class="mc-item">
                <span class="mc-label">RBAC</span>
                <span class="mc-val">{t("ロールベース", "Role-based")}</span>
              </div>
              <div class="mc-item">
                <span class="mc-label">ABAC</span>
                <span class="mc-val">{t("属性ベース", "Attribute-based")}</span>
              </div>
              <div class="mc-item">
                <span class="mc-label">ACL</span>
                <span class="mc-val">{t("リソース固有リスト", "Resource-specific list")}</span>
              </div>
              <div class="mc-item">
                <span class="mc-label">{t("ポリシー", "Policy")}</span>
                <span class="mc-val">{t("宣言的ルール", "Declarative rules")}</span>
              </div>
            </div>
          </div>
        </div>
      </Show>

      <AccessCheckDemo mode={mode} />
    </div>
  );
}

export default function PermissionModel() {
  const ROUTE_BY_ID: Record<string, string> = {
    "rbac-idor": "idor",
    "rbac-horizontal-privilege-escalation": "horizontal-escalation",
    "rbac-vertical-privilege-escalation": "vertical-escalation",
    "rbac-abac-attribute-tampering": "abac-tamper",
  };

  return (
    <div class="permission-model">
      <ViewModeToggle tabId="rbac" />
      <Show when={getViewMode("rbac") === "defender"}>
        <PermissionModelDefender />
      </Show>
      <Show when={getViewMode("rbac") === "attacker"}>
        <AttackPanel
          tabId="rbac"
          scenarios={rbacScenarios}
          allowedTargets={["victim-web"]}
          onRunScenario={async (s: AttackScenarioMeta) => {
            const routeSuffix = ROUTE_BY_ID[s.id] ?? s.id.replace(/^rbac-/, "");
            const res = await apiPost<AttackResult>(
              `/api/rbac/attack/${routeSuffix}`,
              {},
              "attack-rbac"
            );
            if (!res.data) {
              return {
                scenarioId: s.id,
                outcome: "error" as const,
                startedAt: Date.now(),
                finishedAt: Date.now(),
                steps: [],
                summaryJa: res.error ?? "実行エラー",
                summary: res.error ?? "Execution error",
              };
            }
            return res.data;
          }}
          onRunLiveScenario={async (s, payload) => {
            const res = await apiPost<OrchestratorExecResponse>(
              "/api/orchestrator/exec",
              {
                scenarioId: s.id,
                target: payload.target,
                request: payload.request,
              },
              "attack-rbac"
            );
            if (!res.data) {
              const errMsg = res.error ?? "Execution error";
              const friendlyJa =
                errMsg === "victim_unreachable"
                  ? "victim-web が起動していません。docker compose up -d victim-web または npm run dev:victim を実行してください。"
                  : errMsg === "live_attack_disabled_in_production"
                  ? "live モードは production 環境では無効です。"
                  : errMsg === "phase_not_reached"
                  ? "このシナリオは現在の Phase ではまだ live 化されていません。"
                  : `実行エラー: ${errMsg}`;
              const friendlyEn =
                errMsg === "victim_unreachable"
                  ? "victim-web is not reachable. Start it with `docker compose up -d victim-web` or `npm run dev:victim`."
                  : errMsg === "live_attack_disabled_in_production"
                  ? "Live mode is disabled in production."
                  : errMsg === "phase_not_reached"
                  ? "This scenario is not yet live in the current phase."
                  : `Execution error: ${errMsg}`;
              return {
                scenarioId: s.id,
                outcome: "error" as const,
                startedAt: Date.now(),
                finishedAt: Date.now(),
                steps: [],
                summaryJa: friendlyJa,
                summary: friendlyEn,
              };
            }
            return res.data;
          }}
        />
      </Show>
    </div>
  );
}
