import { For, Show, createSignal, onMount } from "solid-js";
import { useI18n } from "../../i18n/context";
import { AUTH_METHODS, CATEGORY_COLORS } from "../../data/auth-methods";
import type { AuthMethodInfo } from "../../types/security";
import { apiPost, apiGet } from "../../api/client";
import DataFlowPanel from "../shared/DataFlowPanel";
import ViewModeToggle from "../shared/ViewModeToggle";
import AttackPanel from "../shared/AttackPanel";
import { getViewMode } from "../../state/attack-state";
import { passwordScenarios } from "./attacks/scenarios/password-scenarios";
import type { AttackResult } from "../../../shared/api-types";
import "./AuthMethods.css";

const SCOPE = "password-auth";

// scenarioId → route suffix のマッピング (api/auth/password/attack/<suffix>)
// ROB-OIDC-9 / ROB-RBAC-11 同類: scenario meta に routeSuffix を持たせる代わりに
// コンポーネント内で解決。fallback (s.id.replace) は到達不能だが、scenario id ミスマッチ時の
// silent 404 を防ぐため明示マップを優先する。
const ROUTE_BY_ID: Record<string, string> = {
  "password-rainbow-vs-bcrypt": "rainbow-vs-bcrypt",
  "password-timing-string-compare": "timing-string-compare",
  "password-bruteforce-no-rate-limit": "bruteforce-no-rate-limit",
};

function PasswordDemo() {
  const { t } = useI18n();
  const [mode, setMode] = createSignal<"register" | "login">("register");
  const [username, setUsername] = createSignal("alice");
  const [password, setPassword] = createSignal("password123");
  const [result, setResult] = createSignal<{ ok: boolean; message: string } | null>(null);
  const [loading, setLoading] = createSignal(false);
  interface UserDisplay { id: number; username: string; password_hash: string; created_at: string }
  const [users, setUsers] = createSignal<UserDisplay[]>([]);

  async function fetchUsers() {
    const res = await apiGet<{ users: UserDisplay[] }>("/api/auth/password/users", SCOPE);
    if (res.data) setUsers(res.data.users);
  }

  async function handleSubmit(e: Event) {
    e.preventDefault();
    if (!username() || !password()) return;
    setLoading(true);
    setResult(null);

    const endpoint = mode() === "register"
      ? "/api/auth/password/register"
      : "/api/auth/password/login";

    const res = await apiPost(endpoint, { username: username(), password: password() }, SCOPE);
    setLoading(false);

    if (res.error) {
      setResult({ ok: false, message: res.error });
    } else {
      setResult({
        ok: true,
        message: mode() === "register"
          ? t("登録成功！", "Registration successful!")
          : t("ログイン成功！", "Login successful!"),
      });
      fetchUsers();
    }
  }

  onMount(() => fetchUsers());

  return (
    <div class="password-demo">
      <h4 class="demo-title">
        {t("パスワード認証デモ", "Password Auth Demo")}
        <span class="demo-badge">{t("実動作", "Live")}</span>
      </h4>

      <div class="demo-layout">
        <div class="demo-form-area">
          <div class="demo-mode-toggle">
            <button
              classList={{ active: mode() === "register" }}
              onClick={() => { setMode("register"); setResult(null); }}
            >
              {t("登録", "Register")}
            </button>
            <button
              classList={{ active: mode() === "login" }}
              onClick={() => { setMode("login"); setResult(null); }}
            >
              {t("ログイン", "Login")}
            </button>
          </div>

          <form class="demo-form" onSubmit={handleSubmit}>
            <div class="form-field">
              <label class="form-label mono">{t("ユーザー名", "Username")}</label>
              <input
                type="text"
                class="form-input"
                value={username()}
                onInput={(e) => setUsername(e.currentTarget.value)}
                placeholder="alice"
              />
            </div>
            <div class="form-field">
              <label class="form-label mono">{t("パスワード", "Password")}</label>
              <input
                type="text"
                class="form-input"
                value={password()}
                onInput={(e) => setPassword(e.currentTarget.value)}
                placeholder="password123"
              />
              <span class="form-hint">
                {t("※教育用のため平文表示", "Shown in plaintext for educational purposes")}
              </span>
            </div>
            <button type="submit" class="demo-submit" disabled={loading()}>
              {loading()
                ? t("処理中...", "Processing...")
                : mode() === "register"
                  ? t("登録する", "Register")
                  : t("ログインする", "Login")
              }
            </button>
          </form>

          <Show when={result()}>
            <div
              class="demo-result"
              role="alert"
              classList={{ success: result()!.ok, error: !result()!.ok }}
            >
              {result()!.ok ? "✓" : "✗"} {result()!.message}
            </div>
          </Show>
        </div>

        <div class="demo-db-area">
          <div class="db-panel-title mono">
            {t("users テーブル", "users table")}
            <button class="db-refresh" onClick={fetchUsers} aria-label={t("更新", "Refresh")}>↻</button>
          </div>
          <Show when={users().length > 0} fallback={
            <div class="db-empty">{t("ユーザーなし", "No users yet")}</div>
          }>
            <div class="db-table-wrap">
              <table class="db-table">
                <thead>
                  <tr>
                    <th>id</th>
                    <th>username</th>
                    <th>password_hash</th>
                    <th>created_at</th>
                  </tr>
                </thead>
                <tbody>
                  <For each={users()}>
                    {(u) => (
                      <tr>
                        <td>{u.id}</td>
                        <td>{u.username}</td>
                        <td class="db-hash-cell">
                          <span class="hash-preview">{u.password_hash.substring(0, 20)}...</span>
                          <span class="hash-full">{u.password_hash}</span>
                        </td>
                        <td>{u.created_at}</td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </div>
          </Show>
        </div>
      </div>

      <DataFlowPanel scopeId={SCOPE} />
    </div>
  );
}

function AuthMethodsDefender() {
  const { t } = useI18n();
  const [expandedId, setExpandedId] = createSignal<string | null>(null);

  return (
    <div class="auth-methods">
      <PasswordDemo />

      <p class="auth-methods-desc">
        {t(
          "認証方式は「知識（知っていること）」「所有物（持っているもの）」「生体（自分自身）」の3要素に分類されます。",
          "Authentication methods are classified into three factors: Knowledge (something you know), Possession (something you have), and Inherence (something you are)."
        )}
      </p>

      {/* Factor legend */}
      <div class="factor-legend">
        <span class="factor-chip" style={{ "--f-color": CATEGORY_COLORS.knowledge }}>
          {t("知識", "Knowledge")}
        </span>
        <span class="factor-chip" style={{ "--f-color": CATEGORY_COLORS.possession }}>
          {t("所有物", "Possession")}
        </span>
        <span class="factor-chip" style={{ "--f-color": CATEGORY_COLORS.inherence }}>
          {t("生体", "Inherence")}
        </span>
        <span class="factor-chip" style={{ "--f-color": CATEGORY_COLORS.multi }}>
          {t("複合", "Multi-Factor")}
        </span>
      </div>

      <div class="methods-grid">
        <For each={AUTH_METHODS}>
          {(method: AuthMethodInfo) => {
            const color = CATEGORY_COLORS[method.category] || "#888";
            return (
              <div
                class="method-card"
                classList={{ expanded: expandedId() === method.id }}
                style={{ "--m-color": color }}
                role="button"
                tabIndex={0}
                aria-expanded={expandedId() === method.id}
                onClick={() => setExpandedId(prev => prev === method.id ? null : method.id)}
                onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setExpandedId(prev => prev === method.id ? null : method.id); } }}
              >
                <div class="method-header">
                  <span class="method-icon">{method.icon}</span>
                  <div class="method-title-area">
                    <span class="method-name">{t(method.nameJa, method.name)}</span>
                    <span class="method-category mono" style={{ color, background: `${color}18` }}>
                      {t(method.categoryLabelJa, method.categoryLabel)}
                    </span>
                  </div>
                </div>
                <p class="method-desc">{t(method.descriptionJa, method.description)}</p>

                <Show when={expandedId() === method.id}>
                  <div class="method-detail">
                    <div class="detail-section">
                      <span class="detail-label mono">{t("長所", "Strengths")}</span>
                      <ul class="detail-list strengths-list">
                        <For each={t(method.strengthsJa, method.strengths)}>
                          {(s: string) => <li>{s}</li>}
                        </For>
                      </ul>
                    </div>
                    <div class="detail-section">
                      <span class="detail-label mono">{t("短所", "Weaknesses")}</span>
                      <ul class="detail-list weaknesses-list">
                        <For each={t(method.weaknessesJa, method.weaknesses)}>
                          {(w: string) => <li>{w}</li>}
                        </For>
                      </ul>
                    </div>
                  </div>
                </Show>
              </div>
            );
          }}
        </For>
      </div>
    </div>
  );
}

export default function AuthMethods() {
  return (
    <div class="auth-methods-wrapper">
      <ViewModeToggle tabId="auth-methods" />
      <Show when={getViewMode("auth-methods") === "defender"}>
        <AuthMethodsDefender />
      </Show>
      <Show when={getViewMode("auth-methods") === "attacker"}>
        <AttackPanel
          tabId="auth-methods"
          scenarios={passwordScenarios}
          onRunScenario={async (s) => {
            const routeSuffix = ROUTE_BY_ID[s.id] ?? s.id.replace(/^password-/, "");
            const res = await apiPost<AttackResult>(
              `/api/auth/password/attack/${routeSuffix}`,
              {},
              "attack-auth-methods",
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
        />
      </Show>
    </div>
  );
}
