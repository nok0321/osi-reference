import { Match, Switch, For } from "solid-js";
import { useI18n } from "../../i18n/context";
import { authSubView, setAuthSubView } from "../../state/security-state";
import type { AuthSubView } from "../../types/security";
import OAuthFlow from "./OAuthFlow";
import JwtInspector from "./JwtInspector";
import "./AuthView.css";

interface SubTab {
  id: AuthSubView;
  label: string;
  labelJa: string;
  icon: string;
}

const SUB_TABS: SubTab[] = [
  { id: "oauth", label: "OAuth 2.0", labelJa: "OAuth 2.0", icon: "⟐" },
  { id: "jwt", label: "JWT", labelJa: "JWT", icon: "⊟" },
  { id: "tls-deep", label: "TLS Deep", labelJa: "TLS詳細", icon: "⊛" },
  { id: "session-vs-token", label: "Session vs Token", labelJa: "セッション vs トークン", icon: "⇄" },
  { id: "rbac", label: "RBAC/ABAC", labelJa: "RBAC/ABAC", icon: "⊞" },
];

function PlaceholderSubView(props: { name: string }) {
  return (
    <div class="auth-placeholder">
      <span class="ph-icon">◇</span>
      <span>{props.name}</span>
      <span class="ph-note">Coming in Phase 5...</span>
    </div>
  );
}

export default function AuthView() {
  const { t } = useI18n();

  return (
    <div class="auth-view">
      <div class="auth-header">
        <h2 class="view-title">
          {t("認証・認可フロー", "Authentication & Authorization Flows")}
        </h2>
      </div>

      <nav class="auth-subtabs">
        <For each={SUB_TABS}>
          {(tab) => (
            <button
              class="subtab"
              classList={{ active: authSubView() === tab.id }}
              onClick={() => setAuthSubView(tab.id)}
            >
              <span class="subtab-icon">{tab.icon}</span>
              <span class="subtab-label">{t(tab.labelJa, tab.label)}</span>
            </button>
          )}
        </For>
      </nav>

      <div class="auth-content">
        <Switch>
          <Match when={authSubView() === "oauth"}>
            <OAuthFlow />
          </Match>
          <Match when={authSubView() === "jwt"}>
            <JwtInspector />
          </Match>
          <Match when={authSubView() === "tls-deep"}>
            <PlaceholderSubView name={t("TLS詳細解析", "TLS Deep Dive")} />
          </Match>
          <Match when={authSubView() === "session-vs-token"}>
            <PlaceholderSubView name={t("セッション vs トークン比較", "Session vs Token Comparison")} />
          </Match>
          <Match when={authSubView() === "rbac"}>
            <PlaceholderSubView name={t("RBAC / ABAC モデル", "RBAC / ABAC Models")} />
          </Match>
        </Switch>
      </div>
    </div>
  );
}
