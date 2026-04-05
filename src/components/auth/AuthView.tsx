import { Match, Switch, For } from "solid-js";
import { useI18n } from "../../i18n/context";
import { authSubView, setAuthSubView } from "../../state/security-state";
import type { AuthSubView } from "../../types/security";
import OAuthFlow from "./OAuthFlow";
import JwtInspector from "./JwtInspector";
import TlsDeepDive from "./TlsDeepDive";
import AuthComparison from "./AuthComparison";
import PermissionModel from "./PermissionModel";
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
            <TlsDeepDive />
          </Match>
          <Match when={authSubView() === "session-vs-token"}>
            <AuthComparison />
          </Match>
          <Match when={authSubView() === "rbac"}>
            <PermissionModel />
          </Match>
        </Switch>
      </div>
    </div>
  );
}
