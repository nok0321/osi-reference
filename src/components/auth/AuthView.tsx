import { Match, Switch, For, createMemo, createEffect } from "solid-js";
import { useNavigate, useLocation } from "@solidjs/router";
import { useI18n } from "../../i18n/context";
import { markSectionViewed } from "../../utils/progress";
import type { AuthSubView } from "../../types/security";
import OAuthFlow from "./OAuthFlow";
import JwtInspector from "./JwtInspector";
import TlsDeepDive from "./TlsDeepDive";
import AuthComparison from "./AuthComparison";
import PermissionModel from "./PermissionModel";
import AuthMethods from "./AuthMethods";
import OidcSamlFlow from "./OidcSamlFlow";
import Fido2WebAuthn from "./Fido2WebAuthn";
import KerberosFlow from "./KerberosFlow";
import SsoPatterns from "./SsoPatterns";
import "./AuthView.css";

interface SubTab {
  id: AuthSubView;
  label: string;
  labelJa: string;
  icon: string;
}

const SUB_TABS: SubTab[] = [
  { id: "oauth", label: "OAuth 2.0", labelJa: "OAuth 2.0", icon: "\u27D0" },
  { id: "jwt", label: "JWT", labelJa: "JWT", icon: "\u229F" },
  { id: "tls-deep", label: "TLS Deep", labelJa: "TLS\u8A73\u7D30", icon: "\u229B" },
  { id: "session-vs-token", label: "Session vs Token", labelJa: "\u30BB\u30C3\u30B7\u30E7\u30F3 vs \u30C8\u30FC\u30AF\u30F3", icon: "\u21C4" },
  { id: "rbac", label: "Access Control", labelJa: "\u30A2\u30AF\u30BB\u30B9\u5236\u5FA1", icon: "\u229E" },
  { id: "auth-methods", label: "Auth Methods", labelJa: "\u8A8D\u8A3C\u65B9\u5F0F", icon: "\u2609" },
  { id: "oidc-saml", label: "OIDC & SAML", labelJa: "OIDC & SAML", icon: "\u21CC" },
  { id: "fido2", label: "FIDO2/WebAuthn", labelJa: "FIDO2/WebAuthn", icon: "\u2295" },
  { id: "kerberos", label: "Kerberos", labelJa: "Kerberos", icon: "\u2298" },
  { id: "sso-idp-apikey", label: "SSO / IdP / API Key", labelJa: "SSO / IdP / API\u30AD\u30FC", icon: "\u2297" },
];

const VALID_SUBTABS = new Set<string>(SUB_TABS.map(t => t.id));

export default function AuthView() {
  const { t } = useI18n();
  const navigate = useNavigate();
  const location = useLocation();

  const activeSubTab = createMemo<AuthSubView>(() => {
    const parts = location.pathname.split("/");
    const subtab = parts[2]; // /auth/:subtab
    return VALID_SUBTABS.has(subtab) ? (subtab as AuthSubView) : "oauth";
  });

  // Track section visits for progress
  createEffect(() => {
    markSectionViewed("auth", activeSubTab());
  });

  function handleSubTabChange(id: AuthSubView) {
    navigate(`/auth/${id}`);
  }

  return (
    <div class="auth-view">
      <div class="auth-header">
        <h2 class="view-title">
          {t("\u8A8D\u8A3C\u30FB\u8A8D\u53EF\u30D5\u30ED\u30FC", "Authentication & Authorization Flows")}
        </h2>
      </div>

      <nav class="auth-subtabs" role="tablist">
        <For each={SUB_TABS}>
          {(tab) => (
            <button
              class="subtab"
              classList={{ active: activeSubTab() === tab.id }}
              onClick={() => handleSubTabChange(tab.id)}
              role="tab"
              aria-selected={activeSubTab() === tab.id}
            >
              <span class="subtab-icon">{tab.icon}</span>
              <span class="subtab-label">{t(tab.labelJa, tab.label)}</span>
            </button>
          )}
        </For>
      </nav>

      <div class="auth-content">
        <Switch>
          <Match when={activeSubTab() === "oauth"}>
            <OAuthFlow />
          </Match>
          <Match when={activeSubTab() === "jwt"}>
            <JwtInspector />
          </Match>
          <Match when={activeSubTab() === "tls-deep"}>
            <TlsDeepDive />
          </Match>
          <Match when={activeSubTab() === "session-vs-token"}>
            <AuthComparison />
          </Match>
          <Match when={activeSubTab() === "rbac"}>
            <PermissionModel />
          </Match>
          <Match when={activeSubTab() === "auth-methods"}>
            <AuthMethods />
          </Match>
          <Match when={activeSubTab() === "oidc-saml"}>
            <OidcSamlFlow />
          </Match>
          <Match when={activeSubTab() === "fido2"}>
            <Fido2WebAuthn />
          </Match>
          <Match when={activeSubTab() === "kerberos"}>
            <KerberosFlow />
          </Match>
          <Match when={activeSubTab() === "sso-idp-apikey"}>
            <SsoPatterns />
          </Match>
        </Switch>
      </div>
    </div>
  );
}
