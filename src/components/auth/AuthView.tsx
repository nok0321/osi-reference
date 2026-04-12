import { Match, Switch, For, createMemo, createEffect, ErrorBoundary } from "solid-js";
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
import MfaFlow from "./MfaFlow";
import PasskeyFlow from "./PasskeyFlow";
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
  { id: "mfa", label: "MFA/TOTP", labelJa: "MFA/TOTP", icon: "\u29BF" },
  { id: "passkey", label: "Passkey", labelJa: "\u30D1\u30B9\u30AD\u30FC", icon: "\u25CE" },
  { id: "kerberos", label: "Kerberos", labelJa: "Kerberos", icon: "\u2298" },
  { id: "sso-idp-apikey", label: "SSO / IdP / API Key", labelJa: "SSO / IdP / API\u30AD\u30FC", icon: "\u2297" },
];

const VALID_SUBTABS = new Set<string>(SUB_TABS.map(t => t.id));

function AuthErrorFallback(props: { error: Error; reset: () => void }) {
  return (
    <div class="auth-error-fallback">
      <h3>Something went wrong</h3>
      <pre class="mono" style={{ "white-space": "pre-wrap", "word-break": "break-all", color: "var(--color-danger)" }}>
        {props.error.message}
      </pre>
      <button class="subtab" onClick={() => props.reset()} style={{ "margin-top": "1rem" }}>
        Try Again
      </button>
    </div>
  );
}

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

      <nav class="auth-subtabs" role="tablist" aria-label={t("認証方式タブ", "Authentication method tabs")}>
        <For each={SUB_TABS}>
          {(tab) => (
            <button
              class="subtab"
              classList={{ active: activeSubTab() === tab.id }}
              onClick={() => handleSubTabChange(tab.id)}
              onKeyDown={(e) => {
                const tabs = SUB_TABS;
                const idx = tabs.findIndex((s) => s.id === tab.id);
                if (e.key === "ArrowRight" || e.key === "ArrowDown") {
                  e.preventDefault();
                  const next = tabs[(idx + 1) % tabs.length];
                  handleSubTabChange(next.id);
                  (e.currentTarget.parentElement?.children[(idx + 1) % tabs.length] as HTMLElement)?.focus();
                } else if (e.key === "ArrowLeft" || e.key === "ArrowUp") {
                  e.preventDefault();
                  const prev = tabs[(idx - 1 + tabs.length) % tabs.length];
                  handleSubTabChange(prev.id);
                  (e.currentTarget.parentElement?.children[(idx - 1 + tabs.length) % tabs.length] as HTMLElement)?.focus();
                }
              }}
              role="tab"
              id={`auth-tab-${tab.id}`}
              aria-selected={activeSubTab() === tab.id}
              aria-controls="auth-tabpanel"
              tabIndex={activeSubTab() === tab.id ? 0 : -1}
            >
              <span class="subtab-icon" aria-hidden="true">{tab.icon}</span>
              <span class="subtab-label">{t(tab.labelJa, tab.label)}</span>
            </button>
          )}
        </For>
      </nav>

      <div class="auth-content" role="tabpanel" id="auth-tabpanel" aria-labelledby={`auth-tab-${activeSubTab()}`}>
        <ErrorBoundary fallback={(err, reset) => <AuthErrorFallback error={err} reset={reset} />}>
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
            <Match when={activeSubTab() === "mfa"}>
              <MfaFlow />
            </Match>
            <Match when={activeSubTab() === "passkey"}>
              <PasskeyFlow />
            </Match>
            <Match when={activeSubTab() === "kerberos"}>
              <KerberosFlow />
            </Match>
            <Match when={activeSubTab() === "sso-idp-apikey"}>
              <SsoPatterns />
            </Match>
          </Switch>
        </ErrorBoundary>
      </div>
    </div>
  );
}
