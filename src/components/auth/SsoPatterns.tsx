import { For, Show, createSignal } from "solid-js";
import { useI18n } from "../../i18n/context";
import { SSO_PATTERNS, IDP_TYPES, API_KEY_PATTERNS } from "../../data/sso-patterns";
import type { SsoPattern, IdpInfo, ApiKeyPattern } from "../../types/security";
import "./SsoPatterns.css";

export default function SsoPatterns() {
  const { t } = useI18n();
  const [section, setSection] = createSignal<"sso" | "idp" | "apikey">("sso");

  const securityColor = (level: string) => {
    if (level === "high") return "#22C55E";
    if (level === "medium") return "#F59E0B";
    return "#EF4444";
  };

  return (
    <div class="sso-patterns">
      <div class="sso-toggle">
        <button
          class="sso-mode-btn"
          classList={{ active: section() === "sso" }}
          onClick={() => setSection("sso")}
        >
          SSO
        </button>
        <button
          class="sso-mode-btn"
          classList={{ active: section() === "idp" }}
          onClick={() => setSection("idp")}
        >
          IdP
        </button>
        <button
          class="sso-mode-btn"
          classList={{ active: section() === "apikey" }}
          onClick={() => setSection("apikey")}
        >
          {t("APIキー", "API Key")}
        </button>
      </div>

      {/* SSO Section */}
      <Show when={section() === "sso"}>
        <div class="sso-section">
          <p class="sso-section-desc">
            {t(
              "シングルサインオン(SSO)は一度の認証で複数のサービスにアクセスできる仕組み。ユーザー体験の向上とセキュリティの一元管理を実現。",
              "Single Sign-On (SSO) allows accessing multiple services with a single authentication. Improves user experience and centralizes security management."
            )}
          </p>
          <div class="sso-patterns-grid">
            <For each={SSO_PATTERNS}>
              {(pattern: SsoPattern) => (
                <div class="sso-pattern-card">
                  <div class="sso-pattern-name">{t(pattern.nameJa, pattern.name)}</div>
                  <p class="sso-pattern-desc">{t(pattern.descriptionJa, pattern.description)}</p>
                  <div class="sso-flow-steps">
                    <span class="sso-flow-title mono">{t("フロー", "Flow")}</span>
                    <ol class="sso-flow-list">
                      <For each={t(pattern.flowJa, pattern.flow) as unknown as string[]}>
                        {(step: string) => <li>{step}</li>}
                      </For>
                    </ol>
                  </div>
                </div>
              )}
            </For>
          </div>
        </div>
      </Show>

      {/* IdP Section */}
      <Show when={section() === "idp"}>
        <div class="idp-section">
          <p class="sso-section-desc">
            {t(
              "アイデンティティプロバイダ(IdP)はユーザーの身元を認証し、サービスプロバイダにアサーション/トークンを発行する。",
              "An Identity Provider (IdP) authenticates user identity and issues assertions/tokens to Service Providers."
            )}
          </p>
          <div class="idp-grid">
            <For each={IDP_TYPES}>
              {(idp: IdpInfo) => (
                <div class="idp-card" style={{ "--idp-color": idp.color }}>
                  <div class="idp-header">
                    <span class="idp-name">{t(idp.nameJa, idp.name)}</span>
                    <span class="idp-protocol mono">{idp.protocol}</span>
                  </div>
                  <p class="idp-desc">{t(idp.descriptionJa, idp.description)}</p>
                  <div class="idp-examples">
                    <For each={idp.examples}>
                      {(ex: string) => (
                        <span class="idp-example-chip mono">{ex}</span>
                      )}
                    </For>
                  </div>
                </div>
              )}
            </For>
          </div>
        </div>
      </Show>

      {/* API Key Section */}
      <Show when={section() === "apikey"}>
        <div class="apikey-section">
          <p class="sso-section-desc">
            {t(
              "APIキーはサーバー間通信やサードパーティ統合で使用されるシンプルな認証方式。送信方法によってセキュリティレベルが異なる。",
              "API keys are a simple authentication method for server-to-server communication and third-party integrations. Security level varies by transmission method."
            )}
          </p>
          <div class="apikey-grid">
            <For each={API_KEY_PATTERNS}>
              {(pattern: ApiKeyPattern) => (
                <div class="apikey-card" style={{ "--ak-color": securityColor(pattern.security) }}>
                  <div class="apikey-header">
                    <span class="apikey-name">{t(pattern.nameJa, pattern.name)}</span>
                    <span class="apikey-method mono">{pattern.method}</span>
                  </div>
                  <div class="apikey-security">
                    <span class="apikey-sec-label mono">{t("セキュリティ", "Security")}</span>
                    <span
                      class="apikey-sec-badge mono"
                      style={{ color: securityColor(pattern.security) }}
                    >
                      {pattern.security.toUpperCase()}
                    </span>
                  </div>
                  <p class="apikey-desc">{t(pattern.descriptionJa, pattern.description)}</p>
                  <pre class="apikey-example mono">{pattern.example}</pre>
                </div>
              )}
            </For>
          </div>
        </div>
      </Show>
    </div>
  );
}
