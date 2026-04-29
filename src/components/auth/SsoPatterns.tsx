import { For, Show, createSignal, onCleanup } from "solid-js";
import { useI18n } from "../../i18n/context";
import { SSO_PATTERNS, IDP_TYPES, API_KEY_PATTERNS } from "../../data/sso-patterns";
import type { SsoPattern, IdpInfo, ApiKeyPattern } from "../../types/security";
import type { SsoLoginData, SsoAccessData, ApiKeyGenerateData, ApiKeyVerifyData } from "../../types/auth-responses";
import { apiPost, apiGet } from "../../api/client";
import DataFlowPanel from "../shared/DataFlowPanel";
import ViewModeToggle from "../shared/ViewModeToggle";
import AttackPanel from "../shared/AttackPanel";
import { getViewMode } from "../../state/attack-state";
import { ssoApikeyScenarios } from "./attacks/scenarios/sso-apikey-scenarios";
import type { AttackResult } from "../../../shared/api-types";
import "./SsoPatterns.css";

const SCOPE = "sso-apikey";

// シナリオ ID → ルートサフィックスのマッピング (passkey/oauth/rbac 同パターン)。
// scenario meta の `id` は AttackScenarioMeta の SSoT のため、ここでは API ルート側のサフィックスのみ管理。
const ROUTE_BY_ID: Record<string, string> = {
  "apikey-leakage": "apikey-leakage",
  "apikey-hmac-bypass": "hmac-bypass",
  "apikey-replay-no-timestamp": "replay-no-timestamp",
};

function SsoPatternsDefender() {
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
                      <For each={t(pattern.flowJa, pattern.flow)}>
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

      {/* Interactive SSO Demo */}
      <SsoDemo />

      {/* Interactive API Key Demo */}
      <ApiKeyDemo />
    </div>
  );
}

/* ── Interactive SSO Demo ── */
function SsoDemo() {
  const { t } = useI18n();
  const ac = new AbortController();
  onCleanup(() => ac.abort());

  const [active, setActive] = createSignal(false);
  const [username, setUsername] = createSignal("");
  const [ssoToken, setSsoToken] = createSignal("");
  const [loading, setLoading] = createSignal(false);
  const [error, setError] = createSignal("");
  const [loginResult, setLoginResult] = createSignal<SsoLoginData | null>(null);
  const [serviceAResult, setServiceAResult] = createSignal<SsoAccessData | null>(null);
  const [serviceBResult, setServiceBResult] = createSignal<SsoAccessData | null>(null);

  async function handleLogin(e: Event) {
    e.preventDefault();
    if (!username()) return;
    setLoading(true);
    setError("");
    setLoginResult(null);
    setServiceAResult(null);
    setServiceBResult(null);

    const res = await apiPost<SsoLoginData>("/api/sso/login", { username: username() }, SCOPE, undefined, ac.signal);
    if (ac.signal.aborted) return;
    setLoading(false);

    if (res.error) {
      setError(res.error);
    } else {
      setLoginResult(res.data ?? null);
      setSsoToken(res.data?.ssoToken || "");
    }
  }

  async function accessService(serviceName: string) {
    if (!ssoToken()) { setError(t("先にログインしてください", "Please login first")); return; }
    setLoading(true);
    setError("");

    const res = await apiPost<SsoAccessData>("/api/sso/access-service", {
      ssoToken: ssoToken(),
      serviceName,
    }, SCOPE, undefined, ac.signal);
    if (ac.signal.aborted) return;
    setLoading(false);

    if (res.error) {
      setError(res.error);
    } else {
      if (serviceName === "Service A") setServiceAResult(res.data ?? null);
      else setServiceBResult(res.data ?? null);
    }
  }

  return (
    <div class="sso-live-section">
      <Show when={!active()} fallback={
        <div class="sso-live-panel">
          <div class="live-header">
            <h4 class="demo-title">
              {t("SSO デモ", "SSO Demo")}
              <span class="demo-badge">{t("実動作", "Live")}</span>
            </h4>
            <button class="demo-submit side-btn" onClick={() => setActive(false)}>
              {t("閉じる", "Close")}
            </button>
          </div>

          <form class="demo-form" onSubmit={handleLogin}>
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
            <button type="submit" class="demo-submit" disabled={loading() || !username()}>
              {loading() ? t("処理中...", "Processing...") : t("SSO ログイン", "SSO Login")}
            </button>
          </form>

          <Show when={error()}>
            <div class="demo-result error">{error()}</div>
          </Show>

          <Show when={loginResult()}>
            <div class="demo-result success">
              {t("SSO ログイン成功！", "SSO Login Successful!")}
            </div>
            <div class="live-data-cards">
              <div class="live-data-card">
                <span class="ldc-label mono">SSO Token</span>
                <span class="ldc-value mono">{ssoToken()?.substring(0, 40)}{ssoToken()?.length > 40 ? "..." : ""}</span>
              </div>
            </div>

            <p class="sso-service-hint">
              {t(
                "SSOトークンで複数サービスに再認証なしでアクセスできます:",
                "Access multiple services without re-authentication using the SSO token:"
              )}
            </p>

            <div class="sso-service-buttons">
              <button
                class="demo-submit"
                onClick={() => accessService("Service A")}
                disabled={loading()}
              >
                {t("サービスAにアクセス", "Access Service A")}
              </button>
              <button
                class="demo-submit"
                onClick={() => accessService("Service B")}
                disabled={loading()}
              >
                {t("サービスBにアクセス", "Access Service B")}
              </button>
            </div>

            <div class="live-data-cards">
              <Show when={serviceAResult()}>
                <div class="live-data-card success-card">
                  <span class="ldc-label mono">Service A</span>
                  <span class="ldc-value mono">{JSON.stringify(serviceAResult(), null, 2)}</span>
                </div>
              </Show>
              <Show when={serviceBResult()}>
                <div class="live-data-card success-card">
                  <span class="ldc-label mono">Service B</span>
                  <span class="ldc-value mono">{JSON.stringify(serviceBResult(), null, 2)}</span>
                </div>
              </Show>
            </div>
          </Show>

          <DataFlowPanel scopeId={SCOPE} defaultOpen={true} />
        </div>
      }>
        <button class="demo-submit" onClick={() => setActive(true)}>
          {t("SSO デモを開始", "Start SSO Demo")}
        </button>
      </Show>
    </div>
  );
}

/* ── Interactive API Key Demo ── */
function ApiKeyDemo() {
  const { t } = useI18n();
  const ac = new AbortController();
  onCleanup(() => ac.abort());

  const [active, setActive] = createSignal(false);
  const [keyName, setKeyName] = createSignal("my-app");
  const [generatedKey, setGeneratedKey] = createSignal<ApiKeyGenerateData | null>(null);
  const [keyShown, setKeyShown] = createSignal(false);
  const [loading, setLoading] = createSignal(false);
  const [error, setError] = createSignal("");
  interface VerifyResult { ok: boolean; data?: ApiKeyVerifyData; error?: string }
  const [headerResult, setHeaderResult] = createSignal<VerifyResult | null>(null);
  const [queryResult, setQueryResult] = createSignal<VerifyResult | null>(null);
  const [testMethod, setTestMethod] = createSignal<"header" | "query">("header");

  async function generateKey() {
    if (!keyName()) return;
    setLoading(true);
    setError("");
    setGeneratedKey(null);
    setKeyShown(false);
    setHeaderResult(null);
    setQueryResult(null);

    const res = await apiPost<ApiKeyGenerateData>("/api/sso/apikey/generate", { name: keyName() }, SCOPE, undefined, ac.signal);
    if (ac.signal.aborted) return;
    setLoading(false);

    if (res.error) {
      setError(res.error);
    } else {
      setGeneratedKey(res.data ?? null);
      setKeyShown(true);
    }
  }

  async function verifyHeader() {
    const key = generatedKey()?.rawKey || "";
    if (!key) { setError(t("先にキーを生成してください", "Generate a key first")); return; }
    setLoading(true);
    setError("");

    const res = await apiPost<ApiKeyVerifyData>(
      "/api/sso/apikey/verify/header",
      {},
      SCOPE,
      { "X-API-Key": key },
      ac.signal
    );
    if (ac.signal.aborted) return;
    setLoading(false);

    if (res.error) {
      setHeaderResult({ ok: false, error: res.error });
    } else {
      setHeaderResult({ ok: true, data: res.data });
    }
  }

  async function verifyQuery() {
    const key = generatedKey()?.rawKey || "";
    if (!key) { setError(t("先にキーを生成してください", "Generate a key first")); return; }
    setLoading(true);
    setError("");

    const res = await apiGet<ApiKeyVerifyData>(`/api/sso/apikey/verify/query?api_key=${encodeURIComponent(key)}`, SCOPE, ac.signal);
    if (ac.signal.aborted) return;
    setLoading(false);

    if (res.error) {
      setQueryResult({ ok: false, error: res.error });
    } else {
      setQueryResult({ ok: true, data: res.data });
    }
  }

  return (
    <div class="apikey-live-section">
      <Show when={!active()} fallback={
        <div class="apikey-live-panel">
          <div class="live-header">
            <h4 class="demo-title">
              {t("API キーデモ", "API Key Demo")}
              <span class="demo-badge">{t("実動作", "Live")}</span>
            </h4>
            <button class="demo-submit side-btn" onClick={() => setActive(false)}>
              {t("閉じる", "Close")}
            </button>
          </div>

          {/* Generate Key */}
          <div class="demo-form">
            <div class="form-field">
              <label class="form-label mono">{t("キー名", "Key Name")}</label>
              <input
                type="text"
                class="form-input"
                value={keyName()}
                onInput={(e) => setKeyName(e.currentTarget.value)}
                placeholder="my-app"
              />
            </div>
            <button class="demo-submit" onClick={generateKey} disabled={loading() || !keyName()}>
              {loading() ? t("処理中...", "Processing...") : t("キーを生成", "Generate Key")}
            </button>
          </div>

          <Show when={error()}>
            <div class="demo-result error">{error()}</div>
          </Show>

          <Show when={generatedKey()}>
            <div class="live-data-cards">
              <div class="live-data-card">
                <span class="ldc-label mono">API Key</span>
                <Show when={keyShown()} fallback={
                  <span class="ldc-value mono">{t("キーは生成時のみ表示されます", "Key shown only at generation time")}</span>
                }>
                  <span class="ldc-value mono">{generatedKey()?.rawKey}</span>
                  <div class="demo-result" role="alert" classList={{ error: true }}>
                    {t(
                      "このキーは再表示されません。安全に保管してください。",
                      "This key will not be shown again. Store it securely."
                    )}
                  </div>
                </Show>
              </div>
              <Show when={generatedKey()?.keyId}>
                <div class="live-data-card">
                  <span class="ldc-label mono">Key ID</span>
                  <span class="ldc-value mono">{generatedKey()?.keyId}</span>
                </div>
              </Show>
            </div>

            {/* Test Panels */}
            <div class="demo-mode-toggle">
              <button
                classList={{ active: testMethod() === "header" }}
                onClick={() => setTestMethod("header")}
              >
                {t("ヘッダー方式", "Header Method")}
              </button>
              <button
                classList={{ active: testMethod() === "query" }}
                onClick={() => setTestMethod("query")}
              >
                {t("クエリ方式", "Query Method")}
              </button>
            </div>

            <Show when={testMethod() === "header"}>
              <div class="apikey-test-panel">
                <p class="apikey-test-desc mono">
                  POST /api/sso/apikey/verify/header<br />
                  X-API-Key: {(generatedKey()?.rawKey || "").substring(0, 20)}...
                </p>
                <button class="demo-submit" onClick={verifyHeader} disabled={loading()}>
                  {t("ヘッダーで検証", "Verify with Header")}
                </button>
                <Show when={headerResult()}>
                  <div class="demo-result" role="alert" classList={{ success: headerResult()?.ok, error: !headerResult()?.ok }}>
                    {headerResult()?.ok ? "OK" : "FAIL"} {JSON.stringify(headerResult()?.data || headerResult()?.error)}
                  </div>
                </Show>
              </div>
            </Show>

            <Show when={testMethod() === "query"}>
              <div class="apikey-test-panel">
                <p class="apikey-test-desc mono">
                  GET /api/sso/apikey/verify/query?api_key={
                    (generatedKey()?.rawKey || "").substring(0, 20)
                  }...
                </p>
                <button class="demo-submit" onClick={verifyQuery} disabled={loading()}>
                  {t("クエリで検証", "Verify with Query")}
                </button>
                <Show when={queryResult()}>
                  <div class="demo-result" role="alert" classList={{ success: queryResult()?.ok, error: !queryResult()?.ok }}>
                    {queryResult()?.ok ? "OK" : "FAIL"} {JSON.stringify(queryResult()?.data || queryResult()?.error)}
                  </div>
                </Show>
              </div>
            </Show>
          </Show>

          <DataFlowPanel scopeId={SCOPE} defaultOpen={true} />
        </div>
      }>
        <button class="demo-submit" onClick={() => setActive(true)}>
          {t("API キーデモを開始", "Start API Key Demo")}
        </button>
      </Show>
    </div>
  );
}

export default function SsoPatterns() {
  return (
    <div class="sso-patterns-wrapper">
      <ViewModeToggle tabId="sso-idp-apikey" />
      <Show when={getViewMode("sso-idp-apikey") === "defender"}>
        <SsoPatternsDefender />
      </Show>
      <Show when={getViewMode("sso-idp-apikey") === "attacker"}>
        <AttackPanel
          tabId="sso-idp-apikey"
          scenarios={ssoApikeyScenarios}
          onRunScenario={async (s) => {
            const routeSuffix = ROUTE_BY_ID[s.id] ?? s.id.replace(/^apikey-/, "");
            const res = await apiPost<AttackResult>(
              `/api/sso/attack/${routeSuffix}`,
              {},
              "attack-sso-idp-apikey",
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
