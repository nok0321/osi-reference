import { For, Show, createSignal, onCleanup } from "solid-js";
import { useI18n } from "../../i18n/context";
import {
  OIDC_ACTORS, OIDC_STEPS,
  SAML_ACTORS, SAML_STEPS,
  OIDC_VS_SAML,
} from "../../data/protocol-flows";
import type { ProtocolFlowStep, ProtocolActor } from "../../types/security";
import type { OidcAuthorizeData, OidcTokenData, SamlSsoData, OidcUserInfoData } from "../../types/auth-responses";
import { apiPost, apiGet } from "../../api/client";
import DataFlowPanel from "../shared/DataFlowPanel";
import StepControl from "../shared/StepControl";
import ViewModeToggle from "../shared/ViewModeToggle";
import AttackPanel from "../shared/AttackPanel";
import { getViewMode } from "../../state/attack-state";
import { oidcSamlScenarios } from "./attacks/scenarios/oidc-saml-scenarios";
import type { AttackResult } from "../../../shared/api-types";
import "./OidcSamlFlow.css";

const SCOPE = "oidc-saml";

// scenarioId → route suffix のマッピング (api/oidc/attack/<suffix>)
const ROUTE_BY_ID: Record<string, string> = {
  "saml-xsw": "saml-xsw",
  "saml-assertion-replay": "saml-assertion-replay",
  "oidc-id-token-spoofing": "id-token-spoof",
};

function OidcSamlFlowDefender() {
  const { t } = useI18n();
  const [mode, setMode] = createSignal<"oidc" | "saml">("oidc");
  const [oidcStep, setOidcStep] = createSignal(0);
  const [samlStep, setSamlStep] = createSignal(0);

  const currentSteps = () => mode() === "oidc" ? OIDC_STEPS : SAML_STEPS;
  const currentActors = () => mode() === "oidc" ? OIDC_ACTORS : SAML_ACTORS;
  const currentStep = () => mode() === "oidc" ? oidcStep() : samlStep();
  const setCurrentStep = (v: number | ((prev: number) => number)) => {
    if (mode() === "oidc") {
      setOidcStep(v);
    } else {
      setSamlStep(v);
    }
  };

  const step = () => currentSteps()[currentStep()];

  function getActorColor(id: string): string {
    return currentActors().find((a: ProtocolActor) => a.id === id)?.color || "#888";
  }

  return (
    <div class="oidc-saml-flow">
      <div class="os-toggle">
        <button
          class="os-mode-btn"
          classList={{ active: mode() === "oidc" }}
          onClick={() => setMode("oidc")}
        >
          OpenID Connect
        </button>
        <button
          class="os-mode-btn"
          classList={{ active: mode() === "saml" }}
          onClick={() => setMode("saml")}
        >
          SAML 2.0
        </button>
      </div>

      <p class="os-desc">
        <Show when={mode() === "oidc"}>
          {t(
            "OpenID ConnectはOAuth 2.0の上にIDレイヤーを追加するプロトコル。IDトークン(JWT)でユーザーの身元を証明する。",
            "OpenID Connect adds an identity layer on top of OAuth 2.0. It proves user identity via an ID Token (JWT)."
          )}
        </Show>
        <Show when={mode() === "saml"}>
          {t(
            "SAML 2.0はXMLベースの認証・認可フレームワーク。企業SSOやフェデレーションで広く使用される。",
            "SAML 2.0 is an XML-based authentication and authorization framework widely used in enterprise SSO and federation."
          )}
        </Show>
      </p>

      {/* Actor legend */}
      <div class="os-actors">
        <For each={currentActors()}>
          {(actor: ProtocolActor) => (
            <span class="os-actor-chip" style={{ "--ac-color": actor.color }}>
              {t(actor.nameJa, actor.name)}
            </span>
          )}
        </For>
      </div>

      {/* Step control */}
      <StepControl
        current={currentStep()}
        total={currentSteps().length}
        onPrev={() => setCurrentStep((p: number) => Math.max(0, p - 1))}
        onNext={() => setCurrentStep((p: number) => Math.min(currentSteps().length - 1, p + 1))}
      />

      {/* Current step display */}
      <Show when={step()}>
        <div class="os-step-card">
          <div class="os-step-header">
            <span class="os-step-num mono">Step {step()!.stepNumber}</span>
            <span class="os-step-action">{t(step()!.actionJa, step()!.action)}</span>
          </div>
          <div class="os-step-flow">
            <span class="os-step-from" style={{ color: getActorColor(step()!.from) }}>
              {currentActors().find((a: ProtocolActor) => a.id === step()!.from)?.name || step()!.from}
            </span>
            <span class="os-arrow">→</span>
            <span class="os-step-to" style={{ color: getActorColor(step()!.to) }}>
              {currentActors().find((a: ProtocolActor) => a.id === step()!.to)?.name || step()!.to}
            </span>
          </div>
          <p class="os-step-desc">{t(step()!.descriptionJa, step()!.description)}</p>
          <Show when={step()!.dataPayload}>
            <pre class="os-payload mono">{step()!.dataPayload}</pre>
          </Show>
        </div>
      </Show>

      {/* Timeline */}
      <div class="os-timeline">
        <For each={currentSteps()}>
          {(s: ProtocolFlowStep, i) => (
            <div
              class="os-tl-item"
              classList={{ active: i() === currentStep(), past: i() < currentStep() }}
              onClick={() => setCurrentStep(i())}
            >
              <span class="os-tl-num mono">{s.stepNumber}</span>
              <span class="os-tl-label">{t(s.actionJa, s.action)}</span>
            </div>
          )}
        </For>
      </div>

      {/* Comparison table */}
      <div class="os-compare">
        <div class="os-compare-title mono">{t("OIDC vs SAML 比較", "OIDC vs SAML Comparison")}</div>
        <div class="os-compare-table">
          <div class="os-cmp-header">
            <span class="os-cmp-aspect">{t("項目", "Aspect")}</span>
            <span class="os-cmp-val">OIDC</span>
            <span class="os-cmp-val">SAML</span>
          </div>
          <For each={OIDC_VS_SAML}>
            {(row) => (
              <div class="os-cmp-row">
                <span class="os-cmp-aspect">{t(row.aspectJa, row.aspect)}</span>
                <span class="os-cmp-val">{t(row.oidcJa, row.oidc)}</span>
                <span class="os-cmp-val">{t(row.samlJa, row.saml)}</span>
              </div>
            )}
          </For>
        </div>
      </div>

      {/* Interactive Demo */}
      <OidcSamlDemo />
    </div>
  );
}

/* ── Interactive OIDC / SAML Demo ── */
interface OidcDemoState {
  pkce?: { codeVerifier: string; codeChallenge: string; method: string };
  discovery?: Record<string, unknown>;
  authorize?: OidcAuthorizeData;
  state?: string;
  nonce?: string;
  token?: OidcTokenData;
  idTokenDecoded?: { header: Record<string, unknown>; payload: Record<string, unknown>; signature: string };
  userinfo?: OidcUserInfoData;
}

function OidcSamlDemo() {
  const { t } = useI18n();
  const ac = new AbortController();
  onCleanup(() => ac.abort());

  const [demoMode, setDemoMode] = createSignal<"oidc" | "saml">("oidc");
  const [loading, setLoading] = createSignal(false);
  const [error, setError] = createSignal("");
  const [oidcStepNum, setOidcStepNum] = createSignal(0);
  const [oidcData, setOidcData] = createSignal<OidcDemoState>({});
  const [samlData, setSamlData] = createSignal<SamlSsoData | null>(null);

  // PKCE helpers
  function generateCodeVerifier(): string {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, b => b.toString(36).padStart(2, "0")).join("").substring(0, 43);
  }

  async function sha256Base64Url(plain: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(plain);
    const hash = await crypto.subtle.digest("SHA-256", data);
    const base64 = btoa(String.fromCharCode(...new Uint8Array(hash)));
    return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  async function runOidcFlow() {
    setLoading(true);
    setError("");
    setOidcStepNum(0);
    setOidcData({});

    try {
      // Generate PKCE values
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = await sha256Base64Url(codeVerifier);

      setOidcData({ pkce: { codeVerifier, codeChallenge, method: "S256" } });

      // Step 1: Discovery
      setOidcStepNum(1);
      const disc = await apiGet<Record<string, unknown>>("/api/oidc/.well-known/openid-configuration", SCOPE, ac.signal);
      if (ac.signal.aborted) return;
      if (disc.error) { setError(disc.error); setLoading(false); return; }
      setOidcData((prev: OidcDemoState) => ({ ...prev, discovery: disc.data }));

      // Step 2: Authorization
      setOidcStepNum(2);
      const state = `oidc_state_${Date.now()}`;
      const nonce = `nonce_${Date.now()}`;
      const authRes = await apiPost<OidcAuthorizeData>("/api/oidc/authorize", {
        username: "oidc-user",
        password: "demo123",
        client_id: "demo-oidc-app",
        redirect_uri: "http://localhost:3000/callback",
        scope: "openid profile email",
        state,
        nonce,
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
      }, SCOPE, undefined, ac.signal);
      if (ac.signal.aborted) return;
      if (authRes.error) { setError(authRes.error); setLoading(false); return; }
      setOidcData((prev: OidcDemoState) => ({ ...prev, authorize: authRes.data, state, nonce }));

      // Step 3: Token Exchange
      setOidcStepNum(3);
      const tokenRes = await apiPost<OidcTokenData>("/api/oidc/token", {
        code: authRes.data?.code,
        client_id: "demo-oidc-app",
        client_secret: "oidc-secret-12345",
        redirect_uri: "http://localhost:3000/callback",
        code_verifier: codeVerifier,
      }, SCOPE, undefined, ac.signal);
      if (ac.signal.aborted) return;
      if (tokenRes.error) { setError(tokenRes.error); setLoading(false); return; }
      setOidcData((prev: OidcDemoState) => ({ ...prev, token: tokenRes.data }));

      // Decode ID token
      const idToken = tokenRes.data?.id_token;
      if (idToken) {
        try {
          const parts = idToken.split(".");
          const header = JSON.parse(atob(parts[0]));
          const payload = JSON.parse(atob(parts[1]));
          setOidcData((prev: OidcDemoState) => ({ ...prev, idTokenDecoded: { header, payload, signature: parts[2]?.substring(0, 20) + "..." } }));
        } catch { /* ignore decode errors */ }
      }

      // Step 4: UserInfo
      setOidcStepNum(4);
      const accessToken = tokenRes.data?.access_token;
      if (accessToken) {
        const uiRes = await apiGet<OidcUserInfoData>("/api/oidc/userinfo", SCOPE, ac.signal);
        if (ac.signal.aborted) return;
        setOidcData((prev: OidcDemoState) => ({ ...prev, userinfo: uiRes.data }));
      }
    } catch (err: unknown) {
      if (ac.signal.aborted) return;
      setError(err instanceof Error ? err.message : "Unknown error");
    }
    setLoading(false);
  }

  async function runSamlFlow() {
    setLoading(true);
    setError("");
    setSamlData(null);

    try {
      const res = await apiPost<SamlSsoData>("/api/oidc/saml/sso", {
        username: "saml-user",
        password: "demo123",
        sp_entity_id: "https://sp.example.com/metadata",
      }, SCOPE, undefined, ac.signal);
      if (ac.signal.aborted) return;
      if (res.error) { setError(res.error); setLoading(false); return; }
      setSamlData(res.data ?? null);
    } catch (err: unknown) {
      if (ac.signal.aborted) return;
      setError(err instanceof Error ? err.message : "Unknown error");
    }
    setLoading(false);
  }

  const oidcStepLabels = () => [
    t("Discovery", "Discovery"),
    t("認可リクエスト", "Authorization"),
    t("トークン交換", "Token Exchange"),
    t("UserInfo取得", "UserInfo"),
  ];

  return (
    <div class="os-demo-section">
      <h4 class="demo-title">
        {t("インタラクティブ デモ", "Interactive Demo")}
        <span class="demo-badge">{t("実動作", "Live")}</span>
      </h4>

      <div class="demo-mode-toggle">
        <button classList={{ active: demoMode() === "oidc" }} onClick={() => setDemoMode("oidc")}>
          OIDC + PKCE
        </button>
        <button classList={{ active: demoMode() === "saml" }} onClick={() => setDemoMode("saml")}>
          SAML SSO
        </button>
      </div>

      {/* OIDC Demo */}
      <Show when={demoMode() === "oidc"}>
        <button class="demo-submit" onClick={runOidcFlow} disabled={loading()}>
          {loading() ? t("実行中...", "Running...") : t("OIDC フローを実行", "Run OIDC Flow")}
        </button>

        <Show when={oidcStepNum() > 0}>
          <div class="os-demo-steps">
            <For each={oidcStepLabels()}>
              {(label, i) => (
                <div class="os-demo-step-indicator" classList={{
                  done: oidcStepNum() > i() + 1,
                  active: oidcStepNum() === i() + 1,
                  pending: oidcStepNum() < i() + 1,
                }}>
                  <span class="os-demo-step-num mono">{i() + 1}</span>
                  <span class="os-demo-step-label">{label}</span>
                </div>
              )}
            </For>
          </div>
        </Show>

        {/* PKCE values */}
        <Show when={oidcData().pkce}>
          <div class="os-demo-card">
            <div class="os-demo-card-title mono">PKCE {t("パラメータ", "Parameters")}</div>
            <div class="os-demo-kv">
              <span class="os-demo-k mono">code_verifier</span>
              <span class="os-demo-v mono">{oidcData().pkce?.codeVerifier}</span>
            </div>
            <div class="os-demo-kv">
              <span class="os-demo-k mono">code_challenge</span>
              <span class="os-demo-v mono">{oidcData().pkce?.codeChallenge}</span>
            </div>
            <div class="os-demo-kv">
              <span class="os-demo-k mono">method</span>
              <span class="os-demo-v mono">{oidcData().pkce?.method}</span>
            </div>
          </div>
        </Show>

        {/* Discovery */}
        <Show when={oidcData().discovery}>
          <div class="os-demo-card">
            <div class="os-demo-card-title mono">1. {t("ディスカバリ", "Discovery")}</div>
            <pre class="os-demo-pre mono">{JSON.stringify(oidcData().discovery, null, 2)}</pre>
          </div>
        </Show>

        {/* Authorization */}
        <Show when={oidcData().authorize}>
          <div class="os-demo-card">
            <div class="os-demo-card-title mono">2. {t("認可レスポンス", "Authorization Response")}</div>
            <pre class="os-demo-pre mono">{JSON.stringify(oidcData().authorize, null, 2)}</pre>
          </div>
        </Show>

        {/* Token + Decoded ID Token */}
        <Show when={oidcData().token}>
          <div class="os-demo-card">
            <div class="os-demo-card-title mono">3. {t("トークンレスポンス", "Token Response")}</div>
            <pre class="os-demo-pre mono">{JSON.stringify(oidcData().token, null, 2)}</pre>
          </div>
        </Show>

        <Show when={oidcData().idTokenDecoded}>
          <div class="os-demo-card highlight">
            <div class="os-demo-card-title mono">ID Token ({t("デコード済み", "Decoded")})</div>
            <div class="os-demo-kv">
              <span class="os-demo-k mono">Header</span>
              <pre class="os-demo-pre mono">{JSON.stringify(oidcData().idTokenDecoded?.header, null, 2)}</pre>
            </div>
            <div class="os-demo-kv">
              <span class="os-demo-k mono">Payload</span>
              <pre class="os-demo-pre mono">{JSON.stringify(oidcData().idTokenDecoded?.payload, null, 2)}</pre>
            </div>
            <div class="os-demo-kv">
              <span class="os-demo-k mono">Signature</span>
              <span class="os-demo-v mono">{oidcData().idTokenDecoded?.signature}</span>
            </div>
          </div>
        </Show>

        {/* UserInfo */}
        <Show when={oidcData().userinfo}>
          <div class="os-demo-card">
            <div class="os-demo-card-title mono">4. UserInfo</div>
            <pre class="os-demo-pre mono">{JSON.stringify(oidcData().userinfo, null, 2)}</pre>
          </div>
        </Show>
      </Show>

      {/* SAML Demo */}
      <Show when={demoMode() === "saml"}>
        <button class="demo-submit" onClick={runSamlFlow} disabled={loading()}>
          {loading() ? t("実行中...", "Running...") : t("SAML SSO を実行", "Run SAML SSO")}
        </button>

        <Show when={samlData()}>
          <div class="os-demo-card">
            <div class="os-demo-card-title mono">SAML {t("レスポンス", "Response")}</div>
            <pre class="os-demo-pre mono">{JSON.stringify(samlData(), null, 2)}</pre>
          </div>
        </Show>
      </Show>

      <Show when={error()}>
        <div class="demo-result error">{error()}</div>
      </Show>

      <DataFlowPanel scopeId={SCOPE} defaultOpen={true} />
    </div>
  );
}

export default function OidcSamlFlow() {
  return (
    <div class="oidc-saml-flow-wrapper">
      <ViewModeToggle tabId="oidc-saml" />
      <Show when={getViewMode("oidc-saml") === "defender"}>
        <OidcSamlFlowDefender />
      </Show>
      <Show when={getViewMode("oidc-saml") === "attacker"}>
        <AttackPanel
          tabId="oidc-saml"
          scenarios={oidcSamlScenarios}
          onRunScenario={async (s) => {
            const routeSuffix = ROUTE_BY_ID[s.id] ?? s.id.replace(/^oidc-saml-/, "");
            const res = await apiPost<AttackResult>(
              `/api/oidc/attack/${routeSuffix}`,
              {},
              "attack-oidc-saml",
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
