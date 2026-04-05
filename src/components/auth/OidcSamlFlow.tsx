import { For, Show, createSignal } from "solid-js";
import { useI18n } from "../../i18n/context";
import {
  OIDC_ACTORS, OIDC_STEPS,
  SAML_ACTORS, SAML_STEPS,
  OIDC_VS_SAML,
} from "../../data/protocol-flows";
import type { ProtocolFlowStep, ProtocolActor } from "../../types/security";
import StepControl from "../shared/StepControl";
import "./OidcSamlFlow.css";

export default function OidcSamlFlow() {
  const { t } = useI18n();
  const [mode, setMode] = createSignal<"oidc" | "saml">("oidc");
  const [oidcStep, setOidcStep] = createSignal(0);
  const [samlStep, setSamlStep] = createSignal(0);

  const currentSteps = () => mode() === "oidc" ? OIDC_STEPS : SAML_STEPS;
  const currentActors = () => mode() === "oidc" ? OIDC_ACTORS : SAML_ACTORS;
  const currentStep = () => mode() === "oidc" ? oidcStep() : samlStep();
  const setCurrentStep = (v: number | ((prev: number) => number)) => {
    if (mode() === "oidc") {
      setOidcStep(v as any);
    } else {
      setSamlStep(v as any);
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
    </div>
  );
}
