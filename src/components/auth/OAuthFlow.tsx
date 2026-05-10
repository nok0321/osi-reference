import { For, Show, createSignal, createMemo, onCleanup } from "solid-js";
import { useI18n } from "../../i18n/context";
import { oauthStep, setOauthStep } from "../../state/security-state";
import { OAUTH_STEPS, OAUTH_ACTORS } from "../../data/auth-flows";
import type { OAuthStep } from "../../types/security";
import { apiPost, apiGet } from "../../api/client";
import type { OAuthAuthorizePageData, OAuthCodeData, OAuthTokenData } from "../../types/auth-responses";
import DataFlowPanel from "../shared/DataFlowPanel";
import StepControl from "../shared/StepControl";
import ViewModeToggle from "../shared/ViewModeToggle";
import AttackPanel from "../shared/AttackPanel";
import { getViewMode } from "../../state/attack-state";
import { oauthScenarios } from "./attacks/scenarios/oauth-scenarios";
import type { AttackResult, OrchestratorExecResponse } from "../../../shared/api-types";
import "./OAuthFlow.css";

const SCOPE = "oauth-flow";

interface OAuthLiveState {
  state?: string;
  authPage?: OAuthAuthorizePageData;
  code?: string;
  redirectUri?: string;
  accessToken?: string;
  refreshToken?: string;
  tokenResponse?: OAuthTokenData;
  resource?: { resource?: { data?: unknown }; [key: string]: unknown };
}

function OAuthFlowDefender() {
  const { t } = useI18n();
  const ac = new AbortController();
  onCleanup(() => ac.abort());

  const [liveMode, setLiveMode] = createSignal(false);
  const [liveStep, setLiveStep] = createSignal(0);
  const [liveData, setLiveData] = createSignal<OAuthLiveState>({});
  const [liveLoading, setLiveLoading] = createSignal(false);
  const [liveError, setLiveError] = createSignal("");

  async function startLiveFlow() {
    setLiveMode(true);
    setLiveStep(0);
    setLiveData({});
    setLiveError("");
    // First register a demo user
    await apiPost("/api/auth/password/register", { username: "oauth-user", password: "demo123" }, undefined, undefined, ac.signal);
    await runLiveStep(0);
  }

  async function runLiveStep(step: number) {
    setLiveLoading(true);
    setLiveError("");
    setLiveStep(step);
    setOauthStep(step);

    try {
      const state = `state_${Date.now()}`;
      const d = liveData();

      if (step === 0) {
        // Step 1: Authorization Request
        const res = await apiGet<OAuthAuthorizePageData>(
          `/api/oauth/authorize?client_id=demo-app&redirect_uri=http://localhost:3000/auth/oauth/callback&scope=read&state=${state}`,
          SCOPE,
          ac.signal
        );
        if (ac.signal.aborted) return;
        setLiveData({ ...d, state, authPage: res.data });
      } else if (step === 1) {
        // Step 2: User Login + Consent
        const res = await apiPost<OAuthCodeData>("/api/oauth/authorize", {
          client_id: "demo-app",
          redirect_uri: "http://localhost:3000/auth/oauth/callback",
          scope: "read",
          state: d.state || state,
          username: "oauth-user",
          password: "demo123",
        }, SCOPE, undefined, ac.signal);
        if (ac.signal.aborted) return;
        setLiveData({ ...d, code: res.data?.code, redirectUri: res.data?.redirectUri });
      } else if (step === 2) {
        // Step 3: Exchange code for tokens (one-time use)
        if (!d.code) { setLiveError("No authorization code"); setLiveLoading(false); return; }
        const res = await apiPost<OAuthTokenData>("/api/oauth/token", {
          grant_type: "authorization_code",
          code: d.code,
          client_id: "demo-app",
          client_secret: "demo-secret-12345",
        }, SCOPE, undefined, ac.signal);
        if (ac.signal.aborted) return;
        if (res.error) { setLiveError(res.error); setLiveLoading(false); return; }
        setLiveData({
          ...d,
          accessToken: res.data?.access_token,
          refreshToken: res.data?.refresh_token,
          tokenResponse: res.data,
        });
      } else if (step >= 3) {
        // Step 4+: Access resource with token
        if (!d.accessToken) { setLiveError("No access token"); setLiveLoading(false); return; }
        const r = await fetch("/api/oauth/resource", {
          headers: { "Authorization": `Bearer ${d.accessToken}` },
          signal: ac.signal,
        });
        if (ac.signal.aborted) return;
        const body = await r.json();
        if (ac.signal.aborted) return;
        setLiveData({ ...d, resource: body.data || body });
      }
    } catch (err: unknown) {
      if (ac.signal.aborted) return;
      setLiveError(err instanceof Error ? err.message : "Error");
    }
    setLiveLoading(false);
  }

  async function nextLiveStep() {
    const next = Math.min(liveStep() + 1, OAUTH_STEPS.length - 1);
    await runLiveStep(next);
  }

  const currentStep = createMemo(() => OAUTH_STEPS[oauthStep()]);

  function getActorColor(id: string): string {
    return OAUTH_ACTORS.find(a => a.id === id)?.color ?? "#888";
  }

  function getActorIndex(id: string): number {
    return OAUTH_ACTORS.findIndex(a => a.id === id);
  }

  return (
    <div class="oauth-flow">
      <div class="oauth-controls">
        <StepControl
          current={oauthStep()}
          total={OAUTH_STEPS.length}
          onPrev={() => setOauthStep(prev => Math.max(0, prev - 1))}
          onNext={() => setOauthStep(prev => Math.min(OAUTH_STEPS.length - 1, prev + 1))}
          label="OAuth"
        />
        <Show when={currentStep().isSecure}>
          <span class="secure-badge mono">HTTPS</span>
        </Show>
      </div>

      {/* Swimlane Header */}
      <div class="swimlane-header">
        <For each={OAUTH_ACTORS}>
          {(actor) => (
            <div class="lane-header" style={{ "--lane-color": actor.color }}>
              <span class="lane-icon">●</span>
              <span class="lane-name">{t(actor.nameJa, actor.name)}</span>
            </div>
          )}
        </For>
      </div>

      {/* Swimlane Steps */}
      <div class="swimlane-body">
        <For each={OAUTH_STEPS}>
          {(step: OAuthStep, i) => {
            const fromIdx = () => getActorIndex(step.from);
            const toIdx = () => getActorIndex(step.to);
            const isCurrent = () => i() === oauthStep();
            const isPast = () => i() < oauthStep();

            return (
              <div
                class="swim-row"
                classList={{
                  current: isCurrent(),
                  past: isPast(),
                  future: !isCurrent() && !isPast(),
                }}
                role="button"
                tabindex="0"
                onClick={() => setOauthStep(i())}
                onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setOauthStep(i()); } }}
              >
                {/* Step number */}
                <div class="swim-step-num mono">{step.stepNumber}</div>

                {/* Lane columns */}
                <div class="swim-lanes">
                  <For each={OAUTH_ACTORS}>
                    {(_, laneIdx) => (
                      <div
                        class="swim-cell"
                        classList={{
                          "is-from": fromIdx() === laneIdx(),
                          "is-to": toIdx() === laneIdx(),
                        }}
                      >
                        <Show when={fromIdx() === laneIdx()}>
                          <div
                            class="swim-dot from-dot"
                            style={{ background: getActorColor(step.from) }}
                          />
                        </Show>
                        <Show when={toIdx() === laneIdx() && fromIdx() !== toIdx()}>
                          <div
                            class="swim-dot to-dot"
                            style={{ background: getActorColor(step.to) }}
                          />
                        </Show>
                      </div>
                    )}
                  </For>

                  {/* Arrow overlay */}
                  <Show when={fromIdx() !== toIdx()}>
                    <div
                      class="swim-arrow"
                      style={{
                        left: `${((Math.min(fromIdx(), toIdx()) + 0.5) / 4) * 100}%`,
                        width: `${(Math.abs(toIdx() - fromIdx()) / 4) * 100}%`,
                        "--arrow-color": getActorColor(step.from),
                      }}
                      classList={{ "arrow-right": toIdx() > fromIdx(), "arrow-left": toIdx() < fromIdx() }}
                    />
                  </Show>
                </div>

                {/* Action label */}
                <div class="swim-action">
                  <span class="action-text">{t(step.actionJa, step.action)}</span>
                </div>
              </div>
            );
          }}
        </For>
      </div>

      {/* Detail Panel */}
      <Show when={currentStep()}>
        <div
          class="oauth-detail"
          style={{ "--detail-color": getActorColor(currentStep().from) }}
        >
          <div class="detail-header">
            <span class="detail-step mono">
              Step {currentStep().stepNumber}/{OAUTH_STEPS.length}
            </span>
            <span class="detail-direction">
              {t(
                OAUTH_ACTORS.find(a => a.id === currentStep().from)?.nameJa ?? "",
                OAUTH_ACTORS.find(a => a.id === currentStep().from)?.name ?? ""
              )}
              {" → "}
              {t(
                OAUTH_ACTORS.find(a => a.id === currentStep().to)?.nameJa ?? "",
                OAUTH_ACTORS.find(a => a.id === currentStep().to)?.name ?? ""
              )}
            </span>
          </div>
          <h3 class="detail-action">{t(currentStep().actionJa, currentStep().action)}</h3>
          <p class="detail-desc">{t(currentStep().descriptionJa, currentStep().description)}</p>
          <Show when={currentStep().dataPayload}>
            <pre class="detail-payload mono">{currentStep().dataPayload}</pre>
          </Show>
          <div class="detail-layers mono">
            OSI: {currentStep().osiLayers.map(l => `L${l}`).join(", ")}
          </div>
        </div>
      </Show>

      {/* Live OAuth Flow */}
      <div class="oauth-live-section">
        <Show when={!liveMode()} fallback={
          <div class="oauth-live-panel">
            <div class="live-header">
              <h4 class="demo-title">
                {t("ライブ OAuth 2.0 フロー", "Live OAuth 2.0 Flow")}
                <span class="demo-badge">{t("実動作", "Live")}</span>
              </h4>
              <button class="demo-submit side-btn" onClick={() => setLiveMode(false)}>
                {t("閉じる", "Close")}
              </button>
            </div>

            <div class="live-data-cards">
              <Show when={liveData().code}>
                <div class="live-data-card">
                  <span class="ldc-label mono">Authorization Code</span>
                  <span class="ldc-value mono">{liveData().code}</span>
                </div>
              </Show>
              <Show when={liveData().accessToken}>
                <div class="live-data-card">
                  <span class="ldc-label mono">Access Token</span>
                  <span class="ldc-value mono">{liveData().accessToken?.substring(0, 40)}...</span>
                </div>
              </Show>
              <Show when={liveData().refreshToken}>
                <div class="live-data-card">
                  <span class="ldc-label mono">Refresh Token</span>
                  <span class="ldc-value mono">{liveData().refreshToken}</span>
                </div>
              </Show>
              <Show when={liveData().resource}>
                <div class="live-data-card success-card">
                  <span class="ldc-label mono">{t("保護リソース取得成功", "Protected Resource")}</span>
                  <span class="ldc-value mono">{JSON.stringify(liveData().resource?.resource?.data || liveData().resource, null, 1)}</span>
                </div>
              </Show>
            </div>

            <Show when={liveError()}>
              <div class="demo-result error" role="alert">✗ {liveError()}</div>
            </Show>

            <button
              class="demo-submit"
              onClick={nextLiveStep}
              disabled={liveLoading() || liveStep() >= OAUTH_STEPS.length - 1}
            >
              {liveLoading()
                ? t("処理中...", "Processing...")
                : t("次のステップを実行", "Execute Next Step")
              } ({liveStep() + 1}/{OAUTH_STEPS.length})
            </button>

            <DataFlowPanel scopeId={SCOPE} defaultOpen={true} />
          </div>
        }>
          <button class="demo-submit oauth-live-btn" onClick={startLiveFlow}>
            {t("ライブ OAuth フローを開始", "Start Live OAuth Flow")}
          </button>
        </Show>
      </div>
    </div>
  );
}

export default function OAuthFlow() {
  return (
    <div class="oauth-flow-wrapper">
      {/* View mode toggle (Defender / Attacker) — 両モード共通領域 */}
      <ViewModeToggle tabId="oauth" />

      <Show when={getViewMode("oauth") === "defender"}>
        <OAuthFlowDefender />
      </Show>

      {/* Attacker mode: attack scenario panel */}
      <Show when={getViewMode("oauth") === "attacker"}>
        <AttackPanel
          tabId="oauth"
          scenarios={oauthScenarios}
          allowedTargets={["victim-web"]}
          onRunScenario={async (s) => {
            const suffix = s.id.replace(/^oauth-/, "");
            // E-2: 両モード並列実行のため body は不要 (空オブジェクト)
            const res = await apiPost<AttackResult>(
              `/api/oauth/attack/${suffix}`,
              {},
              "attack-oauth"
            );
            if (!res.data) {
              return {
                scenarioId: s.id,
                outcome: "error" as const,
                startedAt: Date.now(),
                finishedAt: Date.now(),
                steps: [],
                summaryJa: res.error ?? "実行エラーが発生しました",
                summary: res.error ?? "Execution error occurred",
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
              "attack-oauth"
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
