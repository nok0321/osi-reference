import { For, Show, createMemo } from "solid-js";
import { useI18n } from "../../i18n/context";
import { oauthStep, setOauthStep } from "../../state/security-state";
import { OAUTH_STEPS, OAUTH_ACTORS } from "../../data/auth-flows";
import type { OAuthStep } from "../../types/security";
import StepControl from "../shared/StepControl";
import "./OAuthFlow.css";

export default function OAuthFlow() {
  const { t } = useI18n();

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
                onClick={() => setOauthStep(i())}
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
    </div>
  );
}
