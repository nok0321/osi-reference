import { For, Show, createSignal } from "solid-js";
import { useI18n } from "../../i18n/context";
import { KERBEROS_ACTORS, KERBEROS_STEPS } from "../../data/protocol-flows";
import type { KerberosStep, ProtocolActor } from "../../types/security";
import StepControl from "../shared/StepControl";
import "./KerberosFlow.css";

export default function KerberosFlow() {
  const { t } = useI18n();
  const [stepIdx, setStepIdx] = createSignal(0);

  const step = () => KERBEROS_STEPS[stepIdx()];

  function getActorColor(id: string): string {
    return KERBEROS_ACTORS.find((a: ProtocolActor) => a.id === id)?.color || "#888";
  }

  function getActorName(id: string): string {
    const actor = KERBEROS_ACTORS.find((a: ProtocolActor) => a.id === id);
    return actor ? t(actor.nameJa, actor.name) : id;
  }

  return (
    <div class="kerberos-flow">
      <p class="kerb-desc">
        {t(
          "Kerberosはチケットベースの認証プロトコル。KDC（鍵配布センター）が認証サービス(AS)とチケット発行サービス(TGS)を提供し、ユーザーはパスワードを一度入力するだけで複数サービスにアクセス可能。",
          "Kerberos is a ticket-based authentication protocol. The KDC (Key Distribution Center) provides Authentication Service (AS) and Ticket-Granting Service (TGS), allowing users to access multiple services with a single password entry."
        )}
      </p>

      {/* Actors */}
      <div class="kerb-actors">
        <For each={KERBEROS_ACTORS}>
          {(actor: ProtocolActor) => (
            <span class="kerb-actor-chip" style={{ "--ac-color": actor.color }}>
              {t(actor.nameJa, actor.name)}
            </span>
          )}
        </For>
      </div>

      <StepControl
        current={stepIdx()}
        total={KERBEROS_STEPS.length}
        onPrev={() => setStepIdx(p => Math.max(0, p - 1))}
        onNext={() => setStepIdx(p => Math.min(KERBEROS_STEPS.length - 1, p + 1))}
      />

      <Show when={step()}>
        <div class="kerb-step-card">
          <div class="kerb-step-header">
            <span class="kerb-step-num mono">Step {step()!.stepNumber}</span>
            <span class="kerb-step-action">{t(step()!.actionJa, step()!.action)}</span>
          </div>
          <div class="kerb-step-flow">
            <span style={{ color: getActorColor(step()!.from) }}>{getActorName(step()!.from)}</span>
            <span class="kerb-arrow">→</span>
            <span style={{ color: getActorColor(step()!.to) }}>{getActorName(step()!.to)}</span>
          </div>
          <p class="kerb-step-desc">{t(step()!.descriptionJa, step()!.description)}</p>
          <Show when={step()!.ticket}>
            <div class="kerb-ticket">
              <span class="kerb-ticket-label mono">{t("チケット", "Ticket")}</span>
              <span class="kerb-ticket-name mono">{step()!.ticket}</span>
            </div>
          </Show>
        </div>
      </Show>

      {/* Timeline */}
      <div class="kerb-timeline">
        <For each={KERBEROS_STEPS}>
          {(s: KerberosStep, i) => (
            <div
              class="kerb-tl-item"
              classList={{ active: i() === stepIdx(), past: i() < stepIdx() }}
              onClick={() => setStepIdx(i())}
            >
              <span class="kerb-tl-num mono">{s.stepNumber}</span>
              <span class="kerb-tl-label">{t(s.actionJa, s.action)}</span>
              <Show when={s.ticket}>
                <span class="kerb-tl-ticket mono">{s.ticket}</span>
              </Show>
            </div>
          )}
        </For>
      </div>

      {/* Swimlane diagram */}
      <div class="kerb-swimlane">
        <div class="kerb-swim-title mono">{t("Kerberos フロー概要", "Kerberos Flow Overview")}</div>
        <div class="kerb-swim-grid">
          <For each={KERBEROS_ACTORS}>
            {(actor: ProtocolActor) => (
              <div class="kerb-swim-lane">
                <div class="kerb-swim-header" style={{ "--lane-color": actor.color }}>
                  {t(actor.nameJa, actor.name)}
                </div>
                <div class="kerb-swim-body">
                  <For each={KERBEROS_STEPS}>
                    {(s: KerberosStep, i) => (
                      <Show when={s.from === actor.id || s.to === actor.id}>
                        <div
                          class="kerb-swim-event"
                          classList={{
                            active: i() === stepIdx(),
                            sender: s.from === actor.id,
                            receiver: s.to === actor.id,
                          }}
                          style={{
                            "--ev-color": s.from === actor.id
                              ? getActorColor(s.from)
                              : getActorColor(s.to),
                          }}
                          onClick={() => setStepIdx(i())}
                        >
                          <span class="kerb-ev-num mono">{s.stepNumber}</span>
                          <span class="kerb-ev-dir">{s.from === actor.id ? "→" : "←"}</span>
                        </div>
                      </Show>
                    )}
                  </For>
                </div>
              </div>
            )}
          </For>
        </div>
      </div>
    </div>
  );
}
