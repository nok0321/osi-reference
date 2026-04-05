import { For, Show, createSignal } from "solid-js";
import { useI18n } from "../../i18n/context";
import { tlsDeepStep, setTlsDeepStep } from "../../state/security-state";
import { TLS_DEEP_STEPS } from "../../data/auth-flows";
import type { TlsStep } from "../../types/security";
import StepControl from "../shared/StepControl";
import "./TlsDeepDive.css";

export default function TlsDeepDive() {
  const { t } = useI18n();
  const [expandedStep, setExpandedStep] = createSignal<number | null>(null);

  function toggleExpand(idx: number) {
    setExpandedStep(prev => prev === idx ? null : idx);
  }

  // Step 1 = TCP (plaintext), steps 2-3 = handshake (mixed), steps 4+ = encrypted
  function getEncryptionState(step: TlsStep): "plaintext" | "handshake" | "encrypted" {
    if (step.stepNumber <= 1) return "plaintext";
    if (step.stepNumber <= 3) return "handshake";
    return "encrypted";
  }

  return (
    <div class="tls-deep-dive">
      <div class="tls-controls">
        <StepControl
          current={tlsDeepStep()}
          total={TLS_DEEP_STEPS.length}
          onPrev={() => setTlsDeepStep(prev => Math.max(0, prev - 1))}
          onNext={() => setTlsDeepStep(prev => Math.min(TLS_DEEP_STEPS.length - 1, prev + 1))}
          label="TLS"
        />
      </div>

      <div class="tls-timeline">
        {/* Column headers */}
        <div class="timeline-headers">
          <div class="th-client mono">{t("クライアント", "Client")}</div>
          <div class="th-middle" />
          <div class="th-server mono">{t("サーバー", "Server")}</div>
        </div>

        {/* Encryption threshold line */}
        <div class="encryption-legend">
          <span class="legend-item plaintext">
            <span class="legend-dot" /> {t("平文", "Plaintext")}
          </span>
          <span class="legend-item handshake">
            <span class="legend-dot" /> {t("ハンドシェイク", "Handshake")}
          </span>
          <span class="legend-item encrypted">
            <span class="legend-dot" /> {t("暗号化", "Encrypted")}
          </span>
        </div>

        {/* Steps */}
        <For each={TLS_DEEP_STEPS}>
          {(step: TlsStep, i) => {
            const isCurrent = () => i() === tlsDeepStep();
            const isPast = () => i() < tlsDeepStep();
            const isExpanded = () => expandedStep() === i();
            const encState = () => getEncryptionState(step);

            return (
              <div
                class="tls-step"
                classList={{
                  current: isCurrent(),
                  past: isPast(),
                  future: !isCurrent() && !isPast(),
                  expanded: isExpanded(),
                }}
                data-enc={encState()}
                onClick={() => { setTlsDeepStep(i()); toggleExpand(i()); }}
              >
                <div class="step-row">
                  {/* Direction indicator */}
                  <div class="step-side client-side">
                    <Show when={step.direction === "client-to-server" || step.direction === "both"}>
                      <div class="direction-dot client-dot" />
                    </Show>
                  </div>

                  <div class="step-center">
                    <div class="step-arrow" classList={{
                      "arrow-right": step.direction === "client-to-server",
                      "arrow-left": step.direction === "server-to-client",
                      "arrow-both": step.direction === "both",
                    }}>
                      <span class="step-name">{step.name}</span>
                    </div>
                  </div>

                  <div class="step-side server-side">
                    <Show when={step.direction === "server-to-client" || step.direction === "both"}>
                      <div class="direction-dot server-dot" />
                    </Show>
                  </div>
                </div>

                {/* Expanded detail card */}
                <Show when={isExpanded()}>
                  <div class="step-detail-card">
                    <p class="sdc-desc">{t(step.descriptionJa, step.description)}</p>
                    <Show when={step.cryptoDetails}>
                      <div class="sdc-crypto">
                        <span class="crypto-label mono">{t("暗号詳細", "Crypto Details")}</span>
                        <p class="crypto-text">{t(step.cryptoDetailsJa!, step.cryptoDetails!)}</p>
                      </div>
                    </Show>
                    <div class="sdc-fields">
                      <For each={step.dataFields}>
                        {(field) => (
                          <div class="sdc-field">
                            <span class="sdc-key mono">{field.name}</span>
                            <span class="sdc-val mono">{field.value}</span>
                          </div>
                        )}
                      </For>
                    </div>
                    <div class="sdc-layer mono">OSI Layer: L{step.osiLayer}</div>
                  </div>
                </Show>
              </div>
            );
          }}
        </For>
      </div>
    </div>
  );
}
