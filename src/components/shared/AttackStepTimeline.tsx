import { For, Show, createSignal } from "solid-js";
import { Motion } from "solid-motionone";
import { useI18n } from "../../i18n/context";
import type { AttackStep } from "../../../shared/api-types";
import { safeStringify } from "../../utils/safe-stringify";
import "./AttackStepTimeline.css";

interface AttackStepTimelineProps {
  steps: AttackStep[];
  running?: boolean;
}

/** kind → アイコン文字 (絵文字禁止、Unicode 装飾文字のみ) */
const KIND_ICONS: Record<string, string> = {
  intercept: "◉",
  tamper: "✎",
  replay: "↻",
  forge: "⚒",
  probe: "?",
  verify: "✓",
  exploit: "!",
  blocked: "[x]",
};

/** status → CSS カスタムプロパティ値 */
function statusColor(status: AttackStep["status"]): string {
  switch (status) {
    case "pending": return "var(--text-muted)";
    case "running": return "var(--glow-color)";
    case "success": return "var(--color-attack-accent)";
    case "failed": return "var(--color-danger)";
    case "blocked": return "var(--color-success)";
    default: return "var(--text-muted)";
  }
}

function StepCard(props: { step: AttackStep }) {
  const { t } = useI18n();
  const [payloadOpen, setPayloadOpen] = createSignal(false);

  return (
    <Motion
      initial={{ opacity: 0, x: -16 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.25, easing: "ease-out" }}
    >
      <div
        class="attack-step-card"
        data-status={props.step.status}
        style={{ "--step-color": statusColor(props.step.status) }}
      >
        <div class="attack-step-header">
          <span class="attack-step-icon" aria-hidden="true">
            {KIND_ICONS[props.step.kind] ?? "?"}
          </span>
          <span class="attack-step-label">
            {t(props.step.labelJa, props.step.label)}
          </span>
          <span class="attack-step-status" data-status={props.step.status}>
            {props.step.status.toUpperCase()}
          </span>
        </div>

        <Show when={props.step.detail || props.step.detailJa}>
          <div class="attack-step-detail">
            {t(props.step.detailJa ?? "", props.step.detail ?? "")}
          </div>
        </Show>

        <Show when={props.step.payload !== undefined}>
          <div class="attack-step-payload-area">
            <button
              class="attack-step-payload-toggle"
              aria-expanded={payloadOpen()}
              onClick={() => setPayloadOpen(!payloadOpen())}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  setPayloadOpen(!payloadOpen());
                }
              }}
            >
              {t("ペイロード", "Payload")} {payloadOpen() ? "▾" : "▸"}
            </button>
            <Show when={payloadOpen()}>
              <pre class="json-block attack-step-payload-json">
                {safeStringify(props.step.payload, 2)}
              </pre>
            </Show>
          </div>
        </Show>
      </div>
    </Motion>
  );
}

function AttackStepTimeline(props: AttackStepTimelineProps) {
  const { t } = useI18n();

  return (
    <div
      class="attack-step-timeline"
      role="log"
      aria-live="polite"
      aria-label={t("攻撃ステップログ", "Attack step log")}
    >
      <Show when={props.steps.length === 0}>
        <div class="attack-step-empty">
          {t("攻撃ステップなし", "No attack steps yet")}
        </div>
      </Show>
      <div class="attack-step-list">
        <For each={props.steps}>
          {(step) => <StepCard step={step} />}
        </For>
      </div>
    </div>
  );
}

export default AttackStepTimeline;
