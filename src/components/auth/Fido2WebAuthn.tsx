import { For, Show, createSignal } from "solid-js";
import { useI18n } from "../../i18n/context";
import {
  FIDO2_ACTORS, FIDO2_REGISTRATION_STEPS, FIDO2_AUTH_STEPS,
} from "../../data/protocol-flows";
import type { ProtocolFlowStep, ProtocolActor } from "../../types/security";
import StepControl from "../shared/StepControl";
import "./Fido2WebAuthn.css";

export default function Fido2WebAuthn() {
  const { t } = useI18n();
  const [ceremony, setCeremony] = createSignal<"register" | "auth">("register");
  const [regStep, setRegStep] = createSignal(0);
  const [authStep, setAuthStep] = createSignal(0);

  const steps = () => ceremony() === "register" ? FIDO2_REGISTRATION_STEPS : FIDO2_AUTH_STEPS;
  const currentIdx = () => ceremony() === "register" ? regStep() : authStep();
  const setCurrentIdx = (v: number | ((p: number) => number)) => {
    if (ceremony() === "register") setRegStep(v as any);
    else setAuthStep(v as any);
  };
  const step = () => steps()[currentIdx()];

  function getActorColor(id: string): string {
    return FIDO2_ACTORS.find((a: ProtocolActor) => a.id === id)?.color || "#888";
  }

  return (
    <div class="fido2-webauthn">
      <div class="fido2-toggle">
        <button
          class="fido2-mode-btn"
          classList={{ active: ceremony() === "register" }}
          onClick={() => setCeremony("register")}
        >
          {t("登録セレモニー", "Registration")}
        </button>
        <button
          class="fido2-mode-btn"
          classList={{ active: ceremony() === "auth" }}
          onClick={() => setCeremony("auth")}
        >
          {t("認証セレモニー", "Authentication")}
        </button>
      </div>

      <p class="fido2-desc">
        <Show when={ceremony() === "register"}>
          {t(
            "FIDO2/WebAuthn登録：ユーザーの認証器が新しい公開鍵ペアを生成し、リライングパーティに登録する。秘密鍵は認証器から外に出ない。",
            "FIDO2/WebAuthn Registration: The user's authenticator generates a new key pair and registers the public key with the Relying Party. The private key never leaves the authenticator."
          )}
        </Show>
        <Show when={ceremony() === "auth"}>
          {t(
            "FIDO2/WebAuthn認証：リライングパーティがチャレンジを送信し、認証器が秘密鍵で署名して返す。オリジンに紐づくためフィッシング耐性がある。",
            "FIDO2/WebAuthn Authentication: The Relying Party sends a challenge, and the authenticator signs it with the private key. Origin-bound, making it phishing-resistant."
          )}
        </Show>
      </p>

      {/* Actors */}
      <div class="fido2-actors">
        <For each={FIDO2_ACTORS}>
          {(actor: ProtocolActor) => (
            <span class="fido2-actor-chip" style={{ "--ac-color": actor.color }}>
              {t(actor.nameJa, actor.name)}
            </span>
          )}
        </For>
      </div>

      <StepControl
        current={currentIdx()}
        total={steps().length}
        onPrev={() => setCurrentIdx((p: number) => Math.max(0, p - 1))}
        onNext={() => setCurrentIdx((p: number) => Math.min(steps().length - 1, p + 1))}
      />

      <Show when={step()}>
        <div class="fido2-step-card">
          <div class="fido2-step-header">
            <span class="fido2-step-num mono">Step {step()!.stepNumber}</span>
            <span class="fido2-step-action">{t(step()!.actionJa, step()!.action)}</span>
          </div>
          <div class="fido2-step-flow">
            <span style={{ color: getActorColor(step()!.from) }}>
              {FIDO2_ACTORS.find((a: ProtocolActor) => a.id === step()!.from)?.name || step()!.from}
            </span>
            <span class="fido2-arrow">→</span>
            <span style={{ color: getActorColor(step()!.to) }}>
              {FIDO2_ACTORS.find((a: ProtocolActor) => a.id === step()!.to)?.name || step()!.to}
            </span>
          </div>
          <p class="fido2-step-desc">{t(step()!.descriptionJa, step()!.description)}</p>
          <Show when={step()!.dataPayload}>
            <pre class="fido2-payload mono">{step()!.dataPayload}</pre>
          </Show>
        </div>
      </Show>

      {/* Timeline */}
      <div class="fido2-timeline">
        <For each={steps()}>
          {(s: ProtocolFlowStep, i) => (
            <div
              class="fido2-tl-item"
              classList={{ active: i() === currentIdx(), past: i() < currentIdx() }}
              onClick={() => setCurrentIdx(i())}
            >
              <span class="fido2-tl-num mono">{s.stepNumber}</span>
              <span class="fido2-tl-label">{t(s.actionJa, s.action)}</span>
            </div>
          )}
        </For>
      </div>

      {/* Key concepts */}
      <div class="fido2-concepts">
        <div class="fido2-concept-title mono">{t("FIDO2 主要概念", "FIDO2 Key Concepts")}</div>
        <div class="fido2-concept-grid">
          <div class="fido2-concept">
            <span class="fc-label mono">{t("オリジンバインディング", "Origin Binding")}</span>
            <span class="fc-val">{t("クレデンシャルはRP IDに紐づき、別オリジンでは使用不可", "Credentials are bound to the RP ID and cannot be used on different origins")}</span>
          </div>
          <div class="fido2-concept">
            <span class="fc-label mono">{t("公開鍵暗号", "Public Key Crypto")}</span>
            <span class="fc-val">{t("共有秘密なし。サーバーは公開鍵のみ保存", "No shared secrets. Server only stores the public key")}</span>
          </div>
          <div class="fido2-concept">
            <span class="fc-label mono">{t("ユーザー検証", "User Verification")}</span>
            <span class="fc-val">{t("ローカルで生体/PINによるユーザー確認", "Local biometric/PIN verification of the user")}</span>
          </div>
          <div class="fido2-concept">
            <span class="fc-label mono">{t("アテステーション", "Attestation")}</span>
            <span class="fc-val">{t("認証器のハードウェア/ソフトウェアの信頼性を証明", "Proves the authenticity of the authenticator hardware/software")}</span>
          </div>
        </div>
      </div>
    </div>
  );
}
