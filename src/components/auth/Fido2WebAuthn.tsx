import { For, Show, createSignal, onMount, onCleanup } from "solid-js";
import { useI18n } from "../../i18n/context";
import {
  FIDO2_ACTORS, FIDO2_REGISTRATION_STEPS, FIDO2_AUTH_STEPS,
} from "../../data/protocol-flows";
import type { ProtocolFlowStep, ProtocolActor } from "../../types/security";
import { apiPost, apiGet } from "../../api/client";
import type { WebAuthnRegisterOptionsData, WebAuthnAuthOptionsData } from "../../types/auth-responses";
import { startRegistration, startAuthentication } from "@simplewebauthn/browser";
import DataFlowPanel from "../shared/DataFlowPanel";
import StepControl from "../shared/StepControl";
import "./Fido2WebAuthn.css";

const SCOPE = "fido2-webauthn";

function Fido2Demo() {
  const { t } = useI18n();
  const ac = new AbortController();
  onCleanup(() => ac.abort());

  const [username, setUsername] = createSignal("");
  const [result, setResult] = createSignal<{ ok: boolean; message: string } | null>(null);
  const [loading, setLoading] = createSignal(false);
  interface CredentialDisplay { username?: string; user?: string; credential_id?: string; credentialId?: string; id?: string; created_at?: string; createdAt?: string }
  const [credentials, setCredentials] = createSignal<CredentialDisplay[]>([]);

  async function fetchCredentials() {
    const res = await apiGet<{ credentials: CredentialDisplay[] }>("/api/webauthn/credentials", SCOPE, ac.signal);
    if (ac.signal.aborted) return;
    if (res.data) setCredentials(res.data.credentials ?? []);
  }

  async function handleRegister() {
    if (!username()) return;
    setLoading(true);
    setResult(null);

    try {
      // Step 1: Get registration options from server
      const optRes = await apiPost<WebAuthnRegisterOptionsData>("/api/webauthn/register/options", { username: username() }, SCOPE, undefined, ac.signal);
      if (ac.signal.aborted) return;
      if (optRes.error) {
        setResult({ ok: false, message: optRes.error });
        setLoading(false);
        return;
      }

      // Step 2: Create credential using browser WebAuthn API
      const attestationResponse = await startRegistration({ optionsJSON: optRes.data!.options as Parameters<typeof startRegistration>[0]["optionsJSON"] });
      if (ac.signal.aborted) return;

      // Step 3: Verify with server
      const verifyRes = await apiPost<Record<string, unknown>>("/api/webauthn/register/verify", {
        username: username(),
        response: attestationResponse,
      }, SCOPE, undefined, ac.signal);
      if (ac.signal.aborted) return;

      if (verifyRes.error) {
        setResult({ ok: false, message: verifyRes.error });
      } else {
        setResult({ ok: true, message: t("登録成功！", "Registration successful!") });
        fetchCredentials();
      }
    } catch (err: unknown) {
      if (ac.signal.aborted) return;
      setResult({
        ok: false,
        message: (err instanceof Error ? err.message : null) || t("WebAuthn未対応のブラウザです", "WebAuthn not supported in this browser"),
      });
    }

    setLoading(false);
  }

  async function handleAuthenticate() {
    if (!username()) return;
    setLoading(true);
    setResult(null);

    try {
      // Step 1: Get authentication options from server
      const optRes = await apiPost<WebAuthnAuthOptionsData>("/api/webauthn/auth/options", { username: username() }, SCOPE, undefined, ac.signal);
      if (ac.signal.aborted) return;
      if (optRes.error) {
        setResult({ ok: false, message: optRes.error });
        setLoading(false);
        return;
      }

      // Step 2: Get assertion using browser WebAuthn API
      const assertionResponse = await startAuthentication({ optionsJSON: optRes.data!.options as Parameters<typeof startAuthentication>[0]["optionsJSON"] });
      if (ac.signal.aborted) return;

      // Step 3: Verify with server
      const verifyRes = await apiPost<Record<string, unknown>>("/api/webauthn/auth/verify", {
        username: username(),
        response: assertionResponse,
      }, SCOPE, undefined, ac.signal);
      if (ac.signal.aborted) return;

      if (verifyRes.error) {
        setResult({ ok: false, message: verifyRes.error });
      } else {
        setResult({ ok: true, message: t("認証成功！", "Authentication successful!") });
      }
    } catch (err: unknown) {
      if (ac.signal.aborted) return;
      setResult({
        ok: false,
        message: (err instanceof Error ? err.message : null) || t("WebAuthn未対応のブラウザです", "WebAuthn not supported in this browser"),
      });
    }

    setLoading(false);
  }

  onMount(() => fetchCredentials());

  return (
    <div class="password-demo">
      <h4 class="demo-title">
        {t("WebAuthn デモ", "WebAuthn Demo")}
        <span class="demo-badge">{t("実動作", "Live")}</span>
      </h4>

      <div class="demo-layout">
        <div class="demo-form-area">
          <form class="demo-form" onSubmit={(e) => e.preventDefault()}>
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
            <div style={{ display: "flex", gap: "8px" }}>
              <button
                type="button"
                class="demo-submit"
                disabled={loading() || !username()}
                onClick={handleRegister}
              >
                {loading() ? t("処理中...", "Processing...") : t("登録", "Register")}
              </button>
              <button
                type="button"
                class="demo-submit"
                disabled={loading() || !username()}
                onClick={handleAuthenticate}
              >
                {loading() ? t("処理中...", "Processing...") : t("認証", "Authenticate")}
              </button>
            </div>
          </form>

          <Show when={result()}>
            <div
              class="demo-result"
              role="alert"
              classList={{ success: result()!.ok, error: !result()!.ok }}
            >
              {result()!.ok ? "✓" : "✗"} {result()!.message}
            </div>
          </Show>
        </div>

        <div class="demo-db-area">
          <div class="db-panel-title mono">
            {t("credentials テーブル", "credentials table")}
            <button class="db-refresh" onClick={fetchCredentials}>↻</button>
          </div>
          <Show when={credentials().length > 0} fallback={
            <div class="db-empty">{t("クレデンシャルなし", "No credentials yet")}</div>
          }>
            <div class="db-table-wrap">
              <table class="db-table">
                <thead>
                  <tr>
                    <th>{t("ユーザー", "User")}</th>
                    <th>{t("クレデンシャルID", "Credential ID")}</th>
                    <th>{t("作成日時", "Created")}</th>
                  </tr>
                </thead>
                <tbody>
                  <For each={credentials()}>
                    {(c) => (
                      <tr>
                        <td>{c.username || c.user}</td>
                        <td class="db-hash-cell">
                          <span class="hash-preview">{(c.credentialId || c.id || "").substring(0, 20)}...</span>
                        </td>
                        <td>{c.created_at || c.createdAt || "—"}</td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </div>
          </Show>
        </div>
      </div>

      <DataFlowPanel scopeId={SCOPE} />
    </div>
  );
}

export default function Fido2WebAuthn() {
  const { t } = useI18n();
  const [ceremony, setCeremony] = createSignal<"register" | "auth">("register");
  const [regStep, setRegStep] = createSignal(0);
  const [authStep, setAuthStep] = createSignal(0);

  const steps = () => ceremony() === "register" ? FIDO2_REGISTRATION_STEPS : FIDO2_AUTH_STEPS;
  const currentIdx = () => ceremony() === "register" ? regStep() : authStep();
  const setCurrentIdx = (v: number | ((p: number) => number)) => {
    if (ceremony() === "register") setRegStep(v as number | ((p: number) => number));
    else setAuthStep(v as number | ((p: number) => number));
  };
  const step = () => steps()[currentIdx()];

  function getActorColor(id: string): string {
    return FIDO2_ACTORS.find((a: ProtocolActor) => a.id === id)?.color || "#888";
  }

  return (
    <div class="fido2-webauthn">
      <Fido2Demo />

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
