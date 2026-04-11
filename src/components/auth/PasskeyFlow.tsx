import { For, Show, createSignal, onMount, onCleanup } from "solid-js";
import { useI18n } from "../../i18n/context";
import {
  PASSKEY_ACTORS, PASSKEY_REGISTRATION_STEPS, PASSKEY_AUTH_STEPS,
} from "../../data/protocol-flows";
import type { ProtocolFlowStep, ProtocolActor } from "../../types/security";
import type { PasskeyRegisterOptionsData, PasskeyAuthOptionsData } from "../../types/auth-responses";
import { apiPost, apiGet } from "../../api/client";
import { startRegistration, startAuthentication, browserSupportsWebAuthnAutofill, WebAuthnAbortService } from "@simplewebauthn/browser";
import DataFlowPanel from "../shared/DataFlowPanel";
import StepControl from "../shared/StepControl";
import "./PasskeyFlow.css";

const SCOPE = "passkey";

function PasskeyDemo() {
  const { t } = useI18n();
  const ac = new AbortController();
  onCleanup(() => {
    ac.abort();
    conditionalUiActive = false;
    WebAuthnAbortService.cancelCeremony();
  });

  const [username, setUsername] = createSignal("");
  const [result, setResult] = createSignal<{ ok: boolean; message: string } | null>(null);
  const [loading, setLoading] = createSignal(false);
  interface CredentialDisplay { username?: string; credential_id?: string; counter?: number; created_at?: string }
  const [credentials, setCredentials] = createSignal<CredentialDisplay[]>([]);
  const [deviceType, setDeviceType] = createSignal<string | null>(null);
  const [resolvedUser, setResolvedUser] = createSignal<string | null>(null);
  const [autofillSupported, setAutofillSupported] = createSignal(false);
  let conditionalUiActive = false;

  async function fetchCredentials() {
    const res = await apiGet<{ credentials: CredentialDisplay[] }>("/api/passkey/credentials", SCOPE, ac.signal);
    if (ac.signal.aborted) return;
    if (res.data) setCredentials(res.data.credentials ?? []);
  }

  async function handleRegister() {
    if (!username()) return;
    setLoading(true);
    setResult(null);
    setDeviceType(null);

    try {
      // Step 1: Get registration options from server (residentKey: required)
      const optRes = await apiPost<PasskeyRegisterOptionsData>("/api/passkey/register/options", { username: username() }, SCOPE, undefined, ac.signal);
      if (ac.signal.aborted) return;
      if (optRes.error) {
        setResult({ ok: false, message: optRes.error });
        setLoading(false);
        return;
      }

      // Step 2: Create discoverable credential using browser WebAuthn API
      const attestationResponse = await startRegistration({ optionsJSON: optRes.data!.options as Parameters<typeof startRegistration>[0]["optionsJSON"] });
      if (ac.signal.aborted) return;

      // Step 3: Verify with server
      const verifyRes = await apiPost<{
        verified: boolean;
        credentialDeviceType: string;
        credentialBackedUp: boolean;
        credentialId: string;
      }>("/api/passkey/register/verify", {
        username: username(),
        response: attestationResponse,
      }, SCOPE, undefined, ac.signal);
      if (ac.signal.aborted) return;

      if (verifyRes.error) {
        setResult({ ok: false, message: verifyRes.error });
      } else if (verifyRes.data) {
        setDeviceType(verifyRes.data.credentialDeviceType);
        setResult({
          ok: true,
          message: t(
            `パスキー登録成功！ デバイスタイプ: ${verifyRes.data.credentialDeviceType}${verifyRes.data.credentialBackedUp ? "（同期済み）" : ""}`,
            `Passkey registered! Device type: ${verifyRes.data.credentialDeviceType}${verifyRes.data.credentialBackedUp ? " (synced)" : ""}`
          ),
        });
        fetchCredentials();
      }
    } catch (err: unknown) {
      if (ac.signal.aborted) return;
      setResult({
        ok: false,
        message: (err instanceof Error ? err.message : null) || t("WebAuthn未対応のブラウザです", "WebAuthn not supported"),
      });
    }

    setLoading(false);
  }

  async function handleAuthButton() {
    setLoading(true);
    setResult(null);
    setResolvedUser(null);

    try {
      // Step 1: Get auth options — no username!
      const optRes = await apiPost<PasskeyAuthOptionsData>("/api/passkey/auth/options", {}, SCOPE, undefined, ac.signal);
      if (ac.signal.aborted) return;
      if (optRes.error) {
        setResult({ ok: false, message: optRes.error });
        setLoading(false);
        return;
      }

      // Step 2: Browser shows passkey picker
      const assertionResponse = await startAuthentication({ optionsJSON: optRes.data!.options as Parameters<typeof startAuthentication>[0]["optionsJSON"] });
      if (ac.signal.aborted) return;

      // Step 3: Verify with server — server resolves identity from credential
      const verifyRes = await apiPost<{
        verified: boolean;
        username: string;
        credentialId: string;
      }>("/api/passkey/auth/verify", {
        sessionId: optRes.data!.sessionId,
        response: assertionResponse,
      }, SCOPE, undefined, ac.signal);
      if (ac.signal.aborted) return;

      if (verifyRes.error) {
        setResult({ ok: false, message: verifyRes.error });
      } else if (verifyRes.data) {
        setResolvedUser(verifyRes.data.username);
        setResult({
          ok: true,
          message: t(
            `認証成功！ ユーザー名なしでサインインしました。`,
            `Authentication successful! Signed in without a username.`
          ),
        });
      }
    } catch (err: unknown) {
      if (ac.signal.aborted) return;
      const msg = err instanceof Error ? err.message : "";
      if (msg.includes("AbortError") || msg.includes("abort")) {
        // Conditional UI was cancelled (e.g. user switched tabs)
        setResult(null);
      } else {
        setResult({
          ok: false,
          message: msg || t("認証に失敗しました", "Authentication failed"),
        });
      }
    }

    setLoading(false);
  }

  async function setupConditionalUi() {
    try {
      const supported = await browserSupportsWebAuthnAutofill();
      if (ac.signal.aborted) return;
      setAutofillSupported(supported);
      if (!supported) return;

      // Get fresh auth options from server
      const optRes = await apiPost<PasskeyAuthOptionsData>("/api/passkey/auth/options", {}, SCOPE, undefined, ac.signal);
      if (ac.signal.aborted) return;
      if (optRes.error || !optRes.data) return;

      conditionalUiActive = true;
      const assertionResponse = await startAuthentication({
        optionsJSON: optRes.data.options as Parameters<typeof startAuthentication>[0]["optionsJSON"],
        useBrowserAutofill: true,
      });
      if (ac.signal.aborted) return;
      conditionalUiActive = false;

      // Verify
      const verifyRes = await apiPost<{
        verified: boolean;
        username: string;
        credentialId: string;
      }>("/api/passkey/auth/verify", {
        sessionId: optRes.data.sessionId,
        response: assertionResponse,
      }, SCOPE, undefined, ac.signal);
      if (ac.signal.aborted) return;

      if (verifyRes.data) {
        setResolvedUser(verifyRes.data.username);
        setResult({
          ok: true,
          message: t(
            "Conditional UI で認証成功！ ブラウザのオートフィルからパスキーが選択されました。",
            "Authenticated via Conditional UI! Passkey selected from browser autofill."
          ),
        });
      }
    } catch {
      conditionalUiActive = false;
      // Silently fail — conditional UI is an enhancement, not required
    }
  }

  onMount(() => {
    fetchCredentials();
    setupConditionalUi();
  });

  return (
    <div class="password-demo">
      <h4 class="demo-title">
        {t("Passkey デモ", "Passkey Demo")}
        <span class="demo-badge">{t("実動作", "Live")}</span>
      </h4>

      <div class="passkey-autofill-banner">
        <Show when={autofillSupported()} fallback={
          t("このブラウザはConditional UI（パスキーオートフィル）をサポートしていません。ボタンクリックで認証してください。",
            "This browser doesn't support Conditional UI (passkey autofill). Use the button to authenticate.")
        }>
          {t("下のユーザー名入力欄にフォーカスすると、ブラウザが登録済みパスキーを自動提案します（Conditional UI）。",
            "Focus the username field below and your browser will suggest registered passkeys (Conditional UI).")}
        </Show>
      </div>

      <div class="demo-layout">
        <div class="demo-form-area">
          <form class="demo-form" onSubmit={(e) => e.preventDefault()}>
            <div class="form-field">
              <label class="form-label mono">{t("ユーザー名（登録用）", "Username (for registration)")}</label>
              <input
                type="text"
                class="form-input"
                autocomplete="username webauthn"
                value={username()}
                onInput={(e) => setUsername(e.currentTarget.value)}
                placeholder={t("パスキーで自動入力", "Passkey autofill")}
              />
              <span class="form-hint">
                {t("認証時はユーザー名不要 — パスキーが自動的にアカウントを識別します",
                  "No username needed for auth — passkey identifies your account automatically")}
              </span>
            </div>

            <button
              type="button"
              class="demo-submit"
              disabled={loading() || !username()}
              onClick={handleRegister}
            >
              {loading() ? "..." : t("パスキー登録", "Register Passkey")}
            </button>

            <div class="passkey-separator">{t("または", "or")}</div>

            <button
              type="button"
              class="demo-submit"
              disabled={loading()}
              onClick={handleAuthButton}
              style={{ background: "var(--color-success, #22C55E)" }}
            >
              {loading() ? "..." : t("パスキーでサインイン（ユーザー名不要）", "Sign in with Passkey (no username)")}
            </button>
          </form>

          <Show when={deviceType()}>
            <span class="passkey-device-badge" classList={{
              multi: deviceType() === "multiDevice",
              single: deviceType() !== "multiDevice",
            }}>
              {deviceType() === "multiDevice"
                ? t("☁ マルチデバイス（同期パスキー）", "☁ MultiDevice (synced passkey)")
                : t("🔒 シングルデバイス（デバイス固有）", "🔒 SingleDevice (device-bound)")}
            </span>
          </Show>

          <Show when={resolvedUser()}>
            <div class="passkey-identity-box">
              <div class="identity-label">{t("サーバーが識別したユーザー", "Server-Resolved Identity")}</div>
              <div class="identity-value">Welcome, {resolvedUser()}!</div>
            </div>
          </Show>

          <Show when={result()}>
            <div class="demo-result" role="alert" classList={{ success: result()!.ok, error: !result()!.ok }}>
              {result()!.ok ? "\u2713" : "\u2717"} {result()!.message}
            </div>
          </Show>
        </div>

        <div class="demo-db-area">
          <div class="db-panel-title mono">
            {t("credentials テーブル", "credentials table")}
            <button class="db-refresh" onClick={fetchCredentials}>\u21BB</button>
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
                        <td>{c.username}</td>
                        <td class="db-hash-cell">
                          <span class="hash-preview">{(c.credential_id || "").substring(0, 20)}...</span>
                        </td>
                        <td>{c.created_at || "\u2014"}</td>
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

export default function PasskeyFlow() {
  const { t } = useI18n();
  const [ceremony, setCeremony] = createSignal<"register" | "auth">("register");
  const [regStep, setRegStep] = createSignal(0);
  const [authStep, setAuthStep] = createSignal(0);

  const steps = () => ceremony() === "register" ? PASSKEY_REGISTRATION_STEPS : PASSKEY_AUTH_STEPS;
  const currentIdx = () => ceremony() === "register" ? regStep() : authStep();
  const setCurrentIdx = (v: number | ((p: number) => number)) => {
    if (ceremony() === "register") setRegStep(v as number | ((p: number) => number));
    else setAuthStep(v as number | ((p: number) => number));
  };
  const step = () => steps()[currentIdx()];

  function getActorColor(id: string): string {
    return PASSKEY_ACTORS.find((a: ProtocolActor) => a.id === id)?.color || "#888";
  }

  return (
    <div class="fido2-webauthn">
      <PasskeyDemo />

      <div class="fido2-toggle">
        <button
          class="fido2-mode-btn"
          classList={{ active: ceremony() === "register" }}
          onClick={() => setCeremony("register")}
        >
          {t("登録フロー", "Registration Flow")}
        </button>
        <button
          class="fido2-mode-btn"
          classList={{ active: ceremony() === "auth" }}
          onClick={() => setCeremony("auth")}
        >
          {t("認証フロー（ユーザー名なし）", "Auth Flow (Usernameless)")}
        </button>
      </div>

      <p class="fido2-desc">
        <Show when={ceremony() === "register"}>
          {t(
            "Passkey登録：residentKey: 'required' により、認証器がクレデンシャルとuserHandleをデバイス内に保存。プラットフォーム認証器（Touch ID / Windows Hello）はiCloud / Googleを通じてクロスデバイス同期可能。",
            "Passkey Registration: With residentKey: 'required', the authenticator stores the credential + userHandle internally. Platform authenticators (Touch ID / Windows Hello) can sync across devices via iCloud / Google."
          )}
        </Show>
        <Show when={ceremony() === "auth"}>
          {t(
            "ユーザー名なし認証：サーバーはallowCredentials: []（空）を送信。ブラウザがこのサイトの全パスキーを表示。ユーザー選択後、サーバーはuserHandleからアカウントを特定（クライアントはユーザー名を送らない）。",
            "Usernameless Auth: Server sends allowCredentials: [] (empty). Browser shows all passkeys for this site. After selection, the server identifies the account from the userHandle (client never sends a username)."
          )}
        </Show>
      </p>

      {/* Actors */}
      <div class="fido2-actors">
        <For each={PASSKEY_ACTORS}>
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
              {PASSKEY_ACTORS.find((a: ProtocolActor) => a.id === step()!.from)?.name || step()!.from}
            </span>
            <span class="fido2-arrow">{"\u2192"}</span>
            <span style={{ color: getActorColor(step()!.to) }}>
              {PASSKEY_ACTORS.find((a: ProtocolActor) => a.id === step()!.to)?.name || step()!.to}
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
        <div class="fido2-concept-title mono">{t("Passkey 主要概念", "Passkey Key Concepts")}</div>
        <div class="fido2-concept-grid">
          <div class="fido2-concept">
            <span class="fc-label mono">{t("Discoverable Credential", "Discoverable Credential")}</span>
            <span class="fc-val">{t("認証器がクレデンシャルを内部に保存。サーバーのヒントなしで見つけられる（resident key）", "Authenticator stores credential internally. Discoverable without server hints (resident key)")}</span>
          </div>
          <div class="fido2-concept">
            <span class="fc-label mono">{t("ユーザー名なしログイン", "Usernameless Login")}</span>
            <span class="fc-val">{t("ブラウザがこのサイトの全パスキーを列挙。ユーザーがピッカーから選択", "Browser lists all passkeys for this site. User picks from the OS-level chooser")}</span>
          </div>
          <div class="fido2-concept">
            <span class="fc-label mono">{t("Conditional UI", "Conditional UI")}</span>
            <span class="fc-val">{t("入力欄フォーカスでブラウザがパスキーをオートフィルとして提案。シームレスなUX", "Passkeys offered as autofill suggestions when input is focused. Seamless UX")}</span>
          </div>
          <div class="fido2-concept">
            <span class="fc-label mono">{t("デバイスタイプ", "Device Type")}</span>
            <span class="fc-val">{t("MultiDevice: iCloud/Google同期可。SingleDevice: このデバイスのみ（YubiKey等）", "MultiDevice: can sync via iCloud/Google. SingleDevice: locked to this device (e.g., YubiKey)")}</span>
          </div>
        </div>
      </div>
    </div>
  );
}
