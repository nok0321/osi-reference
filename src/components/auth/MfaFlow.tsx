import { For, Show, createSignal, onMount, onCleanup } from "solid-js";
import { useI18n } from "../../i18n/context";
import {
  TOTP_ACTORS, TOTP_ENROLL_STEPS, TOTP_LOGIN_STEPS,
} from "../../data/protocol-flows";
import type { ProtocolFlowStep, ProtocolActor } from "../../types/security";
import { apiPost, apiGet } from "../../api/client";
import DataFlowPanel from "../shared/DataFlowPanel";
import StepControl from "../shared/StepControl";
import ViewModeToggle from "../shared/ViewModeToggle";
import AttackPanel from "../shared/AttackPanel";
import { getViewMode } from "../../state/attack-state";
import { mfaScenarios } from "./attacks/scenarios/mfa-scenarios";
import type { AttackResult, OrchestratorExecResponse } from "../../../shared/api-types";
import "./MfaFlow.css";

const SCOPE = "mfa-totp";

// scenarioId → route suffix のマッピング (api/mfa/attack/<suffix>)
// AuthMethods.tsx の ROUTE_BY_ID と同パターン。fallback (s.id.replace) は到達不能だが、
// scenario id ミスマッチ時の silent 404 を防ぐため明示マップを優先する。
const ROUTE_BY_ID: Record<string, string> = {
  "mfa-otp-replay": "otp-replay",
  "mfa-time-window-too-wide": "time-window-wide",
  "mfa-sms-swap": "sms-swap",
};

function MfaDemo() {
  const { t } = useI18n();
  const ac = new AbortController();
  onCleanup(() => ac.abort());

  const [username, setUsername] = createSignal("alice");
  const [password, setPassword] = createSignal("password123");
  const [code, setCode] = createSignal("");
  const [qrSvg, setQrSvg] = createSignal("");
  const [secret, setSecret] = createSignal("");
  const [otpauthUri, setOtpauthUri] = createSignal("");
  const [challengeId, setChallengeId] = createSignal<string | null>(null);
  const [stage, setStage] = createSignal<"idle" | "enrolled" | "enroll-verified" | "step1-done" | "done">("idle");
  const [result, setResult] = createSignal<{ ok: boolean; message: string } | null>(null);
  const [loading, setLoading] = createSignal(false);
  const [showSecret, setShowSecret] = createSignal(false);
  const [mfaEnabled, setMfaEnabled] = createSignal(false);
  interface MfaRow { user_id: number; verified: number; created_at: string; verified_at: string | null }
  const [mfaRows, setMfaRows] = createSignal<MfaRow[]>([]);
  const [mode, setMode] = createSignal<"enroll" | "login">("enroll");

  async function fetchMfaTable() {
    const res = await apiGet<{ rows: MfaRow[] }>("/api/debug/tables/user_mfa", SCOPE, ac.signal);
    if (ac.signal.aborted) return;
    if (res.data) setMfaRows(res.data.rows ?? []);
  }

  async function checkMfaStatus() {
    if (!username()) return;
    const res = await apiGet<{ enabled: boolean }>(`/api/mfa/totp/status?username=${encodeURIComponent(username())}`, SCOPE, ac.signal);
    if (ac.signal.aborted) return;
    if (res.data) setMfaEnabled(res.data.enabled);
  }

  async function handleQuickSetup() {
    setLoading(true);
    setResult(null);
    const res = await apiPost<{ user: { id: number; username: string } }>("/api/auth/password/register", {
      username: username(),
      password: password(),
    }, SCOPE, undefined, ac.signal);
    if (ac.signal.aborted) return;
    if (res.error) {
      if (res.error.includes("already exists")) {
        setResult({ ok: true, message: t("ユーザーは既に存在します。そのまま続行できます。", "User already exists. You can continue.") });
      } else {
        setResult({ ok: false, message: res.error });
      }
    } else {
      setResult({ ok: true, message: t(`ユーザー「${username()}」を登録しました`, `User "${username()}" registered`) });
    }
    setLoading(false);
  }

  async function handleEnrollStart() {
    if (!username()) return;
    setLoading(true);
    setResult(null);
    const res = await apiPost<{ secret: string; otpauthUri: string; qrCodeSvg: string }>("/api/mfa/totp/enroll/start", {
      username: username(),
    }, SCOPE, undefined, ac.signal);
    if (ac.signal.aborted) return;
    if (res.error) {
      setResult({ ok: false, message: res.error });
    } else if (res.data) {
      setSecret(res.data.secret);
      setOtpauthUri(res.data.otpauthUri);
      setQrSvg(res.data.qrCodeSvg);
      setStage("enrolled");
      setResult({ ok: true, message: t("シークレットを生成しました。認証アプリでQRコードをスキャンしてください。", "Secret generated. Scan the QR code with your authenticator app.") });
    }
    setLoading(false);
  }

  async function handleEnrollVerify() {
    if (!code()) return;
    setLoading(true);
    setResult(null);
    const res = await apiPost<{ verified: boolean }>("/api/mfa/totp/enroll/verify", {
      username: username(),
      code: code(),
    }, SCOPE, undefined, ac.signal);
    if (ac.signal.aborted) return;
    if (res.error) {
      setResult({ ok: false, message: res.error });
    } else {
      setStage("enroll-verified");
      setMfaEnabled(true);
      setCode("");
      setResult({ ok: true, message: t("MFA登録完了！今後のログインでTOTPコードが必要になります。", "MFA enrollment complete! Future logins will require a TOTP code.") });
      fetchMfaTable();
    }
    setLoading(false);
  }

  async function handleLoginStep1() {
    if (!username() || !password()) return;
    setLoading(true);
    setResult(null);
    const res = await apiPost<{ requiresMfa: boolean; challengeId: string | null; message: string }>("/api/mfa/totp/login/step1", {
      username: username(),
      password: password(),
    }, SCOPE, undefined, ac.signal);
    if (ac.signal.aborted) return;
    if (res.error) {
      setResult({ ok: false, message: res.error });
    } else if (res.data) {
      if (res.data.requiresMfa) {
        setChallengeId(res.data.challengeId);
        setStage("step1-done");
        setResult({ ok: true, message: t("パスワード検証OK。認証アプリの6桁コードを入力してください。", "Password verified. Enter the 6-digit code from your authenticator app.") });
      } else {
        setStage("done");
        setResult({ ok: true, message: t("ログイン成功（MFA未設定のためパスワードのみ）", "Login successful (MFA not enabled, password only)") });
      }
    }
    setLoading(false);
  }

  async function handleLoginStep2() {
    if (!code() || !challengeId()) return;
    setLoading(true);
    setResult(null);
    const res = await apiPost<{ success: boolean; username: string; message: string }>("/api/mfa/totp/login/step2", {
      challengeId: challengeId(),
      code: code(),
    }, SCOPE, undefined, ac.signal);
    if (ac.signal.aborted) return;
    if (res.error) {
      setResult({ ok: false, message: res.error });
    } else {
      setStage("done");
      setCode("");
      setResult({ ok: true, message: res.data?.message || t("2FA ログイン成功！", "2FA login successful!") });
    }
    setLoading(false);
  }

  onMount(() => {
    checkMfaStatus();
    fetchMfaTable();
  });

  return (
    <div class="password-demo">
      <h4 class="demo-title">
        {t("MFA (TOTP) デモ", "MFA (TOTP) Demo")}
        <span class="demo-badge">{t("実動作", "Live")}</span>
        <Show when={mfaEnabled()}>
          <span class="mfa-stage-badge">{t("MFA有効", "MFA Active")}</span>
        </Show>
      </h4>

      {/* Mode toggle */}
      <div class="demo-mode-toggle">
        <button classList={{ active: mode() === "enroll" }} onClick={() => { setMode("enroll"); setResult(null); setStage("idle"); }}>
          {t("登録（Enroll）", "Enroll")}
        </button>
        <button classList={{ active: mode() === "login" }} onClick={() => { setMode("login"); setResult(null); setStage("idle"); }}>
          {t("ログイン（Login）", "Login")}
        </button>
      </div>

      <div class="demo-layout">
        <div class="demo-form-area">
          <Show when={mode() === "enroll"}>
            <form class="demo-form" onSubmit={(e) => e.preventDefault()}>
              <div class="form-field">
                <label class="form-label mono">{t("ユーザー名", "Username")}</label>
                <input type="text" class="form-input" value={username()} onInput={(e) => setUsername(e.currentTarget.value)} placeholder="alice" />
              </div>

              <Show when={stage() === "idle" || stage() === "enroll-verified"}>
                <div style={{ display: "flex", gap: "8px", "flex-wrap": "wrap" }}>
                  <button type="button" class="mfa-quick-setup" disabled={loading()} onClick={handleQuickSetup}>
                    {t("ユーザー作成", "Quick Setup")}
                  </button>
                  <button type="button" class="demo-submit" disabled={loading() || !username()} onClick={handleEnrollStart}>
                    {loading() ? "..." : t("TOTP登録開始", "Start Enrollment")}
                  </button>
                </div>
              </Show>

              <Show when={stage() === "enrolled"}>
                <div class="mfa-qr-container" innerHTML={qrSvg()} />
                <div class="mfa-secret-row">
                  <Show when={showSecret()} fallback={
                    <button type="button" class="mfa-secret-toggle" onClick={() => setShowSecret(true)}>
                      {t("シークレットを表示（スクリーンショット注意）", "Show Secret (beware of screenshots)")}
                    </button>
                  }>
                    <div class="mfa-secret-display mono">Secret: {secret()}</div>
                    <button type="button" class="mfa-secret-copy" onClick={() => navigator.clipboard?.writeText(secret())}>
                      {t("コピー", "Copy")}
                    </button>
                    <button type="button" class="mfa-secret-toggle mfa-secret-hide" onClick={() => setShowSecret(false)}>
                      {t("隠す", "Hide")}
                    </button>
                  </Show>
                </div>
                <div class="mfa-otpauth-uri mono">{otpauthUri()}</div>
                <div class="mfa-info-box">
                  {t("認証アプリ（Google Authenticator等）でQRコードをスキャンし、表示された6桁コードを入力してください。",
                    "Scan the QR code with an authenticator app (Google Authenticator, etc.) and enter the 6-digit code shown.")}
                </div>
                <div class="form-field">
                  <label class="form-label mono">{t("6桁コード", "6-Digit Code")}</label>
                  <input type="text" class="form-input mfa-code-input" value={code()} onInput={(e) => setCode(e.currentTarget.value)} placeholder="000000" maxLength={6} inputMode="numeric" autocomplete="one-time-code" />
                </div>
                <button type="button" class="demo-submit" disabled={loading() || code().length !== 6} onClick={handleEnrollVerify}>
                  {loading() ? "..." : t("コード検証", "Verify Code")}
                </button>
              </Show>
            </form>
          </Show>

          <Show when={mode() === "login"}>
            <form class="demo-form" onSubmit={(e) => e.preventDefault()}>
              <Show when={stage() !== "step1-done" && stage() !== "done"}>
                <div class="form-field">
                  <label class="form-label mono">{t("ユーザー名", "Username")}</label>
                  <input type="text" class="form-input" value={username()} onInput={(e) => setUsername(e.currentTarget.value)} placeholder="alice" />
                </div>
                <div class="form-field">
                  <label class="form-label mono">{t("パスワード", "Password")}</label>
                  <input type="password" class="form-input" value={password()} onInput={(e) => setPassword(e.currentTarget.value)} placeholder="password123" />
                </div>
                <button type="button" class="demo-submit" disabled={loading() || !username() || !password()} onClick={handleLoginStep1}>
                  {loading() ? "..." : t("Step 1: パスワード検証", "Step 1: Verify Password")}
                </button>
              </Show>

              <Show when={stage() === "step1-done"}>
                <div class="mfa-info-box">
                  {t("パスワード検証OK！認証アプリの6桁コードを入力してください（第2要素）。",
                    "Password verified! Enter the 6-digit code from your authenticator app (Factor 2).")}
                </div>
                <div class="form-field">
                  <label class="form-label mono">{t("TOTPコード", "TOTP Code")}</label>
                  <input type="text" class="form-input mfa-code-input" value={code()} onInput={(e) => setCode(e.currentTarget.value)} placeholder="000000" maxLength={6} inputMode="numeric" autocomplete="one-time-code" />
                </div>
                <button type="button" class="demo-submit" disabled={loading() || code().length !== 6} onClick={handleLoginStep2}>
                  {loading() ? "..." : t("Step 2: TOTP検証", "Step 2: Verify TOTP")}
                </button>
              </Show>
            </form>
          </Show>

          <Show when={result()}>
            <div class="demo-result" role="alert" classList={{ success: result()!.ok, error: !result()!.ok }}>
              {result()!.ok ? "\u2713" : "\u2717"} {result()!.message}
            </div>
          </Show>
        </div>

        <div class="demo-db-area">
          <div class="db-panel-title mono">
            {t("user_mfa テーブル", "user_mfa table")}
            <button class="db-refresh" onClick={fetchMfaTable}>\u21BB</button>
          </div>
          <Show when={mfaRows().length > 0} fallback={
            <div class="db-empty">{t("MFA登録なし", "No MFA enrollments yet")}</div>
          }>
            <div class="db-table-wrap">
              <table class="db-table">
                <thead>
                  <tr>
                    <th>user_id</th>
                    <th>verified</th>
                    <th>created_at</th>
                    <th>verified_at</th>
                  </tr>
                </thead>
                <tbody>
                  <For each={mfaRows()}>
                    {(row) => (
                      <tr>
                        <td>{row.user_id}</td>
                        <td>{row.verified ? "\u2713" : "\u2717"}</td>
                        <td>{row.created_at || "\u2014"}</td>
                        <td>{row.verified_at || "\u2014"}</td>
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

function MfaFlowDefender() {
  const { t } = useI18n();
  const [ceremony, setCeremony] = createSignal<"enroll" | "login">("enroll");
  const [enrollStep, setEnrollStep] = createSignal(0);
  const [loginStep, setLoginStep] = createSignal(0);

  const steps = () => ceremony() === "enroll" ? TOTP_ENROLL_STEPS : TOTP_LOGIN_STEPS;
  const currentIdx = () => ceremony() === "enroll" ? enrollStep() : loginStep();
  const setCurrentIdx = (v: number | ((p: number) => number)) => {
    if (ceremony() === "enroll") setEnrollStep(v as number | ((p: number) => number));
    else setLoginStep(v as number | ((p: number) => number));
  };
  const step = () => steps()[currentIdx()];

  function getActorColor(id: string): string {
    return TOTP_ACTORS.find((a: ProtocolActor) => a.id === id)?.color || "#888";
  }

  return (
    <div class="fido2-webauthn">
      <MfaDemo />

      <div class="fido2-toggle">
        <button
          class="fido2-mode-btn"
          classList={{ active: ceremony() === "enroll" }}
          onClick={() => setCeremony("enroll")}
        >
          {t("登録フロー", "Enrollment Flow")}
        </button>
        <button
          class="fido2-mode-btn"
          classList={{ active: ceremony() === "login" }}
          onClick={() => setCeremony("login")}
        >
          {t("ログインフロー", "Login Flow")}
        </button>
      </div>

      <p class="fido2-desc">
        <Show when={ceremony() === "enroll"}>
          {t(
            "TOTP登録：サーバーが共有シークレット（base32）を生成し、QRコード経由で認証アプリに配布。アプリが6桁コードを計算し、サーバーが検証して登録完了。",
            "TOTP Enrollment: Server generates a shared secret (base32) and distributes it via QR code to the authenticator app. The app computes a 6-digit code which the server verifies to complete enrollment."
          )}
        </Show>
        <Show when={ceremony() === "login"}>
          {t(
            "2FAログイン：第1要素（パスワード）で認証後、第2要素（TOTP）を要求。サーバーはchallengeIdで2段階を紐付け、パスワードとTOTP両方の成功をもってログイン完了。",
            "2FA Login: After authenticating with Factor 1 (password), Factor 2 (TOTP) is requested. The server binds the two steps with a challengeId, requiring both password and TOTP success."
          )}
        </Show>
      </p>

      {/* Actors */}
      <div class="fido2-actors">
        <For each={TOTP_ACTORS}>
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
              {TOTP_ACTORS.find((a: ProtocolActor) => a.id === step()!.from)?.name || step()!.from}
            </span>
            <span class="fido2-arrow">{"\u2192"}</span>
            <span style={{ color: getActorColor(step()!.to) }}>
              {TOTP_ACTORS.find((a: ProtocolActor) => a.id === step()!.to)?.name || step()!.to}
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
              role="button"
              tabindex="0"
              onClick={() => setCurrentIdx(i())}
              onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setCurrentIdx(i()); } }}
            >
              <span class="fido2-tl-num mono">{s.stepNumber}</span>
              <span class="fido2-tl-label">{t(s.actionJa, s.action)}</span>
            </div>
          )}
        </For>
      </div>

      {/* Key concepts */}
      <div class="fido2-concepts">
        <div class="fido2-concept-title mono">{t("TOTP / MFA 主要概念", "TOTP / MFA Key Concepts")}</div>
        <div class="fido2-concept-grid">
          <div class="fido2-concept">
            <span class="fc-label mono">{t("共有シークレット", "Shared Secret")}</span>
            <span class="fc-val">{t("サーバーと認証アプリが同じ秘密を保持（WebAuthnとの大きな違い）", "Both server and app hold the same secret (key difference from WebAuthn)")}</span>
          </div>
          <div class="fido2-concept">
            <span class="fc-label mono">{t("時間窓", "Time Window")}</span>
            <span class="fc-val">{t("30秒ごとにカウンタが進む。±1窓でクロックドリフトを許容", "Counter advances every 30s. ±1 window tolerates clock drift")}</span>
          </div>
          <div class="fido2-concept">
            <span class="fc-label mono">{t("フィッシング耐性", "Phishing Resistance")}</span>
            <span class="fc-val">{t("TOTPコードは手入力のため、リアルタイムフィッシングに脆弱（FIDO2と異なる）", "TOTP codes are manually entered, vulnerable to real-time phishing (unlike FIDO2)")}</span>
          </div>
          <div class="fido2-concept">
            <span class="fc-label mono">{t("オフライン動作", "Offline Capable")}</span>
            <span class="fc-val">{t("認証アプリ側はネットワーク不要。時刻のみで計算可能", "Authenticator app needs no network — computes from time alone")}</span>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function MfaFlow() {
  return (
    <div class="mfa-wrapper">
      <ViewModeToggle tabId="mfa" />
      <Show when={getViewMode("mfa") === "defender"}>
        <MfaFlowDefender />
      </Show>
      <Show when={getViewMode("mfa") === "attacker"}>
        <AttackPanel
          tabId="mfa"
          scenarios={mfaScenarios}
          allowedTargets={["victim-web"]}
          onRunScenario={async (s) => {
            const routeSuffix = ROUTE_BY_ID[s.id] ?? s.id.replace(/^mfa-/, "");
            const res = await apiPost<AttackResult>(
              `/api/mfa/attack/${routeSuffix}`,
              {},
              "attack-mfa",
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
          onRunLiveScenario={async (s, payload) => {
            const res = await apiPost<OrchestratorExecResponse>(
              "/api/orchestrator/exec",
              {
                scenarioId: s.id,
                target: payload.target,
                request: payload.request,
              },
              "attack-mfa",
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
