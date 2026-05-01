import { For, createSignal, Show, onCleanup } from "solid-js";
import { useI18n } from "../../i18n/context";
import { AUTH_COMPARISON } from "../../data/auth-flows";
import type { AuthMethodComparison } from "../../types/security";
import { apiPost, apiGet, apiDelete, apiFetch } from "../../api/client";
import type { SessionLoginData, TokenLoginData, SessionProfileData, TokenProfileData, SessionLogoutData } from "../../types/auth-responses";
import DataFlowPanel from "../shared/DataFlowPanel";
import ViewModeToggle from "../shared/ViewModeToggle";
import AttackPanel from "../shared/AttackPanel";
import { getViewMode } from "../../state/attack-state";
import { sessionTokenScenarios } from "./attacks/scenarios/session-token-scenarios";
import type { AttackResult } from "../../../shared/api-types";
import "./AuthComparison.css";

const SCOPE_SESSION = "session-auth";
const SCOPE_TOKEN = "token-auth";

interface StepGuide {
  title: string;
  titleJa: string;
  desc: string;
  descJa: string;
  sessionPoint: string;
  sessionPointJa: string;
  tokenPoint: string;
  tokenPointJa: string;
}

const DEMO_STEPS: StepGuide[] = [
  {
    title: "Login", titleJa: "ログイン",
    desc: "Both sides authenticate with the same credentials. Watch how each stores the auth state differently.",
    descJa: "同じ認証情報で両方ログインします。認証状態の保存方法の違いに注目。",
    sessionPoint: "Server creates session in DB, returns Set-Cookie: session_id=...",
    sessionPointJa: "サーバーがDBにセッション作成 → Set-Cookie: session_id=... を返却",
    tokenPoint: "Server returns JWT accessToken + refreshToken in response body",
    tokenPointJa: "サーバーがJWT accessToken + refreshToken をレスポンスボディで返却",
  },
  {
    title: "Get Profile", titleJa: "プロフィール取得",
    desc: "Both sides request user profile. Watch how each sends the auth credentials.",
    descJa: "両方でプロフィールを取得します。認証情報の送信方法の違いに注目。",
    sessionPoint: "Browser auto-sends Cookie header — no app code needed",
    sessionPointJa: "ブラウザがCookieヘッダを自動送信 — アプリコード不要",
    tokenPoint: "App must manually set Authorization: Bearer <token> header",
    tokenPointJa: "アプリが Authorization: Bearer <token> ヘッダを手動設定",
  },
  {
    title: "Logout & Retry", titleJa: "ログアウト → 再取得",
    desc: "Both sides logout, then try to access profile again. Watch how invalidation differs.",
    descJa: "両方ログアウト後、再度プロフィールを取得。無効化方法の違いに注目。",
    sessionPoint: "Server deletes session from DB + clears Cookie → immediate invalidation",
    sessionPointJa: "サーバーがDBからセッション削除 + Cookie消去 → 即時無効化",
    tokenPoint: "Client discards token (server can't revoke JWT) → client-side only",
    tokenPointJa: "クライアントがトークン破棄（サーバーはJWT取り消し不可）→ クライアント側のみ",
  },
];

function LiveComparisonDemo() {
  const { t } = useI18n();
  const ac = new AbortController();
  onCleanup(() => ac.abort());

  const [step, setStep] = createSignal(-1); // -1 = not started
  const [loading, setLoading] = createSignal(false);
  const username = "alice";
  const password = "password123";

  // Session side state
  const [sessionUser, setSessionUser] = createSignal<{id: number; username: string} | null>(null);
  const [sessionError, setSessionError] = createSignal("");
  const sessionLoggedIn = () => !!sessionUser();

  // Token side state
  const [tokenUser, setTokenUser] = createSignal<{id: number; username: string} | null>(null);
  const [tokenError, setTokenError] = createSignal("");
  const [accessToken, setAccessToken] = createSignal("");
  const [refreshToken, setRefreshToken] = createSignal("");
  const tokenLoggedIn = () => !!accessToken();

  async function runStep(idx: number) {
    setLoading(true);
    setSessionError("");
    setTokenError("");
    setStep(idx);

    if (idx === 0) {
      // Step 1: Login both
      await apiPost("/api/auth/password/register", { username, password }, undefined, undefined, ac.signal);

      const [sRes, tRes] = await Promise.all([
        apiPost<SessionLoginData>("/api/session/login", { username, password }, SCOPE_SESSION, undefined, ac.signal),
        apiPost<TokenLoginData>("/api/token/login", { username, password }, SCOPE_TOKEN, undefined, ac.signal),
      ]);
      if (ac.signal.aborted) return;
      if (sRes.error) setSessionError(sRes.error);
      else setSessionUser(sRes.data?.user ?? null);

      if (tRes.error) setTokenError(tRes.error);
      else {
        setTokenUser(tRes.data?.user ?? null);
        setAccessToken(tRes.data?.accessToken || "");
        setRefreshToken(tRes.data?.refreshToken || "");
      }
    } else if (idx === 1) {
      // Step 2: Get profile both
      const sPromise = apiGet<SessionProfileData>("/api/session/profile", SCOPE_SESSION, ac.signal);
      const tPromise = accessToken()
        ? apiFetch<TokenProfileData>("/api/token/profile", { method: "GET", headers: { "Authorization": `Bearer ${accessToken()}` } }, SCOPE_TOKEN, ac.signal)
        : Promise.resolve({ error: "No access token" } as const);

      const [sRes, tRes] = await Promise.all([sPromise, tPromise]);
      if (ac.signal.aborted) return;
      if (sRes.error) setSessionError(sRes.error);
      else setSessionUser(sRes.data?.user ?? null);

      if (tRes.error) setTokenError(tRes.error);
      else if ("data" in tRes) setTokenUser(tRes.data?.user ?? null);
    } else if (idx === 2) {
      // Step 3: Logout both, then re-fetch profile
      await Promise.all([
        apiDelete<SessionLogoutData>("/api/session/logout", SCOPE_SESSION, ac.signal),
        Promise.resolve().then(() => { setTokenUser(null); setAccessToken(""); setRefreshToken(""); }),
      ]);
      if (ac.signal.aborted) return;
      setSessionUser(null);

      // Short pause so user sees the state change
      await new Promise((r) => setTimeout(r, 300));
      if (ac.signal.aborted) return;

      // Now try to access profile (should fail)
      const [sRes, tRes] = await Promise.all([
        apiGet<SessionProfileData>("/api/session/profile", SCOPE_SESSION, ac.signal),
        apiFetch<TokenProfileData>("/api/token/profile", { method: "GET", headers: { "Authorization": "Bearer (cleared)" } }, SCOPE_TOKEN, ac.signal),
      ]);
      if (ac.signal.aborted) return;
      if (sRes.error) setSessionError(sRes.error);
      if (tRes.error) setTokenError(tRes.error);
    }
    setLoading(false);
  }

  function nextStep() {
    const next = step() + 1;
    if (next < DEMO_STEPS.length) runStep(next);
  }

  function resetDemo() {
    setStep(-1);
    setSessionUser(null);
    setSessionError("");
    setTokenUser(null);
    setTokenError("");
    setAccessToken("");
    setRefreshToken("");
  }

  const currentGuide = () => step() >= 0 ? DEMO_STEPS[step()] : null;

  return (
    <div class="live-comparison">
      <h4 class="demo-title">
        {t("ライブ比較デモ", "Live Comparison Demo")}
        <span class="demo-badge">{t("実動作", "Live")}</span>
      </h4>

      {/* Step progress indicator */}
      <Show when={step() >= 0}>
        <div class="comp-step-progress">
          <For each={DEMO_STEPS}>
            {(s, i) => (
              <div class="comp-progress-step" classList={{
                completed: i() < step(),
                current: i() === step(),
                pending: i() > step(),
              }}>
                <span class="comp-progress-num mono">{i() + 1}</span>
                <span class="comp-progress-label">{t(s.titleJa, s.title)}</span>
              </div>
            )}
          </For>
        </div>
      </Show>

      {/* Guide text for current step */}
      <Show when={currentGuide()}>
        <div class="comp-guide">
          <p class="comp-guide-desc">{t(currentGuide()!.descJa, currentGuide()!.desc)}</p>
          <div class="comp-guide-points">
            <div class="comp-guide-point session-point">
              <span class="cgp-label mono">Session</span>
              <span class="cgp-text">{t(currentGuide()!.sessionPointJa, currentGuide()!.sessionPoint)}</span>
            </div>
            <div class="comp-guide-point token-point">
              <span class="cgp-label mono">Token</span>
              <span class="cgp-text">{t(currentGuide()!.tokenPointJa, currentGuide()!.tokenPoint)}</span>
            </div>
          </div>
        </div>
      </Show>

      {/* Side-by-side results */}
      <div class="live-comp-grid">
        {/* Session side */}
        <div class="live-comp-side session-side">
          <div class="side-label mono">
            Session (Cookie)
            <span class="auth-status" classList={{ "logged-in": sessionLoggedIn(), "logged-out": !sessionLoggedIn() }}>
              {sessionLoggedIn() ? t("● 認証済み", "● Authenticated") : t("○ 未認証", "○ Not authenticated")}
            </span>
          </div>
          <Show when={sessionUser()}>
            <div class="demo-result success" role="status">✓ {sessionUser()!.username} (id: {sessionUser()!.id})</div>
          </Show>
          <Show when={sessionError()}>
            <div class="demo-result error" role="alert">✗ {sessionError()}</div>
          </Show>
          <DataFlowPanel scopeId={SCOPE_SESSION} />
        </div>

        {/* Token side */}
        <div class="live-comp-side token-side">
          <div class="side-label mono">
            Token (JWT)
            <span class="auth-status" classList={{ "logged-in": tokenLoggedIn(), "logged-out": !tokenLoggedIn() }}>
              {tokenLoggedIn() ? t("● 認証済み", "● Authenticated") : t("○ 未認証", "○ Not authenticated")}
            </span>
          </div>
          <Show when={accessToken()}>
            <div class="token-preview mono">
              <span class="token-label">Access:</span> {accessToken().substring(0, 30)}...
            </div>
          </Show>
          <Show when={tokenUser()}>
            <div class="demo-result success" role="status">✓ {tokenUser()!.username} (id: {tokenUser()!.id})</div>
          </Show>
          <Show when={tokenError()}>
            <div class="demo-result error" role="alert">✗ {tokenError()}</div>
          </Show>
          <DataFlowPanel scopeId={SCOPE_TOKEN} />
        </div>
      </div>

      {/* Action buttons */}
      <div class="comp-actions">
        <Show when={step() < 0}>
          <button class="demo-submit" onClick={() => runStep(0)}>
            {t("比較デモを開始", "Start Comparison Demo")}
          </button>
        </Show>
        <Show when={step() >= 0 && step() < DEMO_STEPS.length - 1}>
          <button class="demo-submit" onClick={nextStep} disabled={loading()}>
            {loading()
              ? t("処理中...", "Processing...")
              : t("次のステップを実行", "Execute Next Step")
            } ({step() + 2}/{DEMO_STEPS.length})
          </button>
        </Show>
        <Show when={step() >= DEMO_STEPS.length - 1}>
          <button class="demo-submit" onClick={resetDemo}>
            {t("最初からやり直す", "Start Over")}
          </button>
        </Show>
      </div>
    </div>
  );
}

function AuthComparisonDefender() {
  const { t } = useI18n();
  const [expandedRow, setExpandedRow] = createSignal<number | null>(null);

  function toggleRow(idx: number) {
    setExpandedRow(prev => prev === idx ? null : idx);
  }

  return (
    <div class="auth-comparison">
      <div class="comparison-header-row">
        <h3 class="comp-title mono">
          {t("セッション認証 vs トークン認証", "Session Auth vs Token Auth")}
        </h3>
      </div>

      {/* Visual diagrams */}
      <div class="comp-diagrams">
        <div class="comp-diagram session-diagram">
          <div class="diagram-label mono">Session (Cookie)</div>
          <div class="diagram-flow">
            <div class="flow-node">{t("ブラウザ", "Browser")}</div>
            <div class="flow-arrow">→ Cookie: sid=abc</div>
            <div class="flow-node">{t("サーバー", "Server")}</div>
            <div class="flow-arrow">→ Lookup sid</div>
            <div class="flow-node highlight-session">{t("セッションストア", "Session Store")}</div>
          </div>
        </div>
        <div class="comp-diagram token-diagram">
          <div class="diagram-label mono">Token (JWT)</div>
          <div class="diagram-flow">
            <div class="flow-node">{t("クライアント", "Client")}</div>
            <div class="flow-arrow">→ Bearer eyJ...</div>
            <div class="flow-node">{t("サーバー", "Server")}</div>
            <div class="flow-arrow">→ {t("署名検証", "Verify sig")}</div>
            <div class="flow-node highlight-token">{t("自己完結", "Self-contained")}</div>
          </div>
        </div>
      </div>

      {/* Comparison table */}
      <div class="comp-table">
        <div class="comp-table-header">
          <span class="cth aspect">{t("観点", "Aspect")}</span>
          <span class="cth session">Session</span>
          <span class="cth token">Token (JWT)</span>
        </div>
        <For each={AUTH_COMPARISON}>
          {(item: AuthMethodComparison, i) => (
            <div
              class="comp-row"
              classList={{ expanded: expandedRow() === i() }}
              role="button"
              tabindex="0"
              aria-expanded={expandedRow() === i()}
              onClick={() => toggleRow(i())}
              onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggleRow(i()); } }}
            >
              <div class="comp-row-main">
                <span class="cr-aspect">{t(item.aspectJa, item.aspect)}</span>
                <span class="cr-session">{t(item.session.valueJa, item.session.value)}</span>
                <span class="cr-token">{t(item.token.valueJa, item.token.value)}</span>
              </div>
              <Show when={expandedRow() === i()}>
                <div class="comp-row-detail">
                  <div class="detail-col session-col">
                    <div class="pros">
                      <span class="pro-label">+</span> {t(item.session.prosJa, item.session.pros)}
                    </div>
                    <div class="cons">
                      <span class="con-label">-</span> {t(item.session.consJa, item.session.cons)}
                    </div>
                  </div>
                  <div class="detail-col token-col">
                    <div class="pros">
                      <span class="pro-label">+</span> {t(item.token.prosJa, item.token.pros)}
                    </div>
                    <div class="cons">
                      <span class="con-label">-</span> {t(item.token.consJa, item.token.cons)}
                    </div>
                  </div>
                </div>
              </Show>
            </div>
          )}
        </For>
      </div>

      {/* Live comparison demo */}
      <LiveComparisonDemo />
    </div>
  );
}

const ROUTE_BY_ID: Record<string, { area: "session" | "token"; suffix: string }> = {
  "session-fixation": { area: "session", suffix: "fixation" },
  "session-xss-cookie-theft": { area: "session", suffix: "xss-cookie-theft" },
  "token-replay": { area: "token", suffix: "replay" },
};

export default function AuthComparison() {
  return (
    <div class="auth-comparison-wrapper">
      <ViewModeToggle tabId="session-vs-token" />
      <Show when={getViewMode("session-vs-token") === "defender"}>
        <AuthComparisonDefender />
      </Show>
      <Show when={getViewMode("session-vs-token") === "attacker"}>
        <AttackPanel
          tabId="session-vs-token"
          scenarios={sessionTokenScenarios}
          onRunScenario={async (s) => {
            const route = ROUTE_BY_ID[s.id];
            if (!route) {
              return {
                scenarioId: s.id,
                outcome: "error" as const,
                startedAt: Date.now(),
                finishedAt: Date.now(),
                steps: [],
                summaryJa: "未対応のシナリオ ID です",
                summary: "Unsupported scenario ID",
              };
            }
            const res = await apiPost<AttackResult>(
              `/api/${route.area}/attack/${route.suffix}`,
              {},
              "attack-session-vs-token",
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
        />
      </Show>
    </div>
  );
}
