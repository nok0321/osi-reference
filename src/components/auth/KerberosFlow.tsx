import { For, Show, createSignal, onCleanup } from "solid-js";
import { useI18n } from "../../i18n/context";
import { KERBEROS_ACTORS, KERBEROS_STEPS } from "../../data/protocol-flows";
import type { KerberosStep, ProtocolActor } from "../../types/security";
import { apiPost, apiGet } from "../../api/client";
import type { KerberosAsData, KerberosTgsData, KerberosApData, KerberosTicketCacheData } from "../../types/auth-responses";
import DataFlowPanel from "../shared/DataFlowPanel";
import StepControl from "../shared/StepControl";
import ViewModeToggle from "../shared/ViewModeToggle";
import AttackPanel from "../shared/AttackPanel";
import { getViewMode } from "../../state/attack-state";
import { kerberosScenarios } from "./attacks/scenarios/kerberos-scenarios";
import type { AttackResult } from "../../../shared/api-types";
import "./KerberosFlow.css";

const SCOPE = "kerberos";

// scenarioId → route suffix のマッピング (api/kerberos/attack/<suffix>)
// ROB-OIDC-9 同類: scenario meta に routeSuffix を持たせる代わりにコンポーネント内で解決。
// scenarioId と suffix が揃っているため fallback (s.id.replace) は到達不能だが、
// 将来 scenario id ミスマッチ時の silent 404 を防ぐため明示マップを優先する。
const ROUTE_BY_ID: Record<string, string> = {
  "kerberos-pass-the-ticket": "pass-the-ticket",
  "kerberos-kerberoasting": "kerberoasting",
  "kerberos-golden-ticket": "golden-ticket",
};

function KerberosFlowDefender() {
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
              role="button"
              tabindex="0"
              onClick={() => setStepIdx(i())}
              onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setStepIdx(i()); } }}
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
                          role="button"
                          tabindex="0"
                          onClick={() => setStepIdx(i())}
                          onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setStepIdx(i()); } }}
                        >
                          <span class="kerb-ev-num mono">{s.stepNumber}</span>
                          <span class="kerb-ev-dir" aria-hidden="true">{s.from === actor.id ? "→" : "←"}</span>
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

      {/* Interactive Demo */}
      <KerberosDemo />
    </div>
  );
}

/* ── Interactive Kerberos Demo ── */
interface KerberosFlowState {
  asResponse?: KerberosAsData;
  tgsResponse?: KerberosTgsData;
  apResponse?: KerberosApData;
}

function KerberosDemo() {
  const { t } = useI18n();
  const ac = new AbortController();
  onCleanup(() => ac.abort());

  const [principal, setPrincipal] = createSignal("alice@EXAMPLE.COM");
  const [servicePrincipal, setServicePrincipal] = createSignal("http/web-server");
  const [loading, setLoading] = createSignal(false);
  const [error, setError] = createSignal("");
  const [demoStep, setDemoStep] = createSignal(0);
  const [flowData, setFlowData] = createSignal<KerberosFlowState>({});
  const [ticketCache, setTicketCache] = createSignal<KerberosTicketCacheData | null>(null);

  async function runKerberosFlow() {
    setLoading(true);
    setError("");
    setDemoStep(0);
    setFlowData({});
    setTicketCache(null);

    try {
      // Step 1: AS-REQ → get TGT
      setDemoStep(1);
      const asRes = await apiPost<KerberosAsData>("/api/kerberos/as-req", {
        principal: principal(),
        password: "demo123",
      }, SCOPE, undefined, ac.signal);
      if (ac.signal.aborted) return;
      if (asRes.error) { setError(asRes.error); setLoading(false); return; }
      setFlowData({ asResponse: asRes.data });

      // Step 2: TGS-REQ → get service ticket
      setDemoStep(2);
      const tgsRes = await apiPost<KerberosTgsData>("/api/kerberos/tgs-req", {
        tgt: asRes.data?.tgt?.encrypted,
        tgtIv: asRes.data?.tgt?.iv,
        servicePrincipal: servicePrincipal(),
      }, SCOPE, undefined, ac.signal);
      if (ac.signal.aborted) return;
      if (tgsRes.error) { setError(tgsRes.error); setLoading(false); return; }
      setFlowData((prev: KerberosFlowState) => ({ ...prev, tgsResponse: tgsRes.data }));

      // Step 3: AP-REQ → authenticate to service
      setDemoStep(3);
      const apRes = await apiPost<KerberosApData>("/api/kerberos/ap-req", {
        serviceTicket: tgsRes.data?.serviceTicket?.encrypted,
        serviceTicketIv: tgsRes.data?.serviceTicket?.iv,
      }, SCOPE, undefined, ac.signal);
      if (ac.signal.aborted) return;
      if (apRes.error) { setError(apRes.error); setLoading(false); return; }
      setFlowData((prev: KerberosFlowState) => ({ ...prev, apResponse: apRes.data }));

      // Fetch ticket cache
      const cacheRes = await apiGet<KerberosTicketCacheData>("/api/kerberos/ticket-cache", SCOPE, ac.signal);
      if (ac.signal.aborted) return;
      if (!cacheRes.error) {
        setTicketCache(cacheRes.data ?? null);
      }
    } catch (err: unknown) {
      if (ac.signal.aborted) return;
      setError(err instanceof Error ? err.message : "Unknown error");
    }
    setLoading(false);
  }

  const stepLabels = () => [
    t("AS-REQ (TGT取得)", "AS-REQ (Get TGT)"),
    t("TGS-REQ (サービスチケット)", "TGS-REQ (Service Ticket)"),
    t("AP-REQ (サービス認証)", "AP-REQ (Authenticate)"),
  ];

  return (
    <div class="kerb-demo-section">
      <h4 class="demo-title">
        {t("インタラクティブ Kerberos デモ", "Interactive Kerberos Demo")}
        <span class="demo-badge">{t("実動作", "Live")}</span>
      </h4>

      <div class="kerb-demo-form">
        <div class="form-field">
          <label class="form-label mono">{t("プリンシパル", "Principal")}</label>
          <input
            type="text"
            class="form-input"
            value={principal()}
            onInput={(e) => setPrincipal(e.currentTarget.value)}
          />
        </div>
        <div class="form-field">
          <label class="form-label mono">{t("サービスプリンシパル", "Service Principal")}</label>
          <input
            type="text"
            class="form-input"
            value={servicePrincipal()}
            onInput={(e) => setServicePrincipal(e.currentTarget.value)}
          />
        </div>
      </div>

      <button class="demo-submit" onClick={runKerberosFlow} disabled={loading()}>
        {loading() ? t("実行中...", "Running...") : t("Kerberos フローを実行", "Run Kerberos Flow")}
      </button>

      {/* Step progress */}
      <Show when={demoStep() > 0}>
        <div class="kerb-demo-steps">
          <For each={stepLabels()}>
            {(label, i) => (
              <div class="kerb-demo-step-indicator" classList={{
                done: demoStep() > i() + 1,
                active: demoStep() === i() + 1,
                pending: demoStep() < i() + 1,
              }}>
                <span class="kerb-demo-step-num mono">{i() + 1}</span>
                <span class="kerb-demo-step-label">{label}</span>
              </div>
            )}
          </For>
        </div>
      </Show>

      {/* AS-REQ Result */}
      <Show when={flowData().asResponse}>
        <div class="kerb-demo-card">
          <div class="kerb-demo-card-title mono">1. AS-REP: {t("TGT取得", "TGT Obtained")}</div>
          <Show when={flowData().asResponse?.tgt}>
            <div class="kerb-demo-kv">
              <span class="kerb-demo-k mono">{t("暗号化TGT", "Encrypted TGT")}</span>
              <span class="kerb-demo-v mono">{(flowData().asResponse?.tgt?.encrypted || JSON.stringify(flowData().asResponse?.tgt)).substring(0, 60)}...</span>
            </div>
          </Show>
          <Show when={flowData().asResponse?.decryptedTgt}>
            <div class="kerb-demo-kv">
              <span class="kerb-demo-k mono">{t("復号内容", "Decrypted Contents")}</span>
              <pre class="kerb-demo-pre mono">{JSON.stringify(flowData().asResponse?.decryptedTgt, null, 2)}</pre>
            </div>
          </Show>
          <Show when={!flowData().asResponse?.decryptedTgt && flowData().asResponse}>
            <pre class="kerb-demo-pre mono">{JSON.stringify(flowData().asResponse, null, 2)}</pre>
          </Show>
        </div>
      </Show>

      {/* TGS-REQ Result */}
      <Show when={flowData().tgsResponse}>
        <div class="kerb-demo-card">
          <div class="kerb-demo-card-title mono">2. TGS-REP: {t("サービスチケット取得", "Service Ticket Obtained")}</div>
          <Show when={flowData().tgsResponse?.serviceTicket}>
            <div class="kerb-demo-kv">
              <span class="kerb-demo-k mono">{t("暗号化サービスチケット", "Encrypted Service Ticket")}</span>
              <span class="kerb-demo-v mono">{(flowData().tgsResponse?.serviceTicket?.encrypted || JSON.stringify(flowData().tgsResponse?.serviceTicket)).substring(0, 60)}...</span>
            </div>
          </Show>
          <Show when={flowData().tgsResponse?.decryptedServiceTicket}>
            <div class="kerb-demo-kv">
              <span class="kerb-demo-k mono">{t("復号内容", "Decrypted Contents")}</span>
              <pre class="kerb-demo-pre mono">{JSON.stringify(flowData().tgsResponse?.decryptedServiceTicket, null, 2)}</pre>
            </div>
          </Show>
          <Show when={!flowData().tgsResponse?.decryptedServiceTicket && flowData().tgsResponse}>
            <pre class="kerb-demo-pre mono">{JSON.stringify(flowData().tgsResponse, null, 2)}</pre>
          </Show>
        </div>
      </Show>

      {/* AP-REQ Result */}
      <Show when={flowData().apResponse}>
        <div class="kerb-demo-card highlight">
          <div class="kerb-demo-card-title mono">3. AP-REP: {t("認証成功", "Authentication Success")}</div>
          <pre class="kerb-demo-pre mono">{JSON.stringify(flowData().apResponse, null, 2)}</pre>
        </div>
      </Show>

      {/* Ticket Cache */}
      <Show when={ticketCache()}>
        <div class="kerb-demo-card">
          <div class="kerb-demo-card-title mono">{t("チケットキャッシュ", "Ticket Cache")}</div>
          <pre class="kerb-demo-pre mono">{JSON.stringify(ticketCache(), null, 2)}</pre>
        </div>
      </Show>

      <Show when={error()}>
        <div class="demo-result error">{error()}</div>
      </Show>

      <DataFlowPanel scopeId={SCOPE} defaultOpen={true} />
    </div>
  );
}

export default function KerberosFlow() {
  return (
    <div class="kerberos-flow-wrapper">
      <ViewModeToggle tabId="kerberos" />
      <Show when={getViewMode("kerberos") === "defender"}>
        <KerberosFlowDefender />
      </Show>
      <Show when={getViewMode("kerberos") === "attacker"}>
        <AttackPanel
          tabId="kerberos"
          scenarios={kerberosScenarios}
          onRunScenario={async (s) => {
            const routeSuffix = ROUTE_BY_ID[s.id] ?? s.id.replace(/^kerberos-/, "");
            const res = await apiPost<AttackResult>(
              `/api/kerberos/attack/${routeSuffix}`,
              {},
              "attack-kerberos",
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
