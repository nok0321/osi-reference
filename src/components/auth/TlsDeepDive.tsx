import { For, Show, createSignal, onCleanup } from "solid-js";
import { useI18n } from "../../i18n/context";
import { tlsDeepStep, setTlsDeepStep } from "../../state/security-state";
import { TLS_DEEP_STEPS } from "../../data/auth-flows";
import type { TlsStep } from "../../types/security";
import { apiPost, apiGet } from "../../api/client";
import type { TlsClientHelloData, TlsServerHelloData, TlsKeyExchangeData, TlsCertificateData, TlsFinishData } from "../../types/auth-responses";
import DataFlowPanel from "../shared/DataFlowPanel";
import StepControl from "../shared/StepControl";
import ViewModeToggle from "../shared/ViewModeToggle";
import AttackPanel from "../shared/AttackPanel";
import { getViewMode } from "../../state/attack-state";
import { tlsScenarios } from "./attacks/scenarios/tls-scenarios";
import type { AttackResult } from "../../../shared/api-types";
import "./TlsDeepDive.css";

const SCOPE = "tls-handshake";

// scenarioId → route suffix のマッピング (api/tls/attack/<suffix>)
// ROB-OIDC-9 同類: scenario meta に routeSuffix を持たせる代わりにコンポーネント内で解決。
// scenarioId と suffix が揃っているため fallback (s.id.replace) は到達不能だが、
// 将来 scenario id ミスマッチ時の silent 404 を防ぐため明示マップを優先する。
const ROUTE_BY_ID: Record<string, string> = {
  "tls-version-downgrade": "version-downgrade",
  "tls-self-signed-mitm": "self-signed-mitm",
  "tls-weak-cipher-negotiation": "weak-cipher",
};

function TlsDeepDiveDefender() {
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

      {/* Interactive TLS Handshake Demo */}
      <TlsHandshakeDemo />
    </div>
  );
}

export default function TlsDeepDive() {
  return (
    <div class="tls-deep-dive-wrapper">
      <ViewModeToggle tabId="tls-deep" />
      <Show when={getViewMode("tls-deep") === "defender"}>
        <TlsDeepDiveDefender />
      </Show>
      <Show when={getViewMode("tls-deep") === "attacker"}>
        <AttackPanel
          tabId="tls-deep"
          scenarios={tlsScenarios}
          onRunScenario={async (s) => {
            const routeSuffix = ROUTE_BY_ID[s.id] ?? s.id.replace(/^tls-/, "");
            const res = await apiPost<AttackResult>(
              `/api/tls/attack/${routeSuffix}`,
              {},
              "attack-tls-deep",
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

/* ── Interactive TLS Handshake Demo ── */
interface TlsHandshakeState {
  clientHello?: {
    clientRandom?: string;
    clientPublicKey?: string;
    cipherSuites?: string[];
    tlsVersion?: string;
  };
  serverHello?: {
    serverRandom?: string;
    serverPublicKey?: string;
    selectedCipher?: string;
  };
  keyExchange?: {
    sharedSecret?: string;
    handshakeSecret?: string;
    masterSecret?: string;
    clientPublicKey?: string;
    serverPublicKey?: string;
  };
  finish?: {
    message?: string;
    cipherSuite?: string;
    masterSecret?: string;
    derivedKeys?: {
      clientWriteKey?: string;
      serverWriteKey?: string;
    };
  };
}

interface TlsCertDisplay {
  subject?: string;
  issuer?: string;
  serialNumber?: string;
  validFrom?: string;
  validTo?: string;
  signatureAlgorithm?: string;
  publicKey?: string;
  fingerprint?: string;
}

function TlsHandshakeDemo() {
  const { t } = useI18n();
  const ac = new AbortController();
  onCleanup(() => ac.abort());

  const [active, setActive] = createSignal(false);
  const [step, setStep] = createSignal(0);
  const [loading, setLoading] = createSignal(false);
  const [error, setError] = createSignal("");
  const [sessionId] = createSignal(`tls-${Date.now()}`);
  const [handshakeData, setHandshakeData] = createSignal<TlsHandshakeState>({});
  const [certData, setCertData] = createSignal<TlsCertDisplay | null>(null);

  const STEPS = [
    { key: "client-hello", label: "ClientHello", labelJa: "ClientHello" },
    { key: "server-hello", label: "ServerHello", labelJa: "ServerHello" },
    { key: "key-exchange", label: "Key Exchange", labelJa: "鍵交換" },
    { key: "finish", label: "Finish", labelJa: "完了" },
  ];

  async function startHandshake() {
    setActive(true);
    setStep(0);
    setHandshakeData({});
    setCertData(null);
    setError("");
    await runStep(0);
  }

  async function runStep(idx: number) {
    setLoading(true);
    setError("");
    setStep(idx);

    try {
      const d = handshakeData();

      if (idx === 0) {
        // ClientHello
        const res = await apiPost<TlsClientHelloData>("/api/tls/client-hello", { sessionId: sessionId() }, SCOPE, undefined, ac.signal);
        if (ac.signal.aborted) return;
        if (res.error) { setError(res.error); setLoading(false); return; }
        setHandshakeData({
          ...d,
          clientHello: {
            clientRandom: res.data?.clientRandom,
            clientPublicKey: res.data?.clientPublicKey,
            cipherSuites: res.data?.supportedCipherSuites,
            tlsVersion: res.data?.tlsVersion,
          },
        });
        // Also fetch certificate
        const certRes = await apiGet<TlsCertificateData>("/api/tls/certificate", SCOPE, ac.signal);
        if (ac.signal.aborted) return;
        if (certRes.data) setCertData(certRes.data.certificate);
      } else if (idx === 1) {
        // ServerHello
        const res = await apiPost<TlsServerHelloData>("/api/tls/server-hello", { sessionId: sessionId() }, SCOPE, undefined, ac.signal);
        if (ac.signal.aborted) return;
        if (res.error) { setError(res.error); setLoading(false); return; }
        setHandshakeData({
          ...d,
          serverHello: {
            serverRandom: res.data?.serverRandom,
            serverPublicKey: res.data?.serverPublicKey,
            selectedCipher: res.data?.selectedCipherSuite,
          },
        });
      } else if (idx === 2) {
        // Key Exchange
        const res = await apiPost<TlsKeyExchangeData>("/api/tls/key-exchange", { sessionId: sessionId() }, SCOPE, undefined, ac.signal);
        if (ac.signal.aborted) return;
        if (res.error) { setError(res.error); setLoading(false); return; }
        setHandshakeData({
          ...d,
          keyExchange: {
            sharedSecret: res.data?.sharedSecret,
            handshakeSecret: res.data?.handshakeSecret,
            masterSecret: res.data?.masterSecret,
            clientPublicKey: d.clientHello?.clientPublicKey,
            serverPublicKey: d.serverHello?.serverPublicKey,
          },
        });
      } else if (idx === 3) {
        // Finish
        const res = await apiPost<TlsFinishData>("/api/tls/finish", { sessionId: sessionId() }, SCOPE, undefined, ac.signal);
        if (ac.signal.aborted) return;
        if (res.error) { setError(res.error); setLoading(false); return; }
        setHandshakeData({
          ...d,
          finish: {
            message: res.data?.message,
            cipherSuite: res.data?.cipherSuite,
            masterSecret: d.keyExchange?.masterSecret,
            derivedKeys: {
              clientWriteKey: res.data?.clientWriteKey,
              serverWriteKey: res.data?.serverWriteKey,
            },
          },
        });
      }
    } catch (err: unknown) {
      if (ac.signal.aborted) return;
      setError(err instanceof Error ? err.message : "Error");
    }
    setLoading(false);
  }

  async function nextStep() {
    const next = Math.min(step() + 1, STEPS.length - 1);
    await runStep(next);
  }

  return (
    <div class="tls-handshake-demo">
      <Show when={!active()} fallback={
        <div class="tls-live-panel">
          <div class="live-header">
            <h4 class="demo-title">
              {t("TLS ハンドシェイクデモ", "TLS Handshake Demo")}
              <span class="demo-badge">{t("実動作", "Live")}</span>
            </h4>
            <button class="demo-submit side-btn" onClick={() => setActive(false)}>
              {t("閉じる", "Close")}
            </button>
          </div>

          {/* Step progress indicator */}
          <div class="tls-step-progress">
            <For each={STEPS}>
              {(s, i) => (
                <div
                  class="tls-progress-step"
                  classList={{
                    "completed": i() < step(),
                    "current": i() === step(),
                    "pending": i() > step(),
                  }}
                >
                  <span class="tls-progress-num mono">{i() + 1}</span>
                  <span class="tls-progress-label">{t(s.labelJa, s.label)}</span>
                </div>
              )}
            </For>
          </div>

          {/* Data cards for each completed step */}
          <div class="live-data-cards">
            <Show when={handshakeData().clientHello}>
              <div class="live-data-card">
                <span class="ldc-label mono">ClientHello</span>
                <Show when={handshakeData().clientHello?.cipherSuites}>
                  <div class="ldc-sub">
                    <span class="ldc-sublabel mono">{t("暗号スイート", "Cipher Suites")}</span>
                    <For each={handshakeData().clientHello?.cipherSuites}>
                      {(suite: string) => <span class="ldc-value mono">{suite}</span>}
                    </For>
                  </div>
                </Show>
                <Show when={handshakeData().clientHello?.clientRandom}>
                  <div class="ldc-sub">
                    <span class="ldc-sublabel mono">{t("クライアントランダム", "Client Random")}</span>
                    <span class="ldc-value mono">{handshakeData().clientHello?.clientRandom}</span>
                  </div>
                </Show>
              </div>
            </Show>

            <Show when={handshakeData().serverHello}>
              <div class="live-data-card">
                <span class="ldc-label mono">ServerHello</span>
                <Show when={handshakeData().serverHello?.selectedCipher}>
                  <div class="ldc-sub">
                    <span class="ldc-sublabel mono">{t("選択された暗号", "Selected Cipher")}</span>
                    <span class="ldc-value mono">{handshakeData().serverHello?.selectedCipher}</span>
                  </div>
                </Show>
                <Show when={handshakeData().serverHello?.serverRandom}>
                  <div class="ldc-sub">
                    <span class="ldc-sublabel mono">{t("サーバーランダム", "Server Random")}</span>
                    <span class="ldc-value mono">{handshakeData().serverHello?.serverRandom}</span>
                  </div>
                </Show>
              </div>
            </Show>

            <Show when={handshakeData().keyExchange}>
              <div class="live-data-card">
                <span class="ldc-label mono">{t("鍵交換", "Key Exchange")}</span>
                <Show when={handshakeData().keyExchange?.clientPublicKey}>
                  <div class="ldc-sub">
                    <span class="ldc-sublabel mono">{t("クライアント公開鍵 (ECDHE)", "Client Public Key (ECDHE)")}</span>
                    <span class="ldc-value mono">{handshakeData().keyExchange?.clientPublicKey}</span>
                  </div>
                </Show>
                <Show when={handshakeData().keyExchange?.serverPublicKey}>
                  <div class="ldc-sub">
                    <span class="ldc-sublabel mono">{t("サーバー公開鍵 (ECDHE)", "Server Public Key (ECDHE)")}</span>
                    <span class="ldc-value mono">{handshakeData().keyExchange?.serverPublicKey}</span>
                  </div>
                </Show>
                <Show when={handshakeData().keyExchange?.sharedSecret}>
                  <div class="ldc-sub">
                    <span class="ldc-sublabel mono">{t("共有シークレット", "Shared Secret")}</span>
                    <span class="ldc-value mono">{handshakeData().keyExchange?.sharedSecret}</span>
                  </div>
                </Show>
              </div>
            </Show>

            <Show when={handshakeData().finish}>
              <div class="live-data-card success-card">
                <span class="ldc-label mono">{t("ハンドシェイク完了", "Handshake Complete")}</span>
                <Show when={handshakeData().finish?.derivedKeys}>
                  <div class="ldc-sub">
                    <span class="ldc-sublabel mono">{t("導出された鍵", "Derived Keys")}</span>
                    <pre class="ldc-value mono">{JSON.stringify(handshakeData().finish?.derivedKeys, null, 2)}</pre>
                  </div>
                </Show>
                <Show when={handshakeData().finish?.masterSecret}>
                  <div class="ldc-sub">
                    <span class="ldc-sublabel mono">{t("マスターシークレット", "Master Secret")}</span>
                    <span class="ldc-value mono">{handshakeData().finish?.masterSecret}</span>
                  </div>
                </Show>
              </div>
            </Show>

            {/* Certificate details */}
            <Show when={certData()}>
              <div class="live-data-card">
                <span class="ldc-label mono">{t("サーバー証明書", "Server Certificate")}</span>
                <Show when={certData()?.subject}>
                  <div class="ldc-sub">
                    <span class="ldc-sublabel mono">Subject</span>
                    <span class="ldc-value mono">{certData()?.subject}</span>
                  </div>
                </Show>
                <Show when={certData()?.issuer}>
                  <div class="ldc-sub">
                    <span class="ldc-sublabel mono">Issuer</span>
                    <span class="ldc-value mono">{certData()?.issuer}</span>
                  </div>
                </Show>
                <Show when={certData()?.validFrom}>
                  <div class="ldc-sub">
                    <span class="ldc-sublabel mono">{t("有効期間", "Valid")}</span>
                    <span class="ldc-value mono">{certData()?.validFrom} - {certData()?.validTo}</span>
                  </div>
                </Show>
                <Show when={certData()?.serialNumber}>
                  <div class="ldc-sub">
                    <span class="ldc-sublabel mono">{t("シリアル番号", "Serial Number")}</span>
                    <span class="ldc-value mono">{certData()?.serialNumber}</span>
                  </div>
                </Show>
              </div>
            </Show>
          </div>

          <Show when={error()}>
            <div class="demo-result error">{error()}</div>
          </Show>

          <button
            class="demo-submit"
            onClick={nextStep}
            disabled={loading() || step() >= STEPS.length - 1}
          >
            {loading()
              ? t("処理中...", "Processing...")
              : t("次のステップを実行", "Execute Next Step")
            } ({step() + 1}/{STEPS.length})
          </button>

          <DataFlowPanel scopeId={SCOPE} defaultOpen={true} />
        </div>
      }>
        <button class="demo-submit" onClick={startHandshake}>
          {t("TLS ハンドシェイクを開始", "Start TLS Handshake")}
        </button>
      </Show>
    </div>
  );
}
