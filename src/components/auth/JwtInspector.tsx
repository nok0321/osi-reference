import { For, Show, createSignal, createMemo, onCleanup } from "solid-js";
import { useI18n } from "../../i18n/context";
import { jwtActiveSection, setJwtActiveSection } from "../../state/security-state";
import { JWT_SECTIONS, SAMPLE_JWT_ENCODED } from "../../data/auth-flows";
import type { JwtSection, JwtField } from "../../types/security";
import { apiPost } from "../../api/client";
import DataFlowPanel from "../shared/DataFlowPanel";
import ViewModeToggle from "../shared/ViewModeToggle";
import AttackPanel from "../shared/AttackPanel";
import { getViewMode } from "../../state/attack-state";
import { jwtScenarios } from "./attacks/scenarios/jwt-scenarios";
import type { AttackResult } from "../../../shared/api-types";
import "./JwtInspector.css";

const SCOPE = "jwt-ops";

function JwtWorkshop() {
  const { t } = useI18n();
  const [algo, setAlgo] = createSignal<"HS256" | "RS256">("HS256");
  const [claims, setClaims] = createSignal('{\n  "sub": "user123",\n  "name": "Alice",\n  "role": "admin"\n}');
  const [expiresIn, setExpiresIn] = createSignal(3600);
  const [generatedToken, setGeneratedToken] = createSignal("");
  const [verifyResult, setVerifyResult] = createSignal<{ valid: boolean; error?: string } | null>(null);
  const [loading, setLoading] = createSignal(false);
  const [countdown, setCountdown] = createSignal<number | null>(null);
  let countdownTimer: ReturnType<typeof setInterval> | undefined;

  onCleanup(() => {
    if (countdownTimer) clearInterval(countdownTimer);
  });

  async function handleSign() {
    setLoading(true);
    setVerifyResult(null);
    try {
      const parsed = JSON.parse(claims());
      const res = await apiPost<{ token: string }>("/api/jwt/sign", {
        claims: parsed,
        algorithm: algo(),
        expiresIn: expiresIn(),
      }, SCOPE);
      if (res.data) {
        setGeneratedToken(res.data.token);
        // Start countdown if short expiry
        if (expiresIn() <= 30) {
          startCountdown(expiresIn());
        } else {
          setCountdown(null);
        }
      }
    } catch {
      setVerifyResult({ valid: false, error: "Invalid JSON in claims" });
    }
    setLoading(false);
  }

  function startCountdown(seconds: number) {
    if (countdownTimer) clearInterval(countdownTimer);
    setCountdown(seconds);
    countdownTimer = setInterval(() => {
      setCountdown((prev) => {
        if (prev === null || prev <= 0) {
          clearInterval(countdownTimer);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
  }

  async function handleVerify() {
    if (!generatedToken()) return;
    const res = await apiPost<{ valid: boolean; error?: string }>("/api/jwt/verify", {
      token: generatedToken(),
      algorithm: algo(),
    }, SCOPE);
    if (res.data) {
      setVerifyResult({ valid: res.data.valid, error: res.data.error });
    }
  }

  async function handleTamper() {
    if (!generatedToken()) return;
    // Tamper with one character in the payload section
    const parts = generatedToken().split(".");
    if (parts.length === 3) {
      const tampered = parts[0] + "." + parts[1].slice(0, -1) + "X" + "." + parts[2];
      setGeneratedToken(tampered);
      setVerifyResult(null);
    }
  }

  return (
    <div class="jwt-workshop">
      <h4 class="demo-title">
        {t("JWT ワークショップ", "JWT Workshop")}
        <span class="demo-badge">{t("実動作", "Live")}</span>
      </h4>

      <div class="jwt-ws-layout">
        <div class="jwt-ws-input">
          <div class="jwt-ws-algo">
            <label class="form-label mono">{t("アルゴリズム", "Algorithm")}</label>
            <div class="demo-mode-toggle">
              <button classList={{ active: algo() === "HS256" }} onClick={() => setAlgo("HS256")}>HS256</button>
              <button classList={{ active: algo() === "RS256" }} onClick={() => setAlgo("RS256")}>RS256</button>
            </div>
          </div>

          <div class="form-field">
            <label class="form-label mono">{t("有効期限", "Expires In")}</label>
            <div class="jwt-ws-expiry">
              <button classList={{ active: expiresIn() === 10 }} onClick={() => setExpiresIn(10)}>10s</button>
              <button classList={{ active: expiresIn() === 60 }} onClick={() => setExpiresIn(60)}>1m</button>
              <button classList={{ active: expiresIn() === 3600 }} onClick={() => setExpiresIn(3600)}>1h</button>
            </div>
          </div>

          <div class="form-field">
            <label class="form-label mono">{t("カスタムクレーム (JSON)", "Custom Claims (JSON)")}</label>
            <textarea
              class="form-input jwt-ws-claims"
              value={claims()}
              onInput={(e) => setClaims(e.currentTarget.value)}
              rows={5}
              spellcheck={false}
            />
          </div>

          <button class="demo-submit" onClick={handleSign} disabled={loading()}>
            {t("署名してトークン生成", "Sign & Generate Token")}
          </button>
        </div>

        <div class="jwt-ws-output">
          <Show when={generatedToken()}>
            <div class="form-field">
              <label class="form-label mono">
                {t("生成されたトークン", "Generated Token")}
                <Show when={countdown() !== null}>
                  <span class="jwt-countdown" classList={{ expired: countdown() === 0 }}>
                    {countdown()! > 0 ? ` TTL: ${countdown()}s` : " EXPIRED"}
                  </span>
                </Show>
              </label>
              <textarea
                class="form-input jwt-ws-token"
                value={generatedToken()}
                onInput={(e) => setGeneratedToken(e.currentTarget.value)}
                rows={4}
                spellcheck={false}
              />
            </div>

            <div class="jwt-ws-actions">
              <button class="demo-submit" onClick={handleVerify}>
                {t("検証する", "Verify")}
              </button>
              <button class="demo-submit jwt-ws-tamper" onClick={handleTamper}>
                {t("改竄する", "Tamper")}
              </button>
            </div>

            <Show when={verifyResult()}>
              <div
                class="demo-result"
                role="alert"
                classList={{ success: verifyResult()!.valid, error: !verifyResult()!.valid }}
              >
                {verifyResult()!.valid ? "✓ VALID" : `✗ INVALID — ${verifyResult()!.error}`}
              </div>
            </Show>
          </Show>
        </div>
      </div>

      <DataFlowPanel scopeId={SCOPE} />
    </div>
  );
}

export default function JwtInspector() {
  const { t } = useI18n();
  const [isEdited, setIsEdited] = createSignal(false);
  const [editedPayload, setEditedPayload] = createSignal("");

  const activeSection = createMemo(() =>
    JWT_SECTIONS.find(s => s.name === jwtActiveSection())
  );

  function handleSectionClick(name: "header" | "payload" | "signature") {
    if (jwtActiveSection() === name) {
      setJwtActiveSection(null);
    } else {
      setJwtActiveSection(name);
      if (name === "payload") {
        setEditedPayload(JWT_SECTIONS[1].decoded);
        setIsEdited(false);
      }
    }
  }

  function handlePayloadEdit(value: string) {
    setEditedPayload(value);
    setIsEdited(value !== JWT_SECTIONS[1].decoded);
  }

  return (
    <div class="jwt-inspector">
      {/* View mode toggle (Defender / Attacker) — 両モード共通領域 */}
      <ViewModeToggle tabId="jwt" />

      <Show when={getViewMode("jwt") === "defender"}>
        <div class="jwt-title-row">
          <h3 class="jwt-title mono">JWT (JSON Web Token)</h3>
          <Show when={isEdited()}>
            <span class="jwt-invalid-badge">INVALID SIGNATURE</span>
          </Show>
        </div>

        {/* Encoded JWT display */}
        <div class="jwt-encoded">
          <div class="encoded-label mono">{t("エンコード済みトークン", "Encoded Token")}</div>
          <div class="encoded-segments">
            <For each={JWT_SECTIONS}>
              {(section: JwtSection) => (
                <span
                  class="encoded-segment"
                  classList={{ active: jwtActiveSection() === section.name }}
                  style={{ color: section.color }}
                  onClick={() => handleSectionClick(section.name)}
                >
                  {section.encoded}
                </span>
              )}
            </For>
          </div>
        </div>

        {/* Section selector */}
        <div class="jwt-sections">
          <For each={JWT_SECTIONS}>
            {(section: JwtSection) => (
              <button
                class="section-btn"
                classList={{ active: jwtActiveSection() === section.name }}
                style={{
                  "--sec-color": section.color,
                  "--sec-color-dim": `${section.color}22`,
                }}
                onClick={() => handleSectionClick(section.name)}
              >
                <span class="sec-dot" style={{ background: section.color }} />
                <span class="sec-name">{section.name.toUpperCase()}</span>
              </button>
            )}
          </For>
        </div>

        {/* Decoded Panel */}
        <Show when={activeSection()}>
          <div
            class="jwt-decoded"
            style={{ "--dec-color": activeSection()!.color }}
          >
            <div class="decoded-header">
              <span class="decoded-title">{activeSection()!.name.toUpperCase()}</span>
              <span class="decoded-subtitle mono">
                {activeSection()!.name === "header" && t("アルゴリズム＆トークン型", "ALGORITHM & TOKEN TYPE")}
                {activeSection()!.name === "payload" && t("データ（クレーム）", "DATA (CLAIMS)")}
                {activeSection()!.name === "signature" && t("署名検証", "VERIFY SIGNATURE")}
              </span>
            </div>

            {/* Editable payload or readonly */}
            <Show
              when={jwtActiveSection() === "payload"}
              fallback={
                <pre class="decoded-json mono">{activeSection()!.decoded}</pre>
              }
            >
              <textarea
                class="decoded-editor mono"
                value={editedPayload()}
                onInput={(e) => handlePayloadEdit(e.currentTarget.value)}
                rows={8}
                spellcheck={false}
              />
            </Show>

            {/* Field details */}
            <div class="decoded-fields">
              <For each={activeSection()!.fields}>
                {(field: JwtField) => (
                  <div class="jwt-field-row">
                    <span class="jwt-field-key mono" style={{ color: activeSection()!.color }}>
                      {field.key}
                    </span>
                    <span class="jwt-field-value mono">{field.value}</span>
                    <span class="jwt-field-desc">{t(field.descriptionJa, field.description)}</span>
                  </div>
                )}
              </For>
            </div>
          </div>
        </Show>

        {/* JWT Structure explanation */}
        <div class="jwt-structure">
          <div class="struct-label mono">{t("JWT構造", "JWT Structure")}</div>
          <div class="struct-formula mono">
            <span style={{ color: JWT_SECTIONS[0].color }}>Header</span>
            <span class="struct-dot">.</span>
            <span style={{ color: JWT_SECTIONS[1].color }}>Payload</span>
            <span class="struct-dot">.</span>
            <span style={{ color: JWT_SECTIONS[2].color }}>Signature</span>
          </div>
          <p class="struct-desc">
            {t(
              "Base64urlエンコードされた3部分をドット(.)で連結。署名はヘッダとペイロードの完全性を保証。",
              "Three Base64url-encoded parts joined by dots. The signature guarantees integrity of header and payload."
            )}
          </p>
        </div>

        {/* Live JWT Workshop */}
        <JwtWorkshop />
      </Show>

      {/* Attacker mode: attack scenario panel */}
      <Show when={getViewMode("jwt") === "attacker"}>
        <AttackPanel
          tabId="jwt"
          scenarios={jwtScenarios}
          onRunScenario={async (s) => {
            const suffix = s.id.replace(/^jwt-/, "");
            // E-2: 両モード並列実行のため body は不要 (空オブジェクト)
            const res = await apiPost<AttackResult>(
              `/api/jwt/attack/${suffix}`,
              {},
              "attack-jwt"
            );
            if (!res.data) {
              return {
                scenarioId: s.id,
                outcome: "error" as const,
                startedAt: Date.now(),
                finishedAt: Date.now(),
                steps: [],
                summaryJa: res.error ?? "実行エラーが発生しました",
                summary: res.error ?? "Execution error occurred",
              };
            }
            return res.data;
          }}
        />
      </Show>
    </div>
  );
}
