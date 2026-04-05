import { For, Show, createSignal, createMemo } from "solid-js";
import { useI18n } from "../../i18n/context";
import { jwtActiveSection, setJwtActiveSection } from "../../state/security-state";
import { JWT_SECTIONS, SAMPLE_JWT_ENCODED } from "../../data/auth-flows";
import type { JwtSection, JwtField } from "../../types/security";
import "./JwtInspector.css";

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
              {activeSection()!.name === "header" && "ALGORITHM & TOKEN TYPE"}
              {activeSection()!.name === "payload" && "DATA (CLAIMS)"}
              {activeSection()!.name === "signature" && "VERIFY SIGNATURE"}
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
    </div>
  );
}
