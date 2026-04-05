import { For, Show, createSignal } from "solid-js";
import { useI18n } from "../../i18n/context";
import { AUTH_METHODS, CATEGORY_COLORS } from "../../data/auth-methods";
import type { AuthMethodInfo } from "../../types/security";
import "./AuthMethods.css";

export default function AuthMethods() {
  const { t } = useI18n();
  const [expandedId, setExpandedId] = createSignal<string | null>(null);

  return (
    <div class="auth-methods">
      <p class="auth-methods-desc">
        {t(
          "認証方式は「知識（知っていること）」「所有物（持っているもの）」「生体（自分自身）」の3要素に分類されます。",
          "Authentication methods are classified into three factors: Knowledge (something you know), Possession (something you have), and Inherence (something you are)."
        )}
      </p>

      {/* Factor legend */}
      <div class="factor-legend">
        <span class="factor-chip" style={{ "--f-color": CATEGORY_COLORS.knowledge }}>
          {t("知識", "Knowledge")}
        </span>
        <span class="factor-chip" style={{ "--f-color": CATEGORY_COLORS.possession }}>
          {t("所有物", "Possession")}
        </span>
        <span class="factor-chip" style={{ "--f-color": CATEGORY_COLORS.inherence }}>
          {t("生体", "Inherence")}
        </span>
        <span class="factor-chip" style={{ "--f-color": CATEGORY_COLORS.multi }}>
          {t("複合", "Multi-Factor")}
        </span>
      </div>

      <div class="methods-grid">
        <For each={AUTH_METHODS}>
          {(method: AuthMethodInfo) => {
            const color = CATEGORY_COLORS[method.category] || "#888";
            return (
              <div
                class="method-card"
                classList={{ expanded: expandedId() === method.id }}
                style={{ "--m-color": color }}
                onClick={() => setExpandedId(prev => prev === method.id ? null : method.id)}
              >
                <div class="method-header">
                  <span class="method-icon">{method.icon}</span>
                  <div class="method-title-area">
                    <span class="method-name">{t(method.nameJa, method.name)}</span>
                    <span class="method-category mono" style={{ color, background: `${color}18` }}>
                      {t(method.categoryLabelJa, method.categoryLabel)}
                    </span>
                  </div>
                </div>
                <p class="method-desc">{t(method.descriptionJa, method.description)}</p>

                <Show when={expandedId() === method.id}>
                  <div class="method-detail">
                    <div class="detail-section">
                      <span class="detail-label mono">{t("長所", "Strengths")}</span>
                      <ul class="detail-list strengths-list">
                        <For each={t(method.strengthsJa, method.strengths) as unknown as string[]}>
                          {(s: string) => <li>{s}</li>}
                        </For>
                      </ul>
                    </div>
                    <div class="detail-section">
                      <span class="detail-label mono">{t("短所", "Weaknesses")}</span>
                      <ul class="detail-list weaknesses-list">
                        <For each={t(method.weaknessesJa, method.weaknesses) as unknown as string[]}>
                          {(w: string) => <li>{w}</li>}
                        </For>
                      </ul>
                    </div>
                  </div>
                </Show>
              </div>
            );
          }}
        </For>
      </div>
    </div>
  );
}
