import { For, createSignal, Show } from "solid-js";
import { useI18n } from "../../i18n/context";
import { AUTH_COMPARISON } from "../../data/auth-flows";
import type { AuthMethodComparison } from "../../types/security";
import "./AuthComparison.css";

export default function AuthComparison() {
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
              onClick={() => toggleRow(i())}
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
    </div>
  );
}
