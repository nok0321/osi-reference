import { createSignal, createEffect, Show, For } from "solid-js";
import { useI18n } from "../../i18n/context";
import type { CapturedExchange, ServerTrace, CryptoOp, DbQuery, SessionOp } from "../../api/client";
import { getScopedExchanges } from "../../api/client";
import "./DataFlowPanel.css";

interface DataFlowPanelProps {
  scopeId: string;
  defaultOpen?: boolean;
}

export default function DataFlowPanel(props: DataFlowPanelProps) {
  const { t } = useI18n();
  const [open, setOpen] = createSignal(props.defaultOpen ?? false);
  const [tab, setTab] = createSignal<"http" | "trace" | "db">("http");

  const exs = () => getScopedExchanges(props.scopeId)();

  return (
    <div class="data-flow-panel">
      <button
        class="data-flow-toggle"
        data-open={open()}
        onClick={() => setOpen(!open())}
      >
        <span>{t("Server Data Flow", "Server Data Flow")} ({exs().length})</span>
        <span class="toggle-icon">{open() ? "▾" : "▸"}</span>
      </button>

      <Show when={open()}>
        <div class="data-flow-tabs">
          <button class="data-flow-tab" data-active={tab() === "http"} onClick={() => setTab("http")}>
            HTTP
          </button>
          <button class="data-flow-tab" data-active={tab() === "trace"} onClick={() => setTab("trace")}>
            {t("サーバー処理", "Server Trace")}
          </button>
          <button class="data-flow-tab" data-active={tab() === "db"} onClick={() => setTab("db")}>
            {t("DB操作", "DB Queries")}
          </button>
        </div>

        <div class="data-flow-content">
          <Show when={tab() === "http"}>
            <HttpInspectorView exchanges={exs()} />
          </Show>
          <Show when={tab() === "trace"}>
            <TraceView exchanges={exs()} />
          </Show>
          <Show when={tab() === "db"}>
            <DbQueryView exchanges={exs()} />
          </Show>
        </div>
      </Show>
    </div>
  );
}

/* ── HTTP Inspector ── */
function HttpInspectorView(props: { exchanges: CapturedExchange[] }) {
  const [expandedId, setExpandedId] = createSignal<string | null>(null);
  const { t } = useI18n();

  return (
    <div class="http-inspector">
      <Show when={props.exchanges.length === 0}>
        <div class="trace-empty">{t("HTTP交換なし", "No HTTP exchanges yet")}</div>
      </Show>
      <div class="exchange-list">
        <For each={[...props.exchanges].reverse()}>
          {(ex) => (
            <div class="http-exchange">
              <div
                class="http-exchange-header"
                onClick={() => setExpandedId(expandedId() === ex.id ? null : ex.id)}
              >
                <span class="http-method" data-method={ex.request.method}>{ex.request.method}</span>
                <span class="http-url">{ex.request.url}</span>
                <span class="http-status" data-ok={ex.response.status >= 200 && ex.response.status < 400}>
                  {ex.response.status}
                </span>
                <span class="http-duration">{Math.round(ex.response.durationMs)}ms</span>
              </div>
              <Show when={expandedId() === ex.id}>
                <div class="http-exchange-body">
                  <Show when={ex.request.body}>
                    <div class="http-section-label">{t("リクエストボディ", "Request Body")}</div>
                    <pre class="json-block">{JSON.stringify(ex.request.body, null, 2)}</pre>
                  </Show>
                  <div class="http-section-label">{t("レスポンスボディ", "Response Body")}</div>
                  <pre class="json-block">{JSON.stringify(ex.response.body, null, 2)}</pre>
                </div>
              </Show>
            </div>
          )}
        </For>
      </div>
    </div>
  );
}

/* ── Trace View (Crypto + Session ops) ── */
function TraceView(props: { exchanges: CapturedExchange[] }) {
  const { t } = useI18n();
  const allCryptoOps = () => {
    const ops: (CryptoOp & { exchangeId: string })[] = [];
    for (const ex of props.exchanges) {
      if (ex.trace?.cryptoOps) {
        for (const op of ex.trace.cryptoOps) {
          ops.push({ ...op, exchangeId: ex.id });
        }
      }
    }
    return ops;
  };

  const allSessionOps = () => {
    const ops: (SessionOp & { exchangeId: string })[] = [];
    for (const ex of props.exchanges) {
      if (ex.trace?.sessionOps) {
        for (const op of ex.trace.sessionOps) {
          ops.push({ ...op, exchangeId: ex.id });
        }
      }
    }
    return ops;
  };

  return (
    <div>
      <Show when={allCryptoOps().length === 0 && allSessionOps().length === 0}>
        <div class="trace-empty">{t("サーバートレースなし", "No server trace data yet")}</div>
      </Show>

      <Show when={allCryptoOps().length > 0}>
        <div class="trace-section">
          <div class="trace-section-title">
            <span class="trace-section-icon">🔐</span> {t("暗号処理", "Crypto Operations")}
          </div>
          <div class="crypto-viz">
            <For each={allCryptoOps()}>
              {(op) => (
                <div class="crypto-op">
                  <div class="crypto-op-header">
                    <span class="crypto-op-name">{op.op}</span>
                    <span class="crypto-op-algo">{op.algo}</span>
                  </div>
                  <div class="crypto-op-row">
                    <span class="label">{t("入力:", "IN:")}</span>
                    <span class="value">{op.input}</span>
                  </div>
                  <div class="crypto-op-row">
                    <span class="label">{t("出力:", "OUT:")}</span>
                    <span class="value">{op.output}</span>
                  </div>
                  <Show when={op.detail}>
                    <div class="crypto-op-detail">{op.detail}</div>
                  </Show>
                </div>
              )}
            </For>
          </div>
        </div>
      </Show>

      <Show when={allSessionOps().length > 0}>
        <div class="trace-section">
          <div class="trace-section-title">
            <span class="trace-section-icon">📋</span> {t("セッション操作", "Session Operations")}
          </div>
          <div class="crypto-viz">
            <For each={allSessionOps()}>
              {(op) => (
                <div class="session-op">
                  <div class="session-op-action">{op.action}</div>
                  <div class="session-op-data">{JSON.stringify(op.data, null, 2)}</div>
                </div>
              )}
            </For>
          </div>
        </div>
      </Show>
    </div>
  );
}

/* ── DB Query View ── */
function DbQueryView(props: { exchanges: CapturedExchange[] }) {
  const { t } = useI18n();
  const allQueries = () => {
    const queries: (DbQuery & { exchangeId: string })[] = [];
    for (const ex of props.exchanges) {
      if (ex.trace?.dbQueries) {
        for (const q of ex.trace.dbQueries) {
          queries.push({ ...q, exchangeId: ex.id });
        }
      }
    }
    return queries;
  };

  return (
    <div class="db-viewer">
      <Show when={allQueries().length === 0}>
        <div class="trace-empty">{t("DBクエリなし", "No database queries yet")}</div>
      </Show>
      <Show when={allQueries().length > 0}>
        <div class="crypto-viz">
          <For each={allQueries()}>
            {(q) => (
              <div class="crypto-op">
                <div class="crypto-op-header">
                  <span class="crypto-op-name">SQL</span>
                  <span class="crypto-op-algo">{q.ms.toFixed(1)}ms</span>
                </div>
                <pre class="json-block" style="max-height:80px">{q.sql}</pre>
                <Show when={q.params && q.params.length > 0}>
                  <div class="crypto-op-row" style="margin-top:4px">
                    <span class="label">{t("パラメータ:", "Params:")}</span>
                    <span class="value">{JSON.stringify(q.params)}</span>
                  </div>
                </Show>
                <Show when={q.rows && (q.rows as unknown[]).length > 0}>
                  <div class="crypto-op-row">
                    <span class="label">{t("行:", "Rows:")}</span>
                    <span class="value">{JSON.stringify(q.rows)}</span>
                  </div>
                </Show>
              </div>
            )}
          </For>
        </div>
      </Show>
    </div>
  );
}
