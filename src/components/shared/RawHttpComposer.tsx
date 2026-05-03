import { createSignal, Show, For } from "solid-js";
import { useI18n } from "../../i18n/context";
import type {
  HttpMethod,
  OrchestratorExecRequest,
  VictimTarget,
} from "../../../shared/api-types";
import "./RawHttpComposer.css";

/**
 * Live attack request composer.
 *
 * 学習者がブラウザから生 HTTP リクエストを組み立てて
 * `POST /api/orchestrator/exec` に送る入力 UI。
 * Host ヘッダは orchestrator が強制上書きするため編集不可。
 *
 * Phase 1 minimal: Headers タブ + Body タブのみ実装、Raw タブと SequenceDiagramView は PR-2 に分離。
 *
 * 関連設計書: DESIGN/33-raw-http-composer.md, DESIGN/34-safety-guardrails-live.md
 */

interface RawHttpComposerProps {
  scenarioId: string;
  /** orchestrator 側の VICTIM_ALLOWLIST と同期した利用可能 target */
  allowedTargets: VictimTarget[];
  /** 初期テンプレート (シナリオごとの推奨開始値) */
  template: {
    target: VictimTarget;
    method: HttpMethod;
    path: string;
    headers: Record<string, string>;
    body: string;
  };
  /** SEND ボタン押下で呼ばれる。AttackPanel が orchestrator/exec を叩く。 */
  onSend: (
    payload: { target: VictimTarget; request: OrchestratorExecRequest["request"] },
  ) => Promise<void>;
  /** AttackPanel が「実行中」状態を伝播する */
  sending: boolean;
}

type HeaderEntry = { key: string; value: string };

const HTTP_METHODS: HttpMethod[] = ["GET", "POST", "PUT", "PATCH", "DELETE"];

function RawHttpComposer(props: RawHttpComposerProps) {
  const { t } = useI18n();

  const [target, setTarget] = createSignal<VictimTarget>(props.template.target);
  const [method, setMethod] = createSignal<HttpMethod>(props.template.method);
  const [path, setPath] = createSignal<string>(props.template.path);
  const [headers, setHeaders] = createSignal<HeaderEntry[]>(
    Object.entries(props.template.headers)
      .filter(([k]) => k.toLowerCase() !== "host")
      .map(([key, value]) => ({ key, value })),
  );
  const [body, setBody] = createSignal<string>(props.template.body);
  const [activeTab, setActiveTab] = createSignal<"headers" | "body" | "raw">("body");

  /**
   * Raw タブ用の派生値。本物の HTTP プレコンパイルではなく可視化用。
   * Host ヘッダは orchestrator が常に強制上書きするため、プレビューとして表示する。
   * 編集系操作 (copy/export/persist) は意図的に提供しない (DESIGN/33 §2.4)。
   */
  const rawPreview = () => {
    const userHeaders = headers()
      .filter((h) => h.key.trim() && h.key.trim().toLowerCase() !== "host")
      .map((h) => `${h.key.trim()}: ${h.value}`);
    const lines = [
      `${method()} ${path() || "/"} HTTP/1.1`,
      "Host: <victim host> (orchestrator が強制設定 / set by orchestrator)",
      ...userHeaders,
    ];
    const bodyStr = body();
    return [...lines, "", bodyStr].join("\r\n");
  };

  function updateHeader(idx: number, patch: Partial<HeaderEntry>) {
    setHeaders((prev) =>
      prev.map((h, i) => (i === idx ? { ...h, ...patch } : h)),
    );
  }
  function removeHeader(idx: number) {
    setHeaders((prev) => prev.filter((_, i) => i !== idx));
  }
  function addHeader() {
    setHeaders((prev) => [...prev, { key: "", value: "" }]);
  }

  async function handleSend() {
    if (props.sending) return;
    const headerObj: Record<string, string> = {};
    for (const h of headers()) {
      const k = h.key.trim();
      if (k && k.toLowerCase() !== "host") headerObj[k] = h.value;
    }
    await props.onSend({
      target: target(),
      request: {
        method: method(),
        path: path(),
        headers: headerObj,
        body: body() || null,
      },
    });
  }

  return (
    <div
      class="raw-http-composer"
      data-scenario-id={props.scenarioId}
      role="region"
      aria-label={t("生 HTTP リクエスト編集", "Raw HTTP request composer")}
    >
      <span
        class="raw-http-composer-live-badge"
        aria-label={t("LIVE 攻撃モード", "LIVE attack mode")}
      >
        LIVE
      </span>

      <div class="raw-http-composer-topbar">
        <label class="rhc-label" for={`rhc-target-${props.scenarioId}`}>
          {t("送信先", "Target")}
        </label>
        <select
          id={`rhc-target-${props.scenarioId}`}
          class="rhc-select"
          value={target()}
          onChange={(e) => setTarget(e.currentTarget.value as VictimTarget)}
          aria-label={t("攻撃対象 victim を選択", "Select attack target")}
        >
          <For each={props.allowedTargets}>
            {(tgt) => <option value={tgt}>{tgt}</option>}
          </For>
        </select>

        <label class="rhc-label" for={`rhc-method-${props.scenarioId}`}>
          {t("メソッド", "Method")}
        </label>
        <select
          id={`rhc-method-${props.scenarioId}`}
          class="rhc-select"
          value={method()}
          onChange={(e) => setMethod(e.currentTarget.value as HttpMethod)}
        >
          <For each={HTTP_METHODS}>
            {(m) => <option value={m}>{m}</option>}
          </For>
        </select>

        <label class="rhc-label" for={`rhc-path-${props.scenarioId}`}>
          {t("パス", "Path")}
        </label>
        <input
          id={`rhc-path-${props.scenarioId}`}
          class="rhc-input rhc-path"
          type="text"
          value={path()}
          onInput={(e) => setPath(e.currentTarget.value)}
          spellcheck={false}
        />
      </div>

      <div class="raw-http-composer-tabs" role="tablist">
        <button
          type="button"
          class="rhc-tab"
          role="tab"
          aria-selected={activeTab() === "headers"}
          data-active={activeTab() === "headers"}
          onClick={() => setActiveTab("headers")}
        >
          {t("ヘッダー", "Headers")}
        </button>
        <button
          type="button"
          class="rhc-tab"
          role="tab"
          aria-selected={activeTab() === "body"}
          data-active={activeTab() === "body"}
          onClick={() => setActiveTab("body")}
        >
          {t("ボディ", "Body")}
        </button>
        <button
          type="button"
          class="rhc-tab"
          role="tab"
          aria-selected={activeTab() === "raw"}
          data-active={activeTab() === "raw"}
          onClick={() => setActiveTab("raw")}
        >
          {t("Raw", "Raw")}
        </button>
      </div>

      <div class="raw-http-composer-tabpanel" role="tabpanel">
        <Show when={activeTab() === "headers"}>
          <div class="rhc-header-row rhc-header-row-disabled">
            <input
              class="rhc-input rhc-header-key"
              value="Host"
              disabled
              aria-label="Host header (orchestrator-managed)"
            />
            <input
              class="rhc-input rhc-header-value"
              value={t(
                "(orchestrator が強制設定)",
                "(set by orchestrator)",
              )}
              disabled
            />
          </div>
          <For each={headers()}>
            {(h, idx) => (
              <div class="rhc-header-row">
                <input
                  class="rhc-input rhc-header-key"
                  type="text"
                  placeholder="Header-Name"
                  value={h.key}
                  onInput={(e) => updateHeader(idx(), { key: e.currentTarget.value })}
                  spellcheck={false}
                />
                <input
                  class="rhc-input rhc-header-value"
                  type="text"
                  placeholder="value"
                  value={h.value}
                  onInput={(e) => updateHeader(idx(), { value: e.currentTarget.value })}
                  spellcheck={false}
                />
                <button
                  type="button"
                  class="rhc-header-remove"
                  onClick={() => removeHeader(idx())}
                  aria-label={t("ヘッダ削除", "Remove header")}
                >
                  ×
                </button>
              </div>
            )}
          </For>
          <button type="button" class="rhc-header-add" onClick={addHeader}>
            {t("+ ヘッダを追加", "+ Add header")}
          </button>
        </Show>

        <Show when={activeTab() === "body"}>
          <textarea
            class="rhc-body"
            value={body()}
            onInput={(e) => setBody(e.currentTarget.value)}
            rows={8}
            spellcheck={false}
            aria-label={t("リクエストボディ", "Request body")}
            placeholder={t(
              '例: {"token":"<偽造 JWT>"}',
              'e.g. {"token":"<forged JWT>"}',
            )}
          />
        </Show>

        <Show when={activeTab() === "raw"}>
          <pre
            class="rhc-raw"
            aria-label={t("生 HTTP プレビュー (読み取り専用)", "Raw HTTP preview (read-only)")}
          >
            {rawPreview()}
          </pre>
          <p class="rhc-raw-note">
            {t(
              "プレビューのみ。Host ヘッダは送信時に orchestrator が解決した victim ホストへ強制上書きされます。",
              "Preview only. The Host header is overwritten at send time by the orchestrator to the resolved victim host.",
            )}
          </p>
        </Show>
      </div>

      <button
        type="button"
        class="rhc-send"
        disabled={props.sending}
        aria-busy={props.sending}
        onClick={handleSend}
      >
        <Show
          when={props.sending}
          fallback={t("送信 (LIVE)", "Send Attack (LIVE)")}
        >
          {t("送信中…", "Sending…")}
        </Show>
      </button>
    </div>
  );
}

export default RawHttpComposer;
