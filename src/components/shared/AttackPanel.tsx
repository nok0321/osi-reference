import { createSignal, createEffect, Show, For } from "solid-js";
import { useI18n } from "../../i18n/context";
import type {
  AttackScenarioMeta,
  AttackResult,
  OrchestratorExecRequest,
  OrchestratorExecResponse,
  RawExchange,
  VictimTarget,
} from "../../../shared/api-types";
import type { AuthSubView } from "../../types/security";
import EducationalWarningBanner from "./EducationalWarningBanner";
import AttackScenarioSelector from "./AttackScenarioSelector";
import AttackStepTimeline from "./AttackStepTimeline";
import AttackResultBanner from "./AttackResultBanner";
import AttackDefensePanel from "./AttackDefensePanel";
import DataFlowPanel from "./DataFlowPanel";
import RawHttpComposer from "./RawHttpComposer";
import "./AttackPanel.css";

interface AttackPanelProps {
  tabId: AuthSubView;
  scenarios: AttackScenarioMeta[];
  /**
   * E-2: 攻撃ルートは 1 リクエストで両モード (脆弱+堅牢) を必ず並列実行する。
   * 排他選択モードは廃止されたため、modeBody 引数は不要。
   */
  onRunScenario: (scenario: AttackScenarioMeta) => Promise<AttackResult>;
  /**
   * mode: "live" シナリオで RawHttpComposer の SEND 押下時に呼ばれる。
   * 未指定時は live シナリオを narration にフォールバックさせる (PR-1 後方互換)。
   */
  onRunLiveScenario?: (
    scenario: AttackScenarioMeta,
    payload: { target: VictimTarget; request: OrchestratorExecRequest["request"] },
  ) => Promise<AttackResult>;
  /** Phase 1 では victim-web のみ。Phase 4+ で複数 target を表示する。 */
  allowedTargets?: VictimTarget[];
}

function AttackPanel(props: AttackPanelProps) {
  const { t } = useI18n();

  const [selectedId, setSelectedId] = createSignal<string>(
    props.scenarios[0]?.id ?? ""
  );
  const [attackResult, setAttackResult] = createSignal<AttackResult | null>(null);
  const [rawExchange, setRawExchange] = createSignal<RawExchange | null>(null);
  const [running, setRunning] = createSignal(false);
  const [defenseOpen, setDefenseOpen] = createSignal(false);
  const [errorMessage, setErrorMessage] = createSignal<string | null>(null);

  const selectedScenario = () =>
    props.scenarios.find((s) => s.id === selectedId()) ?? props.scenarios[0] ?? null;

  const isLiveMode = () => selectedScenario()?.mode === "live";
  const allowedTargets = (): VictimTarget[] =>
    props.allowedTargets ?? ["victim-web"];

  /* scenarios が変化したとき selectedId が無効/空なら最初のシナリオに同期 */
  createEffect(() => {
    const scenarios = props.scenarios;
    const current = selectedId();
    if (scenarios.length > 0 && (!current || !scenarios.some(s => s.id === current))) {
      setSelectedId(scenarios[0].id);
    }
  });

  /* 攻撃完了後に防御パネルを自動展開 */
  createEffect(() => {
    const r = attackResult();
    if (r !== null) {
      setDefenseOpen(true);
    }
  });

  /* シナリオ切替時に直前の結果・エラー・rawExchange をクリア */
  createEffect(() => {
    selectedId();
    setAttackResult(null);
    setRawExchange(null);
    setErrorMessage(null);
  });

  async function handleRunAttack() {
    const scenario = selectedScenario();
    if (!scenario || running()) return;
    setRunning(true);
    setAttackResult(null);
    setRawExchange(null);
    setDefenseOpen(false);
    setErrorMessage(null);
    try {
      const result = await props.onRunScenario(scenario);
      setAttackResult(result);
    } finally {
      setRunning(false);
    }
  }

  async function handleSendLive(payload: {
    target: VictimTarget;
    request: OrchestratorExecRequest["request"];
  }) {
    const scenario = selectedScenario();
    if (!scenario || running() || !props.onRunLiveScenario) return;
    setRunning(true);
    setAttackResult(null);
    setRawExchange(null);
    setDefenseOpen(false);
    setErrorMessage(null);
    try {
      const result = await props.onRunLiveScenario(scenario, payload);
      setAttackResult(result);
      // OrchestratorExecResponse extends AttackResult & { rawExchange, mode: "live" }。
      // success path のみ runtime で rawExchange を保持する (error fallback path は plain AttackResult)。
      const live = result as Partial<OrchestratorExecResponse>;
      setRawExchange(live.rawExchange ?? null);
      if (result.outcome === "error") {
        setErrorMessage(result.summaryJa ?? result.summary ?? t("実行エラー", "Execution error"));
      }
    } finally {
      setRunning(false);
    }
  }

  return (
    <div class="attack-panel">
      {/* 1. 教育用バナー (常時表示)。live モードでは LIVE バッジを付与 */}
      <EducationalWarningBanner mode={isLiveMode() ? "live" : "narration"} />

      <div class="attack-panel-inner">
        {/* 2. シナリオセレクタ */}
        <AttackScenarioSelector
          scenarios={props.scenarios}
          selectedId={selectedId()}
          onSelect={setSelectedId}
        />

        {/* 3. 並列モードラベル表示 (E-2: 排他選択ではなく両モードを表示するためのラベル) */}
        <Show when={(selectedScenario()?.modes ?? []).length > 0}>
          <div
            class="attack-mode-labels"
            role="group"
            aria-label={t("攻撃モード (両方並列実行)", "Attack modes (run in parallel)")}
          >
            <For each={selectedScenario()!.modes!}>
              {(mode) => (
                <span
                  class="attack-mode-label"
                  data-kind={mode.kind}
                >
                  {t(mode.labelJa, mode.label)}
                </span>
              )}
            </For>
          </div>
        </Show>

        {/* 4a. live モード: RawHttpComposer */}
        <Show when={isLiveMode() && selectedScenario()?.liveTemplate && props.onRunLiveScenario}>
          <RawHttpComposer
            scenarioId={selectedScenario()!.id}
            allowedTargets={allowedTargets()}
            template={{
              target: selectedScenario()!.liveTemplate!.target,
              method: selectedScenario()!.liveTemplate!.method,
              path: selectedScenario()!.liveTemplate!.path,
              headers: selectedScenario()!.liveTemplate!.headers ?? {},
              body: selectedScenario()!.liveTemplate!.body ?? "",
            }}
            sending={running()}
            onSend={handleSendLive}
          />
        </Show>

        {/* 4b. narration モード: 既存実行ボタン */}
        <Show when={!isLiveMode()}>
          <button
            class="attack-run-button"
            disabled={running() || props.scenarios.length === 0}
            aria-busy={running()}
            onClick={handleRunAttack}
          >
            <Show when={running()} fallback={t("攻撃を実行", "Run Attack")}>
              {t("実行中...", "Running...")}
            </Show>
          </button>
        </Show>

        <Show when={errorMessage() !== null}>
          <div class="attack-error-toast" role="alert" aria-live="assertive">
            {errorMessage()}
          </div>
        </Show>

        <div class="attack-panel-body">
          {/* 5. タイムライン */}
          <div class="attack-panel-timeline">
            <AttackStepTimeline
              steps={attackResult()?.steps ?? []}
              running={running()}
            />
          </div>

          {/* 6. 防御策パネル */}
          <div class="attack-panel-defense">
            <AttackDefensePanel
              scenario={selectedScenario()}
              open={defenseOpen()}
              onToggle={() => setDefenseOpen(!defenseOpen())}
            />
          </div>
        </div>

        {/* 7. 結果バナー */}
        <Show when={attackResult() !== null}>
          <AttackResultBanner result={attackResult()!} />
        </Show>

        {/* 8. DataFlowPanel — live モード時のみ Sequence タブが露出する */}
        <DataFlowPanel
          scopeId={`attack-${props.tabId}`}
          defaultOpen={false}
          isLiveMode={isLiveMode()}
          rawExchange={rawExchange()}
        />
      </div>
    </div>
  );
}

export default AttackPanel;
