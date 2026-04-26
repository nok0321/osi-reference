import { createSignal, createEffect, Show, For } from "solid-js";
import { useI18n } from "../../i18n/context";
import type { AttackScenarioMeta, AttackResult } from "../../../shared/api-types";
import type { AuthSubView } from "../../types/security";
import EducationalWarningBanner from "./EducationalWarningBanner";
import AttackScenarioSelector from "./AttackScenarioSelector";
import AttackStepTimeline from "./AttackStepTimeline";
import AttackResultBanner from "./AttackResultBanner";
import AttackDefensePanel from "./AttackDefensePanel";
import DataFlowPanel from "./DataFlowPanel";
import "./AttackPanel.css";

interface AttackPanelProps {
  tabId: AuthSubView;
  scenarios: AttackScenarioMeta[];
  /**
   * E-2: 攻撃ルートは 1 リクエストで両モード (脆弱+堅牢) を必ず並列実行する。
   * 排他選択モードは廃止されたため、modeBody 引数は不要。
   */
  onRunScenario: (scenario: AttackScenarioMeta) => Promise<AttackResult>;
}

function AttackPanel(props: AttackPanelProps) {
  const { t } = useI18n();

  const [selectedId, setSelectedId] = createSignal<string>(
    props.scenarios[0]?.id ?? ""
  );
  const [attackResult, setAttackResult] = createSignal<AttackResult | null>(null);
  const [running, setRunning] = createSignal(false);
  const [defenseOpen, setDefenseOpen] = createSignal(false);

  const selectedScenario = () =>
    props.scenarios.find((s) => s.id === selectedId()) ?? props.scenarios[0] ?? null;

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

  async function handleRunAttack() {
    const scenario = selectedScenario();
    if (!scenario || running()) return;
    setRunning(true);
    setAttackResult(null);
    setDefenseOpen(false);
    try {
      const result = await props.onRunScenario(scenario);
      setAttackResult(result);
    } finally {
      setRunning(false);
    }
  }

  return (
    <div class="attack-panel">
      {/* 1. 教育用バナー (常時表示) */}
      <EducationalWarningBanner />

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

        {/* 4. 実行ボタン */}
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

        {/* 8. DataFlowPanel */}
        <DataFlowPanel scopeId={`attack-${props.tabId}`} defaultOpen={false} />
      </div>
    </div>
  );
}

export default AttackPanel;
