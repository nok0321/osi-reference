import { For, Show, createSignal, createMemo } from "solid-js";
import { useI18n } from "../../i18n/context";
import { selectedAttackLayer, setSelectedAttackLayer } from "../../state/security-state";
import { OSI_ATTACKS, SEVERITY_COLORS } from "../../data/security-attacks";
import { getLayerColor } from "../../utils/colors";
import type { OsiAttack } from "../../types/security";
import type { LayerNumber } from "../../types";
import "./AttackMap.css";

export default function AttackMap() {
  const { t } = useI18n();
  const [expandedAttack, setExpandedAttack] = createSignal<string | null>(null);
  const [simulating, setSimulating] = createSignal(false);
  const [simAttack, setSimAttack] = createSignal<OsiAttack | null>(null);

  const layers: LayerNumber[] = [7, 6, 5, 4, 3, 2, 1];

  const attacksByLayer = createMemo(() => {
    const map = new Map<LayerNumber, OsiAttack[]>();
    for (const layer of layers) {
      map.set(layer, OSI_ATTACKS.filter(a => a.layer === layer));
    }
    return map;
  });

  const filteredAttacks = createMemo(() => {
    const sel = selectedAttackLayer();
    if (sel === null) return OSI_ATTACKS;
    return OSI_ATTACKS.filter(a => a.layer === sel);
  });

  function simulateAttack(attack: OsiAttack) {
    setSimAttack(attack);
    setSimulating(true);
    setTimeout(() => { setSimulating(false); setSimAttack(null); }, 3000);
  }

  return (
    <div class="attack-map">
      <div class="am-header">
        <span class="am-title mono">{t("攻撃マップ", "Attack Map")}</span>
        <span class="am-count mono">{filteredAttacks().length} {t("脅威", "threats")}</span>
      </div>

      {/* Layer selector with attack count badges */}
      <div class="am-layers">
        <button
          class="am-layer-btn"
          classList={{ active: selectedAttackLayer() === null }}
          onClick={() => setSelectedAttackLayer(null)}
        >
          {t("全層", "All")}
        </button>
        <For each={layers}>
          {(layer) => {
            const count = () => attacksByLayer().get(layer)?.length ?? 0;
            const color = () => getLayerColor(layer);
            return (
              <Show when={count() > 0}>
                <button
                  class="am-layer-btn"
                  classList={{ active: selectedAttackLayer() === layer }}
                  style={{ "--lb-color": color().bg }}
                  onClick={() => setSelectedAttackLayer(prev => prev === layer ? null : layer)}
                >
                  <span>L{layer}</span>
                  <span class="layer-attack-count">{count()}</span>
                </button>
              </Show>
            );
          }}
        </For>
      </div>

      {/* Simulation alert */}
      <Show when={simulating() && simAttack()}>
        <div class="sim-alert" style={{ "--sim-color": SEVERITY_COLORS[simAttack()!.severity] }}>
          <span class="sim-icon">⚠</span>
          <span class="sim-text">
            {t("シミュレーション: ", "Simulating: ")}{t(simAttack()!.nameJa, simAttack()!.name)}
          </span>
          <span class="sim-layer mono">L{simAttack()!.layer}</span>
        </div>
      </Show>

      {/* Attack list */}
      <div class="am-list">
        <For each={filteredAttacks()}>
          {(attack: OsiAttack) => {
            const isExpanded = () => expandedAttack() === attack.name;
            const sevColor = () => SEVERITY_COLORS[attack.severity];
            const layerColor = () => getLayerColor(attack.layer);

            return (
              <div
                class="attack-card"
                classList={{ expanded: isExpanded() }}
                tabindex="0"
                onClick={() => setExpandedAttack(prev => prev === attack.name ? null : attack.name)}
                onKeyDown={(e: KeyboardEvent) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setExpandedAttack(prev => prev === attack.name ? null : attack.name); } }}
              >
                <div class="attack-top">
                  <span class="attack-sev" style={{ background: sevColor() }}>{attack.severity[0].toUpperCase()}</span>
                  <span class="attack-layer mono" style={{ color: layerColor().bg }}>L{attack.layer}</span>
                  <span class="attack-name">{t(attack.nameJa, attack.name)}</span>
                  <span class="attack-cat">{t(attack.categoryJa, attack.category)}</span>
                </div>

                <Show when={isExpanded()}>
                  <div class="attack-detail">
                    <p class="ad-desc">{t(attack.descriptionJa, attack.description)}</p>
                    <div class="ad-mitigation">
                      <span class="ad-label mono">{t("緩和策", "Mitigation")}</span>
                      <p class="ad-text">{t(attack.mitigationJa, attack.mitigation)}</p>
                    </div>
                    <button
                      class="ad-sim-btn"
                      onClick={(e) => { e.stopPropagation(); simulateAttack(attack); }}
                    >
                      {t("シミュレーション", "Simulate")}
                    </button>
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
