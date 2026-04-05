import { For, Show, createSignal, createMemo } from "solid-js";
import { useI18n } from "../../i18n/context";
import { firewallFilterLayer, setFirewallFilterLayer } from "../../state/security-state";
import { DEFAULT_FW_RULES, generatePacket } from "../../data/certificate-data";
import { getLayerColor } from "../../utils/colors";
import { evaluatePacket } from "../../utils/firewall-eval";
import type { FirewallRule, SecurityPacket } from "../../types/security";
import type { LayerNumber } from "../../types";
import "./FirewallRules.css";

export default function FirewallRules() {
  const { t } = useI18n();
  const [testPacket, setTestPacket] = createSignal<SecurityPacket | null>(null);
  const [testResult, setTestResult] = createSignal<"allow" | "deny" | null>(null);

  const filteredRules = createMemo(() => {
    const fl = firewallFilterLayer();
    if (fl === null) return DEFAULT_FW_RULES;
    return DEFAULT_FW_RULES.filter(r => r.osiLayer === fl);
  });

  function simulatePacket() {
    const pkt = generatePacket();
    setTestPacket(pkt);

    setTestResult(evaluatePacket(pkt, DEFAULT_FW_RULES));

    // Clear after animation
    setTimeout(() => { setTestPacket(null); setTestResult(null); }, 3000);
  }

  return (
    <div class="firewall-rules">
      <div class="fw-header">
        <span class="fw-title mono">{t("ファイアウォールルール", "Firewall Rules")}</span>
        <button class="fw-test-btn" onClick={simulatePacket}>
          {t("テスト送信", "Test Packet")}
        </button>
      </div>

      {/* Test result */}
      <Show when={testPacket()}>
        <div class="fw-test-result" classList={{ allow: testResult() === "allow", deny: testResult() === "deny" }}>
          <span class="test-proto mono">{testPacket()!.protocol}</span>
          <span class="test-addr mono">{testPacket()!.sourceIp} → {testPacket()!.destIp}:{testPacket()!.port}</span>
          <span class="test-verdict mono">
            {testResult() === "allow" ? "✓ ALLOW" : "✕ DENY"}
          </span>
        </div>
      </Show>

      {/* Layer filter */}
      <div class="fw-filters">
        <button
          class="fw-filter"
          classList={{ active: firewallFilterLayer() === null }}
          onClick={() => setFirewallFilterLayer(null)}
        >
          {t("全層", "All")}
        </button>
        <For each={[7, 4, 3] as LayerNumber[]}>
          {(layer) => (
            <button
              class="fw-filter"
              classList={{ active: firewallFilterLayer() === layer }}
              onClick={() => setFirewallFilterLayer(prev => prev === layer ? null : layer)}
            >
              L{layer}
            </button>
          )}
        </For>
      </div>

      {/* Rules list */}
      <div class="fw-list">
        <For each={filteredRules()}>
          {(rule: FirewallRule) => {
            const color = () => getLayerColor(rule.osiLayer);
            return (
              <div
                class="fw-rule"
                classList={{ "rule-allow": rule.action === "allow", "rule-deny": rule.action === "deny" }}
              >
                <div class="rule-action-badge mono">
                  {rule.action === "allow" ? "✓" : "✕"}
                </div>
                <div class="rule-info">
                  <div class="rule-top">
                    <span class="rule-layer mono" style={{ color: color().bg }}>L{rule.osiLayer}</span>
                    <span class="rule-dir mono">{rule.direction === "inbound" ? "IN" : "OUT"}</span>
                    <span class="rule-proto mono">{rule.protocol}</span>
                    <Show when={rule.port}>
                      <span class="rule-port mono">:{rule.port}</span>
                    </Show>
                    <Show when={rule.sourceRange}>
                      <span class="rule-range mono">{rule.sourceRange}</span>
                    </Show>
                  </div>
                  <div class="rule-desc">{t(rule.descriptionJa, rule.description)}</div>
                </div>
              </div>
            );
          }}
        </For>
      </div>
    </div>
  );
}
