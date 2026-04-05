import { For, Show, createSignal, createEffect, onCleanup, createMemo } from "solid-js";
import { useI18n } from "../../i18n/context";
import { packetFlowRunning, setPacketFlowRunning } from "../../state/security-state";
import { generatePacket } from "../../data/certificate-data";
import type { SecurityPacket } from "../../types/security";
import type { LayerNumber } from "../../types";
import "./PacketMonitor.css";

const MAX_PACKETS = 100;

export default function PacketMonitor() {
  const { t } = useI18n();
  const [packets, setPackets] = createSignal<SecurityPacket[]>([]);
  const [filterLayer, setFilterLayer] = createSignal<LayerNumber | null>(null);
  const [filterStatus, setFilterStatus] = createSignal<SecurityPacket["status"] | null>(null);
  let intervalId: number | undefined;

  function startFlow() {
    setPacketFlowRunning(true);
  }

  function stopFlow() {
    setPacketFlowRunning(false);
  }

  function clearPackets() {
    setPackets([]);
  }

  createEffect(() => {
    if (packetFlowRunning()) {
      intervalId = window.setInterval(() => {
        setPackets(prev => {
          const newPkt = generatePacket();
          const updated = [newPkt, ...prev];
          return updated.length > MAX_PACKETS ? updated.slice(0, MAX_PACKETS) : updated;
        });
      }, 500);
    } else {
      if (intervalId !== undefined) {
        clearInterval(intervalId);
        intervalId = undefined;
      }
    }
  });

  onCleanup(() => {
    if (intervalId !== undefined) clearInterval(intervalId);
  });

  const filteredPackets = createMemo(() => {
    let result = packets();
    const fl = filterLayer();
    const fs = filterStatus();
    if (fl !== null) result = result.filter(p => p.osiLayer === fl);
    if (fs !== null) result = result.filter(p => p.status === fs);
    return result;
  });

  const stats = createMemo(() => {
    return packets().reduce(
      (acc, p) => { acc[p.status]++; acc.total++; return acc; },
      { total: 0, safe: 0, warning: 0, threat: 0 },
    );
  });

  return (
    <div class="packet-monitor">
      <div class="pm-header">
        <span class="pm-title mono">{t("パケットモニター", "Packet Monitor")}</span>
        <div class="pm-controls">
          <button
            class="pm-btn"
            classList={{ active: packetFlowRunning() }}
            onClick={() => packetFlowRunning() ? stopFlow() : startFlow()}
            aria-label={packetFlowRunning() ? t("一時停止", "Pause") : t("再生", "Play")}
          >
            {packetFlowRunning() ? "⏸" : "▶"}
          </button>
          <button class="pm-btn" onClick={clearPackets} aria-label={t("クリア", "Clear packets")}>✕</button>
        </div>
      </div>

      {/* Stats bar */}
      <div class="pm-stats">
        <span class="stat total">{stats().total}</span>
        <span class="stat safe" onClick={() => setFilterStatus(prev => prev === "safe" ? null : "safe")}>
          ● {stats().safe}
        </span>
        <span class="stat warning" onClick={() => setFilterStatus(prev => prev === "warning" ? null : "warning")}>
          ● {stats().warning}
        </span>
        <span class="stat threat" onClick={() => setFilterStatus(prev => prev === "threat" ? null : "threat")}>
          ● {stats().threat}
        </span>
      </div>

      {/* Filter */}
      <div class="pm-filters">
        <button
          class="filter-btn"
          classList={{ active: filterLayer() === null }}
          onClick={() => setFilterLayer(null)}
        >
          {t("全層", "All")}
        </button>
        <For each={[7, 6, 4, 3] as LayerNumber[]}>
          {(layer) => (
            <button
              class="filter-btn"
              classList={{ active: filterLayer() === layer }}
              onClick={() => setFilterLayer(prev => prev === layer ? null : layer)}
            >
              L{layer}
            </button>
          )}
        </For>
      </div>

      {/* Packet list */}
      <div class="pm-list">
        <Show when={filteredPackets().length === 0}>
          <div class="pm-empty mono">
            {packetFlowRunning()
              ? t("パケット待機中...", "Waiting for packets...")
              : t("▶ で開始", "Press ▶ to start")}
          </div>
        </Show>
        <For each={filteredPackets().slice(0, 30)}>
          {(pkt: SecurityPacket) => (
            <div class="pkt-row" classList={{ [pkt.status]: true }}>
              <span class="pkt-status-dot" />
              <span class="pkt-proto mono">{pkt.protocol}</span>
              <span class="pkt-addr mono">{pkt.sourceIp}</span>
              <span class="pkt-arrow">→</span>
              <span class="pkt-addr mono">{pkt.destIp}:{pkt.port}</span>
              <span class="pkt-layer mono">L{pkt.osiLayer}</span>
              <Show when={pkt.encrypted}>
                <span class="pkt-encrypted">🔒</span>
              </Show>
            </div>
          )}
        </For>
      </div>
    </div>
  );
}
