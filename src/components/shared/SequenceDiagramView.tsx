import { onMount, onCleanup, createEffect, createSignal, Show } from "solid-js";
import { select, type Selection } from "d3-selection";
import "d3-transition";
import { useI18n } from "../../i18n/context";
import type { RawExchange } from "../../../shared/api-types";
import "./SequenceDiagramView.css";

/**
 * Live attack シーケンス図。
 *
 * Browser → Orchestrator → Victim の 3 アクター間で交わされた
 * raw HTTP exchange を D3 SVG スイムレーンで可視化する。
 * 矢印クリックで raw bytes ポップアップを表示。
 *
 * 関連設計書: DESIGN/33 §3
 */

interface SequenceDiagramViewProps {
  /** orchestrator レスポンスの rawExchange。null/undefined の場合は空状態を表示 */
  exchange: RawExchange | null | undefined;
  scenarioId: string;
}

type ActorKey = "browser" | "orchestrator" | "victim";

interface RawArrow {
  from: ActorKey;
  to: ActorKey;
  /** 矢印ラベル (例: "POST /jwt/verify HTTP/1.1") */
  label: string;
  direction: "request" | "response";
  /** クリック popup で表示する生テキスト (request line + headers + body) */
  rawBytes: string;
  elapsedMs?: number;
}

const ACTOR_LABELS: Record<ActorKey, { ja: string; en: string }> = {
  browser: { ja: "Browser", en: "Browser" },
  orchestrator: { ja: "Orchestrator", en: "Orchestrator" },
  victim: { ja: "Victim", en: "Victim" },
};

const VIEW_WIDTH = 720;
const VIEW_HEIGHT = 360;
const ACTOR_X: Record<ActorKey, number> = {
  browser: 100,
  orchestrator: 360,
  victim: 620,
};
const HEADER_Y = 32;
const FIRST_ARROW_Y = 96;
const ARROW_GAP = 56;
const LIFELINE_BOTTOM = 320;
const ARROW_TRANSITION_MS = 400;
const ARROW_STAGGER_MS = 250;

function deriveArrows(ex: RawExchange): RawArrow[] {
  const b2o = ex.browserToOrchestrator;
  const o2v = ex.orchestratorToVictim;

  const formatHeaders = (h: Record<string, string>) =>
    Object.entries(h).map(([k, v]) => `${k}: ${v}`).join("\r\n");
  const renderRaw = (
    line: string,
    headers: Record<string, string>,
    body: string | null | undefined,
  ) => {
    const headerStr = formatHeaders(headers);
    const bodyStr = body ?? "";
    return `${line}\r\n${headerStr}\r\n\r\n${bodyStr}`;
  };

  return [
    {
      from: "browser",
      to: "orchestrator",
      label: b2o.request.line,
      direction: "request",
      rawBytes: renderRaw(b2o.request.line, b2o.request.headers, b2o.request.body),
    },
    {
      from: "orchestrator",
      to: "victim",
      label: o2v.request.line,
      direction: "request",
      rawBytes: renderRaw(o2v.request.line, o2v.request.headers, o2v.request.body),
      elapsedMs: ex.elapsedMs,
    },
    {
      from: "victim",
      to: "orchestrator",
      label: o2v.response.line,
      direction: "response",
      rawBytes: renderRaw(o2v.response.line, o2v.response.headers, o2v.response.body),
    },
    {
      from: "orchestrator",
      to: "browser",
      label: b2o.response.line,
      direction: "response",
      rawBytes: renderRaw(b2o.response.line, b2o.response.headers, b2o.response.body),
    },
  ];
}

function SequenceDiagramView(props: SequenceDiagramViewProps) {
  const { t } = useI18n();
  let svgRef: SVGSVGElement | undefined;
  const [popupArrow, setPopupArrow] = createSignal<RawArrow | null>(null);

  function initStaticLayer(svg: Selection<SVGSVGElement, unknown, null, undefined>) {
    const defs = svg.append("defs");

    for (const dir of ["request", "response"] as const) {
      const color = dir === "request"
        ? "var(--color-attack-accent)"
        : "var(--color-info, #1677ff)";
      defs
        .append("marker")
        .attr("id", `seq-arrow-${dir}`)
        .attr("viewBox", "0 -5 10 10")
        .attr("refX", 8)
        .attr("refY", 0)
        .attr("markerWidth", 6)
        .attr("markerHeight", 6)
        .attr("orient", "auto")
        .append("path")
        .attr("d", "M0,-5L10,0L0,5")
        .attr("fill", color);
    }

    const headerGroup = svg.append("g").attr("class", "seq-headers");
    const lifelineGroup = svg.append("g").attr("class", "seq-lifelines");

    (Object.keys(ACTOR_X) as ActorKey[]).forEach((actor) => {
      const x = ACTOR_X[actor];
      headerGroup
        .append("rect")
        .attr("class", "seq-actor-box")
        .attr("x", x - 70)
        .attr("y", HEADER_Y - 20)
        .attr("width", 140)
        .attr("height", 32)
        .attr("rx", 4);
      headerGroup
        .append("text")
        .attr("class", "seq-actor-label")
        .attr("x", x)
        .attr("y", HEADER_Y)
        .attr("text-anchor", "middle")
        .attr("dominant-baseline", "middle")
        .text(ACTOR_LABELS[actor].en);

      lifelineGroup
        .append("line")
        .attr("class", "seq-lifeline")
        .attr("x1", x)
        .attr("y1", HEADER_Y + 16)
        .attr("x2", x)
        .attr("y2", LIFELINE_BOTTOM);
    });

    svg.append("g").attr("class", "seq-arrows");
  }

  function drawArrows(
    svg: Selection<SVGSVGElement, unknown, null, undefined>,
    arrows: RawArrow[],
  ) {
    const arrowsGroup = svg.select<SVGGElement>("g.seq-arrows");
    arrowsGroup.selectAll("*").interrupt();
    arrowsGroup.selectAll("*").remove();

    arrows.forEach((arrow, idx) => {
      const fromX = ACTOR_X[arrow.from];
      const toX = ACTOR_X[arrow.to];
      const y = FIRST_ARROW_Y + idx * ARROW_GAP;
      const colorClass = `seq-arrow-${arrow.direction}`;

      const group = arrowsGroup
        .append("g")
        .attr("class", `seq-arrow-group ${colorClass}`)
        .style("cursor", "pointer")
        .on("click", () => setPopupArrow(arrow))
        .on("keydown", (event: KeyboardEvent) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            setPopupArrow(arrow);
          }
        });

      group.append("title").text(arrow.label);

      const labelMidX = (fromX + toX) / 2;
      group
        .append("text")
        .attr("class", "seq-arrow-label")
        .attr("x", labelMidX)
        .attr("y", y - 8)
        .attr("text-anchor", "middle")
        .text(arrow.label);

      const line = group
        .append("line")
        .attr("class", "seq-arrow-line")
        .attr("x1", fromX)
        .attr("y1", y)
        .attr("x2", fromX)
        .attr("y2", y)
        .attr("marker-end", `url(#seq-arrow-${arrow.direction})`);

      const hitbox = group
        .append("rect")
        .attr("class", "seq-arrow-hitbox")
        .attr("x", Math.min(fromX, toX))
        .attr("y", y - 14)
        .attr("width", Math.abs(toX - fromX))
        .attr("height", 28)
        .attr("fill", "transparent")
        .attr("tabindex", 0)
        .attr("role", "button")
        .attr("aria-label", arrow.label);

      // delayed reveal
      line
        .transition()
        .delay(idx * ARROW_STAGGER_MS)
        .duration(ARROW_TRANSITION_MS)
        .attr("x2", toX);

      // elapsedMs annotation (only on orchestrator→victim arrow)
      if (arrow.elapsedMs !== undefined) {
        group
          .append("text")
          .attr("class", "seq-arrow-elapsed")
          .attr("x", labelMidX)
          .attr("y", y + 16)
          .attr("text-anchor", "middle")
          .text(`${arrow.elapsedMs} ms`);
      }

      // a11y: focus highlights line
      hitbox.on("focus", () => group.classed("seq-arrow-focused", true));
      hitbox.on("blur", () => group.classed("seq-arrow-focused", false));
    });
  }

  onMount(() => {
    if (!svgRef) return;
    const svg = select(svgRef)
      .attr("viewBox", `0 0 ${VIEW_WIDTH} ${VIEW_HEIGHT}`)
      .attr("preserveAspectRatio", "xMidYMid meet");
    initStaticLayer(svg);

    const ex = props.exchange;
    if (ex) {
      drawArrows(svg, deriveArrows(ex));
    }
  });

  createEffect(() => {
    const ex = props.exchange;
    if (!svgRef) return;
    const svg = select(svgRef);
    if (!ex) {
      svg.select("g.seq-arrows").selectAll("*").interrupt();
      svg.select("g.seq-arrows").selectAll("*").remove();
      setPopupArrow(null);
      return;
    }
    drawArrows(svg, deriveArrows(ex));
  });

  onCleanup(() => {
    if (svgRef) {
      select(svgRef).selectAll("*").interrupt();
    }
  });

  return (
    <div class="sequence-diagram-view">
      <Show
        when={props.exchange}
        fallback={
          <div class="sequence-diagram-empty">
            {t(
              "live 攻撃をまだ実行していません。RawHttpComposer から送信してください。",
              "No live attack run yet. Send a request from RawHttpComposer.",
            )}
          </div>
        }
      >
        <svg
          ref={svgRef}
          class="sequence-diagram-svg"
          role="img"
          aria-label={t(
            "Browser・Orchestrator・Victim 間のシーケンス図",
            "Sequence diagram across Browser, Orchestrator, and Victim",
          )}
          data-scenario-id={props.scenarioId}
        />
        <p class="sequence-diagram-hint">
          {t(
            "矢印をクリックすると raw bytes を表示します。",
            "Click an arrow to view the raw bytes.",
          )}
        </p>
      </Show>

      <Show when={popupArrow() !== null}>
        <RawBytesPopup
          arrow={popupArrow()!}
          onClose={() => setPopupArrow(null)}
        />
      </Show>
    </div>
  );
}

function RawBytesPopup(props: { arrow: RawArrow; onClose: () => void }) {
  const { t } = useI18n();
  return (
    <div
      class="raw-bytes-popup-overlay"
      role="presentation"
      onClick={props.onClose}
    >
      <div
        class="raw-bytes-popup"
        role="dialog"
        aria-modal="true"
        aria-label={t("生バイト表示", "Raw bytes")}
        onClick={(e) => e.stopPropagation()}
      >
        <div class="raw-bytes-popup-header">
          <span class="raw-bytes-popup-title" data-direction={props.arrow.direction}>
            {props.arrow.label}
          </span>
          <button
            type="button"
            class="raw-bytes-popup-close"
            aria-label={t("閉じる", "Close")}
            onClick={props.onClose}
          >
            ×
          </button>
        </div>
        <pre class="raw-bytes-popup-body">{props.arrow.rawBytes || t("(空)", "(empty)")}</pre>
      </div>
    </div>
  );
}

export default SequenceDiagramView;
