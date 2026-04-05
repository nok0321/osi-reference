import { onMount, onCleanup, createEffect } from "solid-js";
import * as d3 from "d3";
import { OSI_LAYERS } from "../../data/layers";
import { LAYER_COLORS } from "../../utils/colors";
import { useI18n } from "../../i18n/context";
import type { LayerNumber } from "../../types";
import "./LayerDiagram.css";

interface LayerDiagramProps {
  selectedLayer: LayerNumber | null;
  onLayerClick: (layer: LayerNumber) => void;
  onLayerHover: (layer: LayerNumber | null) => void;
}

export default function LayerDiagram(props: LayerDiagramProps) {
  let svgRef!: SVGSVGElement;
  const { t } = useI18n();

  const MARGIN = { top: 20, right: 20, bottom: 20, left: 20 };
  const WIDTH = 420;
  const HEIGHT = 520;
  const LAYER_HEIGHT = 60;
  const LAYER_GAP = 6;

  onMount(() => {
    const svg = d3.select(svgRef)
      .attr("viewBox", `0 0 ${WIDTH} ${HEIGHT}`)
      .attr("preserveAspectRatio", "xMidYMid meet");

    // Glow filter
    const defs = svg.append("defs");
    const filter = defs.append("filter").attr("id", "glow");
    filter.append("feGaussianBlur").attr("stdDeviation", "4").attr("result", "coloredBlur");
    const feMerge = filter.append("feMerge");
    feMerge.append("feMergeNode").attr("in", "coloredBlur");
    feMerge.append("feMergeNode").attr("in", "SourceGraphic");

    // Circuit trace decoration lines
    const traceGroup = svg.append("g").attr("class", "traces");
    for (let i = 0; i < 6; i++) {
      const y = MARGIN.top + (i + 1) * (LAYER_HEIGHT + LAYER_GAP) - LAYER_GAP / 2;
      traceGroup.append("line")
        .attr("x1", MARGIN.left + 10)
        .attr("y1", y)
        .attr("x2", MARGIN.left + 20)
        .attr("y2", y)
        .attr("stroke", "var(--trace-color)")
        .attr("stroke-width", 1)
        .attr("opacity", 0.3);
    }

    // Layer groups
    const layerGroups = svg.selectAll(".layer-group")
      .data(OSI_LAYERS)
      .enter()
      .append("g")
      .attr("class", "layer-group")
      .attr("transform", (_d, i) => {
        const y = MARGIN.top + i * (LAYER_HEIGHT + LAYER_GAP);
        return `translate(${MARGIN.left}, ${y})`;
      })
      .style("cursor", "pointer")
      .on("click", (_event, d) => props.onLayerClick(d.number))
      .on("mouseenter", (_event, d) => props.onLayerHover(d.number))
      .on("mouseleave", () => props.onLayerHover(null));

    const rectWidth = WIDTH - MARGIN.left - MARGIN.right;

    // Background rect
    layerGroups.append("rect")
      .attr("class", "layer-bg")
      .attr("width", rectWidth)
      .attr("height", LAYER_HEIGHT)
      .attr("rx", 6)
      .attr("fill", d => `${LAYER_COLORS[d.number].bg}22`)
      .attr("stroke", d => `${LAYER_COLORS[d.number].bg}55`)
      .attr("stroke-width", 1.5);

    // Left color accent bar
    layerGroups.append("rect")
      .attr("width", 5)
      .attr("height", LAYER_HEIGHT)
      .attr("rx", 2)
      .attr("fill", d => LAYER_COLORS[d.number].bg);

    // Layer number
    layerGroups.append("text")
      .attr("x", 22)
      .attr("y", LAYER_HEIGHT / 2)
      .attr("dy", "0.35em")
      .attr("font-family", "var(--font-mono)")
      .attr("font-size", "14px")
      .attr("font-weight", "700")
      .attr("fill", d => LAYER_COLORS[d.number].bg)
      .text(d => `L${d.number}`);

    // Layer name
    layerGroups.append("text")
      .attr("class", "layer-name-text")
      .attr("x", 62)
      .attr("y", LAYER_HEIGHT / 2 - 8)
      .attr("font-family", "var(--font-body)")
      .attr("font-size", "14px")
      .attr("font-weight", "600")
      .attr("fill", "var(--text-primary)")
      .text(d => d.name);

    // Layer name (Japanese)
    layerGroups.append("text")
      .attr("class", "layer-name-ja-text")
      .attr("x", 62)
      .attr("y", LAYER_HEIGHT / 2 + 12)
      .attr("font-family", "var(--font-body)")
      .attr("font-size", "11px")
      .attr("fill", "var(--text-secondary)")
      .text(d => d.nameJa);

    // PDU label
    layerGroups.append("text")
      .attr("x", rectWidth - 10)
      .attr("y", LAYER_HEIGHT / 2)
      .attr("dy", "0.35em")
      .attr("text-anchor", "end")
      .attr("font-family", "var(--font-mono)")
      .attr("font-size", "10px")
      .attr("fill", "var(--text-muted)")
      .text(d => d.pdu);

    // Selection effect
    createEffect(() => {
      const selected = props.selectedLayer;
      svg.selectAll<SVGGElement, typeof OSI_LAYERS[0]>(".layer-group")
        .select(".layer-bg")
        .transition()
        .duration(200)
        .attr("fill", d =>
          d.number === selected
            ? `${LAYER_COLORS[d.number].bg}44`
            : `${LAYER_COLORS[d.number].bg}22`
        )
        .attr("stroke", d =>
          d.number === selected
            ? LAYER_COLORS[d.number].bg
            : `${LAYER_COLORS[d.number].bg}55`
        )
        .attr("stroke-width", d => d.number === selected ? 2.5 : 1.5)
        .attr("filter", d => d.number === selected ? "url(#glow)" : "none");
    });
  });

  onCleanup(() => {
    d3.select(svgRef).selectAll("*").interrupt();
  });

  return (
    <div class="layer-diagram">
      <svg ref={svgRef!} class="diagram-svg" />
    </div>
  );
}
