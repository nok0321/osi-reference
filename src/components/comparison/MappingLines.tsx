import { onMount, onCleanup, createEffect } from "solid-js";
import { hoveredMapping } from "../../state/app-state";
import { getLayerColor } from "../../utils/colors";
import type { TcpIpMapping, LayerNumber } from "../../types";
import "./MappingLines.css";

interface MappingLinesProps {
  mappings: TcpIpMapping[];
}

export default function MappingLines(props: MappingLinesProps) {
  let svgRef: SVGSVGElement | undefined;

  function draw() {
    if (!svgRef) return;

    const parent = svgRef.parentElement;
    if (!parent) return;

    const parentRect = parent.getBoundingClientRect();
    svgRef.setAttribute("width", String(parentRect.width));
    svgRef.setAttribute("height", String(parentRect.height));

    // Clear existing
    while (svgRef.firstChild) {
      svgRef.removeChild(svgRef.firstChild);
    }

    const hovered = hoveredMapping();

    props.mappings.forEach((mapping, tcpIdx) => {
      const tcpEl = parent.querySelector(`[data-tcpip="${tcpIdx}"]`);
      if (!tcpEl) return;

      mapping.osiLayers.forEach((layerNum: LayerNumber) => {
        const osiEl = parent.querySelector(`[data-layer="${layerNum}"]`);
        if (!osiEl) return;

        const osiRect = osiEl.getBoundingClientRect();
        const tcpRect = tcpEl.getBoundingClientRect();

        const x1 = osiRect.right - parentRect.left;
        const y1 = osiRect.top + osiRect.height / 2 - parentRect.top;
        const x2 = tcpRect.left - parentRect.left;
        const y2 = tcpRect.top + tcpRect.height / 2 - parentRect.top;

        const isHighlighted = hovered !== null && mapping.osiLayers.includes(hovered);
        const color = getLayerColor(layerNum).bg;

        const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
        const cx = (x1 + x2) / 2;
        path.setAttribute("d", `M ${x1} ${y1} C ${cx} ${y1}, ${cx} ${y2}, ${x2} ${y2}`);
        path.setAttribute("stroke", color);
        path.setAttribute("stroke-width", isHighlighted ? "2.5" : "1");
        path.setAttribute("fill", "none");
        path.setAttribute("opacity", isHighlighted ? "0.9" : hovered !== null ? "0.1" : "0.3");
        path.setAttribute("class", "mapping-path");

        svgRef!.appendChild(path);
      });
    });
  }

  onMount(() => {
    // Delay to allow DOM to render
    requestAnimationFrame(() => {
      draw();
    });
    window.addEventListener("resize", draw);
  });

  onCleanup(() => {
    window.removeEventListener("resize", draw);
  });

  createEffect(() => {
    hoveredMapping(); // track
    requestAnimationFrame(draw);
  });

  return <svg ref={svgRef} class="mapping-lines-svg" />;
}
