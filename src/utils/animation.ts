import type { Selection, BaseType } from "d3-selection";
import "d3-transition";

/** Animate an SVG path drawing like a circuit trace */
export function traceDrawEffect(
  path: Selection<SVGPathElement, unknown, BaseType, unknown>,
  duration: number = 800
): void {
  const node = path.node();
  if (!node) return;
  const length = node.getTotalLength();
  path
    .attr("stroke-dasharray", `${length} ${length}`)
    .attr("stroke-dashoffset", length)
    .transition()
    .duration(duration)
    .attr("stroke-dashoffset", 0);
}

/** Pulse glow effect on an element */
export function glowPulse(
  el: Selection<BaseType, unknown, BaseType, unknown>,
  color: string = "var(--glow-color)",
  duration: number = 1500
): void {
  el.style("filter", `drop-shadow(0 0 4px ${color})`)
    .transition()
    .duration(duration / 2)
    .style("filter", `drop-shadow(0 0 12px ${color})`)
    .transition()
    .duration(duration / 2)
    .style("filter", `drop-shadow(0 0 4px ${color})`);
}

/** Move an element along an SVG path */
export function moveAlongPath(
  dot: Selection<BaseType, unknown, BaseType, unknown>,
  path: SVGPathElement,
  duration: number = 2000,
  onEnd?: () => void
): void {
  const length = path.getTotalLength();
  dot
    .transition()
    .duration(duration)
    .attrTween("transform", () => {
      return (t: number) => {
        const p = path.getPointAtLength(t * length);
        return `translate(${p.x},${p.y})`;
      };
    })
    .on("end", () => onEnd?.());
}
