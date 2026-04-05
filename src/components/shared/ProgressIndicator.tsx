import { createSignal, onMount } from "solid-js";
import { getProgress } from "../../utils/progress";
import type { ViewType } from "../../types";
import "./ProgressIndicator.css";

interface ProgressIndicatorProps {
  view: ViewType;
}

const SECTION_COUNTS: Record<ViewType, number> = {
  overview: 7,       // 7 OSI layers
  encapsulation: 5,  // 5 encap steps
  scenario: 4,       // 4 scenarios
  comparison: 1,     // 1 view
  auth: 10,          // 10 subtabs
  security: 4,       // 4 dashboard panels
};

export default function ProgressIndicator(props: ProgressIndicatorProps) {
  const [visited, setVisited] = createSignal(false);
  const [sectionCount, setSectionCount] = createSignal(0);

  function refresh() {
    const data = getProgress();
    const vp = data[props.view];
    setVisited(vp.visited);
    setSectionCount(vp.sections.length);
  }

  onMount(refresh);

  // Poll on a reasonable interval to update UI when progress changes
  // (since localStorage changes don't trigger signals)
  onMount(() => {
    const id = setInterval(refresh, 2000);
    return () => clearInterval(id);
  });

  const total = () => SECTION_COUNTS[props.view];
  const percent = () => total() > 0 ? Math.round((sectionCount() / total()) * 100) : 0;

  return (
    <span class="progress-indicator" classList={{ visited: visited(), complete: percent() >= 100 }}>
      {visited() ? (percent() >= 100 ? "\u2713" : `${percent()}%`) : ""}
    </span>
  );
}
