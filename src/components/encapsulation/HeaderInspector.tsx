import type { EncapStep } from "../../types";
import { HeaderInspectorPanel } from "../shared/HeaderBlock";

interface HeaderInspectorProps {
  step: EncapStep;
}

export default function HeaderInspector(props: HeaderInspectorProps) {
  return <HeaderInspectorPanel step={props.step} />;
}
