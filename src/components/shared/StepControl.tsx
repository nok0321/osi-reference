import { useI18n } from "../../i18n/context";
import "./StepControl.css";

interface StepControlProps {
  current: number;
  total: number;
  onPrev: () => void;
  onNext: () => void;
  label?: string;
}

export default function StepControl(props: StepControlProps) {
  const { t } = useI18n();

  return (
    <div class="step-control">
      <button
        class="step-btn"
        onClick={() => props.onPrev()}
        disabled={props.current <= 0}
        aria-label={t("前へ", "Previous")}
      >
        ◁
      </button>
      <div class="step-indicator">
        <span class="step-label">{props.label ?? t("ステップ", "Step")}</span>
        <span class="step-count mono">
          {props.current + 1} / {props.total}
        </span>
      </div>
      <button
        class="step-btn"
        onClick={() => props.onNext()}
        disabled={props.current >= props.total - 1}
        aria-label={t("次へ", "Next")}
      >
        ▷
      </button>
    </div>
  );
}
