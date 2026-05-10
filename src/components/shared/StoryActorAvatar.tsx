/**
 * StoryActorAvatar (DESIGN/35 §9) — 攻撃ストーリーボードのキャラクター描画。
 *
 * 例外規約: emoji 使用は本コンポーネントに限定 (DESIGN/35 §9.5)。
 * 他の Attack* コンポーネントへの絵文字波及は禁止。
 *
 * Phase 1: emoji 直接描画。将来 SVG 化する場合は本ファイル内で switch するだけで済む
 * (シナリオデータは無変更で差し替え可能)。
 */
import { useI18n } from "../../i18n/context";
import type { AttackStoryActor } from "../../../shared/api-types";

interface StoryActorAvatarProps {
  actor: AttackStoryActor;
  active?: boolean;
}

const ACTOR_EMOJI: Record<AttackStoryActor, string> = {
  attacker: "\u{1F608}",     // 😈
  victim: "\u{1F464}",        // 👤
  server: "\u{1F5A5}\u{FE0F}", // 🖥️
  "victim-srv": "\u{1F513}", // 🔓
  narrator: "\u{1F4E2}",      // 📢
  system: "\u{1F310}",        // 🌐
};

const ACTOR_LABEL_JA: Record<AttackStoryActor, string> = {
  attacker: "攻撃者",
  victim: "被害者",
  server: "サーバ",
  "victim-srv": "脆弱 victim",
  narrator: "解説",
  system: "ネットワーク",
};

const ACTOR_LABEL_EN: Record<AttackStoryActor, string> = {
  attacker: "Attacker",
  victim: "Victim",
  server: "Server",
  "victim-srv": "Vulnerable victim",
  narrator: "Narrator",
  system: "Network",
};

export default function StoryActorAvatar(props: StoryActorAvatarProps) {
  const { t } = useI18n();
  const label = () => t(ACTOR_LABEL_JA[props.actor], ACTOR_LABEL_EN[props.actor]);

  return (
    <div
      class="story-actor-avatar"
      data-actor={props.actor}
      data-active={props.active ? "true" : "false"}
      aria-label={label()}
    >
      <span class="story-actor-emoji" aria-hidden="true">
        {ACTOR_EMOJI[props.actor]}
      </span>
      <span class="story-actor-name">{label()}</span>
    </div>
  );
}
