import { createSignal, For, Show } from "solid-js";
import { useI18n } from "../../i18n/context";
import { QUIZ_QUESTIONS } from "../../data/quiz-questions";
import type { QuizQuestion } from "../../data/quiz-questions";
import "./QuizPanel.css";

export default function QuizPanel() {
  const { t } = useI18n();
  const [currentIndex, setCurrentIndex] = createSignal(0);
  const [selectedAnswer, setSelectedAnswer] = createSignal<number | null>(null);
  const [showResult, setShowResult] = createSignal(false);
  const [score, setScore] = createSignal(0);
  const [finished, setFinished] = createSignal(false);
  const [isOpen, setIsOpen] = createSignal(false);

  const questions = QUIZ_QUESTIONS;
  const current = () => questions[currentIndex()];

  function submitAnswer() {
    if (selectedAnswer() === null) return;
    setShowResult(true);
    if (selectedAnswer() === current().correctIndex) {
      setScore(prev => prev + 1);
    }
  }

  function nextQuestion() {
    if (currentIndex() < questions.length - 1) {
      setCurrentIndex(prev => prev + 1);
      setSelectedAnswer(null);
      setShowResult(false);
    } else {
      setFinished(true);
    }
  }

  function restart() {
    setCurrentIndex(0);
    setSelectedAnswer(null);
    setShowResult(false);
    setScore(0);
    setFinished(false);
  }

  return (
    <div class="quiz-panel">
      <button class="quiz-toggle" onClick={() => setIsOpen(prev => !prev)} aria-label={t("クイズ", "Quiz")}>
        {t("クイズ", "Quiz")} {isOpen() ? "\u25B2" : "\u25BC"}
      </button>

      <Show when={isOpen()}>
        <div class="quiz-content">
          <Show when={!finished()} fallback={
            <div class="quiz-finished">
              <span class="quiz-score mono">{score()} / {questions.length}</span>
              <p>{t(
                `${questions.length}問中${score()}問正解です！`,
                `You got ${score()} out of ${questions.length} correct!`
              )}</p>
              <button class="quiz-btn" onClick={restart}>{t("もう一度", "Try Again")}</button>
            </div>
          }>
            <div class="quiz-progress mono">
              {currentIndex() + 1} / {questions.length}
            </div>
            <p class="quiz-question">{t(current().questionJa, current().question)}</p>
            <div class="quiz-options">
              <For each={current().options}>
                {(option, i) => (
                  <button
                    class="quiz-option"
                    classList={{
                      selected: selectedAnswer() === i(),
                      correct: showResult() && i() === current().correctIndex,
                      wrong: showResult() && selectedAnswer() === i() && i() !== current().correctIndex,
                    }}
                    onClick={() => { if (!showResult()) setSelectedAnswer(i()); }}
                    disabled={showResult()}
                  >
                    <span class="option-letter mono">{String.fromCharCode(65 + i())}</span>
                    {t(option.textJa, option.text)}
                  </button>
                )}
              </For>
            </div>

            <Show when={showResult()}>
              <div class="quiz-explanation" classList={{ correct: selectedAnswer() === current().correctIndex }}>
                <span class="explanation-icon">
                  {selectedAnswer() === current().correctIndex ? "\u2713" : "\u2717"}
                </span>
                <p>{t(current().explanationJa, current().explanation)}</p>
              </div>
            </Show>

            <div class="quiz-actions">
              <Show when={!showResult()}>
                <button class="quiz-btn" onClick={submitAnswer} disabled={selectedAnswer() === null}>
                  {t("回答", "Submit")}
                </button>
              </Show>
              <Show when={showResult()}>
                <button class="quiz-btn" onClick={nextQuestion}>
                  {currentIndex() < questions.length - 1 ? t("次の問題", "Next") : t("結果を見る", "See Results")}
                </button>
              </Show>
            </div>
          </Show>
        </div>
      </Show>
    </div>
  );
}
