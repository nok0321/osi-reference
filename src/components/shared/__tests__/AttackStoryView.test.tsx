import { describe, it, expect } from "vitest";
import { screen, fireEvent } from "@solidjs/testing-library";
import { renderWithProviders } from "../../../test/render-with-providers";
import AttackStoryView from "../AttackStoryView";
import type { AttackStoryScene } from "../../../../shared/api-types";

const SAMPLE_STORY: AttackStoryScene[] = [
  {
    id: "s1",
    title: "First scene",
    titleJa: "シーン 1",
    actor: "attacker",
    speech: { ja: "攻撃開始", en: "Starting the attack" },
  },
  {
    id: "s2",
    title: "Second scene",
    titleJa: "シーン 2",
    actor: "victim",
    speech: { ja: "気づかなかった", en: "Did not notice" },
  },
  {
    id: "s3",
    title: "Final scene",
    titleJa: "シーン 3",
    actor: "narrator",
    narration: { ja: "防御策はこちら", en: "Defense steps below" },
  },
];

describe("AttackStoryView", () => {
  it("renders empty fallback when story is empty", () => {
    renderWithProviders(() => <AttackStoryView story={[]} />);
    expect(screen.getByText("ストーリーが定義されていません")).toBeTruthy();
  });

  it("renders the first scene by default", () => {
    renderWithProviders(() => <AttackStoryView story={SAMPLE_STORY} />);
    expect(screen.getByText("シーン 1")).toBeTruthy();
    expect(screen.getByText("攻撃開始")).toBeTruthy();
  });

  it("disables prev button at first scene", () => {
    renderWithProviders(() => <AttackStoryView story={SAMPLE_STORY} />);
    const prev = screen.getByLabelText("前のシーン") as HTMLButtonElement;
    expect(prev.disabled).toBe(true);
  });

  it("advances scene when next button clicked", () => {
    renderWithProviders(() => <AttackStoryView story={SAMPLE_STORY} />);
    const next = screen.getByLabelText("次のシーン");
    fireEvent.click(next);
    expect(screen.getByText("シーン 2")).toBeTruthy();
    expect(screen.getByText("気づかなかった")).toBeTruthy();
  });

  it("disables next button at last scene", () => {
    renderWithProviders(() => <AttackStoryView story={SAMPLE_STORY} />);
    const next = screen.getByLabelText("次のシーン");
    fireEvent.click(next);
    fireEvent.click(next);
    expect(screen.getByText("シーン 3")).toBeTruthy();
    const nextBtn = screen.getByLabelText("次のシーン") as HTMLButtonElement;
    expect(nextBtn.disabled).toBe(true);
  });

  it("dot click jumps to specific scene", () => {
    renderWithProviders(() => <AttackStoryView story={SAMPLE_STORY} />);
    const dots = screen.getAllByRole("tab");
    expect(dots.length).toBe(3);
    fireEvent.click(dots[2]);
    expect(screen.getByText("シーン 3")).toBeTruthy();
  });

  it("toggles autoplay button label between start/pause", () => {
    renderWithProviders(() => <AttackStoryView story={SAMPLE_STORY} />);
    const toggle = screen.getByLabelText("自動再生を開始");
    fireEvent.click(toggle);
    expect(screen.getByLabelText("自動再生を停止")).toBeTruthy();
  });

  it("region has correct role and aria-label", () => {
    renderWithProviders(() => <AttackStoryView story={SAMPLE_STORY} />);
    const region = screen.getByRole("region");
    expect(region.getAttribute("aria-label")).toBe("攻撃ストーリーボード");
  });

  it("ArrowRight key advances scene", () => {
    renderWithProviders(() => <AttackStoryView story={SAMPLE_STORY} />);
    const region = screen.getByRole("region");
    fireEvent.keyDown(region, { key: "ArrowRight" });
    expect(screen.getByText("シーン 2")).toBeTruthy();
  });

  it("End key jumps to the last scene", () => {
    renderWithProviders(() => <AttackStoryView story={SAMPLE_STORY} />);
    const region = screen.getByRole("region");
    fireEvent.keyDown(region, { key: "End" });
    expect(screen.getByText("シーン 3")).toBeTruthy();
  });

  it("Home key returns to first scene", () => {
    renderWithProviders(() => <AttackStoryView story={SAMPLE_STORY} />);
    const region = screen.getByRole("region");
    fireEvent.keyDown(region, { key: "End" });
    fireEvent.keyDown(region, { key: "Home" });
    expect(screen.getByText("シーン 1")).toBeTruthy();
  });

  it("renders position indicator", () => {
    renderWithProviders(() => <AttackStoryView story={SAMPLE_STORY} />);
    expect(screen.getByText("シーン 1 / 3")).toBeTruthy();
  });
});
