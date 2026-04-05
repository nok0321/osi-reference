import { describe, it, expect, vi } from "vitest";
import { screen } from "@solidjs/testing-library";
import { renderWithProviders } from "../../../test/render-with-providers";
import StepControl from "../StepControl";

describe("StepControl", () => {
  it("renders step count correctly", () => {
    renderWithProviders(() => (
      <StepControl current={2} total={5} onPrev={() => {}} onNext={() => {}} />
    ));
    expect(screen.getByText("3 / 5")).toBeTruthy();
  });

  it("previous button is disabled at step 0", () => {
    renderWithProviders(() => (
      <StepControl current={0} total={5} onPrev={() => {}} onNext={() => {}} />
    ));
    const prevBtn = screen.getByLabelText("前へ");
    expect(prevBtn).toBeDisabled();
  });

  it("next button is disabled at last step", () => {
    renderWithProviders(() => (
      <StepControl current={4} total={5} onPrev={() => {}} onNext={() => {}} />
    ));
    const nextBtn = screen.getByLabelText("次へ");
    expect(nextBtn).toBeDisabled();
  });

  it("calls onPrev and onNext handlers", () => {
    const onPrev = vi.fn();
    const onNext = vi.fn();
    renderWithProviders(() => (
      <StepControl current={2} total={5} onPrev={onPrev} onNext={onNext} />
    ));
    screen.getByLabelText("前へ").click();
    expect(onPrev).toHaveBeenCalledOnce();
    screen.getByLabelText("次へ").click();
    expect(onNext).toHaveBeenCalledOnce();
  });

  it("has aria-labels on buttons", () => {
    renderWithProviders(() => (
      <StepControl current={1} total={3} onPrev={() => {}} onNext={() => {}} />
    ));
    expect(screen.getByLabelText("前へ")).toBeTruthy();
    expect(screen.getByLabelText("次へ")).toBeTruthy();
  });
});
