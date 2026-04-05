import { describe, it, expect, vi } from "vitest";
import { screen } from "@solidjs/testing-library";
import { renderWithProviders } from "../../../test/render-with-providers";
import TabBar from "../TabBar";

describe("TabBar", () => {
  it("renders 6 tabs", () => {
    renderWithProviders(() => <TabBar activeTab="overview" onTabChange={() => {}} />);
    const tabs = screen.getAllByRole("tab");
    expect(tabs).toHaveLength(6);
  });

  it("marks the active tab with aria-selected", () => {
    renderWithProviders(() => <TabBar activeTab="auth" onTabChange={() => {}} />);
    const tabs = screen.getAllByRole("tab");
    const authTab = tabs.find(t => t.textContent?.includes("Auth") || t.textContent?.includes("認証"));
    expect(authTab).toBeDefined();
    expect(authTab!.getAttribute("aria-selected")).toBe("true");
  });

  it("calls onTabChange when a tab is clicked", () => {
    const handler = vi.fn();
    renderWithProviders(() => <TabBar activeTab="overview" onTabChange={handler} />);
    const tabs = screen.getAllByRole("tab");
    tabs[2].click(); // "scenario" tab (3rd)
    expect(handler).toHaveBeenCalledWith("scenario");
  });

  it("non-active tabs have aria-selected false", () => {
    renderWithProviders(() => <TabBar activeTab="overview" onTabChange={() => {}} />);
    const tabs = screen.getAllByRole("tab");
    // All except the first should have aria-selected="false"
    for (let i = 1; i < tabs.length; i++) {
      expect(tabs[i].getAttribute("aria-selected")).toBe("false");
    }
  });
});
