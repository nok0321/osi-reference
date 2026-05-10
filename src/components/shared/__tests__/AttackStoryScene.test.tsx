import { describe, it, expect } from "vitest";
import { screen } from "@solidjs/testing-library";
import { renderWithProviders } from "../../../test/render-with-providers";
import AttackStoryScene from "../AttackStoryScene";
import type { AttackStoryScene as Scene, RawExchange } from "../../../../shared/api-types";

function makeRawExchange(): RawExchange {
  return {
    browserToOrchestrator: {
      request: { line: "POST /api/x", headers: {}, body: null, bytesSent: 0 },
      response: { line: "HTTP/1.1 200 OK", status: 200, headers: {}, body: null, bytesReceived: 0 },
    },
    orchestratorToVictim: {
      request: {
        line: "POST /totp/login-replay HTTP/1.1",
        headers: { "Content-Type": "application/json", "X-Demo-Header": "demo-value" },
        body: '{"username":"seed_alice"}',
        bytesSent: 90,
      },
      response: {
        line: "HTTP/1.1 200 OK",
        status: 200,
        headers: { "x-computed-otp": "123456" },
        body: '{"ok":true,"computedOtp":"123456","leakedToAttacker":{"email":"alice@victim.local"}}',
        bytesReceived: 110,
      },
      targetResolvedTo: "http://localhost:4001",
    },
    elapsedMs: 30,
  };
}

describe("AttackStoryScene", () => {
  it("renders title in Japanese by default", () => {
    const scene: Scene = {
      id: "x",
      title: "Hello",
      titleJa: "こんにちは",
      actor: "attacker",
      narration: { ja: "解説です", en: "Narration" },
    };
    renderWithProviders(() => <AttackStoryScene scene={scene} />);
    expect(screen.getByText("こんにちは")).toBeTruthy();
    expect(screen.getByText("解説です")).toBeTruthy();
  });

  it("renders speech bubble for primary actor", () => {
    const scene: Scene = {
      id: "x",
      title: "Hello",
      titleJa: "こんにちは",
      actor: "attacker",
      speech: { ja: "やった", en: "Done" },
    };
    renderWithProviders(() => <AttackStoryScene scene={scene} />);
    expect(screen.getByText("やった")).toBeTruthy();
  });

  it("renders http-request visual with header highlight", () => {
    const scene: Scene = {
      id: "x",
      title: "Req",
      titleJa: "リクエスト",
      actor: "attacker",
      visual: {
        type: "http-request",
        sourceRef: { pair: "orchestratorToVictim", side: "request", field: "line" },
        highlight: [{ target: "header", match: "X-Demo-Header" }],
      },
    };
    renderWithProviders(() => <AttackStoryScene scene={scene} rawExchange={makeRawExchange()} />);
    expect(screen.getByText("POST /totp/login-replay HTTP/1.1")).toBeTruthy();
    expect(screen.getByText("demo-value")).toBeTruthy();
  });

  it("renders data-leak visual with resolved value", () => {
    const scene: Scene = {
      id: "x",
      title: "Leak",
      titleJa: "漏えい",
      actor: "attacker",
      visual: {
        type: "data-leak",
        label: "OTP",
        labelJa: "OTP",
        valueRef: { pair: "orchestratorToVictim", side: "response", field: { header: "X-Computed-OTP" } },
        severity: "high",
      },
    };
    renderWithProviders(() => <AttackStoryScene scene={scene} rawExchange={makeRawExchange()} />);
    expect(screen.getByText("123456")).toBeTruthy();
  });

  it("renders data-leak fallback when rawExchange is null", () => {
    const scene: Scene = {
      id: "x",
      title: "Leak",
      titleJa: "漏えい",
      actor: "attacker",
      visual: {
        type: "data-leak",
        label: "OTP",
        labelJa: "OTP",
        valueRef: { pair: "orchestratorToVictim", side: "response", field: { header: "X-Computed-OTP" } },
      },
    };
    renderWithProviders(() => <AttackStoryScene scene={scene} rawExchange={null} />);
    expect(screen.getByText("—")).toBeTruthy();
  });

  it("renders code-defense visual using codeHints", () => {
    const scene: Scene = {
      id: "x",
      title: "Defense",
      titleJa: "防御策",
      actor: "narrator",
      visual: { type: "code-defense", codeHintIndex: 0, lineHighlight: [0, 1] },
    };
    const codeHints = [
      { lang: "typescript", label: "Defended", code: "function ok() {\n  return true;\n}" },
    ];
    renderWithProviders(() => <AttackStoryScene scene={scene} codeHints={codeHints} />);
    expect(screen.getByText("Defended")).toBeTruthy();
    expect(screen.getByText("[typescript]")).toBeTruthy();
    expect(screen.getByText("function ok() {")).toBeTruthy();
  });

  it("renders sequence-arrow visual", () => {
    const scene: Scene = {
      id: "x",
      title: "Arrow",
      titleJa: "矢印",
      actor: "narrator",
      visual: {
        type: "sequence-arrow",
        from: "attacker",
        to: "server",
        label: "POST /login",
        labelJa: "POST /login",
        direction: "request",
      },
    };
    renderWithProviders(() => <AttackStoryScene scene={scene} />);
    expect(screen.getByText("POST /login")).toBeTruthy();
  });

  it("renders ascii visual content", () => {
    const scene: Scene = {
      id: "x",
      title: "Ascii",
      titleJa: "アスキー図",
      actor: "narrator",
      visual: { type: "ascii", content: "alice -> server\nattacker -> alice" },
    };
    renderWithProviders(() => <AttackStoryScene scene={scene} />);
    const pre = screen.getByText(/alice -> server/);
    expect(pre).toBeTruthy();
  });
});
