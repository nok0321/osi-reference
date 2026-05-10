import { describe, it, expect } from "vitest";
import { resolveRawRef } from "../story-resolver";
import type { RawExchange } from "../../../shared/api-types";

function makeExchange(): RawExchange {
  return {
    browserToOrchestrator: {
      request: {
        line: "POST /api/orchestrator/exec HTTP/1.1",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: '{"scenarioId":"test"}',
        bytesSent: 80,
      },
      response: {
        line: "HTTP/1.1 200 OK",
        status: 200,
        headers: { "content-type": "application/json" },
        body: '{"ok":true}',
        bytesReceived: 12,
      },
    },
    orchestratorToVictim: {
      request: {
        line: "POST /totp/login-replay HTTP/1.1",
        headers: { Host: "victim-web:4001", "Content-Type": "application/json" },
        body: '{"username":"seed_alice"}',
        bytesSent: 100,
      },
      response: {
        line: "HTTP/1.1 200 OK",
        status: 200,
        headers: { "content-type": "application/json", "x-computed-otp": "123456" },
        body: '{"ok":true,"computedOtp":"123456"}',
        bytesReceived: 120,
      },
      targetResolvedTo: "http://localhost:4001",
    },
    elapsedMs: 42,
  };
}

describe("resolveRawRef", () => {
  it("returns undefined when exchange is null/undefined", () => {
    expect(
      resolveRawRef(
        { pair: "orchestratorToVictim", side: "request", field: "line" },
        null,
      ),
    ).toBeUndefined();
    expect(
      resolveRawRef(
        { pair: "orchestratorToVictim", side: "request", field: "line" },
        undefined,
      ),
    ).toBeUndefined();
  });

  it("resolves request line", () => {
    const ex = makeExchange();
    expect(
      resolveRawRef(
        { pair: "orchestratorToVictim", side: "request", field: "line" },
        ex,
      ),
    ).toBe("POST /totp/login-replay HTTP/1.1");
  });

  it("resolves response body", () => {
    const ex = makeExchange();
    expect(
      resolveRawRef(
        { pair: "orchestratorToVictim", side: "response", field: "body" },
        ex,
      ),
    ).toBe('{"ok":true,"computedOtp":"123456"}');
  });

  it("resolves header case-insensitively (HTTP spec)", () => {
    const ex = makeExchange();
    // Header set as "Host" (PascalCase). Lookup with lowercase, uppercase, mixed.
    expect(
      resolveRawRef(
        { pair: "orchestratorToVictim", side: "request", field: { header: "host" } },
        ex,
      ),
    ).toBe("victim-web:4001");
    expect(
      resolveRawRef(
        { pair: "orchestratorToVictim", side: "request", field: { header: "HOST" } },
        ex,
      ),
    ).toBe("victim-web:4001");
    expect(
      resolveRawRef(
        { pair: "orchestratorToVictim", side: "response", field: { header: "X-Computed-OTP" } },
        ex,
      ),
    ).toBe("123456");
  });

  it("returns undefined when header not present", () => {
    const ex = makeExchange();
    expect(
      resolveRawRef(
        { pair: "orchestratorToVictim", side: "request", field: { header: "Cookie" } },
        ex,
      ),
    ).toBeUndefined();
  });

  it("handles body=null gracefully", () => {
    const ex = makeExchange();
    ex.orchestratorToVictim.response.body = null;
    expect(
      resolveRawRef(
        { pair: "orchestratorToVictim", side: "response", field: "body" },
        ex,
      ),
    ).toBeUndefined();
  });

  it("respects pair selection", () => {
    const ex = makeExchange();
    expect(
      resolveRawRef(
        { pair: "browserToOrchestrator", side: "request", field: "line" },
        ex,
      ),
    ).toBe("POST /api/orchestrator/exec HTTP/1.1");
    expect(
      resolveRawRef(
        { pair: "browserToOrchestrator", side: "response", field: "body" },
        ex,
      ),
    ).toBe('{"ok":true}');
  });
});
