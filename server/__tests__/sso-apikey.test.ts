import { describe, it, expect, beforeEach } from "vitest";
import crypto from "crypto";
import { createTestApp, post } from "./test-helpers.js";
import type { Hono } from "hono";

let app: Hono;

beforeEach(() => {
  ({ app } = createTestApp());
});

// Seed users: "oidc-user" and "saml-user" (password: "demo123")

/** SSO login and return the ssoToken. */
async function ssoLogin(testApp: Hono, username = "oidc-user") {
  const res = await post(testApp, "/api/sso/login", { username });
  expect(res.status).toBe(200);
  return res.json.data.ssoToken as string;
}

/** Generate an API key and return { keyId, rawKey }. */
async function generateApiKey(testApp: Hono, name = "test-key") {
  const res = await post(testApp, "/api/sso/apikey/generate", { name });
  expect(res.status).toBe(200);
  return { keyId: res.json.data.keyId as string, rawKey: res.json.data.rawKey as string };
}

// ── SSO Session Propagation ──

describe("POST /api/sso/login", () => {
  it("creates an SSO session for a valid user", async () => {
    const res = await post(app, "/api/sso/login", { username: "oidc-user" });
    expect(res.status).toBe(200);
    expect(res.json.success).toBe(true);
    expect(res.json.data.ssoToken).toBeTruthy();
    expect(res.json.data.username).toBe("oidc-user");
  });

  it("works for saml-user as well", async () => {
    const res = await post(app, "/api/sso/login", { username: "saml-user" });
    expect(res.status).toBe(200);
    expect(res.json.data.username).toBe("saml-user");
  });

  it("returns 404 for a non-existent user", async () => {
    const res = await post(app, "/api/sso/login", { username: "ghost-user" });
    expect(res.status).toBe(404);
    expect(res.json.error).toContain("User not found");
  });
});

describe("POST /api/sso/access-service", () => {
  it("grants access to a service with a valid SSO token", async () => {
    const ssoToken = await ssoLogin(app);
    const res = await post(app, "/api/sso/access-service", {
      ssoToken,
      serviceName: "email-app",
    });
    expect(res.status).toBe(200);
    expect(res.json.success).toBe(true);
    expect(res.json.data.authenticated).toBe(true);
    expect(res.json.data.service).toBe("email-app");
    expect(res.json.data.accessedServices).toContain("email-app");
  });

  it("accumulates accessed services across multiple requests", async () => {
    const ssoToken = await ssoLogin(app);
    await post(app, "/api/sso/access-service", { ssoToken, serviceName: "email-app" });
    await post(app, "/api/sso/access-service", { ssoToken, serviceName: "crm-app" });
    const res = await post(app, "/api/sso/access-service", { ssoToken, serviceName: "docs-app" });
    expect(res.status).toBe(200);
    expect(res.json.data.accessedServices).toEqual(
      expect.arrayContaining(["email-app", "crm-app", "docs-app"]),
    );
  });

  it("does not duplicate a service already accessed", async () => {
    const ssoToken = await ssoLogin(app);
    await post(app, "/api/sso/access-service", { ssoToken, serviceName: "email-app" });
    const res = await post(app, "/api/sso/access-service", { ssoToken, serviceName: "email-app" });
    expect(res.status).toBe(200);
    const count = res.json.data.accessedServices.filter((s: string) => s === "email-app").length;
    expect(count).toBe(1);
  });

  it("rejects an invalid SSO token", async () => {
    const res = await post(app, "/api/sso/access-service", {
      ssoToken: "invalid-token-abc",
      serviceName: "email-app",
    });
    expect(res.status).toBe(401);
    expect(res.json.error).toContain("Invalid or expired SSO token");
  });
});

// ── API Key Generation & Header Verification ──

describe("POST /api/sso/apikey/generate", () => {
  it("generates an API key with keyId and rawKey", async () => {
    const res = await post(app, "/api/sso/apikey/generate", { name: "my-key" });
    expect(res.status).toBe(200);
    expect(res.json.success).toBe(true);
    expect(res.json.data.keyId).toMatch(/^key_/);
    expect(res.json.data.rawKey).toBeTruthy();
    expect(res.json.data.prefix).toBeTruthy();
    expect(res.json.data.warning).toBeTruthy();
  });

  it("uses 'default' name when none provided", async () => {
    const res = await post(app, "/api/sso/apikey/generate", {});
    expect(res.status).toBe(200);
    expect(res.json.data.keyId).toMatch(/^key_/);
  });
});

describe("POST /api/sso/apikey/verify/header", () => {
  it("verifies a valid API key via X-API-Key header", async () => {
    const { rawKey } = await generateApiKey(app);
    const res = await post(app, "/api/sso/apikey/verify/header", undefined, {
      "X-API-Key": rawKey,
    });
    expect(res.status).toBe(200);
    expect(res.json.success).toBe(true);
    expect(res.json.data.valid).toBe(true);
    expect(res.json.data.name).toBe("test-key");
    expect(res.json.data.method).toContain("Header");
  });

  it("rejects an invalid API key", async () => {
    const res = await post(app, "/api/sso/apikey/verify/header", undefined, {
      "X-API-Key": "bogus-key-value",
    });
    expect(res.status).toBe(401);
    expect(res.json.error).toContain("Invalid API key");
  });

  it("rejects when no API key header is provided", async () => {
    const res = await post(app, "/api/sso/apikey/verify/header", undefined);
    expect(res.status).toBe(401);
    expect(res.json.error).toContain("No API key provided");
  });
});

// ── HMAC Signed Request Verification ──

describe("POST /api/sso/apikey/verify/hmac", () => {
  it("verifies a correctly signed HMAC request", async () => {
    const { keyId, rawKey } = await generateApiKey(app, "hmac-key");

    // The HMAC secret is the SHA-256 hash of the raw key (matches server-side key_hash)
    const keyHash = crypto.createHash("sha256").update(rawKey).digest("hex");
    const timestamp = new Date().toISOString();
    const body = { action: "transfer", amount: 100 };
    const canonical = `${timestamp}\n${JSON.stringify(body)}`;
    const signature = crypto.createHmac("sha256", keyHash).update(canonical).digest("hex");

    const res = await post(app, "/api/sso/apikey/verify/hmac", {
      keyId,
      timestamp,
      body,
      signature,
    });
    expect(res.status).toBe(200);
    expect(res.json.success).toBe(true);
    expect(res.json.data.valid).toBe(true);
    expect(res.json.data.keyId).toBe(keyId);
  });

  it("rejects a request with a wrong signature", async () => {
    const { keyId } = await generateApiKey(app);
    const timestamp = new Date().toISOString();
    const body = { action: "transfer", amount: 100 };
    // Use a deliberately wrong signature (valid hex, correct length)
    const wrongSig = crypto.createHmac("sha256", "wrong-secret").update("wrong").digest("hex");

    const res = await post(app, "/api/sso/apikey/verify/hmac", {
      keyId,
      timestamp,
      body,
      signature: wrongSig,
    });
    expect(res.status).toBe(200);
    expect(res.json.data.valid).toBe(false);
  });

  it("rejects an unknown keyId", async () => {
    const res = await post(app, "/api/sso/apikey/verify/hmac", {
      keyId: "key_nonexist",
      timestamp: new Date().toISOString(),
      body: {},
      signature: "a".repeat(64),
    });
    expect(res.status).toBe(401);
    expect(res.json.error).toContain("Unknown key_id");
  });
});

// ── Full Flows ──

describe("Full SSO flow: login -> access multiple services", () => {
  it("authenticates once and accesses several services without re-login", async () => {
    // Login once
    const ssoToken = await ssoLogin(app, "saml-user");

    // Access three different services
    const services = ["mail", "calendar", "drive"];
    for (const svc of services) {
      const res = await post(app, "/api/sso/access-service", {
        ssoToken,
        serviceName: svc,
      });
      expect(res.status).toBe(200);
      expect(res.json.data.authenticated).toBe(true);
      expect(res.json.data.username).toBe("saml-user");
    }

    // Final request should list all three services
    const finalRes = await post(app, "/api/sso/access-service", {
      ssoToken,
      serviceName: "drive",
    });
    expect(finalRes.json.data.accessedServices).toEqual(
      expect.arrayContaining(services),
    );
  });
});

describe("Full API Key flow: generate -> verify header -> HMAC sign/verify", () => {
  it("generates a key and verifies it both ways", async () => {
    // Step 1: Generate
    const { keyId, rawKey } = await generateApiKey(app, "full-flow-key");

    // Step 2: Verify via header
    const headerRes = await post(app, "/api/sso/apikey/verify/header", undefined, {
      "X-API-Key": rawKey,
    });
    expect(headerRes.status).toBe(200);
    expect(headerRes.json.data.valid).toBe(true);

    // Step 3: HMAC verification
    const keyHash = crypto.createHash("sha256").update(rawKey).digest("hex");
    const timestamp = new Date().toISOString();
    const body = { resource: "/api/secret", method: "GET" };
    const canonical = `${timestamp}\n${JSON.stringify(body)}`;
    const signature = crypto.createHmac("sha256", keyHash).update(canonical).digest("hex");

    const hmacRes = await post(app, "/api/sso/apikey/verify/hmac", {
      keyId,
      timestamp,
      body,
      signature,
    });
    expect(hmacRes.status).toBe(200);
    expect(hmacRes.json.data.valid).toBe(true);
  });
});
