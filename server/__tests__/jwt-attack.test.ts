import { describe, it, expect, beforeEach } from "vitest";
import { createTestApp, post } from "./test-helpers.js";
import type { Hono } from "hono";

let app: Hono;

beforeEach(() => {
  ({ app } = createTestApp());
});

describe("POST /api/jwt/attack/alg-none", () => {
  it("lenient mode succeeds (vulnerable verifier accepts alg=none)", async () => {
    const res = await post(app, "/api/jwt/attack/alg-none", {
      victim: { algorithm: "HS256", strict: false },
    });
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.scenarioId).toBe("jwt-alg-none");
    expect(res.json.data.steps.length).toBeGreaterThanOrEqual(4);
    expect(res.json._trace.attackSteps).toBeDefined();
    expect(res.json._trace.isAttackMode).toBe(true);
    expect(res.json.data.logId).toBeGreaterThan(0);
  });

  it("strict mode is blocked (algorithms allowlist rejects alg=none)", async () => {
    const res = await post(app, "/api/jwt/attack/alg-none", {
      victim: { algorithm: "HS256", strict: true },
    });
    expect(res.status).toBe(401);
    expect(res.json.data.outcome).toBe("blocked");
    expect(res.json.data.blockedBy).toBe("jwt_algorithms_allowlist");
  });

  it("rejects invalid request body (missing victim)", async () => {
    const res = await post(app, "/api/jwt/attack/alg-none", {});
    expect(res.status).toBe(400);
    expect(res.json.error).toContain("Validation error");
  });
});

describe("POST /api/jwt/attack/weak-secret-bruteforce", () => {
  it("weak secret cracked from dictionary", async () => {
    const res = await post(app, "/api/jwt/attack/weak-secret-bruteforce", {
      secretType: "weak", dictionarySize: 100,
    });
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.crackedSecret).toBe("secret");
    expect(res.json.data.attemptCount).toBeGreaterThanOrEqual(1);
  });

  it("strong secret resists dictionary (all attempts fail)", async () => {
    const res = await post(app, "/api/jwt/attack/weak-secret-bruteforce", {
      secretType: "strong", dictionarySize: 100,
    });
    expect(res.status).toBe(401);
    expect(res.json.data.outcome).toBe("blocked");
    expect(res.json.data.blockedBy).toBe("strong_random_secret");
    expect(res.json.data.crackedSecret).toBeNull();
  });

  it("rejects dictionarySize over 200", async () => {
    const res = await post(app, "/api/jwt/attack/weak-secret-bruteforce", {
      secretType: "weak", dictionarySize: 201,
    });
    expect(res.status).toBe(400);
  });
});

describe("POST /api/jwt/attack/signature-stripping", () => {
  it("decode-only mode accepts forged token", async () => {
    const res = await post(app, "/api/jwt/attack/signature-stripping", { mode: "decode-only" });
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
  });

  it("verify mode rejects token with invalid signature", async () => {
    const res = await post(app, "/api/jwt/attack/signature-stripping", { mode: "verify" });
    expect(res.status).toBe(401);
    expect(res.json.data.outcome).toBe("blocked");
    expect(res.json.data.blockedBy).toBe("jwt_signature_mismatch");
  });

  it("rejects invalid mode", async () => {
    const res = await post(app, "/api/jwt/attack/signature-stripping", { mode: "invalid" });
    expect(res.status).toBe(400);
  });
});

describe("POST /api/jwt/attack/kid-injection", () => {
  it("vulnerable mode accepts injected kid (path traversal)", async () => {
    const res = await post(app, "/api/jwt/attack/kid-injection", {
      injectedKid: "../public/attacker-key.pem", mode: "vulnerable",
    });
    expect(res.status).toBe(200);
    expect(res.json.data.outcome).toBe("succeeded");
    expect(res.json.data.kidResolved).toBe("../public/attacker-key.pem");
  });

  it("allowlist mode rejects unknown kid", async () => {
    const res = await post(app, "/api/jwt/attack/kid-injection", {
      injectedKid: "../public/attacker-key.pem", mode: "allowlist",
    });
    expect(res.status).toBe(401);
    expect(res.json.data.outcome).toBe("blocked");
    expect(res.json.data.blockedBy).toBe("jwt_kid_not_in_allowlist");
  });

  it("attack_log row is inserted for every scenario", async () => {
    const res = await post(app, "/api/jwt/attack/kid-injection", { mode: "vulnerable" });
    expect(res.json.data.logId).toBeDefined();
    expect(typeof res.json.data.logId).toBe("number");
  });
});

describe("Production guard", () => {
  it("attack route returns 403 when NODE_ENV=production", async () => {
    const orig = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    try {
      const res = await post(app, "/api/jwt/attack/alg-none", {
        victim: { algorithm: "HS256", strict: false },
      });
      expect(res.status).toBe(403);
      expect(res.json.success).toBe(false);
      expect(res.json.error).toContain("disabled in production");
    } finally {
      process.env.NODE_ENV = orig;
    }
  });

  it("non-attack route is unaffected by production guard", async () => {
    const orig = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    try {
      const res = await post(app, "/api/jwt/sign", {
        claims: { sub: "test-user" },
      });
      expect(res.status).toBe(200);
    } finally {
      process.env.NODE_ENV = orig;
    }
  });
});
