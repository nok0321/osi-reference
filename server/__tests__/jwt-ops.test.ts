import { describe, it, expect, beforeEach } from "vitest";
import { createTestApp, post } from "./test-helpers.js";
import type { Hono } from "hono";

let app: Hono;

beforeEach(() => {
  ({ app } = createTestApp());
});

describe("POST /api/jwt/sign", () => {
  it("signs with HS256 and returns a valid JWT", async () => {
    const res = await post(app, "/api/jwt/sign", {
      claims: { sub: "user1", role: "admin" },
    });
    expect(res.status).toBe(200);
    expect(res.json.success).toBe(true);

    const { token, parts, decoded } = res.json.data;
    // JWT format: three dot-separated base64url segments
    expect(token).toMatch(/^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    expect(parts.header).toBeTruthy();
    expect(parts.payload).toBeTruthy();
    expect(parts.signature).toBeTruthy();
    expect(decoded.header.alg).toBe("HS256");
    expect(decoded.header.typ).toBe("JWT");
    expect(decoded.payload.sub).toBe("user1");
    expect(decoded.payload.role).toBe("admin");
    // HS256 exposes the shared secret
    expect(res.json.data.secret).toBeTruthy();
  });

  it("signs with RS256 and returns a valid JWT", async () => {
    const res = await post(app, "/api/jwt/sign", {
      claims: { sub: "user2" },
      algorithm: "RS256",
    });
    expect(res.status).toBe(200);
    expect(res.json.success).toBe(true);

    const { token, decoded } = res.json.data;
    expect(token).toMatch(/^eyJ/);
    expect(decoded.header.alg).toBe("RS256");
    // RS256 does not expose the private key directly
    expect(res.json.data.secret).toBe("(RSA Private Key)");
  });

  it("respects custom expiresIn", async () => {
    const res = await post(app, "/api/jwt/sign", {
      claims: { sub: "user3" },
      expiresIn: 60,
    });
    expect(res.status).toBe(200);
    const payload = res.json.data.decoded.payload;
    // exp - iat should equal 60
    expect(payload.exp - payload.iat).toBe(60);
  });

  it("rejects empty claims object gracefully", async () => {
    // An empty claims object is still a valid record
    const res = await post(app, "/api/jwt/sign", { claims: {} });
    expect(res.status).toBe(200);
    expect(res.json.success).toBe(true);
  });

  it("rejects missing claims field", async () => {
    const res = await post(app, "/api/jwt/sign", {});
    expect(res.status).toBe(400);
    expect(res.json.error).toContain("Validation error");
  });
});

describe("POST /api/jwt/verify", () => {
  it("verifies a valid HS256 token", async () => {
    // Sign first
    const signRes = await post(app, "/api/jwt/sign", {
      claims: { sub: "user1", role: "admin" },
    });
    const { token } = signRes.json.data;

    // Verify
    const verifyRes = await post(app, "/api/jwt/verify", { token });
    expect(verifyRes.status).toBe(200);
    expect(verifyRes.json.success).toBe(true);
    expect(verifyRes.json.data.valid).toBe(true);
    expect(verifyRes.json.data.decoded.sub).toBe("user1");
  });

  it("verifies a valid RS256 token", async () => {
    const signRes = await post(app, "/api/jwt/sign", {
      claims: { sub: "rs-user" },
      algorithm: "RS256",
    });
    const { token } = signRes.json.data;

    const verifyRes = await post(app, "/api/jwt/verify", {
      token,
      algorithm: "RS256",
    });
    expect(verifyRes.status).toBe(200);
    expect(verifyRes.json.data.valid).toBe(true);
    expect(verifyRes.json.data.decoded.sub).toBe("rs-user");
  });

  it("rejects a tampered token", async () => {
    const signRes = await post(app, "/api/jwt/sign", {
      claims: { sub: "user1" },
    });
    // Tamper with the token by flipping a character in the signature
    const token = signRes.json.data.token;
    const parts = token.split(".");
    const sig = parts[2];
    const flipped = sig[0] === "A" ? "B" + sig.slice(1) : "A" + sig.slice(1);
    const tamperedToken = `${parts[0]}.${parts[1]}.${flipped}`;

    const verifyRes = await post(app, "/api/jwt/verify", { token: tamperedToken });
    expect(verifyRes.status).toBe(200);
    expect(verifyRes.json.data.valid).toBe(false);
    expect(verifyRes.json.data.error).toBeTruthy();
  });

  it("rejects an expired token", async () => {
    // Sign with 1-second expiry
    const signRes = await post(app, "/api/jwt/sign", {
      claims: { sub: "user1" },
      expiresIn: 1,
    });
    const { token } = signRes.json.data;

    // Wait for token to expire
    await new Promise((resolve) => setTimeout(resolve, 1500));

    const verifyRes = await post(app, "/api/jwt/verify", { token });
    expect(verifyRes.status).toBe(200);
    expect(verifyRes.json.data.valid).toBe(false);
    expect(verifyRes.json.data.error).toContain("expired");
  });

  it("fails when verifying HS256 token with RS256 algorithm", async () => {
    const signRes = await post(app, "/api/jwt/sign", {
      claims: { sub: "user1" },
      algorithm: "HS256",
    });
    const { token } = signRes.json.data;

    const verifyRes = await post(app, "/api/jwt/verify", {
      token,
      algorithm: "RS256",
    });
    expect(verifyRes.status).toBe(200);
    expect(verifyRes.json.data.valid).toBe(false);
  });
});

describe("POST /api/jwt/decode", () => {
  it("decodes a valid token without verification", async () => {
    const signRes = await post(app, "/api/jwt/sign", {
      claims: { sub: "user1", data: "hello" },
    });
    const { token } = signRes.json.data;

    const decodeRes = await post(app, "/api/jwt/decode", { token });
    expect(decodeRes.status).toBe(200);
    expect(decodeRes.json.success).toBe(true);
    expect(decodeRes.json.data.decoded.payload.sub).toBe("user1");
    expect(decodeRes.json.data.decoded.payload.data).toBe("hello");
    expect(decodeRes.json.data.decoded.header.alg).toBe("HS256");
    expect(decodeRes.json.data.warning).toContain("WITHOUT verification");
  });

  it("decodes a tampered token (no verification)", async () => {
    const signRes = await post(app, "/api/jwt/sign", {
      claims: { sub: "user1" },
    });
    const token = signRes.json.data.token;
    // Tamper with the signature
    const tampered = token.slice(0, -4) + "XXXX";

    const decodeRes = await post(app, "/api/jwt/decode", { token: tampered });
    expect(decodeRes.status).toBe(200);
    // Decode still returns payload even for tampered tokens
    expect(decodeRes.json.data.decoded.payload.sub).toBe("user1");
  });

  it("rejects missing token field", async () => {
    const res = await post(app, "/api/jwt/decode", {});
    expect(res.status).toBe(400);
    expect(res.json.error).toContain("Validation error");
  });
});
