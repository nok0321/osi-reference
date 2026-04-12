import { describe, it, expect, beforeEach } from "vitest";
import { createTestApp, post, get } from "./test-helpers.js";
import { computeTotp, currentCounter } from "../utils/totp.js";
import type { Hono } from "hono";

let app: Hono;

beforeEach(() => {
  ({ app } = createTestApp());
});

async function registerUser(username: string, password = "pass123") {
  const res = await post(app, "/api/auth/password/register", { username, password });
  expect(res.status).toBe(200);
}

async function enrollMfa(username: string): Promise<string> {
  const enrollRes = await post(app, "/api/mfa/totp/enroll/start", { username });
  expect(enrollRes.status).toBe(200);
  const secret = enrollRes.json.data.secret as string;
  const code = computeTotp(secret, currentCounter()).code;
  const verifyRes = await post(app, "/api/mfa/totp/enroll/verify", { username, code });
  expect(verifyRes.status).toBe(200);
  return secret;
}

describe("POST /api/mfa/totp/enroll/start", () => {
  it("returns secret + QR for a registered user", async () => {
    await registerUser("enroll-user");
    const res = await post(app, "/api/mfa/totp/enroll/start", { username: "enroll-user" });
    expect(res.status).toBe(200);
    expect(res.json.data.secret).toMatch(/^[A-Z2-7]+$/);
    expect(res.json.data.otpauthUri).toContain("otpauth://totp/");
    expect(res.json.data.qrCodeSvg).toContain("<svg");
  });

  it("returns 404 for unknown user", async () => {
    const res = await post(app, "/api/mfa/totp/enroll/start", { username: "ghost" });
    expect(res.status).toBe(404);
  });
});

describe("POST /api/mfa/totp/enroll/verify", () => {
  it("accepts a valid TOTP code and marks MFA verified", async () => {
    await registerUser("verify-user");
    const enrollRes = await post(app, "/api/mfa/totp/enroll/start", { username: "verify-user" });
    const secret = enrollRes.json.data.secret as string;
    const code = computeTotp(secret, currentCounter()).code;

    const res = await post(app, "/api/mfa/totp/enroll/verify", { username: "verify-user", code });
    expect(res.status).toBe(200);
    expect(res.json.data.verified).toBe(true);
  });

  it("rejects an invalid TOTP code", async () => {
    await registerUser("bad-code-user");
    await post(app, "/api/mfa/totp/enroll/start", { username: "bad-code-user" });
    const res = await post(app, "/api/mfa/totp/enroll/verify", {
      username: "bad-code-user",
      code: "000000",
    });
    expect(res.status).toBe(401);
  });
});

describe("POST /api/mfa/totp/login/step1 (regression: LOGIN_CHALLENGE_TTL_MS)", () => {
  it("full flow: enroll → step1 → step2 succeeds", async () => {
    await registerUser("mfa-user");
    const secret = await enrollMfa("mfa-user");

    // Step 1 — this path exercised LOGIN_CHALLENGE_TTL_MS and challenge.createdAt
    const step1 = await post(app, "/api/mfa/totp/login/step1", {
      username: "mfa-user",
      password: "pass123",
    });
    expect(step1.status).toBe(200);
    expect(step1.json.data.requiresMfa).toBe(true);
    expect(step1.json.data.challengeId).toBeTruthy();

    // Step 2
    const step2Code = computeTotp(secret, currentCounter()).code;
    const step2 = await post(app, "/api/mfa/totp/login/step2", {
      challengeId: step1.json.data.challengeId,
      code: step2Code,
    });
    expect(step2.status).toBe(200);
    expect(step2.json.data.success).toBe(true);
    expect(step2.json.data.username).toBe("mfa-user");
  });

  it("reports MFA not required for a user without verified MFA", async () => {
    await registerUser("no-mfa-user");
    const res = await post(app, "/api/mfa/totp/login/step1", {
      username: "no-mfa-user",
      password: "pass123",
    });
    expect(res.status).toBe(200);
    expect(res.json.data.requiresMfa).toBe(false);
    expect(res.json.data.challengeId).toBeNull();
  });

  it("rejects wrong password", async () => {
    await registerUser("wrong-pw");
    await enrollMfa("wrong-pw");
    const res = await post(app, "/api/mfa/totp/login/step1", {
      username: "wrong-pw",
      password: "not-the-password",
    });
    expect(res.status).toBe(401);
  });
});

describe("POST /api/mfa/totp/login/step2", () => {
  it("rejects a bogus challengeId", async () => {
    const res = await post(app, "/api/mfa/totp/login/step2", {
      challengeId: "does-not-exist",
      code: "123456",
    });
    expect(res.status).toBe(400);
  });

  it("rejects a valid challenge with a wrong TOTP code", async () => {
    await registerUser("u2");
    await enrollMfa("u2");
    const step1 = await post(app, "/api/mfa/totp/login/step1", {
      username: "u2",
      password: "pass123",
    });
    const res = await post(app, "/api/mfa/totp/login/step2", {
      challengeId: step1.json.data.challengeId,
      code: "000000",
    });
    expect(res.status).toBe(401);
  });

  it("consumes the challenge on success (replay rejected)", async () => {
    await registerUser("u3");
    const secret = await enrollMfa("u3");
    const step1 = await post(app, "/api/mfa/totp/login/step1", {
      username: "u3",
      password: "pass123",
    });
    const code = computeTotp(secret, currentCounter()).code;
    const first = await post(app, "/api/mfa/totp/login/step2", {
      challengeId: step1.json.data.challengeId,
      code,
    });
    expect(first.status).toBe(200);
    // Same challengeId should no longer be valid
    const replay = await post(app, "/api/mfa/totp/login/step2", {
      challengeId: step1.json.data.challengeId,
      code,
    });
    expect(replay.status).toBe(400);
  });
});

describe("GET /api/mfa/totp/status", () => {
  it("reports enabled:false for user without MFA", async () => {
    await registerUser("status-none");
    const res = await get(app, "/api/mfa/totp/status?username=status-none");
    expect(res.status).toBe(200);
    expect(res.json.data.enabled).toBe(false);
  });

  it("reports enabled:true after enrollment+verification", async () => {
    await registerUser("status-yes");
    await enrollMfa("status-yes");
    const res = await get(app, "/api/mfa/totp/status?username=status-yes");
    expect(res.status).toBe(200);
    expect(res.json.data.enabled).toBe(true);
  });
});
