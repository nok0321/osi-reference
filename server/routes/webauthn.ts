import { Hono } from "hono";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import type { RegistrationResponseJSON, AuthenticationResponseJSON } from "@simplewebauthn/server";
import { v4 as uuidv4 } from "uuid";
import { getDb } from "../db/schema.js";
import { parseBody, webauthnUsernameSchema, webauthnRegisterVerifySchema, webauthnAuthVerifySchema } from "../validation.js";
import type { UserRow, WebAuthnCredentialRow } from "../../shared/api-types.js";
import { createTtlStore } from "../utils/ttl-store.js";

export const webauthnRoutes = new Hono();

const RP_NAME = "OSI Reference Demo";
const RP_ID = "localhost";
const ORIGIN = "http://localhost:3000";

// In-memory challenge store (keyed by sessionId to prevent concurrent-tab overwrites)
const challenges = createTtlStore<{ challenge: string; username: string }>({ ttlMs: 5 * 60 * 1000 });

webauthnRoutes.post("/register/options", async (c) => {
  const parsed = await parseBody(c, webauthnUsernameSchema);
  if ("error" in parsed) return parsed.error;
  const { username } = parsed.data;
  const trace = c.get("trace");
  const db = getDb();

  // Get or create user
  let user = db.prepare("SELECT id, username FROM users WHERE username = ?").get(username) as Pick<UserRow, "id" | "username"> | undefined;
  if (!user) {
    // Create a placeholder user for WebAuthn-only registration
    db.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)").run(username, "WEBAUTHN_ONLY");
    user = db.prepare("SELECT id, username FROM users WHERE username = ?").get(username) as Pick<UserRow, "id" | "username"> | undefined;
    trace.addDbQuery({
      sql: "INSERT INTO users (username, password_hash) VALUES (?, 'WEBAUTHN_ONLY')",
      params: [username],
      ms: 0,
    });
  }
  if (!user) {
    return c.json({ success: false, error: "Failed to create user" }, 500);
  }

  // Get existing credentials
  const existingCreds = db.prepare(
    "SELECT credential_id, public_key, counter, transports FROM webauthn_credentials WHERE user_id = ?"
  ).all(user.id) as WebAuthnCredentialRow[];

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userName: username,
    userID: new TextEncoder().encode(String(user.id)),
    attestationType: "none",
    excludeCredentials: existingCreds.map((cred) => ({
      id: cred.credential_id,
      transports: cred.transports ? JSON.parse(cred.transports) : undefined,
    })),
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "preferred",
    },
  });

  const sessionId = uuidv4();
  challenges.set(sessionId, { challenge: options.challenge, username });

  trace.addCryptoOp({
    op: "generateChallenge",
    input: `rpId="${RP_ID}", user="${username}"`,
    output: options.challenge,
    algo: "crypto.getRandomValues(32 bytes) → base64url",
    detail: "Server generates random challenge to prevent replay attacks",
  });

  trace.addSessionOp({
    action: "STORE_CHALLENGE",
    data: { sessionId, username, challenge: options.challenge, purpose: "registration" },
  });

  return c.json({
    success: true,
    data: {
      sessionId,
      options,
      explanation: {
        challenge: "Random bytes from server — authenticator must sign this",
        rp: { id: RP_ID, name: RP_NAME },
        excludeCredentials: `${existingCreds.length} existing credential(s) excluded`,
      },
    },
  });
});

webauthnRoutes.post("/register/verify", async (c) => {
  const parsed = await parseBody(c, webauthnRegisterVerifySchema);
  if ("error" in parsed) return parsed.error;
  const { sessionId, username, response: attResponseRaw } = parsed.data;
  const attResponse = attResponseRaw as unknown as RegistrationResponseJSON;
  const trace = c.get("trace");
  const db = getDb();

  const stored = challenges.get(sessionId);
  if (!stored || stored.username !== username) {
    return c.json({ success: false, error: "No challenge found or challenge expired — start registration first" }, 400);
  }

  try {
    const verification = await verifyRegistrationResponse({
      response: attResponse,
      expectedChallenge: stored.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
    });

    trace.addCryptoOp({
      op: "verifyRegistration",
      input: `clientDataJSON + attestationObject`,
      output: verification.verified ? "VERIFIED ✓" : "FAILED ✗",
      algo: "FIDO2 Attestation Verification",
      detail: "Verify challenge signature, check origin/rpId, extract public key",
    });

    if (verification.verified && verification.registrationInfo) {
      const { credential } = verification.registrationInfo;
      const user = db.prepare("SELECT id FROM users WHERE username = ?").get(username) as Pick<UserRow, "id"> | undefined;
      if (!user) {
        return c.json({ success: false, error: "User not found" }, 500);
      }

      db.prepare(
        "INSERT INTO webauthn_credentials (credential_id, user_id, public_key, counter, transports) VALUES (?, ?, ?, ?, ?)"
      ).run(
        credential.id,
        user.id,
        Buffer.from(credential.publicKey).toString("base64"),
        credential.counter,
        JSON.stringify(attResponse.response?.transports ?? [])
      );

      trace.addDbQuery({
        sql: "INSERT INTO webauthn_credentials (credential_id, user_id, public_key, counter, transports) VALUES (...)",
        params: [credential.id, user.id],
        ms: 0,
      });

      challenges.delete(sessionId);

      return c.json({
        success: true,
        data: {
          verified: true,
          credentialId: credential.id,
          publicKeyPreview: Buffer.from(credential.publicKey).toString("base64").substring(0, 40) + "...",
          counter: credential.counter,
        },
      });
    }

    return c.json({ success: false, error: "Verification failed" }, 400);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Unknown error";
    return c.json({ success: false, error: message }, 400);
  }
});

webauthnRoutes.post("/auth/options", async (c) => {
  const parsed = await parseBody(c, webauthnUsernameSchema);
  if ("error" in parsed) return parsed.error;
  const { username } = parsed.data;
  const trace = c.get("trace");
  const db = getDb();

  const user = db.prepare("SELECT id FROM users WHERE username = ?").get(username) as Pick<UserRow, "id"> | undefined;
  if (!user) {
    return c.json({ success: false, error: "User not found" }, 404);
  }

  const creds = db.prepare(
    "SELECT credential_id, public_key, counter, transports FROM webauthn_credentials WHERE user_id = ?"
  ).all(user.id) as WebAuthnCredentialRow[];

  if (creds.length === 0) {
    return c.json({ success: false, error: "No credentials registered" }, 400);
  }

  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    allowCredentials: creds.map((cred) => ({
      id: cred.credential_id,
      transports: cred.transports ? JSON.parse(cred.transports) : undefined,
    })),
    userVerification: "preferred",
  });

  const sessionId = uuidv4();
  challenges.set(sessionId, { challenge: options.challenge, username });

  trace.addCryptoOp({
    op: "generateAuthChallenge",
    input: `rpId="${RP_ID}", user="${username}", credentials=${creds.length}`,
    output: options.challenge,
    algo: "crypto.getRandomValues(32 bytes) → base64url",
    detail: "New challenge for authentication — must be signed by registered credential",
  });

  return c.json({
    success: true,
    data: {
      sessionId,
      options,
      explanation: {
        challenge: "Fresh random bytes — authenticator signs with private key",
        allowCredentials: `${creds.length} registered credential(s)`,
      },
    },
  });
});

webauthnRoutes.post("/auth/verify", async (c) => {
  const parsed = await parseBody(c, webauthnAuthVerifySchema);
  if ("error" in parsed) return parsed.error;
  const { sessionId, username, response: authResponseRaw } = parsed.data;
  const authResponse = authResponseRaw as unknown as AuthenticationResponseJSON;
  const trace = c.get("trace");
  const db = getDb();

  const stored = challenges.get(sessionId);
  if (!stored || stored.username !== username) {
    return c.json({ success: false, error: "No challenge found or challenge expired" }, 400);
  }

  const user = db.prepare("SELECT id FROM users WHERE username = ?").get(username) as Pick<UserRow, "id"> | undefined;
  if (!user) {
    return c.json({ success: false, error: "User not found" }, 404);
  }

  const cred = db.prepare(
    "SELECT credential_id, public_key, counter FROM webauthn_credentials WHERE credential_id = ? AND user_id = ?"
  ).get(authResponse.id, user.id) as Pick<WebAuthnCredentialRow, "credential_id" | "public_key" | "counter"> | undefined;

  if (!cred) {
    return c.json({ success: false, error: "Credential not found" }, 400);
  }

  try {
    const verification = await verifyAuthenticationResponse({
      response: authResponse,
      expectedChallenge: stored.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      credential: {
        id: cred.credential_id,
        publicKey: Buffer.from(cred.public_key, "base64"),
        counter: cred.counter,
      },
    });

    trace.addCryptoOp({
      op: "verifyAuthentication",
      input: `signature over clientDataJSON + authenticatorData`,
      output: verification.verified ? "VERIFIED ✓" : "FAILED ✗",
      algo: "ECDSA / RSA (credential-dependent)",
      detail: "Verify signature with stored public key, check counter increment",
    });

    if (verification.verified) {
      const newCounter = verification.authenticationInfo.newCounter;

      // Clone detection: counter must always increment
      if (newCounter > 0 && newCounter <= cred.counter) {
        trace.addCryptoOp({
          op: "counterCloneDetection",
          input: `oldCounter=${cred.counter}, newCounter=${newCounter}`,
          output: "⚠ CLONE DETECTED",
          algo: "Counter Verification",
          detail: "Counter did not increment — possible cloned authenticator",
        });
        return c.json({
          success: false,
          error: "Authenticator counter did not increment — possible clone detected",
        }, 403);
      }

      // Update counter
      db.prepare("UPDATE webauthn_credentials SET counter = ? WHERE credential_id = ?").run(
        newCounter,
        cred.credential_id
      );
      challenges.delete(sessionId);

      return c.json({
        success: true,
        data: {
          verified: true,
          username,
          counter: { old: cred.counter, new: verification.authenticationInfo.newCounter },
        },
      });
    }

    return c.json({ success: false, error: "Authentication failed" }, 401);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Unknown error";
    return c.json({ success: false, error: message }, 400);
  }
});

webauthnRoutes.get("/credentials", (c) => {
  const db = getDb();
  const creds = db.prepare(
    `SELECT wc.credential_id, wc.counter, wc.created_at, u.username
     FROM webauthn_credentials wc JOIN users u ON wc.user_id = u.id`
  ).all();
  return c.json({ success: true, data: { credentials: creds } });
});
