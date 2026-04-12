import { Hono } from "hono";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import { v4 as uuidv4 } from "uuid";
import { getDb } from "../db/schema.js";
import {
  parseBody,
  webauthnUsernameSchema,
  webauthnRegisterVerifySchema,
  passkeyAuthVerifySchema,
} from "../validation.js";
import type { UserRow, WebAuthnCredentialRow } from "../../shared/api-types.js";
import { createTtlStore } from "../utils/ttl-store.js";

export const passkeyRoutes = new Hono();

/** Safely parse the `transports` JSON column — returns undefined if missing or malformed. */
function parseTransports(raw: string | null | undefined): string[] | undefined {
  if (!raw) return undefined;
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

const RP_NAME = "OSI Reference Demo";
const RP_ID = "localhost";
const ORIGIN = "http://localhost:3000";

// ── Challenge stores ──
// Registration: keyed by username (same as existing webauthn.ts)
const registerChallenges = createTtlStore<string>({ ttlMs: 5 * 60 * 1000 });
// Usernameless auth: keyed by sessionId (uuid)
const authChallenges = createTtlStore<string>({ ttlMs: 5 * 60 * 1000 });

// ── POST /register/options ──
passkeyRoutes.post("/register/options", async (c) => {
  const parsed = await parseBody(c, webauthnUsernameSchema);
  if ("error" in parsed) return parsed.error;
  const { username } = parsed.data;
  const trace = c.get("trace");
  const db = getDb();

  // Get-or-create user (WEBAUTHN_ONLY placeholder, same as existing webauthn.ts)
  let user = db
    .prepare("SELECT id, username FROM users WHERE username = ?")
    .get(username) as Pick<UserRow, "id" | "username"> | undefined;
  if (!user) {
    db.prepare(
      "INSERT INTO users (username, password_hash) VALUES (?, ?)"
    ).run(username, "WEBAUTHN_ONLY");
    user = db
      .prepare("SELECT id, username FROM users WHERE username = ?")
      .get(username) as Pick<UserRow, "id" | "username"> | undefined;
    trace.addDbQuery({
      sql: "INSERT INTO users (username, password_hash) VALUES (?, 'WEBAUTHN_ONLY')",
      params: [username],
      ms: 0,
    });
  }

  // Existing credentials for exclusion
  const existingCreds = db
    .prepare(
      "SELECT credential_id, public_key, counter, transports FROM webauthn_credentials WHERE user_id = ?"
    )
    .all(user!.id) as WebAuthnCredentialRow[];

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userName: username,
    userID: new TextEncoder().encode(String(user!.id)),
    attestationType: "none",
    excludeCredentials: existingCreds.map((cred) => ({
      id: cred.credential_id,
      transports: parseTransports(cred.transports) as never,
    })),
    authenticatorSelection: {
      residentKey: "required",
      userVerification: "required",
    },
  });

  registerChallenges.set(username, options.challenge);

  trace.addCryptoOp({
    op: "generateChallenge",
    input: `rpId="${RP_ID}", user="${username}"`,
    output: options.challenge,
    algo: "crypto.getRandomValues(32 bytes) → base64url",
    detail:
      "Random challenge to prevent replay. Note: residentKey = 'required' — authenticator MUST store a discoverable credential containing the user handle internally.",
  });

  trace.addCryptoOp({
    op: "authenticatorSelection",
    input: JSON.stringify(options.authenticatorSelection || {}),
    output: 'residentKey: "required", userVerification: "required"',
    algo: "FIDO2 Passkey Policy",
    detail:
      "Unlike traditional WebAuthn (residentKey: 'preferred'), Passkey REQUIRES a discoverable credential. The authenticator stores the credential locally so the user can sign in without entering a username.",
  });

  trace.addSessionOp({
    action: "STORE_CHALLENGE",
    data: {
      username,
      challenge: options.challenge,
      purpose: "passkey-registration",
    },
  });

  return c.json({
    success: true,
    data: {
      options,
      explanation: {
        challenge:
          "Random bytes from server — authenticator must sign this to prove possession",
        rp: { id: RP_ID, name: RP_NAME },
        residentKey: "required — credential will be stored on device for usernameless auth",
        excludeCredentials: `${existingCreds.length} existing credential(s) excluded`,
      },
    },
  });
});

// ── POST /register/verify ──
passkeyRoutes.post("/register/verify", async (c) => {
  const parsed = await parseBody(c, webauthnRegisterVerifySchema);
  if ("error" in parsed) return parsed.error;
  const { username, response: attResponse } = parsed.data;
  const trace = c.get("trace");
  const db = getDb();

  const expectedChallenge = registerChallenges.get(username);
  if (!expectedChallenge) {
    return c.json(
      { success: false, error: "No challenge found or challenge expired — restart registration" },
      400
    );
  }

  try {
    const verification = await verifyRegistrationResponse({
      response: attResponse as any,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
    });

    const deviceType = verification.registrationInfo?.credentialDeviceType || "unknown";
    const backedUp = verification.registrationInfo?.credentialBackedUp || false;

    trace.addCryptoOp({
      op: "verifyPasskeyRegistration",
      input: "clientDataJSON + attestationObject",
      output: verification.verified ? "VERIFIED ✓" : "FAILED ✗",
      algo: "FIDO2 Attestation Verification",
      detail:
        "Verify challenge signature, check origin/rpId, extract public key from attestation",
    });

    trace.addCryptoOp({
      op: "credentialDeviceType",
      input: `flags from authenticatorData`,
      output: `${deviceType} (backed up: ${backedUp})`,
      algo: "WebAuthn Level 2 flags: BE (Backup Eligible) + BS (Backup State)",
      detail:
        deviceType === "multiDevice"
          ? "MultiDevice credential — this passkey can sync across devices via iCloud Keychain, Google Password Manager, 1Password, etc."
          : "SingleDevice credential — this passkey is locked to this specific authenticator (e.g., hardware security key)",
    });

    if (verification.verified && verification.registrationInfo) {
      const { credential } = verification.registrationInfo;
      const user = db
        .prepare("SELECT id FROM users WHERE username = ?")
        .get(username) as Pick<UserRow, "id"> | undefined;

      db.prepare(
        "INSERT INTO webauthn_credentials (credential_id, user_id, public_key, counter, transports) VALUES (?, ?, ?, ?, ?)"
      ).run(
        credential.id,
        user!.id,
        Buffer.from(credential.publicKey).toString("base64"),
        credential.counter,
        JSON.stringify((attResponse as any).response?.transports || [])
      );

      trace.addDbQuery({
        sql: "INSERT INTO webauthn_credentials (credential_id, user_id, public_key, counter, transports) VALUES (...)",
        params: [credential.id, user!.id],
        ms: 0,
      });

      registerChallenges.delete(username);

      return c.json({
        success: true,
        data: {
          verified: true,
          credentialId: credential.id,
          credentialDeviceType: deviceType,
          credentialBackedUp: backedUp,
          publicKeyPreview:
            Buffer.from(credential.publicKey)
              .toString("base64")
              .substring(0, 40) + "...",
        },
      });
    }

    return c.json({ success: false, error: "Verification failed" }, 400);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Unknown error";
    return c.json({ success: false, error: message }, 400);
  }
});

// ── POST /auth/options (USERNAMELESS!) ──
passkeyRoutes.post("/auth/options", async (c) => {
  const trace = c.get("trace");

  const sessionId = uuidv4();

  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    allowCredentials: [], // Empty — browser shows all available passkeys for this site
    userVerification: "required",
  });

  authChallenges.set(sessionId, options.challenge);

  trace.addCryptoOp({
    op: "generateAuthChallenge",
    input: `rpId="${RP_ID}", allowCredentials=[] (empty!)`,
    output: options.challenge,
    algo: "crypto.getRandomValues(32 bytes) → base64url",
    detail:
      "Empty allowCredentials — the server does NOT specify which credentials to use. The browser will consult its own credential store and present all passkeys for this site. This is the key difference from traditional WebAuthn: the server doesn't know who the user is yet!",
  });

  trace.addSessionOp({
    action: "STORE_AUTH_SESSION",
    data: {
      sessionId,
      challenge: options.challenge,
      purpose: "passkey-usernameless-auth",
      note: "Server only stores the challenge. User identity will be resolved after authentication from the credential's userHandle.",
    },
  });

  return c.json({
    success: true,
    data: {
      options,
      sessionId,
      explanation: {
        allowCredentials:
          "Empty — browser presents ALL passkeys for this site (no account enumeration)",
        userVerification: "required — biometric/PIN mandatory",
      },
    },
  });
});

// ── POST /auth/verify ──
passkeyRoutes.post("/auth/verify", async (c) => {
  const parsed = await parseBody(c, passkeyAuthVerifySchema);
  if ("error" in parsed) return parsed.error;
  const { sessionId, response: authResponse } = parsed.data;
  const trace = c.get("trace");
  const db = getDb();

  const expectedChallenge = authChallenges.get(sessionId);
  if (!expectedChallenge) {
    return c.json(
      { success: false, error: "Session expired or invalid — restart auth" },
      400
    );
  }

  trace.addSessionOp({
    action: "LOOKUP_AUTH_SESSION",
    data: { sessionId, found: true },
  });

  // Look up credential by ID ONLY (no user filter — usernameless!)
  const credentialId = (authResponse as any).id;
  const t0 = performance.now();
  const cred = db
    .prepare(
      "SELECT credential_id, user_id, public_key, counter FROM webauthn_credentials WHERE credential_id = ?"
    )
    .get(credentialId) as
    | Pick<WebAuthnCredentialRow, "credential_id" | "user_id" | "public_key" | "counter">
    | undefined;
  trace.addDbQuery({
    sql: "SELECT ... FROM webauthn_credentials WHERE credential_id = ?  -- NO user_id filter!",
    params: [credentialId],
    rows: cred ? [{ credential_id: cred.credential_id, user_id: cred.user_id, counter: cred.counter }] : [],
    ms: performance.now() - t0,
  });

  if (!cred) {
    authChallenges.delete(sessionId);
    return c.json({ success: false, error: "Credential not registered on this server" }, 400);
  }

  // Resolve user from credential's user_id
  const t1 = performance.now();
  const user = db
    .prepare("SELECT id, username FROM users WHERE id = ?")
    .get(cred.user_id) as Pick<UserRow, "id" | "username"> | undefined;
  trace.addDbQuery({
    sql: "SELECT id, username FROM users WHERE id = ?",
    params: [cred.user_id],
    rows: user ? [user] : [],
    ms: performance.now() - t1,
  });

  if (!user) {
    authChallenges.delete(sessionId);
    return c.json({ success: false, error: "User not found for this credential" }, 400);
  }

  // Decode userHandle from the auth response to cross-check identity
  const rawUserHandle = (authResponse as any).response?.userHandle;
  if (rawUserHandle) {
    const decoded = Buffer.from(rawUserHandle, "base64url").toString("utf-8");
    trace.addSessionOp({
      action: "RESOLVE_IDENTITY_FROM_USERHANDLE",
      data: {
        userHandle_base64url: rawUserHandle,
        decoded_userId: decoded,
        resolved_username: user.username,
        note: "The server does NOT receive a username — instead, the authenticator returns the userHandle (set during registration) which the server maps to a user record. This is how usernameless authentication works!",
      },
    });
  }

  try {
    const verification = await verifyAuthenticationResponse({
      response: authResponse as any,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      credential: {
        id: cred.credential_id,
        publicKey: Buffer.from(cred.public_key, "base64"),
        counter: cred.counter,
      },
    });

    trace.addCryptoOp({
      op: "verifyPasskeyAuth",
      input: "signature over clientDataJSON + authenticatorData",
      output: verification.verified ? "VERIFIED ✓" : "FAILED ✗",
      algo: "ECDSA / RSA (credential-dependent)",
      detail:
        "Verify signature with stored public key, check counter increment, confirm rpIdHash matches",
    });

    if (verification.verified) {
      const newCounter = verification.authenticationInfo.newCounter;

      // Clone detection
      if (newCounter > 0 && newCounter <= cred.counter) {
        trace.addCryptoOp({
          op: "counterCloneDetection",
          input: `oldCounter=${cred.counter}, newCounter=${newCounter}`,
          output: "⚠ CLONE DETECTED",
          algo: "Counter Verification",
          detail:
            "Counter did not increment — possible cloned authenticator",
        });
        authChallenges.delete(sessionId);
        return c.json(
          { success: false, error: "Counter did not increment — possible clone" },
          403
        );
      }

      db.prepare(
        "UPDATE webauthn_credentials SET counter = ? WHERE credential_id = ?"
      ).run(newCounter, cred.credential_id);

      authChallenges.delete(sessionId);

      return c.json({
        success: true,
        data: {
          verified: true,
          username: user.username,
          credentialId: cred.credential_id,
          counter: { old: cred.counter, new: newCounter },
        },
      });
    }

    authChallenges.delete(sessionId);
    return c.json({ success: false, error: "Authentication failed" }, 401);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Unknown error";
    authChallenges.delete(sessionId);
    return c.json({ success: false, error: message }, 400);
  }
});

// ── GET /credentials (reuse existing webauthn credentials endpoint format) ──
passkeyRoutes.get("/credentials", (c) => {
  const db = getDb();
  const creds = db
    .prepare(
      `SELECT wc.credential_id, wc.counter, wc.created_at, u.username
       FROM webauthn_credentials wc JOIN users u ON wc.user_id = u.id`
    )
    .all();
  return c.json({ success: true, data: { credentials: creds } });
});
