import { Hono, type Context } from "hono";
import crypto from "crypto";
import { v4 as uuidv4 } from "uuid";
import { getDb } from "../db/schema.js";
import { parseBody, ssoLoginSchema, ssoAccessServiceSchema, apikeyGenerateSchema, apikeyHmacSchema } from "../validation.js";
import type { UserRow, ApiKeyRow } from "../../shared/api-types.js";
import type { TraceCollector } from "../middleware/trace-logger.js";
import { createTtlStore } from "../utils/ttl-store.js";

export const ssoApikeyRoutes = new Hono();

// ── SSO Session Propagation ──
interface SsoSession {
  userId: number;
  username: string;
  services: string[];
}
const ssoSessions = createTtlStore<SsoSession>({ ttlMs: 30 * 60 * 1000 });

ssoApikeyRoutes.post("/login", async (c) => {
  const parsed = await parseBody(c, ssoLoginSchema);
  if ("error" in parsed) return parsed.error;
  const { username } = parsed.data;
  const trace = c.get("trace");
  const db = getDb();

  // Validate user exists in database
  const user = db.prepare("SELECT id, username FROM users WHERE username = ?").get(username) as Pick<UserRow, "id" | "username"> | undefined;
  if (!user) {
    return c.json({ success: false, error: "User not found" }, 404);
  }

  const ssoToken = uuidv4();
  ssoSessions.set(ssoToken, { userId: user.id, username: user.username, services: [] });

  trace.addSessionOp({
    action: "SSO_SESSION_CREATE",
    data: { ssoToken, username, services: [] },
  });

  return c.json({
    success: true,
    data: {
      ssoToken,
      username,
      message: "SSO session created — use this token to access services",
    },
  });
});

ssoApikeyRoutes.post("/access-service", async (c) => {
  const parsed = await parseBody(c, ssoAccessServiceSchema);
  if ("error" in parsed) return parsed.error;
  const { ssoToken, serviceName } = parsed.data;
  const trace = c.get("trace");

  const session = ssoSessions.get(ssoToken);
  if (!session) {
    return c.json({ success: false, error: "Invalid or expired SSO token" }, 401);
  }

  if (!session.services.includes(serviceName)) {
    session.services.push(serviceName);
    // Re-set to persist the mutation through the TTL store
    ssoSessions.set(ssoToken, session);
  }

  trace.addSessionOp({
    action: "SSO_SERVICE_ACCESS",
    data: {
      ssoToken,
      serviceName,
      allServices: session.services,
      message: `User "${session.username}" accessed ${serviceName} via SSO — no re-authentication needed`,
    },
  });

  return c.json({
    success: true,
    data: {
      authenticated: true,
      username: session.username,
      service: serviceName,
      accessedServices: session.services,
      message: `Access granted to ${serviceName} via SSO (no password re-entry)`,
    },
  });
});

ssoApikeyRoutes.get("/sessions", (c) => {
  if (process.env.NODE_ENV === "production") {
    return c.json({ success: false, error: "Debug endpoint disabled in production" }, 403);
  }
  return c.json({ success: true, data: { message: "SSO sessions are stored in memory — use /access-service to test" } });
});

// ── API Key ──
ssoApikeyRoutes.post("/apikey/generate", async (c) => {
  const parsed = await parseBody(c, apikeyGenerateSchema);
  if ("error" in parsed) return parsed.error;
  const { name } = parsed.data;
  const trace = c.get("trace");
  const db = getDb();

  // Generate key
  const rawKey = crypto.randomBytes(32).toString("base64url");
  const keyId = `key_${uuidv4().substring(0, 8)}`;
  const prefix = rawKey.substring(0, 8);
  const keyHash = crypto.createHash("sha256").update(rawKey).digest("hex");

  trace.addCryptoOp({
    op: "generateApiKey",
    input: "crypto.randomBytes(32)",
    output: `${prefix}...`,
    algo: "base64url",
    detail: "Raw key shown ONCE to user — only hash is stored",
  });

  trace.addCryptoOp({
    op: "hashApiKey",
    input: `rawKey="${prefix}..."`,
    output: keyHash.substring(0, 20) + "...",
    algo: "SHA-256",
    detail: "Server stores hash only — cannot recover original key",
  });

  db.prepare(
    "INSERT INTO api_keys (key_id, key_prefix, key_hash, name) VALUES (?, ?, ?, ?)"
  ).run(keyId, prefix, keyHash, name || "default");

  trace.addDbQuery({
    sql: "INSERT INTO api_keys (key_id, key_prefix, key_hash, name) VALUES (?, ?, ?, ?)",
    params: [keyId, prefix, "(hash)", name || "default"],
    ms: 0,
  });

  return c.json({
    success: true,
    data: {
      keyId,
      rawKey,
      prefix,
      warning: "⚠ Save this key now — it will NOT be shown again!",
    },
  });
});

// Verify API key via header
ssoApikeyRoutes.post("/apikey/verify/header", async (c) => {
  const apiKey = c.req.header("X-API-Key") || "";
  const trace = c.get("trace");
  return verifyApiKey(apiKey, "Header (X-API-Key)", trace, c);
});

// Verify API key via query
ssoApikeyRoutes.get("/apikey/verify/query", (c) => {
  const apiKey = c.req.query("api_key") || "";
  const trace = c.get("trace");
  return verifyApiKey(apiKey, "Query Parameter (?api_key=...)", trace, c);
});

// HMAC signed request
ssoApikeyRoutes.post("/apikey/verify/hmac", async (c) => {
  const parsed = await parseBody(c, apikeyHmacSchema);
  if ("error" in parsed) return parsed.error;
  const { keyId, timestamp, body, signature } = parsed.data;
  const trace = c.get("trace");
  const db = getDb();

  const key = db.prepare("SELECT key_id, key_prefix, key_hash, name, created_at, last_used FROM api_keys WHERE key_id = ?").get(keyId) as ApiKeyRow | undefined;
  if (!key) {
    return c.json({ success: false, error: "Unknown key_id" }, 401);
  }

  // Reconstruct canonical string
  const canonical = `${timestamp}\n${JSON.stringify(body)}`;
  trace.addCryptoOp({
    op: "buildCanonicalString",
    input: `timestamp + body`,
    output: canonical.substring(0, 50) + "...",
    algo: "string concatenation",
    detail: "Canonical string = timestamp + newline + JSON body",
  });

  // Compute expected signature using key_hash as the secret
  const expectedSig = crypto.createHmac("sha256", key.key_hash).update(canonical).digest("hex");
  trace.addCryptoOp({
    op: "HMAC-SHA256",
    input: `secret=key_hash, data=canonical`,
    output: expectedSig.substring(0, 30) + "...",
    algo: "HMAC-SHA256",
    detail: "Server computes HMAC with stored key hash",
  });

  // Timing-safe comparison to prevent timing attacks
  // Buffer lengths must match for timingSafeEqual — reject early if not valid hex or wrong length
  const expectedBuf = Buffer.from(expectedSig, "hex");
  const providedBuf = signature ? Buffer.from(signature, "hex") : Buffer.alloc(0);
  const valid = providedBuf.length === expectedBuf.length
    ? crypto.timingSafeEqual(expectedBuf, providedBuf)
    : false;
  trace.addCryptoOp({
    op: "compareSignatures",
    input: `provided=${(signature || "").substring(0, 20)}... vs computed=${expectedSig.substring(0, 20)}...`,
    output: valid ? "MATCH ✓" : "MISMATCH ✗",
    algo: "crypto.timingSafeEqual",
    detail: valid ? "Request is authentic" : "Signature mismatch — request tampered or wrong key",
  });

  return c.json({
    success: true,
    data: { valid, keyId, canonical, expectedSignature: expectedSig },
  });
});

async function verifyApiKey(apiKey: string, method: string, trace: TraceCollector, c: Context) {
  const db = getDb();

  trace.addSessionOp({
    action: "READ_API_KEY",
    data: { method, value: apiKey ? `${apiKey.substring(0, 8)}...` : "(empty)" },
  });

  if (!apiKey) {
    return c.json({ success: false, error: `No API key provided via ${method}` }, 401);
  }

  const keyHash = crypto.createHash("sha256").update(apiKey).digest("hex");
  trace.addCryptoOp({
    op: "hashProvidedKey",
    input: `"${apiKey.substring(0, 8)}..."`,
    output: keyHash.substring(0, 20) + "...",
    algo: "SHA-256",
    detail: "Hash the provided key to compare with stored hash",
  });

  const key = db.prepare("SELECT key_id, key_prefix, key_hash, name, created_at, last_used FROM api_keys WHERE key_hash = ?").get(keyHash) as ApiKeyRow | undefined;
  trace.addDbQuery({
    sql: "SELECT key_id, name FROM api_keys WHERE key_hash = ?",
    params: [keyHash.substring(0, 20) + "..."],
    rows: key ? [{ key_id: key.key_id, name: key.name }] : [],
    ms: 0,
  });

  if (!key) {
    return c.json({ success: false, error: "Invalid API key" }, 401);
  }

  // Update last_used
  db.prepare("UPDATE api_keys SET last_used = datetime('now') WHERE key_id = ?").run(key.key_id);

  return c.json({
    success: true,
    data: {
      valid: true,
      keyId: key.key_id,
      name: key.name,
      method,
      message: `API key verified via ${method}`,
    },
  });
}
