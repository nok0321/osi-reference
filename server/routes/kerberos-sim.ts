import { Hono } from "hono";
import crypto from "crypto";
import { getDb } from "../db/schema.js";
import { parseBody, kerberosAsReqSchema, kerberosTgsReqSchema, kerberosApReqSchema } from "../validation.js";

export const kerberoSimRoutes = new Hono();

/*
 * EDUCATIONAL SIMULATION — NOT a real Kerberos implementation.
 *
 * Simplifications vs real MIT/Heimdal Kerberos:
 * - Key derivation: real Kerberos uses string2key (PBKDF2 with 4096+ iterations, per-user salt).
 *   This demo uses plain SHA-256 for simplicity, which lacks salt and iteration hardening.
 * - Encryption: real KDCs use AES-CTS-HMAC-SHA256 or similar AEAD modes.
 *   This demo uses AES-256-CBC without authentication (no HMAC/GCM).
 * - Ticket structure: real tickets are ASN.1/DER encoded per RFC 4120.
 *   This demo uses JSON for readability.
 * - Mutual authentication (AP-REP): omitted for brevity.
 * - Pre-authentication (PA-ENC-TIMESTAMP): omitted.
 */

// Derive a proper 32-byte key via SHA-256 hash (AES-256 requires exactly 32 bytes)
const KDC_SECRET = crypto.createHash("sha256").update("osi-demo-kdc-master-key").digest();
const REALM = "OSI-DEMO.LOCAL";

function encrypt(data: string, key: Buffer): { encrypted: string; iv: string } {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  let encrypted = cipher.update(data, "utf8", "base64");
  encrypted += cipher.final("base64");
  return { encrypted, iv: iv.toString("base64") };
}

function decrypt(encrypted: string, key: Buffer, iv: string): string {
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, Buffer.from(iv, "base64"));
  let decrypted = decipher.update(encrypted, "base64", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

// AS-REQ: Client → KDC Authentication Server
kerberoSimRoutes.post("/as-req", async (c) => {
  const parsed = await parseBody(c, kerberosAsReqSchema);
  if ("error" in parsed) return parsed.error;
  const { principal, password } = parsed.data;
  const trace = c.get("trace");
  const db = getDb();

  // Simulate password verification (in real Kerberos, derived from password)
  const clientKey = crypto.createHash("sha256").update(password || "password").digest();
  trace.addCryptoOp({
    op: "deriveClientKey",
    input: `password → SHA-256`,
    output: clientKey.toString("base64").substring(0, 20) + "...",
    algo: "SHA-256",
    detail: "In real Kerberos: string2key function derives key from password",
  });

  // Generate session key for TGT
  const sessionKey = crypto.randomBytes(32);
  trace.addCryptoOp({
    op: "generateSessionKey",
    input: "crypto.randomBytes(32)",
    output: sessionKey.toString("base64").substring(0, 20) + "...",
    algo: "AES-256 key",
    detail: "Random session key for client ↔ TGS communication",
  });

  // Create TGT (encrypted with KDC secret)
  const tgtData = JSON.stringify({
    principal: `${principal}@${REALM}`,
    sessionKey: sessionKey.toString("base64"),
    validUntil: new Date(Date.now() + 8 * 3600 * 1000).toISOString(),
    flags: ["FORWARDABLE", "RENEWABLE", "INITIAL"],
  });

  const tgt = encrypt(tgtData, KDC_SECRET);
  trace.addCryptoOp({
    op: "encryptTGT",
    input: `TGT plaintext (${tgtData.length} bytes)`,
    output: tgt.encrypted.substring(0, 30) + "...",
    algo: "AES-256-CBC",
    detail: "TGT encrypted with KDC master key — only KDC can decrypt",
  });

  // Encrypt session key with client's key (so only client can read it)
  const encSessionKey = encrypt(sessionKey.toString("base64"), clientKey);
  trace.addCryptoOp({
    op: "encryptSessionKey",
    input: `sessionKey for client`,
    output: encSessionKey.encrypted.substring(0, 30) + "...",
    algo: "AES-256-CBC",
    detail: "Session key encrypted with client's key (derived from password)",
  });

  // Store ticket (is_attack_sim=0 で正常系チケットを明示的に挿入 / E-3)
  db.prepare(
    "INSERT INTO kerberos_tickets (ticket_type, principal, realm, encrypted_data, session_key, valid_until, is_attack_sim) VALUES (?, ?, ?, ?, ?, ?, 0)"
  ).run("TGT", principal, REALM, tgt.encrypted, sessionKey.toString("base64"), new Date(Date.now() + 8 * 3600 * 1000).toISOString());

  trace.addDbQuery({
    sql: "INSERT INTO kerberos_tickets (...) VALUES (...) [is_attack_sim=0]",
    params: ["TGT", principal, REALM],
    ms: 0,
  });

  return c.json({
    success: true,
    data: {
      step: "AS-REP",
      tgt: { encrypted: tgt.encrypted, iv: tgt.iv },
      encryptedSessionKey: { encrypted: encSessionKey.encrypted, iv: encSessionKey.iv },
      decryptedTgt: JSON.parse(tgtData),
      realm: REALM,
      message: "TGT issued — client can now request service tickets",
    },
  });
});

// TGS-REQ: Client → KDC Ticket Granting Server
kerberoSimRoutes.post("/tgs-req", async (c) => {
  const parsed = await parseBody(c, kerberosTgsReqSchema);
  if ("error" in parsed) return parsed.error;
  const { tgt, tgtIv, servicePrincipal } = parsed.data;
  const trace = c.get("trace");
  const db = getDb();

  // Decrypt TGT with KDC secret
  interface TgtPayload { principal: string; sessionKey: string; validUntil: string; flags: string[] }
  let tgtData: TgtPayload;
  try {
    const decrypted = decrypt(tgt, KDC_SECRET, tgtIv);
    tgtData = JSON.parse(decrypted);
    trace.addCryptoOp({
      op: "decryptTGT",
      input: tgt.substring(0, 30) + "...",
      output: `principal=${tgtData.principal}`,
      algo: "AES-256-CBC",
      detail: "KDC decrypts TGT with master key to verify client identity",
    });
  } catch {
    return c.json({ success: false, error: "Invalid TGT" }, 400);
  }

  // Check expiry
  if (new Date(tgtData.validUntil) < new Date()) {
    return c.json({ success: false, error: "TGT expired" }, 401);
  }

  // Generate service session key
  const serviceSessionKey = crypto.randomBytes(32);
  trace.addCryptoOp({
    op: "generateServiceSessionKey",
    input: "crypto.randomBytes(32)",
    output: serviceSessionKey.toString("base64").substring(0, 20) + "...",
    algo: "AES-256 key",
    detail: "New session key for client ↔ service communication",
  });

  // Create service ticket (encrypted with service key — we simulate with KDC_SECRET)
  const serviceTicketData = JSON.stringify({
    principal: tgtData.principal,
    servicePrincipal: `${servicePrincipal}@${REALM}`,
    sessionKey: serviceSessionKey.toString("base64"),
    validUntil: new Date(Date.now() + 1 * 3600 * 1000).toISOString(),
  });
  const serviceTicket = encrypt(serviceTicketData, KDC_SECRET);
  trace.addCryptoOp({
    op: "encryptServiceTicket",
    input: `Service ticket (${serviceTicketData.length} bytes)`,
    output: serviceTicket.encrypted.substring(0, 30) + "...",
    algo: "AES-256-CBC",
    detail: `Encrypted with service's secret key — only ${servicePrincipal} can decrypt`,
  });

  // Store (is_attack_sim=0 で正常系サービスチケットを挿入 / E-3)
  db.prepare(
    "INSERT INTO kerberos_tickets (ticket_type, principal, realm, encrypted_data, session_key, valid_until, is_attack_sim) VALUES (?, ?, ?, ?, ?, ?, 0)"
  ).run("ServiceTicket", servicePrincipal, REALM, serviceTicket.encrypted, serviceSessionKey.toString("base64"),
    new Date(Date.now() + 1 * 3600 * 1000).toISOString());

  return c.json({
    success: true,
    data: {
      step: "TGS-REP",
      serviceTicket: { encrypted: serviceTicket.encrypted, iv: serviceTicket.iv },
      decryptedServiceTicket: JSON.parse(serviceTicketData),
      message: `Service ticket for ${servicePrincipal} issued`,
    },
  });
});

// AP-REQ: Client → Service (verify ticket)
kerberoSimRoutes.post("/ap-req", async (c) => {
  const parsed = await parseBody(c, kerberosApReqSchema);
  if ("error" in parsed) return parsed.error;
  const { serviceTicket, serviceTicketIv } = parsed.data;
  const trace = c.get("trace");

  try {
    const decrypted = decrypt(serviceTicket, KDC_SECRET, serviceTicketIv);
    const ticketData = JSON.parse(decrypted);
    trace.addCryptoOp({
      op: "decryptServiceTicket",
      input: serviceTicket.substring(0, 30) + "...",
      output: `client=${ticketData.principal}, service=${ticketData.servicePrincipal}`,
      algo: "AES-256-CBC",
      detail: "Service decrypts ticket with its secret key to verify client",
    });

    if (new Date(ticketData.validUntil) < new Date()) {
      return c.json({ success: false, error: "Service ticket expired" }, 401);
    }

    return c.json({
      success: true,
      data: {
        step: "AP-REP",
        authenticated: true,
        principal: ticketData.principal,
        service: ticketData.servicePrincipal,
        decryptedTicket: ticketData,
        message: "Client authenticated to service via Kerberos ticket",
      },
    });
  } catch {
    return c.json({ success: false, error: "Invalid service ticket" }, 400);
  }
});

kerberoSimRoutes.get("/ticket-cache", (c) => {
  if (process.env.NODE_ENV === "production") {
    return c.json({ success: false, error: "Debug endpoint disabled in production" }, 403);
  }
  const db = getDb();
  // 正常系チケットのみ表示 (E-3: 攻撃シミュレーションのレコードは別経路で確認)
  const tickets = db.prepare("SELECT ticket_type, principal, realm, valid_until, created_at FROM kerberos_tickets WHERE is_attack_sim = 0 ORDER BY created_at DESC").all();
  return c.json({ success: true, data: { tickets } });
});

kerberoSimRoutes.post("/reset", (c) => {
  if (process.env.NODE_ENV === "production") {
    return c.json({ success: false, error: "Reset disabled in production" }, 403);
  }
  const db = getDb();
  // 正常系チケットのみ削除 (E-3: 攻撃ログ用レコードを保護)
  db.prepare("DELETE FROM kerberos_tickets WHERE is_attack_sim = 0").run();
  return c.json({ success: true, data: { message: "Ticket cache cleared" } });
});
