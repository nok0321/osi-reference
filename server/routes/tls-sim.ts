import { Hono } from "hono";
import crypto from "crypto";
import { parseBody, tlsSessionSchema } from "../validation.js";
import { createTtlStore } from "../utils/ttl-store.js";

export const tlsSimRoutes = new Hono();

/*
 * EDUCATIONAL SIMULATION — NOT a real TLS 1.3 implementation.
 *
 * Simplifications vs RFC 8446 (TLS 1.3):
 * - Key derivation: real TLS 1.3 uses HKDF-Extract / HKDF-Expand-Label (RFC 5869).
 *   This demo uses simplified HMAC-SHA384 calls to illustrate the concept.
 * - Certificate verification: real TLS verifies X.509 certificate chains against trusted CAs.
 *   This demo generates a self-signed cert for display only.
 * - Handshake transcript: real TLS 1.3 hashes all handshake messages into the key schedule.
 *   This demo uses only clientRandom + serverRandom.
 * - Encrypted Extensions / Finished messages: omitted.
 * - 0-RTT (early data): not simulated.
 * - AEAD encryption: the demo derives keys but never actually encrypts application data.
 */

interface HandshakeState {
  clientRandom: string;
  serverRandom: string;
  serverKeyPair: { publicKey: string; privateKey: string };
  clientPublicKey?: string;
  sharedSecret?: string;
  handshakeSecret?: string;
  masterSecret?: string;
}
const handshakes = createTtlStore<HandshakeState>({ ttlMs: 5 * 60 * 1000 });

// Step 1: ClientHello
tlsSimRoutes.post("/client-hello", async (c) => {
  const parsed = await parseBody(c, tlsSessionSchema);
  if ("error" in parsed) return parsed.error;
  const { sessionId } = parsed.data;
  const trace = c.get("trace");

  const clientRandom = crypto.randomBytes(32).toString("hex");
  trace.addCryptoOp({
    op: "generateClientRandom",
    input: "crypto.randomBytes(32)",
    output: clientRandom.substring(0, 32) + "...",
    algo: "CSPRNG",
    detail: "32 bytes of cryptographically secure random data",
  });

  // Client generates ECDHE key pair
  const clientECDH = crypto.createECDH("prime256v1");
  clientECDH.generateKeys();
  const clientPubKey = clientECDH.getPublicKey("hex");

  trace.addCryptoOp({
    op: "generateECDHKeyPair(client)",
    input: "curve=P-256 (prime256v1)",
    output: `publicKey=${clientPubKey.substring(0, 30)}...`,
    algo: "ECDHE P-256",
    detail: "Client generates ephemeral key pair for key exchange",
  });

  // Generate server ECDH key pair
  const serverECDH = crypto.createECDH("prime256v1");
  serverECDH.generateKeys();
  const serverRandom = crypto.randomBytes(32).toString("hex");

  handshakes.set(sessionId, {
    clientRandom,
    serverRandom,
    serverKeyPair: {
      publicKey: serverECDH.getPublicKey("hex"),
      privateKey: serverECDH.getPrivateKey("hex"),
    },
    clientPublicKey: clientPubKey,
  });

  return c.json({
    success: true,
    data: {
      step: "ClientHello",
      clientRandom,
      clientPublicKey: clientPubKey,
      supportedCipherSuites: [
        "TLS_AES_256_GCM_SHA384",
        "TLS_AES_128_GCM_SHA256",
        "TLS_CHACHA20_POLY1305_SHA256",
      ],
      supportedGroups: ["x25519", "secp256r1", "secp384r1"],
      signatureAlgorithms: ["ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256"],
      tlsVersion: "TLS 1.3",
    },
  });
});

// Step 2: ServerHello + Key Exchange
tlsSimRoutes.post("/server-hello", async (c) => {
  const parsed = await parseBody(c, tlsSessionSchema);
  if ("error" in parsed) return parsed.error;
  const { sessionId } = parsed.data;
  const trace = c.get("trace");

  const state = handshakes.get(sessionId);
  if (!state) {
    return c.json({ success: false, error: "No handshake in progress" }, 400);
  }

  trace.addCryptoOp({
    op: "generateServerRandom",
    input: "crypto.randomBytes(32)",
    output: state.serverRandom.substring(0, 32) + "...",
    algo: "CSPRNG",
  });

  trace.addCryptoOp({
    op: "selectCipherSuite",
    input: "Client offered: AES_256_GCM, AES_128_GCM, CHACHA20",
    output: "TLS_AES_256_GCM_SHA384",
    algo: "Server preference",
    detail: "Server selects strongest mutually supported cipher suite",
  });

  return c.json({
    success: true,
    data: {
      step: "ServerHello",
      serverRandom: state.serverRandom,
      serverPublicKey: state.serverKeyPair.publicKey,
      selectedCipherSuite: "TLS_AES_256_GCM_SHA384",
      selectedGroup: "secp256r1",
      tlsVersion: "TLS 1.3",
    },
  });
});

// Step 3: Key Exchange computation
tlsSimRoutes.post("/key-exchange", async (c) => {
  const parsed = await parseBody(c, tlsSessionSchema);
  if ("error" in parsed) return parsed.error;
  const { sessionId } = parsed.data;
  const trace = c.get("trace");

  const state = handshakes.get(sessionId);
  if (!state || !state.clientPublicKey) {
    return c.json({ success: false, error: "Missing handshake state" }, 400);
  }

  // Compute shared secret
  const serverECDH = crypto.createECDH("prime256v1");
  serverECDH.setPrivateKey(state.serverKeyPair.privateKey, "hex");
  const sharedSecret = serverECDH.computeSecret(Buffer.from(state.clientPublicKey, "hex")).toString("hex");

  trace.addCryptoOp({
    op: "ECDHE computeSharedSecret",
    input: `serverPrivKey × clientPubKey`,
    output: sharedSecret.substring(0, 32) + "...",
    algo: "ECDHE P-256",
    detail: "Both sides compute same shared secret: server_priv × client_pub = client_priv × server_pub",
  });

  // Derive handshake secret (simplified HKDF)
  const handshakeSecret = crypto.createHmac("sha384", sharedSecret)
    .update(`${state.clientRandom}${state.serverRandom}`)
    .digest("hex");

  trace.addCryptoOp({
    op: "HKDF-Extract(handshakeSecret)",
    input: `sharedSecret + clientRandom + serverRandom`,
    output: handshakeSecret.substring(0, 32) + "...",
    algo: "HMAC-SHA384 (simplified HKDF)",
    detail: "Derive handshake traffic keys from shared secret and random values",
  });

  // Derive master secret
  const masterSecret = crypto.createHmac("sha384", handshakeSecret)
    .update("master-secret-derivation")
    .digest("hex");

  trace.addCryptoOp({
    op: "HKDF-Expand(masterSecret)",
    input: `handshakeSecret → master secret derivation`,
    output: masterSecret.substring(0, 32) + "...",
    algo: "HMAC-SHA384 (simplified HKDF)",
    detail: "Final master secret for application data encryption",
  });

  // Update the handshake state with derived secrets
  handshakes.set(sessionId, { ...state, sharedSecret, handshakeSecret, masterSecret });

  return c.json({
    success: true,
    data: {
      step: "KeyExchange",
      sharedSecret: sharedSecret.substring(0, 32) + "...",
      handshakeSecret: handshakeSecret.substring(0, 32) + "...",
      masterSecret: masterSecret.substring(0, 32) + "...",
      explanation: {
        ecdhe: "Elliptic Curve Diffie-Hellman Ephemeral — both sides derive same secret without transmitting it",
        forwardSecrecy: "Ephemeral keys are discarded after handshake — past sessions cannot be decrypted even if long-term key is compromised",
      },
    },
  });
});

// Step 4: Generate self-signed certificate for demo
tlsSimRoutes.get("/certificate", (c) => {
  const trace = c.get("trace");

  // Generate a fresh self-signed certificate
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  trace.addCryptoOp({
    op: "generateRSAKeyPair",
    input: "modulusLength=2048",
    output: `publicKey=${publicKey.substring(27, 60)}...`,
    algo: "RSA-2048",
    detail: "Key pair for certificate signing (in production: from CA)",
  });

  return c.json({
    success: true,
    data: {
      certificate: {
        subject: "CN=localhost, O=OSI Demo, C=JP",
        issuer: "CN=OSI Demo CA, O=OSI Demo, C=JP",
        serialNumber: crypto.randomBytes(16).toString("hex"),
        validFrom: new Date().toISOString(),
        validTo: new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString(),
        signatureAlgorithm: "SHA256withRSA",
        publicKey: publicKey.split("\n").slice(1, -2).join("").substring(0, 60) + "...",
        fingerprint: crypto.createHash("sha256").update(publicKey).digest("hex").substring(0, 40) + "...",
      },
      publicKeyPem: publicKey,
      explanation: {
        chain: ["End-entity (localhost)", "Intermediate CA", "Root CA"],
        verification: "Browser verifies chain: end-entity → intermediate → trusted root",
      },
    },
  });
});

// Finish handshake
tlsSimRoutes.post("/finish", async (c) => {
  const parsed = await parseBody(c, tlsSessionSchema);
  if ("error" in parsed) return parsed.error;
  const { sessionId } = parsed.data;
  const trace = c.get("trace");

  const state = handshakes.get(sessionId);
  if (!state?.masterSecret) {
    return c.json({ success: false, error: "Handshake not complete" }, 400);
  }

  // Derive application keys
  const clientWriteKey = crypto.createHmac("sha256", state.masterSecret)
    .update("client-write-key").digest("hex");
  const serverWriteKey = crypto.createHmac("sha256", state.masterSecret)
    .update("server-write-key").digest("hex");

  trace.addCryptoOp({
    op: "deriveApplicationKeys",
    input: `masterSecret → client/server write keys`,
    output: `clientKey=${clientWriteKey.substring(0, 16)}... serverKey=${serverWriteKey.substring(0, 16)}...`,
    algo: "HKDF-SHA256",
    detail: "Separate keys for client→server and server→client encryption",
  });

  // Cleanup
  handshakes.delete(sessionId);

  return c.json({
    success: true,
    data: {
      step: "Finished",
      clientWriteKey: clientWriteKey.substring(0, 32) + "...",
      serverWriteKey: serverWriteKey.substring(0, 32) + "...",
      message: "✓ TLS 1.3 handshake complete — application data is now encrypted",
      cipherSuite: "TLS_AES_256_GCM_SHA384",
    },
  });
});
