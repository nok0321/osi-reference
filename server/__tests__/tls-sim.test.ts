import { describe, it, expect, beforeEach } from "vitest";
import { createTestApp, post, get } from "./test-helpers.js";
import type { Hono } from "hono";

let app: Hono;

beforeEach(() => {
  ({ app } = createTestApp());
});

/** Run ClientHello and return the response data. */
async function clientHello(testApp: Hono, sessionId: string) {
  const res = await post(testApp, "/api/tls/client-hello", { sessionId });
  expect(res.status).toBe(200);
  return res.json.data;
}

/** Run ServerHello and return the response data. */
async function serverHello(testApp: Hono, sessionId: string) {
  const res = await post(testApp, "/api/tls/server-hello", { sessionId });
  expect(res.status).toBe(200);
  return res.json.data;
}

/** Run KeyExchange and return the response data. */
async function keyExchange(testApp: Hono, sessionId: string) {
  const res = await post(testApp, "/api/tls/key-exchange", { sessionId });
  expect(res.status).toBe(200);
  return res.json.data;
}

describe("POST /api/tls/client-hello", () => {
  it("returns clientRandom, clientPublicKey, and cipher suites", async () => {
    const res = await post(app, "/api/tls/client-hello", { sessionId: "test-1" });
    expect(res.status).toBe(200);
    expect(res.json.success).toBe(true);
    expect(res.json.data.step).toBe("ClientHello");
    expect(res.json.data.clientRandom).toBeTruthy();
    expect(res.json.data.clientPublicKey).toBeTruthy();
    expect(res.json.data.supportedCipherSuites).toContain("TLS_AES_256_GCM_SHA384");
    expect(res.json.data.supportedGroups).toContain("secp256r1");
    expect(res.json.data.tlsVersion).toBe("TLS 1.3");
  });

  it("includes ECDHE crypto ops in _trace", async () => {
    const res = await post(app, "/api/tls/client-hello", { sessionId: "trace-test" });
    expect(res.status).toBe(200);
    const ops = res.json._trace?.cryptoOps ?? [];
    const opNames = ops.map((o: { op: string }) => o.op);
    expect(opNames).toContain("generateClientRandom");
    expect(opNames).toContain("generateECDHKeyPair(client)");
  });
});

describe("POST /api/tls/server-hello", () => {
  it("returns serverRandom and serverPublicKey after ClientHello", async () => {
    await clientHello(app, "sh-test");
    const res = await post(app, "/api/tls/server-hello", { sessionId: "sh-test" });
    expect(res.status).toBe(200);
    expect(res.json.success).toBe(true);
    expect(res.json.data.step).toBe("ServerHello");
    expect(res.json.data.serverRandom).toBeTruthy();
    expect(res.json.data.serverPublicKey).toBeTruthy();
    expect(res.json.data.selectedCipherSuite).toBe("TLS_AES_256_GCM_SHA384");
    expect(res.json.data.tlsVersion).toBe("TLS 1.3");
  });

  it("returns 400 without a prior ClientHello", async () => {
    const res = await post(app, "/api/tls/server-hello", { sessionId: "no-handshake" });
    expect(res.status).toBe(400);
    expect(res.json.success).toBe(false);
    expect(res.json.error).toContain("No handshake in progress");
  });
});

describe("POST /api/tls/key-exchange", () => {
  it("derives shared secret and master secret", async () => {
    const sid = "ke-test";
    await clientHello(app, sid);
    await serverHello(app, sid);
    const res = await post(app, "/api/tls/key-exchange", { sessionId: sid });
    expect(res.status).toBe(200);
    expect(res.json.success).toBe(true);
    expect(res.json.data.step).toBe("KeyExchange");
    expect(res.json.data.sharedSecret).toBeTruthy();
    expect(res.json.data.handshakeSecret).toBeTruthy();
    expect(res.json.data.masterSecret).toBeTruthy();
    expect(res.json.data.explanation.forwardSecrecy).toBeTruthy();
  });

  it("returns 400 if ClientHello was never sent", async () => {
    const res = await post(app, "/api/tls/key-exchange", { sessionId: "missing-session" });
    expect(res.status).toBe(400);
    expect(res.json.error).toContain("Missing handshake state");
  });
});

describe("POST /api/tls/finish", () => {
  it("derives application keys after full key exchange", async () => {
    const sid = "finish-test";
    await clientHello(app, sid);
    await serverHello(app, sid);
    await keyExchange(app, sid);
    const res = await post(app, "/api/tls/finish", { sessionId: sid });
    expect(res.status).toBe(200);
    expect(res.json.success).toBe(true);
    expect(res.json.data.step).toBe("Finished");
    expect(res.json.data.clientWriteKey).toBeTruthy();
    expect(res.json.data.serverWriteKey).toBeTruthy();
    expect(res.json.data.cipherSuite).toBe("TLS_AES_256_GCM_SHA384");
  });

  it("returns 400 if key exchange was not completed", async () => {
    const sid = "incomplete-hs";
    await clientHello(app, sid);
    await serverHello(app, sid);
    // Skip key-exchange step
    const res = await post(app, "/api/tls/finish", { sessionId: sid });
    expect(res.status).toBe(400);
    expect(res.json.error).toContain("Handshake not complete");
  });

  it("returns 400 for a non-existent session", async () => {
    const res = await post(app, "/api/tls/finish", { sessionId: "does-not-exist" });
    expect(res.status).toBe(400);
    expect(res.json.error).toContain("Handshake not complete");
  });
});

describe("GET /api/tls/certificate", () => {
  it("returns a self-signed certificate with expected fields", async () => {
    const res = await get(app, "/api/tls/certificate");
    expect(res.status).toBe(200);
    expect(res.json.success).toBe(true);
    const cert = res.json.data.certificate;
    expect(cert.subject).toContain("CN=localhost");
    expect(cert.issuer).toContain("OSI Demo CA");
    expect(cert.signatureAlgorithm).toBe("SHA256withRSA");
    expect(cert.fingerprint).toBeTruthy();
    expect(res.json.data.publicKeyPem).toContain("BEGIN PUBLIC KEY");
    expect(res.json.data.explanation.chain).toHaveLength(3);
  });
});

describe("Full TLS 1.3 handshake flow", () => {
  it("completes: ClientHello -> ServerHello -> KeyExchange -> Finish", async () => {
    const sid = "full-handshake";

    // Step 1: ClientHello
    const ch = await clientHello(app, sid);
    expect(ch.step).toBe("ClientHello");
    expect(ch.clientRandom).toHaveLength(64); // 32 bytes hex

    // Step 2: ServerHello
    const sh = await serverHello(app, sid);
    expect(sh.step).toBe("ServerHello");
    expect(sh.serverRandom).toHaveLength(64);

    // Step 3: Key Exchange
    const ke = await keyExchange(app, sid);
    expect(ke.step).toBe("KeyExchange");

    // Step 4: Finish
    const res = await post(app, "/api/tls/finish", { sessionId: sid });
    expect(res.status).toBe(200);
    expect(res.json.data.step).toBe("Finished");
    expect(res.json.data.clientWriteKey).not.toBe(res.json.data.serverWriteKey);

    // Session should be cleaned up after finish — repeating finish should fail
    const res2 = await post(app, "/api/tls/finish", { sessionId: sid });
    expect(res2.status).toBe(400);
  });
});
