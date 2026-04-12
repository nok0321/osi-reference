import { describe, it, expect, beforeEach } from "vitest";
import { createTestApp, post } from "./test-helpers.js";
import type { Hono } from "hono";

let app: Hono;

beforeEach(() => {
  ({ app } = createTestApp());
});

const PRINCIPAL = "alice";

/** Run AS-REQ and return TGT data needed for TGS-REQ. */
async function getTgt(testApp: Hono, principal = PRINCIPAL) {
  const res = await post(testApp, "/api/kerberos/as-req", {
    principal,
    password: "password",
  });
  expect(res.status).toBe(200);
  return res.json.data;
}

/** Run TGS-REQ with a valid TGT and return service ticket data. */
async function getServiceTicket(
  testApp: Hono,
  tgtData: { tgt: { encrypted: string; iv: string } },
  servicePrincipal = "HTTP/web-server",
) {
  const res = await post(testApp, "/api/kerberos/tgs-req", {
    tgt: tgtData.tgt.encrypted,
    tgtIv: tgtData.tgt.iv,
    servicePrincipal,
  });
  expect(res.status).toBe(200);
  return res.json.data;
}

describe("POST /api/kerberos/as-req", () => {
  it("issues a TGT for a valid principal", async () => {
    const res = await post(app, "/api/kerberos/as-req", {
      principal: PRINCIPAL,
      password: "password",
    });
    expect(res.status).toBe(200);
    expect(res.json.success).toBe(true);
    expect(res.json.data.step).toBe("AS-REP");
    expect(res.json.data.tgt.encrypted).toBeTruthy();
    expect(res.json.data.tgt.iv).toBeTruthy();
    expect(res.json.data.encryptedSessionKey.encrypted).toBeTruthy();
    expect(res.json.data.realm).toBe("OSI-DEMO.LOCAL");
    expect(res.json.data.decryptedTgt.principal).toBe(`${PRINCIPAL}@OSI-DEMO.LOCAL`);
    expect(res.json.data.decryptedTgt.flags).toContain("INITIAL");
  });

  it("uses default password when none provided", async () => {
    const res = await post(app, "/api/kerberos/as-req", {
      principal: "bob",
    });
    expect(res.status).toBe(200);
    expect(res.json.success).toBe(true);
    expect(res.json.data.decryptedTgt.principal).toBe("bob@OSI-DEMO.LOCAL");
  });

  it("includes _trace with crypto operations", async () => {
    const res = await post(app, "/api/kerberos/as-req", {
      principal: PRINCIPAL,
    });
    expect(res.status).toBe(200);
    const ops = res.json._trace?.cryptoOps ?? [];
    const opNames = ops.map((o: { op: string }) => o.op);
    expect(opNames).toContain("deriveClientKey");
    expect(opNames).toContain("generateSessionKey");
    expect(opNames).toContain("encryptTGT");
    expect(opNames).toContain("encryptSessionKey");
  });
});

describe("POST /api/kerberos/tgs-req", () => {
  it("issues a service ticket for a valid TGT", async () => {
    const tgtData = await getTgt(app);
    const res = await post(app, "/api/kerberos/tgs-req", {
      tgt: tgtData.tgt.encrypted,
      tgtIv: tgtData.tgt.iv,
      servicePrincipal: "HTTP/web-server",
    });
    expect(res.status).toBe(200);
    expect(res.json.success).toBe(true);
    expect(res.json.data.step).toBe("TGS-REP");
    expect(res.json.data.serviceTicket.encrypted).toBeTruthy();
    expect(res.json.data.serviceTicket.iv).toBeTruthy();
    expect(res.json.data.decryptedServiceTicket.principal).toBe(`${PRINCIPAL}@OSI-DEMO.LOCAL`);
    expect(res.json.data.decryptedServiceTicket.servicePrincipal).toBe("HTTP/web-server@OSI-DEMO.LOCAL");
  });

  it("rejects an invalid TGT (bad ciphertext)", async () => {
    const res = await post(app, "/api/kerberos/tgs-req", {
      tgt: "not-valid-base64-ciphertext==",
      tgtIv: "AAAAAAAAAAAAAAAAAAAAAA==",
      servicePrincipal: "HTTP/web-server",
    });
    expect(res.status).toBe(400);
    expect(res.json.success).toBe(false);
    expect(res.json.error).toContain("Invalid TGT");
  });

  it("rejects a tampered TGT (wrong iv)", async () => {
    const tgtData = await getTgt(app);
    const res = await post(app, "/api/kerberos/tgs-req", {
      tgt: tgtData.tgt.encrypted,
      tgtIv: "AAAAAAAAAAAAAAAAAAAAAA==", // wrong IV
      servicePrincipal: "HTTP/web-server",
    });
    expect(res.status).toBe(400);
    expect(res.json.error).toContain("Invalid TGT");
  });
});

describe("POST /api/kerberos/ap-req", () => {
  it("authenticates a valid service ticket", async () => {
    const tgtData = await getTgt(app);
    const stData = await getServiceTicket(app, tgtData);
    const res = await post(app, "/api/kerberos/ap-req", {
      serviceTicket: stData.serviceTicket.encrypted,
      serviceTicketIv: stData.serviceTicket.iv,
    });
    expect(res.status).toBe(200);
    expect(res.json.success).toBe(true);
    expect(res.json.data.step).toBe("AP-REP");
    expect(res.json.data.authenticated).toBe(true);
    expect(res.json.data.principal).toBe(`${PRINCIPAL}@OSI-DEMO.LOCAL`);
    expect(res.json.data.service).toBe("HTTP/web-server@OSI-DEMO.LOCAL");
  });

  it("rejects an invalid service ticket", async () => {
    const res = await post(app, "/api/kerberos/ap-req", {
      serviceTicket: "garbage-ticket-data==",
      serviceTicketIv: "AAAAAAAAAAAAAAAAAAAAAA==",
    });
    expect(res.status).toBe(400);
    expect(res.json.error).toContain("Invalid service ticket");
  });
});

describe("Full Kerberos flow: AS-REQ -> TGS-REQ -> AP-REQ", () => {
  it("completes authentication to a service via KDC", async () => {
    // Step 1: AS-REQ - get TGT from Authentication Server
    const asRes = await post(app, "/api/kerberos/as-req", {
      principal: "carol",
      password: "secretpass",
    });
    expect(asRes.status).toBe(200);
    expect(asRes.json.data.step).toBe("AS-REP");
    const tgt = asRes.json.data.tgt;

    // Step 2: TGS-REQ - get service ticket from Ticket Granting Server
    const tgsRes = await post(app, "/api/kerberos/tgs-req", {
      tgt: tgt.encrypted,
      tgtIv: tgt.iv,
      servicePrincipal: "CIFS/file-server",
    });
    expect(tgsRes.status).toBe(200);
    expect(tgsRes.json.data.step).toBe("TGS-REP");
    const serviceTicket = tgsRes.json.data.serviceTicket;

    // Step 3: AP-REQ - present service ticket to the service
    const apRes = await post(app, "/api/kerberos/ap-req", {
      serviceTicket: serviceTicket.encrypted,
      serviceTicketIv: serviceTicket.iv,
    });
    expect(apRes.status).toBe(200);
    expect(apRes.json.data.step).toBe("AP-REP");
    expect(apRes.json.data.authenticated).toBe(true);
    expect(apRes.json.data.principal).toBe("carol@OSI-DEMO.LOCAL");
    expect(apRes.json.data.service).toBe("CIFS/file-server@OSI-DEMO.LOCAL");
  });
});
