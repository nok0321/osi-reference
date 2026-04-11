import { Hono } from "hono";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { parseBody, jwtSignSchema, jwtVerifySchema, jwtDecodeSchema } from "../validation.js";

export const jwtOpsRoutes = new Hono();

// Demo secrets (visible for educational purposes)
const HS256_SECRET = "osi-demo-secret-key-for-hs256-signing";
const { publicKey: RS256_PUBLIC, privateKey: RS256_PRIVATE } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const ALLOWED_ALGORITHMS = ["HS256", "RS256"] as const;
type AllowedAlgorithm = (typeof ALLOWED_ALGORITHMS)[number];

jwtOpsRoutes.post("/sign", async (c) => {
  const parsed = await parseBody(c, jwtSignSchema);
  if ("error" in parsed) return parsed.error;
  const { claims, algorithm, expiresIn } = parsed.data;
  const trace = c.get("trace");

  const header = { alg: algorithm, typ: "JWT" };
  const payload = { ...claims, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + expiresIn };

  // Step 1: Encode header
  const headerB64 = Buffer.from(JSON.stringify(header)).toString("base64url");
  trace.addCryptoOp({
    op: "base64url.encode(header)",
    input: JSON.stringify(header),
    output: headerB64,
    algo: "base64url",
    detail: "JWT Header → Base64URL encoding",
  });

  // Step 2: Encode payload
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
  trace.addCryptoOp({
    op: "base64url.encode(payload)",
    input: JSON.stringify(payload),
    output: payloadB64,
    algo: "base64url",
    detail: "JWT Payload → Base64URL encoding",
  });

  // Step 3: Create signature
  const signingInput = `${headerB64}.${payloadB64}`;
  const secret = algorithm === "RS256" ? RS256_PRIVATE : HS256_SECRET;
  const token = jwt.sign(claims, secret, {
    algorithm: algorithm as jwt.Algorithm,
    expiresIn,
  });

  const signature = token.split(".")[2];
  trace.addCryptoOp({
    op: `sign(${algorithm})`,
    input: `${signingInput.substring(0, 40)}...`,
    output: signature.substring(0, 40) + "...",
    algo: algorithm,
    detail: algorithm === "HS256"
      ? `HMAC-SHA256(secret="${HS256_SECRET.substring(0, 15)}...", data=header.payload)`
      : "RSA-SHA256(privateKey, data=header.payload)",
  });

  return c.json({
    success: true,
    data: {
      token,
      parts: { header: headerB64, payload: payloadB64, signature },
      decoded: { header, payload },
      secret: algorithm === "HS256" ? HS256_SECRET : "(RSA Private Key)",
    },
  });
});

jwtOpsRoutes.post("/verify", async (c) => {
  const parsed = await parseBody(c, jwtVerifySchema);
  if ("error" in parsed) return parsed.error;
  const { token, algorithm } = parsed.data;
  const trace = c.get("trace");

  const secret = algorithm === "RS256" ? RS256_PUBLIC : HS256_SECRET;

  try {
    const decoded = jwt.verify(token, secret, { algorithms: [algorithm as jwt.Algorithm] });
    trace.addCryptoOp({
      op: `verify(${algorithm})`,
      input: token.substring(0, 40) + "...",
      output: "VALID ✓",
      algo: algorithm,
      detail: algorithm === "HS256"
        ? "Re-compute HMAC with secret → compare with token signature"
        : "Decrypt signature with public key → compare with hash of header.payload",
    });
    return c.json({ success: true, data: { valid: true, decoded } });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Unknown error";
    trace.addCryptoOp({
      op: `verify(${algorithm})`,
      input: token.substring(0, 40) + "...",
      output: `INVALID ✗ — ${message}`,
      algo: algorithm,
    });
    return c.json({ success: true, data: { valid: false, error: message } });
  }
});

jwtOpsRoutes.post("/decode", async (c) => {
  const parsed = await parseBody(c, jwtDecodeSchema);
  if ("error" in parsed) return parsed.error;
  const { token } = parsed.data;
  const decoded = jwt.decode(token, { complete: true });
  return c.json({ success: true, data: { decoded, warning: "Decoded WITHOUT verification!" } });
});

jwtOpsRoutes.get("/keys", (c) => {
  return c.json({
    success: true,
    data: {
      hs256Secret: HS256_SECRET,
      rs256PublicKey: RS256_PUBLIC,
      note: "⚠ In production, secrets are NEVER exposed to clients",
    },
  });
});
