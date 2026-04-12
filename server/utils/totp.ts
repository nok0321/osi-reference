/**
 * RFC 4648 Base32 and RFC 6238 TOTP implementation.
 * Extracted as pure functions so they can be unit-tested independently.
 */
import crypto from "node:crypto";

export const TOTP_PERIOD = 30;
export const TOTP_DIGITS = 6;
export const TOTP_ALGORITHM = "SHA1";

// ── RFC 4648 Base32 (no padding) ──
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const b of buf) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 0x1f];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 0x1f];
  return out;
}

export function base32Decode(str: string): Buffer {
  const clean = str.toUpperCase().replace(/=+$/, "").replace(/\s/g, "");
  const bytes: number[] = [];
  let bits = 0;
  let value = 0;
  for (const ch of clean) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error(`invalid base32 character: ${ch}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

export interface TotpDetail {
  counter: number;
  counterHex: string;
  hmacHex: string;
  offset: number;
  truncatedHex: string;
  binary: number;
  code: string;
}

// ── RFC 6238 TOTP (HMAC-SHA1 + dynamic truncation) ──
export function computeTotp(secret: string, counter: number): TotpDetail {
  const key = base32Decode(secret);
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac("sha1", key).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const truncated = hmac.subarray(offset, offset + 4);
  const binary =
    ((truncated[0] & 0x7f) << 24) |
    (truncated[1] << 16) |
    (truncated[2] << 8) |
    truncated[3];
  const code = (binary % 10 ** TOTP_DIGITS).toString().padStart(TOTP_DIGITS, "0");
  return {
    counter,
    counterHex: counterBuf.toString("hex"),
    hmacHex: hmac.toString("hex"),
    offset,
    truncatedHex: truncated.toString("hex"),
    binary,
    code,
  };
}

export function currentCounter(): number {
  return Math.floor(Date.now() / 1000 / TOTP_PERIOD);
}

/**
 * Verify a TOTP code with ±1 time window tolerance.
 * Returns the TotpDetail that matched, or null if none matched.
 */
export function verifyTotpWithDetail(
  secret: string,
  code: string,
  window = 1
): { match: TotpDetail | null; attempts: TotpDetail[] } {
  const base = currentCounter();
  const attempts: TotpDetail[] = [];
  let match: TotpDetail | null = null;
  const providedBuf = Buffer.from(code, "utf8");
  for (let i = -window; i <= window; i++) {
    const d = computeTotp(secret, base + i);
    attempts.push(d);
    if (match) continue;
    const expectedBuf = Buffer.from(d.code, "utf8");
    if (providedBuf.length === expectedBuf.length && crypto.timingSafeEqual(providedBuf, expectedBuf)) {
      match = d;
    }
  }
  return { match, attempts };
}
