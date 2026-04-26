/**
 * Phase 2 第二コミット: runAttackScenario ヘルパー (SEC-12 / ROB-FIND-011 統合) のユニットテスト。
 *
 * - clipJson: payload_json サイズ上限 (ROB-FIND-004)
 * - maskSecret: SEC FINDING-5 防御 (DB 保存時の秘密鍵マスキング)
 * - sanitizeForDisplay: SEC FINDING-3 防御 (制御文字除去 + 長さ制限)
 *
 * 統合テスト (5 ステップ完全形・両モード並列実行) は server/__tests__/jwt-attack.test.ts に存在。
 */
import { describe, it, expect } from "vitest";
import { clipJson, maskSecret, sanitizeForDisplay, MAX_PAYLOAD_JSON_BYTES } from "./attack-runner.js";

describe("clipJson (ROB-FIND-004 — payload_json size cap)", () => {
  it("returns input as-is when under MAX_PAYLOAD_JSON_BYTES", () => {
    const small = JSON.stringify({ x: "y" });
    expect(clipJson(small)).toBe(small);
  });

  it("truncates oversized input with marker suffix", () => {
    const huge = JSON.stringify({ data: "x".repeat(MAX_PAYLOAD_JSON_BYTES * 2) });
    const out = clipJson(huge);
    expect(out.endsWith("…(truncated)")).toBe(true);
    expect(Buffer.byteLength(out, "utf8")).toBeLessThanOrEqual(MAX_PAYLOAD_JSON_BYTES);
  });

  it("handles UTF-8 multibyte input without producing invalid sequences", () => {
    // 日本語 (3 byte/文字) で MAX を 2 倍超
    const utf8 = JSON.stringify({ data: "あ".repeat(MAX_PAYLOAD_JSON_BYTES) });
    const out = clipJson(utf8);
    expect(out.endsWith("…(truncated)")).toBe(true);
    // toString("utf8") 経由で再エンコードできること (壊れた UTF-8 でないこと)
    expect(() => Buffer.from(out, "utf8").toString("utf8")).not.toThrow();
  });
});

describe("maskSecret (SEC FINDING-5 — DB plaintext mitigation)", () => {
  it("returns null for null/undefined input", () => {
    expect(maskSecret(null)).toBeNull();
    expect(maskSecret(undefined)).toBeNull();
  });

  it("returns *** for very short secrets (<=2 chars)", () => {
    expect(maskSecret("a")).toBe("***");
    expect(maskSecret("ab")).toBe("***");
  });

  it("returns first/last char + length for longer secrets", () => {
    expect(maskSecret("secret")).toBe("s***t (len=6)");
    expect(maskSecret("osi-demo-secret-key")).toBe("o***y (len=19)");
  });
});

describe("sanitizeForDisplay (SEC FINDING-3 — defense-in-depth for echoed inputs)", () => {
  it("passes printable ASCII unchanged", () => {
    expect(sanitizeForDisplay("../public/attacker-key.pem")).toBe("../public/attacker-key.pem");
    expect(sanitizeForDisplay("key-1")).toBe("key-1");
  });

  it("replaces ASCII control characters with ?", () => {
    expect(sanitizeForDisplay("kid\x00with\x01ctrl")).toBe("kid?with?ctrl");
    expect(sanitizeForDisplay("tab\there\nnewline")).toBe("tab?here?newline");
  });

  it("replaces DEL character (0x7F) with ?", () => {
    expect(sanitizeForDisplay("hello\x7Fworld")).toBe("hello?world");
  });

  it("truncates strings exceeding maxLen with ellipsis", () => {
    const long = "x".repeat(300);
    const out = sanitizeForDisplay(long, 256);
    expect(out.length).toBe(257); // 256 + ellipsis (1 char)
    expect(out.endsWith("…")).toBe(true);
  });

  it("preserves non-control Unicode (Japanese, emoji)", () => {
    expect(sanitizeForDisplay("kid-日本語-🔑")).toBe("kid-日本語-🔑");
  });
});
