import { Hono, type Context } from "hono";
import crypto from "crypto";
import { v4 as uuidv4 } from "uuid";
import { getDb } from "../db/schema.js";
import {
  parseBody,
  ssoLoginSchema,
  ssoAccessServiceSchema,
  apikeyGenerateSchema,
  apikeyHmacSchema,
  ssoAttackApikeyLeakageSchema,
  ssoAttackHmacBypassSchema,
  ssoAttackReplayNoTimestampSchema,
} from "../validation.js";
import type { UserRow, ApiKeyRow } from "../../shared/api-types.js";
import type { TraceCollector } from "../middleware/trace-logger.js";
import { createTtlStore } from "../utils/ttl-store.js";
import { runAttackScenario, sanitizeForDisplay, maskSecret } from "../utils/attack-runner.js";

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

  // is_attack_sim=0 で正常系 API キーを明示的に挿入 (E-3)
  db.prepare(
    "INSERT INTO api_keys (key_id, key_prefix, key_hash, name, is_attack_sim) VALUES (?, ?, ?, ?, 0)"
  ).run(keyId, prefix, keyHash, name || "default");

  trace.addDbQuery({
    sql: "INSERT INTO api_keys (key_id, key_prefix, key_hash, name, is_attack_sim) VALUES (?, ?, ?, ?, 0)",
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
const HMAC_TIMESTAMP_SKEW_MS = 5 * 60 * 1000;

/** Parse an ISO-8601 string or epoch number (seconds or ms) into epoch ms. Returns NaN on failure. */
function parseTimestamp(ts: string): number {
  const asIso = Date.parse(ts);
  if (!Number.isNaN(asIso)) return asIso;
  const asNum = Number(ts);
  if (!Number.isFinite(asNum)) return NaN;
  // Heuristic: values below 1e12 are seconds (year ~2001+ in ms starts at 1e12)
  return asNum < 1e12 ? asNum * 1000 : asNum;
}

ssoApikeyRoutes.post("/apikey/verify/hmac", async (c) => {
  const parsed = await parseBody(c, apikeyHmacSchema);
  if ("error" in parsed) return parsed.error;
  const { keyId, timestamp, body, signature } = parsed.data;
  const trace = c.get("trace");
  const db = getDb();

  // is_attack_sim=0 のみ参照 (E-3: 攻撃シミュレーションのキーを誤認しない)
  const key = db.prepare("SELECT key_id, key_prefix, key_hash, name, created_at, last_used FROM api_keys WHERE key_id = ? AND is_attack_sim = 0").get(keyId) as ApiKeyRow | undefined;
  if (!key) {
    return c.json({ success: false, error: "Unknown key_id" }, 401);
  }

  // Timestamp skew check — prevents indefinite replay of a valid signed request
  const ts = parseTimestamp(timestamp);
  const now = Date.now();
  const skew = Number.isNaN(ts) ? NaN : Math.abs(now - ts);
  trace.addCryptoOp({
    op: "timestampSkewCheck",
    input: `timestamp="${timestamp}", now=${new Date(now).toISOString()}`,
    output: Number.isNaN(ts)
      ? "INVALID ✗ — cannot parse"
      : `skew=${Math.round(skew / 1000)}s (limit=${HMAC_TIMESTAMP_SKEW_MS / 1000}s)`,
    algo: "±5min window",
    detail: "Reject requests with timestamps outside the allowed clock-skew window to prevent replay attacks",
  });
  if (Number.isNaN(ts) || skew > HMAC_TIMESTAMP_SKEW_MS) {
    return c.json(
      { success: false, error: "Timestamp invalid or outside ±5min skew window" },
      401
    );
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

  // is_attack_sim=0 のみ参照 (E-3: 攻撃シミュレーションのキーを正規キーとして認証しない)
  const key = db.prepare("SELECT key_id, key_prefix, key_hash, name, created_at, last_used FROM api_keys WHERE key_hash = ? AND is_attack_sim = 0").get(keyHash) as ApiKeyRow | undefined;
  trace.addDbQuery({
    sql: "SELECT key_id, name FROM api_keys WHERE key_hash = ? AND is_attack_sim = 0",
    params: [keyHash.substring(0, 20) + "..."],
    rows: key ? [{ key_id: key.key_id, name: key.name }] : [],
    ms: 0,
  });

  if (!key) {
    return c.json({ success: false, error: "Invalid API key" }, 401);
  }

  // Update last_used (正常系キーのみ)
  db.prepare("UPDATE api_keys SET last_used = datetime('now') WHERE key_id = ? AND is_attack_sim = 0").run(key.key_id);

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

// ════════════════════════════════════════════════════════════════════════════════
// 攻撃デモ (Phase 2 第十三コミット — sso-idp-apikey タブ)
// ────────────────────────────────────────────────────────────────────────────────
// DESIGN/19-attack-sso-apikey.md の 3 シナリオ実装。
//   A: apikey-leakage              (CWE-200/798, CAPEC-117)
//   B: apikey-hmac-bypass          (CWE-208/326, CAPEC-462)
//   C: apikey-replay-no-timestamp  (CWE-294, CAPEC-60)
//
// 設計判断 (E-1/E-2/E-3 確立規約):
// - E-1 ジェネリック化: AttackResult<TExtra> でシナリオ固有データを `extra` 配下に格納
// - E-2 両モード並列実行: 1 リクエストで脆弱+堅牢を必ず両方実行、outcome 常に "succeeded"
// - E-3 is_attack_sim: api_keys.is_attack_sim で正常系と分離 (Scenario A は INSERT + DELETE)
//
// DESIGN/19 spec drift 整合 (Phase 2 規約適用):
// - DESIGN §4.x の outcome="blocked" は E-2 で outcome="succeeded" に統一 (AttackStep.status="blocked" で表現)
// - DESIGN §4.x の 4 ステップ + intercept kind は 5 ステップ完全形 (probe→tamper→forge→exploit→verify) に統一
// - DESIGN §1.2 / §8.3 の `server/routes/attack-sso-apikey.ts` 新規ファイルは inline (passkey/mfa/fido2 同パターン)
// - DESIGN §4.x.7 リクエスト body フィールド (`scenario`/`keyId`/`compareMethod`/`hmacLength`/`phase`/
//   `includeTimestamp`/`includeNonce`/`delaySimulatedMs`) は廃止 (z.object({}) 統一、
//   ROB-FIND-006 / ROB-KERB-1 教訓)
// ════════════════════════════════════════════════════════════════════════════════

// ── 共通シード (immutable) ──
// ROB-FIND-007 / WEBAUTHN_DEMO_CONSTANTS / KERBEROS_DEMO_CONSTANTS / TLS_DEMO_CONSTANTS /
// PASSWORD_DEMO_CONSTANTS / MFA_DEMO_CONSTANTS / PASSKEY_DEMO_CONSTANTS 同パターン。
// `as const satisfies` で readonly 化、シード値の SSoT 一本化を担保。
const SSO_APIKEY_DEMO_CONSTANTS = {
  victimUsername: "seed_alice",
  attackerUsername: "attacker_charlie",
  // 教育用シミュレートされた漏洩キー (Scenario A): is_attack_sim=1 で INSERT 後に DELETE。
  // 実プレフィックス + 固定文字列で「攻撃者が観測したキー」を表現。
  leakedKeyName: "leaked-key-from-access-log",
  leakedKeyIdPrefix: "key_atk_leak_",
  // HMAC 比較タイミングのシミュレーション値 (Scenario B):
  //   `=== 短絡評価` は一致文字数に比例して時間が伸びる (ベース 0.8ms + 0.05ms × 一致文字数)。
  //   `crypto.timingSafeEqual` は定数時間 (常時 0.85ms)。
  //   実環境ではネットワーク遅延 / OS スケジューリングジッターで観測困難だが、
  //   教育目的でサーバー側シミュレーション値として誇張表示する (DESIGN/19 §4.2 注記)。
  vulnerableBaselineMs: 0.8,
  vulnerableMsPerMatchedChar: 0.05,
  defendedConstantMs: 0.85,
  // HMAC 長 (バイト) — 4 バイト = 8 hex 文字, 32 バイト = 64 hex 文字
  shortHmacByteLen: 4,
  fullHmacByteLen: 32,
  // Scenario C: Replay 遅延シミュレーション (秒)
  replayDelaySec: 60,
  expiredReplayDelaySec: 360, // 6 分 — タイムスタンプ skew 窓 (5 分) 超過
  // タイムスタンプ skew 窓 (sso-apikey.ts:164 と同値、SSoT 二重化回避は Phase 3 で検討)
  timestampSkewMs: 5 * 60 * 1000,
  // 教育用シード API キー (Scenario A の attack_sim INSERT 用に動的生成、SHA-256 ハッシュは bcrypt 不要)
  // raw 値は固定文字列で「過去にログから漏洩したキー」を再現する。
  leakedRawKey: "demo_leaked_apikey_observed_in_access_log_for_education_only",
} as const satisfies Readonly<{
  victimUsername: string;
  attackerUsername: string;
  leakedKeyName: string;
  leakedKeyIdPrefix: string;
  vulnerableBaselineMs: number;
  vulnerableMsPerMatchedChar: number;
  defendedConstantMs: number;
  shortHmacByteLen: number;
  fullHmacByteLen: number;
  replayDelaySec: number;
  expiredReplayDelaySec: number;
  timestampSkewMs: number;
  leakedRawKey: string;
}>;

// ════════════════════════════════════════════════════════════════════════════════
// Scenario A: API キー漏洩 (URL クエリ・ログ経由) — CWE-200/798, CAPEC-117
// ────────────────────────────────────────────────────────────────────────────────
// vulnerable: クエリパラメータでキー送信 → アクセスログにキー文字列が記録される +
//             漏洩したキーで再アクセス成立
// defended:   ヘッダ送信ではキーが URL ログに残らない + キー取消 (revocation) で
//             同一キーでの再アクセス拒否 → `api_key_revocation_invalidates_leaked_key`
//
// 教育目的: 脆弱パスで is_attack_sim=1 のキーを INSERT して「漏洩したキーが API 上で
//           受理されてしまう状態」を観測可能にする。handler 末尾で DELETE して累積回避
//           (SEC-FIDO2-2 痕跡削除パターン継承)。
// ════════════════════════════════════════════════════════════════════════════════
type ApikeyLeakageExtra = {
  /** 脆弱パス: クエリ送信でキー文字列が URL アクセスログに記録された (シミュレーション)。 */
  queryLoggedInUrl: boolean;
  /** ヘッダ送信ではキーが URL に含まれないためログに残らない。 */
  headerNotLoggedInUrl: boolean;
  /** 脆弱パス: 漏洩キーで /verify が成立した (取消前)。 */
  leakedKeyAcceptedBeforeRevocation: boolean;
  /** 堅牢パス: 取消後、同一キーでの再アクセスが拒否された。 */
  defendedRevocationRejected: boolean;
  /** 観測した攻撃用キー ID (痕跡削除前)。INSERT 失敗時は null。 */
  attackKeyId: string | null;
  /** 攻撃用キーが api_keys.is_attack_sim=1 で INSERT されたかを観測。 */
  attackKeyInserted: boolean;
  /** ROB-FIDO2-1 教訓: INSERT 失敗時のエラーメッセージ (sanitize 済み)。 */
  attackKeyInsertError: string | null;
  /** 漏洩キー文字列のプレビュー (UI 表示用、平文 OK — payload_json 側はマスク必須)。 */
  leakedKeyPreview: string;
  /** 教育用注記: ログ範囲 (DESIGN/19 §4.1 実環境差異注記)。 */
  logScopeNote: { ja: string; en: string };
};

ssoApikeyRoutes.post("/attack/apikey-leakage", (c) =>
  runAttackScenario<typeof ssoAttackApikeyLeakageSchema, ApikeyLeakageExtra>(c, {
    schema: ssoAttackApikeyLeakageSchema,
    scenarioId: "apikey-leakage",
    tabId: "sso-idp-apikey",
    async handler({ db, recordStep, trace }) {
      // 漏洩キー (固定文字列) を SHA-256 でハッシュ化 → DB に is_attack_sim=1 で INSERT
      const rawKey = SSO_APIKEY_DEMO_CONSTANTS.leakedRawKey;
      const keyPrefix = rawKey.substring(0, 8);
      const keyHash = crypto.createHash("sha256").update(rawKey).digest("hex");
      const attackKeyId = `${SSO_APIKEY_DEMO_CONSTANTS.leakedKeyIdPrefix}${uuidv4().substring(0, 8)}`;
      const leakedKeyPreview = `${keyPrefix}…(len=${rawKey.length})`;

      // ── Step 1: probe — 攻撃者がアクセスログでクエリパラメータの API キーを観測
      trace.addSessionOp({
        action: "READ_API_KEY",
        data: {
          method: "Query Parameter (?api_key=...)",
          value: keyPrefix + "...",
          loggedInUrl: true,
          note: "クエリ送信のキーは URL アクセスログに完全文字列で記録される",
        },
      });
      recordStep({
        id: "sso-leak-1",
        kind: "probe",
        label: "Observe API key in server access log (query parameter exposes the key)",
        labelJa: "サーバーアクセスログでクエリパラメータの API キーを観測",
        status: "success",
        payload: {
          type: "http",
          request: {
            method: "GET",
            url: `/api/sso/apikey/verify/query?api_key=${keyPrefix}...`,
            body: null,
          },
          response: {
            status: 200,
            body: {
              note: "Server access log records the FULL URL including the api_key query parameter",
            },
          },
        },
        detailJa:
          "API キーが URL クエリパラメータに含まれているため、Web サーバー / プロキシ / CDN / ロードバランサ全段のアクセスログに完全文字列で記録されます。ブラウザの履歴・Referer ヘッダにも残ります。",
        detail:
          "The API key appears verbatim in the URL. Server access logs (web server / proxy / CDN / load balancer) record the full URL including the key. Browser history and Referer headers preserve it as well.",
      });

      // ── Step 2: tamper — ヘッダ送信との比較 (URL ログにはキーが残らない)
      recordStep({
        id: "sso-leak-2",
        kind: "tamper",
        label: "Compare: header transmission keeps the key out of URL access logs",
        labelJa: "比較: ヘッダ送信ではキーが URL アクセスログに記録されない",
        status: "success",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/sso/apikey/verify/header",
            headers: { "X-API-Key": keyPrefix + "..." },
            body: {},
          },
          response: {
            status: 200,
            body: {
              note: "Header value is NOT recorded in URL log; only request line (POST /verify/header) is logged",
            },
          },
        },
        detailJa:
          "ヘッダ送信ではキー値が URL に含まれないため、URL ベースのアクセスログには残りません。プロキシ・CDN のログにもキーが漏出しません (ヘッダロギングを明示的に有効化していない限り)。",
        detail:
          "Header-based transmission keeps the key value out of the URL. URL-based access logs at proxies / CDNs do not capture the key (unless header logging is explicitly enabled).",
      });

      // ── Step 3: forge — 攻撃者が is_attack_sim=1 で漏洩キーを api_keys に登録 (シミュレーション)
      // ROB-FIDO2-1 教訓: INSERT を try/catch で囲み、UNIQUE/SQLITE_BUSY/FK 例外でハンドラ全体が
      //                   500 にならないよう「失敗時 false 記録」設計に揃える。
      let attackKeyInserted = false;
      let attackKeyInsertError: string | null = null;
      try {
        const t0 = performance.now();
        db.prepare(
          "INSERT OR IGNORE INTO api_keys (key_id, key_prefix, key_hash, name, is_attack_sim) VALUES (?, ?, ?, ?, 1)",
        ).run(attackKeyId, keyPrefix, keyHash, SSO_APIKEY_DEMO_CONSTANTS.leakedKeyName);
        trace.addDbQuery({
          sql:
            "INSERT OR IGNORE INTO api_keys (key_id, key_prefix, key_hash, name, is_attack_sim) VALUES (?, ?, ?, ?, 1) -- simulated leaked key in attacker's possession",
          params: [attackKeyId, keyPrefix, "<masked-hash>", SSO_APIKEY_DEMO_CONSTANTS.leakedKeyName],
          ms: performance.now() - t0,
        });
        attackKeyInserted = true;
      } catch (e) {
        attackKeyInsertError = sanitizeForDisplay(
          e instanceof Error ? e.message : "Unknown DB error",
          128,
        );
        trace.addDbQuery({
          sql: "INSERT OR IGNORE INTO api_keys (failed: " + attackKeyInsertError + ")",
          params: [attackKeyId, keyPrefix, "<masked-hash>", SSO_APIKEY_DEMO_CONSTANTS.leakedKeyName],
          ms: 0,
        });
      }

      trace.addCryptoOp({
        op: "hashProvidedKey",
        input: `"${keyPrefix}..."`,
        output: keyHash.substring(0, 20) + "...",
        algo: "SHA-256",
        detail:
          "Attacker has the leaked raw key. The server hashes it for lookup against api_keys.key_hash.",
      });

      recordStep({
        id: "sso-leak-3",
        kind: "forge",
        label: "Attacker now holds the leaked key (simulated INSERT with is_attack_sim=1)",
        labelJa: "攻撃者が漏洩キーを保持している状態を再現 (is_attack_sim=1 で INSERT)",
        status: "success",
        payload: {
          type: "generic",
          data: {
            attackKeyId,
            keyPrefixPreview: keyPrefix + "...",
            attackKeyInserted,
            attackKeyInsertError,
            note: "is_attack_sim=1 で挿入され、正常系 /verify/* (WHERE is_attack_sim=0) からは絶対に参照されない。教育的観察後にハンドラ末尾で削除する (痕跡削除パターン)。",
          },
        },
        detailJa:
          attackKeyInserted
            ? `攻撃者は漏洩したキーを保持しています。教育目的で is_attack_sim=1 として api_keys に登録 (key_id=${attackKeyId})、ハンドラ末尾で必ず削除します。`
            : "攻撃者は漏洩したキーを保持していますが、DB INSERT に失敗したため痕跡は残りません。",
        detail:
          attackKeyInserted
            ? `Attacker possesses the leaked key. For educational visibility, the key is INSERTed with is_attack_sim=1 (key_id=${attackKeyId}) and removed at handler end.`
            : "Attacker possesses the leaked key, but the simulation INSERT failed so no trace remains in DB.",
      });

      // ── Step 4: exploit (脆弱モード) — 漏洩キーを /verify で再利用、is_attack_sim=1 でも取消なしのため受理
      // SSoT 派生: queryLoggedInUrl=true, leakedKeyAccepted=true は「URL にキーが含まれて
      //   そのキーが DB に存在する」という事実から導出される (シードを除去すれば false)。
      const queryLoggedInUrl = rawKey.length > 0; // 「キーが URL クエリに含まれた」事実 (空文字なら false)
      const headerNotLoggedInUrl = true; // ヘッダ送信は URL に出ない (HTTP 規約上の事実)
      // 脆弱パス: 取消されていない漏洩キー (is_attack_sim=1) は SHA-256 ハッシュ照合で一致 → 攻撃者が認証成立
      const leakedKeyAcceptedBeforeRevocation = attackKeyInserted; // INSERT 成立時のみ true

      recordStep({
        id: "sso-leak-4",
        kind: "exploit",
        label: "Vulnerable: leaked key has not been revoked → attacker reuses it indefinitely",
        labelJa: "脆弱版: 漏洩キーが取消されていない → 攻撃者が無期限に再利用成立",
        status: leakedKeyAcceptedBeforeRevocation ? "success" : "failed",
        payload: {
          type: "http",
          request: {
            method: "GET",
            url: `/api/sso/apikey/verify/query?api_key=${keyPrefix}... (simulated reuse)`,
            body: null,
          },
          response: {
            status: leakedKeyAcceptedBeforeRevocation ? 200 : 401,
            body: leakedKeyAcceptedBeforeRevocation
              ? {
                valid: true,
                keyId: attackKeyId,
                name: SSO_APIKEY_DEMO_CONSTANTS.leakedKeyName,
                note: "Vulnerable: a server that does NOT track revocation accepts the leaked key indefinitely",
              }
              : { error: "Simulated INSERT failed; reuse cannot be demonstrated" },
          },
        },
        detailJa:
          leakedKeyAcceptedBeforeRevocation
            ? "この実装は脆弱です: 取消メカニズムを持たないサーバーは、漏洩キーが受理され続けます。攻撃者は鍵が無効化されない限り無期限に API を悪用できます。"
            : "DB INSERT 失敗のため再利用デモはスキップしました (extra.attackKeyInsertError 参照)。",
        detail:
          leakedKeyAcceptedBeforeRevocation
            ? "This implementation is vulnerable: a server without revocation tracking accepts the leaked key indefinitely. The attacker can abuse the API until the key is invalidated."
            : "Reuse demo skipped due to DB INSERT failure (see extra.attackKeyInsertError).",
      });

      // ── Step 5: verify (堅牢モード) — キー取消 → 同一キーでの再アクセスが拒否される
      // 「取消」を api_keys 行の DELETE (is_attack_sim=1 行) でシミュレート。
      // 堅牢実装では `revoked_at` カラム + `WHERE revoked_at IS NULL` で同等の挙動を実現する
      // (DESIGN/19 §3.4 改善案)。本デモではテーブルスキーマ変更を避け、痕跡削除と同経路で表現。
      let revocationRowsDeleted = 0;
      if (attackKeyInserted) {
        const t0 = performance.now();
        const info = db.prepare(
          "DELETE FROM api_keys WHERE key_id = ? AND is_attack_sim = 1",
        ).run(attackKeyId);
        revocationRowsDeleted = info.changes;
        trace.addDbQuery({
          sql:
            "DELETE FROM api_keys WHERE key_id = ? AND is_attack_sim = 1 -- simulated revocation (real implementation would set revoked_at)",
          params: [attackKeyId],
          ms: performance.now() - t0,
        });
      }
      // R-MEDIUM-1 教訓: bare literal `true` を避け、SSoT 派生で「取消が発動した」を表現。
      //   defendedRevocationRejected = (取消対象行が存在し DELETE 成立)
      //                                 OR (INSERT 失敗時はそもそも漏洩キーが DB にない = 拒否相当)
      // 将来「取消メカニズムが壊れる」と DELETE が 0 行になり flag が false に転じる sentinel 化。
      const defendedRevocationRejected = attackKeyInserted ? revocationRowsDeleted === 1 : true;

      trace.addSessionOp({
        action: "API_KEY_REVOKED",
        data: {
          keyId: attackKeyId,
          revokedAt: new Date().toISOString(),
          rowsDeleted: revocationRowsDeleted,
          note: "実装上は `revoked_at` カラムを使うのが推奨だが、本デモでは痕跡削除と同経路で取消をシミュレートする",
        },
      });

      recordStep({
        id: "sso-leak-5",
        kind: "verify",
        label: "Defended: key revocation invalidates the leaked key — reuse is rejected",
        labelJa: "堅牢版: キー取消により漏洩キーが無効化 — 再利用が拒否される",
        status: "blocked",
        payload: {
          type: "http",
          request: {
            method: "DELETE",
            url: `/api/sso/admin/keys/${attackKeyId}/revoke (simulated; real impl uses PATCH revoked_at)`,
          },
          response: {
            status: 401,
            body: {
              error: "Invalid or revoked API key",
              blockedBy: "api_key_revocation_invalidates_leaked_key",
              note: "Defended: subsequent /verify calls with the revoked key fail SHA-256 lookup (row removed / revoked_at IS NOT NULL)",
            },
          },
        },
        detailJa:
          "堅牢実装ではキー取消エンドポイント (例: PATCH /api/keys/:keyId/revoke で revoked_at に現在時刻を設定) により、漏洩キーは即座に無効化されます。SELECT 時の `WHERE revoked_at IS NULL` 条件で取消済みキーは認証ラインから除外されます。本デモでは is_attack_sim=1 行を DELETE して同等の効果をシミュレートしました。",
        detail:
          "The defended implementation provides a key-revocation endpoint (e.g., PATCH /api/keys/:keyId/revoke setting revoked_at to NOW). Subsequent SELECTs include `WHERE revoked_at IS NULL` so revoked keys never authenticate. This demo simulates the same effect by DELETing the is_attack_sim=1 row.",
      });

      return {
        blockedBy: "api_key_revocation_invalidates_leaked_key",
        summary:
          "A leaked API key sent via URL query parameter is recorded verbatim in server / proxy / CDN access logs. Without revocation, an attacker reuses it indefinitely. The defended implementation transmits the key via header (no URL log exposure) and provides a revocation endpoint that invalidates the leaked key via `revoked_at` column or row deletion.",
        summaryJa:
          "この実装は脆弱です: URL クエリパラメータで送信された API キーはサーバー / プロキシ / CDN のアクセスログに完全文字列で記録されます。取消メカニズムを持たないサーバーでは、攻撃者は漏洩キーを無期限に悪用できます。堅牢実装はヘッダ送信 (URL ログへの露出を回避) と取消エンドポイント (revoked_at カラム または 行削除で漏洩キーを即時無効化) を提供します。",
        extra: {
          queryLoggedInUrl,
          headerNotLoggedInUrl,
          leakedKeyAcceptedBeforeRevocation,
          defendedRevocationRejected,
          attackKeyId: attackKeyInserted ? attackKeyId : null,
          attackKeyInserted,
          attackKeyInsertError,
          leakedKeyPreview,
          logScopeNote: {
            ja: "注: このデモはローカルサーバーのインメモリログのみを対象としています。実環境ではログ閲覧者 (システム管理者・ログ解析基盤・CDN プロバイダ) がさらに広範に存在し、複数ホップ先でも記録されます。",
            en: "Note: This demo targets only the local in-memory log. In real deployments, log viewers (sysadmins, log analytics, CDN providers) are far more numerous, and the key would be recorded across multiple hops.",
          },
        } satisfies ApikeyLeakageExtra,
        payload: {
          params: {},
          result: {
            queryLoggedInUrl,
            headerNotLoggedInUrl,
            leakedKeyAcceptedBeforeRevocation,
            defendedRevocationRejected,
            attackKeyInserted,
            attackKeyInsertError,
            // SEC FINDING-5: 平文キーは payload_json に保存しない (extra のプレビューと別)。
            //                maskSecret() でラップして長さ情報のみ残す。
            leakedKeyMasked: maskSecret(rawKey),
            attackKeyIdPreview: attackKeyInserted ? attackKeyId : null,
          },
        },
      };
    },
  }),
);

// ════════════════════════════════════════════════════════════════════════════════
// Scenario B: HMAC 検証バイパス (タイミング攻撃 / 短い HMAC) — CWE-208/326, CAPEC-462
// ────────────────────────────────────────────────────────────────────────────────
// vulnerable: `=== 短絡評価` で署名比較 → 一致文字数に比例した応答時間差で
//             正解プレフィックスが推定可能 + 4 バイト HMAC は鍵空間 2^32 で総当り可能
// defended:   `crypto.timingSafeEqual` で定数時間比較 + 32 バイト HMAC (256 ビット) で
//             総当り計算上不可能 → `timing_safe_equal_and_full_length_hmac_enforced`
//
// DB 書き込みなし (in-memory simulation only — TLS / kerberoasting と同パターン)。
// 平文 HMAC 文字列は対比用として extra に格納するが「秘密」ではない (公開可能なデモ値)。
// ════════════════════════════════════════════════════════════════════════════════
type ApikeyHmacBypassExtra = {
  /** 脆弱パス: === 比較で「先頭 0 文字一致」のシミュレート応答時間 (ms)。 */
  vulnerable0CharMatchMs: number;
  /** 脆弱パス: === 比較で「先頭 16 文字一致」のシミュレート応答時間 (ms)。 */
  vulnerable16CharMatchMs: number;
  /** 堅牢パス: timingSafeEqual の応答時間 (ms、定数時間)。 */
  defendedConstantTimeMs: number;
  /** タイミング差異: vulnerable16 - vulnerable0 (ms)。0 に近いほど安全。 */
  vulnerableTimingLeakageMs: number;
  /** 脆弱パス: 4 バイト HMAC の鍵空間 (2^32 = 4,294,967,296)。 */
  shortHmacKeySpace: number;
  /** 堅牢パス: 32 バイト HMAC の鍵空間 (2^256 — 計算上不可能)。 */
  fullHmacKeySpaceLabel: string;
  /** 脆弱パス: === + 4 バイト HMAC で攻撃が成立可能。 */
  vulnerableAttackFeasible: boolean;
  /** 堅牢パス: timingSafeEqual + 32 バイト HMAC で攻撃を阻止。 */
  defendedAttackBlocked: boolean;
  /** シミュレート 4 バイト HMAC (16 進 8 文字) のサンプル値 — 教育表示用。 */
  shortHmacSample: string;
  /** シミュレート 32 バイト HMAC (16 進 64 文字) のサンプル値 — 教育表示用。 */
  fullHmacSample: string;
  /** 教育用注記: 応答時間がシミュレーション値であることの明示 (DESIGN/19 §4.2 注記)。 */
  simulationNote: { ja: string; en: string };
};

ssoApikeyRoutes.post("/attack/hmac-bypass", (c) =>
  runAttackScenario<typeof ssoAttackHmacBypassSchema, ApikeyHmacBypassExtra>(c, {
    schema: ssoAttackHmacBypassSchema,
    scenarioId: "apikey-hmac-bypass",
    tabId: "sso-idp-apikey",
    async handler({ recordStep, trace }) {
      // 教育用 HMAC サンプルを動的計算 (固定文字列は DESIGN/19 §4.2 サンプルと整合)
      const demoSecret = "demo-hmac-secret-for-education-only";
      const demoCanonical = "2026-04-30T12:00:00Z\n{\"resource\":\"seed-resource\"}";
      const fullHmac = crypto.createHmac("sha256", demoSecret).update(demoCanonical).digest("hex");
      const shortHmac = fullHmac.substring(0, SSO_APIKEY_DEMO_CONSTANTS.shortHmacByteLen * 2); // 4 バイト = 8 hex
      const shortHmacKeySpace = Math.pow(2, SSO_APIKEY_DEMO_CONSTANTS.shortHmacByteLen * 8); // 2^32

      // ── Step 1: probe — === 比較で 0 文字一致時のタイミング計測 (ベースライン)
      const vulnerable0CharMatchMs = SSO_APIKEY_DEMO_CONSTANTS.vulnerableBaselineMs;
      trace.addCryptoOp({
        op: "compareSignatures (=== short-circuit, 0-char match)",
        input: `provided=00000000... vs expected=${shortHmac.substring(0, 4)}...`,
        output: `MISMATCH at index 0 → ${vulnerable0CharMatchMs}ms (simulated)`,
        algo: "string === (short-circuit)",
        detail:
          "Vulnerable: short-circuit comparison stops at the first mismatched byte. Fast response when no characters match.",
      });
      recordStep({
        id: "sso-hmac-1",
        kind: "probe",
        label: "Probe: === comparison with 0-char prefix match (baseline timing)",
        labelJa: "プローブ: === 比較で 0 文字一致のベースラインタイミングを計測",
        status: "success",
        payload: {
          type: "generic",
          data: {
            probeSignature: "00000000",
            matchedHexChars: 0,
            compareMethod: "=== (short-circuit)",
            simulatedTimeMs: vulnerable0CharMatchMs,
            note: "Educational simulation: in real environments, network jitter / OS scheduling makes timing attacks require tens of thousands of measurements + statistical analysis.",
          },
        },
        detailJa:
          "=== 比較は最初の不一致文字で停止します。一致文字数 0 では最速の応答時間 (ベースライン) です。",
        detail:
          "=== comparison stops at the first mismatch. Zero matching characters yields the fastest response time (baseline).",
      });

      // ── Step 2: tamper — === 比較で 16 文字一致時のタイミング計測 (タイミング情報漏洩)
      const matchedChars = 16;
      const vulnerable16CharMatchMs =
        SSO_APIKEY_DEMO_CONSTANTS.vulnerableBaselineMs +
        SSO_APIKEY_DEMO_CONSTANTS.vulnerableMsPerMatchedChar * matchedChars;
      trace.addCryptoOp({
        op: "compareSignatures (=== short-circuit, 16-char match)",
        input: `provided=${shortHmac.substring(0, 8)}AAAA... vs expected=${shortHmac.substring(0, 8)}...`,
        output: `MISMATCH at index 16 → ${vulnerable16CharMatchMs}ms (simulated, 2x slower than baseline)`,
        algo: "string === (short-circuit)",
        detail:
          "Vulnerable: 16 matching characters cause comparison time to grow proportionally, leaking the correct prefix length to the attacker.",
      });
      recordStep({
        id: "sso-hmac-2",
        kind: "tamper",
        label: "Tamper: === comparison with 16-char prefix match — timing leaks correct prefix",
        labelJa: "タンパー: === 比較で 16 文字一致 — タイミング情報が正解プレフィックスを漏洩",
        status: "success",
        payload: {
          type: "generic",
          data: {
            probeSignature: shortHmac.substring(0, 8) + "AAAA...",
            matchedHexChars: matchedChars,
            compareMethod: "=== (short-circuit)",
            simulatedTimeMs: vulnerable16CharMatchMs,
            timingDeltaFromBaselineMs:
              vulnerable16CharMatchMs - SSO_APIKEY_DEMO_CONSTANTS.vulnerableBaselineMs,
            note: "Attacker uses iterative byte probing to discover the correct HMAC one byte at a time, requiring O(N) attempts per byte (256 attempts for 1 byte; 2^32 keyspace becomes feasible).",
          },
        },
        detailJa:
          "16 文字一致により比較時間がベースラインの 2 倍になり、正解プレフィックスの情報が漏洩します。攻撃者は 1 バイトずつ正解を統計的に推定できます (バイトあたり 256 試行 → 32 バイト全体で 8192 試行)。",
        detail:
          "16 matching characters cause comparison time to be ~2x the baseline, leaking the correct prefix. The attacker can statistically infer the correct HMAC byte by byte (256 attempts per byte; ~8192 attempts total for a 32-byte HMAC).",
      });

      // ── Step 3: forge — 攻撃者が 4 バイト HMAC の総当り辞書を構築 (サーバー側シミュレーション)
      recordStep({
        id: "sso-hmac-3",
        kind: "forge",
        label: "Forge: build 4-byte HMAC brute-force search space (2^32 ≈ 4.29 billion values)",
        labelJa: "フォージ: 4 バイト HMAC の総当り探索空間を構築 (2^32 ≈ 42 億通り)",
        status: "success",
        payload: {
          type: "generic",
          data: {
            hmacByteLen: SSO_APIKEY_DEMO_CONSTANTS.shortHmacByteLen,
            hmacBitLen: SSO_APIKEY_DEMO_CONSTANTS.shortHmacByteLen * 8,
            keySpace: shortHmacKeySpace,
            shortHmacSamplePreview: shortHmac.substring(0, 8),
            note: "Server-side simulation: real brute-force would issue 2^31 (median) HTTP requests. The demo skips network round-trips and demonstrates the keyspace size only.",
          },
        },
        detailJa:
          "4 バイト = 32 ビットの HMAC は 2^32 ≈ 42 億通りの鍵空間を持ちます。現代の GPU で数秒〜数分でオフライン総当り可能です。本デモではサーバー側で『成立する事実』のみシミュレートし、ブラウザからの実 HTTP 試行は行いません。",
        detail:
          "A 4-byte (32-bit) HMAC has 2^32 ≈ 4.29 billion possible values, brute-forceable on commodity GPUs in seconds-to-minutes. This demo simulates the feasibility on the server side without issuing actual brute-force HTTP requests from the browser.",
      });

      // ── Step 4: exploit (脆弱モード) — === + 4 バイト HMAC で攻撃成立 (シミュレーション)
      // SSoT 派生 (R-MEDIUM-1 / ROB-PW-1 教訓): bare literal `true` を避ける。
      //   vulnerableAttackFeasible = (HMAC 長 < 16 バイト = 128 ビット未満) AND (比較が === で短絡評価)
      // 将来 shortHmacByteLen を 16 以上に変更すると flag が自動的に false に転じる sentinel 化。
      const minSafeHmacByteLen = 16; // 128 ビット = 一般的に「現代暗号で安全」とされる最低長
      const usesShortCircuitCompare = true; // 脆弱パスの定義: === 比較を使用する
      const vulnerableAttackFeasible =
        SSO_APIKEY_DEMO_CONSTANTS.shortHmacByteLen < minSafeHmacByteLen && usesShortCircuitCompare;
      const vulnerableTimingLeakageMs =
        vulnerable16CharMatchMs - vulnerable0CharMatchMs;

      recordStep({
        id: "sso-hmac-4",
        kind: "exploit",
        label: "Vulnerable: === comparison + 4-byte HMAC succumbs to timing + brute-force",
        labelJa: "脆弱版: === 比較 + 4 バイト HMAC が タイミング攻撃 + 総当りで突破される",
        status: vulnerableAttackFeasible ? "success" : "failed",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/sso/apikey/verify/hmac (vulnerable variant — === + 4-byte HMAC)",
          },
          response: {
            status: 200,
            body: {
              valid: true,
              hmacByteLen: SSO_APIKEY_DEMO_CONSTANTS.shortHmacByteLen,
              compareMethod: "=== (short-circuit)",
              simulatedAttemptsToSuccess: Math.floor(shortHmacKeySpace / 2),
              note: "Vulnerable: a server using === comparison and a 4-byte HMAC would accept a brute-forced or timing-derived signature.",
            },
          },
        },
        detailJa:
          "この実装は脆弱です: === 比較 + 4 バイト HMAC は (a) タイミング攻撃で正解を統計的に推定可能、かつ (b) 鍵空間 2^32 が現代の GPU で総当り可能なため、攻撃者がいずれかの経路で署名を再現できます。",
        detail:
          "This implementation is vulnerable: with === comparison + 4-byte HMAC, an attacker can either (a) statistically derive the signature via timing attacks or (b) brute-force the 2^32 keyspace on a modern GPU.",
      });

      // ── Step 5: verify (堅牢モード) — timingSafeEqual + 32 バイト HMAC で阻止
      const defendedConstantTimeMs = SSO_APIKEY_DEMO_CONSTANTS.defendedConstantMs;
      // SSoT 派生: defendedAttackBlocked = (HMAC 長 >= 16 バイト) AND (timingSafeEqual を使用)
      // 将来一方が崩れると flag が false に転じる sentinel 化。
      const usesTimingSafeEqualCompare = true; // 堅牢パスの定義: crypto.timingSafeEqual を使用する
      const defendedAttackBlocked =
        SSO_APIKEY_DEMO_CONSTANTS.fullHmacByteLen >= minSafeHmacByteLen &&
        usesTimingSafeEqualCompare;
      trace.addCryptoOp({
        op: "compareSignatures (crypto.timingSafeEqual)",
        input: `expected.length=${SSO_APIKEY_DEMO_CONSTANTS.fullHmacByteLen} bytes, provided.length=${SSO_APIKEY_DEMO_CONSTANTS.fullHmacByteLen} bytes`,
        output: `constant time = ${defendedConstantTimeMs}ms (no timing leakage)`,
        algo: "crypto.timingSafeEqual",
        detail:
          "Defended: timingSafeEqual XORs both buffers and accumulates the result, ensuring the comparison time is independent of where the mismatch occurs.",
      });
      recordStep({
        id: "sso-hmac-5",
        kind: "verify",
        label: "Defended: timingSafeEqual + 32-byte HMAC blocks both timing and brute-force attacks",
        labelJa: "堅牢版: timingSafeEqual + 32 バイト HMAC が タイミング攻撃 + 総当りを阻止",
        status: "blocked",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/sso/apikey/verify/hmac (defended — sso-apikey.ts:229-235)",
          },
          response: {
            status: 401,
            body: {
              valid: false,
              error: "Signature mismatch — request tampered or wrong key",
              hmacByteLen: SSO_APIKEY_DEMO_CONSTANTS.fullHmacByteLen,
              compareMethod: "crypto.timingSafeEqual",
              keySpaceLabel: "2^256 (computationally infeasible)",
              blockedBy: "timing_safe_equal_and_full_length_hmac_enforced",
              note: "Defended: 32-byte HMAC has 2^256 keyspace (≈ 10^77) — brute-force is computationally infeasible. timingSafeEqual ensures constant-time comparison.",
            },
          },
        },
        detailJa:
          "堅牢実装は (a) `crypto.timingSafeEqual` で定数時間比較を行い、タイミングサイドチャネルを排除し、(b) 完全な 32 バイト (256 ビット) HMAC を使用することで、鍵空間 2^256 ≈ 10^77 を確保し総当りを計算上不可能にします。sso-apikey.ts:229-235 で実装済みです。",
        detail:
          "The defended implementation (a) uses `crypto.timingSafeEqual` for constant-time comparison, eliminating timing side-channels, and (b) uses the full 32-byte (256-bit) HMAC, providing a 2^256 ≈ 10^77 keyspace that is computationally infeasible to brute-force. Implemented at sso-apikey.ts:229-235.",
      });

      return {
        blockedBy: "timing_safe_equal_and_full_length_hmac_enforced",
        summary:
          "A vulnerable HMAC verification using === comparison leaks timing information proportional to the matching prefix length, while a 4-byte HMAC has only 2^32 brute-forceable keyspace. The defended implementation uses crypto.timingSafeEqual (constant time) + full 32-byte HMAC (2^256 keyspace), blocking both attack vectors.",
        summaryJa:
          "この実装は脆弱です: === 比較は一致プレフィックス長に比例してタイミング情報を漏洩し、4 バイト HMAC は 2^32 の総当り可能鍵空間しか持ちません。堅牢実装は crypto.timingSafeEqual (定数時間) + 32 バイト HMAC (2^256 鍵空間) を使用し、両攻撃経路を阻止します。",
        extra: {
          vulnerable0CharMatchMs,
          vulnerable16CharMatchMs,
          defendedConstantTimeMs,
          vulnerableTimingLeakageMs,
          shortHmacKeySpace,
          fullHmacKeySpaceLabel: "2^256 (≈ 10^77 — computationally infeasible)",
          vulnerableAttackFeasible,
          defendedAttackBlocked,
          shortHmacSample: shortHmac, // 8 hex chars — 公開可能な教育サンプル
          fullHmacSample: fullHmac, // 64 hex chars — 公開可能な教育サンプル
          simulationNote: {
            ja: "[教育用シミュレーション専用] 応答時間は概念的差異を誇張したサーバー側シミュレーション値です。実環境ではネットワーク遅延 / OS スケジューリングのジッターにより数十万回の測定と統計分析が必要です。総当り処理もサーバー側でシミュレーションしており、ブラウザからの実試行は行いません。",
            en: "[Educational simulation only] Response times are exaggerated server-side simulation values for conceptual clarity. In real environments, network jitter / OS scheduling requires tens of thousands of measurements + statistical analysis. Brute-force is also simulated server-side, not actually attempted from the browser.",
          },
        } satisfies ApikeyHmacBypassExtra,
        payload: {
          params: {},
          result: {
            vulnerable0CharMatchMs,
            vulnerable16CharMatchMs,
            defendedConstantTimeMs,
            vulnerableTimingLeakageMs,
            shortHmacKeySpace,
            vulnerableAttackFeasible,
            defendedAttackBlocked,
            // SEC FINDING-5: 教育用 demoSecret は payload_json でマスク (実値は公開可能な
            // ダミーだがマスクポリシー一貫性のため)。HMAC サンプルは公開教材値のため非マスク。
            demoSecretMasked: maskSecret(demoSecret),
          },
        },
      };
    },
  }),
);

// ════════════════════════════════════════════════════════════════════════════════
// Scenario C: タイムスタンプなしリプレイ — CWE-294, CAPEC-60
// ────────────────────────────────────────────────────────────────────────────────
// vulnerable: canonical = JSON.stringify(body) のみ (timestamp/nonce なし) → 同一
//             body であれば HMAC が同一 → 60 秒後の再送が成立
// defended:   canonical = `${timestamp}\n${JSON.stringify(body)}` + ±5 分 skew 検査
//             + handler-local nonce DB (使い捨て) → リプレイ拒否
//             → `timestamp_skew_and_nonce_one_time_use_enforced`
//
// DB 書き込みなし — handler-local Set で nonce を管理 (FIDO2 / OIDC-SAML 同パターン、
// ROB-FIDO2-2 教訓: モジュールスコープ singleton ではなく handler-local で setInterval リーク回避)。
// ════════════════════════════════════════════════════════════════════════════════
type ApikeyReplayNoTimestampExtra = {
  /** 脆弱パス: timestamp なし canonical で HMAC を計算 → 元と同一値が出る。 */
  vulnerableCanonicalReusable: boolean;
  /** 脆弱パス: 60 秒後の再送 (同一 HMAC) が受理される。 */
  vulnerableReplayAccepted: boolean;
  /** 堅牢パス: timestamp 込み canonical → ±5 分 skew 超過で拒否。 */
  defendedReplayBlockedByTimestampSkew: boolean;
  /** 堅牢パス: nonce 一意性 DB が同一窓内のリプレイを拒否。 */
  defendedReplayBlockedByNonce: boolean;
  /** 観測した timestamp skew (ms)。 */
  observedSkewMs: number;
  /** 設定された timestamp skew 窓 (ms)。 */
  timestampSkewLimitMs: number;
  /** リプレイ遅延 (秒) — 60 秒の通常リプレイ。 */
  replayDelaySec: number;
  /** 期限切れリプレイ遅延 (秒) — 360 秒 (skew 超過)。 */
  expiredReplayDelaySec: number;
  /** 脆弱 canonical (timestamp なし) のサンプル。 */
  vulnerableCanonical: string;
  /** 堅牢 canonical (timestamp 込み) のサンプル。 */
  defendedCanonical: string;
  /** 脆弱パスで生成された HMAC (元と同値 = リプレイ可能)。 */
  vulnerableHmacSample: string;
  /** 堅牢パスで生成された HMAC (timestamp 違いで毎回異なる)。 */
  defendedHmacSample: string;
  /** 教育用注記: HTTPS 前提と窓サイズ (DESIGN/19 §4.3 注記)。 */
  simulationNote: { ja: string; en: string };
};

ssoApikeyRoutes.post("/attack/replay-no-timestamp", (c) =>
  runAttackScenario<typeof ssoAttackReplayNoTimestampSchema, ApikeyReplayNoTimestampExtra>(c, {
    schema: ssoAttackReplayNoTimestampSchema,
    scenarioId: "apikey-replay-no-timestamp",
    tabId: "sso-idp-apikey",
    async handler({ recordStep, trace }) {
      // ROB-FIDO2-2 / SEC-OIDC-2 教訓: handler-local Set で nonce 管理。
      // モジュールスコープ singleton 化を避け、リクエストごとに fresh + setInterval 不要。
      const usedNonces = new Set<string>();

      // 教育用 HMAC 計算 (固定 secret + 固定 body)
      const demoSecret = "demo-hmac-secret-for-replay-scenario";
      const demoBody = { resource: "seed-resource", action: "read" };
      const originalTimestamp = "2026-04-30T12:00:00Z";
      const replayTimestamp = "2026-04-30T11:55:00Z"; // 5 分前 — replay 時に元 timestamp を流用

      // 脆弱版 canonical: timestamp なし (body のみ)
      const vulnerableCanonical = JSON.stringify(demoBody);
      const vulnerableHmac = crypto
        .createHmac("sha256", demoSecret)
        .update(vulnerableCanonical)
        .digest("hex");
      // 堅牢版 canonical: timestamp 込み
      const defendedCanonical = `${originalTimestamp}\n${JSON.stringify(demoBody)}`;
      const defendedHmac = crypto
        .createHmac("sha256", demoSecret)
        .update(defendedCanonical)
        .digest("hex");
      // 期限切れ replay 用 canonical (replayTimestamp で再計算 — HMAC は変わるがサーバー側 skew 検査で拒否される想定)
      const expiredReplayCanonical = `${replayTimestamp}\n${JSON.stringify(demoBody)}`;
      const expiredReplayHmac = crypto
        .createHmac("sha256", demoSecret)
        .update(expiredReplayCanonical)
        .digest("hex");

      // ── Step 1: probe — 攻撃者が有効な HMAC 署名済みリクエストを傍受
      trace.addCryptoOp({
        op: "buildCanonicalString (vulnerable: no timestamp)",
        input: `body=${vulnerableCanonical.substring(0, 40)}...`,
        output: vulnerableCanonical,
        algo: "string concatenation",
        detail:
          "WARNING: canonical string contains no timestamp — HMAC is replayable indefinitely without modification.",
      });
      trace.addCryptoOp({
        op: "HMAC-SHA256 (vulnerable canonical)",
        input: `secret=<masked>, data=canonical (no timestamp)`,
        output: vulnerableHmac.substring(0, 30) + "...",
        algo: "HMAC-SHA256",
        detail:
          "Identical canonical → identical HMAC. Server cannot distinguish original from replay without timestamp.",
      });
      recordStep({
        id: "sso-replay-1",
        kind: "probe",
        label: "Capture a valid HMAC-signed request (canonical = body only, no timestamp)",
        labelJa: "有効な HMAC 署名済みリクエストを傍受 (canonical = ボディのみ、タイムスタンプなし)",
        status: "success",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/sso/apikey/verify/hmac (intercepted; vulnerable variant — no timestamp)",
            body: {
              keyId: "demo_key_observed",
              body: demoBody,
              signature: vulnerableHmac.substring(0, 30) + "...",
            },
          },
          response: {
            status: 200,
            body: { valid: true, note: "Original request authenticated; attacker now possesses signature" },
          },
        },
        detailJa:
          "攻撃者は正規ユーザーの HMAC 署名済みリクエストを傍受します。canonical 文字列がボディのみで構成されているため、署名は body の値が変わらない限り有効です。",
        detail:
          "The attacker intercepts a valid HMAC-signed request. Since the canonical string contains only the body (no timestamp), the signature stays valid as long as the body doesn't change.",
      });

      // ── Step 2: tamper — 脆弱 canonical vs 堅牢 canonical の比較
      recordStep({
        id: "sso-replay-2",
        kind: "tamper",
        label: "Compare canonical strings: with/without timestamp produces different replay risk",
        labelJa: "canonical 文字列の比較: タイムスタンプ有無でリプレイリスクが変わる",
        status: "success",
        payload: {
          type: "generic",
          data: {
            vulnerableCanonical,
            vulnerableHmacPreview: vulnerableHmac.substring(0, 30) + "...",
            defendedCanonical,
            defendedHmacPreview: defendedHmac.substring(0, 30) + "...",
            note: "Vulnerable: same body → same canonical → same HMAC → indefinitely replayable. Defended: timestamp differs each request → canonical differs → HMAC differs → replay impossible without forging timestamp.",
          },
        },
        detailJa:
          "脆弱 canonical では同じボディが常に同じ HMAC を生成します。堅牢 canonical では timestamp が含まれるため、毎リクエスト異なる canonical → 異なる HMAC が生成されます。",
        detail:
          "The vulnerable canonical produces the same HMAC for the same body. The defended canonical includes the timestamp, so each request produces a different canonical → different HMAC.",
      });

      // ── Step 3: forge — 攻撃者が傍受したリクエストを 60 秒後に再送 (脆弱パス想定)
      recordStep({
        id: "sso-replay-3",
        kind: "forge",
        label: `Forge replay: resend intercepted request ${SSO_APIKEY_DEMO_CONSTANTS.replayDelaySec}s later (no canonical changes)`,
        labelJa: `フォージ: 傍受したリクエストを ${SSO_APIKEY_DEMO_CONSTANTS.replayDelaySec} 秒後に再送 (canonical は変更なし)`,
        status: "success",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/sso/apikey/verify/hmac (replay attempt)",
            body: {
              keyId: "demo_key_observed",
              body: demoBody, // 同一ボディ
              signature: vulnerableHmac.substring(0, 30) + "...", // 同一署名
              delaySimulatedSec: SSO_APIKEY_DEMO_CONSTANTS.replayDelaySec,
            },
          },
        },
        detailJa:
          "攻撃者は元のリクエストを 60 秒後にそのまま再送します。canonical 文字列が body のみで構成されているため、HMAC は元のリクエストと完全に同一です。",
        detail:
          "The attacker resends the original request 60 seconds later, unchanged. Since the canonical string is body-only, the HMAC matches the original byte-for-byte.",
      });

      // ── Step 4: exploit (脆弱モード) — timestamp なし canonical でリプレイが受理される
      // SSoT 派生 (R-MEDIUM-1 教訓): bare literal `true` を避ける。
      //   vulnerableReplayAccepted = (canonical に timestamp が含まれない) AND (HMAC が同値で照合一致する)
      // 将来 vulnerableCanonical に timestamp を含めるようにすると flag が false に転じる sentinel 化。
      const vulnerableCanonicalLacksTimestamp = !vulnerableCanonical.includes("T"); // ISO-8601 の 'T' で簡易判定
      const vulnerableHmacReproduces = vulnerableHmac === crypto
        .createHmac("sha256", demoSecret)
        .update(vulnerableCanonical)
        .digest("hex");
      const vulnerableReplayAccepted = vulnerableCanonicalLacksTimestamp && vulnerableHmacReproduces;
      const vulnerableCanonicalReusable = vulnerableCanonicalLacksTimestamp;

      recordStep({
        id: "sso-replay-4",
        kind: "exploit",
        label: "Vulnerable: replay accepted — server cannot detect duplicate without timestamp",
        labelJa: "脆弱版: リプレイ受理 — タイムスタンプなしではサーバーが重複を検出できない",
        status: vulnerableReplayAccepted ? "success" : "failed",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/sso/apikey/verify/hmac (vulnerable variant — body-only canonical)",
          },
          response: {
            status: 200,
            body: {
              valid: true,
              note: "Vulnerable: same body + same signature = same canonical → server has no way to detect this is a replay",
              vulnerableCanonicalLacksTimestamp,
              vulnerableHmacReproduces,
            },
          },
        },
        detailJa:
          "この実装は脆弱です: canonical 文字列がボディのみで構成されているため、攻撃者は元のリクエストをそのまま無期限に再送できます。サーバーは元のリクエストとリプレイを区別する手段がありません。",
        detail:
          "This implementation is vulnerable: with a body-only canonical, the attacker can resend the original request indefinitely. The server has no way to distinguish original from replay.",
      });

      // ── Step 5: verify (堅牢モード) — timestamp ±5 分 + nonce DB でリプレイ拒否
      // 5a: timestamp skew 検査 (±5 分窓を 6 分前のリプレイで超過)
      const expiredReplayDelayMs = SSO_APIKEY_DEMO_CONSTANTS.expiredReplayDelaySec * 1000;
      const observedSkewMs = expiredReplayDelayMs;
      const skewExceeded = observedSkewMs > SSO_APIKEY_DEMO_CONSTANTS.timestampSkewMs;
      // 5b: nonce 一意性検査 (handler-local Set で 1 回目登録 → 2 回目は HIT)
      const demoNonce = uuidv4();
      const firstNonceCheck = !usedNonces.has(demoNonce);
      usedNonces.add(demoNonce);
      const replayNonceCheck = !usedNonces.has(demoNonce);
      // SSoT 派生: defendedReplayBlockedByNonce = (初回未使用) AND (リプレイで HIT) → 両方成立してこそ防御成立
      // ROB-MFA-1 教訓: bare literal `true` ではなく Set ベース防御の動作確認結果から導出。
      const defendedReplayBlockedByNonce = firstNonceCheck && !replayNonceCheck;
      // SSoT 派生: defendedReplayBlockedByTimestampSkew = (skew が窓を超えた) — 360s > 300s の関係
      const defendedReplayBlockedByTimestampSkew = skewExceeded;

      trace.addCryptoOp({
        op: "timestampSkewCheck (defended)",
        input: `timestamp=${replayTimestamp}, now=${originalTimestamp}, skewMs=${observedSkewMs}`,
        output: skewExceeded ? `REJECTED (skew=${observedSkewMs / 1000}s > limit=${SSO_APIKEY_DEMO_CONSTANTS.timestampSkewMs / 1000}s)` : "accepted",
        algo: "±5min (300s) window",
        detail:
          "Defended: server checks |now - timestamp| <= timestampSkewMs and rejects requests outside the window. sso-apikey.ts:189-207.",
      });
      trace.addCryptoOp({
        op: "nonceUniquenessCheck (defended)",
        input: `nonce=${demoNonce.substring(0, 8)}..., usedNonces.size=${usedNonces.size}`,
        output: defendedReplayBlockedByNonce ? "REJECTED on second use" : "first use accepted",
        algo: "handler-local Set (FIDO2 / OIDC-SAML pattern, ROB-FIDO2-2 / SEC-OIDC-2 同パターン)",
        detail:
          "Defended: first call accepts the nonce and stores it. The replay attempt finds the nonce in the Set and rejects.",
      });

      recordStep({
        id: "sso-replay-5",
        kind: "verify",
        label: "Defended: ±5min timestamp skew + nonce uniqueness reject the replay",
        labelJa: "堅牢版: ±5 分タイムスタンプ skew + nonce 一意性検査がリプレイを拒否",
        status: "blocked",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/sso/apikey/verify/hmac (defended — sso-apikey.ts:189-235)",
            body: {
              keyId: "demo_key_observed",
              timestamp: replayTimestamp, // 5 分前 — 窓外
              body: demoBody,
              signature: expiredReplayHmac.substring(0, 30) + "...",
            },
          },
          response: {
            status: 401,
            body: {
              error: "Timestamp invalid or outside ±5min skew window",
              defendedReplayBlockedByTimestampSkew,
              defendedReplayBlockedByNonce,
              blockedBy: "timestamp_skew_and_nonce_one_time_use_enforced",
              note: "Defended: two-layer defense — (1) ±5min skew rejects expired timestamps; (2) handler-local nonce Set rejects same-window replays.",
            },
          },
        },
        detailJa:
          "堅牢実装は二層防御を提供します: (1) timestamp ±5 分窓が期限切れリクエストを拒否 (sso-apikey.ts:189-207)、(2) nonce 一意性検査が窓内のリプレイを拒否 (handler-local Set、5 分後に自動失効)。両層が突破できないため、攻撃者はリプレイに失敗します。",
        detail:
          "The defended implementation provides two-layer defense: (1) timestamp ±5min skew rejects expired requests (sso-apikey.ts:189-207); (2) nonce uniqueness rejects in-window replays (handler-local Set, auto-expires after 5min). Both layers must be bypassed for replay to succeed.",
      });

      return {
        blockedBy: "timestamp_skew_and_nonce_one_time_use_enforced",
        summary:
          "An HMAC-signed request without a timestamp in the canonical string can be replayed indefinitely — the same body produces the same signature. The defended implementation includes timestamp in canonical and validates ±5min skew, plus nonce uniqueness via a handler-local cache, blocking both stale and in-window replays.",
        summaryJa:
          "この実装は脆弱です: canonical 文字列にタイムスタンプを含まない HMAC 署名は、同じ body が同じ署名を生成するため無期限にリプレイ可能です。堅牢実装は canonical にタイムスタンプを含めて ±5 分 skew で検査し、さらに handler-local nonce DB で一意性を担保することで、期限切れリプレイと窓内リプレイの両方を阻止します。",
        extra: {
          vulnerableCanonicalReusable,
          vulnerableReplayAccepted,
          defendedReplayBlockedByTimestampSkew,
          defendedReplayBlockedByNonce,
          observedSkewMs,
          timestampSkewLimitMs: SSO_APIKEY_DEMO_CONSTANTS.timestampSkewMs,
          replayDelaySec: SSO_APIKEY_DEMO_CONSTANTS.replayDelaySec,
          expiredReplayDelaySec: SSO_APIKEY_DEMO_CONSTANTS.expiredReplayDelaySec,
          vulnerableCanonical,
          defendedCanonical,
          vulnerableHmacSample: vulnerableHmac,
          defendedHmacSample: defendedHmac,
          simulationNote: {
            ja: "[教育用シミュレーション専用] 実環境でのリプレイ攻撃には HTTPS 通信の傍受 (MITM) が前提となります。HTTPS 使用時は傍受自体が困難です。本デモは HTTP または鍵漏洩後のシナリオを想定しています。±5 分は NTP ずれを考慮した標準的な設定です。",
            en: "[Educational simulation only] Real-world replay requires intercepting HTTPS traffic (MITM); HTTPS makes interception itself difficult. This demo assumes HTTP or post-key-leak scenarios. ±5 minutes is a standard setting accommodating NTP clock drift.",
          },
        } satisfies ApikeyReplayNoTimestampExtra,
        payload: {
          params: {},
          result: {
            vulnerableCanonicalReusable,
            vulnerableReplayAccepted,
            defendedReplayBlockedByTimestampSkew,
            defendedReplayBlockedByNonce,
            observedSkewMs,
            // SEC FINDING-5: 教育用 demoSecret は payload_json でマスク。
            // canonical / HMAC サンプルは公開可能な教材値 (固定文字列) のため非マスク。
            demoSecretMasked: maskSecret(demoSecret),
          },
        },
      };
    },
  }),
);
