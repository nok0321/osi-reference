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
 *
 * E-2: 各攻撃シナリオは 1 リクエストで 5 ステップ完全形 (probe → tamper → forge → exploit → verify) を実行し、
 *      ステップ 4 (exploit) で脆弱モード結果、ステップ 5 (verify) で堅牢モード結果を返す。
 *      両モード並列実行のため、リクエスト body にモード選択フィールドはなく、outcome は常に "succeeded" を返す。
 *
 * Phase 2 第二コミット (SEC-12 / ROB-FIND-011): 共通ヘルパー `runAttackScenario` を経由してボイラープレート集約。
 *      各ハンドラは 5 ステップの recordStep + AttackRunResult メタデータ返却に専念する。
 */
import { Hono } from "hono";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import {
  parseBody,
  jwtSignSchema,
  jwtVerifySchema,
  jwtDecodeSchema,
  jwtAttackAlgNoneSchema,
  jwtAttackWeakSecretSchema,
  jwtAttackSignatureStrippingSchema,
  jwtAttackKidInjectionSchema,
} from "../validation.js";
import { runAttackScenario, maskSecret, sanitizeForDisplay } from "../utils/attack-runner.js";

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
  // 教材用に秘密鍵を表示するエンドポイントだが、本番環境では絶対に公開しない (SEC FINDING-2 対応)。
  // 秘密鍵漏洩は weak-secret-bruteforce 攻撃シナリオの「強い秘密鍵が辞書に含まれない」前提を破壊する。
  if (process.env.NODE_ENV === "production") {
    return c.json({ success: false, error: "Key disclosure endpoint disabled in production" }, 403);
  }
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
jwtOpsRoutes.post("/attack/alg-none", (c) =>
  runAttackScenario(c, {
    schema: jwtAttackAlgNoneSchema,
    scenarioId: "jwt-alg-none",
    tabId: "jwt",
    async handler({ trace, recordStep }) {
      // ── Step 1: probe — 元 JWT ヘッダをデコード ──
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

      // ── Step 2: tamper — alg=none に書き換え + role admin 昇格 ──
      const forgedHeader = { alg: "none", typ: "JWT" };
      const forgedPayload = { ...SEED_ALICE_PAYLOAD, role: "admin" };
      const forgedHeaderB64 = Buffer.from(JSON.stringify(forgedHeader)).toString("base64url");
      const forgedPayloadB64 = Buffer.from(JSON.stringify(forgedPayload)).toString("base64url");
      trace.addCryptoOp({
        op: "base64url.encode(forged-header)",
        input: JSON.stringify(forgedHeader),
        output: forgedHeaderB64,
        algo: "base64url",
      });
      trace.addCryptoOp({
        op: "base64url.encode(forged-payload)",
        input: JSON.stringify(forgedPayload),
        output: forgedPayloadB64,
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

      // ── Step 3: forge — 署名セグメント削除 (末尾ドットを維持) ──
      const forgedToken = `${forgedHeaderB64}.${forgedPayloadB64}.`;
      recordStep({
        id: "alg-none-3",
        kind: "forge",
        label: "Drop signature segment (keep trailing dot)",
        labelJa: "署名セグメントを削除 (末尾ドットを維持)",
        status: "success",
        payload: {
          type: "token",
          after: forgedToken,
          algo: "none",
          signatureValid: false,
        },
        detailJa: "alg=none トークンは空の署名セグメントが必要です。末尾のドットは JWT 仕様で必須です。",
        detail: "alg=none tokens must have an empty signature. The trailing dot is required by the JWT spec.",
      });

      // ── Step 4: exploit — 偽造トークンを脆弱検証エンドポイントに送信 (lenient mode) ──
      const [, lenientPart] = forgedToken.split(".");
      const lenientDecoded = JSON.parse(Buffer.from(lenientPart, "base64url").toString("utf8"));
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
          request: { method: "POST", url: "/api/jwt/attack/alg-none" },
          response: { status: 200, body: { decoded: lenientDecoded, accepted: true } },
        },
        detailJa: "脆弱なエンドポイントは algorithms オプションなしで jwt.verify() を呼ぶため、alg=none を受け入れます。",
        detail: "The lenient endpoint calls jwt.verify() without specifying algorithms, accepting alg=none.",
      });

      // ── Step 5: verify — 同じ偽造トークンを堅牢検証エンドポイントに送信 (strict mode) ──
      let strictError = "invalid algorithm";
      try {
        jwt.verify(forgedToken, HS256_SECRET, { algorithms: ALLOWED_ALGORITHMS });
      } catch (err) {
        strictError = err instanceof Error ? err.message : "verification failed";
      }
      trace.addCryptoOp({
        op: "jwt.verify(strict)",
        input: forgedToken.substring(0, 40) + "...",
        output: `REJECTED (${strictError})`,
        algo: "HS256",
        detail: "Strict verifier rejects alg=none via algorithms allowlist",
      });
      recordStep({
        id: "alg-none-5",
        kind: "verify",
        label: "Send same forged token to strict verifier",
        labelJa: "同じ偽造トークンを堅牢検証エンドポイントに送信",
        status: "blocked",
        payload: {
          type: "http",
          request: { method: "POST", url: "/api/jwt/attack/alg-none" },
          response: { status: 401, body: { error: strictError, blockedBy: "jwt_algorithms_allowlist" } },
        },
        detailJa: "堅牢なエンドポイントは jwt.verify() に { algorithms: ['HS256', 'RS256'] } を渡し、none を拒否します。",
        detail: "The strict endpoint passes { algorithms: ['HS256', 'RS256'] } to jwt.verify(), rejecting none.",
      });

      return {
        blockedBy: "jwt_algorithms_allowlist",
        summary: "Lenient verifier accepted alg=none (vulnerable). Strict verifier with algorithms allowlist rejected it (defense worked).",
        summaryJa: "脆弱検証は alg=none を受理しましたが、algorithms 許可リストを指定した堅牢検証は拒否しました。",
        payload: {
          params: {},
          result: { forgedTokenPreview: forgedToken.substring(0, 60), strictError },
        },
      };
    },
  }),
);

// ── Scenario B: HS256 弱秘密鍵ブルートフォース ──
type WeakSecretExtra = { crackedSecret: string | null; attemptCount: number };

jwtOpsRoutes.post("/attack/weak-secret-bruteforce", (c) =>
  runAttackScenario<typeof jwtAttackWeakSecretSchema, WeakSecretExtra>(c, {
    schema: jwtAttackWeakSecretSchema,
    scenarioId: "jwt-weak-secret-bruteforce",
    tabId: "jwt",
    async handler({ body, trace, recordStep }) {
      const { dictionarySize } = body;
      const candidates = COMMON_DICT.slice(0, dictionarySize);

      // 弱トークン (秘密鍵 = "secret"、辞書 1 件目で発見される) と強トークン (HS256_SECRET) を両方生成
      const weakSecret = "secret";
      const strongSecret = HS256_SECRET;
      const tokenPayload = { sub: "seed_alice", role: "admin", iat: Math.floor(Date.now() / 1000) };
      const weakToken = jwt.sign(tokenPayload, weakSecret, { algorithm: "HS256" });
      const strongToken = jwt.sign(tokenPayload, strongSecret, { algorithm: "HS256" });

      // ── Step 1: intercept ──
      recordStep({
        id: "brute-1",
        kind: "intercept",
        label: "Capture HS256 JWT token",
        labelJa: "HS256 JWT トークンを入手",
        status: "success",
        payload: {
          type: "token",
          before: weakToken.substring(0, 40) + "...",
          algo: "HS256",
          decodedHeader: { alg: "HS256", typ: "JWT" },
          decodedPayload: tokenPayload,
        },
        detailJa: "攻撃者は HS256 署名済みトークンを入手します。署名入力 (header.payload) は公開情報です。",
        detail: "Attacker obtains a signed HS256 token. Signing input is public (header.payload).",
      });

      // ── Step 2: probe ──
      recordStep({
        id: "brute-2",
        kind: "probe",
        label: `Begin offline dictionary attack (${candidates.length} candidates)`,
        labelJa: `オフライン辞書攻撃を開始 (${candidates.length} 候補)`,
        status: "success",
        payload: {
          type: "generic",
          data: {
            dictionary: candidates.slice(0, 10),
            totalCandidates: candidates.length,
            targetAlgo: "HMAC-SHA256",
            serverConnectionRequired: false,
          },
        },
        detail: "HMAC-SHA256 can be computed locally. No server requests needed.",
        detailJa: "HMAC-SHA256 はローカルで計算できます。サーバーへのリクエストは不要です。",
      });

      // ── Step 3: exploit — 弱秘密鍵側で辞書ループ実行 ──
      let crackedSecret: string | null = null;
      let weakAttemptCount = 0;
      const triedPasswords: string[] = [];
      for (const candidate of candidates) {
        weakAttemptCount++;
        triedPasswords.push(candidate);
        try {
          jwt.verify(weakToken, candidate, { algorithms: ALLOWED_ALGORITHMS });
          crackedSecret = candidate;
          break;
        } catch {
          // 不一致、次の候補へ
        }
      }
      trace.addCryptoOp({
        op: `HMAC-SHA256 dictionary trial (weak target, ${weakAttemptCount} attempts)`,
        input: `target=${weakToken.substring(0, 30)}..., dict=${candidates.length} candidates`,
        output: crackedSecret ? `MATCH: "${crackedSecret}" at attempt ${weakAttemptCount}` : `NO MATCH`,
        algo: "HMAC-SHA256",
      });
      recordStep({
        id: "brute-3",
        kind: "exploit",
        label: "Match found: weak secret cracked",
        labelJa: "一致発見: 弱い秘密鍵がクラックされました",
        status: "success",
        payload: {
          type: "credential",
          crackedPassword: crackedSecret ?? undefined,
          triedPasswords: triedPasswords.slice(0, Math.min(triedPasswords.length, 10)),
        },
        detailJa: `HMAC-SHA256(header.payload, '${crackedSecret}') がトークン署名と一致しました (${weakAttemptCount} 件目)。`,
        detail: `HMAC-SHA256(header.payload, '${crackedSecret}') matches the token signature at attempt ${weakAttemptCount}.`,
      });

      // ── Step 4: forge — クラックした秘密鍵で偽造トークン署名 ──
      let forgedAdminToken = "";
      if (crackedSecret) {
        const adminPayload = { sub: "attacker_charlie", role: "admin" };
        forgedAdminToken = jwt.sign(adminPayload, crackedSecret, { algorithm: "HS256" });
        trace.addCryptoOp({
          op: "jwt.sign(forgedPayload, crackedSecret)",
          input: JSON.stringify(adminPayload),
          output: forgedAdminToken.substring(0, 40) + "...",
          algo: "HS256",
        });
        recordStep({
          id: "brute-4",
          kind: "forge",
          label: "Re-sign token with cracked secret (role=admin)",
          labelJa: "クラックした秘密鍵で新規トークン署名 (role=admin)",
          status: "success",
          payload: {
            type: "token",
            after: forgedAdminToken.substring(0, 40) + "...",
            algo: "HS256",
            decodedPayload: adminPayload,
            signatureValid: true,
          },
          detailJa: "秘密鍵が判明すれば、任意のペイロードで有効な署名を生成できます。",
          detail: "With the secret known, attacker can forge any payload with a valid signature.",
        });
      } else {
        // 通常はここに到達しない (辞書 1 件目で発見されるため) が、セーフティとして記録
        recordStep({
          id: "brute-4",
          kind: "forge",
          label: "Forge step skipped (no secret cracked)",
          labelJa: "偽造ステップをスキップ (秘密鍵未発見)",
          status: "failed",
          payload: { type: "generic", data: { reason: "Weak secret not in dictionary" } },
        });
      }

      // ── Step 5: verify — 強秘密鍵側で辞書ループ実行 ──
      let strongAttemptCount = 0;
      let strongCracked: string | null = null;
      for (const candidate of candidates) {
        strongAttemptCount++;
        try {
          jwt.verify(strongToken, candidate, { algorithms: ALLOWED_ALGORITHMS });
          strongCracked = candidate;
          break;
        } catch {
          // 不一致、続行
        }
      }
      trace.addCryptoOp({
        op: `HMAC-SHA256 dictionary trial (strong target, ${strongAttemptCount} attempts)`,
        input: `target=${strongToken.substring(0, 30)}..., dict=${candidates.length} candidates`,
        output: strongCracked ? `MATCH: "${strongCracked}"` : `NO MATCH (${strongAttemptCount} attempts)`,
        algo: "HMAC-SHA256",
      });
      // ROB-FIND-010: 強秘密鍵が辞書でクラックされた場合は HS256_SECRET 設定ミス。
      // 防御失敗を示すため status=failed + 警告ラベルで記録 (status=blocked と取り違えない)。
      if (strongCracked !== null) {
        recordStep({
          id: "brute-5",
          kind: "verify",
          label: `WARNING: strong secret unexpectedly cracked at "${strongCracked}" — HS256_SECRET misconfigured`,
          labelJa: `警告: 強秘密鍵が予期せずクラック ("${strongCracked}") — HS256_SECRET 設定ミス`,
          status: "failed",
          payload: {
            type: "generic",
            data: {
              warning: "strong_secret_in_dictionary",
              strongSecretLength: strongSecret.length,
              triedCandidates: strongAttemptCount,
              matchedCandidate: strongCracked,
            },
          },
          detailJa: "防御が機能していません。HS256_SECRET を 32 バイト以上のランダム値に再設定してください。",
          detail: "Defense did not engage. Reset HS256_SECRET to a 32+ byte random value.",
        });
      } else {
        recordStep({
          id: "brute-5",
          kind: "verify",
          label: `Strong random secret resists dictionary (all ${strongAttemptCount} fail)`,
          labelJa: `十分なランダム秘密鍵では辞書が通用しない (${strongAttemptCount} 件全て失敗)`,
          status: "blocked",
          payload: {
            type: "generic",
            data: {
              strongSecretLength: strongSecret.length,
              triedCandidates: strongAttemptCount,
              matched: 0,
            },
          },
          detailJa: `${strongSecret.length} 文字のランダム文字列はいかなる辞書にも含まれません。ブルートフォースは失敗します。`,
          detail: `A ${strongSecret.length}-char random secret is not in any dictionary. Brute force fails.`,
        });
      }

      return {
        blockedBy: "strong_random_secret",
        summary: `Weak secret cracked at attempt ${weakAttemptCount} (vulnerable). Strong ${strongSecret.length}-char random secret resisted all ${strongAttemptCount} attempts (defense worked).`,
        summaryJa: `弱秘密鍵は ${weakAttemptCount} 件目でクラックされましたが、${strongSecret.length} 文字のランダム秘密鍵は ${strongAttemptCount} 件全てに耐えました。`,
        // 表示用 extra は教育目的のため平文 (フロントの DataFlowPanel で見せる)
        extra: { crackedSecret, attemptCount: weakAttemptCount },
        payload: {
          params: { dictionarySize },
          // SEC FINDING-5: DB 保存用 payload_json では crackedSecret をマスク (長さ情報のみ保持)
          result: {
            weakAttemptCount,
            strongAttemptCount,
            crackedSecretMasked: maskSecret(crackedSecret),
            forgedAdminTokenPreview: forgedAdminToken ? forgedAdminToken.substring(0, 40) : null,
          },
        },
      };
    },
  }),
);

// ── Scenario C: 署名ストリッピング ──
jwtOpsRoutes.post("/attack/signature-stripping", (c) =>
  runAttackScenario(c, {
    schema: jwtAttackSignatureStrippingSchema,
    scenarioId: "jwt-signature-stripping",
    tabId: "jwt",
    async handler({ body, trace, recordStep }) {
      const { forgedToken: reqToken } = body;
      const forgedHeaderB64 = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
      const forgedPayload = { sub: "attacker_charlie", role: "admin", iat: 1714000000 };
      const forgedPayloadB64 = Buffer.from(JSON.stringify(forgedPayload)).toString("base64url");
      const forgedToken = reqToken ?? `${forgedHeaderB64}.${forgedPayloadB64}.INVALID_SIGNATURE_PLACEHOLDER`;

      // ── Step 1: probe ──
      recordStep({
        id: "strip-1",
        kind: "probe",
        label: "Inspect target: uses jwt.decode() without verify",
        labelJa: "ターゲット調査: jwt.decode() のみで verify を省略",
        status: "success",
        payload: {
          type: "generic",
          data: {
            vulnerableCode: "const user = jwt.decode(token); // verify() を呼ばずに信頼",
            secureCode: "const user = jwt.verify(token, secret, { algorithms: ['HS256'] });",
            antipatternReason: "decode() はヘッダ/ペイロードを Base64url 復号するだけで署名を検証しない",
          },
        },
        detailJa: "jwt.decode() はデコードのみで、署名を一切検証しません。任意の偽造トークンが通過します。",
        detail: "jwt.decode() only decodes — it never checks the signature. Any forged token passes.",
      });

      // ── Step 2: tamper ──
      recordStep({
        id: "strip-2",
        kind: "tamper",
        label: "Craft token with valid header+payload but invalid signature",
        labelJa: "有効なヘッダ+ペイロードを持つが署名が無効なトークンを作成",
        status: "success",
        payload: {
          type: "token",
          before: forgedToken.substring(0, 40) + "...",
          decodedHeader: { alg: "HS256", typ: "JWT" },
          decodedPayload: forgedPayload,
          algo: "HS256",
          signatureValid: false,
        },
        detail: "Token has a valid structure but the signature segment is forged.",
        detailJa: "トークンは有効な構造ですが、署名セグメントは偽造されています。",
      });

      // ── Step 3: forge ──
      recordStep({
        id: "strip-3",
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

      // ── Step 4: exploit — decode-only エンドポイントが署名未検証でペイロードを返す (脆弱モード) ──
      // ROB-FIND-003: jwt.decode() は壊れたトークン (Base64url 不正・ピリオド数不一致) で null を返す。
      // null の場合は教育的整合性のため "failed" ステップとして記録し、誤って "success" と表示しない。
      const lenientDecoded = jwt.decode(forgedToken, { complete: true });
      if (lenientDecoded === null) {
        trace.addCryptoOp({
          op: "jwt.decode(token) — no verification",
          input: forgedToken.substring(0, 40) + "...",
          output: "DECODE FAILED (malformed token structure)",
          algo: "none",
          detail: "jwt.decode() returned null — token is structurally invalid.",
        });
        recordStep({
          id: "strip-4",
          kind: "exploit",
          label: "decode-only endpoint cannot decode malformed token",
          labelJa: "decode-only エンドポイントが壊れたトークンをデコードできない",
          status: "failed",
          payload: {
            type: "generic",
            data: { reason: "Malformed token: jwt.decode() returned null" },
          },
          detailJa: "提供されたトークンは構造的に無効なため、decode-only エンドポイントでもペイロードを取得できません。",
          detail: "The provided token is structurally invalid — even decode-only cannot extract a payload.",
        });
      } else {
        const payloadPreview = JSON.stringify(lenientDecoded.payload ?? {}).substring(0, 60);
        trace.addCryptoOp({
          op: "jwt.decode(token) — no verification",
          input: forgedToken.substring(0, 40) + "...",
          output: `DECODED (no signature check): ${payloadPreview}...`,
          algo: "none",
          detail: "jwt.decode() does not verify the signature — any payload is accepted.",
        });
        recordStep({
          id: "strip-4",
          kind: "exploit",
          label: "decode-only endpoint returns payload without verification",
          labelJa: "decode-only エンドポイントが署名未検証でペイロードを返す",
          status: "success",
          payload: {
            type: "http",
            request: { method: "POST", url: "/api/jwt/attack/signature-stripping" },
            response: { status: 200, body: { decoded: lenientDecoded.payload, accepted: true } },
          },
          detailJa: "decode-only エンドポイントは署名に関わらず任意のトークンを受け入れます。",
          detail: "The decode-only endpoint accepts any token regardless of signature.",
        });
      }

      // ── Step 5: verify — verify エンドポイントが署名不一致を検出して拒否 (堅牢モード) ──
      let strictError = "invalid signature";
      try {
        jwt.verify(forgedToken, HS256_SECRET, { algorithms: ALLOWED_ALGORITHMS });
      } catch (err) {
        strictError = err instanceof Error ? err.message : "verification failed";
      }
      trace.addCryptoOp({
        op: "jwt.verify(token, secret)",
        input: forgedToken.substring(0, 40) + "...",
        output: `REJECTED (${strictError})`,
        algo: "HS256",
        detail: "jwt.verify() recomputes the HMAC and rejects tokens with invalid signatures.",
      });
      recordStep({
        id: "strip-5",
        kind: "verify",
        label: "Strict verifier rejects token with invalid signature",
        labelJa: "堅牢検証が無効な署名を持つトークンを拒否",
        status: "blocked",
        payload: {
          type: "http",
          request: { method: "POST", url: "/api/jwt/attack/signature-stripping" },
          response: { status: 401, body: { error: strictError, blockedBy: "jwt_signature_mismatch" } },
        },
        detailJa: "jwt.verify() が署名の不一致を検出し、JsonWebTokenError をスローします。",
        detail: "jwt.verify() detects the signature mismatch and throws JsonWebTokenError.",
      });

      return {
        blockedBy: "jwt_signature_mismatch",
        summary: "decode-only endpoint accepted forged token (vulnerable). jwt.verify() rejected it (defense worked).",
        summaryJa: "decode-only エンドポイントは偽造トークンを受理しましたが、jwt.verify() は拒否しました。",
        payload: {
          params: { forgedTokenPreview: forgedToken.substring(0, 60) },
          result: { strictError, lenientDecoded: lenientDecoded === null ? "malformed" : "decoded" },
        },
      };
    },
  }),
);

// ── Scenario D: kid ヘッダインジェクション ──
// ROB-FIND-007: ReadonlySet 型で許可リストを変更不能化 (TypeScript 静的検証)
const ALLOWED_KID: ReadonlySet<string> = new Set(["key-1", "key-2"]);
const DEFAULT_INJECTED_KID = "../public/attacker-key.pem";

type KidInjectionExtra = { kidResolved: string };

jwtOpsRoutes.post("/attack/kid-injection", (c) =>
  runAttackScenario<typeof jwtAttackKidInjectionSchema, KidInjectionExtra>(c, {
    schema: jwtAttackKidInjectionSchema,
    scenarioId: "jwt-kid-injection",
    tabId: "jwt",
    async handler({ body, trace, recordStep }) {
      const { injectedKid } = body;
      // SEC FINDING-3: 攻撃者制御の文字列は表示前に制御文字除去 + 長さ制限 (XSS sink 防御深層)。
      // schema 側で 256 文字上限を持つため maxLen=256 で透過するが、制御文字 (タブ・改行・NUL) は ? に正規化。
      const kid = sanitizeForDisplay(injectedKid ?? DEFAULT_INJECTED_KID, 256);

      // ── Step 1: probe ──
      recordStep({
        id: "kid-1",
        kind: "probe",
        label: "Inspect JWT kid header field",
        labelJa: "JWT kid ヘッダフィールドを調査",
        status: "success",
        payload: {
          type: "token",
          decodedHeader: { alg: "RS256", typ: "JWT", kid: "key-1" },
          decodedPayload: { sub: "seed_alice", role: "viewer" },
          algo: "RS256",
        },
        detailJa: "kid (Key ID) ヘッダはサーバーに検証に使う鍵を指示します。",
        detail: "The kid (Key ID) header tells the server which key to use for verification.",
      });

      // ── Step 2: tamper ──
      recordStep({
        id: "kid-2",
        kind: "tamper",
        label: "Inject path traversal in kid header",
        labelJa: "kid ヘッダにパストラバーサルを注入",
        status: "success",
        payload: {
          type: "token",
          decodedHeader: { alg: "RS256", typ: "JWT", kid },
          algo: "RS256",
        },
        detailJa: `攻撃者は kid を "${kid}" に置き換えます — パストラバーサルペイロードです。`,
        detail: `Attacker replaces kid with "${kid}" — a path traversal payload.`,
      });

      // ── Step 3: forge — 攻撃者制御の鍵で偽造ペイロードに署名 (シミュレーション) ──
      // 実際のファイル読み込みは絶対に行わない (隔離原則)
      recordStep({
        id: "kid-3",
        kind: "forge",
        label: "Sign forged payload with attacker-controlled key (simulated)",
        labelJa: "攻撃者制御の鍵で偽造ペイロードに署名 (シミュレーション)",
        status: "success",
        payload: {
          type: "token",
          decodedHeader: { alg: "RS256", typ: "JWT", kid },
          decodedPayload: { sub: "attacker_charlie", role: "admin" },
          algo: "RS256",
          signatureValid: true,
        },
        detailJa: "シミュレーション: 攻撃者の秘密鍵で偽造トークンを署名。サーバーは attacker-key.pem を鍵として読み込みます。",
        detail: "Simulated: forged token signed with attacker's private key. Server will load attacker-key.pem for verification.",
      });

      // ── Step 4: exploit — 脆弱な kid 解決エンドポイントが偽造トークンを受理 (脆弱モード) ──
      trace.addCryptoOp({
        op: "kid resolution (simulated)",
        input: `kid="${kid}"`,
        output: "RESOLVED to attacker-controlled key (simulated, NO file read)",
        algo: "RS256",
        detail: "Vulnerable mode: kid is used as path without sanitization. NO actual file read.",
      });
      recordStep({
        id: "kid-4",
        kind: "exploit",
        label: "Vulnerable verifier accepts forged token with injected kid",
        labelJa: "脆弱な検証が注入された kid を持つ偽造トークンを受理",
        status: "success",
        payload: {
          type: "http",
          request: { method: "POST", url: "/api/jwt/attack/kid-injection" },
          response: { status: 200, body: { kidResolved: kid, accepted: true } },
        },
        detailJa: "サーバーはサニタイズなしに kid から派生したパスの鍵を読み込みます (シミュレーション)。",
        detail: "The server loads the key at the path derived from kid without sanitization (simulated).",
      });

      // ── Step 5: verify — 許可リスト検証エンドポイントが未知の kid を拒否 (堅牢モード) ──
      const isAllowed = ALLOWED_KID.has(kid);
      trace.addCryptoOp({
        op: "kid allowlist check",
        input: `kid="${kid}", allowlist=["key-1","key-2"]`,
        output: isAllowed ? "ALLOWED" : "REJECTED (not in allowlist)",
        algo: "validation",
      });
      // 注入された kid (デフォルト DEFAULT_INJECTED_KID) は ALLOWED_KID に含まれない設計
      recordStep({
        id: "kid-5",
        kind: "verify",
        label: "Allowlist-protected endpoint rejects injected kid",
        labelJa: "許可リスト保護エンドポイントが注入 kid を拒否",
        status: "blocked",
        payload: {
          type: "http",
          request: { method: "POST", url: "/api/jwt/attack/kid-injection" },
          response: {
            status: 401,
            body: { error: `unknown key id: ${kid}`, blockedBy: "jwt_kid_not_in_allowlist" },
          },
        },
        detailJa: `許可リスト検証: 有効な kid は "key-1", "key-2" のみ。"${kid}" は拒否されます。`,
        detail: `Allowlist validation: only "key-1", "key-2" are valid kids. "${kid}" is rejected.`,
      });

      return {
        blockedBy: "jwt_kid_not_in_allowlist",
        summary: `Vulnerable verifier resolved kid "${kid}" as file path (simulated). Allowlist verifier rejected it (defense worked).`,
        summaryJa: `脆弱検証は kid "${kid}" をファイルパスとして解決 (シミュレーション)、許可リスト検証は拒否しました。`,
        extra: { kidResolved: kid },
        payload: {
          params: { injectedKid: kid },
          result: { isAllowed },
        },
      };
    },
  }),
);
