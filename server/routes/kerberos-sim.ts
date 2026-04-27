import { Hono } from "hono";
import crypto from "crypto";
import { getDb } from "../db/schema.js";
import {
  parseBody,
  kerberosAsReqSchema,
  kerberosTgsReqSchema,
  kerberosApReqSchema,
  kerberosAttackPassTheTicketSchema,
  kerberosAttackKerberoastingSchema,
  kerberosAttackGoldenTicketSchema,
} from "../validation.js";
import { runAttackScenario, maskSecret, sanitizeForDisplay } from "../utils/attack-runner.js";

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

// ─────────────────────────────────────────────────────────────────────────────
// Kerberos 攻撃シナリオ (DESIGN/17-attack-kerberos.md 実装)
//
// 教育用シミュレーション — 実 Kerberos の string2key (PBKDF2) や ASN.1/DER ではなく、
// SHA-256 + AES-256-CBC + JSON で簡略化。本ファイル冒頭の注記を継承する。
//
// 攻撃ルートは必ず `runAttackScenario` 経由で 5 ステップ完全形 (probe → tamper → forge →
// exploit → verify) を 1 リクエストで両モード並列実行する (E-2)。outcome は常に "succeeded"、
// HTTP 200 で統一し、堅牢ステップ 5 の status="blocked" + blockedBy で防御識別子を表現する。
//
// 安全装置: DESIGN/04-safety-guardrails.md
// ─────────────────────────────────────────────────────────────────────────────

// ── 共通シード (immutable) ──
// ROB-FIND-007 / ROB-RBAC-3 / ROB-FIDO2-5 / ROB-OIDC-3 と同パターンで `as const satisfies Readonly<...>`。
// 攻撃者制御値 (forgedPrincipal / fakePrincipal) と正規値 (victimUsername / legitimateService) の対比を
// SSoT 一本化することで、一方だけ変更し忘れて偶然一致してしまう事故 (= 検証バイパス) を防ぐ。
const KERBEROS_DEMO_CONSTANTS = {
  // 被害者・攻撃者プリンシパル
  victimUsername: "seed_alice",
  attackerUsername: "attacker_charlie",
  // Pass-the-Ticket でターゲットとするサービスプリンシパル (固定値 — DESIGN/17 §4.1)
  legitimateServicePrincipal: "http/web-server",
  // Kerberoasting シナリオの SPN (DESIGN/17 §4.2 — 固定 2 件)
  // 教育用パスワード — DB ではなく SSoT 定数で保持 (oidc-saml が saml_used_assertions DB テーブルを
  // 見送って handler ローカル TTL store を採用したのと同パターン: DESIGN/16 §8.2 / D43 同類)。
  weakServiceSpn: "http/weak-service",
  strongServiceSpn: "http/strong-service",
  weakServicePassword: "service123",
  // 20 文字以上のランダム文字列 — 4 カテゴリ (大文字 / 小文字 / 数字 / 記号) を全て含む。
  // isKerberoastResistant() の閾値 (length >= 20) を超える設計。
  strongServicePassword: "xK9#mP2$vQ7@nR4!jL8z",
  // Hashcat シミュレーション辞書 (20 件、DESIGN/17 §4.2)。weakServicePassword は 7 番目で一致。
  // 実 Hashcat の代替 — 教材として「辞書語パスワードがオフラインでクラックされる」を可視化。
  // 実在テストユーザー名 (admin/root/john) を含めない — 教育安全装置の禁止事項を遵守。
  hashcatDictionary: [
    "password", "letmein", "qwerty", "welcome", "abc123",
    "monkey", "service123", "default", "changeme", "trustno1",
    "iloveyou", "dragon", "passw0rd", "master", "summer",
    "winter", "spring", "autumn", "computer", "internet",
  ],
  // Golden Ticket シナリオで偽造するプリンシパル (固定 2 件)。
  // "administrator" は NT 系の典型的な高権限名、"seed_admin" は本デモ DB seed のもの。
  goldenTicketForgedAdministrator: "administrator",
  goldenTicketForgedSeedAdmin: "seed_admin",
  // 偽造 TGT の遠未来期限 (DESIGN/17 §4.3 step-2 例: 2030 年末)。教育表示用。
  // Date オブジェクトではなく ISO 文字列で保持 (immutable 化のため)。
  goldenTicketValidUntilIso: "2030-12-31T23:59:59.000Z",
  // 認証チケットの通常有効期限 (Pass-the-Ticket シナリオで「まだ期限内」を表現)。
  serviceTicketLifetimeMs: 60 * 60 * 1000, // 1 時間
} as const satisfies Readonly<{
  victimUsername: string;
  attackerUsername: string;
  legitimateServicePrincipal: string;
  weakServiceSpn: string;
  strongServiceSpn: string;
  weakServicePassword: string;
  strongServicePassword: string;
  hashcatDictionary: readonly string[];
  goldenTicketForgedAdministrator: string;
  goldenTicketForgedSeedAdmin: string;
  goldenTicketValidUntilIso: string;
  serviceTicketLifetimeMs: number;
}>;

// ── Scenario A: Pass-the-Ticket (TGS 窃取・再利用) ──
// 防御の核心: AP-REQ に Authenticator (タイムスタンプ + nonce) を必須化し、
// 受信した nonce をクロックスキュー窓内 (5 分) で重複検出する。現行実装は Authenticator 検証なし。
type KerberosPassTheTicketExtra = {
  victimPrincipal: string;
  servicePrincipal: string;
  capturedTicketEncryptedPreview: string;
  vulnerableReplayAccepted: boolean;
  defendedReplayBlocked: boolean;
  /** ROB-N1/N2: seed_alice 不在時は false (TGT 取得をスキップ)。 */
  victimSeedFound: boolean;
  /** ROB-FIDO2-1: 攻撃シミュレーション用 INSERT が例外で失敗した場合のメッセージ (成功時 null)。 */
  attackTicketInsertError: string | null;
  /** SEC-FIDO2-2: 攻撃シミュレーション用 DB 行が INSERT 成功した (痕跡削除前) — true なら handler 末尾で必ず DELETE される。 */
  attackTicketInserted: boolean;
};

kerberoSimRoutes.post("/attack/pass-the-ticket", (c) =>
  runAttackScenario<typeof kerberosAttackPassTheTicketSchema, KerberosPassTheTicketExtra>(c, {
    schema: kerberosAttackPassTheTicketSchema,
    scenarioId: "kerberos-pass-the-ticket",
    tabId: "kerberos",
    async handler({ db, recordStep, trace }) {
      // ROB-N1/N2: seed_alice 不在ガード (TGT/Service Ticket 取得は seed_alice 前提)
      const aliceUser = db
        .prepare("SELECT id, username FROM users WHERE username = ?")
        .get(KERBEROS_DEMO_CONSTANTS.victimUsername) as
        | { id: number; username: string }
        | undefined;
      const victimSeedFound = !!aliceUser;

      const victimPrincipal = `${KERBEROS_DEMO_CONSTANTS.victimUsername}@${REALM}`;
      const servicePrincipal = `${KERBEROS_DEMO_CONSTANTS.legitimateServicePrincipal}@${REALM}`;
      const validUntil = new Date(
        Date.now() + KERBEROS_DEMO_CONSTANTS.serviceTicketLifetimeMs,
      ).toISOString();

      // 正規フローの shape を再現 (TGS-REP 由来): seed_alice 用のサービスチケットを暗号化
      // ROB-OIDC-7: seed_alice 不在時は victimPrincipal を使用しないため fallback で
      //             プレースホルダ subject を生成 (教育的誤誘導回避)。
      const sessionKey = crypto.randomBytes(32);
      const baselineTicketPlaintext = JSON.stringify({
        principal: victimSeedFound ? victimPrincipal : `<seed_alice_missing>@${REALM}`,
        servicePrincipal,
        sessionKey: sessionKey.toString("base64"),
        validUntil,
      });
      const capturedTicket = victimSeedFound
        ? encrypt(baselineTicketPlaintext, KDC_SECRET)
        : { encrypted: "<not-computed: seed_alice missing>", iv: "" };
      const capturedTicketEncryptedPreview =
        capturedTicket.encrypted.length > 30
          ? capturedTicket.encrypted.substring(0, 30) + "..."
          : capturedTicket.encrypted;

      // 攻撃シミュレーション用 DB 行 (is_attack_sim=1 / E-3) — 教育的に「窃取対象」を可視化
      // ROB-FIDO2-1: try/catch で囲い、失敗時は extra.attackTicketInsertError に記録。
      let attackTicketInsertError: string | null = null;
      let attackTicketInserted = false;
      let insertedRowId: number | null = null;
      if (victimSeedFound) {
        try {
          const result = db
            .prepare(
              "INSERT INTO kerberos_tickets (ticket_type, principal, realm, encrypted_data, session_key, valid_until, is_attack_sim) VALUES (?, ?, ?, ?, ?, ?, 1)",
            )
            .run(
              "ServiceTicket",
              KERBEROS_DEMO_CONSTANTS.victimUsername,
              REALM,
              capturedTicket.encrypted,
              sessionKey.toString("base64"),
              validUntil,
            );
          insertedRowId = Number(result.lastInsertRowid);
          attackTicketInserted = true;
          trace.addDbQuery({
            sql: "INSERT INTO kerberos_tickets (...) VALUES (...) [is_attack_sim=1, sim ticket — to be deleted at end]",
            params: ["ServiceTicket", KERBEROS_DEMO_CONSTANTS.victimUsername, REALM],
            ms: 0,
          });
        } catch (e) {
          attackTicketInsertError = e instanceof Error ? e.message : "Unknown insert error";
        }
      }

      // ── Step 1: probe — 被害者が正規 TGS-REQ でサービスチケット取得
      // ROB-KERB-2: probe 成立は seed_alice 存在 AND DB INSERT 成功の双方が必要。
      // INSERT 失敗時は「正規発行されたが攻撃者が参照可能な状態」を再現できないため failed 扱い。
      const baselineReady = victimSeedFound && attackTicketInsertError === null;
      recordStep({
        id: "ptt-1",
        kind: "probe",
        label: "Victim (seed_alice) obtains a Service Ticket via legitimate TGS-REQ",
        labelJa: "被害者 (seed_alice) が正規 TGS-REQ でサービスチケットを取得",
        status: baselineReady ? "success" : "failed",
        payload: {
          type: "ticket",
          ticketType: "ServiceTicket",
          principal: victimSeedFound ? victimPrincipal : "<seed_alice_missing>",
          encryptedData: capturedTicketEncryptedPreview,
          validUntil,
        },
        detailJa: victimSeedFound
          ? "被害者が正常認証し、暗号化されたサービスチケットをローカルのチケットキャッシュに取得します。チケットは KDC_SECRET で暗号化されており、サービス側 (デモでは KDC_SECRET 共有) のみ復号できます。"
          : "シナリオ実行不可: seed_alice が DB に存在しません。",
        detail: victimSeedFound
          ? "The victim authenticates normally and receives an encrypted Service Ticket stored in the local ticket cache. The ticket is encrypted with KDC_SECRET and only decryptable by the service (sharing KDC_SECRET in this demo)."
          : "Scenario unavailable: seed_alice missing from seeds.",
      });

      // ── Step 2: tamper — 攻撃者がチケットキャッシュからチケットを参照 (シミュレーション)
      recordStep({
        id: "ptt-2",
        kind: "tamper",
        label: "Attacker reads the Service Ticket from victim's cache (simulated reference)",
        labelJa: "攻撃者が被害者のチケットキャッシュからサービスチケットを参照 (シミュレーション参照)",
        status: baselineReady ? "success" : "failed",
        payload: {
          type: "generic",
          data: {
            note: "実際のメモリ操作は行いません — 同一プロセス内のシミュレーション参照です",
            noteEn: "No actual memory operations — in-process simulation reference",
            sourceTable: "kerberos_tickets WHERE is_attack_sim=1 (educational sim row)",
            principal: victimSeedFound ? victimPrincipal : "<seed_alice_missing>",
            encryptedDataPreview: capturedTicketEncryptedPreview,
            validUntil,
            ticketRowId: insertedRowId,
          },
        },
        detailJa:
          "攻撃者がシミュレーションされたチケットキャッシュからサービスチケットを読み取ります。実環境では Mimikatz 等のツールが LSASS メモリから抽出しますが、本デモは同一プロセス内の参照のみで実メモリ操作は行いません。",
        detail:
          "The attacker reads the Service Ticket from the simulated ticket cache. In real attacks, tools like Mimikatz extract this from LSASS memory; this demo only references in-process state without real memory operations.",
      });

      // ── Step 3: forge — 攻撃者がチケットを再パッケージして提示準備 (改変なし)
      recordStep({
        id: "ptt-3",
        kind: "forge",
        label: "Attacker repackages stolen ticket for AP-REQ submission (no modification)",
        labelJa: "攻撃者が窃取チケットを AP-REQ 用に再パッケージ (改変なし)",
        status: "success",
        payload: {
          type: "generic",
          data: {
            note: "Pass-the-Ticket 攻撃ではチケット自体を改変しません。署名 (暗号文) も IV も同一のままサービスに提示します。",
            noteEn: "Pass-the-Ticket does not modify the ticket. The same ciphertext and IV are presented to the service.",
            encryptedDataPreview: capturedTicketEncryptedPreview,
            ivPreview: capturedTicket.iv ? capturedTicket.iv.substring(0, 16) + "..." : "<n/a>",
          },
        },
        detailJa:
          "攻撃者は窃取したチケットを AP-REQ にそのまま乗せる準備をします。Authenticator nonce 検証がない実装では、これだけで認証成立します。",
        detail:
          "The attacker prepares to submit the stolen ticket as-is in AP-REQ. Without Authenticator nonce verification, this alone is enough for authentication to succeed.",
      });

      // ── Step 4: exploit (脆弱モード) — Authenticator nonce なし → リプレイ受理
      // ROB-KERB-2: INSERT 失敗時は脆弱パスのチケットキャッシュ自体が存在しないため成立不可。
      const vulnerableReplayAccepted = baselineReady;
      trace.addCryptoOp({
        op: "decryptServiceTicket(stolen)",
        input: capturedTicketEncryptedPreview,
        output: vulnerableReplayAccepted
          ? `principal=${victimPrincipal}, service=${servicePrincipal} — accepted (no replay detection)`
          : "skipped (seed_alice missing)",
        algo: "AES-256-CBC (no Authenticator check)",
        detail:
          "Vulnerable: the service decrypts the ticket and finds it valid. Without Authenticator nonce verification, the same ticket can be replayed indefinitely until valid_until.",
      });
      if (vulnerableReplayAccepted) {
        trace.addSessionOp({
          action: "createSession_pass_the_ticket_vulnerable",
          data: {
            isAttackMode: true,
            authenticatedAs: victimPrincipal,
            service: servicePrincipal,
            sourceTicketRowId: insertedRowId,
            note: "Vulnerable: a service session is created from the replayed ticket — attacker now has access as seed_alice.",
          },
        });
      }
      recordStep({
        id: "ptt-4",
        kind: "exploit",
        label: "Vulnerable: AP-REQ without Authenticator accepts replayed ticket",
        labelJa: "脆弱版: Authenticator 不在の AP-REQ がリプレイチケットを受理",
        status: vulnerableReplayAccepted ? "success" : "failed",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/kerberos/attack/pass-the-ticket (vulnerable variant — no Authenticator)",
            headers: { "X-Attack-Sim": "pass-the-ticket" },
            body: {
              serviceTicket: capturedTicketEncryptedPreview,
              serviceTicketIv: capturedTicket.iv ? capturedTicket.iv.substring(0, 16) + "..." : "<n/a>",
            },
          },
          response: {
            status: vulnerableReplayAccepted ? 200 : 401,
            body: vulnerableReplayAccepted
              ? {
                  step: "AP-REP",
                  authenticated: true,
                  principal: victimPrincipal,
                  service: servicePrincipal,
                  note: "Vulnerable: service has no replay cache and no Authenticator check. Attacker authenticates as seed_alice without knowing the password.",
                }
              : { error: "Vulnerable path could not run — seed_alice missing." },
          },
        },
        detailJa: vulnerableReplayAccepted
          ? "この実装は脆弱です: サービスは復号に成功し有効期限内であればチケットを受理します。Authenticator nonce 検証がないため、攻撃者がパスワードを知らずに seed_alice として認証されます。"
          : "脆弱パス実行不可: seed_alice が DB に存在せず、ベースラインチケットを生成できませんでした。",
        detail: vulnerableReplayAccepted
          ? "This implementation is vulnerable: the service successfully decrypts the ticket and accepts it because it is within validity. Without Authenticator nonce verification, the attacker authenticates as seed_alice without knowing the password."
          : "Vulnerable path could not run — seed_alice missing from seeds, so no baseline ticket was issued.",
      });

      // ── Step 5: verify (堅牢モード) — Authenticator nonce 検証で阻止
      // 設計上 nonce キャッシュヒットを必ず検出 → defendedReplayBlocked 常に true
      const replayCacheHit = true;
      const defendedReplayBlocked = replayCacheHit;
      trace.addCryptoOp({
        op: "verifyAuthenticator(nonce_cache_check)",
        input: `ticketReplay=true, nonceCacheHit=${replayCacheHit}`,
        output: defendedReplayBlocked
          ? "REPLAY DETECTED → reject (Authenticator nonce duplicate)"
          : "first use (accept)",
        algo: "Authenticator nonce + clock-skew window (5 min)",
        detail:
          "Defended: AP-REQ requires an Authenticator (encrypted with the service session key) containing a unique nonce + timestamp. The service caches nonces within the 5-minute clock-skew window and rejects duplicates.",
      });
      recordStep({
        id: "ptt-5",
        kind: "verify",
        label: "Defended: Authenticator nonce cache detects replay — AP-REQ rejected",
        labelJa: "堅牢版: Authenticator nonce キャッシュがリプレイを検出 — AP-REQ 拒否",
        status: defendedReplayBlocked ? "blocked" : "failed",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/kerberos/attack/pass-the-ticket (defended variant — Authenticator + nonce cache)",
          },
          response: {
            status: 401,
            body: {
              error: "Replay detected: Authenticator nonce already seen within clock-skew window",
              blockedBy: "kerberos_authenticator_nonce_replay_cache_enforced",
              clockSkewWindowSec: 300,
            },
          },
        },
        detailJa:
          "堅牢実装は AP-REQ に Authenticator (セッション鍵で暗号化されたタイムスタンプ + nonce) を必須化します。サービスは 5 分のクロックスキュー窓内で nonce の重複を検出し、リプレイを拒否します。RFC 4120 §3.2.3 準拠。",
        detail:
          "The defended implementation requires an Authenticator (timestamp + nonce, encrypted with the session key) in AP-REQ. The service detects duplicate nonces within a 5-minute clock-skew window and rejects replays. Compliant with RFC 4120 §3.2.3.",
      });

      // SEC-FIDO2-2: 痕跡削除パターン — 教育的観察後は is_attack_sim=1 行を即削除して累積回避
      if (insertedRowId !== null) {
        try {
          db.prepare(
            "DELETE FROM kerberos_tickets WHERE id = ? AND is_attack_sim = 1",
          ).run(insertedRowId);
        } catch {
          // 痕跡削除失敗時は握り潰す (累積を放置するより教育的観察結果を優先)
        }
      }

      return {
        blockedBy: "kerberos_authenticator_nonce_replay_cache_enforced",
        summary:
          "A vulnerable AP-REQ that omits the Authenticator accepts a stolen Service Ticket as long as it remains within validity. The defended implementation requires an Authenticator (nonce + timestamp), caches seen nonces within the clock-skew window, and rejects replays.",
        summaryJa:
          "この実装は脆弱です: Authenticator を省略した AP-REQ は、窃取されたサービスチケットが有効期限内である限りそのまま受理してしまいます。堅牢実装は Authenticator (nonce + タイムスタンプ) を必須化し、nonce をクロックスキュー窓内でキャッシュしてリプレイを阻止します。",
        extra: {
          victimPrincipal,
          servicePrincipal,
          capturedTicketEncryptedPreview,
          vulnerableReplayAccepted,
          defendedReplayBlocked,
          victimSeedFound,
          attackTicketInsertError,
          attackTicketInserted,
        } satisfies KerberosPassTheTicketExtra,
        payload: {
          params: {},
          result: {
            victimPrincipal,
            servicePrincipal,
            capturedTicketEncryptedPreview,
            vulnerableReplayAccepted,
            defendedReplayBlocked,
            victimSeedFound,
            attackTicketInserted,
          },
        },
      };
    },
  }),
);

// ── Scenario B: Kerberoasting (SPN ハッシュ抽出・弱パスワード辞書攻撃) ──
// 防御の核心: サービスアカウントのパスワードに 20 文字以上のランダム文字列を使用し、
// 辞書攻撃を実質的に不可能にする。または gMSA でパスワード管理を OS に委ねる。
//
// E-2 (ROB-KERB-1 修正): 1 リクエストで 弱 SPN (脆弱) と 強 SPN (堅牢) の両方を並列実行する。
// 旧実装は body.targetSpn で片方しか実行しないため E-2 違反だった。
type KerberoastingExtra = {
  weakSpn: string;
  strongSpn: string;
  dictionarySize: number;
  /** 弱 SPN のマスク済み解読パスワード ("s***3 (len=10)" 形式)。常に非 null (辞書ヒット必至)。 */
  weakCrackedPasswordMasked: string | null;
  /** 弱 SPN の辞書ヒット位置 (0-indexed)。設計上 6 (= "service123")。 */
  weakCrackedAtIndex: number | null;
  /** 強 SPN の辞書ヒット位置 — 設計上常に null (辞書 20 件で一致なし)。 */
  strongCrackedAtIndex: number | null;
  /** 強 SPN: 辞書全件で一致なし — 設計上常に true。 */
  strongDictionaryExhaustedNoMatch: boolean;
  /** 強 SPN が「20 文字以上 + 全カテゴリ」基準を満たすか — 設計上常に true。 */
  strongIsKerberoastResistant: boolean;
  /** 弱 SPN が同基準を満たすか — 設計上常に false。 */
  weakIsKerberoastResistant: boolean;
};

kerberoSimRoutes.post("/attack/kerberoasting", (c) =>
  runAttackScenario<typeof kerberosAttackKerberoastingSchema, KerberoastingExtra>(c, {
    schema: kerberosAttackKerberoastingSchema,
    scenarioId: "kerberos-kerberoasting",
    tabId: "kerberos",
    async handler({ recordStep, trace }) {
      const dictionarySize = KERBEROS_DEMO_CONSTANTS.hashcatDictionary.length;
      const weakSpnFqdn = `${KERBEROS_DEMO_CONSTANTS.weakServiceSpn}@${REALM}`;
      const strongSpnFqdn = `${KERBEROS_DEMO_CONSTANTS.strongServiceSpn}@${REALM}`;

      // 辞書照合ヘルパー (SHA-256 で簡略化、実 Hashcat の代替)
      const findInDictionary = (password: string): number | null => {
        const targetHash = crypto.createHash("sha256").update(password).digest("hex");
        for (let i = 0; i < dictionarySize; i++) {
          const candidateHash = crypto
            .createHash("sha256")
            .update(KERBEROS_DEMO_CONSTANTS.hashcatDictionary[i])
            .digest("hex");
          if (candidateHash === targetHash) return i;
        }
        return null;
      };

      // 両 SPN のハッシュ抽出 (probe / tamper のための事前計算)
      const weakTicketHashPreview = `$krb5tgs$23$*${weakSpnFqdn}*$${crypto
        .createHash("sha256")
        .update(KERBEROS_DEMO_CONSTANTS.weakServicePassword)
        .digest("hex")
        .substring(0, 32)}...`;
      const strongTicketHashPreview = `$krb5tgs$23$*${strongSpnFqdn}*$${crypto
        .createHash("sha256")
        .update(KERBEROS_DEMO_CONSTANTS.strongServicePassword)
        .digest("hex")
        .substring(0, 32)}...`;

      // ── Step 1: probe — 任意ドメインユーザーが両 SPN に TGS-REQ を要求
      trace.addCryptoOp({
        op: "deriveServiceKey(weak_and_strong_spn)",
        input: `spns=[${KERBEROS_DEMO_CONSTANTS.weakServiceSpn}, ${KERBEROS_DEMO_CONSTANTS.strongServiceSpn}], etype=23 (RC4-HMAC simulated)`,
        output: `weakHashPreview=${weakTicketHashPreview.substring(0, 50)}..., strongHashPreview=${strongTicketHashPreview.substring(0, 50)}...`,
        algo: "SHA-256 (educational simplification of RC4-HMAC etype 23)",
        detail:
          "Real Kerberoasting extracts the service ticket's encrypted blob and reverses the service account password offline. This demo simplifies to SHA-256 of the password.",
      });
      recordStep({
        id: "kr-1",
        kind: "probe",
        label: "Request TGS for both SPNs (any domain user can — by design)",
        labelJa: "両 SPN に TGS を要求 (ドメイン一般ユーザーで可能 — 設計上の特性)",
        status: "success",
        payload: {
          type: "generic",
          data: {
            note: "Any domain user can request a TGS for any registered SPN — this is by design in Kerberos",
            noteJa: "ドメインの一般ユーザーは任意の SPN に対して TGS を要求できます (Kerberos 設計上の特性)",
            weakSpn: weakSpnFqdn,
            strongSpn: strongSpnFqdn,
          },
        },
        detailJa:
          "ドメイン一般ユーザー (例: seed_alice) は弱 SPN・強 SPN 両方に対して TGS を要求できます。これは Kerberos の設計上の特性であり、防御策はパスワード強度のみに依存します。",
        detail:
          "A general domain user (e.g., seed_alice) can request a TGS for both the weak and strong SPNs. This is a design property of Kerberos; defense relies solely on password strength.",
      });

      // ── Step 2: tamper — 攻撃者が両チケットのハッシュを抽出してオフライン辞書攻撃を準備
      recordStep({
        id: "kr-2",
        kind: "tamper",
        label: "Attacker extracts both service ticket hashes for offline cracking",
        labelJa: "攻撃者が両サービスチケットのハッシュを抽出してオフライン解読準備",
        status: "success",
        payload: {
          type: "generic",
          data: {
            note: "Real attacks use Hashcat / John the Ripper offline. This demo uses a fixed 20-entry dictionary simulation.",
            noteJa: "実環境では Hashcat / John the Ripper でオフライン解読。本デモは固定辞書 20 件と単純照合 (シミュレーション)。",
            weakTicketHashPreview: weakTicketHashPreview.substring(0, 60) + "...",
            strongTicketHashPreview: strongTicketHashPreview.substring(0, 60) + "...",
            ticketHashFormat: "$krb5tgs$23$*<spn>*$<hash>",
            hashcatModeRef: "13100 (KerberosV5 TGS-REP etype 23) — 教育用簡略表示",
            dictionarySize,
          },
        },
        detailJa:
          "攻撃者は両チケットの暗号化部分から krb5tgs ハッシュを抽出します。オフラインで自由に解読試行できるため、サービスアカウントのパスワード強度のみが防御になります。",
        detail:
          "The attacker extracts the krb5tgs hashes from both encrypted tickets. These hashes can be subjected to offline cracking attempts at unlimited rate; the only defense is service account password strength.",
      });

      // ── Step 3: forge — 辞書ループを両 SPN に並列実行 (固定辞書 20 件、SHA-256 比較)
      const weakCrackedAtIndex = findInDictionary(KERBEROS_DEMO_CONSTANTS.weakServicePassword);
      const strongCrackedAtIndex = findInDictionary(KERBEROS_DEMO_CONSTANTS.strongServicePassword);
      const strongDictionaryExhaustedNoMatch = strongCrackedAtIndex === null;

      // SEC FINDING-5: 平文を payload / extra に出さず maskSecret 化
      const weakCrackedPasswordMasked =
        weakCrackedAtIndex !== null ? maskSecret(KERBEROS_DEMO_CONSTANTS.weakServicePassword) : null;

      recordStep({
        id: "kr-3",
        kind: "forge",
        label: "Run dictionary attack on both hashes (Hashcat simulation)",
        labelJa: "両ハッシュに辞書攻撃を並列実行 (Hashcat シミュレーション)",
        status: "success",
        payload: {
          type: "generic",
          data: {
            dictionarySize,
            weakCrackedAtIndex,
            weakCrackedPasswordMasked,
            strongCrackedAtIndex,
            strongDictionaryExhaustedNoMatch,
            // 教育用ダミー値 ("dictionary entry あたり 1ms" の便宜表現、実 Hashcat は数十億候補/秒)
            // フィールド名は誤読防止のため明示
            educationalElapsedMsPlaceholder: dictionarySize,
            note: "Hashcat implementation omitted — fixed 20-entry dictionary matching simulation",
            noteJa: "Hashcat の実装は省略 — 固定辞書 20 件との照合シミュレーション",
          },
        },
        detailJa: `辞書 20 件で照合: 弱 SPN は ${weakCrackedAtIndex !== null ? `${weakCrackedAtIndex + 1} 件目で一致` : "一致なし"}、強 SPN は ${strongDictionaryExhaustedNoMatch ? "一致なし (辞書全件)" : `${(strongCrackedAtIndex ?? 0) + 1} 件目で一致 (想定外)`}。`,
        detail: `Dictionary lookup (20 entries): weak SPN ${weakCrackedAtIndex !== null ? `matched at #${weakCrackedAtIndex + 1}` : "no match"}; strong SPN ${strongDictionaryExhaustedNoMatch ? "no match (exhaustive)" : `matched at #${(strongCrackedAtIndex ?? 0) + 1} (unexpected)`}.`,
      });

      // ── Step 4: exploit (脆弱モード, weak SPN) — 解読成功 → サービス偽装可能
      const vulnerableCracked = weakCrackedAtIndex !== null;
      trace.addCryptoOp({
        op: "kerberoasting_dictionary_simulation(weak_spn)",
        input: `spn=${KERBEROS_DEMO_CONSTANTS.weakServiceSpn}, dictSize=${dictionarySize}`,
        output: vulnerableCracked
          ? `MATCH at #${(weakCrackedAtIndex ?? 0) + 1} → service password recovered (masked: ${weakCrackedPasswordMasked})`
          : "NO MATCH (unexpected — weak password should always crack)",
        algo: "SHA-256 hash comparison (educational simplification of Kerberoasting)",
        detail:
          "Vulnerable: weak service-account passwords (dictionary words) are recovered by offline brute-force. Once recovered, the attacker can forge any Service Ticket for that SPN (Silver Ticket).",
      });
      recordStep({
        id: "kr-4",
        kind: "exploit",
        label: "Vulnerable (weak SPN): password cracked — Silver Ticket forging enabled",
        labelJa: "脆弱版 (弱 SPN): パスワード解読成立 — Silver Ticket 偽造可能",
        status: vulnerableCracked ? "success" : "failed",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/kerberos/attack/kerberoasting (vulnerable variant — weak service password)",
          },
          response: {
            status: vulnerableCracked ? 200 : 401,
            body: vulnerableCracked
              ? {
                  outcome: "succeeded",
                  spn: weakSpnFqdn,
                  crackedAtIndex: weakCrackedAtIndex,
                  crackedPasswordMasked: weakCrackedPasswordMasked,
                  note: "Vulnerable: with the recovered service password, the attacker can mint Service Tickets for this SPN (Silver Ticket) without involving the KDC.",
                }
              : {
                  error:
                    "Unexpected: weak service password did not match the dictionary (dictionary or password drift?).",
                },
          },
        },
        detailJa: vulnerableCracked
          ? "この実装は脆弱です: サービスアカウントの弱パスワードがオフラインで解読されました。攻撃者はこのパスワードから派生する鍵でサービスチケットを自由に偽造できます (Silver Ticket)。"
          : "脆弱パス予期せず実行不可: 弱パスワードが辞書に一致しませんでした (辞書定数の drift?)。",
        detail: vulnerableCracked
          ? "This implementation is vulnerable: the service account's weak password was recovered offline. The attacker can now forge Service Tickets for this SPN (Silver Ticket) without KDC involvement."
          : "Vulnerable path unexpectedly could not run — weak password did not match the dictionary (constant drift?).",
      });

      // ── Step 5: verify (堅牢モード, strong SPN) — 強パスワードポリシーが辞書攻撃を阻止
      const weakIsKerberoastResistant = checkKerberoastResistant(
        KERBEROS_DEMO_CONSTANTS.weakServicePassword,
      );
      const strongIsKerberoastResistant = checkKerberoastResistant(
        KERBEROS_DEMO_CONSTANTS.strongServicePassword,
      );
      trace.addCryptoOp({
        op: "verifyServiceAccountPolicy(strong_spn_complexity_check)",
        input: `strongPasswordLength=${KERBEROS_DEMO_CONSTANTS.strongServicePassword.length}, allCategoriesMet=${strongIsKerberoastResistant}, weakPasswordLength=${KERBEROS_DEMO_CONSTANTS.weakServicePassword.length}, weakAllCategoriesMet=${weakIsKerberoastResistant}`,
        output: `strong: ${strongIsKerberoastResistant ? "PASSES" : "FAILS"} policy (≥20 chars + all categories); strong-SPN dictionary outcome: ${strongDictionaryExhaustedNoMatch ? "exhaustive miss → defense holds" : "match → defense BROKEN"}`,
        algo: "Service-account password strength policy",
        detail:
          "Defended: enforce a service-account password policy of ≥20 characters with all categories (or use gMSA where the OS auto-manages a 240-byte random secret).",
      });
      const defendedStrongResisted =
        strongDictionaryExhaustedNoMatch && strongIsKerberoastResistant;
      recordStep({
        id: "kr-5",
        kind: "verify",
        label: "Defended (strong SPN): password policy resists dictionary attack",
        labelJa: "堅牢版 (強 SPN): 強パスワード / gMSA ポリシーが辞書攻撃を阻止",
        status: defendedStrongResisted ? "blocked" : "failed",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/kerberos/attack/kerberoasting (defended variant — strong-password policy)",
          },
          response: {
            status: 401,
            body: {
              error:
                "Service account password policy enforced: dictionary attack cannot recover ≥20-char random passwords.",
              blockedBy: "kerberos_kerberoasting_strong_service_account_password_enforced",
              policy: {
                minLength: 20,
                requiresUpper: true,
                requiresLower: true,
                requiresDigit: true,
                requiresSymbol: true,
                gmsaRecommended: true,
              },
              comparison: {
                weakSpn: {
                  spn: weakSpnFqdn,
                  isKerberoastResistant: weakIsKerberoastResistant,
                  passwordLength: KERBEROS_DEMO_CONSTANTS.weakServicePassword.length,
                },
                strongSpn: {
                  spn: strongSpnFqdn,
                  isKerberoastResistant: strongIsKerberoastResistant,
                  passwordLength: KERBEROS_DEMO_CONSTANTS.strongServicePassword.length,
                  dictionaryExhaustedNoMatch: strongDictionaryExhaustedNoMatch,
                },
              },
            },
          },
        },
        detailJa:
          "堅牢実装はサービスアカウントのパスワードを 20 文字以上のランダム文字列にすることで辞書攻撃を実質不可能にします。Windows 環境では gMSA (Group Managed Service Accounts) を使用し、OS が 240 バイトのランダム秘密を自動管理する設定が推奨されます。etype 23 (RC4) の無効化と TGS 要求の異常検知も併せて推奨されます。",
        detail:
          "The defended implementation enforces ≥20-char random service-account passwords, making dictionary attacks practically infeasible. In Windows, gMSA (Group Managed Service Accounts) is recommended — the OS auto-manages a 240-byte random secret. Disabling etype 23 (RC4) and monitoring abnormal TGS request patterns are also recommended.",
      });

      return {
        blockedBy: "kerberos_kerberoasting_strong_service_account_password_enforced",
        summary:
          "A vulnerable service account with a weak (dictionary-word) password is recovered offline by hashing its TGS ticket against a fixed 20-entry dictionary. The defended deployment uses ≥20-char random service-account passwords (or gMSA) and the same dictionary attack against it produces no match. Both runs occur in parallel within one request.",
        summaryJa:
          "この実装は脆弱です: 弱パスワード (辞書語) のサービスアカウントは TGS チケットのハッシュをオフラインで固定辞書 (20 件) と照合することで解読されます。堅牢実装はサービスアカウントに 20 文字以上のランダムパスワード (または gMSA) を強制し、同じ辞書攻撃を行っても一致は得られません。両モードを 1 リクエスト内で並列実行します。",
        extra: {
          weakSpn: KERBEROS_DEMO_CONSTANTS.weakServiceSpn,
          strongSpn: KERBEROS_DEMO_CONSTANTS.strongServiceSpn,
          dictionarySize,
          weakCrackedPasswordMasked,
          weakCrackedAtIndex,
          strongCrackedAtIndex,
          strongDictionaryExhaustedNoMatch,
          strongIsKerberoastResistant,
          weakIsKerberoastResistant,
        } satisfies KerberoastingExtra,
        payload: {
          params: {},
          result: {
            weakSpn: KERBEROS_DEMO_CONSTANTS.weakServiceSpn,
            strongSpn: KERBEROS_DEMO_CONSTANTS.strongServiceSpn,
            weakCrackedAtIndex,
            weakCrackedPasswordMasked, // SEC FINDING-5: 平文ではなくマスク化
            strongCrackedAtIndex,
            strongDictionaryExhaustedNoMatch,
            strongIsKerberoastResistant,
            weakIsKerberoastResistant,
          },
        },
      };
    },
  }),
);

// 4 カテゴリ + 20 文字以上のサービスアカウントパスワード強度チェック (Kerberoasting 耐性指標)。
// gMSA 相当のランダム 32 バイトベースは 43 文字 base64 で当然満たす。
function checkKerberoastResistant(password: string): boolean {
  return (
    password.length >= 20 &&
    /[A-Z]/.test(password) &&
    /[a-z]/.test(password) &&
    /[0-9]/.test(password) &&
    /[^A-Za-z0-9]/.test(password)
  );
}

// ── Scenario C: Golden Ticket (KDC 長期鍵偽造 TGT) ──
// 防御の核心: krbtgt の二重リセット + PAC 検証 + DC Tier 0 分離 で krbtgt 鍵漏洩を実質不可能にする。
// KDC は krbtgt 鍵で正しく暗号化された TGT を「正規」と判断するため、鍵漏洩時は防御不能。
type GoldenTicketExtra = {
  forgedPrincipal: string;
  servicePrincipal: string;
  forgedTgtEncryptedPreview: string;
  forgedValidUntil: string;
  vulnerableServiceTicketIssued: boolean;
  defendedRotationDetected: boolean;
  /** krbtgt 鍵の漏洩が前提条件 (DESIGN/17 §4.3) — 教育的に表示 */
  prerequisiteOmitted: true;
  /** ROB-FIDO2-1: 攻撃シミュレーション用 INSERT が例外で失敗した場合のメッセージ。 */
  forgedTgtInsertError: string | null;
  /** SEC-FIDO2-2: 攻撃シミュレーション用 DB 行が INSERT 成功した (痕跡削除前) — true なら handler 末尾で必ず DELETE される。 */
  forgedTgtInserted: boolean;
  /** ROB-KERB-3: KDC 復号失敗時のエラーメッセージ (設計上常に成功するが、KDC_SECRET drift 等の
   *  異常時に operator 可視性を保つため記録)。成功時 null。 */
  vulnerableDecryptError: string | null;
};

kerberoSimRoutes.post("/attack/golden-ticket", (c) =>
  runAttackScenario<typeof kerberosAttackGoldenTicketSchema, GoldenTicketExtra>(c, {
    schema: kerberosAttackGoldenTicketSchema,
    scenarioId: "kerberos-golden-ticket",
    tabId: "kerberos",
    async handler({ db, recordStep, trace }) {
      const forgedPrincipal = `${KERBEROS_DEMO_CONSTANTS.goldenTicketForgedAdministrator}@${REALM}`;
      const servicePrincipal = `${KERBEROS_DEMO_CONSTANTS.legitimateServicePrincipal}@${REALM}`;
      const forgedValidUntil = KERBEROS_DEMO_CONSTANTS.goldenTicketValidUntilIso;

      // ── Step 1: probe — 攻撃者が krbtgt 鍵を取得済みと仮定 (前提条件)
      recordStep({
        id: "gt-1",
        kind: "probe",
        label: "Attacker has obtained krbtgt key (prerequisite — out of scope of this demo)",
        labelJa: "攻撃者が krbtgt 鍵を取得済みと仮定 (前提条件 — 本デモのスコープ外)",
        status: "success",
        payload: {
          type: "generic",
          data: {
            note: "Golden Ticket 攻撃は krbtgt 鍵の取得を前提とします。実環境では Domain Controller への侵害 (Domain Admin 相当) が必要であり、本デモはその後の TGT 偽造プロセスを示します。",
            noteEn: "Golden Ticket assumes the krbtgt key is already obtained. In real environments, this requires Domain Controller compromise (Domain Admin or equivalent). This demo shows the TGT forging process that follows.",
            krbtgtKeySource: "SEED_KDC_MASTER_KEY_DEMO (educational fixed value)",
            prerequisiteOmitted: true,
          },
        },
        detailJa:
          "Golden Ticket 攻撃は krbtgt の長期鍵が既知 (漏洩済み) という前提から始まります。鍵取得プロセス自体は本シミュレーションのスコープ外で、デモでは KDC_SECRET を「漏洩済みの krbtgt 鍵」と見なします。",
        detail:
          "The Golden Ticket attack starts after the attacker has already obtained the krbtgt long-term key. The key-acquisition process is out of scope; this demo treats KDC_SECRET as the 'leaked krbtgt key'.",
      });

      // ── Step 2: tamper — 攻撃者が krbtgt 鍵で偽造 TGT を生成 (任意プリンシパル + 遠未来期限)
      const forgedSessionKey = crypto.randomBytes(32);
      const forgedTgtPlaintext = JSON.stringify({
        principal: forgedPrincipal,
        sessionKey: forgedSessionKey.toString("base64"),
        validUntil: forgedValidUntil,
        flags: ["FORWARDABLE", "RENEWABLE", "INITIAL", "FORGED_BY_ATTACKER"],
      });
      const forgedTgt = encrypt(forgedTgtPlaintext, KDC_SECRET);
      const forgedTgtEncryptedPreview = forgedTgt.encrypted.substring(0, 30) + "...";

      trace.addCryptoOp({
        op: "forgeGoldenTicket(stolen_krbtgt)",
        input: `principal=${forgedPrincipal}, validUntil=${forgedValidUntil}, flags=[FORWARDABLE,RENEWABLE,INITIAL,FORGED_BY_ATTACKER]`,
        output: forgedTgtEncryptedPreview,
        algo: "AES-256-CBC (with stolen krbtgt key — KDC cannot distinguish from legitimate)",
        detail:
          "The attacker uses the stolen krbtgt key to encrypt a forged TGT containing arbitrary principal, far-future expiry, and arbitrary flags. The KDC accepts this because the encryption succeeds.",
      });
      recordStep({
        id: "gt-2",
        kind: "tamper",
        label: "Attacker forges a TGT for 'administrator' using the stolen krbtgt key",
        labelJa: "攻撃者が盗んだ krbtgt 鍵で 'administrator' の偽造 TGT を生成",
        status: "success",
        payload: {
          type: "ticket",
          ticketType: "TGT",
          principal: forgedPrincipal,
          encryptedData: forgedTgtEncryptedPreview,
          validUntil: forgedValidUntil,
        },
        detailJa:
          "krbtgt 鍵を使用して、攻撃者は任意の有効期限とフラグを持つ 'administrator' の正規に見える TGT を作成します。KDC が発行したものではなく、攻撃者が自由に validUntil を設定できる (デモでは 2030 年末)。",
        detail:
          "Using the krbtgt key, the attacker creates a valid-looking TGT for 'administrator' with arbitrary expiry and flags. The KDC did NOT issue this; the attacker can set validUntil arbitrarily (2030-12-31 in this demo).",
      });

      // 攻撃シミュレーション用 DB 行 (is_attack_sim=1 / E-3) — 教育的に「偽造 TGT」の存在を可視化
      // ROB-FIDO2-1: try/catch で囲い、失敗時は extra.forgedTgtInsertError に記録。
      let forgedTgtInsertError: string | null = null;
      let forgedTgtInserted = false;
      let forgedTgtRowId: number | null = null;
      try {
        const result = db
          .prepare(
            "INSERT INTO kerberos_tickets (ticket_type, principal, realm, encrypted_data, session_key, valid_until, is_attack_sim) VALUES (?, ?, ?, ?, ?, ?, 1)",
          )
          .run(
            "TGT",
            KERBEROS_DEMO_CONSTANTS.goldenTicketForgedAdministrator,
            REALM,
            forgedTgt.encrypted,
            forgedSessionKey.toString("base64"),
            forgedValidUntil,
          );
        forgedTgtRowId = Number(result.lastInsertRowid);
        forgedTgtInserted = true;
        trace.addDbQuery({
          sql: "INSERT INTO kerberos_tickets (...) VALUES (...) [is_attack_sim=1, forged TGT — to be deleted at end]",
          params: ["TGT", KERBEROS_DEMO_CONSTANTS.goldenTicketForgedAdministrator, REALM],
          ms: 0,
        });
      } catch (e) {
        forgedTgtInsertError = e instanceof Error ? e.message : "Unknown insert error";
      }

      // ── Step 3: forge — 攻撃者が偽造 TGT を KDC TGS-REQ に送信
      recordStep({
        id: "gt-3",
        kind: "forge",
        label: "Attacker submits forged TGT to KDC TGS-REQ",
        labelJa: "攻撃者が偽造 TGT を KDC TGS-REQ に送信",
        status: "success",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/kerberos/attack/golden-ticket (simulated TGS-REQ — both variants receive same forged TGT)",
            headers: { "X-Attack-Sim": "golden-ticket" },
            body: {
              tgt: forgedTgtEncryptedPreview,
              tgtIv: forgedTgt.iv.substring(0, 16) + "...",
              servicePrincipal: KERBEROS_DEMO_CONSTANTS.legitimateServicePrincipal,
            },
          },
          tamperedFields: ["tgt (forged with stolen krbtgt key)"],
        },
        detailJa:
          "攻撃者は偽造 TGT を KDC の TGS-REQ エンドポイントに送信します。脆弱版 (krbtgt 未ローテーション) と堅牢版 (krbtgt ダブルリセット後) で挙動が分岐します。",
        detail:
          "The attacker submits the forged TGT to the KDC's TGS-REQ endpoint. The vulnerable variant (krbtgt not rotated) and the defended variant (after krbtgt double-reset) diverge from here.",
      });

      // ── Step 4: exploit (脆弱モード) — KDC が krbtgt で復号成功 → サービスチケット発行
      // 復号は実際に実行 — KDC の挙動を忠実にシミュレート
      // ROB-KERB-3: 復号失敗時はエラーメッセージを保持して operator 可視性を確保
      // (設計上は常に成功するが、KDC_SECRET drift / IV 形式破損等の異常時に黙って消えないように)
      let vulnerableServiceTicketIssued = false;
      let vulnerableDecryptError: string | null = null;
      try {
        const decrypted = decrypt(forgedTgt.encrypted, KDC_SECRET, forgedTgt.iv);
        const tgtPayload = JSON.parse(decrypted) as { principal: string; validUntil: string };
        // 期限チェック (forgedValidUntil は 2030 で常に未来 → 通る)
        if (new Date(tgtPayload.validUntil) >= new Date() && tgtPayload.principal === forgedPrincipal) {
          vulnerableServiceTicketIssued = true;
        }
      } catch (e) {
        vulnerableDecryptError = e instanceof Error ? e.message : "Unknown decrypt error";
      }

      trace.addCryptoOp({
        op: "decryptTGT(forged_TGT_accepted)",
        input: forgedTgtEncryptedPreview,
        output: vulnerableServiceTicketIssued
          ? `principal=${forgedPrincipal} (FORGED) — TGS-REP issued for ${servicePrincipal}`
          : "decrypt failed (unexpected — krbtgt mismatch?)",
        algo: "AES-256-CBC (KDC cannot distinguish forged from legitimate TGT)",
        detail:
          "Vulnerable: the KDC successfully decrypts the forged TGT (because the krbtgt key was correct) and issues a Service Ticket for the forged principal. The KDC has no way to detect the forgery without PAC validation.",
      });
      if (vulnerableServiceTicketIssued) {
        trace.addSessionOp({
          action: "createSession_golden_ticket_vulnerable",
          data: {
            isAttackMode: true,
            authenticatedAs: forgedPrincipal,
            service: servicePrincipal,
            sourceTgtRowId: forgedTgtRowId,
            note: "Vulnerable: KDC issues a Service Ticket for the forged 'administrator' principal — attacker now has admin access.",
          },
        });
      }
      recordStep({
        id: "gt-4",
        kind: "exploit",
        label: "Vulnerable: KDC accepts forged TGT and issues Service Ticket for 'administrator'",
        labelJa: "脆弱版: KDC が偽造 TGT を受理し 'administrator' のサービスチケットを発行",
        status: vulnerableServiceTicketIssued ? "success" : "failed",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/kerberos/attack/golden-ticket (vulnerable variant — krbtgt not rotated, no PAC validation)",
          },
          response: {
            status: vulnerableServiceTicketIssued ? 200 : 401,
            body: vulnerableServiceTicketIssued
              ? {
                  step: "TGS-REP",
                  decryptedServiceTicket: {
                    principal: forgedPrincipal,
                    servicePrincipal,
                  },
                  note: "Vulnerable: KDC decrypted forged TGT successfully (krbtgt key matched). Service Ticket issued without PAC validation.",
                }
              : {
                  error: "Forged TGT decryption unexpectedly failed.",
                },
          },
        },
        detailJa: vulnerableServiceTicketIssued
          ? "この実装は脆弱です: KDC は偽造 TGT を正常に復号し (krbtgt 鍵が正しく使われているため)、'administrator' のサービスチケットを発行します。KDC は PAC 検証なしには偽造を検出できません。"
          : "脆弱パス実行不可: 偽造 TGT の復号が予期せず失敗しました。",
        detail: vulnerableServiceTicketIssued
          ? "This implementation is vulnerable: the KDC decrypts the forged TGT successfully (because the krbtgt key matches) and issues a Service Ticket for 'administrator'. Without PAC validation, the KDC cannot detect the forgery."
          : "Vulnerable path could not run — forged TGT decryption unexpectedly failed.",
      });

      // ── Step 5: verify (堅牢モード) — krbtgt 二重リセット後は偽造 TGT が失効
      // 設計上常に true (= ローテーション後の鍵では復号失敗 → reject)
      const defendedRotationDetected = true;
      trace.addCryptoOp({
        op: "verifyTGT(post_krbtgt_rotation)",
        input: `forgedTGT encrypted with old krbtgt key, KDC now uses rotated krbtgt key`,
        output: defendedRotationDetected
          ? "DECRYPT FAILED → reject (forged TGT no longer decryptable after krbtgt double-reset)"
          : "decrypt OK (rotation not yet performed — should not reach here)",
        algo: "AES-256-CBC with rotated krbtgt key + PAC validation",
        detail:
          "Defended: after a krbtgt double-reset (within 10 hours), the new krbtgt key cannot decrypt the forged TGT. PAC validation by Domain Controllers also detects forged group memberships independently.",
      });
      recordStep({
        id: "gt-5",
        kind: "verify",
        label: "Defended: krbtgt double-reset invalidates all Golden Tickets",
        labelJa: "堅牢版: krbtgt の二重リセットがすべての Golden Ticket を無効化",
        status: defendedRotationDetected ? "blocked" : "failed",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/kerberos/attack/golden-ticket (defended variant — post krbtgt double-reset)",
          },
          response: {
            status: 401,
            body: {
              error:
                "Forged TGT rejected: krbtgt key has been rotated (double-reset within 10 hours). PAC validation also enforced.",
              blockedBy: "kerberos_krbtgt_double_reset_and_pac_validation_enforced",
              defenses: {
                krbtgtDoubleReset: "Resetting krbtgt password twice (within 10 hours) invalidates all forged TGTs",
                pacValidation: "Domain Controllers validate Privilege Attribute Certificate group memberships",
                tier0Isolation: "DC isolated as Tier 0 — krbtgt acquisition requires DC compromise (high bar)",
                detection: "Alert on TGS requests with abnormally long Ticket lifetimes (>10 hours)",
              },
            },
          },
        },
        detailJa:
          "堅牢実装は以下を組み合わせて Golden Ticket を阻止します: (1) krbtgt パスワードの二重リセット (10 時間以内に 2 回) で既存の偽造 TGT を無効化、(2) DC による PAC 検証で偽造グループ情報を検出、(3) DC を Tier 0 として完全分離して krbtgt 取得自体を困難にする、(4) 異常に長い Ticket 有効期限 (>10 時間) を検知してアラート。",
        detail:
          "The defended implementation combines: (1) krbtgt double-reset (twice within 10 hours) invalidates existing forged TGTs; (2) PAC validation by Domain Controllers detects forged group memberships; (3) DC Tier 0 isolation makes krbtgt acquisition difficult; (4) alerts on TGS requests with abnormally long Ticket lifetimes (>10 hours).",
      });

      // SEC-FIDO2-2: 痕跡削除パターン — 偽造 TGT 行を削除して累積回避
      if (forgedTgtRowId !== null) {
        try {
          db.prepare(
            "DELETE FROM kerberos_tickets WHERE id = ? AND is_attack_sim = 1",
          ).run(forgedTgtRowId);
        } catch {
          // 痕跡削除失敗時は握り潰す
        }
      }

      return {
        blockedBy: "kerberos_krbtgt_double_reset_and_pac_validation_enforced",
        summary:
          "A vulnerable KDC accepts a forged TGT (Golden Ticket) because the krbtgt key was used correctly during forging. The defended deployment rotates krbtgt twice within 10 hours and enforces PAC validation, invalidating all existing forged TGTs.",
        summaryJa:
          "この実装は脆弱です: KDC は krbtgt 鍵で正しく暗号化された偽造 TGT (Golden Ticket) を正規と判断し、'administrator' のサービスチケットを発行してしまいます。堅牢実装は krbtgt を 10 時間以内に二度リセットし PAC 検証を有効化することで、既存の偽造 TGT を全て無効化します。",
        extra: {
          forgedPrincipal,
          servicePrincipal,
          forgedTgtEncryptedPreview,
          forgedValidUntil,
          vulnerableServiceTicketIssued,
          defendedRotationDetected,
          prerequisiteOmitted: true,
          forgedTgtInsertError,
          forgedTgtInserted,
          vulnerableDecryptError,
        } satisfies GoldenTicketExtra,
        payload: {
          params: {},
          result: {
            forgedPrincipal,
            servicePrincipal,
            forgedTgtEncryptedPreview,
            forgedValidUntil,
            vulnerableServiceTicketIssued,
            defendedRotationDetected,
            forgedTgtInserted,
            vulnerableDecryptError,
          },
        },
      };
    },
  }),
);
