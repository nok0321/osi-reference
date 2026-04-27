import { Hono } from "hono";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import { getDb } from "../db/schema.js";
import type { UserRow } from "../../shared/api-types.js";
import {
  parseBody,
  registerSchema,
  loginSchema,
  passwordAttackRainbowVsBcryptSchema,
  passwordAttackTimingStringCompareSchema,
  passwordAttackBruteforceSchema,
} from "../validation.js";
import { runAttackScenario, maskSecret } from "../utils/attack-runner.js";

export const passwordAuthRoutes = new Hono();

passwordAuthRoutes.post("/register", async (c) => {
  const parsed = await parseBody(c, registerSchema);
  if ("error" in parsed) return parsed.error;
  const { username, password } = parsed.data;
  const trace = c.get("trace");
  const db = getDb();

  // Check existing
  const t0 = performance.now();
  const existing = db.prepare("SELECT id FROM users WHERE username = ?").get(username);
  trace.addDbQuery({
    sql: "SELECT id FROM users WHERE username = ?",
    params: [username],
    rows: existing ? [existing] : [],
    ms: performance.now() - t0,
  });

  if (existing) {
    return c.json({ success: false, error: "Username already exists" }, 409);
  }

  // Generate salt
  const salt = await bcrypt.genSalt(10);
  trace.addCryptoOp({
    op: "bcrypt.genSalt",
    input: `rounds=10`,
    output: salt,
    algo: "bcrypt",
    detail: "Generate random salt with cost factor 10 (2^10 = 1024 iterations)",
  });

  // Hash password
  const hash = await bcrypt.hash(password, salt);
  trace.addCryptoOp({
    op: "bcrypt.hash",
    input: `password="[REDACTED]" + salt="${salt}"`,
    output: hash,
    algo: "bcrypt",
    detail: `Blowfish key schedule x1024 rounds. Output: $2a$10$... (60 chars)`,
  });

  // Insert user
  const t1 = performance.now();
  const result = db
    .prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)")
    .run(username, hash);
  trace.addDbQuery({
    sql: "INSERT INTO users (username, password_hash) VALUES (?, ?)",
    params: [username, "***"],
    rows: [{ lastInsertRowid: result.lastInsertRowid }],
    ms: performance.now() - t1,
  });

  const user = db
    .prepare("SELECT id, username, created_at FROM users WHERE id = ?")
    .get(result.lastInsertRowid) as Pick<UserRow, "id" | "username" | "created_at">;

  return c.json({ success: true, data: { user } });
});

passwordAuthRoutes.post("/login", async (c) => {
  const parsed = await parseBody(c, loginSchema);
  if ("error" in parsed) return parsed.error;
  const { username, password } = parsed.data;
  const trace = c.get("trace");
  const db = getDb();

  // Lookup user
  const t0 = performance.now();
  const user = db
    .prepare("SELECT id, username, password_hash, created_at FROM users WHERE username = ?")
    .get(username) as UserRow | undefined;
  trace.addDbQuery({
    sql: "SELECT id, username, password_hash, created_at FROM users WHERE username = ?",
    params: [username],
    rows: user ? [{ ...user, password_hash: user.password_hash.substring(0, 20) + "..." }] : [],
    ms: performance.now() - t0,
  });

  if (!user) {
    return c.json({ success: false, error: "User not found" }, 401);
  }

  // Compare password
  const match = await bcrypt.compare(password, user.password_hash);
  trace.addCryptoOp({
    op: "bcrypt.compare",
    input: `password="[REDACTED]" vs stored_hash="${user.password_hash.substring(0, 20)}..."`,
    output: match ? "MATCH ✓" : "MISMATCH ✗",
    algo: "bcrypt",
    detail: match
      ? "Extract salt from stored hash → re-hash input → compare result"
      : "Hash of provided password does not match stored hash",
  });

  if (!match) {
    return c.json({ success: false, error: "Invalid password" }, 401);
  }

  return c.json({
    success: true,
    data: {
      user: { id: user.id, username: user.username, created_at: user.created_at },
      message: "Login successful",
    },
  });
});

passwordAuthRoutes.get("/users", (c) => {
  if (process.env.NODE_ENV === "production") {
    return c.json({ success: false, error: "Not available in production" }, 403);
  }
  const db = getDb();
  const users = db
    .prepare("SELECT id, username, password_hash, created_at FROM users")
    .all() as UserRow[];
  // Mask password_hash — show algorithm/cost prefix + partial hash for educational display
  const masked = users.map((u) => ({
    id: u.id,
    username: u.username,
    password_hash: u.password_hash === "WEBAUTHN_ONLY"
      ? "WEBAUTHN_ONLY"
      : `${u.password_hash.substring(0, 29)}...` ,
    password_hash_full_length: u.password_hash.length,
    created_at: u.created_at,
  }));
  return c.json({ success: true, data: { users: masked } });
});

// ─────────────────────────────────────────────────────────────────────────────
// Password 攻撃シナリオ (DESIGN/10-attack-password.md 実装)
//
// 教育用シミュレーション — 実環境でのパスワード解析は数百 GB のレインボーテーブル DB と
// Hashcat/John 等で毎秒数十億候補を試行するが、本デモは固定辞書 (10〜20 件) と
// in-memory ループによる「概念モデル」で表現する。
//
// 攻撃ルートは必ず `runAttackScenario` 経由で 5 ステップ完全形 (probe → tamper → forge →
// exploit → verify) を 1 リクエストで両モード並列実行する (E-2)。outcome は常に "succeeded"、
// HTTP 200 で統一し、堅牢ステップ 5 の status="blocked" + blockedBy で防御識別子を表現する。
//
// ROB-KERB-1 教訓: 旧仕様の `algorithm` / `rateLimitEnabled` 等の body フィールドで
// 「片方だけ実行」する形は採用しない。脆弱/堅牢を必ず handler 内で双方並列計算する。
//
// 安全装置: DESIGN/04-safety-guardrails.md
// - 全シナリオ DB 書き込みなし (rainbow_table_sim は事前 seed 固定辞書、
//   bruteforce は in-memory ループ、timing は in-memory 比較のみ)
// - 平文パスワードは payload_json で必ず maskSecret() 経由
// - 辞書はサーバーシードのみ (ユーザー任意辞書投入禁止 — 実攻撃ツール化を避ける)
// ─────────────────────────────────────────────────────────────────────────────

// ── 共通シード (immutable) ──
// ROB-FIND-007 / TLS_DEMO_CONSTANTS / KERBEROS_DEMO_CONSTANTS と同パターン。
// ハッシュアルゴリズム名・bcrypt cost・タイミング値・辞書配列等の固定値を SSoT 一本化することで、
// 一方だけ変更し忘れて教材意図が破綻するリスクを排除する。
const PASSWORD_DEMO_CONSTANTS = {
  // ── レインボーテーブル比較 (シナリオ A) ──
  /** 固定の被害者ユーザー名 (シードユーザー、DB 書き込みなし)。 */
  victimUsername: "seed_alice",
  /** 攻撃者が標的とする平文パスワード (rainbow_table_sim と一致するもの)。 */
  rainbowTargetPlaintext: "password123",
  /** 高速ハッシュアルゴリズム (ソルトなし)。 */
  fastHashAlgorithms: ["sha1", "md5"] as const,
  /** bcrypt の本番推奨 cost (saltRounds)。 */
  bcryptDefendedCost: 12,

  // ── タイミング攻撃 (シナリオ B) ──
  /** 正解パスワード (固定、handler 内のシミュレーション計算にのみ使用)。 */
  timingTargetPassword: "password123",
  /** プローブパスワード列 (先頭 0/3/全 文字一致)。 */
  timingProbes: [
    { label: "x_______", labelJa: "先頭 0 文字一致", matchedChars: 0 },
    { label: "pas_____", labelJa: "先頭 3 文字一致", matchedChars: 3 },
    { label: "password123", labelJa: "全文字一致", matchedChars: 11 },
  ] as const,
  /** 短絡評価 1 文字あたりの追加遅延 (ms)。教育目的の誇張値 (実環境では μs オーダー)。 */
  shortCircuitMsPerChar: 0.15,
  /** 短絡評価のベース応答時間 (ms)。 */
  shortCircuitBaseMs: 1.05,
  /** 定数時間比較の固定応答時間 (ms) — 一致文字数に依存しない。 */
  timingSafeFixedMs: 2.05,
  /** 定数時間比較の許容ジッター (ms) — 0.1 以下なら「無視できる」と評価される。 */
  timingSafeJitterMs: 0.1,

  // ── ブルートフォース (シナリオ C) ──
  /**
   * 固定辞書 (20 件)。OWASP Top 25 の頻出弱パスワードを混在させる。
   * 攻撃成立を観測できるよう、seed_alice の実パスワード "Passw0rd!" を
   * 7 番目 (index=6) に配置する — schema.ts の seedDb() で固定された値と整合させ、
   * 「弱パスワードが辞書攻撃で発見される」を教育的に確実に再現する (DESIGN/04 §3.1)。
   * 配列順序は固定 (テスト不変条件)。
   */
  bruteforceWordlist: [
    "123456", "password", "12345678", "qwerty", "abc123",
    "monkey", "Passw0rd!", "1234567", "letmein", "trustno1",
    "dragon", "iloveyou", "welcome1", "hunter2", "sunshine",
    "princess", "passw0rd", "shadow", "master", "michael",
  ] as const,
  /** レート制限ポリシー (堅牢モード)。 */
  rateLimitPolicy: "5 failures per minute per IP",
  /** レート制限の閾値 (5 回失敗で 429)。 */
  rateLimitThreshold: 5,
  /** 堅牢モードの HTTP ステータス (Too Many Requests)。 */
  defendedHttpStatus: 429,
} as const satisfies Readonly<{
  victimUsername: string;
  rainbowTargetPlaintext: string;
  fastHashAlgorithms: readonly string[];
  bcryptDefendedCost: number;
  timingTargetPassword: string;
  timingProbes: readonly { label: string; labelJa: string; matchedChars: number }[];
  shortCircuitMsPerChar: number;
  shortCircuitBaseMs: number;
  timingSafeFixedMs: number;
  timingSafeJitterMs: number;
  bruteforceWordlist: readonly string[];
  rateLimitPolicy: string;
  rateLimitThreshold: number;
  defendedHttpStatus: number;
}>;

// ── Scenario A: bcrypt vs Rainbow Table 比較 ──
// 防御の核心: bcrypt のソルト + 計算コスト (2^cost rounds) は、ソルトなし高速ハッシュ
// (SHA-1/MD5) と異なり、事前計算済みレインボーテーブルでの逆引きを実質不可能にする。
type PasswordRainbowVsBcryptExtra = {
  /** 固定被害者ユーザー名 (固定シード)。 */
  victimUsername: string;
  /** ターゲット平文 (rainbow_table_sim と一致するもの — 教育用、表示は plaintext)。 */
  targetPlaintext: string;
  /** SHA-1 ハッシュ値 (実計算)。 */
  sha1Hash: string;
  /** MD5 ハッシュ値 (実計算)。 */
  md5Hash: string;
  /** SHA-1 のレインボーテーブル逆引きで発見された平文 (一致時) または null。 */
  sha1RecoveredPlaintext: string | null;
  /** MD5 のレインボーテーブル逆引きで発見された平文 (一致時) または null。 */
  md5RecoveredPlaintext: string | null;
  /** bcrypt ハッシュ (堅牢モード、cost=12 で計算した代表値、表示用 preview)。 */
  bcryptHashPreview: string;
  /** bcrypt のレインボーテーブル逆引き — 設計上常に null (固定辞書には bcrypt エントリなし)。 */
  bcryptRecoveredPlaintext: string | null;
  /** 脆弱モード: SHA-1 + MD5 のいずれかで逆引き成立 (= 攻撃者がパスワードを入手) — 設計上常に true。 */
  vulnerableHashReversed: boolean;
  /** 堅牢モード: bcrypt の逆引きで一致なし — 設計上常に true。 */
  defendedBcryptResistant: boolean;
};

passwordAuthRoutes.post("/attack/rainbow-vs-bcrypt", (c) =>
  runAttackScenario<typeof passwordAttackRainbowVsBcryptSchema, PasswordRainbowVsBcryptExtra>(c, {
    schema: passwordAttackRainbowVsBcryptSchema,
    scenarioId: "password-rainbow-vs-bcrypt",
    tabId: "auth-methods",
    async handler({ recordStep, trace, db }) {
      const target = PASSWORD_DEMO_CONSTANTS.rainbowTargetPlaintext;
      const sha1Hash = crypto.createHash("sha1").update(target).digest("hex");
      const md5Hash = crypto.createHash("md5").update(target).digest("hex");

      // ── Step 1: probe — 攻撃者が漏洩 DB ダンプから SHA-1/MD5 ハッシュを取得
      recordStep({
        id: "rb-1",
        kind: "probe",
        label: "Obtain SHA-1/MD5 password hash from leaked DB dump",
        labelJa: "漏洩 DB ダンプから SHA-1/MD5 パスワードハッシュを取得",
        status: "success",
        payload: {
          type: "credential",
          username: PASSWORD_DEMO_CONSTANTS.victimUsername,
          passwordHashAlgo: "sha1+md5",
        },
        detailJa:
          "攻撃者は SQL インジェクションや DB バックアップ漏洩等の経路で、被害者のパスワードハッシュを取得済みと仮定します (取得経路は本シナリオの対象外)。古いシステムでは SHA-1 や MD5 のような高速ハッシュがソルトなしで使われていることが多く、ハッシュ値が同じパスワードに対して常に同一 — レインボーテーブルでの逆引きが現実的になります。",
        detail:
          "The attacker is assumed to have obtained the victim's password hash via SQL injection, DB backup leak, or similar (the exfiltration path is out of scope here). Legacy systems often use unsalted fast hashes like SHA-1 or MD5 — identical passwords always yield identical hashes, making rainbow-table lookups practical.",
      });

      // ── Step 2: tamper — 攻撃者が手元で同じ平文を SHA-1 でハッシュ化 (検証用)
      trace.addCryptoOp({
        op: "crypto.createHash(sha1)",
        input: `password="[REDACTED]" (no salt)`,
        output: sha1Hash,
        algo: "SHA-1 (unsalted, fast)",
        detail:
          "Vulnerable: SHA-1 with no salt produces a deterministic 40-char hex digest. Same password → same hash → rainbow-table reversible. RFC 6194 deprecates SHA-1 for any security purpose.",
      });
      recordStep({
        id: "rb-2",
        kind: "tamper",
        label: "Compute candidate SHA-1 hash (no salt) for rainbow lookup",
        labelJa: "レインボーテーブル照合用に SHA-1 ハッシュ (ソルトなし) を計算",
        status: "success",
        payload: {
          type: "credential",
          passwordHashAlgo: "sha1",
        },
        detailJa:
          "攻撃者は手元のマシンで標的の弱パスワードを SHA-1 でハッシュ化します。SHA-1 はソルトなし・高速 (CPU 一台で数億候補/秒) のため、攻撃者は事前計算済みハッシュ→平文の対応表 (レインボーテーブル) を保持できます。本デモではサーバー側に組み込んだ 10 件の固定辞書 (rainbow_table_sim テーブル) でこの対応表をシミュレートします。",
        detail:
          "The attacker hashes a candidate weak password with SHA-1 on their own machine. SHA-1 is unsalted and fast (hundreds of millions of candidates/sec on commodity CPUs), so attackers can maintain precomputed hash→plaintext maps (rainbow tables). This demo simulates such a map with a fixed 10-entry dictionary (rainbow_table_sim) embedded server-side.",
      });

      // ── Step 3: forge — MD5 でも同じ平文をハッシュ化 (複数アルゴリズム対比)
      trace.addCryptoOp({
        op: "crypto.createHash(md5)",
        input: `password="[REDACTED]" (no salt)`,
        output: md5Hash,
        algo: "MD5 (unsalted, fast)",
        detail:
          "Vulnerable: MD5 with no salt produces a deterministic 32-char hex digest. RFC 6151 declares MD5 cryptographically broken — collision attacks are practical, and rainbow-table reversal is even faster than SHA-1.",
      });
      recordStep({
        id: "rb-3",
        kind: "forge",
        label: "Compute candidate MD5 hash (no salt) for rainbow lookup",
        labelJa: "レインボーテーブル照合用に MD5 ハッシュ (ソルトなし) を計算",
        status: "success",
        payload: {
          type: "credential",
          passwordHashAlgo: "md5",
        },
        detailJa:
          "攻撃者は MD5 でも同じ計算を行います。MD5 は SHA-1 よりさらに脆弱 (RFC 6151 で暗号学的に破られていると公式宣言済み) で、辞書攻撃の速度も SHA-1 より高速です。同じ平文に対して SHA-1 / MD5 の両方が逆引き可能なら、攻撃者はどちらの形式の漏洩 DB に対しても解読可能です。",
        detail:
          "The attacker repeats with MD5. MD5 is even weaker than SHA-1 (RFC 6151 declares it cryptographically broken) and faster to brute-force. If both hashes are reversible for a given plaintext, the attacker can crack either format of leaked DB.",
      });

      // ── Step 4: exploit (脆弱モード) — rainbow_table_sim テーブルで SHA-1/MD5 を逆引き
      const t0 = performance.now();
      const sha1Row = db
        .prepare("SELECT plaintext FROM rainbow_table_sim WHERE hash = ? AND algo = 'sha1'")
        .get(sha1Hash) as { plaintext: string } | undefined;
      trace.addDbQuery({
        sql: "SELECT plaintext FROM rainbow_table_sim WHERE hash = ? AND algo = 'sha1'",
        params: [sha1Hash],
        rows: sha1Row ? [{ plaintext: sha1Row.plaintext }] : [],
        ms: performance.now() - t0,
      });
      const t1 = performance.now();
      const md5Row = db
        .prepare("SELECT plaintext FROM rainbow_table_sim WHERE hash = ? AND algo = 'md5'")
        .get(md5Hash) as { plaintext: string } | undefined;
      trace.addDbQuery({
        sql: "SELECT plaintext FROM rainbow_table_sim WHERE hash = ? AND algo = 'md5'",
        params: [md5Hash],
        rows: md5Row ? [{ plaintext: md5Row.plaintext }] : [],
        ms: performance.now() - t1,
      });
      const sha1Recovered = sha1Row?.plaintext ?? null;
      const md5Recovered = md5Row?.plaintext ?? null;
      // R-MEDIUM-1 教訓: bare literal `true` は使わず SSoT 派生条件で表現する。
      // 「いずれかのアルゴリズムで逆引き成立」を意味する表現で、将来 rainbow_table_sim から
      // 該当行を削除すれば自動的に false に転じて教材意図の破綻を検出可能。
      const vulnerableHashReversed = sha1Recovered !== null || md5Recovered !== null;
      trace.addCryptoOp({
        op: "rainbow_table_sim.lookup (vulnerable_unsalted_fast_hash)",
        input: `sha1=${sha1Hash.substring(0, 16)}..., md5=${md5Hash.substring(0, 16)}...`,
        output: vulnerableHashReversed
          ? `RECOVERED: sha1→${sha1Recovered ?? "<miss>"}, md5→${md5Recovered ?? "<miss>"}`
          : "no match in rainbow table (unexpected)",
        algo: "rainbow table reverse lookup",
        detail:
          "Vulnerable: the leaked SHA-1/MD5 hashes are looked up in the precomputed rainbow table. Both hashes match the 'password123' entry, recovering the plaintext in <1ms. Salted hashes would require separate rainbow tables for every salt — infeasible.",
      });
      recordStep({
        id: "rb-4",
        kind: "exploit",
        label: "Vulnerable: SHA-1/MD5 hashes reversed via rainbow table lookup",
        labelJa: "脆弱版: SHA-1/MD5 ハッシュをレインボーテーブルで逆引き → 平文復元成立",
        status: vulnerableHashReversed ? "success" : "failed",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/auth/password/attack/rainbow-vs-bcrypt (vulnerable variant — unsalted fast hashes)",
            headers: { "X-Attack-Sim": "rainbow-vs-bcrypt" },
          },
          response: {
            status: vulnerableHashReversed ? 200 : 500,
            body: vulnerableHashReversed
              ? {
                  step: "rainbow lookup",
                  recovered: { sha1: sha1Recovered, md5: md5Recovered },
                  note: "Vulnerable: unsalted SHA-1/MD5 hashes are reversible via precomputed rainbow tables. Plaintext recovered in <1ms.",
                }
              : { error: "Rainbow table miss (unexpected — seed data drift?)." },
          },
        },
        detailJa: vulnerableHashReversed
          ? "この実装は脆弱です: SHA-1 と MD5 はソルトなしで使うとレインボーテーブルで即座に逆引きできます。漏洩した password_hash 列が SHA-1/MD5 形式なら、攻撃者は被害者の平文パスワードを <1ms で復元します。同じパスワードを他サービスで使い回していれば、横展開攻撃 (credential stuffing) に直結します。"
          : "脆弱パス予期せず実行不可: rainbow_table_sim seed データに該当行が見当たりませんでした。",
        detail: vulnerableHashReversed
          ? "This implementation is vulnerable: SHA-1 and MD5 without salt are reversible via precomputed rainbow tables in <1ms. If a leaked password_hash column uses SHA-1/MD5, attackers immediately recover plaintext. Reused passwords on other services then enable credential stuffing."
          : "Vulnerable path unexpectedly failed: rainbow_table_sim seed data did not contain the expected row.",
      });

      // ── Step 5: verify (堅牢モード) — bcrypt (ソルト + cost=12) でレインボーテーブル無効化
      // 実 bcrypt ハッシュを生成し、rainbow_table_sim にも問い合わせて「一致なし」を確認する。
      const bcryptHash = await bcrypt.hash(target, PASSWORD_DEMO_CONSTANTS.bcryptDefendedCost);
      const t2 = performance.now();
      const bcryptRow = db
        .prepare("SELECT plaintext FROM rainbow_table_sim WHERE hash = ?")
        .get(bcryptHash) as { plaintext: string } | undefined;
      trace.addDbQuery({
        sql: "SELECT plaintext FROM rainbow_table_sim WHERE hash = ?",
        params: [bcryptHash.substring(0, 32) + "..."], // 表示用 preview (実 SQL bind は full hash)
        rows: bcryptRow ? [{ plaintext: bcryptRow.plaintext }] : [],
        ms: performance.now() - t2,
      });
      const bcryptRecovered = bcryptRow?.plaintext ?? null;
      // R-MEDIUM-1 教訓: bare literal `true` は使わず、SSoT 派生条件で防御成立を表現する。
      const defendedBcryptResistant = bcryptRecovered === null;
      trace.addCryptoOp({
        op: "bcrypt.hash (defended_salted_slow)",
        input: `password="[REDACTED]", cost=${PASSWORD_DEMO_CONSTANTS.bcryptDefendedCost}`,
        output: `${bcryptHash.substring(0, 29)}... (60 chars, unique salt)`,
        algo: `bcrypt (Blowfish key schedule x 2^${PASSWORD_DEMO_CONSTANTS.bcryptDefendedCost})`,
        detail:
          "Defended: bcrypt embeds a unique 16-byte random salt and runs Blowfish 2^cost iterations. Same password produces a different hash each time. A rainbow table would need a separate precomputation per salt — infeasible.",
      });
      trace.addCryptoOp({
        op: "rainbow_table_sim.lookup (defended_bcrypt_with_salt)",
        input: `bcryptHash=${bcryptHash.substring(0, 16)}...`,
        output: defendedBcryptResistant
          ? "no match (bcrypt salt + cost defeats rainbow table lookup)"
          : "unexpected match (rainbow table seed drift?)",
        algo: "rainbow table reverse lookup",
        detail:
          "Defended: the bcrypt hash format ($2a$12$<22-char-salt><31-char-hash>) cannot be matched in the unsalted-hash rainbow table. Even if the salt were known, the cost factor (2^12 = 4096 iterations) raises the per-candidate cost by ~12 orders of magnitude vs SHA-1.",
      });
      recordStep({
        id: "rb-5",
        kind: "verify",
        label: "Defended: bcrypt salt + cost defeat rainbow table — no plaintext recovery",
        labelJa: "堅牢版: bcrypt のソルトと計算コストがレインボーテーブルを無効化 — 平文復元不能",
        status: defendedBcryptResistant ? "blocked" : "failed",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/auth/password/attack/rainbow-vs-bcrypt (defended variant — bcrypt salt+cost)",
          },
          response: {
            status: 401,
            body: {
              error: "bcrypt-protected hash cannot be reversed via rainbow table.",
              blockedBy: "bcrypt_salt_and_cost_factor_defeats_rainbow_table_lookup",
              policy: {
                algorithm: "bcrypt",
                cost: PASSWORD_DEMO_CONSTANTS.bcryptDefendedCost,
                saltBits: 128,
                rounds: 1 << PASSWORD_DEMO_CONSTANTS.bcryptDefendedCost,
                owaspRecommendation: "Argon2id is the OWASP-preferred password hash; bcrypt is acceptable",
              },
              comparison: {
                sha1: { hash: sha1Hash, recovered: sha1Recovered },
                md5: { hash: md5Hash, recovered: md5Recovered },
                bcrypt: { hashPreview: `${bcryptHash.substring(0, 29)}...`, recovered: null },
              },
            },
          },
        },
        detailJa:
          "堅牢実装は OWASP Password Storage Cheat Sheet に従い、ソルト付きの計算コストの高い関数 (bcrypt cost=12 推奨、Argon2id がさらに推奨) でパスワードをハッシュ化します。bcrypt のハッシュ形式 ($2a$12$<22 文字ソルト><31 文字ハッシュ>) はソルトなし向けレインボーテーブルと一致しません。仮にソルトが既知でも、cost=12 (2^12=4096 回反復) により候補あたりの計算コストが SHA-1 比で約 12 桁増加するため、ブルートフォースも実質不能です。",
        detail:
          "The defended implementation, per OWASP Password Storage Cheat Sheet, hashes passwords with a salted, computationally expensive function (bcrypt cost=12 recommended; Argon2id even more so). The bcrypt format ($2a$12$<22-char-salt><31-char-hash>) does not match unsalted-hash rainbow tables. Even with a known salt, cost=12 (2^12=4096 iterations) raises per-candidate cost by ~12 orders of magnitude vs SHA-1, making brute force impractical.",
      });

      return {
        blockedBy: "bcrypt_salt_and_cost_factor_defeats_rainbow_table_lookup",
        summary:
          "A vulnerable system using unsalted SHA-1/MD5 hashes for password storage allows precomputed rainbow tables to recover plaintext in <1ms. The defended system uses bcrypt with cost=12 — a unique salt and 2^12 iterations make rainbow tables infeasible and brute force impractical. Both modes run in parallel within one request.",
        summaryJa:
          "この実装は脆弱です: ソルトなし SHA-1/MD5 でパスワードを保存するシステムは、事前計算済みレインボーテーブルで <1ms で平文を復元されます。堅牢実装は bcrypt (cost=12) を使用し、一意のソルトと 2^12 回反復によりレインボーテーブルを実質無効化、ブルートフォースも実用不能にします。両モードを 1 リクエスト内で並列実行します。",
        extra: {
          victimUsername: PASSWORD_DEMO_CONSTANTS.victimUsername,
          targetPlaintext: target,
          sha1Hash,
          md5Hash,
          sha1RecoveredPlaintext: sha1Recovered,
          md5RecoveredPlaintext: md5Recovered,
          bcryptHashPreview: `${bcryptHash.substring(0, 29)}...`,
          bcryptRecoveredPlaintext: bcryptRecovered,
          vulnerableHashReversed,
          defendedBcryptResistant,
        } satisfies PasswordRainbowVsBcryptExtra,
        payload: {
          params: {},
          result: {
            // SEC FINDING-5: 平文パスワードは payload_json では maskSecret() でマスク。
            // (extra フィールドは UI 表示用のため平文 OK、payload_json は DB 永続化されるため要マスク)
            targetPlaintextMasked: maskSecret(target),
            sha1HashPreview: sha1Hash.substring(0, 16) + "...",
            md5HashPreview: md5Hash.substring(0, 16) + "...",
            vulnerableHashReversed,
            defendedBcryptResistant,
          },
        },
      };
    },
  }),
);

// ── Scenario B: タイミング攻撃 (短絡評価 vs timingSafeEqual) ──
// 防御の核心: `===` や `Buffer.compare` による短絡評価は、最初に不一致な文字で即座に
// `false` を返すため、応答時間がプレフィックス一致長に比例して変化する (= サイドチャネル)。
// `crypto.timingSafeEqual` は常に全バイトを比較するため、応答時間がリーク情報を含まない。
type PasswordTimingExtra = {
  /** 正解パスワードの長さ (実値はマスク)。 */
  targetPasswordLength: number;
  /** プローブ別の応答時間 (脆弱モード = 短絡評価)。 */
  vulnerableTimings: { probe: string; matchedChars: number; responseTimeMs: number }[];
  /** プローブ別の応答時間 (堅牢モード = 定数時間比較)。 */
  defendedTimings: { probe: string; matchedChars: number; responseTimeMs: number }[];
  /** 脆弱モード: タイミング差から推定されたパスワードプレフィックス。 */
  vulnerableInferredPrefix: string;
  /** 脆弱モード: 応答時間レンジ (max - min)。閾値超過なら攻撃成立 — 設計上常に true。 */
  vulnerableTimingVarianceMs: number;
  /** 堅牢モード: 応答時間レンジ (max - min)。`timingSafeJitterMs` 以下なら防御成立 — 設計上常に true。 */
  defendedTimingVarianceMs: number;
  /** 脆弱モード: タイミング差からのパスワード推論成立 — 設計上常に true。 */
  vulnerableTimingLeakObserved: boolean;
  /** 堅牢モード: タイミング差排除 — 設計上常に true。 */
  defendedTimingConstant: boolean;
};

passwordAuthRoutes.post("/attack/timing-string-compare", (c) =>
  runAttackScenario<typeof passwordAttackTimingStringCompareSchema, PasswordTimingExtra>(c, {
    schema: passwordAttackTimingStringCompareSchema,
    scenarioId: "password-timing-string-compare",
    tabId: "auth-methods",
    async handler({ recordStep, trace }) {
      const target = PASSWORD_DEMO_CONSTANTS.timingTargetPassword;
      const probes = PASSWORD_DEMO_CONSTANTS.timingProbes;

      // 短絡評価のシミュレーション応答時間 = base + matchedChars * msPerChar
      const vulnerableTimings = probes.map((p) => ({
        probe: p.label,
        matchedChars: p.matchedChars,
        responseTimeMs:
          PASSWORD_DEMO_CONSTANTS.shortCircuitBaseMs +
          p.matchedChars * PASSWORD_DEMO_CONSTANTS.shortCircuitMsPerChar,
      }));
      // 定数時間比較のシミュレーション応答時間 = 固定値 ± ジッター/2
      // `seed = matchedChars` で deterministic にし、テストで再現可能にする。
      const defendedTimings = probes.map((p) => {
        const jitter = (((p.matchedChars * 7) % 5) / 5 - 0.5) * PASSWORD_DEMO_CONSTANTS.timingSafeJitterMs;
        return {
          probe: p.label,
          matchedChars: p.matchedChars,
          responseTimeMs: PASSWORD_DEMO_CONSTANTS.timingSafeFixedMs + jitter,
        };
      });

      const vulnerableTimes = vulnerableTimings.map((t) => t.responseTimeMs);
      const defendedTimes = defendedTimings.map((t) => t.responseTimeMs);
      const vulnerableTimingVarianceMs =
        Math.max(...vulnerableTimes) - Math.min(...vulnerableTimes);
      const defendedTimingVarianceMs =
        Math.max(...defendedTimes) - Math.min(...defendedTimes);

      // ── Step 1: probe — 0 文字一致のプローブで応答時間計測 (短絡評価)
      const probe0 = vulnerableTimings[0];
      trace.addCryptoOp({
        op: "string.=== (vulnerable_short_circuit_compare)",
        input: `probe="${probe0.probe}" vs target="[REDACTED]" (matched=${probe0.matchedChars} chars)`,
        output: `false (stopped at char 0); responseTime=${probe0.responseTimeMs.toFixed(2)}ms`,
        algo: "short-circuit-equal",
        detail:
          "Vulnerable: comparison terminates at the first mismatching character. With 0 chars matching, the response is the fastest. Note: the response times in this demo are exaggerated simulation values for conceptual clarity — real timing differences are at the microsecond scale and require statistical aggregation over many requests.",
      });
      recordStep({
        id: "tm-1",
        kind: "probe",
        label: "Measure response time with 0-character match (vulnerable mode)",
        labelJa: "脆弱モード: 先頭 0 文字一致で応答時間を計測",
        status: "success",
        payload: {
          type: "generic",
          data: {
            probe: probe0.probe,
            matchedChars: probe0.matchedChars,
            responseTimeMs: probe0.responseTimeMs,
            compareMethod: "=== (short-circuit)",
            note: "Response times are simulation values exaggerating microsecond-scale differences for conceptual clarity",
          },
        },
        detailJa:
          "攻撃者はログインエンドポイントに対して、先頭文字が正解と異なる試行パスワードを送信し、応答時間を計測します。短絡評価では先頭 1 文字目で `false` が確定するため、応答時間が最速になります。注: 本デモの応答時間値はミリ秒オーダーまで誇張したシミュレーション値で、実環境ではマイクロ秒オーダーの差異を統計的に集約する必要があります。",
        detail:
          "The attacker sends a probe password whose first character differs from the target and measures the server's response time. With short-circuit comparison, the result is determined at character 1 — fastest response. Note: the response times in this demo are exaggerated simulation values; real-world timing attacks require microsecond-scale measurements aggregated over many requests.",
      });

      // ── Step 2: tamper — 3 文字一致のプローブで応答時間計測 (脆弱モード)
      const probe3 = vulnerableTimings[1];
      trace.addCryptoOp({
        op: "string.=== (vulnerable_short_circuit_compare)",
        input: `probe="${probe3.probe}" vs target="[REDACTED]" (matched=${probe3.matchedChars} chars)`,
        output: `false (stopped at char 3); responseTime=${probe3.responseTimeMs.toFixed(2)}ms`,
        algo: "short-circuit-equal",
        detail:
          "Vulnerable: comparison continues for 3 characters before finding a mismatch. Response time increases proportionally to the matched prefix length — this is the timing leak.",
      });
      recordStep({
        id: "tm-2",
        kind: "tamper",
        label: "Measure response time with 3-character match (vulnerable mode)",
        labelJa: "脆弱モード: 先頭 3 文字一致で応答時間を計測",
        status: "success",
        payload: {
          type: "generic",
          data: {
            probe: probe3.probe,
            matchedChars: probe3.matchedChars,
            responseTimeMs: probe3.responseTimeMs,
            compareMethod: "=== (short-circuit)",
            increaseFromBaseline: probe3.responseTimeMs - probe0.responseTimeMs,
          },
        },
        detailJa:
          "攻撃者はプレフィックスを徐々に正解に近づけながら応答時間を計測します。先頭 3 文字が一致すると、短絡評価は 3 文字目を超えて 4 文字目で `false` を返すため、応答時間が 0 文字一致時より明確に増加します。この応答時間差が「3 文字目までは正解」というシグナルになります。",
        detail:
          "The attacker progressively refines the prefix and measures response times. When 3 characters match, short-circuit comparison evaluates beyond the 3rd character before failing at the 4th — yielding a clearly increased response time. This delta is the signal that 'the first 3 characters are correct'.",
      });

      // ── Step 3: forge — タイミング差から full prefix を推定 (シミュレーション)
      const inferredPrefix = target.substring(0, probe3.matchedChars);
      trace.addCryptoOp({
        op: "timing.statisticalAggregation (vulnerable_inference)",
        input: `vulnerableTimings (${vulnerableTimings.length} probes)`,
        output: `varianceMs=${vulnerableTimingVarianceMs.toFixed(2)} → prefix="${inferredPrefix}" inferred`,
        algo: "statistical timing-leak inference",
        detail:
          "The attacker iterates: for each character position, try all 95 printable ASCII candidates and measure response time; the candidate with the slowest response is the correct character (one more byte advanced before short-circuit). Repeat until the full password is recovered. Real attacks require thousands of repetitions per character to overcome network jitter.",
      });
      recordStep({
        id: "tm-3",
        kind: "forge",
        label: "Infer password prefix from accumulated timing differences",
        labelJa: "蓄積されたタイミング差からパスワードのプレフィックスを推定",
        status: "success",
        payload: {
          type: "generic",
          data: {
            inferredPrefix,
            vulnerableTimings,
            method: "Iterate per-character: pick the candidate with the slowest response (one more byte advanced)",
            methodJa: "1 文字ずつイテレート: 最も応答時間が遅い候補が正解 (1 バイト多く進んだことを意味する)",
          },
        },
        detailJa:
          "プレフィックス長と応答時間のほぼ線形な関係が観測できれば、攻撃者は 1 文字ずつ反復試行することで全パスワードを復元できます。各文字位置で 95 候補 (印字可能 ASCII) を試行し、最も応答時間が遅いものを次の文字として確定します。実環境ではネットワークジッターを克服するため数千回の繰り返しが必要です。",
        detail:
          "Once the near-linear relationship between prefix length and response time is observed, the attacker recovers the full password one character at a time: at each position, try all 95 printable ASCII candidates and pick the one with the slowest response. Real-world attacks need thousands of repetitions per character to overcome network jitter.",
      });

      // ── Step 4: exploit (脆弱モード) — タイミング差からパスワード復元成立
      const vulnerableTimingLeakObserved =
        vulnerableTimingVarianceMs > PASSWORD_DEMO_CONSTANTS.timingSafeJitterMs;
      recordStep({
        id: "tm-4",
        kind: "exploit",
        label: "Vulnerable: timing-leak signal exceeds noise threshold — password recoverable",
        labelJa: "脆弱版: タイミング差がジッター閾値を超過 — パスワード復元可能",
        status: vulnerableTimingLeakObserved ? "success" : "failed",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/auth/password/attack/timing-string-compare (vulnerable variant — short-circuit compare)",
            headers: { "X-Attack-Sim": "timing-string-compare" },
          },
          response: {
            status: vulnerableTimingLeakObserved ? 200 : 500,
            body: vulnerableTimingLeakObserved
              ? {
                  step: "timing-leak observed",
                  vulnerableTimings,
                  varianceMs: vulnerableTimingVarianceMs,
                  jitterThresholdMs: PASSWORD_DEMO_CONSTANTS.timingSafeJitterMs,
                  inferredPrefix,
                  note: "Vulnerable: timing variance exceeds jitter threshold. Password recoverable via per-character iteration.",
                }
              : { error: "Timing variance below jitter threshold (unexpected)." },
          },
        },
        detailJa: vulnerableTimingLeakObserved
          ? "この実装は脆弱です: 短絡評価による文字列比較は応答時間にプレフィックス一致長を漏洩させます。観測された分散値はジッター閾値を上回り、攻撃者は 1 文字ずつ反復試行することでパスワード全体を復元可能です。実環境でも、低レイテンシネットワーク (同一データセンタ内の VM 間など) では数時間で復元される事例が報告されています。"
          : "脆弱パス予期せず実行不可: タイミング分散値がジッター閾値以下となりました。",
        detail: vulnerableTimingLeakObserved
          ? "This implementation is vulnerable: short-circuit string comparison leaks prefix-match length via response time. The observed variance exceeds the jitter threshold; an attacker can recover the full password via per-character iteration. Real-world reports show recovery in hours over low-latency networks (e.g., between VMs in the same data center)."
          : "Vulnerable path unexpectedly failed: timing variance was below the jitter threshold.",
      });

      // ── Step 5: verify (堅牢モード) — crypto.timingSafeEqual で応答時間を一定化
      // 実際に Buffer.from + timingSafeEqual を呼び出し、概念実証として記録する。
      // (応答時間そのものはシミュレーション値で、実測では nanosecond オーダーの差異)。
      // ROB-PW-2 教訓: timingSafeEqual は等長バッファを要求するため、固定長 (target.length)
      // へクランプ + ゼロパディングする。padEnd は probe.length > target.length のとき no-op に
      // なるため、Buffer.alloc + copy で必ず target.length バイトに揃える (将来 timingProbes を
      // 長い文字列に変更しても RangeError でハンドラが 500 に落ちないことを保証)。
      const fixedLen = target.length;
      const targetBuf = Buffer.alloc(fixedLen);
      Buffer.from(target).copy(targetBuf, 0, 0, fixedLen);
      const probeBuf = Buffer.alloc(fixedLen);
      Buffer.from(probes[0].label).copy(probeBuf, 0, 0, fixedLen);
      const tseResult = crypto.timingSafeEqual(targetBuf, probeBuf);
      trace.addCryptoOp({
        op: "crypto.timingSafeEqual (defended_constant_time_compare)",
        input: `probe="${probes[0].label}" vs target="[REDACTED]" (length-padded to ${target.length})`,
        output: `${tseResult} (all ${target.length} bytes compared regardless of mismatch position)`,
        algo: "timing-safe-equal",
        detail:
          "Defended: crypto.timingSafeEqual always compares all bytes (XOR-and-accumulate). Response time is independent of how many leading bytes match. Note: timingSafeEqual requires equal-length buffers — pad to a fixed length first to avoid leaking length information.",
      });
      const defendedTimingConstant =
        defendedTimingVarianceMs <= PASSWORD_DEMO_CONSTANTS.timingSafeJitterMs;
      recordStep({
        id: "tm-5",
        kind: "verify",
        label: "Defended: crypto.timingSafeEqual eliminates timing variance — no signal to recover",
        labelJa: "堅牢版: crypto.timingSafeEqual がタイミング差を排除 — 復元用シグナルなし",
        status: defendedTimingConstant ? "blocked" : "failed",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/auth/password/attack/timing-string-compare (defended variant — timingSafeEqual)",
          },
          response: {
            status: 401,
            body: {
              error: "Constant-time comparison eliminates the timing side-channel.",
              blockedBy: "crypto_timing_safe_equal_eliminates_response_time_variance",
              policy: {
                algorithm: "crypto.timingSafeEqual",
                requirement: "Equal-length buffers (pad inputs to fixed length first)",
                bcryptCompare: "bcrypt.compare uses constant-time comparison internally — already safe",
                rfc: "OWASP ASVS V2.5.4: Use constant-time comparison for credential validation",
              },
              comparison: {
                vulnerableTimings,
                defendedTimings,
                vulnerableVarianceMs: vulnerableTimingVarianceMs,
                defendedVarianceMs: defendedTimingVarianceMs,
                jitterThresholdMs: PASSWORD_DEMO_CONSTANTS.timingSafeJitterMs,
              },
            },
          },
        },
        detailJa:
          "堅牢実装は OWASP ASVS V2.5.4 に従い、認証情報の比較に定数時間比較関数 (`crypto.timingSafeEqual`) を使用します。timingSafeEqual は常に全バイトを XOR-加算で比較するため、応答時間が一致文字数に依存しません。実環境でも、bcrypt.compare は内部で定数時間比較を行うため既に安全です。独自比較ロジックを書く場合は必ず timingSafeEqual を使用し、長さの異なる入力は固定長にパディングしてください (長さ自体のリークを防ぐため)。",
        detail:
          "The defended implementation, per OWASP ASVS V2.5.4, uses a constant-time comparison function (crypto.timingSafeEqual) for credential validation. timingSafeEqual XOR-accumulates all bytes regardless of matching position, making response time independent of the number of matching characters. In practice, bcrypt.compare uses constant-time comparison internally and is already safe. When writing custom comparison logic, always use timingSafeEqual and pad inputs to a fixed length first (to avoid leaking length).",
      });

      return {
        blockedBy: "crypto_timing_safe_equal_eliminates_response_time_variance",
        summary:
          "A vulnerable login endpoint using `===` short-circuit comparison leaks the matched-prefix length via response time, allowing per-character password recovery. The defended endpoint uses crypto.timingSafeEqual (and bcrypt.compare internally), which evaluates all bytes regardless of mismatch position — eliminating the timing side-channel. Both modes run in parallel within one request.",
        summaryJa:
          "この実装は脆弱です: `===` 短絡評価で文字列比較を行うログインエンドポイントは応答時間に「一致プレフィックス長」を漏洩させ、攻撃者は 1 文字ずつパスワードを復元できます。堅牢実装は crypto.timingSafeEqual (および bcrypt.compare の内部実装) を使用し、不一致位置に関わらず全バイトを評価することでタイミングサイドチャネルを排除します。両モードを 1 リクエスト内で並列実行します。",
        extra: {
          targetPasswordLength: target.length,
          vulnerableTimings,
          defendedTimings,
          vulnerableInferredPrefix: inferredPrefix,
          vulnerableTimingVarianceMs,
          defendedTimingVarianceMs,
          vulnerableTimingLeakObserved,
          defendedTimingConstant,
        } satisfies PasswordTimingExtra,
        payload: {
          params: {},
          result: {
            // SEC FINDING-5: 平文 target は payload_json で必ずマスク。
            targetPasswordMasked: maskSecret(target),
            vulnerableVarianceMs: vulnerableTimingVarianceMs,
            defendedVarianceMs: defendedTimingVarianceMs,
            vulnerableTimingLeakObserved,
            defendedTimingConstant,
          },
        },
      };
    },
  }),
);

// ── Scenario C: レート制限なしブルートフォース ──
// 防御の核心: ログイン失敗回数を IP/アカウント単位で計測し、閾値超過で 429 Too Many Requests を返却。
// アカウントロックアウト + ユーザー列挙防止 (エラーメッセージ統一) + CAPTCHA も併用推奨。
type PasswordBruteforceExtra = {
  /** 固定被害者ユーザー名 (シードユーザー)。 */
  victimUsername: string;
  /** 試行された辞書サイズ (脆弱モードは全件、堅牢モードは閾値で停止)。 */
  wordlistSize: number;
  /** 脆弱モード: 一致発見した辞書インデックス (0 始まり) または null。 */
  vulnerableFoundAtIndex: number | null;
  /** 脆弱モード: 一致発見した平文 (UI 表示用、payload_json では maskSecret)。 */
  vulnerableFoundPasswordPreview: string | null;
  /** 脆弱モード: 試行回数 (= 一致発見までに試行した数)。 */
  vulnerableAttemptsUntilHit: number;
  /** 脆弱モード: 認証成立 — 設計上常に true (辞書に正解を含むため)。 */
  vulnerableAuthenticated: boolean;
  /** 堅牢モード: 試行回数 (= レート制限で停止した時点の数)。 */
  defendedAttemptsBeforeBlock: number;
  /** 堅牢モード: 適用されたレート制限ポリシー文字列。 */
  defendedRateLimitPolicy: string;
  /** 堅牢モード: 拒否時の HTTP ステータス。 */
  defendedHttpStatus: number;
  /** 堅牢モード: ブロック成立 — 設計上常に true。 */
  defendedRateLimitBlocked: boolean;
  /** seed_alice が DB に存在するか (ROB-N1 同パターンの early guard)。 */
  victimSeedFound: boolean;
};

passwordAuthRoutes.post("/attack/bruteforce-no-rate-limit", (c) =>
  runAttackScenario<typeof passwordAttackBruteforceSchema, PasswordBruteforceExtra>(c, {
    schema: passwordAttackBruteforceSchema,
    scenarioId: "password-bruteforce-no-rate-limit",
    tabId: "auth-methods",
    async handler({ recordStep, trace, db }) {
      const wordlist = [...PASSWORD_DEMO_CONSTANTS.bruteforceWordlist];
      const victim = PASSWORD_DEMO_CONSTANTS.victimUsername;

      // ROB-N1/N2 教訓: seed_alice 不在時の early guard (FK 制約違反やシード drift から
      // ハンドラ全体を 500 に落とさないため)。本シナリオは DB 書き込みなしだが、
      // bcrypt.compare が空 hash で undefined になる経路を防ぐ。
      const victimRow = db
        .prepare("SELECT id, username, password_hash FROM users WHERE username = ?")
        .get(victim) as Pick<UserRow, "id" | "username" | "password_hash"> | undefined;
      const victimSeedFound = victimRow !== undefined;

      // ── Step 1: probe — ユーザー列挙 (UserNotFound vs InvalidPassword でユーザー存在を確定)
      recordStep({
        id: "bf-1",
        kind: "probe",
        label: "Enumerate target username via login error message difference",
        labelJa: "ログインエラーメッセージの差異でターゲットユーザーを列挙",
        status: victimSeedFound ? "success" : "failed",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/auth/password/login",
            body: { username: victim, password: "wrong" },
          },
          response: {
            status: 401,
            body: victimSeedFound
              ? { success: false, error: "Invalid password" }
              : { success: false, error: "User not found" },
          },
        },
        detailJa: victimSeedFound
          ? "攻撃者はログインエンドポイントに既知の弱パスワード (例: 'wrong') を送信し、レスポンスを観察します。'User not found' と 'Invalid password' で異なるメッセージを返す実装は、ユーザー名の存在/不在を意図せず明かしてしまいます。攻撃者はこれを利用してまず正しいユーザー名を特定し、その後ブルートフォースに移行します。"
          : "シードユーザー seed_alice が DB に見当たりません (テストデータ drift)。ユーザー列挙は本デモの教育目的を達成しないため failed として記録します。",
        detail: victimSeedFound
          ? "The attacker sends a probe login with a known wrong password and inspects the response. Implementations returning distinct messages for 'User not found' vs 'Invalid password' inadvertently reveal username existence. Attackers use this to first enumerate valid usernames, then proceed to brute force."
          : "Seed user seed_alice not found in DB (test-data drift). Recording as failed because the educational target is not reachable.",
      });

      // ── Step 2: tamper — 辞書を構築 (固定 20 件、ユーザー任意辞書投入を許可しない)
      recordStep({
        id: "bf-2",
        kind: "tamper",
        label: "Load 20-entry weak-password dictionary (server-side fixed seed)",
        labelJa: "20 件の弱パスワード辞書をロード (サーバー側固定シード)",
        status: "success",
        payload: {
          type: "generic",
          data: {
            wordlistSize: wordlist.length,
            wordlistPreview: wordlist.slice(0, 5),
            note: "Wordlist is fixed server-side. Users cannot inject custom wordlists — that would risk turning the demo into a real attack tool.",
            noteJa: "辞書はサーバー側で固定されており、ユーザーが任意辞書を投入することはできません (実攻撃ツール化を避けるため)。",
          },
        },
        detailJa:
          "本デモでは固定 20 件の弱パスワード辞書 (OWASP Top 25 由来) を使用します。実環境のブルートフォース攻撃は数百万〜数十億エントリの辞書 (RockYou.txt, HaveIBeenPwned 等) を使用しますが、本デモは概念実証のため小規模に留めます。ユーザーが任意辞書を投入できないよう、辞書はサーバー側で固定されています。",
        detail:
          "The demo uses a 20-entry fixed weak-password wordlist (sourced from OWASP Top 25). Real attacks use millions to billions of entries (RockYou.txt, HaveIBeenPwned, etc.); the demo is intentionally small for proof-of-concept. The wordlist is server-side fixed — users cannot inject custom wordlists, which would risk turning the demo into a real attack tool.",
      });

      // ── Step 3: forge — 脆弱モードでサーバー側ループで bcrypt.compare 全件試行
      // (実 bcrypt.compare を実行 — DB 書き込みなし、in-memory loop のみ)
      let vulnerableFoundAtIndex: number | null = null;
      let vulnerableAttemptsUntilHit = 0;
      if (victimSeedFound && victimRow) {
        for (let i = 0; i < wordlist.length; i++) {
          vulnerableAttemptsUntilHit = i + 1;
          const candidate = wordlist[i];
          // eslint-disable-next-line no-await-in-loop -- 教育目的のため逐次実行 (タイミング再現性)
          const match = await bcrypt.compare(candidate, victimRow.password_hash);
          if (match) {
            vulnerableFoundAtIndex = i;
            break;
          }
        }
      }
      const vulnerableAuthenticated = vulnerableFoundAtIndex !== null;
      const vulnerableFoundPlaintext =
        vulnerableFoundAtIndex !== null ? wordlist[vulnerableFoundAtIndex] : null;
      trace.addCryptoOp({
        op: "bcrypt.compare (vulnerable_no_rate_limit_bulk_simulation)",
        input: `wordlistSize=${wordlist.length}, victimUsername=${victim}`,
        output: vulnerableAuthenticated
          ? `match found at index ${vulnerableFoundAtIndex} after ${vulnerableAttemptsUntilHit} attempts`
          : `no match found after ${vulnerableAttemptsUntilHit} attempts`,
        algo: "bcrypt",
        detail:
          "Vulnerable: server-side loop of bcrypt.compare() with no rate limiting. Each call is ~50-500ms at cost=10, but without throttling, an attacker scripting from outside can iterate freely. The bcrypt cost slows brute force but does not stop it — rate limiting is mandatory.",
      });

      // ── Step 4: exploit (脆弱モード) — 一致発見でログイン成立
      recordStep({
        id: "bf-3",
        kind: "forge",
        label: "Vulnerable: iterate dictionary against bcrypt.compare without throttling",
        labelJa: "脆弱版: レート制限なしで辞書を bcrypt.compare に逐次投入",
        status: vulnerableAuthenticated ? "success" : "failed",
        payload: {
          type: "generic",
          data: {
            wordlistSize: wordlist.length,
            attemptsUntilHit: vulnerableAttemptsUntilHit,
            foundAtIndex: vulnerableFoundAtIndex,
            // SEC FINDING-5 + payload_json マスク方針: trace_attackSteps は UI 表示用のため
            // preview のみを残す。payload_json (DB 永続化) には別途 maskSecret を適用済み。
            foundPasswordPreview:
              vulnerableFoundPlaintext !== null
                ? maskSecret(vulnerableFoundPlaintext)
                : null,
          },
        },
        detailJa: vulnerableAuthenticated
          ? `攻撃者は辞書 ${wordlist.length} 件を bcrypt.compare に逐次投入し、${vulnerableAttemptsUntilHit} 回目で一致を発見しました。bcrypt の計算コスト (cost=10 で約 50-500ms/回) は試行を遅らせますが停止はしません — レート制限なしでは数時間〜数日で OWASP Top 25 弱パスワードは全て破られます。`
          : "脆弱パス予期せず実行不可: 辞書全件試行で一致が見つかりませんでした (シード drift)。",
        detail: vulnerableAuthenticated
          ? `The attacker iterates ${wordlist.length} dictionary entries against bcrypt.compare and finds a match at attempt #${vulnerableAttemptsUntilHit}. bcrypt's cost (~50-500ms/call at cost=10) slows but does not stop brute force — without rate limiting, OWASP Top 25 weak passwords are all crackable in hours to days.`
          : "Vulnerable path unexpectedly failed: no match in entire wordlist (seed drift).",
      });
      recordStep({
        id: "bf-4",
        kind: "exploit",
        label: "Vulnerable: authenticate with the discovered password — account compromised",
        labelJa: "脆弱版: 発見したパスワードで認証成功 — アカウント侵害成立",
        status: vulnerableAuthenticated ? "success" : "failed",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/auth/password/login (vulnerable variant — no rate limit)",
            headers: { "X-Attack-Sim": "bruteforce-no-rate-limit" },
          },
          response: {
            status: vulnerableAuthenticated ? 200 : 401,
            body: vulnerableAuthenticated
              ? {
                  success: true,
                  data: {
                    user: { id: victimRow?.id ?? null, username: victim },
                    message: "Login successful",
                  },
                  note: "Vulnerable: no rate limit allowed unrestricted brute force. Account is now compromised.",
                }
              : { success: false, error: "No match found in wordlist." },
          },
        },
        detailJa: vulnerableAuthenticated
          ? "この実装は脆弱です: レート制限がない実装では、OWASP Top 25 弱パスワードを使用するアカウントは時間の問題で侵害されます。同じパスワードを他サービスで使い回していれば、横展開攻撃 (credential stuffing) に直結します。"
          : "脆弱パス予期せず実行不可: 認証ステップに到達できませんでした。",
        detail: vulnerableAuthenticated
          ? "This implementation is vulnerable: with no rate limiting, accounts using OWASP Top 25 weak passwords fall to brute force in time. Reused passwords on other services then enable credential stuffing."
          : "Vulnerable path unexpectedly failed: did not reach the authentication step.",
      });

      // ── Step 5: verify (堅牢モード) — レート制限が閾値で停止
      // 実際のレート制限ライブラリは導入していないため、シミュレーションで「閾値で停止」を表現。
      // ROB-PW-1 教訓: `Math.min(x, threshold) <= threshold` は数学的恒真式 (= bare literal `true` と等価)
      // のため避ける。R-MEDIUM-1 教訓に従い、SSoT 派生条件で「レート制限が攻撃を阻止できる」を表現:
      // 「辞書サイズが閾値より大きい」(= 攻撃者は閾値に到達するまで試行できる) かつ
      // 「脆弱モードで一致発見されるまでの試行数が閾値を超える」(= レート制限がなければ閾値以降の試行で発見される)。
      // 将来 wordlist を 3 件に縮小したり threshold を引き上げたりすれば、自動的に false に転じて教材意図破綻を検出可能。
      const defendedAttemptsBeforeBlock = Math.min(
        wordlist.length,
        PASSWORD_DEMO_CONSTANTS.rateLimitThreshold,
      );
      const defendedRateLimitBlocked =
        wordlist.length > PASSWORD_DEMO_CONSTANTS.rateLimitThreshold &&
        vulnerableAttemptsUntilHit > PASSWORD_DEMO_CONSTANTS.rateLimitThreshold;
      trace.addCryptoOp({
        op: "rateLimit.check (defended_5_per_minute_per_ip)",
        input: `attemptsObserved=${defendedAttemptsBeforeBlock}, threshold=${PASSWORD_DEMO_CONSTANTS.rateLimitThreshold}`,
        output: defendedRateLimitBlocked
          ? `429 Too Many Requests (blocked after ${defendedAttemptsBeforeBlock} attempts)`
          : "rate limit not triggered (unexpected)",
        algo: "sliding-window rate limit",
        detail:
          "Defended: a sliding-window rate limiter (5 failures per minute per IP) blocks the brute force at attempt #5. Per-account lockout (e.g., 10 failures → 15-min lock) provides defense-in-depth against distributed attacks. CAPTCHA after 3 failures is recommended for high-value accounts.",
      });
      recordStep({
        id: "bf-5",
        kind: "verify",
        label: "Defended: rate limiting blocks the dictionary attack at threshold — 429 response",
        labelJa: "堅牢版: レート制限が辞書攻撃を閾値でブロック — 429 応答",
        status: defendedRateLimitBlocked ? "blocked" : "failed",
        payload: {
          type: "http",
          request: {
            method: "POST",
            url: "/api/auth/password/login (defended variant — rate limit 5/min/IP)",
          },
          response: {
            status: PASSWORD_DEMO_CONSTANTS.defendedHttpStatus,
            body: {
              error: `Too Many Requests. Try again in 60 seconds.`,
              blockedBy: "rate_limit_per_ip_threshold_exceeded_with_account_lockout",
              policy: {
                rateLimit: PASSWORD_DEMO_CONSTANTS.rateLimitPolicy,
                threshold: PASSWORD_DEMO_CONSTANTS.rateLimitThreshold,
                accountLockout: "10 failures within 15 minutes → 15-minute lock",
                userEnumerationDefense:
                  "Return identical error message ('Invalid credentials') for both 'user not found' and 'wrong password'",
                captchaRecommended: "After 3 failures for high-value accounts",
                rfc: "OWASP ASVS V2.2 Authentication Verification Requirements",
              },
              comparison: {
                vulnerable: {
                  attemptsUntilHit: vulnerableAttemptsUntilHit,
                  authenticated: vulnerableAuthenticated,
                },
                defended: {
                  attemptsBeforeBlock: defendedAttemptsBeforeBlock,
                  blocked: defendedRateLimitBlocked,
                },
              },
            },
          },
        },
        detailJa:
          "堅牢実装は OWASP ASVS V2.2 に従い、IP ごとのスライディングウィンドウレート制限 (5 失敗/分) を強制し、5 回目の失敗で 429 Too Many Requests を返してブルートフォースを停止させます。アカウント単位のロックアウト (15 分以内に 10 失敗 → 15 分ロック) を併用すれば分散攻撃にも耐えます。さらにユーザー列挙対策として、'ユーザーが見つかりません' と 'パスワード不正' を統一エラーメッセージ ('認証情報が無効です') で返却します。重要アカウントには 3 回失敗後の CAPTCHA を併用推奨。",
        detail:
          "The defended implementation, per OWASP ASVS V2.2, enforces a sliding-window rate limit per IP (5 failures/minute) and returns 429 Too Many Requests on the 5th failure. Account-level lockout (10 failures within 15 minutes → 15-minute lock) defends against distributed attacks. Anti-enumeration: return identical error ('Invalid credentials') for both 'user not found' and 'wrong password'. CAPTCHA after 3 failures is recommended for high-value accounts.",
      });

      return {
        blockedBy: "rate_limit_per_ip_threshold_exceeded_with_account_lockout",
        summary: `A vulnerable login endpoint with no rate limiting allows a 20-entry weak-password dictionary attack to succeed at attempt #${vulnerableAttemptsUntilHit}. The defended endpoint enforces a 5/minute/IP rate limit and blocks the attack at attempt #${defendedAttemptsBeforeBlock} with HTTP 429. Both modes run in parallel within one request.`,
        summaryJa: `この実装は脆弱です: レート制限なしのログインエンドポイントでは、20 件の弱パスワード辞書攻撃が ${vulnerableAttemptsUntilHit} 回目で成功します。堅牢実装は IP ごとに 5 回/分のレート制限を強制し、${defendedAttemptsBeforeBlock} 回目で HTTP 429 で攻撃を停止します。両モードを 1 リクエスト内で並列実行します。`,
        extra: {
          victimUsername: victim,
          wordlistSize: wordlist.length,
          vulnerableFoundAtIndex,
          // UI 表示用のため平文の preview を残す (extra は payload_json と分離)。
          // E-2 契約により全シナリオ outcome="succeeded" のため、AttackResultBanner で
          // 「弱パスワードが何だったか」が分かる必要がある (教育目的)。
          vulnerableFoundPasswordPreview: vulnerableFoundPlaintext,
          vulnerableAttemptsUntilHit,
          vulnerableAuthenticated,
          defendedAttemptsBeforeBlock,
          defendedRateLimitPolicy: PASSWORD_DEMO_CONSTANTS.rateLimitPolicy,
          defendedHttpStatus: PASSWORD_DEMO_CONSTANTS.defendedHttpStatus,
          defendedRateLimitBlocked,
          victimSeedFound,
        } satisfies PasswordBruteforceExtra,
        payload: {
          params: {},
          result: {
            wordlistSize: wordlist.length,
            // SEC FINDING-5: payload_json では平文を必ずマスク。
            vulnerableFoundPasswordMasked: vulnerableFoundPlaintext
              ? maskSecret(vulnerableFoundPlaintext)
              : null,
            vulnerableAttemptsUntilHit,
            vulnerableAuthenticated,
            defendedAttemptsBeforeBlock,
            defendedRateLimitBlocked,
          },
        },
      };
    },
  }),
);
