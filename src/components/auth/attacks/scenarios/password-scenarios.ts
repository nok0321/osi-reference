import type { AttackScenarioMeta } from "../../../../../shared/api-types";

export const passwordScenarios: AttackScenarioMeta[] = [
  {
    id: "password-rainbow-vs-bcrypt",
    tabId: "auth-methods",
    name: "bcrypt vs Rainbow Table Comparison",
    nameJa: "bcrypt vs レインボーテーブル比較",
    category: "A2:Cryptographic Failures",
    cweId: "CWE-916",
    capecId: "CAPEC-55",
    difficulty: 2,
    osiLayer: 7,
    severity: "high",
    description:
      "This is a proof-of-concept for CWE-916 / CAPEC-55. Legacy systems storing passwords as unsalted SHA-1 or MD5 hashes are vulnerable to precomputed rainbow tables — the attacker recovers plaintext in <1ms by looking up the hash in a hash→plaintext map. The defended implementation uses bcrypt (cost=12) with a unique salt, making rainbow tables infeasible (a separate precomputation would be required per salt) and brute force impractical (2^12 iterations per candidate). Note: real rainbow tables are hundreds of GB in size; this demo simulates with a fixed 10-entry dictionary in the rainbow_table_sim table.",
    descriptionJa:
      "これは CWE-916 / CAPEC-55 の概念実証です。SHA-1 や MD5 でパスワードをソルトなし保存する旧来のシステムは、事前計算済みレインボーテーブルで <1ms で平文を復元されます。堅牢実装は bcrypt (cost=12) をユニークソルトと共に使用し、ソルトごとに別途事前計算が必要なためレインボーテーブルを実質無効化、2^12 回反復によりブルートフォースも実用不能にします。注: 実環境のレインボーテーブルは数百 GB のデータベースですが、本デモは rainbow_table_sim テーブルに 10 件の固定辞書を seed したシミュレーションです。",
    mitigation:
      "Hash passwords with bcrypt (saltRounds ≥ 12 in production), Argon2id (OWASP first-choice), or scrypt — never SHA-1, MD5, or even SHA-256 alone. bcrypt and Argon2id automatically generate per-record random salts and apply a deliberate computational cost. Migrate legacy unsalted hashes by re-hashing on next successful login. Set Argon2id parameters per OWASP Password Storage Cheat Sheet: memoryCost=64MB, timeCost=3, parallelism=4. Monitor for credential stuffing attacks indicating leaked DB usage.",
    mitigationJa:
      "パスワードのハッシュには bcrypt (本番は saltRounds ≥ 12)、Argon2id (OWASP 第一推奨)、または scrypt を使用してください — SHA-1 / MD5 / 単独の SHA-256 は使用禁止です。bcrypt と Argon2id はレコードごとにランダムソルトを自動生成し、意図的な計算コストを適用します。レガシーなソルトなしハッシュは次回ログイン成功時に再ハッシュ化して移行してください。Argon2id パラメータは OWASP Password Storage Cheat Sheet に従い memoryCost=64MB / timeCost=3 / parallelism=4 を設定してください。漏洩 DB 流通の指標として credential stuffing 攻撃を監視してください。",
    references: [
      "https://cwe.mitre.org/data/definitions/916.html",
      "https://capec.mitre.org/data/definitions/55.html",
      "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
      "https://datatracker.ietf.org/doc/html/rfc9106",
    ],
    codeHints: [
      {
        lang: "typescript",
        label: "Vulnerable: unsalted SHA-1 (do not use)",
        code: `// 脆弱: ソルトなし SHA-1 — レインボーテーブルで <1ms で逆引きされる
import crypto from "crypto";

function vulnerableHash(password: string): string {
  return crypto.createHash("sha1").update(password).digest("hex");
  // ↑ 同じ password に対して常に同じハッシュ
  // → 攻撃者は事前計算済みハッシュ→平文の対応表 (レインボーテーブル) を使用可能
}`,
      },
      {
        lang: "typescript",
        label: "Defended: bcrypt with cost=12 (current implementation)",
        code: `// 安全: bcrypt はソルト + 計算コストでレインボーテーブルを無効化
import bcrypt from "bcryptjs";

const SALT_ROUNDS = 12; // 本番は 12 以上推奨 (cost=10 は CPU 性能向上で弱体化)

async function safeHash(password: string): Promise<string> {
  // bcrypt は内部で 16 バイトのランダムソルトを生成し、
  // Blowfish key schedule を 2^12 = 4096 回反復する
  return bcrypt.hash(password, SALT_ROUNDS);
}

// 各呼び出しで異なるハッシュが返る (ソルトが毎回ランダム)
// $2a$12$<22 文字 base64 ソルト><31 文字 base64 ハッシュ>
const h1 = await safeHash("password123"); // → $2a$12$AbC...xyz
const h2 = await safeHash("password123"); // → $2a$12$DeF...uvw (異なる)`,
      },
      {
        lang: "typescript",
        label: "Even better: Argon2id (OWASP first-choice)",
        code: `// より推奨: Argon2id (OWASP Password Storage Cheat Sheet 第一推奨)
import argon2 from "argon2"; // npm install argon2

async function bestHash(password: string): Promise<string> {
  return argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 65536,  // 64MB - GPU 攻撃対策のメモリハード性
    timeCost: 3,        // 3 回反復
    parallelism: 4,     // 4 スレッド並列
  });
}`,
      },
    ],
    existingFileLinks: [
      {
        path: "server/routes/password-auth.ts",
        description:
          "POST /api/auth/password/register — bcrypt.genSalt(10) + bcrypt.hash でパスワードをハッシュ化する正常系 (cost=10、本番では 12 推奨)",
      },
      {
        path: "server/routes/password-auth.ts",
        description:
          "POST /api/auth/password/attack/rainbow-vs-bcrypt — SHA-1/MD5/bcrypt の両モード並列実行デモ",
      },
      {
        path: "server/db/schema.ts",
        description:
          "rainbow_table_sim テーブル定義 — 教育用固定辞書 (10 件、SHA-1/MD5 ハッシュ→平文の対応表シード)",
      },
    ],
    modes: [
      {
        id: "unsalted-fast-hash",
        labelJa: "ソルトなし SHA-1/MD5 (脆弱)",
        label: "Unsalted SHA-1/MD5 (vulnerable)",
        kind: "vulnerable",
      },
      {
        id: "bcrypt-salt-cost",
        labelJa: "bcrypt (cost=12 + ソルト) (防御)",
        label: "bcrypt (cost=12 + salt) (defended)",
        kind: "defensive",
      },
    ],
  },
  {
    id: "password-timing-string-compare",
    tabId: "auth-methods",
    name: "Timing Attack via Short-Circuit String Comparison",
    nameJa: "タイミング攻撃 (短絡評価文字列比較)",
    category: "A2:Cryptographic Failures",
    cweId: "CWE-208",
    capecId: "CAPEC-462",
    difficulty: 4,
    osiLayer: 7,
    severity: "medium",
    description:
      "This is a proof-of-concept for CWE-208 / CAPEC-462. The `===` operator and similar comparisons short-circuit at the first mismatching character — response time grows roughly linearly with the matched-prefix length. An attacker measuring response times can recover the password one character at a time (95 candidates per position for printable ASCII). The defended implementation uses crypto.timingSafeEqual (or bcrypt.compare, which uses constant-time internally), eliminating the timing side-channel. Note: the response times in this demo are exaggerated simulation values; real-world timing attacks operate at microsecond scale and require statistical aggregation over thousands of requests per character.",
    descriptionJa:
      "これは CWE-208 / CAPEC-462 の概念実証です。`===` 演算子等による短絡評価比較は、最初に不一致な文字で即座に `false` を返すため、応答時間が一致プレフィックス長にほぼ比例して増加します。応答時間を計測する攻撃者は、各文字位置で 95 候補 (印字可能 ASCII) を試行し、最も応答時間の長いものを正解として 1 文字ずつパスワードを復元できます。堅牢実装は crypto.timingSafeEqual (または内部で定数時間比較を使用する bcrypt.compare) を使用し、タイミングサイドチャネルを排除します。注: 本デモの応答時間値はミリ秒オーダーまで誇張したシミュレーション値で、実環境での攻撃はマイクロ秒オーダーで動作し、文字位置あたり数千回の繰り返しを統計的に集約する必要があります。",
    mitigation:
      "Always use constant-time comparison for credential validation: crypto.timingSafeEqual in Node.js, hmac.compare_digest in Python, MessageDigest.isEqual in Java. bcrypt.compare and similar password-verification APIs use constant-time internally — prefer them over manual comparison. When timingSafeEqual requires equal-length buffers, pad to a fixed maximum length first to avoid leaking length. Add network-level rate limiting and per-request response-time normalization (random delay) for defense-in-depth.",
    mitigationJa:
      "認証情報の比較には必ず定数時間比較関数を使用してください: Node.js の crypto.timingSafeEqual、Python の hmac.compare_digest、Java の MessageDigest.isEqual。bcrypt.compare 等のパスワード検証 API は内部で定数時間比較を使用するため、手動比較より優先してください。timingSafeEqual は等長バッファを要求するため、長さの異なる入力は固定最大長にパディングしてから渡してください (長さ自体のリークを防ぐため)。ネットワークレベルのレート制限とリクエストごとの応答時間正規化 (ランダム遅延) を併用すれば多層防御になります。",
    references: [
      "https://cwe.mitre.org/data/definitions/208.html",
      "https://capec.mitre.org/data/definitions/462.html",
      "https://nodejs.org/api/crypto.html#cryptotimingsafeequala-b",
      "https://owasp.org/www-project-application-security-verification-standard/",
    ],
    codeHints: [
      {
        lang: "typescript",
        label: "Vulnerable: short-circuit comparison (do not use)",
        code: `// 脆弱: === は短絡評価で応答時間にプレフィックス一致長を漏洩する
function vulnerableCompare(input: string, expected: string): boolean {
  return input === expected;
  // ↑ 不一致な最初の文字で即 return → 応答時間が情報を漏らす
}

// 同じく脆弱: ループによる手動比較
function vulnerableLoop(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false; // ← 短絡評価
  }
  return true;
}`,
      },
      {
        lang: "typescript",
        label: "Defended: crypto.timingSafeEqual + length padding",
        code: `// 安全: crypto.timingSafeEqual は常に全バイトを XOR-加算で比較
import crypto from "crypto";

function timingSafeStringEqual(a: string, b: string): boolean {
  // 等長要件: 最大長にパディングしてから比較 (長さ自体のリークも防止)
  const maxLen = Math.max(a.length, b.length, 256);
  const bufA = Buffer.alloc(maxLen);
  const bufB = Buffer.alloc(maxLen);
  Buffer.from(a).copy(bufA);
  Buffer.from(b).copy(bufB);
  // 全バイト比較 (応答時間が一致文字数に依存しない)
  const equal = crypto.timingSafeEqual(bufA, bufB);
  // 長さチェックは別途 (timingSafeEqual の結果と AND する)
  return equal && a.length === b.length;
}

// パスワード検証は bcrypt.compare を使用 (内部で定数時間比較)
import bcrypt from "bcryptjs";
const valid = await bcrypt.compare(plaintext, storedBcryptHash); // ← 安全`,
      },
    ],
    existingFileLinks: [
      {
        path: "server/routes/password-auth.ts",
        description:
          "POST /api/auth/password/login — bcrypt.compare で内部定数時間比較を使用する正常系 (タイミング攻撃に既に耐性)",
      },
      {
        path: "server/routes/password-auth.ts",
        description:
          "POST /api/auth/password/attack/timing-string-compare — 短絡評価 vs timingSafeEqual の両モード並列実行デモ",
      },
    ],
    modes: [
      {
        id: "short-circuit-compare",
        labelJa: "短絡評価 === 比較 (脆弱)",
        label: "Short-circuit === comparison (vulnerable)",
        kind: "vulnerable",
      },
      {
        id: "timing-safe-equal",
        labelJa: "crypto.timingSafeEqual (防御)",
        label: "crypto.timingSafeEqual (defended)",
        kind: "defensive",
      },
    ],
  },
  {
    id: "password-bruteforce-no-rate-limit",
    tabId: "auth-methods",
    name: "Brute Force Without Rate Limiting",
    nameJa: "レート制限なしブルートフォース",
    category: "A7:Identification and Authentication Failures",
    cweId: "CWE-307",
    capecId: "CAPEC-112",
    difficulty: 2,
    osiLayer: 7,
    severity: "high",
    description:
      "This is a proof-of-concept for CWE-307 / CAPEC-112. A login endpoint that does not throttle failed attempts allows an attacker to iterate weak-password dictionaries until a match is found — bcrypt's per-call cost (~50-500ms) slows but does not stop the attack. The defended implementation enforces a sliding-window rate limit (5 failures per minute per IP) plus account-level lockout, returning 429 Too Many Requests on threshold breach. Note: this demo runs the dictionary loop server-side as a single API call — it does not actually fire 20 separate login requests from the browser, which would itself be the attack pattern we are studying.",
    descriptionJa:
      "これは CWE-307 / CAPEC-112 の概念実証です。失敗試行を制限しないログインエンドポイントは、攻撃者が弱パスワード辞書を順次試行することで一致を発見されるまで耐えられません — bcrypt の呼び出しコスト (約 50-500ms/回) は試行を遅らせますが停止はしません。堅牢実装は IP ごとのスライディングウィンドウレート制限 (5 失敗/分) とアカウント単位のロックアウトを併用し、閾値超過で 429 Too Many Requests を返します。注: 本デモは辞書ループをサーバー側で 1 API 呼び出し内で実行しており、ブラウザから実際に 20 件のログインリクエストを発射しているわけではありません (それ自体が研究対象の攻撃パターンになるため)。",
    mitigation:
      "Implement IP-based sliding-window rate limiting (e.g., 5 failures/minute per IP) with 429 Too Many Requests responses (OWASP ASVS V2.2). Add account-level lockout (10 failures within 15 minutes → 15-min lock) for distributed-attack defense-in-depth. Unify error messages — return 'Invalid credentials' for both 'user not found' and 'wrong password' to prevent username enumeration. Add CAPTCHA after 3 failures for high-value accounts. Monitor for credential stuffing patterns (single password tried across many usernames). Consider WebAuthn/passkeys for high-value accounts (eliminates passwords entirely).",
    mitigationJa:
      "IP ごとのスライディングウィンドウレート制限 (例: 5 失敗/分) を実装し、429 Too Many Requests で応答してください (OWASP ASVS V2.2)。アカウント単位のロックアウト (15 分以内に 10 失敗 → 15 分ロック) を併用すれば分散攻撃にも耐えます。エラーメッセージを統一 — 'ユーザーが見つかりません' と 'パスワード不正' を 'Invalid credentials' (認証情報が無効) に統一してユーザー列挙を防いでください。重要アカウントには 3 回失敗後の CAPTCHA を追加してください。credential stuffing パターン (1 つのパスワードを多数のユーザー名で試行) を監視してください。重要アカウントには WebAuthn/passkey の採用を検討してください (パスワードを完全に排除)。",
    references: [
      "https://cwe.mitre.org/data/definitions/307.html",
      "https://capec.mitre.org/data/definitions/112.html",
      "https://owasp.org/www-project-application-security-verification-standard/",
      "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
    ],
    codeHints: [
      {
        lang: "typescript",
        label: "Vulnerable: no rate limiting (current /login)",
        code: `// 脆弱: 失敗回数の制限なし — 攻撃者は無制限に辞書攻撃可能
app.post("/api/auth/password/login", async (c) => {
  const { username, password } = await c.req.json();
  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
  if (!user) {
    // ↓ ユーザー列挙: 'User not found' で「このユーザーは存在する」と分かる
    return c.json({ error: "User not found" }, 401);
  }
  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) {
    return c.json({ error: "Invalid password" }, 401);
    // ↑ 別のメッセージで「パスワードだけが間違っている」と分かる → 列挙加担
  }
  return c.json({ success: true });
  // ↑ 失敗カウンターを増やさない / レート制限なし / アカウントロック なし
});`,
      },
      {
        lang: "typescript",
        label: "Defended: rate limit + lockout + unified error message",
        code: `// 安全: 多層防御 — レート制限 + ロックアウト + エラーメッセージ統一
import { rateLimiter } from "hono-rate-limiter"; // または自前実装

const loginLimiter = rateLimiter({
  windowMs: 60 * 1000,  // 1 分
  limit: 5,              // 5 失敗で 429
  keyGenerator: (c) => c.req.header("x-forwarded-for") ?? "unknown",
});

app.post("/api/auth/password/login", loginLimiter, async (c) => {
  const { username, password } = await c.req.json();
  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);

  // ユーザー列挙対策: 統一エラーメッセージ
  const UNIFIED_ERROR = { error: "Invalid credentials" };
  if (!user) return c.json(UNIFIED_ERROR, 401);

  // アカウントロックアウト
  if (user.locked_until && new Date(user.locked_until) > new Date()) {
    return c.json({ error: "Account temporarily locked" }, 423);
  }

  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) {
    // 失敗回数を増やしてロックアウト判定
    db.prepare(\`UPDATE users SET login_attempts = login_attempts + 1 WHERE id = ?\`).run(user.id);
    if (user.login_attempts + 1 >= 10) {
      const lockUntil = new Date(Date.now() + 15 * 60 * 1000).toISOString();
      db.prepare(\`UPDATE users SET locked_until = ? WHERE id = ?\`).run(lockUntil, user.id);
    }
    return c.json(UNIFIED_ERROR, 401);
  }

  // 成功時はカウンターリセット
  db.prepare(\`UPDATE users SET login_attempts = 0, locked_until = NULL WHERE id = ?\`).run(user.id);
  return c.json({ success: true });
});`,
      },
    ],
    existingFileLinks: [
      {
        path: "server/routes/password-auth.ts",
        description:
          "POST /api/auth/password/login — 現状はレート制限なし、エラーメッセージも 'User not found' / 'Invalid password' で分離 (シナリオ C の脆弱モード対象)",
      },
      {
        path: "server/routes/password-auth.ts",
        description:
          "POST /api/auth/password/attack/bruteforce-no-rate-limit — レート制限あり/なしの両モード並列実行デモ",
      },
    ],
    modes: [
      {
        id: "no-rate-limit",
        labelJa: "レート制限なし (脆弱)",
        label: "No rate limit (vulnerable)",
        kind: "vulnerable",
      },
      {
        id: "rate-limit-with-lockout",
        labelJa: "レート制限 + アカウントロックアウト (防御)",
        label: "Rate limit + account lockout (defended)",
        kind: "defensive",
      },
    ],
  },
];
