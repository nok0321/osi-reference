import type { AttackScenarioMeta } from "../../../../../shared/api-types";

export const fido2Scenarios: AttackScenarioMeta[] = [
  {
    id: "fido2-phishing-origin-rejection",
    tabId: "fido2",
    name: "Phishing: Blocked by Origin Validation",
    nameJa: "フィッシング: origin 検証による失敗",
    category: "A2:Broken Authentication",
    cweId: "CWE-290",
    capecId: "CAPEC-89",
    difficulty: 3,
    osiLayer: 7,
    severity: "info",
    description:
      "This is a proof-of-concept for CWE-290 / CWE-346 / CAPEC-89 / CAPEC-194. An attacker hosts a phishing page on attacker.example that mimics the legitimate site. When the victim's authenticator signs the WebAuthn challenge, the clientDataJSON.origin field records attacker.example. The vulnerable server (omitting expectedOrigin check) accepts the assertion; the defended server's strict origin comparison blocks the relay attempt. Learning goal: understand why FIDO2 is structurally resistant to phishing.",
    descriptionJa:
      "これは CWE-290 / CWE-346 / CAPEC-89 / CAPEC-194 の概念実証です。攻撃者が attacker.example で正規サイトに似たフィッシングページを公開し、被害者の Authenticator が WebAuthn チャレンジに署名します。clientDataJSON.origin には attacker.example が記録されます。脆弱版 (expectedOrigin チェック省略) は assertion を受理しますが、堅牢版は厳密一致比較で中継試行を拒否します。学習目的: FIDO2 が構造的にフィッシング耐性を持つ理由を理解する。",
    mitigation:
      "Always pass expectedOrigin (and expectedRPID) to verifyAuthenticationResponse / verifyRegistrationResponse. @simplewebauthn/server performs strict string-equality comparison on clientDataJSON.origin and throws on mismatch. Never skip these checks even when supporting multiple origins (use an allowlist instead).",
    mitigationJa:
      "verifyAuthenticationResponse / verifyRegistrationResponse には必ず expectedOrigin (および expectedRPID) を渡してください。@simplewebauthn/server は clientDataJSON.origin を厳密文字列比較し、不一致なら例外をスローします。複数 origin をサポートする場合でもチェックを省略せず、許可リスト方式を使用してください。",
    references: [
      "https://cwe.mitre.org/data/definitions/290.html",
      "https://cwe.mitre.org/data/definitions/346.html",
      "https://capec.mitre.org/data/definitions/89.html",
      "https://capec.mitre.org/data/definitions/194.html",
      "https://www.w3.org/TR/webauthn-2/#sctn-validating-origin",
      "https://simplewebauthn.dev/docs/packages/server",
    ],
    codeHints: [
      {
        lang: "typescript",
        label: "Vulnerable: expectedOrigin check skipped (do not use)",
        code: `// 脆弱な実装: expectedOrigin を渡さない/検証しない
const verification = await verifyAuthenticationResponse({
  response: authResponse,
  expectedChallenge: stored.challenge,
  // expectedOrigin: "http://localhost:3000",  // ← 省略すると検証されない
  // expectedRPID: "localhost",
  credential: { ... },
});
// attacker.example で署名された clientDataJSON も受理してしまう`,
      },
      {
        lang: "typescript",
        label: "Defended: expectedOrigin strict-equality (webauthn.ts pattern)",
        code: `// 安全な実装: @simplewebauthn/server による厳密 origin 検証 (webauthn.ts の実装)
const verification = await verifyAuthenticationResponse({
  response: authResponse,
  expectedChallenge: stored.challenge,
  expectedOrigin: "http://localhost:3000",   // ← 厳密一致検証
  expectedRPID: "localhost",                 // ← rpId 不一致も拒否
  credential: {
    id: cred.credential_id,
    publicKey: Buffer.from(cred.public_key, "base64"),
    counter: cred.counter,
  },
});
// origin 不一致 → throws Error → 上位 catch で 400 Bad Request`,
      },
    ],
    existingFileLinks: [
      {
        path: "server/routes/webauthn.ts",
        description:
          "POST /api/webauthn/auth/verify — expectedOrigin / expectedRPID を厳密検証する堅牢実装 (参照実装)",
      },
      {
        path: "server/routes/webauthn.ts",
        description:
          "POST /api/webauthn/attack/phishing-origin — origin 偽装による attack の両モード並列実行デモ",
      },
    ],
    modes: [
      {
        id: "no-origin-check",
        labelJa: "expectedOrigin 検証なし (脆弱)",
        label: "Without origin validation (vulnerable)",
        kind: "vulnerable",
      },
      {
        id: "with-origin-check",
        labelJa: "expectedOrigin 厳密一致 (防御)",
        label: "With strict origin check (defended)",
        kind: "defensive",
      },
    ],
  },
  {
    id: "fido2-vs-password-phishing",
    tabId: "fido2",
    name: "Side-by-Side: Password vs FIDO2 Phishing Resistance",
    nameJa: "並列比較: パスワード vs FIDO2 フィッシング耐性",
    category: "A2:Broken Authentication",
    cweId: "CWE-290",
    capecId: "CAPEC-89",
    difficulty: 2,
    osiLayer: 7,
    severity: "high",
    description:
      "This is a proof-of-concept for CWE-290 / CAPEC-89 contrasting password and FIDO2 authentication. The same phishing scenario is run against both: the attacker captures the password and replays it (password authentication has no origin signal — phishing succeeds), while FIDO2's origin-bound signature cannot be replayed against the legitimate server. Demonstrates why FIDO2 is recommended for high-value accounts.",
    descriptionJa:
      "これは CWE-290 / CAPEC-89 の概念実証で、パスワード認証と FIDO2 認証を対比します。同じフィッシングシナリオを両方に対して実行します: 攻撃者がパスワードを傍受してリプレイすると認証が成立しますが (パスワード認証には origin 信号がない)、FIDO2 の origin バインド署名は正規サーバーに対して再利用できません。FIDO2 が高価値アカウントで推奨される理由を実証します。",
    mitigation:
      "Migrate high-value accounts (admin, finance, executive) to FIDO2/WebAuthn or passkeys. If passwords must remain, combine with phishing-resistant MFA (WebAuthn second factor) and short-session timeouts. Implement Content-Security-Policy and Strict-Transport-Security to reduce phishing surface area.",
    mitigationJa:
      "高価値アカウント (管理者・経理・役員) は FIDO2/WebAuthn またはパスキーに移行してください。パスワードを維持する場合は、フィッシング耐性 MFA (WebAuthn セカンドファクター) と短いセッションタイムアウトを組み合わせてください。Content-Security-Policy / Strict-Transport-Security ヘッダでフィッシング攻撃面を減らすことも有効です。",
    references: [
      "https://cwe.mitre.org/data/definitions/290.html",
      "https://capec.mitre.org/data/definitions/89.html",
      "https://www.w3.org/TR/webauthn-2/#sctn-phishing",
      "https://fidoalliance.org/why-fido/",
      "https://owasp.org/www-community/attacks/Phishing",
    ],
    codeHints: [
      {
        lang: "typescript",
        label: "Vulnerable (password): no origin signal — phishing relay succeeds",
        code: `// パスワード認証では origin 検証がない (脆弱な実装)
app.post("/login", async (c) => {
  const { username, password } = await c.req.json();
  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
  const valid = await bcrypt.compare(password, user.password_hash);
  // ← フィッシングサイトが中継しても valid === true になる
  return c.json({ success: valid });
});
// 攻撃者がフィッシングページで取得したパスワードをそのまま正規 /login に送信できる`,
      },
      {
        lang: "typescript",
        label: "Defended (FIDO2): origin cryptographically bound (webauthn.ts pattern)",
        code: `// FIDO2 では origin が暗号的に検証される (webauthn.ts の実装)
await verifyAuthenticationResponse({
  response: authResponse,
  expectedOrigin: "http://localhost:3000",  // ← 一致しない場合は例外
  expectedRPID: "localhost",
  credential: { ... },
});
// 攻撃者が assertion を傍受しても、署名は attacker.example origin に紐付いており
// 正規サーバーで使用できない (暗号的にリプレイ不可)`,
      },
    ],
    existingFileLinks: [
      {
        path: "server/routes/session-auth.ts",
        description:
          "POST /api/session/login — bcrypt.compare のみ (origin 検証なし) のパスワード認証",
      },
      {
        path: "server/routes/webauthn.ts",
        description:
          "POST /api/webauthn/auth/verify — expectedOrigin で origin バインドする FIDO2 認証",
      },
      {
        path: "server/routes/webauthn.ts",
        description:
          "POST /api/webauthn/attack/vs-password-phishing — パスワード/FIDO2 両モード並列比較デモ",
      },
    ],
    modes: [
      {
        id: "password-side",
        labelJa: "パスワード側 (脆弱: フィッシング成立)",
        label: "Password side (vulnerable: phishing succeeds)",
        kind: "vulnerable",
      },
      {
        id: "fido2-side",
        labelJa: "FIDO2 側 (防御: origin バインドで阻止)",
        label: "FIDO2 side (defended: origin-bound block)",
        kind: "defensive",
      },
    ],
  },
  {
    id: "fido2-challenge-replay",
    tabId: "fido2",
    name: "Challenge Replay: Blocked by One-Time Design",
    nameJa: "チャレンジリプレイ: 使い捨て設計による阻止",
    category: "A2:Broken Authentication",
    cweId: "CWE-294",
    capecId: "CAPEC-60",
    difficulty: 3,
    osiLayer: 7,
    severity: "info",
    description:
      "This is a proof-of-concept for CWE-294 / CAPEC-60. An attacker captures a victim's WebAuthn registration attestationObject and replays it against the server. The vulnerable server (omitting challenges.delete after verification) accepts the replay; the defended implementation calls challenges.delete(sessionId) immediately on first use, blocking any replay. Demonstrates the one-time challenge design that complements FIDO2's cryptographic challenge binding.",
    descriptionJa:
      "これは CWE-294 / CAPEC-60 の概念実証です。攻撃者が被害者の WebAuthn 登録 attestationObject を傍受し、サーバーへ再送します。脆弱版 (検証後の challenges.delete を省略) は再送を受理しますが、堅牢版は challenges.delete(sessionId) を初回使用時に即実行してリプレイを阻止します。FIDO2 の暗号的チャレンジバインドを補完する『使い捨てチャレンジ設計』を実証します。",
    mitigation:
      "Always call challenges.delete(sessionId) (or equivalent) immediately after a successful verifyRegistrationResponse / verifyAuthenticationResponse. Use a TTL store with short expiry (5 minutes recommended) so even forgotten deletions auto-expire. For distributed deployments, store challenges in a TTL-aware backend (Redis with EXPIRE).",
    mitigationJa:
      "verifyRegistrationResponse / verifyAuthenticationResponse 成功直後に必ず challenges.delete(sessionId) (または同等の操作) を呼んでください。短い TTL (5 分推奨) のストアを使用すれば、削除を忘れても自動失効します。分散デプロイメントでは TTL 対応バックエンド (EXPIRE 付き Redis 等) を使用してください。",
    references: [
      "https://cwe.mitre.org/data/definitions/294.html",
      "https://capec.mitre.org/data/definitions/60.html",
      "https://www.w3.org/TR/webauthn-2/#sctn-cryptographic-challenges",
      "https://simplewebauthn.dev/docs/packages/server#registration",
      "https://owasp.org/www-community/attacks/Replay_Attack",
    ],
    codeHints: [
      {
        lang: "typescript",
        label: "Vulnerable: challenges not deleted after verification (do not use)",
        code: `// 脆弱な実装: challenges.delete を省略
const stored = challenges.get(sessionId);
if (!stored || stored.username !== username) {
  return c.json({ error: "No challenge found" }, 400);
}

const verification = await verifyRegistrationResponse({ ... });
if (verification.verified) {
  db.prepare("INSERT INTO webauthn_credentials ...").run(...);
  // challenges.delete(sessionId);  // ← 省略すると同じ attestation で再登録できてしまう
  return c.json({ success: true });
}`,
      },
      {
        lang: "typescript",
        label: "Defended: one-time challenge consumption (webauthn.ts pattern)",
        code: `// 安全な実装: 検証成功後に即削除 (webauthn.ts の実装)
const stored = challenges.get(sessionId);
if (!stored || stored.username !== username) {
  return c.json({ success: false, error: "No challenge found or challenge expired" }, 400);
}

const verification = await verifyRegistrationResponse({ ... });
if (verification.verified && verification.registrationInfo) {
  db.prepare("INSERT INTO webauthn_credentials ...").run(...);
  challenges.delete(sessionId);  // ← この1行がリプレイ攻撃を阻止する
  return c.json({ success: true, data: { verified: true } });
}`,
      },
    ],
    existingFileLinks: [
      {
        path: "server/routes/webauthn.ts",
        description:
          "POST /api/webauthn/register/verify — challenges.delete(sessionId) を実行する堅牢実装",
      },
      {
        path: "server/utils/ttl-store.ts",
        description:
          "createTtlStore — TTL 5 分の使い捨てチャレンジ管理 (challenges ストアの実装)",
      },
      {
        path: "server/routes/webauthn.ts",
        description:
          "POST /api/webauthn/attack/challenge-replay — チャレンジ再送に対する両モード並列実行デモ",
      },
    ],
    modes: [
      {
        id: "challenge-not-deleted",
        labelJa: "challenges.delete 省略 (脆弱)",
        label: "Without challenges.delete (vulnerable)",
        kind: "vulnerable",
      },
      {
        id: "challenge-one-time",
        labelJa: "challenges.delete 即時実行 (防御)",
        label: "With challenges.delete (defended)",
        kind: "defensive",
      },
    ],
  },
];
