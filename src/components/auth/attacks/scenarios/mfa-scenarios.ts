import type { AttackScenarioMeta } from "../../../../../shared/api-types";

export const mfaScenarios: AttackScenarioMeta[] = [
  {
    id: "mfa-otp-replay",
    tabId: "mfa",
    name: "TOTP OTP Replay Attack",
    nameJa: "TOTP OTP リプレイ攻撃",
    category: "A7:Identification and Authentication Failures",
    cweId: "CWE-294",
    capecId: "CAPEC-60",
    difficulty: 3,
    osiLayer: 7,
    severity: "medium",
    description:
      "This is a proof-of-concept for CWE-294 / CAPEC-60. TOTP (RFC 6238) is designed as a one-time password — codes should be valid for only one successful authentication. However, when the server does not record consumed OTPs, an attacker who observes a code (via shoulder-surfing, phishing relay, or screen recording) can replay the same code within the valid window (up to 90 seconds with ±1 step tolerance). The defended implementation maintains a (userId, counter) record of consumed OTPs (in-memory Set or used_otps DB table) and rejects any subsequent use of the same counter — RFC 6238 §5.2 explicitly assigns replay defense to the implementer. Note: real attackers must observe and replay within the valid window — TOTP itself does not auto-renew, so a longer wait simply expires the code naturally; the threat is the explicit replay-within-window window.",
    descriptionJa:
      "これは CWE-294 / CAPEC-60 の概念実証です。TOTP (RFC 6238) は本来「1回限りのパスワード」として設計されており、コードは1回の認証成功でのみ有効であるべきです。しかしサーバーが使用済み OTP を記録していない場合、ショルダーサーフィン、フィッシングサイトへのリアルタイム中継、画面録画等で観測した OTP を有効期間内 (±1 窓では最大 90 秒) に再送した攻撃者は、同一コードで再度認証に成功してしまいます。堅牢実装は (userId, counter) の組を使用済みとして記録 (in-memory Set または used_otps テーブル) し、同一 counter の再使用を拒否します — RFC 6238 §5.2 はリプレイ対策を実装者の責任と明示しています。注: 実環境の攻撃者は有効期間内に観測・再送する必要があり、長く待てばコードは自然に期限切れとなります。脅威は「有効期間内のリプレイ」に限定されます。",
    mitigation:
      "Record the (userId, counter) pair of every successfully verified TOTP in a used_otps table (or in-memory Set with TTL). On subsequent verification, reject any code whose (userId, counter) is already present. Set the TTL to (window * 2 + 1) * TOTP_PERIOD seconds — for ±1 window this is 90 seconds. Combine with: (1) device-binding for high-value accounts via FIDO2/WebAuthn, (2) anomaly detection on rapid back-to-back logins, (3) client-side challenge nonces for endpoints where TOTP alone is the only factor. Note that TOTP replay defense alone does NOT defeat real-time phishing relays — those require origin-bound credentials (FIDO2).",
    mitigationJa:
      "TOTP の検証成功時に (userId, counter) のペアを used_otps テーブル (または TTL 付き in-memory Set) に記録してください。次回以降の検証時、既存の (userId, counter) があればコードを拒否します。TTL は (window * 2 + 1) * TOTP_PERIOD 秒 — ±1 窓では 90 秒に設定してください。併用すべき対策: (1) 重要アカウントには FIDO2/WebAuthn でデバイスバインドを採用、(2) 連続ログインの異常検知、(3) TOTP 単独依存のエンドポイントにはクライアントチャレンジ nonce を導入。TOTP リプレイ対策単独ではリアルタイムフィッシング中継を防げない点に注意してください — それには origin バインドの認証情報 (FIDO2) が必要です。",
    references: [
      "https://cwe.mitre.org/data/definitions/294.html",
      "https://capec.mitre.org/data/definitions/60.html",
      "https://www.rfc-editor.org/rfc/rfc6238#section-5.2",
      "https://pages.nist.gov/800-63-3/sp800-63b.html",
    ],
    codeHints: [
      {
        lang: "typescript",
        label: "Vulnerable: no used-OTP tracking (current /totp/login/step2)",
        code: `// 脆弱: verifyTotpWithDetail() の一致のみで成功を返す
async function vulnerableLoginStep2(challengeId: string, code: string) {
  const challenge = loginChallenges.get(challengeId);
  if (!challenge) return { success: false, error: "challenge not found" };

  const { match } = verifyTotpWithDetail(secret, code);
  if (!match) return { success: false, error: "invalid code" };

  loginChallenges.delete(challengeId);
  return { success: true };
  // ↑ 同一コードを2回送ると2回目も「一致」して受理される
}`,
      },
      {
        lang: "sql",
        label: "Defended: used_otps DB table with UNIQUE constraint",
        code: `-- server/db/schema.ts への追加
CREATE TABLE IF NOT EXISTS used_otps (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL REFERENCES users(id),
  counter    INTEGER NOT NULL,
  used_at    TEXT DEFAULT (datetime('now')),
  UNIQUE(user_id, counter)
);

-- TTL クリーンアップ (定期実行 or pre-check で削除)
DELETE FROM used_otps
WHERE used_at < datetime('now', '-90 seconds');`,
      },
      {
        lang: "typescript",
        label: "Defended: server/routes/mfa-totp.ts step2 with used-OTP check",
        code: `// 安全: 検証成功後に (user_id, counter) を used_otps へ記録
async function defendedLoginStep2(challengeId: string, code: string) {
  const challenge = loginChallenges.get(challengeId);
  if (!challenge) return { success: false, error: "challenge not found" };

  const { match } = verifyTotpWithDetail(secret, code);
  if (!match) return { success: false, error: "invalid code" };

  // 使用済みチェック
  const existing = db
    .prepare("SELECT id FROM used_otps WHERE user_id = ? AND counter = ?")
    .get(challenge.userId, match.counter);
  if (existing) {
    return { success: false, error: "OTP already used. Wait for the next code." };
  }

  // 使用済みとして記録 (UNIQUE 制約で同時実行も安全)
  db.prepare("INSERT OR IGNORE INTO used_otps (user_id, counter) VALUES (?, ?)")
    .run(challenge.userId, match.counter);

  loginChallenges.delete(challengeId);
  return { success: true };
}`,
      },
    ],
    existingFileLinks: [
      {
        path: "server/routes/mfa-totp.ts",
        description:
          "POST /api/mfa/totp/login/step2 — 現状は使用済み OTP チェックなし (シナリオ A の脆弱モード対象、教材的に意図的に未実装)",
      },
      {
        path: "server/utils/totp.ts",
        description:
          "verifyTotpWithDetail — RFC 6238 HMAC-SHA1 検証コアロジック、±1 窓固定。使用済み記録は呼び出し側の責務",
      },
      {
        path: "server/routes/mfa-totp.ts",
        description:
          "POST /api/mfa/attack/otp-replay — 使用済み OTP 追跡なし vs in-memory Set による追跡の両モード並列実行デモ",
      },
    ],
    modes: [
      {
        id: "no-used-otp-tracking",
        labelJa: "使用済み OTP 記録なし (脆弱)",
        label: "No used-OTP tracking (vulnerable)",
        kind: "vulnerable",
      },
      {
        id: "used-otp-record-blocks-replay",
        labelJa: "使用済み OTP 記録によるリプレイ拒否 (防御)",
        label: "Used-OTP record blocks replay (defended)",
        kind: "defensive",
      },
    ],
  },
  {
    id: "mfa-time-window-too-wide",
    tabId: "mfa",
    name: "TOTP Time Window Too Wide",
    nameJa: "TOTP 時刻窓広すぎ攻撃",
    category: "A5:Security Misconfiguration",
    cweId: "CWE-208",
    capecId: "CAPEC-462",
    difficulty: 2,
    osiLayer: 7,
    severity: "medium",
    description:
      "This is a proof-of-concept for CWE-208 / CAPEC-462. TOTP servers normally allow a small ±1 step (±30s) tolerance to absorb clock drift between server and client. However, when the window is misconfigured to ±10 steps (±5 minutes) — sometimes done for 'user convenience' — attackers can replay an observed OTP for up to 5 minutes after observation. The demo shows a code observed at T+0s being replayed at T+90s: ±1 window correctly rejects the 90-second-old code, while ±10 window accepts it (90s = 3 steps, well within ±10). NIST SP 800-63B §5.1.4.2 mandates ±1 step maximum. RFC 6238 §5.2 explicitly recommends 'small' windows. Note: clock drift in production with NTP-synchronized servers is typically <1 second; ±1 step tolerance is more than sufficient.",
    descriptionJa:
      "これは CWE-208 / CAPEC-462 の概念実証です。TOTP サーバーは通常、サーバーとクライアントの時刻のずれ (クロックドリフト) を吸収するため ±1 ステップ (±30 秒) の許容ウィンドウを設けます。しかし設定ミスや「ユーザー利便性」のために ±10 ステップ (±5 分) 等に広げた実装では、攻撃者が観測した OTP を最大 5 分間使い回せてしまいます。本デモでは T+0s に観測したコードを T+90s に再送し、±1 窓では正しく拒否、±10 窓では受理 (90 秒 = 3 ステップ、±10 窓内) されることを並列比較します。NIST SP 800-63B §5.1.4.2 は ±1 ステップ最大を勧告し、RFC 6238 §5.2 も「小さなウィンドウ」を推奨しています。注: NTP 同期されたサーバーでのクロックドリフトは通常 1 秒未満で、±1 ステップ許容は過剰なほど十分です。",
    mitigation:
      "Set the TOTP verification window to ±1 step (±30s) — RFC 6238 §5.2 / NIST SP 800-63B §5.1.4.2 mandate this maximum. If environment-variable configuration is exposed, guard with `Math.min(Number(process.env.TOTP_WINDOW ?? 1), 2)` to prevent operators from accidentally widening it to ±5 or ±10. Combine with used-OTP tracking (Scenario A defense): even if the window is slightly wider, the same code cannot be replayed. Use NTP for server clock synchronization (clock drift is typically <1s). Document the security implication of widening the window in code comments and operational runbooks.",
    mitigationJa:
      "TOTP 検証ウィンドウは ±1 ステップ (±30 秒) に設定してください — RFC 6238 §5.2 / NIST SP 800-63B §5.1.4.2 がこの最大値を勧告しています。環境変数で設定可能にする場合は `Math.min(Number(process.env.TOTP_WINDOW ?? 1), 2)` でガードし、運用者が誤って ±5 や ±10 に広げないようにしてください。シナリオ A の防御 (使用済み OTP 記録) と併用すれば、ウィンドウが多少広くても同一コードのリプレイは阻止できます。サーバー時刻は NTP で同期させてください (クロックドリフトは通常 1 秒未満)。ウィンドウを広げる場合のセキュリティ影響をコードコメントや運用手順に明記してください。",
    references: [
      "https://cwe.mitre.org/data/definitions/208.html",
      "https://capec.mitre.org/data/definitions/462.html",
      "https://www.rfc-editor.org/rfc/rfc6238#section-5",
      "https://pages.nist.gov/800-63-3/sp800-63b.html#sec5",
    ],
    codeHints: [
      {
        lang: "typescript",
        label: "Vulnerable: ±10 wide window (do not use)",
        code: `// 脆弱: ±10 ステップ (±5 分) — 5 分間のリプレイ窓
function vulnerableVerify(secret: string, code: string): boolean {
  const key = base32Decode(secret);
  const counter = currentCounter();
  const window = 10;  // ←誤設定: ±5 分は過剰に広い
  for (let delta = -window; delta <= window; delta++) {
    if (timingSafeEqual(computeTotp(key, counter + delta), code)) {
      return true;
    }
  }
  return false;
}`,
      },
      {
        lang: "typescript",
        label: "Defended: ±1 narrow window with env-var upper bound",
        code: `// 安全: ±1 ステップ (±30 秒) + 環境変数の上限ガード
const TOTP_WINDOW_RAW = Number(process.env.TOTP_WINDOW ?? "1");
// 上限ガード — 環境変数で 10 等を指定しても ±2 以上にはならない
const TOTP_WINDOW = Math.min(Math.max(TOTP_WINDOW_RAW, 1), 2);

export function verifyTotpWithDetail(
  secret: string,
  code: string,
  window = TOTP_WINDOW,  // デフォルト ±1
): { match: TotpDetail | null; attempts: TotpDetail[] } {
  const base = currentCounter();
  // ... ±window 範囲のみ試行
  for (let i = -window; i <= window; i++) {
    // ... HMAC-SHA1 検証
  }
}`,
      },
      {
        lang: "typescript",
        label: "Defense-in-depth: combine with used-OTP tracking",
        code: `// 多層防御: 仮にウィンドウが多少広くても、使用済み記録が再利用を防ぐ
async function defendedVerify(secret: string, code: string, userId: number) {
  const { match } = verifyTotpWithDetail(secret, code, 1);  // ±1 窓
  if (!match) return { ok: false, reason: "code expired or invalid" };

  // 使用済みチェック (Scenario A の防御を併用)
  const existing = db
    .prepare("SELECT id FROM used_otps WHERE user_id = ? AND counter = ?")
    .get(userId, match.counter);
  if (existing) {
    return { ok: false, reason: "code already used" };
  }
  db.prepare("INSERT OR IGNORE INTO used_otps (user_id, counter) VALUES (?, ?)")
    .run(userId, match.counter);
  return { ok: true, counter: match.counter };
}`,
      },
    ],
    existingFileLinks: [
      {
        path: "server/utils/totp.ts",
        description:
          "verifyTotpWithDetail — 現状 window=1 (推奨設定済み)。本シナリオは ±10 設定の脆弱性を比較教材として再現",
      },
      {
        path: "server/routes/mfa-totp.ts",
        description:
          "POST /api/mfa/attack/time-window-wide — ±1 (推奨) と ±10 (脆弱) のウィンドウ幅両モード並列実行デモ",
      },
    ],
    modes: [
      {
        id: "wide-window-10-steps",
        labelJa: "±10 ステップ広い窓 (脆弱)",
        label: "±10 step wide window (vulnerable)",
        kind: "vulnerable",
      },
      {
        id: "narrow-window-1-step",
        labelJa: "±1 ステップ推奨窓 (防御)",
        label: "±1 step narrow window (defended)",
        kind: "defensive",
      },
    ],
  },
  {
    id: "mfa-sms-swap",
    tabId: "mfa",
    name: "SMS OTP SIM Swap (Educational Simulation)",
    nameJa: "SMS OTP SIM スワップ (教育用シミュレーション)",
    category: "A7:Identification and Authentication Failures",
    cweId: "CWE-308",
    capecId: "CAPEC-115",
    difficulty: 4,
    osiLayer: 7,
    severity: "high",
    description:
      "[EDUCATIONAL SIMULATION ONLY] This is a proof-of-concept for CWE-308 / CWE-294 / CAPEC-115. SMS OTP authentication binds the second factor to phone-number ownership rather than to a specific device. When an attacker performs a SIM swap (social engineering at a carrier to redirect the victim's phone number to an attacker-controlled SIM), all subsequent SMS OTPs are delivered to the attacker's device, enabling account takeover even when the victim still possesses their original phone. TOTP authenticator apps (RFC 6238) instead bind the secret to the device storing the app — SIM swap cannot transfer the secret because it never travels over the carrier network. NIST SP 800-63B §5.1.3 classifies SMS OTP as a 'restricted' authenticator with documented risks. **Important**: this demo simulates only the post-swap effect (SMS routing diverted to attacker). The actual SIM swap technique requires social engineering at a carrier and is NOT reproduced here. This scenario is for educational purposes to demonstrate why SMS OTP should be avoided in favor of TOTP, push, or FIDO2.",
    descriptionJa:
      "[教育用シミュレーション専用] これは CWE-308 / CWE-294 / CAPEC-115 の概念実証です。SMS OTP 認証は第2要素を「電話番号の所有権」に紐付けており、特定のデバイスに紐付いていません。攻撃者が SIM スワップ (キャリアへの Social Engineering で被害者の電話番号を攻撃者の SIM に転送させる手法) を実行すると、以降の SMS OTP はすべて攻撃者のデバイスに届き、被害者が元の電話を所持していてもアカウント乗っ取りが成立します。TOTP 認証アプリ (RFC 6238) はシークレットをアプリの保存先デバイスにバインドしており、シークレットがキャリアネットワークを通じて送信されることがないため SIM スワップでは転送できません。NIST SP 800-63B §5.1.3 は SMS OTP を「制限付き」認証器に分類し、リスクを明示しています。**重要**: 本デモは SIM スワップ後の影響 (SMS 転送先の変更) のみをシミュレートしています。実際の SIM スワップ手法 (キャリアへの Social Engineering) は再現していません。本シナリオは SMS OTP を避けて TOTP / Push / FIDO2 を採用すべき理由を示す教育目的のものです。",
    mitigation:
      "Avoid SMS OTP for any account where account-takeover impact is non-trivial (NIST SP 800-63B §5.1.3 classifies it as 'restricted'). Migrate to (in order of preference): (1) FIDO2/WebAuthn passkeys (origin-bound, phishing-resistant, device-bound), (2) Push-notification MFA via authenticated mobile app, (3) TOTP authenticator apps (device-bound shared secret, no carrier dependency). If SMS OTP must remain available as a fallback, mitigate with: (a) carrier-level SIM-lock PIN configuration prompts, (b) anomaly detection on logins from new geographic regions or devices, (c) short OTP TTL (≤5 minutes), (d) used-OTP tracking (Scenario A defense), (e) explicit user education about the risk. Combine with risk-based authentication to require step-up verification on suspicious sign-ins.",
    mitigationJa:
      "アカウント乗っ取りの影響が無視できないアカウントには SMS OTP の使用を避けてください (NIST SP 800-63B §5.1.3 で「制限付き」に分類されています)。次の優先順位で移行してください: (1) FIDO2/WebAuthn パスキー (origin バインド、フィッシング耐性、デバイスバインド)、(2) 認証済みモバイルアプリへの Push 通知 MFA、(3) TOTP 認証アプリ (デバイスバインドの共有シークレット、キャリア非依存)。SMS OTP をフォールバックとして残す場合の緩和策: (a) キャリアの SIM ロック PIN 設定をユーザーに促す、(b) 新しい地域・デバイスからのログイン異常検知、(c) 短い OTP TTL (5 分以内)、(d) 使用済み OTP 記録 (シナリオ A の防御)、(e) リスクの明示的なユーザー教育。リスクベース認証と組み合わせて、不審なサインインに段階的検証を要求してください。",
    references: [
      "https://cwe.mitre.org/data/definitions/308.html",
      "https://cwe.mitre.org/data/definitions/294.html",
      "https://capec.mitre.org/data/definitions/115.html",
      "https://pages.nist.gov/800-63-3/sp800-63b.html#oob",
    ],
    codeHints: [
      {
        lang: "typescript",
        label: "Vulnerable concept: SMS OTP only (phone-number-bound)",
        code: `// 脆弱概念: SMS OTP のみで MFA を構成すると、SIM スワップで突破される
async function smsOtpLogin(username: string, password: string, smsCode: string) {
  const user = await getUser(username);
  if (!await bcrypt.compare(password, user.password_hash)) {
    return { ok: false, reason: "invalid password" };
  }
  // SMS OTP 検証 — 電話番号宛に送信した OTP と一致するか
  // ↓ このパスは SIM スワップ後に攻撃者の電話で受信される
  const sent = await getRecentSmsOtp(user.phone_number);
  if (sent !== smsCode) return { ok: false, reason: "invalid SMS OTP" };

  // ↑ 第2要素が「電話番号の所有」に依存している
  return { ok: true, sessionId: createSession(user.id) };
}`,
      },
      {
        lang: "typescript",
        label: "Defended: TOTP authenticator app (device-bound secret)",
        code: `// 安全: TOTP は共有シークレットがアプリ内に保存され、SIM スワップで転送されない
async function totpLogin(username: string, password: string, totpCode: string) {
  const user = await getUser(username);
  if (!await bcrypt.compare(password, user.password_hash)) {
    return { ok: false, reason: "invalid password" };
  }
  // TOTP 検証 — シークレットはアプリ内のセキュアストレージに保存
  const mfa = db.prepare("SELECT secret FROM user_mfa WHERE user_id = ?").get(user.id);
  const { match } = verifyTotpWithDetail(mfa.secret, totpCode, 1);
  // ↑ シークレットは SIM スワップでは転送されない (キャリアネットワーク非依存)
  if (!match) return { ok: false, reason: "invalid TOTP code" };

  return { ok: true, sessionId: createSession(user.id) };
}`,
      },
      {
        lang: "typescript",
        label: "Best: FIDO2/WebAuthn passkey (origin-bound, phishing-resistant)",
        code: `// 最推奨: FIDO2/WebAuthn — origin バインド + デバイスバインドで多層耐性
import { verifyAuthenticationResponse } from "@simplewebauthn/server";

async function fido2Login(username: string, response: AuthResponse) {
  const user = await getUser(username);
  const credential = await getCredential(user.id, response.id);

  const verification = await verifyAuthenticationResponse({
    response,
    expectedChallenge: storedChallenge,
    expectedOrigin: "https://app.example.com",  // origin バインド
    expectedRPID: "app.example.com",
    authenticator: credential,
  });

  // ↑ 秘密鍵は認証器内に保存され、外部に出ない
  // ↑ origin が一致しないとフィッシングサイトでは検証が成立しない
  // ↑ SIM スワップでもフィッシングでも侵害不可能
  if (!verification.verified) return { ok: false };
  return { ok: true, sessionId: createSession(user.id) };
}`,
      },
    ],
    existingFileLinks: [
      {
        path: "server/routes/mfa-totp.ts",
        description:
          "TOTP ベースの MFA 実装 (デバイスバインドシークレット方式) — 本シナリオの「堅牢モード」相当の実装",
      },
      {
        path: "server/routes/webauthn.ts",
        description:
          "FIDO2/WebAuthn 実装 — SMS OTP / TOTP よりさらに強固な origin バインド方式",
      },
      {
        path: "server/routes/mfa-totp.ts",
        description:
          "POST /api/mfa/attack/sms-swap — SMS OTP (電話番号バインド) と TOTP (デバイスバインド) の両モード並列実行デモ。SIM スワップは教育的シミュレーションのみで、実手順は再現しない",
      },
    ],
    modes: [
      {
        id: "sms-otp-phone-bound",
        labelJa: "SMS OTP (電話番号バインド、SIM スワップ脆弱)",
        label: "SMS OTP (phone-number-bound, SIM-swap vulnerable)",
        kind: "vulnerable",
      },
      {
        id: "totp-device-bound",
        labelJa: "TOTP アプリ (デバイスバインドシークレット)",
        label: "TOTP app (device-bound secret)",
        kind: "defensive",
      },
    ],
  },
];
