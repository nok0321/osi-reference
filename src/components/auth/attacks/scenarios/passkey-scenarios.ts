import type { AttackScenarioMeta } from "../../../../../shared/api-types";

/**
 * Passkey 攻撃シナリオメタ (DESIGN/21-attack-passkey.md, Phase 2 第十二コミット)。
 *
 * このタブの教材的位置付け (DESIGN/21 §1.4):
 *   全シナリオで「攻撃が阻止されること」を示す。E-2 契約により outcome="succeeded"
 *   固定だが、AttackStep.status="blocked" で防御成立を表現。
 *   PasskeyFlow.tsx 上部の PASSKEY_SPECIAL_NOTE で「防御確認デモ」を強調する
 *   (FIDO2 の SEC-FIDO2-7 緩和策と同パターン)。
 */
export const passkeyScenarios: AttackScenarioMeta[] = [
  {
    id: "passkey-phishing-origin-binding",
    tabId: "passkey",
    name: "Phishing Resistance: Origin Binding (synced passkey unchanged)",
    nameJa: "フィッシング耐性: origin binding (同期パスキーでも有効)",
    category: "A2:Broken Authentication",
    cweId: "CWE-290",
    capecId: "CAPEC-89",
    difficulty: 3,
    osiLayer: 7,
    severity: "info",
    description:
      "This is a proof-of-concept for CWE-290 / CWE-346 / CAPEC-89 / CAPEC-194 in the Passkey context. An attacker hosts a phishing page that mimics the legitimate site. When the victim's authenticator signs the WebAuthn challenge, clientDataJSON.origin records attacker.example. The vulnerable server (omitting expectedOrigin) accepts the assertion; the defended server's strict comparison blocks it. Critical Passkey-specific learning: multiDevice (synced) and singleDevice (device-bound) passkeys behave identically for origin binding — synchronization does NOT weaken phishing resistance.",
    descriptionJa:
      "これは Passkey 文脈における CWE-290 / CWE-346 / CAPEC-89 / CAPEC-194 の概念実証です。攻撃者が正規サイトに似たフィッシングページを公開し、被害者の Authenticator が WebAuthn チャレンジに署名します。clientDataJSON.origin には attacker.example が記録されます。脆弱版 (expectedOrigin 省略) は assertion を受理しますが、堅牢版は厳密一致比較で阻止します。Passkey 固有の重要な学習目標: multiDevice (同期) と singleDevice (デバイス固有) のパスキーは origin バインディングに対して完全に同一の挙動を示します — 同期によってフィッシング耐性が失われることはありません。",
    mitigation:
      "Always pass expectedOrigin (and expectedRPID) to verifyAuthenticationResponse / verifyRegistrationResponse in passkey.ts. @simplewebauthn/server performs strict string-equality comparison and throws on mismatch. The same defense applies to both synced and device-bound credentials — credentialDeviceType does not affect the origin check. For multi-origin support, use an allowlist instead of skipping the check.",
    mitigationJa:
      "passkey.ts の verifyAuthenticationResponse / verifyRegistrationResponse には必ず expectedOrigin (および expectedRPID) を渡してください。@simplewebauthn/server は厳密文字列比較を行い、不一致なら例外をスローします。同じ防御は同期パスキーとデバイス固有パスキーの両方に適用されます — credentialDeviceType は origin チェックに影響しません。複数 origin をサポートする場合でもチェックを省略せず、許可リスト方式を使用してください。",
    references: [
      "https://cwe.mitre.org/data/definitions/290.html",
      "https://cwe.mitre.org/data/definitions/346.html",
      "https://capec.mitre.org/data/definitions/89.html",
      "https://capec.mitre.org/data/definitions/194.html",
      "https://www.w3.org/TR/webauthn-3/#sctn-validating-origin",
      "https://simplewebauthn.dev/docs/packages/server",
      "https://fidoalliance.org/passkeys/",
    ],
    codeHints: [
      {
        lang: "typescript",
        label: "Vulnerable: expectedOrigin check skipped (do not use)",
        code: `// 脆弱な実装: expectedOrigin を渡さない/検証しない
const verification = await verifyAuthenticationResponse({
  response: authResponse,
  expectedChallenge: stored,
  // expectedOrigin: "http://localhost:3000",  // ← 省略すると検証されない
  // expectedRPID: "localhost",
  credential: { ... },
});
// attacker.example で署名された clientDataJSON も受理してしまう
// multiDevice (同期パスキー) でも singleDevice でも同じ脆弱性`,
      },
      {
        lang: "typescript",
        label: "Defended: expectedOrigin strict-equality (passkey.ts pattern)",
        code: `// 安全な実装: @simplewebauthn/server による厳密 origin 検証 (passkey.ts)
const verification = await verifyAuthenticationResponse({
  response: authResponse,
  expectedChallenge: stored,
  expectedOrigin: "http://localhost:3000",   // ← 厳密一致検証
  expectedRPID: "localhost",                 // ← rpId 不一致も拒否
  credential: {
    id: cred.credential_id,
    publicKey: Buffer.from(cred.public_key, "base64"),
    counter: cred.counter,
  },
});
// 同期パスキー (multiDevice) であっても、credential 署名は RP ID に
// 暗号的に紐付いており、別オリジンからは絶対に使用できない`,
      },
    ],
    existingFileLinks: [
      {
        path: "server/routes/passkey.ts",
        description:
          "POST /api/passkey/auth/verify — expectedOrigin / expectedRPID を厳密検証する堅牢実装 (参照実装)",
      },
      {
        path: "server/routes/passkey.ts",
        description:
          "POST /api/passkey/attack/phishing-origin-binding — origin 偽装による attack の両モード並列実行デモ",
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
    id: "passkey-cloud-sync-compromise",
    tabId: "passkey",
    name: "[Educational simulation] Cloud-Sync Compromise: Cloud Account Protection Prerequisite",
    nameJa: "[教育用シミュレーション専用] クラウド同期リスク: クラウドアカウント保護の重要性",
    category: "A2:Broken Authentication",
    cweId: "CWE-287",
    capecId: "CAPEC-560",
    difficulty: 2,
    osiLayer: 7,
    severity: "high",
    description:
      "[Educational simulation] This is a proof-of-concept for CWE-287 / CAPEC-560. The scenario does NOT touch the internal implementation of iCloud Keychain / Google Password Manager / 1Password. It demonstrates the conceptual risk: synced (multiDevice) passkeys are stored in cloud accounts, so cloud account security is a prerequisite for synced passkey security. With weak cloud protection (weak password + no MFA), an attacker can compromise the cloud account and clone the synced passkey. With strong cloud protection (16+ char password + MFA), the cloud provider blocks the attacker. The defense is NOT in passkey.ts — it is the operational prerequisite that users must satisfy.",
    descriptionJa:
      "[教育用シミュレーション専用] これは CWE-287 / CAPEC-560 の概念実証です。シナリオは iCloud Keychain / Google Password Manager / 1Password の内部実装には触れず、概念的なリスクを示します: 同期パスキー (multiDevice) はクラウドアカウントに保存されるため、クラウドアカウントのセキュリティが同期パスキーのセキュリティの前提条件となります。弱いクラウド保護 (弱パスワード + MFA なし) では、攻撃者がクラウドアカウントを侵害して同期パスキーを複製できます。強いクラウド保護 (16 文字以上のパスワード + MFA) では、クラウドプロバイダが攻撃者をブロックします。防御は passkey.ts ではなく、利用者側のクラウドアカウント保護という運用上の前提条件にあります。",
    mitigation:
      "Educate users to protect their cloud accounts (Apple ID / Google account / 1Password vault) with strong unique passwords (16+ chars) and phishing-resistant MFA (TOTP or FIDO2 second factor). For high-security deployments, prefer device-bound credentials (singleDevice / hardware authenticators like YubiKey) where cloud sync is not desired. The credentialDeviceType / credentialBackedUp flags exposed by passkey.ts can be used to display warnings about synced credentials.",
    mitigationJa:
      "ユーザーに対してクラウドアカウント (Apple ID / Google アカウント / 1Password vault 等) を強い一意のパスワード (16 文字以上) とフィッシング耐性 MFA (TOTP または FIDO2 セカンドファクター) で保護することを教育してください。高セキュリティのデプロイメントでは、クラウド同期が不要な場合はデバイス固有クレデンシャル (singleDevice / YubiKey 等のハードウェア認証器) を優先してください。passkey.ts が公開する credentialDeviceType / credentialBackedUp フラグは、同期クレデンシャルに関する警告表示に活用できます。",
    references: [
      "https://cwe.mitre.org/data/definitions/287.html",
      "https://capec.mitre.org/data/definitions/560.html",
      "https://www.w3.org/TR/webauthn-3/#sctn-credential-backup",
      "https://fidoalliance.org/passkeys-faq/",
      "https://support.apple.com/en-us/HT213305",
      "https://owasp.org/www-community/attacks/Credential_stuffing",
    ],
    codeHints: [
      {
        lang: "typescript",
        label: "Display cloud sync risk to users (passkey.ts pattern)",
        code: `// passkey.ts: deviceType を返してフロントエンドで利用者に提示
return c.json({
  success: true,
  data: {
    credentialDeviceType: deviceType,  // "multiDevice" | "singleDevice"
    credentialBackedUp:   backedUp,    // true → クラウド同期済み
  },
});

// クライアント側で警告表示
// multiDevice → "☁ クラウド同期パスキー: クラウドアカウントの保護が重要です"
// singleDevice → "🔒 デバイス固有パスキー: このデバイスにのみ存在します"`,
      },
      {
        lang: "typescript",
        label: "High-security deployment: prefer device-bound credentials",
        code: `// 高セキュリティ用途: residentKey 付き singleDevice クレデンシャル要求
const options = await generateRegistrationOptions({
  rpName: "MyApp",
  rpID: "localhost",
  userName: username,
  userID: ...,
  // クロスプラットフォーム認証器 (YubiKey 等) のみ許可
  authenticatorSelection: {
    authenticatorAttachment: "cross-platform",
    residentKey: "required",
    userVerification: "required",
  },
});
// → singleDevice (BE=0, BS=0) のクレデンシャルが生成され、
//    クラウド同期経路の侵害リスクを排除できる`,
      },
    ],
    existingFileLinks: [
      {
        path: "server/routes/passkey.ts",
        description:
          "POST /api/passkey/register/verify — credentialDeviceType / credentialBackedUp を返却し、フロントエンドに同期パスキーかどうかの判定材料を提供",
      },
      {
        path: "server/routes/passkey.ts",
        description:
          "POST /api/passkey/attack/cloud-sync-compromise — 弱/強クラウド保護の両モード並列比較デモ",
      },
    ],
    modes: [
      {
        id: "weak-cloud-protection",
        labelJa: "弱クラウド保護 (脆弱: 弱パスワード + MFA なし)",
        label: "Weak cloud protection (vulnerable: weak password + no MFA)",
        kind: "vulnerable",
      },
      {
        id: "strong-cloud-protection",
        labelJa: "強クラウド保護 (防御: 強パスワード + MFA)",
        label: "Strong cloud protection (defended: strong password + MFA)",
        kind: "defensive",
      },
    ],
  },
  {
    id: "passkey-cross-device-mitm",
    tabId: "passkey",
    name: "[Educational simulation] Cross-device MITM: Blocked by BLE Proximity + Tunnel Key",
    nameJa: "[教育用シミュレーション専用] Cross-device MITM: BLE 近接 + tunnel key が阻止",
    category: "A2:Broken Authentication",
    cweId: "CWE-300",
    capecId: "CAPEC-94",
    difficulty: 3,
    osiLayer: 7,
    severity: "high",
    description:
      "[Educational simulation] This is a proof-of-concept for CWE-300 / CAPEC-94. The scenario does NOT include the full cryptographic implementation of the CTAP 2.2 hybrid protocol. It demonstrates the two-layer defense: (a) BLE proximity advertising blocks remote attackers who intercept the QR code from outside Bluetooth range, and (b) ECDH-derived tunnel keys block physically nearby attackers who lack the legitimate responder's private share. A purely hypothetical implementation that omitted both layers would allow QR-relay MITM, but the real CTAP 2.2 spec mandates both.",
    descriptionJa:
      "[教育用シミュレーション専用] これは CWE-300 / CAPEC-94 の概念実証です。シナリオは CTAP 2.2 ハイブリッドプロトコルの完全な暗号実装を含みません。二層防御の仕組みを示します: (a) BLE 近接アドバタイジングが、Bluetooth 圏外から QR コードを傍受したリモート攻撃者を阻止します。(b) ECDH 由来の tunnel key が、正規レスポンダーの秘密シェアを持たない物理的に近い攻撃者を阻止します。両層を欠いた仮想実装では QR 中継 MITM が成立しますが、実際の CTAP 2.2 仕様は両層を必須としています。",
    mitigation:
      "Use authenticators and platforms that implement the CTAP 2.2 hybrid flow correctly (current iOS / Android / Chrome / Safari). Do NOT remove BLE proximity advertising checks even when designing custom cross-device flows — they prevent remote QR-relay attacks. The tunnel key (ECDH-derived) provides defense-in-depth against physically nearby attackers. For server-side passkey.ts, this is a transparent feature provided by browser + authenticator; ensure expectedOrigin / expectedRPID are still enforced after the hybrid handshake completes.",
    mitigationJa:
      "CTAP 2.2 ハイブリッドフローを正しく実装した認証器とプラットフォーム (現行の iOS / Android / Chrome / Safari) を使用してください。カスタム cross-device フローを設計する際も、BLE 近接アドバタイジング検証は絶対に省略しないでください — リモート QR 中継攻撃を阻止します。tunnel key (ECDH 由来) は物理的に近い攻撃者に対する深層防御を提供します。サーバー側 passkey.ts では、これはブラウザと認証器が透過的に提供する機能ですが、ハイブリッドハンドシェイク完了後の expectedOrigin / expectedRPID 検証は必ず維持してください。",
    references: [
      "https://cwe.mitre.org/data/definitions/300.html",
      "https://capec.mitre.org/data/definitions/94.html",
      "https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html",
      "https://www.w3.org/TR/webauthn-3/#hybrid-transport",
      "https://blog.cloudflare.com/passkeys-and-fido-cloudflare/",
    ],
    codeHints: [
      {
        lang: "typescript",
        label: "CTAP 2.2 hybrid flow (transport layer — handled by browser + authenticator)",
        code: `// hybrid transport は authenticator + ブラウザが透過的に処理する。
// passkey.ts (サーバー側) は expectedOrigin / expectedRPID 検証のみ追加で行う。

// 1. クライアント側 (ブラウザ): hybrid transport を許可
const options = await generateAuthenticationOptions({
  rpID: "localhost",
  allowCredentials: [],         // ユーザー名なし認証
  userVerification: "required",
});
// → ブラウザが QR コードを表示、スマートフォンで読み取らせる

// 2. CTAP 2.2 仕様の防御層 (authenticator + browser layer)
// (a) BLE 近接: スマートフォンが PC ブラウザと BLE 圏内にあること
// (b) Tunnel key: QR コード埋込 ephemeral pubkey から ECDH で派生した
//     共有秘密のみが正規通信路を確立可能

// 3. サーバー側はハンドシェイク後の assertion を origin で検証
await verifyAuthenticationResponse({
  expectedOrigin: "http://localhost:3000",  // ← BLE/tunnel 通過後も必須
  expectedRPID: "localhost",
  credential: { ... },
});`,
      },
      {
        lang: "typescript",
        label: "Conceptual defense layers (CTAP 2.2 hybrid flow)",
        code: `// CTAP 2.2 ハイブリッドプロトコルの防御層 (概念的表現)

// Layer 1: BLE 近接アドバタイジング
//   → スマートフォンが PC と物理的に近く (~10m 圏内) にあるか
//   → リモート攻撃者は BLE 信号を発信できない (距離による減衰 / OS 制約)
const bleProximityOk = await checkBleAdvertisingResponse(qrContactId);

// Layer 2: Tunnel Key (ECDH 鍵交換)
//   → QR コードに埋め込まれた一時公開鍵
//   → スマートフォンの一時秘密鍵
//   → 双方向の ECDH で共有秘密を導出
//   → 攻撃者は QR を傍受しても秘密鍵を持たないため通信路を確立できない
const tunnelKey = await deriveSharedSecret(
  qrEphemeralPubkey,
  responderEphemeralPrivkey,
);

// 両層が成立して初めて challenge / assertion の受け渡しが可能`,
      },
    ],
    existingFileLinks: [
      {
        path: "server/routes/passkey.ts",
        description:
          "POST /api/passkey/auth/verify — ハイブリッド完了後の assertion を expectedOrigin / expectedRPID で再検証する堅牢実装",
      },
      {
        path: "server/routes/passkey.ts",
        description:
          "POST /api/passkey/attack/cross-device-mitm — リモート/物理近接攻撃者の両モード並列阻止デモ",
      },
    ],
    modes: [
      {
        id: "no-ble-no-tunnel-key",
        labelJa: "BLE 近接 / tunnel key 検証なし (仮想脆弱実装)",
        label: "Without BLE proximity / tunnel key (hypothetical vulnerable)",
        kind: "vulnerable",
      },
      {
        id: "ctap22-spec",
        labelJa: "CTAP 2.2 仕様準拠 (防御: BLE 近接 + tunnel key)",
        label: "CTAP 2.2 spec-compliant (defended: BLE proximity + tunnel key)",
        kind: "defensive",
      },
    ],
  },
];
