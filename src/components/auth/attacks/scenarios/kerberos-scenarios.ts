import type { AttackScenarioMeta } from "../../../../../shared/api-types";

export const kerberosScenarios: AttackScenarioMeta[] = [
  {
    id: "kerberos-pass-the-ticket",
    tabId: "kerberos",
    name: "Pass-the-Ticket (Service Ticket Theft & Replay)",
    nameJa: "Pass-the-Ticket (TGS 窃取・再利用)",
    category: "A2:Broken Authentication",
    cweId: "CWE-294",
    capecId: "CAPEC-555",
    difficulty: 3,
    osiLayer: 7,
    severity: "high",
    description:
      "This is a proof-of-concept for CWE-294 / CAPEC-555. Kerberos Service Tickets are kept in a local 'ticket cache' on the client. An attacker who can extract this cache can replay the ticket against the service without re-authenticating to the KDC. The current AP-REQ implementation has no replay detection (no Authenticator nonce check), so the same ticket is accepted indefinitely until valid_until. The defended implementation requires an Authenticator (timestamp + nonce, encrypted with the session key) and rejects duplicate nonces within the clock-skew window. Note: in real environments, Pass-the-Ticket requires LSASS access (Domain Admin or local admin); this demo simulates an in-process reference only.",
    descriptionJa:
      "これは CWE-294 / CAPEC-555 の概念実証です。Kerberos のサービスチケットはクライアントのローカル『チケットキャッシュ』に保存されます。攻撃者がこのキャッシュを抽出できれば、KDC への再認証なしにそのチケットをサービスに提示して認証できます。現行の AP-REQ 実装はリプレイ検出 (Authenticator nonce 検証) を行わないため、同じチケットが valid_until までは何度でも受理されます。堅牢実装は AP-REQ に Authenticator (セッション鍵で暗号化したタイムスタンプ + nonce) を必須化し、クロックスキュー窓内で nonce の重複を検出して拒否します。注: 実環境での Pass-the-Ticket は LSASS アクセス権 (Domain Admin または local admin 相当) が前提であり、本デモは同一プロセス内の参照シミュレーションに留めます。",
    mitigation:
      "Require an Authenticator (timestamp + random nonce, encrypted with the session key) in every AP-REQ as mandated by RFC 4120 §3.2.3. On the service side, maintain a TTL-bounded cache of seen nonces (within the 5-minute clock-skew window) and reject any duplicate. Keep system clocks synchronized via NTP/Chrony so the clock-skew window can remain narrow. In Windows, enable LSASS Protected Process Light (PPL) and Credential Guard to make ticket cache extraction harder. Monitor for anomalous AP-REQ patterns (same ticket from multiple IPs).",
    mitigationJa:
      "AP-REQ に Authenticator (セッション鍵で暗号化したタイムスタンプ + ランダム nonce) を必須化してください (RFC 4120 §3.2.3 準拠)。サービス側では受信した nonce を TTL 付きキャッシュ (クロックスキュー窓 5 分以内) に記録し、重複を拒否します。NTP/Chrony で時刻同期を維持し、クロックスキュー窓を狭く保ってください。Windows 環境では LSASS の Protected Process Light (PPL) と Credential Guard を有効化してチケットキャッシュ抽出を困難にしてください。同一チケットが複数 IP から提示される等の異常 AP-REQ パターンを監視してください。",
    references: [
      "https://cwe.mitre.org/data/definitions/294.html",
      "https://capec.mitre.org/data/definitions/555.html",
      "https://datatracker.ietf.org/doc/html/rfc4120#section-3.2.3",
      "https://attack.mitre.org/techniques/T1550/003/",
    ],
    codeHints: [
      {
        lang: "typescript",
        label: "Vulnerable: AP-REQ with no Authenticator / nonce cache (do not use)",
        code: `// 脆弱: チケットを復号して期限内なら受理 — リプレイ検出なし
function vulnerableApReq(serviceTicket: string, iv: string) {
  const ticket = decrypt(serviceTicket, KDC_SECRET, iv);
  const data = JSON.parse(ticket);
  if (new Date(data.validUntil) < new Date()) {
    throw new Error("Service ticket expired");
  }
  return { authenticated: true, principal: data.principal };
  // ↑ 同じ serviceTicket を何度でも受理してしまう
}`,
      },
      {
        lang: "typescript",
        label: "Defended: Authenticator nonce + clock-skew window (RFC 4120 §3.2.3)",
        code: `// 安全: Authenticator (timestamp + nonce) を必須化
const seenNonces = createTtlStore<true>({ ttlMs: 5 * 60 * 1000 }); // 5 分窓

function strictApReq(
  serviceTicket: string,
  iv: string,
  encryptedAuthenticator: string,
  authIv: string,
) {
  const ticket = JSON.parse(decrypt(serviceTicket, KDC_SECRET, iv));
  if (new Date(ticket.validUntil) < new Date()) {
    throw new Error("Service ticket expired");
  }

  // Authenticator はサービスセッション鍵で暗号化されている
  const sessionKey = Buffer.from(ticket.sessionKey, "base64");
  const auth = JSON.parse(decrypt(encryptedAuthenticator, sessionKey, authIv));

  // クロックスキュー窓 (5 分) を超えていれば拒否
  const skewMs = Math.abs(Date.now() - new Date(auth.timestamp).getTime());
  if (skewMs > 5 * 60 * 1000) {
    throw new Error("Authenticator timestamp outside clock-skew window");
  }

  // nonce 重複検出
  if (seenNonces.has(auth.nonce)) {
    throw new Error("Replay detected: Authenticator nonce already seen");
  }
  seenNonces.set(auth.nonce, true);

  return { authenticated: true, principal: ticket.principal };
}`,
      },
    ],
    existingFileLinks: [
      {
        path: "server/routes/kerberos-sim.ts",
        description:
          "POST /api/kerberos/ap-req — 現行実装 (Authenticator nonce 検証なし、リプレイ拒否未実装)",
      },
      {
        path: "server/routes/kerberos-sim.ts",
        description:
          "POST /api/kerberos/attack/pass-the-ticket — リプレイの両モード並列実行デモ",
      },
      {
        path: "server/utils/ttl-store.ts",
        description:
          "createTtlStore — クロックスキュー窓内 nonce キャッシュの実装パターン",
      },
    ],
    modes: [
      {
        id: "no-authenticator",
        labelJa: "Authenticator なし AP-REQ (脆弱)",
        label: "AP-REQ without Authenticator (vulnerable)",
        kind: "vulnerable",
      },
      {
        id: "with-authenticator-nonce",
        labelJa: "Authenticator + nonce キャッシュ (防御)",
        label: "With Authenticator + nonce cache (defended)",
        kind: "defensive",
      },
    ],
  },
  {
    id: "kerberos-kerberoasting",
    tabId: "kerberos",
    name: "Kerberoasting (SPN Hash Extraction & Dictionary Attack)",
    nameJa: "Kerberoasting (SPN ハッシュ抽出・辞書攻撃)",
    category: "A2:Broken Authentication",
    cweId: "CWE-326",
    capecId: "CAPEC-509",
    difficulty: 3,
    osiLayer: 7,
    severity: "high",
    description:
      "This is a proof-of-concept for CWE-326 / CAPEC-509. In Kerberos, any authenticated domain user can request a TGS for any registered SPN (by design). The Service Ticket is encrypted with a key derived from the service account's password, so an attacker can extract the encrypted blob and crack the password offline at unlimited rate. Service accounts with weak (dictionary-word) passwords are recovered in seconds. The defended deployment uses ≥20-character random passwords (or gMSA in Windows) which are practically immune to dictionary attacks. Note: real Kerberoasting uses Hashcat/John the Ripper at billions of candidates/second; this demo simplifies to a 20-entry fixed-dictionary simulation.",
    descriptionJa:
      "これは CWE-326 / CAPEC-509 の概念実証です。Kerberos ではドメイン認証済みの一般ユーザーが任意の SPN に対して TGS を要求できます (設計上の特性)。サービスチケットの暗号化鍵はサービスアカウントのパスワードから導出されるため、攻撃者は暗号文を抽出してオフラインで自由に解読試行できます。弱パスワード (辞書語) のサービスアカウントは数秒で解読されます。堅牢実装は 20 文字以上のランダムパスワード (または Windows の gMSA) を使用し、辞書攻撃に対して実質的に耐性があります。注: 実環境の Kerberoasting は Hashcat/John the Ripper で毎秒数十億候補を試行しますが、本デモは固定辞書 20 件との照合シミュレーションに留めます。",
    mitigation:
      "Use ≥20-character random passwords for all service accounts (or use Group Managed Service Accounts (gMSA) in Windows where the OS auto-manages a 240-byte random secret with automatic rotation). Disable etype 23 (RC4-HMAC) at the KDC and require AES (etype 17/18) only — RC4 is the most vulnerable to Kerberoasting. Rotate service account passwords at least every 90 days. Monitor for anomalous TGS request patterns (one user requesting many SPNs in a short time). Limit which accounts have SPNs registered.",
    mitigationJa:
      "全てのサービスアカウントに 20 文字以上のランダムパスワードを使用してください (Windows 環境では gMSA を使用し、240 バイトのランダム秘密を OS が自動管理 + 自動ローテーションする設定を推奨)。KDC で etype 23 (RC4-HMAC) を無効化し AES (etype 17/18) のみ許可してください — RC4 は Kerberoasting に最も悪用されやすい暗号方式です。サービスアカウントのパスワードは 90 日以内にローテーションしてください。同一ユーザーが短時間で大量の SPN に TGS を要求する等の異常パターンを監視してください。SPN を登録するアカウントを最小限に絞ってください。",
    references: [
      "https://cwe.mitre.org/data/definitions/326.html",
      "https://capec.mitre.org/data/definitions/509.html",
      "https://attack.mitre.org/techniques/T1558/003/",
      "https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview",
    ],
    codeHints: [
      {
        lang: "typescript",
        label: "Vulnerable: weak service-account password (dictionary word — do not use)",
        code: `// 脆弱: サービスアカウントに辞書語パスワード
const servicePassword = "service123";  // ← 辞書攻撃で即解読
const serviceKey = sha256(servicePassword);
// 攻撃者は TGS チケットの暗号文を抽出し、
// オフラインで毎秒数十億候補を試行 → 数秒で解読`,
      },
      {
        lang: "typescript",
        label: "Defended: ≥20-char random password / gMSA equivalent",
        code: `// 安全: 20 文字以上ランダム — オフライン辞書攻撃に対する実質耐性
import crypto from "crypto";

// gMSA 相当: 240 バイトのランダム秘密 (Windows gMSA は OS が自動管理)
const strongServicePassword = crypto.randomBytes(32).toString("base64"); // 43 文字 base64

function isKerberoastResistant(password: string): boolean {
  return (
    password.length >= 20 &&
    /[A-Z]/.test(password) &&
    /[a-z]/.test(password) &&
    /[0-9]/.test(password) &&
    /[^A-Za-z0-9]/.test(password)
  );
}

// KDC 設定: etype 17/18 (AES128/AES256) のみ許可、RC4 (etype 23) は無効化
// 監視: 短時間に多数の SPN へ TGS 要求するユーザーをアラート`,
      },
    ],
    existingFileLinks: [
      {
        path: "server/routes/kerberos-sim.ts",
        description:
          "POST /api/kerberos/tgs-req — TGS 発行ロジック (任意ドメインユーザーが任意 SPN に要求可能 — 設計上の特性)",
      },
      {
        path: "server/routes/kerberos-sim.ts",
        description:
          "POST /api/kerberos/attack/kerberoasting — 弱/強パスワード SPN 比較の両モード並列実行デモ",
      },
    ],
    modes: [
      {
        id: "weak-service-password",
        labelJa: "弱パスワードサービス (辞書語 — 脆弱)",
        label: "Weak service password (dictionary word — vulnerable)",
        kind: "vulnerable",
      },
      {
        id: "strong-service-password-or-gmsa",
        labelJa: "強パスワード / gMSA (≥20 文字ランダム — 防御)",
        label: "Strong password / gMSA (≥20 random chars — defended)",
        kind: "defensive",
      },
    ],
  },
  {
    id: "kerberos-golden-ticket",
    tabId: "kerberos",
    name: "Golden Ticket (Forged TGT via krbtgt Key)",
    nameJa: "Golden Ticket (krbtgt 鍵漏洩による TGT 偽造)",
    category: "A2:Broken Authentication",
    cweId: "CWE-345",
    capecId: "CAPEC-196",
    difficulty: 5,
    osiLayer: 7,
    severity: "critical",
    description:
      "This is a proof-of-concept for CWE-345 / CAPEC-196. The Kerberos TGT is encrypted with the krbtgt account's long-term key. An attacker who has obtained this key (typically via Domain Controller compromise) can forge TGTs for arbitrary principals (e.g., 'administrator') with arbitrary expiry and group memberships, bypassing the KDC entirely. The KDC cannot distinguish a forged TGT from a legitimate one because the encryption is correct. The defended deployment performs a krbtgt double-reset (twice within 10 hours) to invalidate all forged TGTs, enables PAC validation by Domain Controllers, and isolates DCs as Tier 0. Note: this scenario assumes the krbtgt key is already leaked — real attacks require Domain Admin compromise.",
    descriptionJa:
      "これは CWE-345 / CAPEC-196 の概念実証です。Kerberos の TGT は krbtgt アカウントの長期鍵で暗号化されています。攻撃者がこの鍵を取得 (通常は Domain Controller 侵害経由) すると、任意のプリンシパル (例: 'administrator') を任意の有効期限・グループ情報で偽造 TGT を作成でき、KDC を通さずに利用できます。KDC は暗号化が正しい限り偽造 TGT と正規 TGT を区別できません。堅牢実装は krbtgt の二重リセット (10 時間以内に 2 回) で既存の偽造 TGT を無効化し、Domain Controller による PAC 検証を有効化し、DC を Tier 0 として完全分離します。注: 本シナリオは krbtgt 鍵が既に漏洩している前提です — 実環境では Domain Admin 相当の侵害が必要です。",
    mitigation:
      "Rotate the krbtgt password twice within 10 hours after any suspected compromise (the double-reset invalidates all forged TGTs because old krbtgt password keys remain valid until the second rotation). Rotate krbtgt at least every 180 days as routine hygiene (NIST SP 800-228). Enforce PAC validation between member services and Domain Controllers (MS-KILE §3.4.5.3) so forged group memberships are detected. Treat Domain Controllers as Tier 0 — restrict DC access to dedicated Privileged Access Workstations (PAW), prohibit general-purpose use (web/email) on DCs, restrict RDP/SMB to specific jump hosts. Monitor for TGS requests with abnormally long Ticket lifetimes (>10 hours) and unusual krbtgt-related events.",
    mitigationJa:
      "侵害が疑われた場合は krbtgt パスワードを 10 時間以内に 2 回リセットしてください (二重リセットによりすべての偽造 TGT が無効化されます — 古い krbtgt パスワード鍵は 2 回目のリセットまで有効なため)。日常運用としては 180 日以内にローテーションしてください (NIST SP 800-228)。メンバーサービスと Domain Controller 間で PAC 検証 (MS-KILE §3.4.5.3) を有効化し、偽造されたグループ情報を検出してください。Domain Controller を Tier 0 として扱い、専用の PAW (Privileged Access Workstation) からのみアクセス可能にし、DC 上での一般業務 (Web 閲覧・メール) を禁止し、RDP/SMB アクセスを特定のジャンプサーバーに制限してください。異常に長い Ticket 有効期限 (>10 時間) を持つ TGS 要求や krbtgt 関連の異常イベントを監視してください。",
    references: [
      "https://cwe.mitre.org/data/definitions/345.html",
      "https://capec.mitre.org/data/definitions/196.html",
      "https://attack.mitre.org/techniques/T1558/001/",
      "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-resetting-the-krbtgt-password",
      "https://www.microsoft.com/en-us/security/blog/2022/10/18/defenders-beware-a-case-for-post-ransomware-investigations/",
    ],
    codeHints: [
      {
        lang: "typescript",
        label: "Vulnerable: KDC accepts any TGT decryptable with current krbtgt key (do not use)",
        code: `// 脆弱: KDC は krbtgt 鍵で復号成功した TGT を全て信用
function vulnerableTgsReq(forgedTgt: string, iv: string) {
  // forgedTgt は攻撃者が krbtgt 鍵で暗号化した偽 TGT
  const tgt = JSON.parse(decrypt(forgedTgt, KDC_SECRET, iv));
  // ↓ KDC には偽造を検出する手段がない (PAC 検証なし)
  return issueServiceTicket(tgt.principal, tgt.servicePrincipal);
}`,
      },
      {
        lang: "typescript",
        label: "Defended: krbtgt rotation + PAC validation + Tier 0 isolation",
        code: `// 安全: 多層防御 — 単一の対策では不十分
// 1. krbtgt 二重リセット (10 時間以内 2 回)
//    一度目: 新しい krbtgt 鍵を導入 (既存の正規 TGT は古い鍵で有効)
//    二度目: 古い krbtgt 鍵を完全失効 (偽造 TGT は復号不能になる)
async function rotateKrbtgtTwice() {
  await resetKrbtgtPassword();
  await sleep(2 * 60 * 60 * 1000); // 2 時間待機 (10 時間以内)
  await resetKrbtgtPassword();      // 古い鍵を完全失効
}

// 2. PAC (Privilege Attribute Certificate) 検証
//    メンバーサービスが DC に PAC 検証リクエストを送信し、
//    DC が保持する署名で改竄を検出する (MS-KILE §3.4.5.3)
function enablePacValidation() {
  registry.set(
    "HKLM\\\\System\\\\CurrentControlSet\\\\Services\\\\Kdc\\\\Parameters",
    "ValidateKdcPacSignature", 1,
  );
}

// 3. DC Tier 0 分離 + 異常検知
//    - DC アクセスは PAW のみ
//    - DC 上での Web/メール禁止
//    - Ticket 有効期限 >10 時間のリクエストをアラート`,
      },
    ],
    existingFileLinks: [
      {
        path: "server/routes/kerberos-sim.ts",
        description:
          "POST /api/kerberos/tgs-req — KDC の TGT 復号 + サービスチケット発行ロジック (PAC 検証なし)",
      },
      {
        path: "server/routes/kerberos-sim.ts",
        description:
          "POST /api/kerberos/attack/golden-ticket — 偽造 TGT の両モード並列実行デモ",
      },
    ],
    modes: [
      {
        id: "no-krbtgt-rotation",
        labelJa: "krbtgt 未ローテーション + PAC 検証なし (脆弱)",
        label: "krbtgt not rotated + no PAC validation (vulnerable)",
        kind: "vulnerable",
      },
      {
        id: "krbtgt-double-reset-and-pac",
        labelJa: "krbtgt 二重リセット + PAC 検証 + Tier 0 分離 (防御)",
        label: "krbtgt double-reset + PAC validation + Tier 0 isolation (defended)",
        kind: "defensive",
      },
    ],
  },
];
