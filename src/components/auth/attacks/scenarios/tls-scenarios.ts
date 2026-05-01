import type { AttackScenarioMeta } from "../../../../../shared/api-types";

export const tlsScenarios: AttackScenarioMeta[] = [
  {
    id: "tls-version-downgrade",
    tabId: "tls-deep",
    name: "Version Downgrade Attack (Force TLS 1.0)",
    nameJa: "バージョンダウングレード攻撃 (TLS 1.0 強制)",
    category: "A2:Cryptographic Failures",
    cweId: "CWE-757",
    capecId: "CAPEC-220",
    difficulty: 3,
    osiLayer: 5,
    severity: "high",
    description:
      "This is a proof-of-concept for CWE-757 / CAPEC-220. A MITM intercepts the ClientHello, strips TLS 1.2/1.3 from the supported_versions extension, and forces the server to negotiate TLS 1.0 with RC4-MD5 — exposing the connection to BEAST/POODLE-class attacks. The defended server detects the forced downgrade via TLS_FALLBACK_SCSV (RFC 7507) and aborts with the inappropriate_fallback alert. Note: in real environments, TLS 1.0/1.1 is disabled on most modern servers; this demo assumes a legacy server that retained backward compatibility.",
    descriptionJa:
      "これは CWE-757 / CAPEC-220 の概念実証です。MITM が ClientHello を傍受し supported_versions エクステンションから TLS 1.2/1.3 を削除することで、サーバーに TLS 1.0 + RC4-MD5 でのネゴシエーションを強制し、BEAST/POODLE クラスの攻撃に接続を露出させます。堅牢サーバーは TLS_FALLBACK_SCSV (RFC 7507) でダウングレードを検知し inappropriate_fallback アラートで接続を中断します。注: 実環境では TLS 1.0/1.1 はほとんどのサーバーで無効化されており、本デモは後方互換性を残した古いサーバーを想定した概念実証です。",
    mitigation:
      "Disable TLS 1.0 and TLS 1.1 entirely at the server (set minimum protocol version to TLS 1.2 or, preferably, TLS 1.3 only). Implement TLS_FALLBACK_SCSV per RFC 7507 to detect forced downgrades from clients that retry with a lower version. Use Qualys SSL Labs or similar tools to periodically verify that no deprecated protocol versions remain enabled. In Node.js: `tls.createServer({ minVersion: 'TLSv1.3' })`.",
    mitigationJa:
      "サーバー設定で TLS 1.0 / TLS 1.1 を完全に無効化してください (最低バージョンを TLS 1.2、推奨は TLS 1.3 のみに設定)。TLS_FALLBACK_SCSV (RFC 7507) を実装し、低位バージョンで再試行したクライアントからのダウングレードを検知してください。Qualys SSL Labs 等のツールで非推奨プロトコルバージョンが残っていないか定期的に検証してください。Node.js では `tls.createServer({ minVersion: 'TLSv1.3' })` で固定できます。",
    references: [
      "https://cwe.mitre.org/data/definitions/757.html",
      "https://capec.mitre.org/data/definitions/220.html",
      "https://datatracker.ietf.org/doc/html/rfc7507",
      "https://datatracker.ietf.org/doc/html/rfc8446",
    ],
    codeHints: [
      {
        lang: "typescript",
        label: "Vulnerable: server accepts whatever the client offers (do not use)",
        code: `// 脆弱: TLS_FALLBACK_SCSV を確認せず、最低バージョンも未設定
function vulnerableSelectVersion(offered: string[]): string {
  // SCSV チェックなし → MITM が削った後の TLS 1.0 をそのまま受諾
  if (offered.includes("TLS 1.0")) return "TLS 1.0";
  return offered[0] ?? "TLS 1.0";
}

// Node.js 設定例 (脆弱)
const server = tls.createServer({
  // minVersion 未指定 → デフォルトで TLS 1.0 まで許可されてしまう
});`,
      },
      {
        lang: "typescript",
        label: "Defended: TLS 1.3-only + TLS_FALLBACK_SCSV check (RFC 7507)",
        code: `// 安全: 最低バージョン強制 + SCSV 検証
import tls from "tls";

const secureServer = tls.createServer({
  minVersion: "TLSv1.3",   // TLS 1.0/1.1/1.2 を完全無効化
  // TLS 1.3 では暗号スイートは AEAD のみ (AES-GCM, ChaCha20-Poly1305) が自動有効化
});

// TLS 1.2 互換が必要な場合の SCSV 検証ロジック
function checkFallbackSCSV(
  offeredCiphers: string[],
  negotiatedVersion: string,
  serverMaxVersion: string,
): void {
  if (offeredCiphers.includes("TLS_FALLBACK_SCSV")
      && negotiatedVersion < serverMaxVersion) {
    // RFC 7507 §3: クライアントが低位バージョンで再試行している
    // → 強制ダウングレードと判断し inappropriate_fallback で中断
    throw new Error("inappropriate_fallback: TLS downgrade detected");
  }
}`,
      },
    ],
    existingFileLinks: [
      {
        path: "server/routes/tls-sim.ts",
        description:
          "POST /api/tls/client-hello — TLS 1.3 専用 AEAD 暗号スイートのみ提示する正常系",
      },
      {
        path: "server/routes/tls-sim.ts",
        description:
          "POST /api/tls/attack/version-downgrade — SCSV あり/なし両モード並列実行デモ",
      },
    ],
    modes: [
      {
        id: "no-fallback-scsv",
        labelJa: "FALLBACK_SCSV チェックなし (脆弱)",
        label: "No FALLBACK_SCSV check (vulnerable)",
        kind: "vulnerable",
      },
      {
        id: "with-fallback-scsv",
        labelJa: "FALLBACK_SCSV + TLS 1.3 強制 (防御)",
        label: "FALLBACK_SCSV + TLS 1.3 enforced (defended)",
        kind: "defensive",
      },
    ],
  },
  {
    id: "tls-self-signed-mitm",
    tabId: "tls-deep",
    name: "Self-Signed Certificate MITM",
    nameJa: "自己署名証明書による MITM",
    category: "A2:Cryptographic Failures",
    cweId: "CWE-295",
    capecId: "CAPEC-94",
    difficulty: 3,
    osiLayer: 5,
    severity: "high",
    description:
      "This is a proof-of-concept for CWE-295 / CWE-300 / CAPEC-94. A MITM intercepts the TLS handshake and presents a self-signed certificate impersonating the legitimate server. A vulnerable client with rejectUnauthorized=false (or NODE_TLS_REJECT_UNAUTHORIZED=0) accepts the fake cert and the MITM reads/modifies all TLS-encrypted traffic. The defended client validates the certificate chain to a trusted root CA per RFC 5280 §6 and aborts with TLS Alert 46 (certificate_unknown). Note: real MITM requires network path interception (ARP spoofing, DNS poisoning, rogue Wi-Fi AP); this demo abstracts that step and focuses on the certificate validation phase.",
    descriptionJa:
      "これは CWE-295 / CWE-300 / CAPEC-94 の概念実証です。MITM が TLS ハンドシェイクを傍受し、正規サーバーになりすました自己署名証明書を提示します。rejectUnauthorized=false (または NODE_TLS_REJECT_UNAUTHORIZED=0) のクライアントは偽証明書を受諾し、MITM が TLS 暗号化された全通信を読み書きできるようになります。堅牢クライアントは RFC 5280 §6 に従い信頼されたルート CA への証明書チェーン検証を行い、TLS Alert 46 (certificate_unknown) で接続を中断します。注: 実環境の MITM はネットワーク経路への介入 (ARP スプーフィング・DNS ポイズニング・偽 Wi-Fi AP 等) が必要ですが、本デモはその手順を抽象化し証明書検証段階に焦点を当てます。",
    mitigation:
      "Never disable certificate validation in production code. `rejectUnauthorized: false` and `NODE_TLS_REJECT_UNAUTHORIZED=0` should be banned by linting. Validate the full X.509 chain to a trusted root CA per RFC 5280 §6. Match the certificate's CN/SAN against the server's hostname. Add Certificate Pinning (pin the server's public-key fingerprint) for defense-in-depth — even a CA compromise will not bypass pinned keys. For mTLS, require client certificates as well. Monitor certificate transparency logs (CT) for unexpected issuance.",
    mitigationJa:
      "本番コードで証明書検証を絶対に無効化しないでください。`rejectUnauthorized: false` や `NODE_TLS_REJECT_UNAUTHORIZED=0` は lint で禁止すべきです。RFC 5280 §6 に従い X.509 全チェーンを信頼されたルート CA まで検証してください。証明書の CN/SAN とサーバーのホスト名の一致も確認してください。Certificate Pinning (サーバー公開鍵フィンガープリントの固定) を追加することで、CA そのものが侵害された場合でも防御が機能します。mTLS では加えてクライアント証明書も要求してください。Certificate Transparency (CT) ログで予期せぬ発行を監視してください。",
    references: [
      "https://cwe.mitre.org/data/definitions/295.html",
      "https://cwe.mitre.org/data/definitions/300.html",
      "https://capec.mitre.org/data/definitions/94.html",
      "https://datatracker.ietf.org/doc/html/rfc5280",
    ],
    codeHints: [
      {
        lang: "typescript",
        label: "Vulnerable: certificate validation disabled (do not use)",
        code: `// 絶対に本番で使用しない
import https from "https";

const vulnerableAgent = new https.Agent({
  rejectUnauthorized: false,  // ← 全ての証明書を受諾 (自己署名含む)
});

const res = await fetch("https://example.com", {
  // @ts-ignore
  agent: vulnerableAgent,
});

// 環境変数による無効化も同様に脆弱
// process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";`,
      },
      {
        lang: "typescript",
        label: "Defended: strict CA chain validation + Certificate Pinning",
        code: `import https from "https";
import fs from "fs";
import crypto from "crypto";
import type tls from "tls";

// 信頼するルート CA を明示
const secureAgent = new https.Agent({
  // rejectUnauthorized: true (デフォルト — 変更禁止)
  ca: fs.readFileSync("/path/to/trusted-ca.crt"),
});

// Certificate Pinning (defense-in-depth)
const EXPECTED_PIN_BASE64 = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

function verifyCertPin(cert: tls.PeerCertificate): boolean {
  const publicKeyDer = cert.raw;
  const actualPin = "sha256/" + crypto
    .createHash("sha256")
    .update(publicKeyDer)
    .digest("base64");
  return actualPin === EXPECTED_PIN_BASE64;
}

// checkServerIdentity でホスト名と CN/SAN の一致も検証
const pinnedAgent = new https.Agent({
  checkServerIdentity: (host, cert) => {
    if (!verifyCertPin(cert)) {
      return new Error("Certificate pin mismatch");
    }
    return undefined;  // tls.checkServerIdentity が呼ばれる
  },
});`,
      },
    ],
    existingFileLinks: [
      {
        path: "server/routes/tls-sim.ts",
        description:
          "GET /api/tls/certificate — 教育用自己署名証明書の生成 (CA チェーン概念の表示)",
      },
      {
        path: "server/routes/tls-sim.ts",
        description:
          "POST /api/tls/attack/self-signed-mitm — 検証 ON/OFF の両モード並列実行デモ",
      },
    ],
    modes: [
      {
        id: "cert-validation-disabled",
        labelJa: "rejectUnauthorized=false (脆弱)",
        label: "rejectUnauthorized=false (vulnerable)",
        kind: "vulnerable",
      },
      {
        id: "ca-chain-validation",
        labelJa: "CA チェーン検証 + Pinning (防御)",
        label: "CA chain validation + Pinning (defended)",
        kind: "defensive",
      },
    ],
  },
  {
    id: "tls-weak-cipher-negotiation",
    tabId: "tls-deep",
    name: "Weak Cipher Suite Negotiation (RC4/3DES)",
    nameJa: "弱い暗号スイートネゴシエーション (RC4/3DES)",
    category: "A2:Cryptographic Failures",
    cweId: "CWE-327",
    capecId: "CAPEC-220",
    difficulty: 3,
    osiLayer: 5,
    severity: "high",
    description:
      "This is a proof-of-concept for CWE-327 / CAPEC-220. A MITM strips strong cipher suites (TLS 1.3 AEAD) from the ClientHello, leaving only RC4-MD5. A vulnerable server retaining RC4/3DES/NULL for legacy compatibility negotiates the broken cipher; RC4 statistical biases (RFC 7465) and 3DES Sweet32 attacks then enable plaintext recovery. The defended server enforces an AEAD-only allowlist (TLS 1.3) per RFC 7525 (BCP 195) and aborts with TLS Alert 40 (handshake_failure) when no common cipher exists. Note: in real environments, RC4/3DES are disabled in modern server configurations; this demo assumes a legacy server retaining them for backward compatibility.",
    descriptionJa:
      "これは CWE-327 / CAPEC-220 の概念実証です。MITM が ClientHello から強い暗号スイート (TLS 1.3 AEAD) を削除し、RC4-MD5 のみを残します。後方互換性のために RC4/3DES/NULL を残した脆弱サーバーは RC4 でネゴシエーションを成立させ、RC4 統計バイアス (RFC 7465) や 3DES Sweet32 攻撃により平文を復元されます。堅牢サーバーは RFC 7525 (BCP 195) に従い AEAD のみの allowlist (TLS 1.3) を強制し、共通暗号がなければ TLS Alert 40 (handshake_failure) で接続を中断します。注: 実環境では RC4/3DES は現代のサーバー設定では無効化されており、本デモは後方互換性を残したレガシーサーバーを想定した概念実証です。",
    mitigation:
      "Enforce a strict cipher suite allowlist: TLS 1.3 AEAD only (TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_GCM_SHA256). Disable RC4 (RFC 7465), 3DES (Sweet32-vulnerable), DES, NULL, EXPORT, and anonymous DH. Set `honorCipherOrder: true` so the server's preference wins (preventing client-side downgrade). Use Qualys SSL Labs to verify configuration. In Apache: `SSLCipherSuite`; in nginx: `ssl_ciphers`; in Node.js: `tls.createServer({ ciphers: '...' })`.",
    mitigationJa:
      "厳格な暗号スイート allowlist を強制してください: TLS 1.3 AEAD のみ (TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_GCM_SHA256)。RC4 (RFC 7465)、3DES (Sweet32 脆弱)、DES、NULL、EXPORT、匿名 DH を無効化してください。`honorCipherOrder: true` を設定しサーバー側の優先順位を強制 (クライアント側ダウングレードの阻止)。Qualys SSL Labs で設定を検証してください。Apache では `SSLCipherSuite`、nginx では `ssl_ciphers`、Node.js では `tls.createServer({ ciphers: '...' })` で制御します。",
    references: [
      "https://cwe.mitre.org/data/definitions/327.html",
      "https://datatracker.ietf.org/doc/html/rfc7465",
      "https://datatracker.ietf.org/doc/html/rfc7525",
      "https://sweet32.info/",
    ],
    codeHints: [
      {
        lang: "typescript",
        label: "Vulnerable: server retains RC4/3DES for legacy compatibility (do not use)",
        code: `// 脆弱: 後方互換性のために RC4/3DES を残した設定
import tls from "tls";

const weakServer = tls.createServer({
  // 弱い暗号スイートを許可 — Sweet32/RC4-bias で平文復元される
  ciphers: [
    "RC4-MD5",                  // RC4 統計バイアス → RFC 7465 で禁止
    "DES-CBC3-SHA",             // 3DES → Sweet32 で破られる
    "NULL-SHA",                 // NULL 暗号 (= 暗号化なし)
    "TLS_AES_256_GCM_SHA384",   // 強い暗号も一応サポート
  ].join(":"),
  // honorCipherOrder 未設定 → クライアントの優先順が採用されてしまう
});`,
      },
      {
        lang: "typescript",
        label: "Defended: AEAD-only allowlist (RFC 7525 / BCP 195)",
        code: `import tls from "tls";

// TLS 1.3 のみ許可 — AEAD 暗号スイートが自動的に強制される
const secureServer = tls.createServer({
  minVersion: "TLSv1.3",
  // TLS 1.3 は cipher suite が事実上以下の 3 つに固定される:
  //   TLS_AES_256_GCM_SHA384
  //   TLS_CHACHA20_POLY1305_SHA256
  //   TLS_AES_128_GCM_SHA256
});

// TLS 1.2 互換も必要な場合の安全な allowlist
const compatServer = tls.createServer({
  minVersion: "TLSv1.2",
  ciphers: [
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    // 含めない: RC4, 3DES, DES, NULL, EXPORT, 匿名 DH
  ].join(":"),
  honorCipherOrder: true,  // サーバー側の優先順位を強制
});`,
      },
    ],
    existingFileLinks: [
      {
        path: "server/routes/tls-sim.ts",
        description:
          "POST /api/tls/client-hello — TLS 1.3 専用 AEAD 暗号スイートのみ提示する正常系",
      },
      {
        path: "server/routes/tls-sim.ts",
        description:
          "POST /api/tls/server-hello — selectCipherSuite で最強の暗号を選択する正常系",
      },
      {
        path: "server/routes/tls-sim.ts",
        description:
          "POST /api/tls/attack/weak-cipher — 弱い暗号許可サーバー / AEAD allowlist サーバーの両モード並列実行デモ",
      },
    ],
    modes: [
      {
        id: "weak-cipher-allowed",
        labelJa: "RC4/3DES を許可するサーバー (脆弱)",
        label: "Server allowing RC4/3DES (vulnerable)",
        kind: "vulnerable",
      },
      {
        id: "aead-allowlist",
        labelJa: "AEAD のみ allowlist (防御)",
        label: "AEAD-only allowlist (defended)",
        kind: "defensive",
      },
    ],
  },
];
