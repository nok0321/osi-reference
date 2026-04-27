import type { AttackScenarioMeta } from "../../../../../shared/api-types";

export const oidcSamlScenarios: AttackScenarioMeta[] = [
  {
    id: "saml-xsw",
    tabId: "oidc-saml",
    name: "SAML XML Signature Wrapping (XSW)",
    nameJa: "SAML XSW (XML 署名ラッピング)",
    category: "A2:Broken Authentication",
    cweId: "CWE-345",
    capecId: "CAPEC-475",
    difficulty: 4,
    osiLayer: 7,
    severity: "critical",
    description:
      "This is a proof-of-concept for CWE-345 / CAPEC-475. SAML's XML Digital Signature signs only specific assertion elements identified by an @ID attribute. In an XSW attack, the attacker wraps a legitimately-signed assertion as an inner element and inserts a fake (unsigned) assertion in an outer element. A naive parser concludes 'the signature is valid' but processes the outer fake assertion (admin role / different subject), allowing privilege escalation. The defended implementation uses XPath to verify that the signed element's ID matches the actually-processed element's ID. Note: real XSW requires deep XML XPath and namespace knowledge; this demo uses a simplified 2-layer JSON structure.",
    descriptionJa:
      "これは CWE-345 / CAPEC-475 の概念実証です。SAML の XML Digital Signature は @ID 属性で特定されるアサーション要素のみを署名対象とします。XSW 攻撃では、攻撃者が正規の署名済みアサーションを内側要素としてラップし、その外側に偽 (署名対象外) アサーションを挿入します。素朴なパーサは『署名が有効』と判断しますが、外側の偽アサーション (admin ロール / 別の Subject) を処理してしまい、権限昇格を許してしまいます。堅牢実装は XPath で『署名対象の要素 ID』と『実際に処理する要素 ID』が一致することを確認します。注: 実環境の XSW は XML XPath と名前空間の深い知識を要しますが、本デモは 2 層構造の簡略化 JSON で概念を示します。",
    mitigation:
      "Use a SAML library that performs strict XPath-based signature scope resolution (e.g., xml-crypto with explicit reference URI matching). Verify that the @ID attribute referenced by the signature matches the @ID of the assertion element actually being processed. Reject any payload where the signed ID and processed ID differ. Keep your SAML library up to date with XSW-related security patches (most major libraries have published XSW fixes since 2012).",
    mitigationJa:
      "厳密な XPath ベース署名範囲解決を行う SAML ライブラリ (例: xml-crypto に明示的な reference URI マッチを設定) を使用してください。署名が参照する @ID 属性と、実際に処理されるアサーション要素の @ID が一致することを確認し、不一致なら必ず拒否してください。SAML ライブラリは最新バージョンを維持し、XSW 関連のセキュリティパッチ (2012 年以降主要ライブラリで配布済み) を適用してください。",
    references: [
      "https://cwe.mitre.org/data/definitions/345.html",
      "https://capec.mitre.org/data/definitions/475.html",
      "https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html",
      "https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91.pdf",
    ],
    codeHints: [
      {
        lang: "typescript",
        label: "Vulnerable: signature checked but processed element ID not validated (do not use)",
        code: `// 脆弱: 署名は確認するが処理対象との同一性を確認しない
function naiveVerify(parsed: SAMLResponse) {
  const signedEl = parsed.SignedAssertion;
  const valid = verifySignature(signedEl.assertion, signedEl.signature);  // true
  // ↓ XSW: 外側の偽が選択される。署名対象 ID との一致確認なし
  const processed = parsed.Assertion || signedEl.assertion;
  return { valid, subject: processed.Subject.NameID["#text"] }; // 偽 Subject が返る
}`,
      },
      {
        lang: "typescript",
        label: "Defended: XPath-based scope check (xml-crypto pattern)",
        code: `// 安全: 署名対象 ID と処理対象アサーション ID の一致確認
function strictVerifySamlAssertion(samlResponse: SamlWrappedPayload): VerifyResult {
  const signed = samlResponse.SignedAssertion;
  const signedId = signed.assertion["@ID"];

  // XPath で署名が参照する要素 ID を取得し、
  // 実際に処理するアサーション要素の ID と比較する
  const processedId = samlResponse.Assertion?.["@ID"];

  if (processedId && processedId !== signedId) {
    // XSW 攻撃を検出: 署名対象と処理対象の ID が異なる
    throw new Error(
      \`XSW detected: signed ID='\${signedId}' !== processed ID='\${processedId}'\`
    );
  }

  // 署名検証は署名対象の要素 (signedId) に対してのみ行う
  const isValid = verifySignature(signed.assertion, signed.signature);
  return { valid: isValid, subject: signed.assertion.Subject.NameID["#text"] };
}`,
      },
    ],
    existingFileLinks: [
      {
        path: "server/routes/oidc-saml-sim.ts",
        description:
          "POST /api/oidc/saml/sso — SAML アサーション生成 + HMAC-SHA256 署名 (現行は educational simplification、XML-DSIG ではなく JSON ペイロードに対する署名)",
      },
      {
        path: "server/routes/oidc-saml-sim.ts",
        description:
          "POST /api/oidc/attack/saml-xsw — XSW ペイロードの両モード並列実行デモ",
      },
    ],
    modes: [
      {
        id: "naive-parser",
        labelJa: "素朴なパーサ (XPath 署名範囲検証なし — 脆弱)",
        label: "Naive parser (no XPath scope check — vulnerable)",
        kind: "vulnerable",
      },
      {
        id: "strict-parser",
        labelJa: "厳密なパーサ (XPath 署名範囲検証あり — 防御)",
        label: "Strict parser (with XPath scope check — defended)",
        kind: "defensive",
      },
    ],
  },
  {
    id: "saml-assertion-replay",
    tabId: "oidc-saml",
    name: "SAML Assertion Replay",
    nameJa: "SAML アサーションリプレイ",
    category: "A2:Broken Authentication",
    cweId: "CWE-294",
    capecId: "CAPEC-60",
    difficulty: 3,
    osiLayer: 7,
    severity: "high",
    description:
      "This is a proof-of-concept for CWE-294 / CAPEC-60. A SAML assertion captured from a legitimate authentication can be replayed if its signature is valid and it is within its NotOnOrAfter window. A vulnerable SP that does not maintain a OneTimeUse cache (or check OneTimeUse condition) accepts the replay and creates a new session for the attacker. The defended SP caches accepted assertion IDs (TTL-bounded) and enforces NotOnOrAfter / NotBefore validation, blocking replays. Note: in real environments, proper TLS configuration makes interception difficult; this demo simulates 'a previously captured assertion'.",
    descriptionJa:
      "これは CWE-294 / CAPEC-60 の概念実証です。正規認証から傍受された SAML アサーションは、署名が有効かつ NotOnOrAfter 時間内であればリプレイ可能です。OneTimeUse キャッシュを持たない (または OneTimeUse 条件を確認しない) 脆弱な SP は再送を受理し、攻撃者用に新しいセッションを作成してしまいます。堅牢な SP は受理済みアサーション ID を TTL 付きキャッシュに記録し、NotOnOrAfter / NotBefore 検証も併せて実施することでリプレイを阻止します。注: 実環境では TLS が正しく設定されていれば傍受は困難です。本デモは『事前に傍受されたアサーション』を仮定します。",
    mitigation:
      "Maintain a TTL-bounded cache of accepted assertion IDs (memory-based for single-node, Redis EXPIRE for distributed deployments). On each assertion submission, look up the @ID in the cache and reject if found. Use a TTL longer than the assertion's NotOnOrAfter window. Also verify NotOnOrAfter / NotBefore timestamps against the current time and reject expired/not-yet-valid assertions. If the SAML library supports OneTimeUse condition processing, enable it and enforce the cache lookup as a hard requirement.",
    mitigationJa:
      "受理済みアサーション ID を TTL 付きキャッシュに保持してください (単一ノードならメモリ、分散デプロイメントなら Redis EXPIRE)。アサーション受信時に @ID をキャッシュ検索し、ヒットしたら拒否します。TTL はアサーションの NotOnOrAfter ウィンドウより長く設定してください。NotOnOrAfter / NotBefore タイムスタンプを現在時刻と比較し、期限切れ・未到来のアサーションも拒否してください。SAML ライブラリが OneTimeUse condition 処理をサポートしている場合は有効化し、キャッシュ検索を必須要件として強制してください。",
    references: [
      "https://cwe.mitre.org/data/definitions/294.html",
      "https://capec.mitre.org/data/definitions/60.html",
      "https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf",
      "https://owasp.org/www-community/attacks/Replay_Attack",
    ],
    codeHints: [
      {
        lang: "typescript",
        label: "Vulnerable: signature only, no replay cache (do not use)",
        code: `// 脆弱: 署名のみ検証、OneTimeUse / 使用済み ID キャッシュを確認しない
function vulnerableAssertionVerify(a: SamlAssertion) {
  return { ok: verifyHmac(a, SECRET), subject: a.Subject.NameID["#text"] };
}
// 攻撃者は同じアサーションを何度でも再送できる`,
      },
      {
        lang: "typescript",
        label: "Defended: TTL-bounded OneTimeUse cache + NotOnOrAfter check",
        code: `// 安全: 使用済み ID キャッシュ + 時刻制約
const usedAssertionIds = createTtlStore<true>({ ttlMs: 10 * 60 * 1000 });

function strictAssertionVerify(assertion: SamlAssertion): SessionResult {
  // 1. 有効期間チェック (NotBefore <= now <= NotOnOrAfter)
  const now = new Date();
  const notOnOrAfter = new Date(assertion.Conditions["@NotOnOrAfter"]);
  const notBefore = new Date(assertion.Conditions["@NotBefore"]);
  if (now > notOnOrAfter || now < notBefore) {
    throw new Error("Assertion is outside valid time window");
  }

  // 2. OneTimeUse / リプレイキャッシュチェック
  const assertionId = assertion["@ID"];
  if (usedAssertionIds.get(assertionId)) {
    throw new Error(\`Replay detected: assertion ID '\${assertionId}' already used\`);
  }
  usedAssertionIds.set(assertionId, true);  // 使用済みとして記録

  return { authenticated: true, subject: assertion.Subject.NameID["#text"] };
}`,
      },
    ],
    existingFileLinks: [
      {
        path: "server/routes/oidc-saml-sim.ts",
        description:
          "POST /api/oidc/saml/sso — assertion.Conditions の NotBefore / NotOnOrAfter 設定 (有効期間制約の SSoT)",
      },
      {
        path: "server/utils/ttl-store.ts",
        description: "createTtlStore — TTL 付きキャッシュ (OneTimeUse 実装パターン)",
      },
      {
        path: "server/routes/oidc-saml-sim.ts",
        description:
          "POST /api/oidc/attack/saml-assertion-replay — リプレイの両モード並列実行デモ",
      },
    ],
    modes: [
      {
        id: "no-one-time-use-check",
        labelJa: "OneTimeUse キャッシュ無効 (脆弱)",
        label: "Without OneTimeUse cache (vulnerable)",
        kind: "vulnerable",
      },
      {
        id: "with-one-time-use-check",
        labelJa: "OneTimeUse キャッシュ有効 + NotOnOrAfter 検証 (防御)",
        label: "With OneTimeUse cache + NotOnOrAfter check (defended)",
        kind: "defensive",
      },
    ],
  },
  {
    id: "oidc-id-token-spoofing",
    tabId: "oidc-saml",
    name: "OIDC ID Token Spoofing (Missing iss/aud/nonce Validation)",
    nameJa: "OIDC ID Token なりすまし (iss/aud/nonce 検証省略)",
    category: "A2:Broken Authentication",
    cweId: "CWE-345",
    capecId: "CAPEC-196",
    difficulty: 3,
    osiLayer: 7,
    severity: "critical",
    description:
      "This is a proof-of-concept for CWE-345 / CWE-1004 / CAPEC-196. An OIDC ID Token is a JWT containing iss (issuer), aud (audience), and nonce (replay-prevention) claims. If the RP (relying party) does not validate these claims, an attacker who controls their own IdP (attacker.example) can issue a spoofed ID Token claiming to be a victim user (e.g., seed_alice with admin role) and present it to the target RP. A vulnerable RP using jwt.decode without verification accepts the spoofed token at face value. The defended RP uses jwt.verify with issuer/audience options and a separate nonce check, blocking the attack per OIDC Core 1.0 §3.1.3.7.",
    descriptionJa:
      "これは CWE-345 / CWE-1004 / CAPEC-196 の概念実証です。OIDC の ID Token は iss (発行元) / aud (受信者) / nonce (リプレイ防止) クレームを含む JWT です。RP (リライング・パーティ) がこれらのクレームを検証しない場合、自身の IdP (attacker.example) を制御する攻撃者は被害者ユーザー (例: seed_alice、admin ロール) を偽る ID Token を発行し、ターゲット RP に提示できます。jwt.decode のみで検証なしの脆弱な RP はトークンをそのまま信用してしまいます。堅牢な RP は jwt.verify に issuer/audience オプションを渡し、nonce も別途検証することで OIDC Core 1.0 §3.1.3.7 準拠の検証を行い、この攻撃を阻止します。",
    mitigation:
      "Always use jwt.verify (NOT jwt.decode) with explicit issuer and audience options when validating OIDC ID Tokens. Use the algorithms option to pin the expected signing algorithm (e.g., RS256) to prevent algorithm confusion. After signature verification, separately verify the nonce claim against the value generated during the authorization request. Verify exp, iat, and (if present) auth_time claims. Maintain an allowlist of trusted iss values and reject any token whose iss is not in the allowlist. Compliant: OpenID Connect Core 1.0 §3.1.3.7.",
    mitigationJa:
      "OIDC ID Token を検証する際は必ず jwt.verify (NOT jwt.decode) に issuer / audience オプションを明示的に渡してください。algorithms オプションで期待するアルゴリズム (例: RS256) を固定し、アルゴリズム混乱攻撃を防いでください。署名検証後、nonce クレームを認可リクエスト時に生成した値と照合してください。exp / iat / (存在すれば) auth_time クレームも検証してください。信頼する iss 値の許可リストを維持し、未知の iss のトークンは拒否してください。準拠: OpenID Connect Core 1.0 §3.1.3.7。",
    references: [
      "https://cwe.mitre.org/data/definitions/345.html",
      "https://cwe.mitre.org/data/definitions/1004.html",
      "https://capec.mitre.org/data/definitions/196.html",
      "https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation",
      "https://owasp.org/www-community/vulnerabilities/Improper_Validation_of_OAuth_Token",
    ],
    codeHints: [
      {
        lang: "typescript",
        label: "Vulnerable: jwt.decode only, trusts sub claim blindly (do not use)",
        code: `// 脆弱: jwt.decode のみ (署名検証・iss/aud/nonce チェックなし)
const payload = jwt.decode(idToken);  // attacker.example 発行トークンが通る
return { userId: payload.sub, role: payload.role };  // 攻撃者の admin ロールを信用`,
      },
      {
        lang: "typescript",
        label: "Defended: jwt.verify with issuer/audience + separate nonce check",
        code: `// 安全: OIDC Core 1.0 §3.1.3.7 準拠の ID Token 検証
function strictVerifyIdToken(
  idToken: string,
  expectedIss: string,   // 登録済み IdP の issuer URL
  expectedAud: string,   // 自身の client_id
  expectedNonce: string  // 認可リクエスト時に生成した nonce
): IdTokenClaims {
  // jwt.verify は署名検証 + exp チェックを自動実行
  const payload = jwt.verify(idToken, OIDC_PUBLIC_KEY, {
    algorithms: ["RS256"],  // 鍵アルゴリズムを明示 (alg=none バイパス防止)
    issuer: expectedIss,    // iss 検証
    audience: expectedAud,  // aud 検証
  }) as IdTokenClaims;

  // nonce 検証 (jwt.verify は nonce を自動検証しないため手動で確認)
  if (payload.nonce !== expectedNonce) {
    throw new Error(\`nonce mismatch: expected '\${expectedNonce}', got '\${payload.nonce}'\`);
  }

  return payload;
}`,
      },
    ],
    existingFileLinks: [
      {
        path: "server/routes/oidc-saml-sim.ts",
        description:
          "POST /api/oidc/token — ID Token 生成 (iss / aud / nonce クレームの設定: HMAC-SHA256 / 教育用簡略化)",
      },
      {
        path: "server/routes/oidc-saml-sim.ts",
        description:
          "GET /api/oidc/userinfo — jwt.verify による Bearer トークン検証 (algorithm 固定の堅牢パターン)",
      },
      {
        path: "server/routes/oidc-saml-sim.ts",
        description:
          "POST /api/oidc/attack/id-token-spoof — 攻撃者 IdP 発行トークンに対する両モード並列実行デモ",
      },
    ],
    modes: [
      {
        id: "no-claims-check",
        labelJa: "iss/aud/nonce 検証なし — jwt.decode のみ (脆弱)",
        label: "Without iss/aud/nonce check — jwt.decode only (vulnerable)",
        kind: "vulnerable",
      },
      {
        id: "strict-claims-check",
        labelJa: "iss/aud/nonce 検証あり — jwt.verify with options (防御)",
        label: "With iss/aud/nonce check — jwt.verify with options (defended)",
        kind: "defensive",
      },
    ],
  },
];
