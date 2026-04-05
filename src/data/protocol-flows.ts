import type { ProtocolFlowStep, ProtocolActor, KerberosStep } from "../types/security";

/* ──── OpenID Connect (Authorization Code Flow) ──── */

export const OIDC_ACTORS: ProtocolActor[] = [
  { id: "user", name: "User (Browser)", nameJa: "ユーザー（ブラウザ）", color: "#3B82F6" },
  { id: "rp", name: "Relying Party (App)", nameJa: "リライングパーティ（アプリ）", color: "#22C55E" },
  { id: "op", name: "OpenID Provider", nameJa: "OpenIDプロバイダ", color: "#F59E0B" },
  { id: "userinfo", name: "UserInfo Endpoint", nameJa: "UserInfoエンドポイント", color: "#A855F7" },
];

export const OIDC_STEPS: ProtocolFlowStep[] = [
  {
    stepNumber: 1,
    from: "user", to: "rp",
    action: "Login Request",
    actionJa: "ログインリクエスト",
    description: "User clicks 'Sign in with OIDC'. RP generates state + nonce and redirects to OP's authorization endpoint.",
    descriptionJa: "ユーザーが「OIDCでサインイン」をクリック。RPがstate + nonceを生成し、OPの認可エンドポイントにリダイレクト。",
    dataPayload: "GET /authorize?response_type=code&scope=openid+profile+email&client_id=...&redirect_uri=...&state=xyz&nonce=abc",
    osiLayer: 7,
  },
  {
    stepNumber: 2,
    from: "rp", to: "op",
    action: "Authorization Request",
    actionJa: "認可リクエスト",
    description: "Browser is redirected to OP. The scope=openid triggers OIDC behavior (in addition to OAuth 2.0).",
    descriptionJa: "ブラウザがOPにリダイレクトされる。scope=openidがOIDC動作をトリガー（OAuth 2.0に加えて）。",
    osiLayer: 7,
  },
  {
    stepNumber: 3,
    from: "op", to: "user",
    action: "Authentication & Consent",
    actionJa: "認証と同意",
    description: "OP authenticates the user (login form, MFA, etc.) and requests consent for the requested scopes (profile, email).",
    descriptionJa: "OPがユーザーを認証（ログインフォーム、MFA等）し、要求されたスコープ（profile, email）への同意を求める。",
    osiLayer: 7,
  },
  {
    stepNumber: 4,
    from: "op", to: "rp",
    action: "Authorization Code",
    actionJa: "認可コード発行",
    description: "OP redirects back to RP's redirect_uri with an authorization code and the original state value for CSRF protection.",
    descriptionJa: "OPがRPのredirect_uriに認可コードとCSRF保護用の元のstate値を付けてリダイレクト。",
    dataPayload: "GET /callback?code=AUTH_CODE&state=xyz",
    osiLayer: 7,
  },
  {
    stepNumber: 5,
    from: "rp", to: "op",
    action: "Token Exchange",
    actionJa: "トークン交換",
    description: "RP sends the authorization code to OP's token endpoint (server-to-server) with client credentials.",
    descriptionJa: "RPが認可コードをOPのトークンエンドポイントにクライアント認証情報と共に送信（サーバー間通信）。",
    dataPayload: "POST /token { grant_type: authorization_code, code: AUTH_CODE, client_id, client_secret }",
    osiLayer: 7,
  },
  {
    stepNumber: 6,
    from: "op", to: "rp",
    action: "ID Token + Access Token",
    actionJa: "IDトークン + アクセストークン",
    description: "OP returns an ID Token (JWT with user identity claims, signed by OP) and an Access Token. RP validates the ID Token signature and nonce.",
    descriptionJa: "OPがIDトークン（OPが署名した、ユーザーID情報を含むJWT）とアクセストークンを返す。RPがIDトークンの署名とnonceを検証。",
    dataPayload: '{ "id_token": "eyJ...(JWT)", "access_token": "at_...", "token_type": "Bearer" }',
    osiLayer: 7,
  },
  {
    stepNumber: 7,
    from: "rp", to: "userinfo",
    action: "UserInfo Request (Optional)",
    actionJa: "UserInfoリクエスト（任意）",
    description: "RP can optionally call the UserInfo endpoint with the access token to get additional claims beyond what's in the ID Token.",
    descriptionJa: "RPは任意でアクセストークンを使ってUserInfoエンドポイントを呼び出し、IDトークンに含まれない追加クレームを取得可能。",
    dataPayload: 'GET /userinfo  Authorization: Bearer at_...',
    osiLayer: 7,
  },
  {
    stepNumber: 8,
    from: "rp", to: "user",
    action: "Authenticated Session",
    actionJa: "認証済みセッション",
    description: "RP creates a session for the user based on the verified ID Token claims (sub, email, name). User is now logged in.",
    descriptionJa: "RPが検証済みIDトークンのクレーム（sub, email, name）に基づいてユーザーセッションを作成。ユーザーはログイン状態に。",
    osiLayer: 7,
  },
];

/* ──── SAML 2.0 (SP-Initiated SSO) ──── */

export const SAML_ACTORS: ProtocolActor[] = [
  { id: "user", name: "User (Browser)", nameJa: "ユーザー（ブラウザ）", color: "#3B82F6" },
  { id: "sp", name: "Service Provider", nameJa: "サービスプロバイダ", color: "#22C55E" },
  { id: "idp", name: "Identity Provider", nameJa: "アイデンティティプロバイダ", color: "#EF4444" },
];

export const SAML_STEPS: ProtocolFlowStep[] = [
  {
    stepNumber: 1,
    from: "user", to: "sp",
    action: "Access Resource",
    actionJa: "リソースアクセス",
    description: "User attempts to access a protected resource at the SP without an active session.",
    descriptionJa: "ユーザーがアクティブセッションなしでSPの保護リソースにアクセスを試みる。",
    osiLayer: 7,
  },
  {
    stepNumber: 2,
    from: "sp", to: "idp",
    action: "SAML AuthnRequest",
    actionJa: "SAML認証リクエスト",
    description: "SP generates a SAML AuthnRequest XML, encodes it in Base64, and redirects the browser to the IdP's SSO URL (HTTP-Redirect or HTTP-POST binding).",
    descriptionJa: "SPがSAML AuthnRequest XMLを生成、Base64エンコードし、ブラウザをIdPのSSO URLにリダイレクト（HTTP-RedirectまたはHTTP-POSTバインディング）。",
    dataPayload: '<samlp:AuthnRequest ID="_abc" IssueInstant="..." Destination="https://idp/sso" AssertionConsumerServiceURL="https://sp/acs" />',
    osiLayer: 7,
  },
  {
    stepNumber: 3,
    from: "idp", to: "user",
    action: "Authentication",
    actionJa: "認証",
    description: "IdP authenticates the user (login form, Kerberos, MFA, etc.). If the user already has an active IdP session, this step may be skipped (SSO).",
    descriptionJa: "IdPがユーザーを認証（ログインフォーム、Kerberos、MFA等）。既にIdPセッションがある場合、このステップはスキップ（SSO）。",
    osiLayer: 7,
  },
  {
    stepNumber: 4,
    from: "idp", to: "sp",
    action: "SAML Response + Assertion",
    actionJa: "SAMLレスポンス + アサーション",
    description: "IdP creates a signed SAML Assertion containing identity attributes (NameID, roles, email) and wraps it in a SAML Response. Sent via browser POST to SP's ACS URL.",
    descriptionJa: "IdPがID属性（NameID、ロール、メール）を含む署名済みSAMLアサーションを作成し、SAMLレスポンスでラップ。ブラウザPOSTでSPのACS URLに送信。",
    dataPayload: '<samlp:Response><saml:Assertion><saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>...</saml:Assertion></samlp:Response>',
    osiLayer: 7,
  },
  {
    stepNumber: 5,
    from: "sp", to: "sp",
    action: "Validate Assertion",
    actionJa: "アサーション検証",
    description: "SP validates the SAML Assertion: checks XML signature against IdP's X.509 certificate, verifies timestamps (NotBefore/NotOnOrAfter), audience restriction, and InResponseTo.",
    descriptionJa: "SPがSAMLアサーションを検証：IdPのX.509証明書でXML署名チェック、タイムスタンプ（NotBefore/NotOnOrAfter）、オーディエンス制限、InResponseToを確認。",
    osiLayer: 7,
  },
  {
    stepNumber: 6,
    from: "sp", to: "user",
    action: "Session Created",
    actionJa: "セッション作成",
    description: "SP creates a local session based on the assertion attributes and redirects the user to the originally requested resource.",
    descriptionJa: "SPがアサーション属性に基づいてローカルセッションを作成し、ユーザーを元のリクエストリソースにリダイレクト。",
    osiLayer: 7,
  },
];

/* ──── FIDO2 / WebAuthn ──── */

export const FIDO2_ACTORS: ProtocolActor[] = [
  { id: "user", name: "User", nameJa: "ユーザー", color: "#3B82F6" },
  { id: "browser", name: "Browser (Client)", nameJa: "ブラウザ（クライアント）", color: "#22C55E" },
  { id: "authn", name: "Authenticator", nameJa: "認証器", color: "#F59E0B" },
  { id: "rp", name: "Relying Party (Server)", nameJa: "リライングパーティ（サーバー）", color: "#A855F7" },
];

export const FIDO2_REGISTRATION_STEPS: ProtocolFlowStep[] = [
  {
    stepNumber: 1,
    from: "user", to: "rp",
    action: "Registration Start",
    actionJa: "登録開始",
    description: "User initiates credential registration. RP generates a challenge (random bytes) and sends PublicKeyCredentialCreationOptions including rp.id, user info, supported algorithms, and attestation preference.",
    descriptionJa: "ユーザーがクレデンシャル登録を開始。RPがチャレンジ（ランダムバイト）を生成し、rp.id、ユーザー情報、対応アルゴリズム、アテステーション設定を含むPublicKeyCredentialCreationOptionsを送信。",
    dataPayload: '{ rp: { id: "example.com" }, user: { id, name, displayName }, challenge: "random...", pubKeyCredParams: [{ alg: -7 (ES256) }] }',
    osiLayer: 7,
  },
  {
    stepNumber: 2,
    from: "browser", to: "authn",
    action: "navigator.credentials.create()",
    actionJa: "navigator.credentials.create()",
    description: "Browser calls the WebAuthn API. The authenticator prompts the user for consent (touch, biometric, PIN). On approval, generates a new key pair bound to the RP's origin.",
    descriptionJa: "ブラウザがWebAuthn APIを呼び出す。認証器がユーザーに同意を求める（タッチ、生体、PIN）。承認後、RPのオリジンに紐づく新しい鍵ペアを生成。",
    osiLayer: 7,
  },
  {
    stepNumber: 3,
    from: "authn", to: "browser",
    action: "Attestation Response",
    actionJa: "アテステーションレスポンス",
    description: "Authenticator returns an attestation object containing the new public key, credential ID, and attestation statement (proving the authenticator's identity and key origin).",
    descriptionJa: "認証器が新しい公開鍵、クレデンシャルID、アテステーションステートメント（認証器のIDと鍵の出自を証明）を含むアテステーションオブジェクトを返す。",
    dataPayload: '{ id: "credId...", rawId, response: { clientDataJSON, attestationObject: { authData, fmt, attStmt } } }',
    osiLayer: 7,
  },
  {
    stepNumber: 4,
    from: "browser", to: "rp",
    action: "Send Attestation to Server",
    actionJa: "アテステーションをサーバーに送信",
    description: "Browser sends the PublicKeyCredential to the RP server. The response includes clientDataJSON (origin, challenge, type) and the attestation object.",
    descriptionJa: "ブラウザがPublicKeyCredentialをRPサーバーに送信。レスポンスにclientDataJSON（オリジン、チャレンジ、タイプ）とアテステーションオブジェクトを含む。",
    osiLayer: 7,
  },
  {
    stepNumber: 5,
    from: "rp", to: "rp",
    action: "Verify & Store",
    actionJa: "検証と保存",
    description: "RP verifies: challenge matches, origin matches rp.id, attestation signature is valid. Stores the credential ID and public key mapped to the user account.",
    descriptionJa: "RPが検証：チャレンジ一致、オリジンがrp.idと一致、アテステーション署名が有効。クレデンシャルIDと公開鍵をユーザーアカウントに紐づけて保存。",
    osiLayer: 7,
  },
];

export const FIDO2_AUTH_STEPS: ProtocolFlowStep[] = [
  {
    stepNumber: 1,
    from: "user", to: "rp",
    action: "Authentication Start",
    actionJa: "認証開始",
    description: "User initiates login. RP generates a new challenge and sends PublicKeyCredentialRequestOptions with allowed credential IDs (or empty for discoverable credentials/passkeys).",
    descriptionJa: "ユーザーがログインを開始。RPが新しいチャレンジを生成し、許可されたクレデンシャルID（またはdiscoverable credential/パスキー用に空）を含むPublicKeyCredentialRequestOptionsを送信。",
    dataPayload: '{ challenge: "random...", rpId: "example.com", allowCredentials: [{ id: "credId..." }], userVerification: "preferred" }',
    osiLayer: 7,
  },
  {
    stepNumber: 2,
    from: "browser", to: "authn",
    action: "navigator.credentials.get()",
    actionJa: "navigator.credentials.get()",
    description: "Browser calls WebAuthn API. Authenticator finds matching credentials, prompts user for verification (biometric/PIN), then signs the challenge with the private key.",
    descriptionJa: "ブラウザがWebAuthn APIを呼び出す。認証器が一致するクレデンシャルを見つけ、ユーザーに検証を求め（生体/PIN）、秘密鍵でチャレンジに署名。",
    osiLayer: 7,
  },
  {
    stepNumber: 3,
    from: "authn", to: "browser",
    action: "Assertion Response",
    actionJa: "アサーションレスポンス",
    description: "Authenticator returns the assertion: credential ID, authenticator data (sign count, flags), client data hash, and the signature over the combined data.",
    descriptionJa: "認証器がアサーションを返す：クレデンシャルID、認証器データ（署名カウント、フラグ）、クライアントデータハッシュ、結合データの署名。",
    dataPayload: '{ id: "credId...", response: { authenticatorData, clientDataJSON, signature, userHandle } }',
    osiLayer: 7,
  },
  {
    stepNumber: 4,
    from: "browser", to: "rp",
    action: "Send Assertion to Server",
    actionJa: "アサーションをサーバーに送信",
    description: "Browser forwards the assertion to the RP server for verification.",
    descriptionJa: "ブラウザがアサーションをRPサーバーに検証のため転送。",
    osiLayer: 7,
  },
  {
    stepNumber: 5,
    from: "rp", to: "user",
    action: "Verify & Authenticate",
    actionJa: "検証と認証",
    description: "RP looks up the stored public key by credential ID, verifies the signature, checks the challenge, increments sign count. On success, user is authenticated.",
    descriptionJa: "RPがクレデンシャルIDで保存済み公開鍵を検索、署名を検証、チャレンジを確認、署名カウントをインクリメント。成功すればユーザーは認証済み。",
    osiLayer: 7,
  },
];

/* ──── Kerberos ──── */

export const KERBEROS_ACTORS: ProtocolActor[] = [
  { id: "client", name: "Client", nameJa: "クライアント", color: "#3B82F6" },
  { id: "kdc-as", name: "KDC (AS)", nameJa: "KDC（認証サービス）", color: "#F59E0B" },
  { id: "kdc-tgs", name: "KDC (TGS)", nameJa: "KDC（チケット発行サービス）", color: "#EF4444" },
  { id: "service", name: "Service Server", nameJa: "サービスサーバー", color: "#22C55E" },
];

export const KERBEROS_STEPS: KerberosStep[] = [
  {
    stepNumber: 1,
    from: "client", to: "kdc-as",
    action: "AS-REQ (Authentication Request)",
    actionJa: "AS-REQ（認証リクエスト）",
    description: "Client sends principal name and timestamp (pre-authentication) encrypted with the user's password-derived key to the KDC's Authentication Service.",
    descriptionJa: "クライアントがプリンシパル名とタイムスタンプ（事前認証）をユーザーのパスワード派生鍵で暗号化してKDCの認証サービスに送信。",
    osiLayer: 7,
  },
  {
    stepNumber: 2,
    from: "kdc-as", to: "client",
    action: "AS-REP (TGT Issued)",
    actionJa: "AS-REP（TGT発行）",
    description: "KDC verifies the user's identity, then returns a Ticket-Granting Ticket (TGT) encrypted with the TGS secret key, plus a session key encrypted with the user's key.",
    descriptionJa: "KDCがユーザーのIDを検証後、TGS秘密鍵で暗号化されたチケット認可チケット（TGT）と、ユーザーの鍵で暗号化されたセッション鍵を返す。",
    ticket: "TGT",
    osiLayer: 7,
  },
  {
    stepNumber: 3,
    from: "client", to: "kdc-tgs",
    action: "TGS-REQ (Service Ticket Request)",
    actionJa: "TGS-REQ（サービスチケットリクエスト）",
    description: "Client presents the TGT and an authenticator (timestamp encrypted with the session key) to the TGS, requesting access to a specific service (SPN).",
    descriptionJa: "クライアントがTGTと認証子（セッション鍵で暗号化されたタイムスタンプ）をTGSに提示し、特定サービス（SPN）へのアクセスを要求。",
    ticket: "TGT",
    osiLayer: 7,
  },
  {
    stepNumber: 4,
    from: "kdc-tgs", to: "client",
    action: "TGS-REP (Service Ticket Issued)",
    actionJa: "TGS-REP（サービスチケット発行）",
    description: "TGS validates the TGT and authenticator, then issues a Service Ticket encrypted with the target service's secret key, plus a new session key for client-service communication.",
    descriptionJa: "TGSがTGTと認証子を検証後、対象サービスの秘密鍵で暗号化されたサービスチケットと、クライアント-サービス間通信用の新しいセッション鍵を発行。",
    ticket: "Service Ticket",
    osiLayer: 7,
  },
  {
    stepNumber: 5,
    from: "client", to: "service",
    action: "AP-REQ (Application Request)",
    actionJa: "AP-REQ（アプリケーションリクエスト）",
    description: "Client presents the Service Ticket and a new authenticator to the target service. The service decrypts the ticket with its own key to obtain the session key and user identity.",
    descriptionJa: "クライアントがサービスチケットと新しい認証子をサービスに提示。サービスが自身の鍵でチケットを復号し、セッション鍵とユーザーIDを取得。",
    ticket: "Service Ticket",
    osiLayer: 7,
  },
  {
    stepNumber: 6,
    from: "service", to: "client",
    action: "AP-REP (Mutual Authentication)",
    actionJa: "AP-REP（相互認証）",
    description: "Service optionally sends back the timestamp from the client's authenticator encrypted with the session key, proving it could decrypt the ticket. Mutual authentication complete.",
    descriptionJa: "サービスが任意でクライアントの認証子のタイムスタンプをセッション鍵で暗号化して返し、チケットを復号できたことを証明。相互認証完了。",
    osiLayer: 7,
  },
];

/* ──── OIDC vs SAML Comparison ──── */

export interface ProtocolComparison {
  aspect: string;
  aspectJa: string;
  oidc: string;
  oidcJa: string;
  saml: string;
  samlJa: string;
}

export const OIDC_VS_SAML: ProtocolComparison[] = [
  {
    aspect: "Token Format", aspectJa: "トークン形式",
    oidc: "JWT (JSON)", oidcJa: "JWT (JSON)",
    saml: "XML Assertion", samlJa: "XMLアサーション",
  },
  {
    aspect: "Transport", aspectJa: "トランスポート",
    oidc: "REST / JSON over HTTPS", oidcJa: "REST / JSON over HTTPS",
    saml: "XML / SOAP / Browser redirects", samlJa: "XML / SOAP / ブラウザリダイレクト",
  },
  {
    aspect: "Primary Use Case", aspectJa: "主なユースケース",
    oidc: "Web/Mobile apps, SPAs, APIs", oidcJa: "Web/モバイルアプリ、SPA、API",
    saml: "Enterprise SSO, legacy systems", samlJa: "企業SSO、レガシーシステム",
  },
  {
    aspect: "Complexity", aspectJa: "複雑さ",
    oidc: "Simpler (built on OAuth 2.0)", oidcJa: "シンプル（OAuth 2.0上に構築）",
    saml: "Complex (XML Schema, XML Signature)", samlJa: "複雑（XMLスキーマ、XML署名）",
  },
  {
    aspect: "Discovery", aspectJa: "ディスカバリー",
    oidc: ".well-known/openid-configuration", oidcJa: ".well-known/openid-configuration",
    saml: "Metadata XML exchange", samlJa: "メタデータXML交換",
  },
  {
    aspect: "Mobile Support", aspectJa: "モバイル対応",
    oidc: "Excellent (lightweight JSON)", oidcJa: "優れている（軽量JSON）",
    saml: "Poor (heavy XML parsing)", samlJa: "不向き（XMLパースが重い）",
  },
];
