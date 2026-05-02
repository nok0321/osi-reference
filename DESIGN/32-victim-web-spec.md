---
title: 攻撃デモカタログ — victim-web 脆弱アプリ仕様
phase: design
audience: 開発者・教材執筆者
last-updated: 2026-05-02
safety-reviewed: false
---

## 教育目的

本ファイルは **教育用シミュレーション** の実装設計である。
記載された脆弱エンドポイントは `victim-net (internal: true)` 内の固定シードデータに対してのみ動作するよう設計されており、
実環境への攻撃を意図したものではない。

各エンドポイントの脆弱実装は「この防御がなぜ必要か」を体感するための概念実証であり、
必ず堅牢実装 (`server/routes/*.ts`) との対応関係を併記する。

---

# 32. victim-web 脆弱アプリ仕様

## 1. 目的とスコープ

### 1.1 役割

`services/victim-web/` は orchestrator (`server/routes/orchestrator-exec.ts` の `POST /api/orchestrator/exec`) から
実 HTTP リクエストを受け取り、**意図的に脆弱な実装**で応答する独立 Hono アプリである。

学習者は `RawHttpComposer` でヘッダ・ボディを自ら編集し、orchestrator 経由で victim-web に実 HTTP を送信することで、
脆弱性が成立する条件を体感できる。victim-web が「攻撃が成立した」応答を返すことで、
DataFlowPanel に rawRequest / rawResponse が表示され、教育効果が生まれる。

orchestrator は `VICTIM_ALLOWLIST` で到達先を `victim-web:4001` のみに制限し、
任意の外部 URL への転送は設計上不可能である。

### 1.2 隔離方針

- **ネットワーク**: `victim-net` (`internal: true`) にのみ接続。Docker が OS レイヤでインターネット egress を遮断する
- **DB 分離**: `victim-data.sqlite` を独立 Docker volume (`victim-db`) に配置。orchestrator の `server/db/data.sqlite` とは物理的に別ファイル
- **対象ユーザー**: シードユーザー (`seed_alice`, `seed_bob`, `seed_admin`, `attacker_charlie`) のみ。任意ユーザーデータへの攻撃は設計上不可能
- **egress なし**: victim-web コンテナ自体が外部 URL に fetch することはない

### 1.3 スコープ範囲

| Phase | 担当コンテナ | 対象区分 |
|-------|------------|--------|
| Phase 1-3 | `victim-web` (本仕様) | A 群 18 シナリオ |
| Phase 4 | `victim-tls-proxy` (nginx + 旧 TLS) | B 群: tls-version-downgrade, tls-self-signed-mitm, tls-weak-cipher |
| Phase 4 | `victim-saml-idp` (独自実装) | B 群: saml-xsw, pass-the-ticket |

Phase 4 の 2 コンテナは **本仕様のスコープ外**とする。仕様は別途 `DESIGN/35-victim-tls-proxy.md`、`DESIGN/36-victim-saml-idp.md` で定義する。

---

## 2. `services/victim-web/` ディレクトリ構造

```
services/victim-web/
├── package.json              # 独立 package、name: "@osi-ref/victim-web"
├── Dockerfile                # node:20-alpine ベース
├── tsconfig.json             # extends ../../tsconfig.base.json
├── src/
│   ├── index.ts              # Hono エントリ、全ルート登録 + /health + /api/reset
│   ├── seed.ts               # シードユーザー投入 (seed_alice, seed_bob, seed_admin, attacker_charlie)
│   ├── db.ts                 # better-sqlite3 初期化、victim-data.sqlite を /app/data/ に配置
│   └── routes/
│       ├── jwt.ts            # /jwt/verify, /jwt/verify-kid, /jwt/issue-weak
│       ├── rbac.ts           # /orders/:id, /users/:id, /admin/:action, /resource
│       ├── session.ts        # /session/login, /session/me, /token/refresh
│       ├── oauth.ts          # /oauth/authorize, /oauth/redirect
│       ├── oidc.ts           # /oidc/verify-id-token
│       ├── saml.ts           # /saml/consume-assertion
│       ├── mfa.ts            # /mfa/verify
│       └── sso.ts            # /api/resource, /api/hmac, /api/replay
└── __tests__/
    ├── jwt.test.ts
    ├── rbac.test.ts
    ├── session.test.ts
    ├── oauth.test.ts
    ├── oidc-saml.test.ts
    ├── mfa.test.ts
    └── sso.test.ts
```

> **注意**: `victim-data.sqlite` はコンテナ内 `/app/data/` に配置し、compose の `tmpfs` マウントで管理する。
> gitignore 対象であり、`src/` 配下には含めない。

---

## 3. npm workspaces 統合

### 3.1 root `package.json` への変更

```json
{
  "name": "osi-reference",
  "private": true,
  "workspaces": ["services/*"],
  "scripts": {
    "dev": "docker compose up -d victim-web attacker-shell && concurrently \"vite\" \"tsx watch server/index.ts\"",
    "dev:no-docker": "concurrently \"vite\" \"tsx watch server/index.ts\"",
    "dev:client": "vite",
    "dev:server": "tsx watch server/index.ts",
    "build": "vite build",
    "victim:reset": "docker compose restart victim-web",
    "victim:logs": "docker compose logs -f victim-web"
  }
}
```

### 3.2 `services/victim-web/package.json`

```json
{
  "name": "@osi-ref/victim-web",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "scripts": {
    "build": "tsc -p tsconfig.json",
    "start": "node dist/index.js",
    "test": "vitest run"
  },
  "dependencies": {
    "@hono/node-server": "^1.19.13",
    "better-sqlite3": "^12.8.0",
    "bcryptjs": "^3.0.3",
    "hono": "^4.12.12",
    "jsonwebtoken": "^9.0.3",
    "uuid": "^13.0.0"
  },
  "peerDependencies": {
    "tsx": "^4.21.0",
    "typescript": "^5.7.0",
    "vitest": "^4.1.2"
  }
}
```

### 3.3 型共有方針

- `shared/api-types.ts` の型 (`ServerTrace` 等) を `services/victim-web/` から import 可能とする (型のみ。実装コードは持ち込まない)
- workspaces の単一 root `package-lock.json` でロックファイルを一元管理する
- victim-web 固有の実装依存 (`@simplewebauthn/*`, `d3-*` 等) は持ち込まない

---

## 4. Phase 1-3 脆弱エンドポイント定義 (A 群 18 シナリオ対応)

### 4.1 JWT 系

#### 4.1.1 エンドポイント一覧

| URL | シナリオ ID | CWE | 攻撃ペイロード例 | 期待挙動 | 堅牢実装 |
|-----|------------|-----|----------------|---------|---------|
| `POST /jwt/verify` | jwt-alg-none, jwt-signature-stripping | CWE-345, CWE-347 | `Authorization: Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJzZWVkX2FsaWNlIiwicm9sZSI6ImFkbWluIn0.` | 200 + `{"valid":true,"claims":{...}}` | `server/routes/jwt-ops.ts` `POST /api/jwt/verify` |
| `POST /jwt/verify-kid` | jwt-kid-injection | CWE-22, CWE-90 | `{"token":"...", "kid":"../../etc/passwd"}` | 200 (パストラバーサル後の内容でキー解決を試みる) | `server/routes/jwt-ops.ts` (kid を allowlist で制限) |
| `POST /jwt/issue-weak` | jwt-weak-secret-bruteforce | CWE-326 | `{"sub":"seed_alice","role":"user"}` | 200 + 弱秘密鍵 (`"secret"`) で署名したトークン | `server/routes/jwt-ops.ts` `POST /api/jwt/sign` (強秘密鍵使用) |

#### 4.1.2 `POST /jwt/verify` 脆弱実装コード例

```typescript
// services/victim-web/src/routes/jwt.ts
// これは CWE-345 / CWE-347 の概念実証です。
// algorithms オプションを省略することで alg=none および署名ストリッピングが成立する。

import jwt from "jsonwebtoken";
import { Hono } from "hono";

const WEAK_SECRET = "secret"; // 教材用弱秘密鍵 — 本番環境では絶対に使用しないこと

export const jwtRoutes = new Hono();

// 脆弱: algorithms 未指定 → alg=none / 署名ストリッピングを受理する
jwtRoutes.post("/jwt/verify", async (c) => {
  const { token } = await c.req.json<{ token: string }>();
  try {
    // algorithms オプションを渡さない — これが脆弱性の核心
    const decoded = jwt.verify(token, WEAK_SECRET);
    return c.json({ valid: true, claims: decoded });
  } catch (err) {
    return c.json({ valid: false, error: String(err) }, 401);
  }
});

// 脆弱: kid をファイルパスとして直接使用 (CWE-22 パストラバーサル)
jwtRoutes.post("/jwt/verify-kid", async (c) => {
  const { token, kid } = await c.req.json<{ token: string; kid: string }>();
  try {
    const fs = await import("node:fs");
    // kid をサニタイズせずにファイルパスとして使用する — パストラバーサルが成立する
    const keyMaterial = fs.readFileSync(`/app/keys/${kid}`, "utf-8");
    const decoded = jwt.verify(token, keyMaterial, { algorithms: ["RS256"] });
    return c.json({ valid: true, claims: decoded });
  } catch (err) {
    return c.json({ valid: false, error: String(err) }, 401);
  }
});

// 弱秘密鍵でトークンを発行 (ブルートフォース攻撃のターゲット生成)
jwtRoutes.post("/jwt/issue-weak", async (c) => {
  const { sub, role } = await c.req.json<{ sub: string; role: string }>();
  const token = jwt.sign({ sub, role }, WEAK_SECRET, { algorithm: "HS256", expiresIn: "1h" });
  return c.json({ token, note: "教材用弱秘密鍵で署名済み" });
});
```

> **簡略化方針 (DESIGN/04 §1.3)**: kid パストラバーサルは `/app/keys/` 配下のファイル読み込みのみを示す。
> 実際のシェル実行や任意コード実行には至らない最小実装にとどめる。

### 4.2 RBAC 系

| URL | シナリオ ID | CWE | 攻撃ペイロード例 | 期待挙動 | 堅牢実装 |
|-----|------------|-----|----------------|---------|---------|
| `GET /orders/:id` | rbac-idor, rbac-horizontal-privesc | CWE-639 | `GET /orders/2` (seed_bob の注文を seed_alice が取得) | 200 + 他ユーザーのデータ | `server/routes/rbac.ts` `GET /api/rbac/orders/:id` |
| `GET /users/:id` | rbac-horizontal-privesc | CWE-639 | `GET /users/3` (seed_admin のプロフィールを一般ユーザーが取得) | 200 + 任意ユーザー情報 | `server/routes/rbac.ts` (所有者確認あり) |
| `POST /admin/:action` | rbac-vertical-privesc | CWE-285 | `{"token":"eyJ...role:admin改竄済み..."}` + `POST /admin/list-users` | 200 + 管理者操作結果 | `server/routes/rbac.ts` (role クレーム DB 照合) |
| `POST /resource` | rbac-abac-tampering | CWE-807 | `X-Department: finance` ヘッダを付与して送信 | 200 + finance リソースへのアクセス | `server/routes/rbac.ts` `POST /api/rbac/check` (ABAC ルール検証) |

**`GET /orders/:id` 脆弱実装の核心:**

```typescript
// 脆弱: 呼び出し元 user_id と :id の所有者確認を一切行わない (CWE-639)
rbacRoutes.get("/orders/:id", (c) => {
  const id = c.req.param("id");
  const row = db.prepare("SELECT * FROM victim_orders WHERE id = ?").get(id);
  if (!row) return c.json({ error: "Not found" }, 404);
  return c.json({ data: row }); // 認可チェックなしにデータを返す
});
```

### 4.3 Session 系

| URL | シナリオ ID | CWE | 攻撃ペイロード例 | 期待挙動 | 堅牢実装 |
|-----|------------|-----|----------------|---------|---------|
| `POST /session/login` | session-fixation | CWE-384 | `{"username":"seed_alice","password":"Passw0rd!","sid":"attacker-chosen-sid"}` | 200 + `Set-Cookie: sid=attacker-chosen-sid` (body の sid をそのまま Cookie にセット) | `server/routes/session-auth.ts` `POST /api/session/login` (UUID v4 を新規生成) |
| `GET /session/me` | session-xss-cookie-steal | CWE-1004 | Cookie: `sid=<有効なセッション>` | 200 + `Set-Cookie: sid=...; Path=/` (HttpOnly 属性なし) | `server/routes/session-auth.ts` (`httpOnly: true` 付与) |
| `POST /token/refresh` | session-token-replay | CWE-294 | 同一 `{"jti":"<使用済み jti>"}` を 2 回送信 | 両リクエストとも 200 + 新しいアクセストークン | `server/routes/token-auth.ts` (jti の使用済み検出) |

**`POST /session/login` 脆弱実装の核心:**

```typescript
// 脆弱: リクエスト body の sid を Set-Cookie にそのまま使用 (CWE-384 セッション固定)
sessionRoutes.post("/session/login", async (c) => {
  const { username, password, sid } = await c.req.json<{
    username: string; password: string; sid?: string;
  }>();
  const user = db.prepare("SELECT * FROM victim_users WHERE username = ?").get(username);
  if (!user || !bcrypt.compareSync(password, (user as any).password_hash)) {
    return c.json({ error: "Invalid credentials" }, 401);
  }
  // 攻撃者が指定した sid をそのまま Cookie にセット — 認証後の再生成を行わない
  const sessionId = sid ?? uuidv4();
  setCookie(c, "sid", sessionId, { path: "/", sameSite: "Lax" }); // HttpOnly なし
  return c.json({ ok: true, sessionId });
});
```

### 4.4 OAuth 系

| URL | シナリオ ID | CWE | 攻撃ペイロード例 | 期待挙動 | 堅牢実装 |
|-----|------------|-----|----------------|---------|---------|
| `GET /oauth/authorize` | oauth-state-csrf | CWE-352 | `GET /oauth/authorize?client_id=demo&redirect_uri=http://localhost:3000/callback` (state パラメータなし) | 200 + 認可コード発行 (state 検証なし) | `server/routes/oauth-sim.ts` `GET /api/oauth/authorize` (state 必須検証) |
| `POST /oauth/redirect` | oauth-redirect-uri-bypass | CWE-601 | `{"redirect_uri":"http://localhost:3000.evil.example/callback"}` | 200 + 認可コードを evil.example に転送 (startsWith 部分一致) | `server/routes/oauth-sim.ts` (完全一致 allowlist 検証) |

**`POST /oauth/redirect` 脆弱実装の核心:**

```typescript
// 脆弱: redirect_uri の検証を startsWith で行う (CWE-601 オープンリダイレクト)
oauthRoutes.post("/oauth/redirect", async (c) => {
  const { redirect_uri, code } = await c.req.json<{ redirect_uri: string; code: string }>();
  const ALLOWED_PREFIX = "http://localhost:3000";
  // startsWith は "http://localhost:3000.evil.example/" も通してしまう
  if (!redirect_uri.startsWith(ALLOWED_PREFIX)) {
    return c.json({ error: "Invalid redirect_uri" }, 400);
  }
  return c.redirect(`${redirect_uri}?code=${code}`);
});
```

### 4.5 OIDC/SAML 系 (Phase 3 / A 群 2 件)

| URL | シナリオ ID | CWE | 攻撃ペイロード例 | 期待挙動 | 堅牢実装 |
|-----|------------|-----|----------------|---------|---------|
| `POST /oidc/verify-id-token` | oidc-id-token-spoofing | CWE-290, CWE-347 | `{"id_token":"eyJ...aud:evil-client,iss:attacker.example..."}` | 200 + `{"valid":true}` (aud/iss 無検証) | `server/routes/oidc-saml-sim.ts` (aud/iss を expected 値と照合) |
| `POST /saml/consume-assertion` | saml-assertion-replay | CWE-294 | 過去の有効な SAML アサーション (NotOnOrAfter 超過) を 2 回 POST | 両リクエストとも 200 (NotOnOrAfter / InResponseTo 無検証) | `server/routes/oidc-saml-sim.ts` (NotOnOrAfter + InResponseTo + 使用済み ID 検出) |

**`POST /oidc/verify-id-token` 脆弱実装の核心:**

```typescript
// 脆弱: aud (audience) および iss (issuer) を検証しない (CWE-290)
oidcRoutes.post("/oidc/verify-id-token", async (c) => {
  const { id_token } = await c.req.json<{ id_token: string }>();
  try {
    // jwt.decode はシグネチャ検証なしでクレームを読むだけ
    const claims = jwt.decode(id_token) as Record<string, unknown>;
    // aud / iss の検証を完全に省略 — 任意の IdP のトークンを受け入れる
    return c.json({ valid: true, claims });
  } catch {
    return c.json({ valid: false }, 401);
  }
});
```

### 4.6 MFA 系

| URL | シナリオ ID | CWE | 攻撃ペイロード例 | 期待挙動 | 堅牢実装 |
|-----|------------|-----|----------------|---------|---------|
| `POST /mfa/verify` | mfa-otp-replay | CWE-294, CWE-308 | 同一 OTP (`{"otp":"123456"}`) を連続 2 回 POST | 両リクエストとも 200 + `{"ok":true}` (使用済みフラグなし) | `server/routes/mfa-totp.ts` (`used_otps` テーブルで重複検出) |

**脆弱実装の核心 (使用済みフラグを持たない):**

```typescript
// 脆弱: OTP の使用済み記録をしない (CWE-294 リプレイ攻撃が成立)
mfaRoutes.post("/mfa/verify", async (c) => {
  const { otp, username } = await c.req.json<{ otp: string; username: string }>();
  const user = db.prepare("SELECT * FROM victim_users WHERE username = ?").get(username) as any;
  if (!user) return c.json({ ok: false }, 401);
  // 固定 OTP シークレットとの TOTP 照合のみ。used フラグ / nonce テーブルなし
  const isValid = verifyTotp(otp, user.totp_secret);
  return c.json({ ok: isValid }); // 同じ OTP で何度でも通る
});
```

### 4.7 SSO/APIKey 系

| URL | シナリオ ID | CWE | 攻撃ペイロード例 | 期待挙動 | 堅牢実装 |
|-----|------------|-----|----------------|---------|---------|
| `GET /api/resource?api_key=xxx` | sso-apikey-leakage | CWE-598, CWE-200 | `GET /api/resource?api_key=seed-key-abc123` | 200 + リソースデータ (URL クエリのキーが access_log に残る) | `server/routes/sso-apikey.ts` (Authorization ヘッダのみ受理) |
| `POST /api/hmac` | sso-hmac-bypass | CWE-345 | `X-Signature` ヘッダなしで POST | 200 + `{"ok":true}` (HMAC 検証完全省略) | `server/routes/sso-apikey.ts` (HMAC-SHA256 検証必須) |
| `POST /api/replay` | sso-replay-no-timestamp | CWE-294 | 同一タイムスタンプのリクエストを 2 回 POST | 両リクエストとも 200 (タイムスタンプ・nonce 検証なし) | `server/routes/sso-apikey.ts` (timestamp ±30 秒 + replay_nonce テーブル) |

**`GET /api/resource` 脆弱実装の核心:**

```typescript
// 脆弱: API キーをクエリパラメータで受理 (CWE-598 — URL が access_log / Referer ヘッダに漏洩)
ssoRoutes.get("/api/resource", (c) => {
  const apiKey = c.req.query("api_key"); // クエリパラメータで受け取る
  if (!apiKey) return c.json({ error: "api_key required" }, 401);
  const row = db.prepare("SELECT * FROM victim_api_keys WHERE key_value = ?").get(apiKey);
  if (!row) return c.json({ error: "Invalid key" }, 403);
  return c.json({ data: "protected resource", owner: (row as any).username });
});
```

---

## 5. シードデータ (`src/seed.ts`)

### 5.1 シードユーザー定義

DESIGN/04 §5.1 の規約に従い、以下の固定シードユーザーのみを対象とする。

| 識別子 | パスワード (固定・教材用) | role | 用途 |
|-------|----------------------|------|------|
| `seed_alice` | `Passw0rd!` | user | セッション固定・トークン窃取の被害者 |
| `seed_bob` | `hunter2` | user | 権限昇格攻撃の起点 |
| `seed_admin` | `admin` | admin | 権限昇格の到達目標 |
| `attacker_charlie` | `attacker` | user | 攻撃リクエストの送信者 |

> **免責**: 上記パスワードは「弱いパスワードがなぜ危険か」を体感させる教材専用の固定値である。
> `seed_*` というプレフィックスにより実運用ユーザーとの混同を防ぐ (DESIGN/04 §2.3)。
> bcrypt rounds は教材用低コスト設定 (rounds=4) を使用する。本番環境では 12 以上を推奨。

### 5.2 `src/seed.ts` 実装例

```typescript
// services/victim-web/src/seed.ts
// 【教育目的専用】固定シードデータ — 実運用ユーザー情報は含まない
import bcrypt from "bcryptjs";
import { getDb } from "./db.js";

const SEED_ROUNDS = 4; // 教材用低コスト設定 (本番は 12 以上推奨)

export interface SeedUser {
  uuid: string;
  username: string;
  email: string;
  password_hash: string;
  role: "user" | "admin";
}

export function seedDatabase() {
  const db = getDb();
  db.exec("DELETE FROM victim_sessions; DELETE FROM victim_otp_used; DELETE FROM victim_orders; DELETE FROM victim_users;");

  const users: Omit<SeedUser, "uuid">[] = [
    { username: "seed_alice",       email: "alice@seed.example",   password_hash: bcrypt.hashSync("Passw0rd!", SEED_ROUNDS), role: "user" },
    { username: "seed_bob",         email: "bob@seed.example",     password_hash: bcrypt.hashSync("hunter2",  SEED_ROUNDS), role: "user" },
    { username: "seed_admin",       email: "admin@seed.example",   password_hash: bcrypt.hashSync("admin",    SEED_ROUNDS), role: "admin" },
    { username: "attacker_charlie", email: "charlie@seed.example", password_hash: bcrypt.hashSync("attacker", SEED_ROUNDS), role: "user" },
  ];

  const stmt = db.prepare(
    "INSERT INTO victim_users (username, email, password_hash, role) VALUES (?, ?, ?, ?)"
  );
  for (const u of users) {
    stmt.run(u.username, u.email, u.password_hash, u.role);
  }

  // 各ユーザーに対応するサンプル注文データ (IDOR 攻撃のターゲット)
  const aliceId = (db.prepare("SELECT id FROM victim_users WHERE username = ?").get("seed_alice") as any).id;
  const bobId   = (db.prepare("SELECT id FROM victim_users WHERE username = ?").get("seed_bob")   as any).id;
  const orderStmt = db.prepare("INSERT INTO victim_orders (user_id, item, amount) VALUES (?, ?, ?)");
  orderStmt.run(aliceId, "OSI Layer Guide", 2980);
  orderStmt.run(bobId,   "Security Handbook", 4980);
}
```

### 5.3 DB 初期化フロー

```
コンテナ起動
  └─ src/index.ts
       └─ initDb()        # victim-data.sqlite を /app/data/ に作成 + DDL 実行
            └─ seedDatabase()  # シードユーザー・注文データを投入

POST /api/reset
  └─ seedDatabase()       # 全テーブルを削除してシードを再投入
```

`victim-data.sqlite` は orchestrator の `server/db/data.sqlite` とは**物理的に別ファイル**であり、
`POST /api/reset` (orchestrator 側) も `docker compose restart victim-web` (victim-web 側) も
相手の DB に影響を与えない。

---

## 6. Dockerfile 方針

```dockerfile
FROM node:20-alpine
LABEL org.opencontainers.image.description="教育用脆弱アプリ — victim-web (OSI Reference)"

WORKDIR /app

# npm workspaces を活用: root の package.json + lock + victim-web のみビルド
COPY package.json package-lock.json ./
COPY services/victim-web ./services/victim-web
COPY shared ./shared

RUN npm ci --workspace=@osi-ref/victim-web --include-workspace-root=false \
    && npm run build --workspace=@osi-ref/victim-web \
    && npm prune --omit=dev --workspace=@osi-ref/victim-web

# 書き込み可能なデータディレクトリ (compose の tmpfs でマウント)
RUN mkdir -p /app/data && chown node:node /app/data

USER node
EXPOSE 4001

HEALTHCHECK --interval=10s --timeout=2s --retries=3 \
    CMD wget -q -O- http://localhost:4001/health || exit 1

CMD ["node", "services/victim-web/dist/index.js"]
```

### 6.1 compose 側の安全設定

```yaml
# docker-compose.yml (抜粋)
services:
  victim-web:
    build:
      context: .
      dockerfile: services/victim-web/Dockerfile
    networks:
      - victim-net          # orchestrator からのみ到達可。external egress なし
    ports: []               # ホスト側ポートは公開しない (victim-net 内部のみ)
    environment:
      - NODE_ENV=development
      - PORT=4001
    volumes:
      - type: tmpfs
        target: /app/data   # victim-data.sqlite を tmpfs に配置 (再起動でリセット)
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    read_only: true         # tmpfs マウントを除きファイルシステム書き込み禁止
    tmpfs:
      - /tmp
    mem_limit: 256m
    pids_limit: 128

networks:
  victim-net:
    driver: bridge
    internal: true          # OS レイヤで egress を遮断
```

### 6.2 `--read-only` 対応

victim-data.sqlite の書き込みは `volumes: - type: tmpfs target: /app/data` で対応する。
コンテナ再起動時に tmpfs はクリアされるため、シードデータは起動時に毎回再投入される。
永続化が必要な場合は `victim-db` named volume を使用する (compose のコメントで両案を提示)。

---

## 7. エラーハンドリング

victim-web は意図的に脆弱だが、**教材として常時起動可能**であることを保証するため、
クラッシュや信頼性問題は避ける。

| エラー種別 | 対応方針 |
|-----------|---------|
| DB prepare 失敗・テーブル不在 | 500 + `{"error":"Internal error","detail":"<メッセージ>"}` で返す。`process.exit` しない |
| リクエスト body parse 失敗 | 400 + `{"error":"Invalid request body"}` (zod は使わず、`JSON.parse` try-catch のみ) |
| シード未投入状態での参照 | 503 + `{"error":"Seed not ready","hint":"POST /api/reset"}` |
| /health エンドポイント | 常に 200 + `{"status":"ok","service":"victim-web"}` を返す |

**最小バリデーション方針**: zod を依存に含めない。`typeof` / `in` 演算子による型ガードのみ使用する。
これにより victim-web の依存を軽量に保ち、起動時間を短縮する。

---

## 8. テスト要件

配置: `services/victim-web/__tests__/` (vitest)

```typescript
// services/victim-web/__tests__/jwt.test.ts の例
import { describe, it, expect } from "vitest";

describe("jwt-vuln: POST /jwt/verify", () => {
  it("alg=none トークンを 200 で受理すること (CWE-345 概念実証)", async () => {
    const algNoneToken = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJzZWVkX2FsaWNlIiwicm9sZSI6ImFkbWluIn0.";
    const res = await fetch("http://localhost:4001/jwt/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: algNoneToken }),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.valid).toBe(true);
    expect(body.claims.role).toBe("admin");
  });
});
```

### 8.1 必須テストケース一覧

- [ ] `POST /jwt/verify` — alg=none トークンで 200 + `valid: true` が返ること
- [ ] `POST /jwt/verify` — 署名ストリッピングトークンで 200 + `valid: true` が返ること
- [ ] `POST /jwt/verify-kid` — `kid: "../../etc/hostname"` 等パストラバーサルパスでエラーなく応答すること
- [ ] `POST /jwt/issue-weak` — 弱秘密鍵 (`"secret"`) で署名されたトークンが返ること
- [ ] `GET /orders/1` — 認可ヘッダなしで 200 + 注文データが返ること
- [ ] `GET /orders/2` — seed_alice のセッションで seed_bob の注文が取得できること
- [ ] `POST /session/login` — body の `sid` が Set-Cookie にそのまま使われること
- [ ] `GET /session/me` — Cookie ヘッダに `HttpOnly` 属性が**ない**こと
- [ ] `POST /token/refresh` — 同一 jti で 2 回とも 200 が返ること
- [ ] `GET /oauth/authorize` — `state` なしで認可コードが発行されること
- [ ] `POST /oauth/redirect` — `http://localhost:3000.evil.example/` が通ること
- [ ] `POST /oidc/verify-id-token` — `aud` / `iss` が不正でも 200 が返ること
- [ ] `POST /saml/consume-assertion` — 期限切れアサーションを 2 回とも受理すること
- [ ] `POST /mfa/verify` — 同一 OTP を 2 回送信して両方 200 が返ること
- [ ] `GET /api/resource?api_key=...` — クエリパラメータのキーで 200 が返ること
- [ ] `POST /api/hmac` — `X-Signature` ヘッダなしで 200 が返ること
- [ ] `POST /api/replay` — 同一タイムスタンプで 2 回とも 200 が返ること
- [ ] `POST /api/reset` — シードデータが再構築されること (ユーザー数 4 件)
- [ ] `GET /health` — 常に 200 + `{"status":"ok"}` が返ること
- [ ] `victim-data.sqlite` と `server/db/data.sqlite` が別プロセスから独立していること

---

## 9. 既存 `server/routes/*.ts` との対応関係

| 攻撃シナリオ ID | victim-web エンドポイント (脆弱) | 堅牢実装 (orchestrator 既存) | 脆弱性の核心 |
|---------------|-------------------------------|---------------------------|-------------|
| jwt-alg-none | `POST /jwt/verify` | `server/routes/jwt-ops.ts` `POST /api/jwt/verify` | `algorithms` 未指定 |
| jwt-signature-stripping | `POST /jwt/verify` | 同上 | `algorithms` 未指定 |
| jwt-kid-injection | `POST /jwt/verify-kid` | `server/routes/jwt-ops.ts` (kid allowlist) | kid をパスとして使用 |
| jwt-weak-secret-bruteforce | `POST /jwt/issue-weak` | `server/routes/jwt-ops.ts` `POST /api/jwt/sign` | 弱秘密鍵 `"secret"` |
| rbac-idor | `GET /orders/:id` | `server/routes/rbac.ts` `POST /api/rbac/check` | 認可チェックなし |
| rbac-horizontal-privesc | `GET /users/:id` | `server/routes/rbac.ts` | 所有者確認なし |
| rbac-vertical-privesc | `POST /admin/:action` | `server/routes/rbac.ts` | role クレームを DB 照合せず信用 |
| rbac-abac-tampering | `POST /resource` | `server/routes/rbac.ts` (ABAC ルール) | X-Department ヘッダを無条件信頼 |
| session-fixation | `POST /session/login` | `server/routes/session-auth.ts` `POST /api/session/login` | 認証後セッション ID 再生成なし |
| session-xss-cookie-steal | `GET /session/me` | `server/routes/session-auth.ts` | HttpOnly 属性なし |
| session-token-replay | `POST /token/refresh` | `server/routes/token-auth.ts` `/refresh` | jti 重複検出なし |
| oauth-state-csrf | `GET /oauth/authorize` | `server/routes/oauth-sim.ts` `GET /api/oauth/authorize` | state パラメータ必須化なし |
| oauth-redirect-uri-bypass | `POST /oauth/redirect` | `server/routes/oauth-sim.ts` (allowlist 完全一致) | startsWith 部分一致検証 |
| oidc-id-token-spoofing | `POST /oidc/verify-id-token` | `server/routes/oidc-saml-sim.ts` | aud/iss 検証なし |
| saml-assertion-replay | `POST /saml/consume-assertion` | `server/routes/oidc-saml-sim.ts` | NotOnOrAfter / InResponseTo 無検証 |
| mfa-otp-replay | `POST /mfa/verify` | `server/routes/mfa-totp.ts` `POST /api/mfa/totp/*` | 使用済み OTP フラグなし |
| sso-apikey-leakage | `GET /api/resource` | `server/routes/sso-apikey.ts` | URL クエリパラメータでキーを受理 |
| sso-hmac-bypass | `POST /api/hmac` | `server/routes/sso-apikey.ts` (HMAC-SHA256) | X-Signature 未検証で通過 |
| sso-replay-no-timestamp | `POST /api/replay` | `server/routes/sso-apikey.ts` (replay_nonce) | タイムスタンプ・nonce 検証なし |

この対応表は `AttackDefensePanel` の「防御策コードへのリンク」として参照される。

---

## 10. 将来拡張

### 10.1 Phase 4 コンテナ (本仕様のスコープ外)

| コンテナ | 対応 B 群シナリオ | 仕様書 |
|---------|----------------|-------|
| `services/victim-tls-proxy/` (nginx + 旧 openssl) | tls-version-downgrade, tls-self-signed-mitm, tls-weak-cipher | DESIGN/35 (予定) |
| `services/victim-saml-idp/` (python + xmlsec1 または Hono) | saml-xsw, pass-the-ticket | DESIGN/36 (予定) |

これらは `victim-net` に追加接続するだけで orchestrator の `VICTIM_ALLOWLIST` に新エントリを追加すれば到達可能になる設計とする。

### 10.2 Phase 5 整理方針

C 群 11 件 + D 群 4 件は victim-web に対応エンドポイントを追加しない。
これらは既存 `server/routes/*.ts` の `/attack/*` パスで引き続きナレーション型として提供し、
Phase 5 で `SIMULATION` / `DEFENSE DEMO` バッジを付与して UI 整理を行う。

### 10.3 A 群 bruteforce-noratelimit の扱い

シナリオ #3 (`auth-methods/bruteforce-noratelimit`) は `POST /login` (rate limit なし) を victim-web に追加することで対応する。
attacker-shell (`--pids-limit=64`) からの辞書ループ (上限 20 回) を orchestrator が中継する形を取り、
フロントエンドで実際のループを実行することはない (DESIGN/04 §1.3 簡略化原則)。
本エンドポイントは Phase 2 の PoC 5 件には含まれず、Phase 3 バンドル PR で追加する。

---

## 11. ソースファイル冒頭コメント規約

`services/victim-web/src/routes/*.ts` の先頭には以下のブロックを必ず含める。

```typescript
/**
 * 脆弱エンドポイント: <エリア名>
 *
 * 【教育目的専用】
 * このファイルは OSI 参照アプリの教材機能として、
 * victim-net 内の固定シードデータに対する概念実証を提供します。
 *
 * - 外部ネットワークへのリクエストは行いません
 * - 実 CVE のエクスプロイトコードは含みません
 * - victim-net 外での動作は想定していません
 *
 * 対応 CWE: CWE-xxx, CWE-yyy
 * 堅牢実装: server/routes/<area>.ts
 * 関連設計書: DESIGN/04-safety-guardrails.md, DESIGN/32-victim-web-spec.md
 */
```

---

## 関連ファイル

### 上流設計

| ファイル | 関係 |
|---------|-----|
| `DESIGN/30-live-attack-architecture.md` | 全体アーキテクチャ・シナリオ分類表 (A/B/C/D)・Phase ロードマップ |
| `DESIGN/04-safety-guardrails.md` | 4 原則 (隔離・明示・簡略化・防御策併記)、禁止表現一覧 §2.3、シードユーザー規約 §5.1 |

### 同列設計

| ファイル | 関係 |
|---------|-----|
| `DESIGN/31-orchestrator-spec.md` | `POST /api/orchestrator/exec` — 本仕様の victim-web を `target` として呼び出す側 |
| `DESIGN/33-raw-http-composer.md` | RawHttpComposer フロント UI — 学習者が攻撃リクエストを組み立てる入口 |
| `DESIGN/34-safety-guardrails-live.md` | live 化安全装置の詳細 (`VICTIM_ALLOWLIST`, `internal: true` 等) |

### 堅牢実装 (防御側の対比対象)

| ファイル | 対応する攻撃エリア |
|---------|----------------|
| `server/routes/jwt-ops.ts` | JWT 系 3 シナリオ |
| `server/routes/rbac.ts` | RBAC 系 4 シナリオ |
| `server/routes/session-auth.ts` | Session 系 (fixation, xss-cookie) |
| `server/routes/token-auth.ts` | Session 系 (token-replay) |
| `server/routes/oauth-sim.ts` | OAuth 系 2 シナリオ |
| `server/routes/oidc-saml-sim.ts` | OIDC/SAML 系 2 シナリオ |
| `server/routes/mfa-totp.ts` | MFA 系 1 シナリオ |
| `server/routes/sso-apikey.ts` | SSO/APIKey 系 3 シナリオ |

### シード規約

| ファイル | 関係 |
|---------|-----|
| `DESIGN/04-safety-guardrails.md` §5 | シードユーザー定義・リセット仕様の基準 |
| `server/db/schema.ts` `seedDb()` | orchestrator 側の実装参考 (同じ seed_alice / seed_bob 規約を踏襲) |
