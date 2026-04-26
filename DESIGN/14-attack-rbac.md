---
title: 攻撃デモカタログ — rbac (アクセス制御) 攻撃詳細
phase: design
last-updated: 2026-04-26
safety-reviewed: false
---

## 教育目的

本ファイルは **教育用シミュレーション** の実装設計である。
記載された攻撃手法は `localhost` 上の固定シードデータに対してのみ動作するよう設計されており、
実環境への攻撃を意図したものではない。

攻撃シミュレーションはすべて「この防御がなぜ必要か」を体感するための概念実証であり、
各シナリオには必ず防御策の解説と実装例が対になっている。

---

# 14. rbac タブ — アクセス制御攻撃詳細 (4シナリオ)

## 1. 概要

`rbac` タブ (アクセス制御) はロールベース (RBAC)・属性ベース (ABAC)・ACL の3モデルをインタラクティブに学ぶデモを提供している。
本設計書では、このタブに Attacker View を追加し、アクセス制御の実装漏れや設計ミスがどのような攻撃に
つながるかを4シナリオで体感させる。

### 対象認証タブ

| フィールド | 値 |
|------------|-----|
| タブ ID | `rbac` |
| コンポーネント | `src/components/auth/PermissionModel.tsx` |
| バックエンドルート | `server/routes/rbac.ts` |
| 攻撃ルート (追加先) | `server/routes/rbac.ts` |
| スコープ ID | `"attack-rbac"` |

### 学習目標

学習者はこの4シナリオを通じて次の知識を体得する:

1. **IDOR**: リソースへの直接参照を ID で行う API が認可チェックなしに他者のデータを返す
2. **水平権限昇格**: 同一ロールの別ユーザーのリソースに `owner_id` チェックなしでアクセスできる
3. **垂直権限昇格**: RBAC ミドルウェアが存在しない管理者専用エンドポイントに一般ユーザーがアクセスできる
4. **ABAC 属性改竄**: クライアント側で送信する属性値 (`department` 等) を改竄するとポリシー判定が覆る

---

## 2. 攻撃シナリオ一覧テーブル

| # | シナリオ ID | 名前 | CWE | CAPEC | OSI 層 | 深刻度 |
|---|-------------|------|-----|-------|--------|--------|
| A | `rbac-idor` | IDOR (直接オブジェクト参照) | CWE-639 | CAPEC-77 | L7 | High |
| B | `rbac-horizontal-privilege-escalation` | 水平権限昇格 | CWE-639 | CAPEC-122 | L7 | High |
| C | `rbac-vertical-privilege-escalation` | 垂直権限昇格 | CWE-269 | CAPEC-233 | L7 | Critical |
| D | `rbac-abac-attribute-tampering` | ABAC 属性改竄 | CWE-807 | CAPEC-153 | L7 | High |

### 深刻度の根拠

| シナリオ | 深刻度 | 根拠 |
|----------|--------|------|
| IDOR | High | 他ユーザーのプロファイル・ドキュメントが漏洩する。影響範囲は水平方向のユーザーデータ全体 |
| 水平権限昇格 | High | 役割は正規でも、`owner_id` 検証が欠如すると任意ユーザーのリソースに読み書き可能 |
| 垂直権限昇格 | Critical | 一般ユーザーが管理者操作 (ユーザー削除等) を直接実行できる。アカウント乗っ取り・サービス破壊につながる |
| ABAC 属性改竄 | High | 属性をクライアントから受け取る設計は、正規ユーザーがポリシーを意図的に回避できる |

---

## 3. 既存防御側実装 (RBAC/ABAC/ACL の評価ロジック)

### 3.1 RBAC 評価 (`server/routes/rbac.ts`)

既存の `POST /api/rbac/check` ハンドラは以下の3ステップで RBAC を評価する:

```
1. users テーブルから subject (username) を検索 → NOT_FOUND なら拒否
2. user_roles + roles テーブルで対象ユーザーのロール一覧を取得
3. role_permissions + permissions テーブルで resource:action に一致する権限を検索
   → 一致あり = ALLOW / 一致なし = DENY
```

**重要な観察**: 既存実装は「対象ユーザーがそのリソースタイプを操作できるロール権限を持つか」のみを
評価する。**リソースの具体的な所有者 (owner_id) の検証は行われていない。** これがシナリオ A・B の
脆弱ポイントとなる。

### 3.2 ABAC 評価 (`server/routes/rbac.ts`)

`POST /api/rbac/abac/check` はクライアントから受け取った `context` オブジェクトを
そのままポリシー評価に使用する:

```typescript
const { subject, resource, action, context = {} } = parsed.data;
const ctx = context as Record<string, string | number | boolean | undefined>;

// "department-match" ポリシー:
check: () => !ctx.department || ctx.department === ctx.resourceDepartment,
```

**重要な観察**: `department`・`resourceDepartment` ともにクライアント送信値をそのまま使用している。
攻撃者はリクエストボディの `context.department` を任意の値に書き換えられる。これがシナリオ D の
脆弱ポイントとなる。

### 3.3 DB テーブル構造 (rbac 関連)

`server/db/schema.ts` で定義されている関連テーブル:

| テーブル | 主なカラム | 役割 |
|----------|-----------|------|
| `users` | id, username, password_hash | ユーザー基本情報 |
| `roles` | id, name, description | ロール定義 (admin/editor/viewer) |
| `user_roles` | user_id, role_id | ユーザー ↔ ロールの多対多 |
| `permissions` | id, name, resource, action | 権限定義 (articles:read 等) |
| `role_permissions` | role_id, permission_id | ロール ↔ 権限の多対多 |

シードデータのロール権限割り当て:

| ロール | 権限 |
|--------|------|
| admin | articles:read/write/delete, users:read/write/delete, settings:read/write/delete |
| editor | articles:read/write, users:read |
| viewer | articles:read, users:read, settings:read |

**注意**: 既存スキーマにはリソースの `owner_id` カラムが存在しない。攻撃シナリオ A・B では
`attack_log` 用データとして固定シードのリソースオブジェクトをサーバー側で模擬する。

### 3.4 既存 UI (`src/components/auth/PermissionModel.tsx`)

- `mode` Signal で RBAC / ABAC / ACL / Policy の4モードを切り替え
- `AccessCheckDemo` コンポーネントが `POST /api/rbac/check` 等を呼び出し評価ステップを表示
- `DataFlowPanel` (scopeId `"rbac-check"`) で DB クエリを可視化

Attacker View は `ViewModeToggle` を `PermissionModel.tsx` 末尾に追加し、
`<Show when={viewMode() === "attacker"}>` で `RbacAttackPanel` を表示する。
`RbacAttackPanel` は `src/components/auth/attacks/rbac/RbacAttackPanel.tsx` として新規作成する
(DESIGN/12 の `OAuthAttackPanel` と同一命名規則 — タブ固有パネル)。

---

## 4. シナリオ詳細

### 4.1 シナリオ A — IDOR (直接オブジェクト参照)

#### 基本情報

| フィールド | 値 |
|------------|-----|
| シナリオ ID | `rbac-idor` |
| 攻撃エンドポイント | `GET /api/rbac/attack/idor?victimId=<id>` |
| 深刻度 | High |
| CWE | CWE-639 (Authorization Bypass Through User-Controlled Key) |
| CAPEC | CAPEC-77 (Manipulating User-Controlled Variables) |
| OSI 層 | L7 (Application) |

#### 攻撃概要

これは **CWE-639 / CAPEC-77** の概念実証である。
API がユーザー ID などの直接オブジェクト参照をクライアントに操作させ、サーバー側で
認可チェック (「そのリソースにアクセスする権限があるか」) を省略している場合、
攻撃者は URL パラメータを変更するだけで任意ユーザーのデータを取得できる。

#### 攻撃フロー

```
攻撃者 (attacker_charlie, editor ロール)
  │
  ├─ Step 1: 自分自身のリソースを正常取得
  │    GET /api/rbac/attack/idor?victimId=3
  │    → 200 OK: { id: 3, username: "attacker_charlie", ... }
  │
  ├─ Step 2: victimId を別ユーザーに変更して送信 (認可チェックなし)
  │    GET /api/rbac/attack/idor?victimId=1
  │    → 200 OK: { id: 1, username: "seed_alice", email: "alice@example.com", ... }
  │    ※ 認可チェックが存在しないためそのまま返却される
  │
  └─ Step 3: 結果確認 — 他ユーザーのプロファイルが漏洩
```

#### AttackStep[] 定義

```typescript
// src/components/auth/attacks/scenarios/rbac-scenarios.ts
const idorSteps: AttackStep[] = [
  {
    id: "rbac-idor-s1",
    kind: "probe",
    label: "Access own profile (normal)",
    labelJa: "自分のプロファイルを正常取得",
    status: "success",
    payload: {
      type: "http",
      request: {
        method: "GET",
        url: "/api/rbac/attack/idor?victimId=3",
        headers: { "Authorization": "Bearer <seed_charlie_token>" },
      },
      response: {
        status: 200,
        body: { id: 3, username: "attacker_charlie", role: "editor" },
      },
    },
    detail: "Attacker accesses their own resource to confirm the endpoint exists.",
    detailJa: "攻撃者が自分自身のリソースにアクセスし、エンドポイントの存在を確認します。",
    timestamp: 0,
  },
  {
    id: "rbac-idor-s2",
    kind: "tamper",
    label: "Change victimId to another user's ID",
    labelJa: "victimId を別ユーザーの ID に変更",
    status: "success",
    payload: {
      type: "http",
      request: {
        method: "GET",
        url: "/api/rbac/attack/idor?victimId=1",
        headers: { "Authorization": "Bearer <seed_charlie_token>" },
      },
      tamperedFields: ["victimId"],
    },
    detail: "Attacker changes the victimId parameter to target another user's resource.",
    detailJa: "攻撃者は victimId パラメータを変更して別ユーザーのリソースを狙います。",
    timestamp: 0,
  },
  {
    id: "rbac-idor-s3",
    kind: "exploit",
    label: "Other user's profile returned without ownership check",
    labelJa: "所有者チェックなし — 他ユーザーのプロファイルが返却",
    status: "success",
    payload: {
      type: "http",
      response: {
        status: 200,
        body: { id: 1, username: "seed_alice", email: "alice@example.com", role: "viewer" },
      },
    },
    detail: "The server returns the target user's data because no owner check is performed.",
    detailJa: "サーバーは所有者チェックを行わないため、対象ユーザーのデータをそのまま返します。",
    timestamp: 0,
  },
];
```

#### バックエンド実装仕様 (`server/routes/rbac.ts` への追加)

```typescript
/**
 * 攻撃デモルート: IDOR (Insecure Direct Object Reference)
 *
 * 【教育目的専用】
 * このエンドポイントは owner_id チェックを意図的に省略した脆弱な実装をシミュレーションします。
 * 対象 CWE: CWE-639
 * 対象 CAPEC: CAPEC-77
 * 関連設計書: DESIGN/04-safety-guardrails.md, DESIGN/14-attack-rbac.md
 */
rbacRoutes.get("/attack/idor", async (c) => {
  const trace = c.get("trace");
  const victimId = Number(c.req.query("victimId") ?? "0");

  // シードユーザーデータ (固定値 — 実 DB アクセスなし)
  const SEED_USERS: Record<number, { id: number; username: string; email: string; role: string }> = {
    1: { id: 1, username: "seed_alice",          email: "alice@example.com",   role: "viewer" },
    2: { id: 2, username: "seed_bob",             email: "bob@example.com",     role: "editor" },
    3: { id: 3, username: "attacker_charlie",     email: "charlie@example.com", role: "editor" },
    4: { id: 4, username: "seed_admin",           email: "admin@example.com",   role: "admin"  },
  };

  const t0 = performance.now();
  const victim = SEED_USERS[victimId];

  trace.addDbQuery({
    sql: "SELECT id, username, email, role FROM users WHERE id = ?  -- ※ owner_id チェックなし",
    params: [victimId],
    rows: victim ? [victim] : [],
    ms: performance.now() - t0,
  });

  // Step 1: 認証チェック (常に attacker_charlie として認証済み想定)
  trace.addAttackStep({
    id: "rbac-idor-s1",
    kind: "probe",
    label: "Request received with victimId parameter",
    labelJa: `victimId=${victimId} のリクエストを受信`,
    status: "success",
  });

  if (!victim) {
    return c.json({ success: false, error: "User not found" }, 404);
  }

  // Step 2: 脆弱な実装 — owner_id チェックなしでそのまま返却
  trace.addAttackStep({
    id: "rbac-idor-s2",
    kind: "exploit",
    label: "Returning resource without ownership verification",
    labelJa: "所有者検証なしでリソースを返却 (脆弱)",
    status: "success",
    detail: "ownershipCheck: false — 認証ユーザーとリソース所有者の一致確認が存在しない",
    detailJa: "ownershipCheck: false — 認証ユーザーとリソース所有者の一致確認が存在しない",
  });

  const result: AttackResult = {
    scenarioId: "rbac-idor",
    outcome: "succeeded",
    startedAt: Date.now(),
    finishedAt: Date.now(),
    steps: [],
    summary: "This implementation is vulnerable: no ownership check was performed. The server returned another user's data based solely on the user-controlled 'victimId' parameter.",
    summaryJa: "この実装は脆弱です: 所有者チェックが存在しません。サーバーはユーザーが操作できる 'victimId' パラメータだけを根拠に別ユーザーのデータを返しました。",
  };

  return c.json({
    success: true,
    data: { profile: victim, attackResult: result },
  });
});
```

#### 防御策

| 防御策 | 実装方法 |
|--------|---------|
| owner_id チェック | `WHERE id = ? AND owner_id = <authenticated_user_id>` でリソース所有者を確認する |
| 間接参照マップ | ユーザーに渡す ID をランダムな不透明トークンにし、サーバー側でマッピングする |
| 認可ミドルウェア | 全リソースアクセスに `canAccess(userId, resourceId)` 関数を強制的に通す |

```typescript
// codeHints[0]: owner_id による所有者チェック
const resource = db.prepare(
  "SELECT * FROM user_profiles WHERE id = ? AND owner_id = ?"
).get(requestedId, authenticatedUserId);
if (!resource) return c.json({ error: "Forbidden" }, 403);

// codeHints[1]: 認可ヘルパー関数パターン
function canAccessResource(
  db: Database,
  resourceId: number,
  requestingUserId: number
): boolean {
  const row = db.prepare(
    "SELECT owner_id FROM resources WHERE id = ?"
  ).get(resourceId) as { owner_id: number } | undefined;
  return row?.owner_id === requestingUserId;
}
```

#### 実環境との差異 (必須付記)

「実環境では WAF やレート制限が連続した ID 列挙を検出し、アラートを発する場合があります。
しかしアプリケーションレベルの owner_id チェックがない限り、単一の IDOR リクエストは
これらの防御を素通りします。」

---

### 4.2 シナリオ B — 水平権限昇格

#### 基本情報

| フィールド | 値 |
|------------|-----|
| シナリオ ID | `rbac-horizontal-privilege-escalation` |
| 攻撃エンドポイント | `POST /api/rbac/attack/horizontal-escalation` |
| 深刻度 | High |
| CWE | CWE-639 (Authorization Bypass Through User-Controlled Key) |
| CAPEC | CAPEC-122 (Privilege Abuse) |
| OSI 層 | L7 (Application) |

#### 攻撃概要

これは **CWE-639 / CAPEC-122** の概念実証である。
水平権限昇格では、攻撃者と被害者のロールが同一 (例: 両者ともに `editor`) であっても、
リソースの所有者チェック (`owner_id` 比較) が欠如している場合、攻撃者は被害者のリソースを
読み取り・書き換えることができる。RBAC が「何を操作できるか (resource:action)」を定義する一方で、
「誰のリソースを操作できるか」の検証は別途実装する必要がある。

#### 攻撃フロー

```
攻撃者 (seed_bob, editor ロール)  vs  被害者 (seed_alice, viewer ロール)
  │
  ├─ Step 1: 攻撃者の認証 — editor ロールでログイン
  │    POST /api/rbac/attack/horizontal-escalation
  │    body: { attackerRole: "editor", targetUserId: 1, action: "read" }
  │
  ├─ Step 2: RBAC チェック — editor は articles:read を持つ → ALLOW
  │    (ロールレベルの確認は通過。所有者チェックは未実施)
  │
  ├─ Step 3: 所有者チェックなしでリソース返却
  │    seed_alice の記事 (owner_id=1) が seed_bob (userId=2) に返却される
  │
  └─ Step 4: 結果確認 — 水平昇格が成立 (同一階層の他者リソースにアクセス)
```

#### AttackStep[] 定義

```typescript
const horizontalEscalationSteps: AttackStep[] = [
  {
    id: "rbac-horiz-s1",
    kind: "probe",
    label: "Verify attacker's role (editor)",
    labelJa: "攻撃者のロール (editor) を確認",
    status: "success",
    payload: {
      type: "generic",
      data: {
        attackerUser: "seed_bob",
        attackerRole: "editor",
        targetUser: "seed_alice",
        targetUserId: 1,
      },
    },
    timestamp: 0,
  },
  {
    id: "rbac-horiz-s2",
    kind: "verify",
    label: "RBAC check: editor has articles:read → ALLOW",
    labelJa: "RBAC チェック: editor は articles:read を持つ → ALLOW (ロールレベルは通過)",
    status: "success",
    payload: {
      type: "generic",
      data: {
        rbacResult: "ALLOW",
        reason: "role=editor has articles:read permission",
        ownershipCheckPerformed: false,
      },
    },
    timestamp: 0,
  },
  {
    id: "rbac-horiz-s3",
    kind: "exploit",
    label: "Horizontal escalation: seed_alice's article returned to seed_bob",
    labelJa: "水平権限昇格成立: seed_alice の記事が seed_bob に返却",
    status: "success",
    payload: {
      type: "http",
      response: {
        status: 200,
        body: {
          articleId: 42,
          title: "seed_alice の非公開メモ",
          ownerId: 1,
          content: "...(seed_alice のプライベートコンテンツ)...",
        },
      },
    },
    timestamp: 0,
  },
  {
    id: "rbac-horiz-s4",
    kind: "verify",
    label: "Confirm: same role level, different user's data leaked",
    labelJa: "確認: 同一ロール階層のまま、別ユーザーのデータが漏洩",
    status: "success",
    payload: {
      type: "generic",
      data: {
        attackerUserId: 2,
        victimUserId: 1,
        rolesAreEqual: true,
        ownershipViolated: true,
      },
    },
    timestamp: 0,
  },
];
```

#### バックエンド実装仕様 (`server/routes/rbac.ts` への追加)

```typescript
/**
 * 攻撃デモルート: 水平権限昇格
 *
 * 【教育目的専用】
 * RBAC のロール確認のみを行い、owner_id チェックを省略した脆弱な実装をシミュレーションします。
 * 対象 CWE: CWE-639
 * 対象 CAPEC: CAPEC-122
 */
rbacRoutes.post("/attack/horizontal-escalation", async (c) => {
  const trace = c.get("trace");
  const body = await c.req.json().catch(() => ({}));
  const { attackerRole = "editor", targetUserId = 1, action = "read" } = body;

  // シードリソース (固定) — seed_alice が所有する記事
  const SEED_ALICE_ARTICLE = {
    articleId: 42,
    title: "seed_alice の非公開メモ",
    ownerId: 1,
    content: "(seed_alice のプライベートコンテンツ — 教育用デモデータ)",
  };

  const SEED_ROLE_PERMISSIONS: Record<string, string[]> = {
    admin:  ["articles:read", "articles:write", "articles:delete", "users:read"],
    editor: ["articles:read", "articles:write", "users:read"],
    viewer: ["articles:read"],
  };

  const t0 = performance.now();

  // Step 1: RBAC チェック (ロールレベルのみ — 所有者チェックなし)
  const rbacPermissions = SEED_ROLE_PERMISSIONS[attackerRole] ?? [];
  const rbacAllowed = rbacPermissions.includes(`articles:${action}`);

  trace.addDbQuery({
    sql: "SELECT permissions FROM role_permissions WHERE role_name = ?",
    params: [attackerRole],
    rows: [{ role: attackerRole, permissions: rbacPermissions }],
    ms: performance.now() - t0,
  });

  trace.addAttackStep({
    id: "rbac-horiz-s1",
    kind: "verify",
    label: `RBAC check: role=${attackerRole} → articles:${action}: ${rbacAllowed ? "ALLOW" : "DENY"}`,
    labelJa: `RBAC チェック: role=${attackerRole} → articles:${action}: ${rbacAllowed ? "ALLOW" : "DENY"}`,
    status: rbacAllowed ? "success" : "blocked",
    detail: "RBAC confirms the role has the permission, but owner_id is never verified.",
    detailJa: "RBAC はロールが権限を持つことを確認するが、owner_id は一切検証されない。",
  });

  if (!rbacAllowed) {
    return c.json({
      success: true,
      data: {
        attackResult: {
          scenarioId: "rbac-horizontal-privilege-escalation",
          outcome: "blocked",
          blockedBy: "rbac_permission_denied",
          summaryJa: "防御が機能しました: RBAC がロールに権限がないことを検出して拒否しました。",
        },
      },
    });
  }

  // Step 2: 脆弱な実装 — owner_id チェックなしでリソース返却
  trace.addAttackStep({
    id: "rbac-horiz-s2",
    kind: "exploit",
    label: "Returning resource without owner_id check (vulnerable)",
    labelJa: "owner_id チェックなしでリソースを返却 (脆弱な実装)",
    status: "success",
    detail: `ownerId=${SEED_ALICE_ARTICLE.ownerId}, attackerUserId=2 — mismatch not detected`,
    detailJa: `ownerId=${SEED_ALICE_ARTICLE.ownerId}, attackerUserId=2 — 不一致が検出されていない`,
  });

  const result: AttackResult = {
    scenarioId: "rbac-horizontal-privilege-escalation",
    outcome: "succeeded",
    startedAt: Date.now(),
    finishedAt: Date.now(),
    steps: [],
    summary: "This implementation is vulnerable: RBAC verified the role but did not check resource ownership (owner_id). A same-level user was able to access another user's private resource.",
    summaryJa: "この実装は脆弱です: RBAC がロールを確認しましたが、リソースの所有者 (owner_id) を検証しませんでした。同一ロールの別ユーザーが他者のプライベートリソースにアクセスできました。",
  };

  return c.json({
    success: true,
    data: { resource: SEED_ALICE_ARTICLE, attackResult: result },
  });
});
```

#### 防御策

| 防御策 | 実装方法 |
|--------|---------|
| owner_id チェック | ロール確認後に `WHERE id = ? AND owner_id = <authenticatedUserId>` を必ず追加する |
| リソースレベル認可 | `canAccessResource(authenticatedUserId, articleId)` ヘルパーをすべてのリソースアクセスに強制適用 |
| OPA / Cedar | ポリシーエンジンでリソース属性 (owner) をポリシー条件に組み込む |

```typescript
// codeHints[0]: owner_id を含むクエリ
const article = db.prepare(
  "SELECT * FROM articles WHERE id = ? AND owner_id = ?"
).get(articleId, authenticatedUserId);
if (!article) return c.json({ error: "Forbidden: you do not own this resource" }, 403);

// codeHints[1]: リソースレベル認可ヘルパー
function assertResourceOwner(
  db: Database,
  table: string,
  resourceId: number,
  userId: number
): void {
  const row = db.prepare(
    `SELECT owner_id FROM ${table} WHERE id = ?`
  ).get(resourceId) as { owner_id: number } | undefined;
  if (!row || row.owner_id !== userId) {
    throw new ForbiddenError("Resource ownership check failed");
  }
}
```

#### 実環境との差異 (必須付記)

「実環境では多くのフレームワーク (Django REST Framework の `IsObjectOwner` パーミッション等) が
リソースレベルの認可を提供しますが、これを正しく設定しない場合は本シナリオと同様の脆弱性が発生します。」

---

### 4.3 シナリオ C — 垂直権限昇格

#### 基本情報

| フィールド | 値 |
|------------|-----|
| シナリオ ID | `rbac-vertical-privilege-escalation` |
| 攻撃エンドポイント | `POST /api/rbac/attack/vertical-escalation` |
| 深刻度 | Critical |
| CWE | CWE-269 (Improper Privilege Management) |
| CAPEC | CAPEC-233 (Privilege Abuse) |
| OSI 層 | L7 (Application) |

#### 攻撃概要

これは **CWE-269 / CAPEC-233** の概念実証である。
垂直権限昇格では、一般ユーザー (ロール: `user`/`viewer`) が管理者専用エンドポイント
(`POST /api/rbac/admin/users/delete` 等) に直接 HTTP リクエストを送ることで、
本来は管理者しかできない操作を実行できてしまう。RBAC ミドルウェアが管理者エンドポイントの前に
配置されていない場合、ロールチェックは行われず操作が成功してしまう。

本シナリオは「脆弱な実装 (ミドルウェアなし)」と「防御された実装 (ミドルウェアあり)」の
比較デモとして提供する。

#### 攻撃フロー

```
攻撃者 (seed_bob, viewer ロール)
  │
  ├─ Step 1: 攻撃者のロールを確認 (viewer)
  │
  ├─ Step 2a [脆弱]: ミドルウェアなし管理者エンドポイントへ直接アクセス
  │    POST /api/rbac/attack/vertical-escalation
  │    body: { targetUserId: 1, useMiddleware: false }
  │    → 200 OK: { deleted: true } ← ロールチェックなしで削除成功
  │
  ├─ Step 2b [防御]: ミドルウェアあり管理者エンドポイントへアクセス
  │    POST /api/rbac/attack/vertical-escalation
  │    body: { targetUserId: 1, useMiddleware: true }
  │    → 403 Forbidden: { error: "Admin role required" }
  │
  └─ Step 3: 結果比較 — ミドルウェア有無で挙動が変化することを確認
```

#### AttackStep[] 定義

```typescript
// 脆弱バリアント (useMiddleware: false)
const verticalEscalationVulnSteps: AttackStep[] = [
  {
    id: "rbac-vert-s1",
    kind: "probe",
    label: "Confirm attacker role: viewer (non-admin)",
    labelJa: "攻撃者ロール確認: viewer (非管理者)",
    status: "success",
    payload: {
      type: "generic",
      data: { username: "seed_bob", role: "viewer", isAdmin: false },
    },
    timestamp: 0,
  },
  {
    id: "rbac-vert-s2",
    kind: "exploit",
    label: "Direct access to admin endpoint (no middleware)",
    labelJa: "管理者エンドポイントへ直接アクセス (ミドルウェアなし)",
    status: "success",
    payload: {
      type: "http",
      request: {
        method: "POST",
        url: "/api/rbac/attack/vertical-escalation",
        headers: { "Authorization": "Bearer <seed_bob_viewer_token>" },
        body: { targetUserId: 1, useMiddleware: false },
      },
      response: {
        status: 200,
        body: { deleted: true, targetUserId: 1, executedBy: "seed_bob (viewer)" },
      },
    },
    timestamp: 0,
  },
];

// 防御バリアント (useMiddleware: true)
const verticalEscalationDefendedSteps: AttackStep[] = [
  {
    id: "rbac-vert-d1",
    kind: "probe",
    label: "Confirm attacker role: viewer (non-admin)",
    labelJa: "攻撃者ロール確認: viewer (非管理者)",
    status: "success",
    payload: {
      type: "generic",
      data: { username: "seed_bob", role: "viewer", isAdmin: false },
    },
    timestamp: 0,
  },
  {
    id: "rbac-vert-d2",
    kind: "blocked",
    label: "RBAC middleware: viewer role rejected (admin required)",
    labelJa: "RBAC ミドルウェア: viewer ロールを拒否 (admin 必須)",
    status: "blocked",
    payload: {
      type: "http",
      response: {
        status: 403,
        body: { error: "Forbidden", message: "Admin role required for this operation" },
      },
    },
    detail: "The RBAC middleware verified the role before the handler ran and rejected the request.",
    detailJa: "RBAC ミドルウェアがハンドラ実行前にロールを検証し、リクエストを拒否しました。",
    timestamp: 0,
  },
];
```

#### バックエンド実装仕様 (`server/routes/rbac.ts` への追加)

```typescript
/**
 * 攻撃デモルート: 垂直権限昇格
 *
 * 【教育目的専用】
 * RBAC ミドルウェアあり/なしで同一エンドポイントの挙動を比較します。
 * 対象 CWE: CWE-269
 * 対象 CAPEC: CAPEC-233
 */
rbacRoutes.post("/attack/vertical-escalation", async (c) => {
  const trace = c.get("trace");
  const body = await c.req.json().catch(() => ({}));
  const { targetUserId = 1, useMiddleware = false, attackerRole = "viewer" } = body;

  trace.addAttackStep({
    id: "rbac-vert-s1",
    kind: "probe",
    label: `Attacker role: ${attackerRole} — targeting admin operation`,
    labelJa: `攻撃者ロール: ${attackerRole} — 管理者操作を狙う`,
    status: "success",
  });

  if (useMiddleware) {
    // 防御された実装: ロール検証ミドルウェアをシミュレーション
    const adminRoles = ["admin"];
    const hasAdminRole = adminRoles.includes(attackerRole);

    trace.addAttackStep({
      id: "rbac-vert-d1",
      kind: "blocked",
      label: "RBAC middleware: role check → " + (hasAdminRole ? "PASS" : "REJECT"),
      labelJa: "RBAC ミドルウェア: ロール確認 → " + (hasAdminRole ? "通過" : "拒否"),
      status: hasAdminRole ? "success" : "blocked",
      detail: hasAdminRole
        ? "Admin role confirmed. Request proceeds to handler."
        : `Role '${attackerRole}' does not have admin privilege. Request rejected with 403.`,
      detailJa: hasAdminRole
        ? "admin ロールを確認。ハンドラに処理を移譲します。"
        : `ロール '${attackerRole}' は admin 権限を持ちません。403 で拒否しました。`,
    });

    if (!hasAdminRole) {
      return c.json({
        success: true,
        data: {
          attackResult: {
            scenarioId: "rbac-vertical-privilege-escalation",
            outcome: "blocked",
            blockedBy: "rbac_middleware_role_check",
            blockedByJa: "RBAC ミドルウェアのロール検証が機能しました",
            summaryJa: "防御が機能しました: ロール検証ミドルウェアが admin 以外のアクセスを拒否しました。",
          },
        },
      }, 403);
    }
  }

  // 脆弱な実装 or 管理者ロールが確認された場合: 操作を実行
  trace.addAttackStep({
    id: "rbac-vert-s2",
    kind: "exploit",
    label: useMiddleware
      ? "Admin operation executed (admin role confirmed)"
      : "Admin operation executed WITHOUT role check (vulnerable)",
    labelJa: useMiddleware
      ? "管理者操作実行 (admin ロール確認済み)"
      : "ロールチェックなしで管理者操作実行 (脆弱)",
    status: "success",
    detail: `targetUserId=${targetUserId} の削除操作を実行。ロールチェック: ${useMiddleware ? "実施" : "未実施"}`,
    detailJa: `targetUserId=${targetUserId} の削除操作を実行。ロールチェック: ${useMiddleware ? "実施" : "未実施"}`,
  });

  const outcome = !useMiddleware ? "succeeded" : "blocked";
  const result: AttackResult = {
    scenarioId: "rbac-vertical-privilege-escalation",
    outcome: !useMiddleware ? "succeeded" : "blocked",
    startedAt: Date.now(),
    finishedAt: Date.now(),
    steps: [],
    summary: !useMiddleware
      ? "This implementation is vulnerable: no role check middleware was applied to the admin endpoint. A viewer-role user was able to execute an admin-only operation."
      : "Defense succeeded: RBAC middleware verified the role before the handler ran.",
    summaryJa: !useMiddleware
      ? "この実装は脆弱です: 管理者エンドポイントにロールチェックミドルウェアが適用されていませんでした。viewer ロールのユーザーが管理者専用操作を実行できました。"
      : "防御が機能しました: RBAC ミドルウェアがハンドラ実行前にロールを検証しました。",
  };

  return c.json({
    success: true,
    data: {
      simulatedDelete: { targetUserId, executedBy: `seed_bob (${attackerRole})`, middlewareApplied: useMiddleware },
      attackResult: result,
    },
  });
});
```

#### 防御策

| 防御策 | 実装方法 |
|--------|---------|
| ロール検証ミドルウェア | `requireRole("admin")` ミドルウェアをルートチェーンの先頭に配置する |
| デフォルト拒否 | 認可チェックが存在しない場合はデフォルトで拒否する設計にする |
| Hono ミドルウェアパターン | `app.use("/api/rbac/admin/*", requireRoleMiddleware("admin"))` |

```typescript
// codeHints[0]: Hono ロール検証ミドルウェア
function requireRole(requiredRole: string) {
  return async (c: Context, next: Next) => {
    const userRole = c.get("userRole");   // JWTミドルウェア等で設定済み想定
    if (userRole !== requiredRole) {
      return c.json({ error: "Forbidden: insufficient privileges" }, 403);
    }
    await next();
  };
}

// codeHints[1]: ルートへの適用
rbacRoutes.use("/admin/*", requireRole("admin"));
rbacRoutes.post("/admin/users/delete", async (c) => {
  // ここに到達する場合は admin ロールが確認済み
  const { targetUserId } = await c.req.json();
  // 削除処理...
});
```

#### 実環境との差異 (必須付記)

「実環境では、認可チェックをアプリケーションコードにのみ依存する設計は危険です。
ゲートウェイ・ミドルウェア・コードの3層で重複したチェック (Defense in Depth) を行うことで
実装漏れの影響を最小化します。」

---

### 4.4 シナリオ D — ABAC 属性改竄

#### 基本情報

| フィールド | 値 |
|------------|-----|
| シナリオ ID | `rbac-abac-attribute-tampering` |
| 攻撃エンドポイント | `POST /api/rbac/attack/abac-tamper` |
| 深刻度 | High |
| CWE | CWE-807 (Reliance on Untrusted Inputs in a Security Decision) |
| CAPEC | CAPEC-153 (Input Data Manipulation) |
| OSI 層 | L7 (Application) |

#### 攻撃概要

これは **CWE-807 / CAPEC-153** の概念実証である。
ABAC (属性ベースアクセス制御) は Subject 属性・Resource 属性・Environment 属性を組み合わせた
ポリシーでアクセス制御を行う。しかしこれらの属性値をクライアント (リクエストボディ) から受け取り、
サーバー側で検証せずにそのままポリシー評価に使用した場合、攻撃者は属性値を改竄して
本来アクセスできないリソースにアクセスできる。

既存の `POST /api/rbac/abac/check` は `context.department` と `context.resourceDepartment` を
クライアントから受け取り、そのままポリシー `department-match` に使用している。
これが改竄対象のポイントとなる。

#### 攻撃フロー

```
攻撃者 (attacker_charlie, Engineering 部門所属)
対象リソース: Finance 部門の秘匿ドキュメント (resourceDepartment: "Finance")

  ├─ Step 1: 正常リクエスト (改竄なし) — アクセス失敗
  │    POST /api/rbac/attack/abac-tamper
  │    body: {
  │      subject: "attacker_charlie",
  │      department: "Engineering",        ← 実際の部門
  │      resourceDepartment: "Finance",    ← 対象リソースの部門
  │    }
  │    → department-match: FAIL → DENY
  │
  ├─ Step 2: 属性改竄 — department を "Finance" に書き換え
  │    body: {
  │      subject: "attacker_charlie",
  │      department: "Finance",            ← 改竄: Engineering → Finance
  │      resourceDepartment: "Finance",
  │    }
  │    → department-match: PASS → ALLOW (本来は拒否すべき)
  │
  └─ Step 3: 結果確認 — 属性改竄によりポリシーバイパス成立
             属性をサーバー側で取得すれば防御できることを示す
```

#### AttackStep[] 定義

```typescript
const abacTamperSteps: AttackStep[] = [
  {
    id: "rbac-abac-s1",
    kind: "probe",
    label: "Normal request: Engineering dept cannot access Finance resource",
    labelJa: "正常リクエスト: Engineering 部門は Finance リソースにアクセス不可",
    status: "success",
    payload: {
      type: "generic",
      data: {
        subject: "attacker_charlie",
        department: "Engineering",
        resourceDepartment: "Finance",
        policyResult: "DENY",
        reason: "department mismatch",
      },
    },
    timestamp: 0,
  },
  {
    id: "rbac-abac-s2",
    kind: "tamper",
    label: "Tamper: change department from 'Engineering' to 'Finance'",
    labelJa: "改竄: department を 'Engineering' から 'Finance' に書き換え",
    status: "success",
    payload: {
      type: "http",
      request: {
        method: "POST",
        url: "/api/rbac/attack/abac-tamper",
        body: {
          subject: "attacker_charlie",
          department: "Finance",           // 改竄値
          resourceDepartment: "Finance",
        },
      },
      tamperedFields: ["department"],
    },
    timestamp: 0,
  },
  {
    id: "rbac-abac-s3",
    kind: "exploit",
    label: "Policy bypass: tampered attribute satisfies department-match policy",
    labelJa: "ポリシーバイパス: 改竄属性が department-match ポリシーを通過",
    status: "success",
    payload: {
      type: "generic",
      data: {
        departmentMatchPolicy: "PASS",
        actionAllowedPolicy: "PASS",
        finalDecision: "ALLOW",
        originalDepartment: "Engineering",
        tamperedDepartment: "Finance",
        attackSucceeded: true,
      },
    },
    timestamp: 0,
  },
];
```

#### バックエンド実装仕様 (`server/routes/rbac.ts` への追加)

```typescript
/**
 * 攻撃デモルート: ABAC 属性改竄
 *
 * 【教育目的専用】
 * クライアント送信の属性値をそのまま ABAC ポリシー評価に使用した場合に
 * ポリシーバイパスが成立することをシミュレーションします。
 * 対象 CWE: CWE-807
 * 対象 CAPEC: CAPEC-153
 */
rbacRoutes.post("/attack/abac-tamper", async (c) => {
  const trace = c.get("trace");
  const body = await c.req.json().catch(() => ({}));
  const {
    subject = "attacker_charlie",
    department,                      // クライアント送信 (改竄対象)
    resourceDepartment = "Finance",
    action = "read",
  } = body;

  // 固定シード: サーバー側での "正解" 属性 (実環境ではここからのみ取得すべき)
  const SEED_USER_DEPARTMENTS: Record<string, string> = {
    seed_alice:       "Engineering",
    seed_bob:         "Marketing",
    attacker_charlie: "Engineering",
    seed_admin:       "IT",
  };

  const serverSideDepartment = SEED_USER_DEPARTMENTS[subject] ?? "Unknown";
  const clientProvidedDepartment = department ?? serverSideDepartment;

  const isTampered = clientProvidedDepartment !== serverSideDepartment;

  trace.addAttackStep({
    id: "rbac-abac-s1",
    kind: isTampered ? "tamper" : "probe",
    label: `Attribute check: department=${clientProvidedDepartment} (server-truth=${serverSideDepartment})`,
    labelJa: `属性確認: department=${clientProvidedDepartment} (サーバー正解値=${serverSideDepartment})`,
    status: isTampered ? "success" : "success",
    detail: isTampered
      ? `TAMPERED: client sent '${clientProvidedDepartment}' but server-side value is '${serverSideDepartment}'`
      : "No tampering detected: client value matches server-side value.",
    detailJa: isTampered
      ? `改竄検出: クライアントは '${clientProvidedDepartment}' を送信しましたが、サーバー側の正解値は '${serverSideDepartment}' です`
      : "改竄なし: クライアント値がサーバー側の値と一致しています。",
  });

  // 脆弱な ABAC 評価: クライアント送信の department をそのまま使用
  const departmentMatchVulnerable = clientProvidedDepartment === resourceDepartment;

  // 防御された ABAC 評価: サーバー側取得の department を使用
  const departmentMatchDefended = serverSideDepartment === resourceDepartment;

  trace.addSessionOp({
    action: "ABAC_POLICY_EVAL",
    data: {
      policy: "department-match",
      clientProvided: clientProvidedDepartment,
      serverSideValue: serverSideDepartment,
      resourceDepartment,
      vulnerableResult: departmentMatchVulnerable ? "PASS" : "FAIL",
      defendedResult: departmentMatchDefended ? "PASS" : "FAIL",
      isTampered,
    },
  });

  trace.addAttackStep({
    id: "rbac-abac-s2",
    kind: departmentMatchVulnerable && isTampered ? "exploit" : "verify",
    label: `Vulnerable ABAC: department-match → ${departmentMatchVulnerable ? "PASS" : "FAIL"} | Defended: ${departmentMatchDefended ? "PASS" : "FAIL"}`,
    labelJa: `脆弱 ABAC: department-match → ${departmentMatchVulnerable ? "通過" : "失敗"} | 防御版: ${departmentMatchDefended ? "通過" : "失敗"}`,
    status: departmentMatchVulnerable && isTampered ? "success" : "blocked",
    detail: `Vulnerable uses client-supplied value (${clientProvidedDepartment}). Defended uses server-side DB value (${serverSideDepartment}).`,
    detailJa: `脆弱版はクライアント送信値 (${clientProvidedDepartment}) を使用。防御版はサーバー側 DB 値 (${serverSideDepartment}) を使用。`,
  });

  const attackSucceeded = isTampered && departmentMatchVulnerable && !departmentMatchDefended;

  const result: AttackResult = {
    scenarioId: "rbac-abac-attribute-tampering",
    outcome: attackSucceeded ? "succeeded" : "blocked",
    startedAt: Date.now(),
    finishedAt: Date.now(),
    steps: [],
    blockedBy: attackSucceeded ? undefined : "server_side_attribute_lookup",
    blockedByJa: attackSucceeded ? undefined : "サーバー側属性取得によりクライアント改竄を無効化",
    summary: attackSucceeded
      ? "This implementation is vulnerable: client-supplied 'department' attribute was used directly in ABAC policy evaluation. The tampered value bypassed the department-match policy."
      : "Defense succeeded: the server-side department value (from the database) was used instead of the client-supplied value.",
    summaryJa: attackSucceeded
      ? "この実装は脆弱です: クライアント送信の 'department' 属性が ABAC ポリシー評価に直接使用されました。改竄値により department-match ポリシーがバイパスされました。"
      : "防御が機能しました: データベースからサーバー側で取得した department 値を使用したため、クライアント送信値が無効化されました。",
  };

  return c.json({
    success: true,
    data: {
      evaluation: {
        clientProvidedDepartment,
        serverSideDepartment,
        resourceDepartment,
        isTampered,
        vulnerableResult: departmentMatchVulnerable ? "ALLOW" : "DENY",
        defendedResult: departmentMatchDefended ? "ALLOW" : "DENY",
      },
      attackResult: result,
    },
  });
});
```

#### 防御策

| 防御策 | 実装方法 |
|--------|---------|
| 属性をサーバー側で取得 | ユーザー属性 (department, clearanceLevel 等) はリクエストボディから取らず、DB から認証済み userId で取得する |
| コンテキスト属性の不変性確保 | `department` のような重要属性は JWT クレームに含めてサーバー署名で保護するか、毎回 DB から引く |
| 入力値バリデーション | ポリシー評価に使用する属性はホワイトリストで事前検証し、不審な値は 400 で拒否する |

```typescript
// codeHints[0]: 属性をサーバー側 DB から取得するパターン
async function getUserDepartment(db: Database, userId: number): Promise<string> {
  const row = db.prepare(
    "SELECT department FROM user_profiles WHERE user_id = ?"
  ).get(userId) as { department: string } | undefined;
  if (!row) throw new Error("User profile not found");
  return row.department;  // クライアント値ではなく DB 値を返す
}

// codeHints[1]: ABAC 評価でサーバー取得値を使用
rbacRoutes.post("/abac/check", async (c) => {
  const { subject, resource, action } = await c.req.json();
  const authenticatedUserId = c.get("userId");   // JWT ミドルウェアで設定済み

  // department は DB から取得 — クライアント送信の context.department は無視
  const userDepartment = await getUserDepartment(db, authenticatedUserId);

  const policies = [
    {
      name: "department-match",
      check: () => userDepartment === getResourceDepartment(resource),  // DB 値同士で比較
    },
  ];
  // ...
});
```

#### 実環境との差異 (必須付記)

「実環境では JWT クレームに department を含め、改竄されていない署名付きトークンから属性を読み取る
設計が一般的です。ただし JWT に含めた属性が古くなる問題があるため、重要な認可判断には
必ずバックエンド DB で最新の属性値を確認することを推奨します。」

---

## 5. UI コンポーネント設計

### 5.1 ディレクトリ構成

```
src/components/auth/attacks/
└── scenarios/
    └── rbac-scenarios.ts            ← RBAC タブ用 AttackScenarioMeta[] の静的データ

src/components/auth/
└── PermissionModel.tsx              ← ViewModeToggle + AttackPanel を追加 (極小変更)
```

### 5.2 `rbac-scenarios.ts` — 静的シナリオメタデータ

**ファイル**: `src/components/auth/attacks/scenarios/rbac-scenarios.ts`

```typescript
import type { AttackScenarioMeta } from "../../../../../shared/api-types";

export const RBAC_ATTACK_SCENARIOS: AttackScenarioMeta[] = [
  {
    id: "rbac-idor",
    tabId: "rbac",
    name: "IDOR (Insecure Direct Object Reference)",
    nameJa: "IDOR (直接オブジェクト参照)",
    category: "Authorization Bypass",
    difficulty: 2,
    description:
      "A vulnerable API returns resources based on a user-controlled ID without verifying ownership. Changing the ID parameter reveals another user's data.",
    descriptionJa:
      "脆弱な API がユーザー操作可能な ID に基づいてリソースを返し、所有者確認を行いません。ID パラメータを変更すると他ユーザーのデータが漏洩します。",
    mitigation:
      "Always verify that the authenticated user owns or has explicit access to the requested resource (owner_id check). Use indirect references when possible.",
    mitigationJa:
      "認証済みユーザーがリクエストしたリソースの所有者であることを常に確認する (owner_id チェック)。可能な限り間接参照を使用する。",
    references: [
      "https://cwe.mitre.org/data/definitions/639.html",
      "https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control",
      "https://capec.mitre.org/data/definitions/77.html",
    ],
  },
  {
    id: "rbac-horizontal-privilege-escalation",
    tabId: "rbac",
    name: "Horizontal Privilege Escalation",
    nameJa: "水平権限昇格",
    category: "Authorization Bypass",
    difficulty: 2,
    description:
      "An attacker with the same role level as the victim accesses the victim's resources by exploiting missing ownership checks. RBAC alone does not prevent cross-user access.",
    descriptionJa:
      "被害者と同一ロールの攻撃者が、所有者チェックの欠如を利用して被害者のリソースにアクセスします。RBAC のみではクロスユーザーアクセスを防げません。",
    mitigation:
      "Combine RBAC (what can be done) with resource-level ownership checks (whose resource can be accessed). Enforce owner_id comparison on every resource fetch.",
    mitigationJa:
      "RBAC (何ができるか) とリソースレベルの所有者チェック (誰のリソースにアクセスできるか) を組み合わせる。すべてのリソース取得で owner_id 比較を強制する。",
    references: [
      "https://cwe.mitre.org/data/definitions/639.html",
      "https://capec.mitre.org/data/definitions/122.html",
      "https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet",
    ],
  },
  {
    id: "rbac-vertical-privilege-escalation",
    tabId: "rbac",
    name: "Vertical Privilege Escalation",
    nameJa: "垂直権限昇格",
    category: "Authorization Bypass",
    difficulty: 3,
    description:
      "A low-privilege user accesses an admin-only endpoint by sending a direct HTTP request when no RBAC middleware is applied. Shows the effect of missing role enforcement at the route level.",
    descriptionJa:
      "低権限ユーザーが RBAC ミドルウェアが適用されていない管理者専用エンドポイントに直接 HTTP リクエストを送ることで、管理者専用操作を実行できます。ルートレベルのロール強制の欠如を示します。",
    mitigation:
      "Apply RBAC middleware to every protected route. Use a default-deny policy and explicitly allow only authorized roles. Do not rely solely on UI hiding to prevent access.",
    mitigationJa:
      "すべての保護されたルートに RBAC ミドルウェアを適用する。デフォルト拒否ポリシーを使用し、承認されたロールのみを明示的に許可する。UI の非表示だけでアクセス防止を試みない。",
    references: [
      "https://cwe.mitre.org/data/definitions/269.html",
      "https://capec.mitre.org/data/definitions/233.html",
      "https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control",
    ],
  },
  {
    id: "rbac-abac-attribute-tampering",
    tabId: "rbac",
    name: "ABAC Attribute Tampering",
    nameJa: "ABAC 属性改竄",
    category: "Input Manipulation",
    difficulty: 3,
    description:
      "ABAC policies that rely on client-supplied attribute values (e.g., department) can be bypassed by sending forged attribute values. The policy evaluates tampered data as if it were legitimate.",
    descriptionJa:
      "クライアント送信の属性値 (department 等) に依存する ABAC ポリシーは、偽造した属性値を送信することでバイパスできます。ポリシーは改竄データを正規データとして評価してしまいます。",
    mitigation:
      "Fetch all security-relevant attributes from the server-side database using the authenticated user's ID. Never trust client-provided attribute values for authorization decisions.",
    mitigationJa:
      "認証済みユーザーの ID を使用してセキュリティ関連属性をすべてサーバー側 DB から取得する。認可の決定にクライアント提供の属性値を信頼しない。",
    references: [
      "https://cwe.mitre.org/data/definitions/807.html",
      "https://capec.mitre.org/data/definitions/153.html",
      "https://owasp.org/www-community/attacks/Mass_Assignment",
    ],
  },
];
```

### 5.3 `PermissionModel.tsx` への変更 (極小)

```typescript
// PermissionModel.tsx への追加 — 末尾に以下を挿入
import { useSearchParams } from "@solidjs/router";
import ViewModeToggle from "./attacks/ViewModeToggle";
import RbacAttackPanel from "./attacks/rbac/RbacAttackPanel";
import { Show } from "solid-js";

// PermissionModel コンポーネントの return 内末尾に追記:
<ViewModeToggle tabId="rbac" />
<Show when={viewMode() === "attacker"}>
  <RbacAttackPanel />
</Show>
```

### 5.4 シナリオ C の並列比較レイアウト

垂直権限昇格シナリオは「脆弱版 (ミドルウェアなし)」と「防御版 (ミドルウェアあり)」を
左右並列で比較表示する。`DESIGN/04-safety-guardrails.md` §9.3 の方針に従い:

- 左パネル上端: `EducationalWarningBanner` (赤色)
- 右パネル上端: `防御実装済み` バナー (緑色)
- 両パネルのバナー高さ・位置を揃えて視覚的に対比

```
┌──────────────────────┐  ┌──────────────────────┐
│ [!] 脆弱な実装        │  │ [OK] 防御済み実装      │
│ ミドルウェアなし      │  │ ミドルウェアあり       │
├──────────────────────┤  ├──────────────────────┤
│ POST /attack/vert-   │  │ POST /attack/vert-    │
│ escalation           │  │ escalation            │
│ body: { middleware:  │  │ body: { middleware:   │
│   false }            │  │   true }              │
│                      │  │                       │
│ 200 OK: deleted:true │  │ 403: Admin required   │
└──────────────────────┘  └──────────────────────┘
```

---

## 6. テスト要件

### 6.1 バックエンド API テスト

`server/routes/rbac.test.ts` に以下のテストケースを追加する:

| # | エンドポイント | テスト内容 | 期待結果 |
|---|----------------|-----------|---------|
| 1 | `GET /api/rbac/attack/idor?victimId=1` | シードユーザー以外の victimId で取得 | `outcome: "succeeded"`, プロファイルデータ返却 |
| 2 | `GET /api/rbac/attack/idor?victimId=999` | 存在しない victimId | 404 |
| 3 | `POST /api/rbac/attack/horizontal-escalation` body: `{attackerRole:"editor",targetUserId:1}` | editor が alice のリソースを取得 | `outcome: "succeeded"` |
| 4 | `POST /api/rbac/attack/horizontal-escalation` body: `{attackerRole:"unknown",targetUserId:1}` | 存在しないロール | `outcome: "blocked"` |
| 5 | `POST /api/rbac/attack/vertical-escalation` body: `{useMiddleware:false,attackerRole:"viewer"}` | ミドルウェアなし | `outcome: "succeeded"` |
| 6 | `POST /api/rbac/attack/vertical-escalation` body: `{useMiddleware:true,attackerRole:"viewer"}` | ミドルウェアあり | 403, `outcome: "blocked"` |
| 7 | `POST /api/rbac/attack/vertical-escalation` body: `{useMiddleware:true,attackerRole:"admin"}` | admin ロールでミドルウェアあり | 200, `outcome: "blocked"` (= 正規アクセス) |
| 8 | `POST /api/rbac/attack/abac-tamper` body: `{department:"Finance",resourceDepartment:"Finance"}` | 改竄あり | `isTampered:true`, `vulnerableResult:"ALLOW"`, `defendedResult:"DENY"` |
| 9 | `POST /api/rbac/attack/abac-tamper` body: `{department:"Engineering",resourceDepartment:"Finance"}` | 改竄なし (正常) | `isTampered:false`, `vulnerableResult:"DENY"`, `defendedResult:"DENY"` |
| 10 | `POST /api/rbac/attack/abac-tamper` body: `{subject:"seed_bob",department:"Finance",resourceDepartment:"Finance"}` | seed_bob (Marketing) の改竄 | `isTampered:true`, `serverSideDepartment:"Marketing"` |

### 6.2 `_trace` 検証

各攻撃エンドポイントのレスポンスに `_trace.attackSteps` が含まれることを確認:

```typescript
// テスト例
it("IDOR attack returns attackSteps in trace", async () => {
  const res = await app.request("/api/rbac/attack/idor?victimId=1", { method: "GET" });
  const json = await res.json();
  expect(json._trace.attackSteps).toBeDefined();
  expect(json._trace.attackSteps.length).toBeGreaterThan(0);
});
```

### 6.3 安全装置チェックリスト (PR 前確認)

- [ ] 全 `fetch` / `apiPost` / `apiGet` の宛先が `/api/rbac/attack/*` のみ
- [ ] 外部 URL へのリクエストが生成されていない
- [ ] 固定シードデータ (`SEED_USERS`, `SEED_ALICE_ARTICLE` 等) のみを対象とし、任意 DB レコードへの攻撃が不可能
- [ ] Attacker View で `EducationalWarningBanner` が常時表示される
- [ ] 攻撃成立文言が「この実装は」または「このシナリオでは」で始まる
- [ ] 禁止表現 (「ハッキング」「簡単に破れる」等) が含まれない
- [ ] `AttackDefensePanel` が攻撃完了後に自動展開される
- [ ] `_trace.attackSteps` が全エンドポイントで返却される

---

## 7. i18n キー一覧表

本シナリオで新規追加が必要な i18n テキスト:

| キー (概念) | 日本語 | English |
|------------|--------|---------|
| IDOR シナリオ名 | `IDOR (直接オブジェクト参照)` | `IDOR (Insecure Direct Object Reference)` |
| 水平権限昇格シナリオ名 | `水平権限昇格` | `Horizontal Privilege Escalation` |
| 垂直権限昇格シナリオ名 | `垂直権限昇格` | `Vertical Privilege Escalation` |
| ABAC 属性改竄シナリオ名 | `ABAC 属性改竄` | `ABAC Attribute Tampering` |
| 所有者チェックなし | `所有者チェックなし — リソースが返却されました` | `No ownership check — resource returned` |
| 水平昇格成立メッセージ | `この実装は脆弱です: RBAC はロールを確認しましたが、owner_id を検証しませんでした` | `This implementation is vulnerable: RBAC verified the role but not the owner_id` |
| 垂直昇格成立メッセージ | `この実装は脆弱です: 管理者エンドポイントにロールチェックミドルウェアが適用されていません` | `This implementation is vulnerable: no role middleware applied to admin endpoint` |
| 垂直昇格防御メッセージ | `防御が機能しました: ロール検証ミドルウェアが admin 以外のアクセスを拒否しました` | `Defense succeeded: role middleware rejected non-admin access` |
| ABAC 改竄成立メッセージ | `この実装は脆弱です: クライアント送信の department 属性がポリシーバイパスに悪用されました` | `This implementation is vulnerable: client-supplied department attribute was abused to bypass policy` |
| ABAC 防御メッセージ | `防御が機能しました: サーバー側 DB から取得した department 値でクライアント改竄を無効化しました` | `Defense succeeded: server-side DB attribute invalidated the tampered client value` |
| ミドルウェアなしラベル | `ミドルウェアなし (脆弱)` | `No Middleware (Vulnerable)` |
| ミドルウェアありラベル | `ミドルウェアあり (防御済み)` | `With Middleware (Protected)` |
| 部門属性ラベル | `部門属性 (クライアント送信)` | `Department Attribute (Client-supplied)` |
| サーバー取得部門属性 | `部門属性 (サーバー DB 取得)` | `Department Attribute (Server DB)` |
| 改竄検出 | `改竄検出: クライアント値がサーバー値と不一致` | `Tampering detected: client value differs from server value` |
| 改竄未検出 | `改竄なし: クライアント値がサーバー値と一致` | `No tampering: client value matches server value` |
| owner_id チェック防御説明 | `owner_id チェックによりリソース所有者であることを確認してから返却する` | `owner_id check verifies resource ownership before returning data` |
| ロール検証ミドルウェア防御説明 | `ロール検証ミドルウェアがハンドラ実行前に認可を確認する` | `Role verification middleware checks authorization before the handler runs` |
| 属性サーバー取得防御説明 | `セキュリティ属性はクライアントから受け取らず、サーバー側 DB から取得する` | `Security attributes are fetched from the server DB, not accepted from the client` |

---

## 8. 関連ファイル

### 8.1 変更対象ファイル

| ファイルパス | 変更種別 | 変更内容 |
|------------|---------|---------|
| `server/routes/rbac.ts` | 追加 | `GET /attack/idor`, `POST /attack/horizontal-escalation`, `POST /attack/vertical-escalation`, `POST /attack/abac-tamper` の4エンドポイント追加 |
| `src/components/auth/PermissionModel.tsx` | 極小変更 | `ViewModeToggle` と `<AttackPanel>` を末尾に追加 |
| `shared/api-types.ts` | 既存変更 (DESIGN/01 参照) | `AttackStep`, `AttackResult`, `ServerTrace.attackSteps` (既出) |
| `server/middleware/trace-logger.ts` | 既存変更 (DESIGN/01 参照) | `addAttackStep()` 追加 (既出) |
| `server/db/schema.ts` | 既存変更 (DESIGN/03 参照) | `attack_log` テーブル追加、`seedDb()` にリセット処理追加 (既出) |

### 8.2 新規作成ファイル

| ファイルパス | 内容 |
|------------|------|
| `src/components/auth/attacks/scenarios/rbac-scenarios.ts` | RBAC タブ用 `AttackScenarioMeta[]` 静的データ (4シナリオ) |

### 8.3 設計書クロスリファレンス

| 設計書 | 参照箇所 |
|--------|---------|
| `DESIGN/00-overview.md` §5.1 | 攻撃カタログマトリクス — rbac タブの4シナリオ (行 14-17) |
| `DESIGN/01-architecture.md` §2.1 | `rbac.ts` への攻撃ルート追加方針 |
| `DESIGN/02-ui-spec.md` §9.3 | 「脆弱版 vs 防御版」並列比較レイアウト (シナリオ C) |
| `DESIGN/03-data-model.md` §4.5 | `rbac-idor-horizontal` の `AttackStepPayload` 例 |
| `DESIGN/04-safety-guardrails.md` §2.1 | 攻撃成立時文言ルール (`「この実装は」` で始める) |
| `DESIGN/04-safety-guardrails.md` §3.3 | リアルワールド外挿の防止 — 付記テキストの要件 |

### 8.4 既存実装ファイル (参照のみ)

| ファイルパス | 参照理由 |
|------------|---------|
| `server/routes/rbac.ts` | 既存 RBAC/ABAC/ACL 評価ロジック — 防御側実装の参照先 |
| `server/db/schema.ts` | roles/permissions/user_roles テーブル構造 |
| `src/components/auth/PermissionModel.tsx` | 既存 UI 構造 — 変更最小化のため |
| `src/api/client.ts` | `apiGet`/`apiPost` 呼び出しパターン |
| `src/components/shared/DataFlowPanel.tsx` | `scopeId="attack-rbac"` でキャプチャ |
| `src/i18n/context.tsx` | `t(ja, en)` ヘルパー |

---

*本ファイルは `DESIGN/14-attack-rbac.md` として配置。実装フェーズでは本ファイルと
`DESIGN/01-architecture.md`・`DESIGN/03-data-model.md` を参照して開発を進める。*
