import type { AttackScenarioMeta } from "../../../../../shared/api-types";

export const rbacScenarios: AttackScenarioMeta[] = [
  {
    id: "rbac-idor",
    tabId: "rbac",
    name: "IDOR (Insecure Direct Object Reference)",
    nameJa: "IDOR (直接オブジェクト参照)",
    category: "Authorization Bypass",
    cweId: "CWE-639",
    capecId: "CAPEC-77",
    difficulty: 2,
    osiLayer: 7,
    severity: "high",
    description:
      "This is a proof-of-concept for CWE-639 / CAPEC-77. When an API uses a user-controlled ID as a direct object reference without verifying ownership, an attacker can access another user's data simply by changing the ID parameter. No privilege escalation is required — the attacker's role is valid, only the ownership check is missing.",
    descriptionJa:
      "これは CWE-639 / CAPEC-77 の概念実証です。API がユーザー制御の ID を所有権チェックなしに直接オブジェクト参照として使用している場合、攻撃者は ID パラメータを変更するだけで別ユーザーのデータにアクセスできます。権限昇格は不要です — 攻撃者のロールは正規であり、所有権チェックが欠如しているだけです。",
    mitigation:
      "Always verify ownership on the server side. Use WHERE id = ? AND owner_id = ? in database queries. Never rely solely on a user-controlled ID to authorize resource access. Apply the principle of least privilege and ensure every data access includes an authorization check tied to the authenticated user's identity.",
    mitigationJa:
      "サーバー側で常に所有権を検証してください。データベースクエリに WHERE id = ? AND owner_id = ? を使用します。ユーザー制御の ID だけを根拠にリソースアクセスを認可しないでください。最小権限の原則を適用し、すべてのデータアクセスに認証済みユーザーの ID に紐付いた認可チェックを含めてください。",
    references: [
      "https://cwe.mitre.org/data/definitions/639.html",
      "https://capec.mitre.org/data/definitions/77.html",
      "https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control",
    ],
    codeHints: [
      {
        lang: "typescript",
        label: "Vulnerable: no ownership check (do not use)",
        code: `// 脆弱な実装: ユーザー制御の victimId をそのまま使用
app.post("/users/profile", async (c) => {
  const { victimId } = await c.req.json();
  // owner_id チェックなし — 任意の ID のデータを返す
  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(victimId);
  return c.json(user);
});`,
      },
      {
        lang: "typescript",
        label: "Defended: server-side ownership check (recommended)",
        code: `// 安全な実装: owner_id 列でリソース所有者を強制
app.post("/articles/get", async (c) => {
  const { articleId } = await c.req.json();
  const authenticatedUserId = c.get("userId"); // JWT から取得
  // サーバー側の owner_id チェックで所有権を強制 (id != owner_id 概念のため別カラム)
  const article = db.prepare(
    "SELECT * FROM articles WHERE id = ? AND owner_id = ?"
  ).get(articleId, authenticatedUserId);
  if (!article) return c.json({ error: "Forbidden" }, 403);
  return c.json(article);
});`,
      },
      {
        lang: "typescript",
        label: "Defended: ignore client-supplied ID entirely",
        code: `// より安全: クライアント提供の ID を無視し、JWT から取得
app.get("/users/me", async (c) => {
  const authenticatedUserId = c.get("userId"); // JWTから取得
  // ユーザーは常に自分自身のデータのみ取得可能
  const user = db.prepare("SELECT * FROM users WHERE id = ?")
    .get(authenticatedUserId);
  return c.json(user);
});`,
      },
    ],
    existingFileLinks: [
      {
        path: "server/routes/rbac.ts",
        description: "POST /api/rbac/attack/idor — owner_id チェックの有無を両モード並列実行",
      },
    ],
    modes: [
      {
        id: "no-owner-check",
        labelJa: "owner_id チェックなし (脆弱)",
        label: "No owner_id check (vulnerable)",
        kind: "vulnerable",
      },
      {
        id: "owner-check",
        labelJa: "owner_id チェックあり (防御)",
        label: "With owner_id check (defended)",
        kind: "defensive",
      },
    ],
    // Phase 2 PoC: live attack 化された 3 件目のシナリオ。
    // 学習者は victimId を 1 (alice) / 2 (bob) / 4 (admin) に書き換えて、
    // 攻撃者 charlie (id=3) として他ユーザーのフルレコードが返ることを観察できる。
    // 堅牢実装側 (server/routes/rbac.ts の defended パス) は WHERE owner_id チェックで 403 を返す。
    mode: "live",
    liveTemplate: {
      target: "victim-web",
      method: "POST",
      // 注: victimId が attacker (charlie=3) ではなく victim (alice=1) を指している。
      // 学習者は victimId を 3 に戻すと「自分のデータ」、別の id にすると「他人のデータ」が
      // どちらも 200 で返ることを観察し、所有権チェックの欠如を理解できる。
      path: "/rbac/users/profile",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ victimId: 1 }),
    },
  },
  {
    id: "rbac-horizontal-privilege-escalation",
    tabId: "rbac",
    name: "Horizontal Privilege Escalation",
    nameJa: "水平権限昇格",
    category: "Authorization Bypass",
    cweId: "CWE-639",
    capecId: "CAPEC-122",
    difficulty: 2,
    osiLayer: 7,
    severity: "high",
    description:
      "This is a proof-of-concept for CWE-639 / CAPEC-122. When RBAC checks only the role-level permission (e.g., 'editor can read articles') without verifying resource ownership, an attacker with a valid role can access another user's resources. This is distinct from IDOR in that the attacker's RBAC permission is legitimate — the missing piece is the resource-level owner check.",
    descriptionJa:
      "これは CWE-639 / CAPEC-122 の概念実証です。RBAC がリソースの所有権を確認せずロールレベルの権限 (例: 'editor は articles を読める') のみをチェックしている場合、正規ロールを持つ攻撃者が別ユーザーのリソースにアクセスできます。IDOR との違いは、攻撃者の RBAC 権限が正当であることです — 欠如しているのはリソースレベルの所有者チェックです。",
    mitigation:
      "Combine RBAC with resource-level ownership checks. After confirming that the role has the required permission, also verify that the resource belongs to the authenticated user (WHERE resource.id = ? AND owner_id = authenticatedUserId). Use object-level authorization frameworks (e.g., OPA, Casbin) to enforce both role and ownership policies.",
    mitigationJa:
      "RBAC とリソースレベルの所有権チェックを組み合わせてください。ロールが必要な権限を持つことを確認した後、リソースが認証済みユーザーに属することも検証します (WHERE resource.id = ? AND owner_id = authenticatedUserId)。オブジェクトレベルの認可フレームワーク (OPA、Casbin など) を使用してロールと所有権の両方のポリシーを適用してください。",
    references: [
      "https://cwe.mitre.org/data/definitions/639.html",
      "https://capec.mitre.org/data/definitions/122.html",
      "https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control",
    ],
    codeHints: [
      {
        lang: "typescript",
        label: "Vulnerable: RBAC-only, no resource ownership check (do not use)",
        code: `// 脆弱な実装: ロールチェックのみ、リソース所有権チェックなし
async function getArticle(userId: number, role: string, articleId: number) {
  // ロールレベルチェックのみ — OK
  if (!hasPermission(role, "articles:read")) throw new Error("Forbidden");
  // 所有権チェックなし — 脆弱
  return db.prepare("SELECT * FROM articles WHERE id = ?").get(articleId);
}`,
      },
      {
        lang: "typescript",
        label: "Defended: RBAC + resource ownership check (recommended)",
        code: `// 安全な実装: ロールチェック + リソース所有権チェック
async function getArticle(userId: number, role: string, articleId: number) {
  // 1. ロールレベルチェック
  if (!hasPermission(role, "articles:read")) throw new Error("Forbidden");
  // 2. リソース所有権チェック (AND owner_id = ?)
  const article = db.prepare(
    "SELECT * FROM articles WHERE id = ? AND owner_id = ?"
  ).get(articleId, userId);
  if (!article) throw new Error("Forbidden: not your article");
  return article;
}`,
      },
    ],
    existingFileLinks: [
      {
        path: "server/routes/rbac.ts",
        description:
          "POST /api/rbac/attack/horizontal-escalation — RBAC ロールチェック + owner_id チェックの有無を両モード並列実行",
      },
    ],
    modes: [
      {
        id: "rbac-only",
        labelJa: "ロールチェックのみ (脆弱)",
        label: "RBAC role check only (vulnerable)",
        kind: "vulnerable",
      },
      {
        id: "rbac-plus-owner",
        labelJa: "ロール + 所有権チェック (防御)",
        label: "Role + ownership check (defended)",
        kind: "defensive",
      },
    ],
  },
  {
    id: "rbac-vertical-privilege-escalation",
    tabId: "rbac",
    name: "Vertical Privilege Escalation",
    nameJa: "垂直権限昇格",
    category: "Privilege Escalation",
    cweId: "CWE-269",
    capecId: "CAPEC-233",
    difficulty: 2,
    osiLayer: 7,
    severity: "critical",
    description:
      "This is a proof-of-concept for CWE-269 / CAPEC-233. When an admin-only endpoint lacks server-side role enforcement middleware, a low-privilege user (e.g., viewer, editor) can directly invoke privileged operations such as deleting users. This scenario is distinct from horizontal escalation: the attacker's role does NOT have the required permission, but the endpoint never checks it.",
    descriptionJa:
      "これは CWE-269 / CAPEC-233 の概念実証です。管理者専用エンドポイントにサーバー側のロール強制ミドルウェアが存在しない場合、低権限ユーザー (viewer、editor など) がユーザー削除などの特権操作を直接実行できます。このシナリオは水平権限昇格と異なります: 攻撃者のロールは必要な権限を持っていませんが、エンドポイントがそれを検証しません。",
    mitigation:
      "Apply role-enforcement middleware to every protected endpoint. Use a centralized authorization layer (e.g., requireRole('admin') middleware) that verifies the authenticated user's role before executing any handler. Never rely on obscurity (hiding admin URLs) — always enforce authorization server-side.",
    mitigationJa:
      "すべての保護されたエンドポイントにロール強制ミドルウェアを適用してください。ハンドラを実行する前に認証済みユーザーのロールを検証する集中認可レイヤー (例: requireRole('admin') ミドルウェア) を使用します。難読化 (管理者 URL の隠蔽) に頼らないでください — 常にサーバー側で認可を強制してください。",
    references: [
      "https://cwe.mitre.org/data/definitions/269.html",
      "https://capec.mitre.org/data/definitions/233.html",
      "https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control",
    ],
    codeHints: [
      {
        lang: "typescript",
        label: "Vulnerable: no role middleware on admin endpoint (do not use)",
        code: `// 脆弱な実装: ミドルウェアなしの管理者専用エンドポイント
app.post("/admin/users/delete", async (c) => {
  // ロールチェックなし — 任意のユーザーが削除を実行できる
  const { targetUserId } = await c.req.json();
  db.prepare("DELETE FROM users WHERE id = ?").run(targetUserId);
  return c.json({ success: true });
});`,
      },
      {
        lang: "typescript",
        label: "Defended: requireRole middleware (recommended)",
        code: `// ミドルウェア定義
function requireRole(role: string) {
  return async (c: Context, next: Next) => {
    const userRole = c.get("userRole"); // JWTから取得
    if (userRole !== role) {
      return c.json({ error: \`Forbidden: role '\${userRole}' is not authorized\` }, 403);
    }
    await next();
  };
}

// 安全な実装: requireRole ミドルウェアで保護
app.post(
  "/admin/users/delete",
  requireRole("admin"), // ← すべての管理者エンドポイントに適用
  async (c) => {
    const { targetUserId } = await c.req.json();
    db.prepare("DELETE FROM users WHERE id = ?").run(targetUserId);
    return c.json({ success: true });
  }
);`,
      },
    ],
    existingFileLinks: [
      {
        path: "server/routes/rbac.ts",
        description:
          "POST /api/rbac/attack/vertical-escalation — requireRole ミドルウェアの有無を両モード並列実行 (削除はシミュレーションのみ、実 DB への書き込みなし)",
      },
    ],
    modes: [
      {
        id: "no-middleware",
        labelJa: "ミドルウェアなし (脆弱)",
        label: "No role middleware (vulnerable)",
        kind: "vulnerable",
      },
      {
        id: "with-middleware",
        labelJa: "requireRole ミドルウェアあり (防御)",
        label: "With requireRole middleware (defended)",
        kind: "defensive",
      },
    ],
  },
  {
    id: "rbac-abac-attribute-tampering",
    tabId: "rbac",
    name: "ABAC Attribute Tampering",
    nameJa: "ABAC 属性改竄",
    category: "Policy Bypass",
    cweId: "CWE-807",
    capecId: "CAPEC-153",
    difficulty: 3,
    osiLayer: 7,
    severity: "high",
    description:
      "This is a proof-of-concept for CWE-807 / CAPEC-153. When an ABAC policy evaluates attributes supplied by the client (e.g., 'department' in the request body) rather than looking them up from the server-side database, an attacker can forge attribute values to satisfy policy conditions and gain unauthorized access. This attack is subtle because the attacker uses a legitimate account — only the attribute values are manipulated.",
    descriptionJa:
      "これは CWE-807 / CAPEC-153 の概念実証です。ABAC ポリシーがサーバー側のデータベースから属性を取得する代わりにクライアントが提供する属性値 (例: リクエストボディの 'department') を評価している場合、攻撃者は属性値を偽造してポリシー条件を満たし、不正アクセスを得ることができます。攻撃者は正規アカウントを使用しており、変更されるのは属性値のみのため、この攻撃は検出が難しい特徴があります。",
    mitigation:
      "Never use client-supplied values for security-sensitive ABAC attributes. Always look up attribute values from the server-side authoritative source (database, identity provider, etc.) using the authenticated user's identity. If JWT claims must carry the attribute, sign them server-side and re-verify on every request — and prefer fetching the latest value from the DB for high-stakes decisions. Validate any policy input against an allow-list and reject unexpected values with HTTP 400.",
    mitigationJa:
      "セキュリティに影響する ABAC 属性にはクライアント提供の値を使用しないでください。常に認証済みユーザーの ID を使用してサーバー側の権威あるソース (データベース、アイデンティティプロバイダーなど) から属性値を取得してください。JWT クレームに属性を載せる場合はサーバー側で署名し、リクエストごとに署名検証を行ってください — 重要な認可判断には DB から最新値を取得するのが推奨です。ポリシー評価に使う属性はホワイトリストで事前検証し、想定外の値は HTTP 400 で拒否してください。",
    references: [
      "https://cwe.mitre.org/data/definitions/807.html",
      "https://capec.mitre.org/data/definitions/153.html",
      "https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control",
    ],
    codeHints: [
      {
        lang: "typescript",
        label: "Vulnerable: client-supplied attribute in ABAC (do not use)",
        code: `// 脆弱な実装: クライアント送信の department でポリシー評価
app.post("/api/rbac/abac/check", async (c) => {
  const { subject, action, context } = await c.req.json();
  // context.department はクライアントが自由に変更可能 — 脆弱
  const allowed = context.department === context.resourceDepartment;
  return c.json({ allowed });
});`,
      },
      {
        lang: "typescript",
        label: "Defended: server-side attribute lookup (recommended)",
        code: `// 安全な実装: サーバー側 DB から department を取得
app.post("/api/rbac/abac/check", async (c) => {
  const { subject, action, resourceDepartment } = await c.req.json();
  // サーバー側 DB から subject の department を取得 (クライアント値を無視)
  const user = db.prepare(
    "SELECT department FROM users WHERE username = ?"
  ).get(subject) as { department: string } | undefined;
  const serverDepartment = user?.department ?? "Unknown";
  // サーバー側の値でポリシー評価
  const allowed = serverDepartment === resourceDepartment;
  return c.json({ allowed });
});`,
      },
    ],
    existingFileLinks: [
      {
        path: "server/routes/rbac.ts",
        description:
          "POST /api/rbac/attack/abac-tamper — クライアント値 vs サーバー側 DB 値での ABAC 評価を両モード並列実行",
      },
    ],
    modes: [
      {
        id: "client-attributes",
        labelJa: "クライアント属性使用 (脆弱)",
        label: "Client-supplied attributes (vulnerable)",
        kind: "vulnerable",
      },
      {
        id: "server-attributes",
        labelJa: "サーバー側属性ルックアップ (防御)",
        label: "Server-side attribute lookup (defended)",
        kind: "defensive",
      },
    ],
  },
];
