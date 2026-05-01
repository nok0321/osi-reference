---
title: 攻撃デモカタログ — Orchestrator API 仕様
phase: design
audience: 開発者・教材執筆者
last-updated: 2026-05-02
safety-reviewed: false
---

# 31. Orchestrator API 仕様

## 1. 目的とスコープ

### 1.1 エンドポイントの役割

`POST /api/orchestrator/exec` は、ブラウザの `RawHttpComposer` コンポーネントが組み立てた
raw HTTP リクエストを、`VICTIM_ALLOWLIST` で事前定義された victim コンテナへ中継するプロキシハンドラである。

処理の概要:

1. ブラウザから `{ scenarioId, target, request, timeoutMs }` を受け取る
2. `target` キーを `VICTIM_ALLOWLIST` で検証し、対応する `baseUrl` を取得する
3. Node.js 組み込みの `http.request` で victim-net 内部の対象コンテナへ転送する
4. raw bytes をフルキャプチャし、`elapsedMs` を計測する
5. `AttackResult` + `_trace (isAttackMode: true, mode: "live")` を整形してブラウザへ返す

### 1.2 既存ナレーション型 `/attack/*` との関係

`DESIGN/30 §6` の共存方針を継承する。

- 既存の `server/routes/<area>.ts` 内 `/attack/<scenario>` ルートは Phase 5 まで残置する。
- `AttackScenarioMeta.mode` フィールド (`"live" | "narration"`) でフロント側がルーティングを切り替える。
  - `mode: "live"` → `apiPost("/api/orchestrator/exec", ...)`
  - `mode: "narration"` → `apiPost("/api/<area>/attack/<scenario>", ...)`
- Phase 5 でナレーション型を撤去するか否かの最終判断を行う。

### 1.3 本エンドポイントが解決する課題

| 課題 | 解決策 |
|------|--------|
| リクエスト生成がサーバー内部に隠蔽されている | 学習者が `RawHttpComposer` でヘッダ・ボディを直接編集してから送信する |
| HTTP の生のやり取りが不可視 | raw bytes をキャプチャして `DataFlowPanel` に表示する |
| victim と orchestrator が同居 | victim-web は独立した Docker コンテナとして分離される |
| 隔離がソフトウェア境界のみ | `victim-net: internal: true` による OS レイヤの egress 遮断で補強する |

---

## 2. エンドポイント仕様

| 項目 | 値 |
|------|----|
| メソッド | `POST` |
| パス | `/api/orchestrator/exec` |
| Content-Type | `application/json` |
| 認証 | なし (localhost 限定 + production guard で代替) |
| タイムアウト | リクエストボディの `timeoutMs` フィールドで制御 (100–10000 ms) |
| Production 環境 | 503 `live_attack_disabled_in_production` を返す |

Vite proxy 設定 (`/api/*` → `http://localhost:3001`) により、ブラウザからは相対パスでアクセスする。

---

## 3. Request スキーマ (zod)

### 3.1 スキーマ定義

```typescript
import { z } from "zod";

export const orchestratorExecRequestSchema = z.object({
  /** AttackScenarioMeta.id と一致させる。例: "jwt-alg-none", "rbac-idor" */
  scenarioId: z.string().min(1).max(64),

  /** VICTIM_ALLOWLIST のキー文字列。baseUrl は orchestrator が allowlist から取得する。 */
  target: z.string().min(1).max(32),

  request: z.object({
    method: z.enum(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]),

    /** pathname + query string。必ず "/" で始まる。例: "/jwt/protected", "/rbac/resource/2" */
    path: z.string().regex(/^\//, "path must start with /").max(1024),

    /**
     * リクエストヘッダ。Host は orchestrator が強制上書きするため、
     * ブラウザが送ってきた Host 値は無視される (DNS rebinding 予防)。
     */
    headers: z.record(z.string(), z.string()),

    /** リクエストボディ。文字列または null。バイナリには未対応 (教育用 HTTP のみ)。 */
    body: z.union([z.string(), z.null()]).optional(),
  }),

  /** victim コンテナへの接続タイムアウト (ms)。デフォルト 3000。 */
  timeoutMs: z.number().int().min(100).max(10000).default(3000),
});

export type OrchestratorExecRequest = z.infer<typeof orchestratorExecRequestSchema>;
```

### 3.2 フィールド制約一覧

| フィールド | 型 | 制約 | 代表例 |
|------------|-----|------|--------|
| `scenarioId` | string | 1–64 文字 | `"jwt-alg-none"`, `"rbac-idor"` |
| `target` | string | 1–32 文字、VICTIM_ALLOWLIST のキーのみ有効 | `"victim-web"`, `"attacker-shell"` |
| `request.method` | enum | 7 種類に限定 | `"GET"`, `"POST"` |
| `request.path` | string | `/` で始まる、最大 1024 文字 | `"/jwt/protected"`, `"/rbac/resource/2"` |
| `request.headers` | Record | 任意。`Host` は orchestrator が上書き | `{ "Authorization": "Bearer eyJ..." }` |
| `request.body` | string \| null | 省略可。バイナリ非対応 | `'{"username":"seed_alice"}'` |
| `timeoutMs` | integer | 100–10000 ms | `3000` |

### 3.3 エラーケース

| HTTP ステータス | 条件 | レスポンス例 |
|----------------|------|-------------|
| 400 | zod スキーマ違反 | `{ error: "schema_validation_failed", _trace: { validationErrors: [...] } }` |
| 403 | `target` が VICTIM_ALLOWLIST に不在 | `{ error: "target_not_in_allowlist", _trace: { securityNote: "..." } }` |
| 502 | victim コンテナ到達不能 | `{ error: "victim_unreachable", detail: "ECONNREFUSED" }` |
| 503 | production mode または Phase 未到達 | `{ error: "live_attack_disabled_in_production" }` |
| 504 | `timeoutMs` 超過 | `{ error: "victim_timeout", timeoutMs: 3000 }` |

---

## 4. Response スキーマ

### 4.1 OrchestratorExecResponse

```typescript
import type { AttackResult } from "../../shared/api-types.js";

export interface RawHttpRequest {
  /** "POST /jwt/verify HTTP/1.1" 形式のリクエスト行 */
  line: string;
  headers: Record<string, string>;
  body: string | null;
  /** 送信した総バイト数 (ヘッダ + ボディ) */
  bytesSent: number;
}

export interface RawHttpResponse {
  /** "HTTP/1.1 200 OK" 形式のステータス行 */
  line: string;
  status: number;
  headers: Record<string, string>;
  body: string | null;
  /** 受信した総バイト数 (ヘッダ + ボディ) */
  bytesReceived: number;
}

export interface RawExchange {
  /** browser ⇄ orchestrator (フロント送信レイヤ) */
  browserToOrchestrator: {
    request: RawHttpRequest;
    response: RawHttpResponse;
  };
  /** orchestrator ⇄ victim (内部転送レイヤ) */
  orchestratorToVictim: {
    request: RawHttpRequest;
    response: RawHttpResponse;
    /** VICTIM_ALLOWLIST から解決された baseUrl */
    targetResolvedTo: string;
  };
  /** browser → orchestrator → victim → orchestrator → browser の総経過 (ms) */
  elapsedMs: number;
}

/**
 * POST /api/orchestrator/exec のレスポンス型。
 * AttackResult に live モード専用フィールドを追加する。
 */
export interface OrchestratorExecResponse extends AttackResult {
  /**
   * 双方向 raw HTTP キャプチャ。DataFlowPanel の HTTP/Sequence タブに表示する。
   * browser⇄orchestrator と orchestrator⇄victim の両ペアをメモリ上のみ保持し、
   * attack_log テーブルには summary のみ書き込む (raw bytes の永続化禁止)。
   */
  rawExchange: RawExchange;

  /** "live" 固定。フロント側が mode バッジを表示するために参照する。 */
  mode: "live";
}
```

`OrchestratorExecResponse` および `RawExchange` 型は `shared/api-types.ts` に追加する (フロント/バックエンド共有のため)。

### 4.2 `_trace` 拡張フィールド

`ServerTrace` に以下の 2 フィールドを追加する。`mode: "live"` の場合にのみ設定される。

```typescript
// shared/api-types.ts の ServerTrace への追加
export interface ServerTrace {
  dbQueries?: DbQuery[];
  cryptoOps?: CryptoOp[];
  sessionOps?: SessionOp[];
  attackSteps?: AttackStep[];
  isAttackMode?: boolean;

  /** "live" = victim コンテナとの実通信 / "narration" = orchestrator 内部シム (追加) */
  mode?: "live" | "narration";

  /**
   * victim 側の内部クエリは orchestrator から観測不能であることを示す注記。
   * mode: "live" のときのみ設定する。
   */
  victimNote?: string;
}
```

### 4.3 `AttackStep.kind` 生成ロジック

orchestrator は victim との通信結果をもとに以下の 3 段階のステップを自動組立する。

| ステップ | kind | 説明 |
|---------|------|------|
| 1 | `"probe"` | リクエストを victim に送信した事実を記録する |
| 2 | `"exploit"` | victim が 2xx を返した場合 (攻撃が設計上成立した条件を示す) |
| 2 (代替) | `"blocked"` | victim が 4xx/5xx を返した場合 (防御が機能したことを示す) |
| 3 | `"verify"` | 攻撃の成否判定ロジックと防御機構の確認を記録する |

**`AttackResult.outcome` の値設定ルール (live モード)**: live モードでも `outcome` は常に `"succeeded"` を返す (DESIGN/03 §1.4 E-2 既定に準拠)。攻撃成立/失敗の判定は `steps[].kind` (probe/exploit/blocked/verify) および `steps[].status` で表現する。`AttackResultBanner` は最終ステップの `kind === "blocked"` の有無で防御成立を判定する。

---

## 5. VICTIM_ALLOWLIST 構造

### 5.1 型定義

```typescript
export interface VictimEntry {
  /**
   * 転送先 URL。docker-compose の DNS 解決のみで完結する。
   * 環境変数での上書きは禁止 (§5.3 参照)。
   * "exec://" で始まる場合は docker exec 経由の実行を示す (attacker-shell 専用)。
   */
  baseUrl: string;

  /** この victim が接続する Docker ネットワーク名。 */
  network: "victim-net";

  /** この victim が利用可能になる最初の Phase 番号。 */
  phaseAvailable: 1 | 2 | 3 | 4 | 5;
}

export type VictimTarget =
  | "victim-web"
  | "attacker-shell"
  | "victim-tls-proxy"
  | "victim-saml-idp";

export const VICTIM_ALLOWLIST: ReadonlyMap<VictimTarget, VictimEntry> = new Map([
  ["victim-web", {
    baseUrl: "http://victim-web:4001",
    network: "victim-net",
    phaseAvailable: 1,
  }],
  ["attacker-shell", {
    // docker exec 経由。HTTP プロキシではなくコマンド実行に使用する。
    baseUrl: "exec://attacker-shell",
    network: "victim-net",
    phaseAvailable: 1,
  }],
  // ── Phase 4 で追加 ─────────────────────────────────────────────────────
  // ["victim-tls-proxy", {
  //   baseUrl: "https://victim-tls-proxy:443",
  //   network: "victim-net",
  //   phaseAvailable: 4,
  // }],
  // ["victim-saml-idp", {
  //   baseUrl: "http://victim-saml-idp:5000",
  //   network: "victim-net",
  //   phaseAvailable: 4,
  // }],
]);
```

### 5.2 Phase 別利用可能性

| target | Phase 1 | Phase 2 | Phase 3 | Phase 4 | Phase 5 |
|--------|---------|---------|---------|---------|---------|
| victim-web | 利用可 | 利用可 | 利用可 | 利用可 | 利用可 |
| attacker-shell | 利用可 | 利用可 | 利用可 | 利用可 | 利用可 |
| victim-tls-proxy | — | — | — | 利用可 | 利用可 |
| victim-saml-idp | — | — | — | 利用可 | 利用可 |

`phaseAvailable > currentPhase` の場合、503 `phase_not_reached` を返す。`currentPhase` は環境変数
`LIVE_ATTACK_PHASE` (デフォルト `1`) で制御する。

### 5.3 URL 偽造防止の設計

- リクエストの `target` フィールドはキー文字列 (`"victim-web"` 等) のみを受け付ける。
- `baseUrl` は orchestrator が `VICTIM_ALLOWLIST` から取得する。ブラウザから URL を直接指定する手段はない。
- 環境変数による `baseUrl` の上書きは禁止する。docker-compose の DNS 解決のみで転送先を確定させる。
- `Host` ヘッダは orchestrator が `baseUrl` の hostname:port から計算して強制上書きする (§6.3 参照)。

---

## 6. raw HTTP プロキシ実装方針

### 6.1 使用モジュール

Node.js 組み込みの `http` モジュールを直接使用する。axios、node-fetch、undici は使用しない。
理由: raw bytes を `Buffer.concat` でフルキャプチャするために、低レベルな `http.ClientRequest` が必要。

### 6.2 実装擬似コード

```typescript
import * as http from "node:http";
import * as https from "node:https";

async function proxyToVictim(
  entry: VictimEntry,
  req: OrchestratorExecRequest["request"],
  timeoutMs: number,
): Promise<{ exchange: RawExchange }> {
  const base = new URL(entry.baseUrl);
  const isHttps = base.protocol === "https:";
  const transport = isHttps ? https : http;
  const startedAt = Date.now();

  // Host ヘッダを allowlist の baseUrl から計算して強制上書きする
  const forcedHeaders: Record<string, string> = {
    ...req.headers,
    Host: base.host,           // DNS rebinding 予防
    Connection: "close",
  };
  if (req.body) {
    forcedHeaders["Content-Length"] = String(Buffer.byteLength(req.body, "utf8"));
  }

  return new Promise((resolve, reject) => {
    const clientReq = transport.request({
      hostname: base.hostname,
      port: base.port || (isHttps ? 443 : 80),
      path: req.path,
      method: req.method,
      headers: forcedHeaders,
    });

    clientReq.setTimeout(timeoutMs, () => {
      clientReq.destroy(new Error("victim_timeout"));
    });

    const responseChunks: Buffer[] = [];
    clientReq.on("response", (res) => {
      res.on("data", (chunk: Buffer) => responseChunks.push(chunk));
      res.on("end", () => {
        const rawBody = Buffer.concat(responseChunks);
        const elapsedMs = Date.now() - startedAt;
        resolve({
          exchange: {
            request: {
              line: `${req.method} ${req.path} HTTP/1.1`,
              headers: forcedHeaders,
              body: req.body ?? null,
              bytesSent: /* ヘッダ文字列 + ボディ */ rawBody.length,
            },
            response: {
              line: `HTTP/1.1 ${res.statusCode} ${res.statusMessage}`,
              status: res.statusCode ?? 0,
              headers: res.headers as Record<string, string>,
              body: rawBody.toString("utf8"),
              bytesReceived: rawBody.length,
            },
            elapsedMs,
            targetResolvedTo: entry.baseUrl,
          },
        });
      });
    });

    clientReq.on("error", reject);
    if (req.body) clientReq.write(req.body);
    clientReq.end();
  });
}
```

### 6.3 `Host` ヘッダ強制上書き

ブラウザが送信した `Host` 値は無条件で破棄し、`VICTIM_ALLOWLIST[target].baseUrl` の
hostname:port を使用する。これにより DNS rebinding 攻撃の経路を物理的に閉じる。

### 6.4 bytes キャプチャポリシー

- browser⇄orchestrator と orchestrator⇄victim の**双方向** raw bytes を独立してキャプチャする。
  両ペアともメモリ上でのみ保持し、レスポンスとして一度だけ返す。
- `attack_log` テーブルには `scenarioId`, `outcome`, `elapsedMs`, `targetResolvedTo` の
  summary のみ書き込む。`rawExchange` の完全な bytes (双方向分) は永続化しない (ROB-FIND 対策)。

---

## 7. `_trace` 整形 (middleware 拡張)

### 7.1 既存 `trace-logger.ts` への変更点

`traceContext` に `mode` フィールドを追加する。`isAttackMode` は既存実装のまま流用する。

```typescript
// server/middleware/trace-logger.ts への変更

// ① TraceCollector インタフェースに setLiveMode() を追加
export interface TraceCollector {
  addDbQuery(q: DbQuery): void;
  addCryptoOp(op: CryptoOp): void;
  addSessionOp(op: SessionOp): void;
  addAttackStep(step: AttackStep | Omit<AttackStep, "timestamp">): void;
  /** orchestrator/exec ルートが呼び出す。mode: "live" を _trace に付与する。 */
  setLiveMode(): void;
  getTrace(): ServerTrace;
}

// ② createTraceCollector() 内部に mode フラグを追加
function createTraceCollector(): TraceCollector {
  let liveMode = false;
  // ... 既存の配列定義は変更なし ...
  return {
    // ... 既存メソッドは変更なし ...
    setLiveMode() { liveMode = true; },
    getTrace() {
      const trace: ServerTrace = {};
      // ... 既存フィールド付与は変更なし ...
      if (liveMode) {
        trace.mode = "live";
        trace.victimNote =
          "victim コンテナ内部の DB クエリ・暗号操作は orchestrator から観測不能です";
      }
      return trace;
    },
  };
}

// ③ traceMiddleware の isAttackMode 判定に orchestrator パスを追加
const isAttackPath =
  ctx.req.path.includes("/attack/") ||
  ctx.req.path.startsWith("/api/orchestrator/");
```

### 7.2 victim 側 `_trace` の不可視性

orchestrator は victim コンテナとの通信を HTTP プロキシとして行うため、
victim 内部で発生した DB クエリ・暗号操作は `_trace` に含まれない。
`_trace.victimNote` にその旨を明示し、学習者が「なぜ victim の内部クエリが見えないか」
を理解できるよう補足する。

---

## 8. Production guard

### 8.1 動作仕様

`process.env.NODE_ENV === "production"` の場合、`/api/orchestrator/*` へのすべてのリクエストに
503 を返す。本機能は教育用ローカル環境専用であり、誤って本番デプロイされた場合の防護線とする。

```typescript
// server/middleware/production-guard.ts (新規作成)
import type { Context, Next } from "hono";

export async function productionGuard(ctx: Context, next: Next) {
  if (process.env.NODE_ENV === "production") {
    return ctx.json(
      { success: false, error: "live_attack_disabled_in_production" },
      503,
    );
  }
  await next();
}
```

### 8.2 登録位置

`server/index.ts` でルート登録前に `productionGuard` を適用する。

```typescript
// server/index.ts への追加
import { productionGuard } from "./middleware/production-guard.js";
import { orchestratorExecRoutes } from "./routes/orchestrator-exec.js";

app.use("/api/orchestrator/*", productionGuard);
app.route("/api/orchestrator", orchestratorExecRoutes);
```

`/api/<area>/attack/*` 既存ルートは別途 `NODE_ENV !== "production"` ガードを適用済 (該当箇所は実装時に確認)。
`/api/orchestrator/*` 専用の独立したガードとして定義することで役割を明確に分離する。

---

## 9. エラーハンドリング

### 9.1 エラーコード一覧

| HTTP | エラーコード | 発生条件 | `_trace` への記録 |
|------|-------------|---------|------------------|
| 400 | `schema_validation_failed` | zod バリデーション違反 | `validationErrors: ZodIssue[]` |
| 403 | `target_not_in_allowlist` | `target` が VICTIM_ALLOWLIST に存在しない | `securityNote: "不正な target 値の可能性あり"` |
| 502 | `victim_unreachable` | コンテナ未起動、ネットワーク不通 (ECONNREFUSED / ENOTFOUND) | `detail: err.message` |
| 503 | `live_attack_disabled_in_production` | `NODE_ENV === "production"` | なし |
| 503 | `phase_not_reached` | `phaseAvailable > currentPhase` | `requiredPhase`, `currentPhase` |
| 504 | `victim_timeout` | `timeoutMs` 超過 | `timeoutMs: number` |

### 9.2 403 の特別扱い

`target` が VICTIM_ALLOWLIST に存在しない場合は URL 偽造試行の可能性があるため、
`_trace.securityNote` に記録するとともに orchestrator サーバーのログに WARNING レベルで出力する。
レスポンスに `target` の実際の値は含めない (情報漏洩防止)。

### 9.3 502 のユーザー向けメッセージ

```typescript
// DataFlowPanel で表示するヒントメッセージ
const victimUnreachableHint = t(
  "victim コンテナに到達できません。`npm run dev` または `docker compose up` を実行してください。",
  "Cannot reach victim container. Run `npm run dev` or `docker compose up`.",
);
```

---

## 10. 共存方針 (既存ナレーション型 `/attack/*` との関係)

### 10.1 フロント側のルーティング切り替え

`AttackScenarioMeta` に `mode` フィールドを追加し (DESIGN/30 §6.2 の提案を正式採用)、
フロントが呼び出し先を動的に切り替える。

```typescript
// shared/api-types.ts の AttackScenarioMeta への追加
export interface AttackScenarioMeta {
  // ... 既存フィールド ...

  /**
   * "live"     : Docker victim コンテナと実通信 → /api/orchestrator/exec
   * "narration": orchestrator 内部シム → /api/<area>/attack/<scenario>
   */
  mode: "live" | "narration";
}
```

```typescript
// AttackPanel.tsx での切り替えロジック (概念)
async function runAttack(scenario: AttackScenarioMeta) {
  if (scenario.mode === "live") {
    const res = await apiPost<OrchestratorExecResponse>(
      "/api/orchestrator/exec",
      { scenarioId: scenario.id, target: "victim-web", request: composedRequest() },
      SCOPE,
    );
    setCurrentResult(res.data);
  } else {
    const res = await apiPost<AttackResult>(scenario.apiPath, params, SCOPE);
    setCurrentResult(res.data);
  }
}
```

### 10.2 バッジ表示

`mode: "live"` のシナリオには DataFlowPanel に `LIVE` バッジ (`#52c41a`) を表示する。
`mode: "narration"` のシナリオには `SIMULATION` バッジ (`#8c8c8c`) を表示する。

### 10.3 Phase 5 での整理方針

Phase 5 では `mode === "narration"` のシナリオを再評価し、live 化が可能なものと
ナレーション型を維持するものを最終決定する (C/D 区分はナレーション維持確定)。

---

## 11. テスト要件

### 11.1 vitest + supertest テストチェックリスト

実装担当者は以下のテストを `server/__tests__/orchestrator-live.test.ts` に追加する。

- [ ] スキーマ違反 (必須フィールド欠如) → 400 + `validationErrors` を返す
- [ ] `target` が VICTIM_ALLOWLIST に不在 → 403 + `_trace.securityNote` が設定されている
- [ ] victim コンテナ未起動 (ECONNREFUSED) → 502 + `detail` にエラーメッセージが含まれる
- [ ] `timeoutMs: 100` でタイムアウト → 504 + `timeoutMs: 100` が返る
- [ ] `NODE_ENV=production` で起動 → 503 `live_attack_disabled_in_production` を返す
- [ ] 正常系: browser → orchestrator の raw bytes (`rawExchange.browserToOrchestrator`) と orchestrator → victim の raw bytes (`rawExchange.orchestratorToVictim`) が両方独立してキャプチャされる
- [ ] 正常系: レスポンスの `rawExchange.orchestratorToVictim.request.headers.Host` が victim の baseUrl から計算した値に強制上書きされている
- [ ] 正常系: `attack_log` には `scenarioId`, `outcome`, `elapsedMs` の summary のみ書かれ、`rawExchange` の双方向生データは含まれない
- [ ] 正常系: `_trace.mode === "live"` が設定されている
- [ ] 正常系: `_trace.victimNote` が設定されている

### 11.2 モック方針

victim コンテナへの HTTP 通信は `nock` または `http.createServer` で in-process にモックする。
実際の docker compose 起動は `test:live` スクリプト (CI 用) でのみ行う。

```json
// package.json (追加分)
{
  "scripts": {
    "test": "vitest",
    "test:live": "LIVE_ATTACK_PHASE=1 vitest --project=live"
  }
}
```

---

## 関連ファイル

### 本シリーズ (DESIGN/30–34)

| ファイル | 内容 |
|---------|------|
| `DESIGN/30-live-attack-architecture.md` | 全体設計・アーキ選択・ロードマップ (本仕様の上流) |
| `DESIGN/31-orchestrator-spec.md` | 本ファイル |
| `DESIGN/32-victim-web-spec.md` | 本仕様の `target` で参照される victim-web の全エンドポイント定義 |
| `DESIGN/33-raw-http-composer.md` | 本仕様の Request を組み立てるフロントの UI 仕様 |
| `DESIGN/34-safety-guardrails-live.md` | 本仕様が依拠する安全装置の詳細実装 |

### 既存ファイル (拡張対象)

| ファイルパス | 変更内容 |
|------------|---------|
| `shared/api-types.ts` | `ServerTrace` に `mode`, `victimNote` を追加。`AttackScenarioMeta` に `mode` を追加 |
| `server/middleware/trace-logger.ts` | `TraceCollector` に `setLiveMode()` を追加。`getTrace()` で `mode: "live"` と `victimNote` を付与 |
| `server/index.ts` | `productionGuard` ミドルウェアを `/api/orchestrator/*` に登録。`orchestratorExecRoutes` を追加 |

### Phase 1 で新規作成するファイル

| ファイルパス | 役割 |
|------------|------|
| `server/routes/orchestrator-exec.ts` | `POST /api/orchestrator/exec` ハンドラ本体 |
| `server/middleware/production-guard.ts` | `NODE_ENV === "production"` ガード |
| `server/__tests__/orchestrator-live.test.ts` | 本仕様のユニット・統合テスト |
