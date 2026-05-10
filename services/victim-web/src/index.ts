/**
 * 脆弱 victim アプリケーション (services/victim-web)
 *
 * 【教育目的専用】
 * このプロセスは OSI 参照アプリの教材機能として、
 * docker-compose の `victim-net (internal: true)` 内で固定シードデータに対する
 * 概念実証エンドポイントを提供します。
 *
 * - 外部ネットワークへのリクエストは行いません
 * - 実 CVE のエクスプロイトコードは含みません
 * - victim-net 外での動作は想定していません
 *
 * 関連設計書: DESIGN/04-safety-guardrails.md, DESIGN/32-victim-web-spec.md
 */
import { Hono } from "hono";
import { serve } from "@hono/node-server";
import { jwtVulnRoutes } from "./routes/jwt-vuln.js";
import { oauthVulnRoutes } from "./routes/oauth-vuln.js";
import { rbacVulnRoutes } from "./routes/rbac-vuln.js";

const app = new Hono();

app.get("/health", (c) =>
  c.json({ status: "ok", service: "victim-web", time: new Date().toISOString() }),
);

app.route("/jwt", jwtVulnRoutes);
app.route("/oauth", oauthVulnRoutes);
app.route("/rbac", rbacVulnRoutes);

// PORT は docker container 環境用 (compose で PORT=4001 を渡す)。
// host で `dev:no-docker` を実行すると vite が PORT=3000 を環境にセットするため、
// それを避ける目的で VICTIM_PORT を最優先 env に採用する。
const PORT = Number(process.env.VICTIM_PORT ?? process.env.VICTIM_WEB_PORT ?? 4001);
console.log(`[victim-web] vulnerable demo server listening on :${PORT}`);
serve({ fetch: app.fetch, port: PORT });
