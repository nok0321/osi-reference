/**
 * Production guard for /api/orchestrator/*
 *
 * NODE_ENV === "production" のとき 503 を返す。
 * 教育用ローカル環境専用エンドポイントが本番デプロイされた場合の防護線。
 *
 * 関連設計書: DESIGN/31 §8, DESIGN/34 §4
 */
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
