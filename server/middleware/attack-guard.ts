import type { Context } from "hono";

/**
 * 攻撃デモエンドポイント用ガード。
 * 本番環境では攻撃ルートを無効化する。
 * Phase 1 の各攻撃ルートハンドラ先頭で呼び出す。
 *
 * @returns null なら処理続行、Response なら即返却すること
 */
export function ensureAttackEnabled(c: Context): Response | null {
  if (process.env.NODE_ENV === "production") {
    return c.json(
      { success: false, error: "Attack demo endpoints are disabled in production" },
      403
    ) as Response;
  }
  return null;
}
