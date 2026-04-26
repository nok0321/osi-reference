import { getDb } from "./schema.js";
import type { UserRow } from "../../shared/api-types.js";
import type Database from "better-sqlite3";

/** Find a user by username. Returns id + username only. */
export function findUserByUsername(username: string): Pick<UserRow, "id" | "username"> | undefined {
  const db = getDb();
  return db.prepare("SELECT id, username FROM users WHERE username = ?").get(username) as Pick<UserRow, "id" | "username"> | undefined;
}

/** Find a user by id. Returns id + username only. */
export function findUserById(id: number): Pick<UserRow, "id" | "username"> | undefined {
  const db = getDb();
  return db.prepare("SELECT id, username FROM users WHERE id = ?").get(id) as Pick<UserRow, "id" | "username"> | undefined;
}

/**
 * Delete expired *normal-flow* sessions from the sessions table. Returns count of deleted rows.
 *
 * E-3: is_attack_sim=1 のレコードは攻撃シミュレーション履歴として attack_log と紐付くため、
 * バックグラウンドの定期削除対象から除外する (DESIGN/04 §5.3 の正常系除外原則準拠)。
 */
export function cleanExpiredSessions(): number {
  const db = getDb();
  const result = db.prepare("DELETE FROM sessions WHERE expires_at < datetime('now') AND is_attack_sim = 0").run();
  return result.changes;
}

/** 攻撃ログ行を新規作成。started_at は now、success=0 で初期化。 */
export function insertAttackLog(
  db: Database.Database,
  args: { scenarioId: string; tabId: string; userSessionId?: string | null }
): number {
  const stmt = db.prepare(
    `INSERT INTO attack_log (scenario_id, tab_id, started_at, success, user_session_id)
     VALUES (?, ?, ?, 0, ?)`
  );
  const info = stmt.run(args.scenarioId, args.tabId, Date.now(), args.userSessionId ?? null);
  return Number(info.lastInsertRowid);
}

/** 攻撃ログ行を完了状態に更新。steps_json / payload_json を保存。 */
export function finalizeAttackLog(
  db: Database.Database,
  id: number,
  args: { success: boolean; blockedBy?: string | null; stepsJson?: string | null; payloadJson?: string | null }
): void {
  db.prepare(
    `UPDATE attack_log
     SET success = ?, finished_at = ?, blocked_by = ?, steps_json = ?, payload_json = ?
     WHERE id = ?`
  ).run(
    args.success ? 1 : 0,
    Date.now(),
    args.blockedBy ?? null,
    args.stepsJson ?? null,
    args.payloadJson ?? null,
    id
  );
}
