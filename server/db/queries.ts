import { getDb } from "./schema.js";
import type { UserRow } from "../../shared/api-types.js";

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

/** Delete expired sessions from the sessions table. Returns count of deleted rows. */
export function cleanExpiredSessions(): number {
  const db = getDb();
  const result = db.prepare("DELETE FROM sessions WHERE expires_at < datetime('now')").run();
  return result.changes;
}
