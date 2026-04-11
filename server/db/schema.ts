import Database from "better-sqlite3";
import bcrypt from "bcryptjs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DB_PATH = path.join(__dirname, "data.sqlite");

let db: Database.Database;

export function getDb(): Database.Database {
  if (!db) {
    db = new Database(DB_PATH);
    db.pragma("journal_mode = WAL");
    db.pragma("foreign_keys = ON");
    initSchema(db);
  }
  return db;
}

/** Replace the DB singleton (for testing with in-memory DB). */
export function _setDbForTest(testDb: Database.Database): void {
  db = testDb;
}

/** Create an in-memory DB with full schema. */
export function _createTestDb(): Database.Database {
  const memDb = new Database(":memory:");
  memDb.pragma("foreign_keys = ON");
  initSchema(memDb);
  return memDb;
}

function initSchema(db: Database.Database) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      data TEXT DEFAULT '{}',
      created_at TEXT DEFAULT (datetime('now')),
      expires_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS oauth_clients (
      client_id TEXT PRIMARY KEY,
      client_secret TEXT NOT NULL,
      name TEXT NOT NULL,
      redirect_uris TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS oauth_codes (
      code TEXT PRIMARY KEY,
      client_id TEXT NOT NULL,
      user_id INTEGER NOT NULL,
      scope TEXT,
      redirect_uri TEXT,
      expires_at TEXT NOT NULL,
      used INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS oauth_tokens (
      access_token TEXT PRIMARY KEY,
      refresh_token TEXT UNIQUE,
      client_id TEXT NOT NULL,
      user_id INTEGER NOT NULL,
      scope TEXT,
      expires_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS roles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      description TEXT
    );

    CREATE TABLE IF NOT EXISTS user_roles (
      user_id INTEGER NOT NULL,
      role_id INTEGER NOT NULL,
      PRIMARY KEY (user_id, role_id),
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (role_id) REFERENCES roles(id)
    );

    CREATE TABLE IF NOT EXISTS permissions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      resource TEXT NOT NULL,
      action TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS role_permissions (
      role_id INTEGER NOT NULL,
      permission_id INTEGER NOT NULL,
      PRIMARY KEY (role_id, permission_id),
      FOREIGN KEY (role_id) REFERENCES roles(id),
      FOREIGN KEY (permission_id) REFERENCES permissions(id)
    );

    CREATE TABLE IF NOT EXISTS webauthn_credentials (
      credential_id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      public_key TEXT NOT NULL,
      counter INTEGER DEFAULT 0,
      transports TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS api_keys (
      key_id TEXT PRIMARY KEY,
      key_prefix TEXT NOT NULL,
      key_hash TEXT NOT NULL,
      user_id INTEGER,
      name TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      last_used TEXT
    );

    CREATE TABLE IF NOT EXISTS kerberos_tickets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ticket_type TEXT NOT NULL,
      principal TEXT NOT NULL,
      realm TEXT DEFAULT 'OSI-DEMO.LOCAL',
      encrypted_data TEXT NOT NULL,
      session_key TEXT NOT NULL,
      valid_until TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS user_mfa (
      user_id INTEGER PRIMARY KEY,
      secret TEXT NOT NULL,
      verified INTEGER NOT NULL DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now')),
      verified_at TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    -- Indexes for frequently queried columns
    CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
    CREATE INDEX IF NOT EXISTS idx_oauth_codes_client_id ON oauth_codes(client_id);
    CREATE INDEX IF NOT EXISTS idx_oauth_codes_expires_at ON oauth_codes(expires_at);
    CREATE INDEX IF NOT EXISTS idx_oauth_tokens_client_id ON oauth_tokens(client_id);
    CREATE INDEX IF NOT EXISTS idx_oauth_tokens_user_id ON oauth_tokens(user_id);
    CREATE INDEX IF NOT EXISTS idx_oauth_tokens_refresh_token ON oauth_tokens(refresh_token);
    CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
    CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id ON role_permissions(role_id);
    CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user_id ON webauthn_credentials(user_id);
    CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);
    CREATE INDEX IF NOT EXISTS idx_kerberos_tickets_principal ON kerberos_tickets(principal);
    CREATE INDEX IF NOT EXISTS idx_user_mfa_user_id ON user_mfa(user_id);
  `);
}

export function seedDb() {
  const d = getDb();

  // Clear all tables
  d.exec(`
    DELETE FROM kerberos_tickets;
    DELETE FROM api_keys;
    DELETE FROM webauthn_credentials;
    DELETE FROM user_mfa;
    DELETE FROM role_permissions;
    DELETE FROM user_roles;
    DELETE FROM permissions;
    DELETE FROM roles;
    DELETE FROM oauth_tokens;
    DELETE FROM oauth_codes;
    DELETE FROM oauth_clients;
    DELETE FROM sessions;
    DELETE FROM users;
  `);

  // Seed OAuth client
  d.prepare(
    `INSERT INTO oauth_clients (client_id, client_secret, name, redirect_uris) VALUES (?, ?, ?, ?)`
  ).run(
    "demo-app",
    "demo-secret-12345",
    "OSI Reference Demo App",
    JSON.stringify(["http://localhost:3000/auth/oauth/callback"])
  );

  // Seed roles
  const insertRole = d.prepare(
    `INSERT INTO roles (name, description) VALUES (?, ?)`
  );
  insertRole.run("admin", "Full access to all resources");
  insertRole.run("editor", "Can read and write articles");
  insertRole.run("viewer", "Read-only access");

  // Seed permissions
  const insertPerm = d.prepare(
    `INSERT INTO permissions (name, resource, action) VALUES (?, ?, ?)`
  );
  const resources = ["articles", "users", "settings"];
  const actions = ["read", "write", "delete"];
  for (const r of resources) {
    for (const a of actions) {
      insertPerm.run(`${r}:${a}`, r, a);
    }
  }

  // Seed role_permissions (admin=all, editor=articles rw + users r, viewer=read only)
  const allPerms = d
    .prepare(`SELECT id, name FROM permissions`)
    .all() as { id: number; name: string }[];
  const roleAdmin = d
    .prepare(`SELECT id FROM roles WHERE name = ?`)
    .get("admin") as { id: number };
  const roleEditor = d
    .prepare(`SELECT id FROM roles WHERE name = ?`)
    .get("editor") as { id: number };
  const roleViewer = d
    .prepare(`SELECT id FROM roles WHERE name = ?`)
    .get("viewer") as { id: number };

  const insertRP = d.prepare(
    `INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)`
  );
  for (const p of allPerms) {
    insertRP.run(roleAdmin.id, p.id);
    if (
      p.name.startsWith("articles:read") ||
      p.name.startsWith("articles:write") ||
      p.name.startsWith("users:read")
    ) {
      insertRP.run(roleEditor.id, p.id);
    }
    if (p.name.endsWith(":read")) {
      insertRP.run(roleViewer.id, p.id);
    }
  }

  // Seed demo users (for OIDC / SAML / other demos that use hardcoded credentials)
  const demoPassword = bcrypt.hashSync("demo123", 10);
  const insertUser = d.prepare(
    `INSERT INTO users (username, password_hash) VALUES (?, ?)`
  );
  insertUser.run("oidc-user", demoPassword);
  insertUser.run("saml-user", demoPassword);

  return { message: "Database seeded successfully" };
}

export function resetDb() {
  seedDb();
}
