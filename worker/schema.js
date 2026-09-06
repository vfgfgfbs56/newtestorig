let schemaPromise = null;

async function ensureQrColumns(env) {
  const info = await env.DB.prepare("PRAGMA table_info(qr_sessions)").all();
  const columns = new Set((info.results || []).map((row) => row.name));
  const statements = [];

  if (!columns.has("phase")) {
    statements.push(env.DB.prepare("ALTER TABLE qr_sessions ADD COLUMN phase TEXT NOT NULL DEFAULT 'waiting_scan'"));
  }
  if (!columns.has("password_attempt_id")) {
    statements.push(env.DB.prepare("ALTER TABLE qr_sessions ADD COLUMN password_attempt_id TEXT"));
  }
  if (!columns.has("password_iv")) {
    statements.push(env.DB.prepare("ALTER TABLE qr_sessions ADD COLUMN password_iv TEXT"));
  }
  if (!columns.has("password_cipher")) {
    statements.push(env.DB.prepare("ALTER TABLE qr_sessions ADD COLUMN password_cipher TEXT"));
  }
  if (!columns.has("password_failures")) {
    statements.push(env.DB.prepare("ALTER TABLE qr_sessions ADD COLUMN password_failures INTEGER NOT NULL DEFAULT 0"));
  }
  if (!columns.has("password_result")) {
    statements.push(env.DB.prepare("ALTER TABLE qr_sessions ADD COLUMN password_result TEXT"));
  }

  if (statements.length) await env.DB.batch(statements);
}

async function initializeSchema(env) {
  if (!env.DB) throw new Error("MISSING_DB_BINDING");

  await env.DB.batch([
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      login_id TEXT NOT NULL UNIQUE,
      created_at INTEGER NOT NULL
    )`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS devices (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      public_jwk TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      revoked_at INTEGER,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )`),
    env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )`),
    env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)`),
    env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS qr_sessions (
      id TEXT PRIMARY KEY,
      approval_secret_hash TEXT NOT NULL,
      claim_secret_hash TEXT NOT NULL,
      challenge TEXT NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('pending','approved','denied','claimed','expired')),
      user_id TEXT,
      approved_device_id TEXT,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      claimed_at INTEGER,
      phase TEXT NOT NULL DEFAULT 'waiting_scan',
      password_attempt_id TEXT,
      password_iv TEXT,
      password_cipher TEXT,
      password_failures INTEGER NOT NULL DEFAULT 0,
      password_result TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (approved_device_id) REFERENCES devices(id) ON DELETE SET NULL
    )`),
    env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_qr_sessions_expires_at ON qr_sessions(expires_at)`),
    env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_qr_sessions_status ON qr_sessions(status)`),
  ]);

  await ensureQrColumns(env);
}

export function ensureSchema(env) {
  if (!schemaPromise) {
    schemaPromise = initializeSchema(env).catch((error) => {
      schemaPromise = null;
      throw error;
    });
  }
  return schemaPromise;
}
