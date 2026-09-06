let schemaPromise = null;

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
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (approved_device_id) REFERENCES devices(id) ON DELETE SET NULL
    )`),
    env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_qr_sessions_expires_at ON qr_sessions(expires_at)`),
    env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_qr_sessions_status ON qr_sessions(status)`),
  ]);
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
