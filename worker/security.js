const encoder = new TextEncoder();

function toBase64Url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64Url(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("GUARD_BAD_PROOF");
  let s = value.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const binary = atob(s);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function randomBytes(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

async function hmacBase64Url(secret, value) {
  if (!secret || secret.length < 32) throw new Error("Server secret is missing or too short");
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(value)));
  return toBase64Url(sig);
}

function clientAddress(request) {
  return request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For")?.split(",")[0]?.trim() || "local";
}

async function clientBinding(env, request) {
  const ip = clientAddress(request);
  const ua = (request.headers.get("User-Agent") || "").slice(0, 256);
  return hmacBase64Url(env.LOGIN_HMAC_KEY, `guard-client:${ip}\n${ua}`);
}

export async function enforceRateLimit(env, request, action, limit, windowSeconds) {
  const now = Math.floor(Date.now() / 1000);
  const windowStart = Math.floor(now / windowSeconds) * windowSeconds;
  const ipHash = await hmacBase64Url(env.LOGIN_HMAC_KEY, `rate-ip:${clientAddress(request)}`);
  const bucketKey = await hmacBase64Url(env.LOGIN_HMAC_KEY, `rate:${action}:${windowStart}:${ipHash}`);
  const expiresAt = windowStart + windowSeconds + 60;

  await env.DB.prepare("DELETE FROM rate_limits WHERE expires_at <= ?1").bind(now).run();
  await env.DB.prepare(
    `INSERT INTO rate_limits (bucket_key, window_start, count, expires_at)
     VALUES (?1, ?2, 1, ?3)
     ON CONFLICT(bucket_key) DO UPDATE SET count = count + 1`
  ).bind(bucketKey, windowStart, expiresAt).run();

  const row = await env.DB.prepare(
    "SELECT count FROM rate_limits WHERE bucket_key = ?1 LIMIT 1"
  ).bind(bucketKey).first();
  const count = Number(row?.count || 0);
  if (count > limit) {
    const error = new Error("RATE_LIMITED");
    error.retryAfter = Math.max(1, windowStart + windowSeconds - now);
    throw error;
  }
  return count;
}

function guardDifficulty(action, pressure = 1) {
  const base = action === "register" ? 18 : 17;
  const adaptive = pressure > 16 ? 2 : pressure > 8 ? 1 : 0;
  return Math.min(21, base + adaptive);
}

export async function issueGuardChallenge(env, request, action, pressure = 1) {
  if (!new Set(["register", "qr-create"]).has(action)) throw new Error("GUARD_BAD_ACTION");
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + 90;
  const id = crypto.randomUUID();
  const seed = randomBytes(32);
  const seedB64 = toBase64Url(seed);
  const difficulty = guardDifficulty(action, pressure);
  const binding = await clientBinding(env, request);

  await env.DB.prepare("DELETE FROM bot_challenges WHERE expires_at <= ?1 OR (used_at IS NOT NULL AND used_at <= ?2)").bind(now, now - 60).run();
  await env.DB.prepare(
    `INSERT INTO bot_challenges
      (id, action, seed, difficulty, client_binding, created_at, expires_at, used_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL)`
  ).bind(id, action, seedB64, difficulty, binding, now, expiresAt).run();

  return { id, seed: seedB64, difficulty, expiresAt, algorithm: "sha256-pow-v1" };
}

function hasLeadingZeroBits(bytes, bits) {
  const full = Math.floor(bits / 8);
  const rem = bits % 8;
  for (let i = 0; i < full; i++) if (bytes[i] !== 0) return false;
  if (rem) {
    const mask = (0xff << (8 - rem)) & 0xff;
    if ((bytes[full] & mask) !== 0) return false;
  }
  return true;
}

function counterBytes(counter) {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, counter, true);
  return out;
}

export async function verifyGuardProof(env, request, proof, expectedAction) {
  if (!proof || typeof proof !== "object") throw new Error("GUARD_REQUIRED");
  const { id, counter } = proof;
  if (typeof id !== "string" || id.length < 20 || id.length > 64) throw new Error("GUARD_BAD_PROOF");
  if (!Number.isInteger(counter) || counter < 0 || counter > 0x7fffffff) throw new Error("GUARD_BAD_PROOF");

  const now = Math.floor(Date.now() / 1000);
  const row = await env.DB.prepare(
    `SELECT action, seed, difficulty, client_binding, expires_at, used_at
     FROM bot_challenges WHERE id = ?1 LIMIT 1`
  ).bind(id).first();

  if (!row || row.used_at != null || Number(row.expires_at) < now) throw new Error("GUARD_EXPIRED");
  if (row.action !== expectedAction) throw new Error("GUARD_BAD_PROOF");
  const binding = await clientBinding(env, request);
  if (binding !== row.client_binding) throw new Error("GUARD_BAD_PROOF");

  const seed = fromBase64Url(row.seed);
  if (seed.length !== 32) throw new Error("GUARD_BAD_PROOF");
  const message = new Uint8Array(36);
  message.set(seed, 0);
  message.set(counterBytes(counter), 32);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", message));
  if (!hasLeadingZeroBits(digest, Number(row.difficulty))) throw new Error("GUARD_BAD_PROOF");

  const claimed = await env.DB.prepare(
    `UPDATE bot_challenges SET used_at = ?1
     WHERE id = ?2 AND used_at IS NULL AND expires_at >= ?1`
  ).bind(now, id).run();
  if (!claimed.meta?.changes) throw new Error("GUARD_REPLAY");
  return true;
}

export async function cleanupSecurity(env) {
  const now = Math.floor(Date.now() / 1000);
  await env.DB.prepare("DELETE FROM jend_replay WHERE expires_at <= ?1").bind(now).run();
  await env.DB.prepare("DELETE FROM rate_limits WHERE expires_at <= ?1").bind(now).run();
  await env.DB.prepare("DELETE FROM bot_challenges WHERE expires_at <= ?1 OR (used_at IS NOT NULL AND used_at <= ?2)")
    .bind(now, now - 60).run();
}
