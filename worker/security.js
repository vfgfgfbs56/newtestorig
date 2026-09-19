const encoder = new TextEncoder();

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
  let binary = "";
  for (const b of sig) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function clientAddress(request) {
  return request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For")?.split(",")[0]?.trim() || "local";
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
}

export async function verifyTurnstile(env, request, token, expectedAction) {
  if (!env.TURNSTILE_SECRET_KEY || !env.TURNSTILE_SITE_KEY) throw new Error("TURNSTILE_NOT_CONFIGURED");
  if (typeof token !== "string" || token.length < 10 || token.length > 2048) throw new Error("TURNSTILE_INVALID");

  const body = {
    secret: env.TURNSTILE_SECRET_KEY,
    response: token,
    remoteip: clientAddress(request),
    idempotency_key: crypto.randomUUID(),
  };

  const response = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok || !result.success) throw new Error("TURNSTILE_INVALID");

  if (expectedAction && result.action && result.action !== expectedAction) {
    throw new Error("TURNSTILE_INVALID");
  }
  const expectedHostname = new URL(request.url).hostname;
  if (result.hostname && result.hostname !== expectedHostname) {
    throw new Error("TURNSTILE_INVALID");
  }
  return true;
}

export async function cleanupSecurity(env) {
  const now = Math.floor(Date.now() / 1000);
  await env.DB.prepare("DELETE FROM jend_replay WHERE expires_at <= ?1").bind(now).run();
  await env.DB.prepare("DELETE FROM rate_limits WHERE expires_at <= ?1").bind(now).run();
}
