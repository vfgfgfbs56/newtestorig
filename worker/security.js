import { coreGuardDecision, coreMinDelay, coreVersion } from "./core.js";

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

function coarseNetwork(ip) {
  if (ip.includes(".")) {
    const p = ip.split(".");
    return p.length === 4 ? `${p[0]}.${p[1]}.${p[2]}.0/24` : ip;
  }
  if (ip.includes(":")) {
    const p = ip.split(":");
    return `${p.slice(0, 4).join(":")}::/64`;
  }
  return ip;
}

async function clientBinding(env, request) {
  const ip = coarseNetwork(clientAddress(request));
  const ua = (request.headers.get("User-Agent") || "").slice(0, 256);
  const lang = (request.headers.get("Accept-Language") || "").slice(0, 80);
  return hmacBase64Url(env.LOGIN_HMAC_KEY, `guard-client-v2:${ip}\n${ua}\n${lang}`);
}

export async function enforceRateLimit(env, request, action, limit, windowSeconds) {
  const now = Math.floor(Date.now() / 1000);
  const windowStart = Math.floor(now / windowSeconds) * windowSeconds;
  const ipHash = await hmacBase64Url(env.LOGIN_HMAC_KEY, `rate-ip:${coarseNetwork(clientAddress(request))}`);
  const bucketKey = await hmacBase64Url(env.LOGIN_HMAC_KEY, `rate:${action}:${windowStart}:${ipHash}`);
  const expiresAt = windowStart + windowSeconds + 60;

  await env.DB.prepare("DELETE FROM rate_limits WHERE expires_at <= ?1").bind(now).run();
  await env.DB.prepare(
    `INSERT INTO rate_limits (bucket_key, window_start, count, expires_at)
     VALUES (?1, ?2, 1, ?3)
     ON CONFLICT(bucket_key) DO UPDATE SET count = count + 1`
  ).bind(bucketKey, windowStart, expiresAt).run();

  const row = await env.DB.prepare("SELECT count FROM rate_limits WHERE bucket_key = ?1 LIMIT 1")
    .bind(bucketKey).first();
  const count = Number(row?.count || 0);
  if (count > limit) {
    const error = new Error("RATE_LIMITED");
    error.retryAfter = Math.max(1, windowStart + windowSeconds - now);
    throw error;
  }
  return count;
}

function validAction(action) {
  return action === "register" || action === "qr-create";
}

function validateGuardId(value) {
  return typeof value === "string" && /^[A-Za-z0-9_-]{40,50}$/.test(value);
}

function validatePublicJwk(jwk) {
  return !!jwk && typeof jwk === "object" && jwk.kty === "EC" && jwk.crv === "P-256" &&
    typeof jwk.x === "string" && /^[A-Za-z0-9_-]{40,50}$/.test(jwk.x) &&
    typeof jwk.y === "string" && /^[A-Za-z0-9_-]{40,50}$/.test(jwk.y);
}

async function publicGuardId(jwk) {
  const canonical = `${jwk.crv}.${jwk.x}.${jwk.y}`;
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(canonical)));
  return toBase64Url(digest);
}

function guardPayload(row) {
  return `JEND-GUARD/2\n${row.id}\n${row.action}\n${row.nonce}\n${row.guard_id}\n${row.created_at_ms}`;
}

function headerFlags(request) {
  let flags = 0;
  const fetchSite = request.headers.get("Sec-Fetch-Site");
  if (!fetchSite || ["same-origin", "same-site", "none"].includes(fetchSite)) flags |= 1;

  const origin = request.headers.get("Origin");
  if (!origin || origin === new URL(request.url).origin) flags |= 2;

  const type = (request.headers.get("Content-Type") || "").toLowerCase();
  if (type.startsWith("application/jend")) flags |= 4;
  return flags;
}

export async function issueGuardChallenge(env, request, action, guardId, pressure = 1) {
  if (!validAction(action) || !validateGuardId(guardId)) throw new Error("GUARD_BAD_ACTION");

  const nowMs = Date.now();
  const binding = await clientBinding(env, request);
  const knownRow = await env.DB.prepare(
    "SELECT success_count, failure_count, blocked_until_ms FROM guard_devices_v2 WHERE guard_id = ?1 LIMIT 1"
  ).bind(guardId).first();
  const blockedUntil = Number(knownRow?.blocked_until_ms || 0);
  if (blockedUntil > nowMs) throw new Error("GUARD_BLOCKED");
  const knownDevice = Number(knownRow?.success_count || 0) >= 3;
  const minDelayMs = await coreMinDelay(action, pressure, knownDevice);
  const id = crypto.randomUUID();
  const nonce = toBase64Url(randomBytes(32));
  const expiresAtMs = nowMs + 30_000;

  await env.DB.prepare(
    "DELETE FROM guard_challenges_v2 WHERE expires_at_ms <= ?1 OR (used_at_ms IS NOT NULL AND used_at_ms <= ?2)"
  ).bind(nowMs, nowMs - 60_000).run();

  await env.DB.prepare(
    `INSERT INTO guard_challenges_v2
      (id, action, nonce, guard_id, client_binding, created_at_ms, expires_at_ms, min_delay_ms, pressure, used_at_ms)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL)`
  ).bind(id, action, nonce, guardId, binding, nowMs, expiresAtMs, minDelayMs, pressure).run();

  return {
    id,
    action,
    nonce,
    createdAtMs: nowMs,
    expiresAtMs,
    minDelayMs,
    algorithm: "ecdsa-browser-v2",
    coreVersion: await coreVersion(),
  };
}

async function recordFailure(env, guardId) {
  const nowMs = Date.now();
  const row = await env.DB.prepare(
    "SELECT failure_count FROM guard_devices_v2 WHERE guard_id = ?1 LIMIT 1"
  ).bind(guardId).first();
  if (!row) return;
  const failures = Number(row.failure_count || 0) + 1;
  const blockedUntil = failures >= 8 ? nowMs + 15 * 60_000 : 0;
  await env.DB.prepare(
    "UPDATE guard_devices_v2 SET failure_count = ?1, blocked_until_ms = ?2, last_seen_ms = ?3 WHERE guard_id = ?4"
  ).bind(failures, blockedUntil, nowMs, guardId).run();
}

export async function verifyGuardProof(env, request, proof, expectedAction) {
  if (!proof || typeof proof !== "object") throw new Error("GUARD_REQUIRED");
  const { id, guardId, publicKeyJwk, signature } = proof;
  if (typeof id !== "string" || id.length < 20 || id.length > 64 || !validateGuardId(guardId)) {
    throw new Error("GUARD_BAD_PROOF");
  }
  if (!validatePublicJwk(publicKeyJwk) || typeof signature !== "string") throw new Error("GUARD_BAD_PROOF");

  const nowMs = Date.now();
  const row = await env.DB.prepare(
    `SELECT id, action, nonce, guard_id, client_binding, created_at_ms, expires_at_ms,
            min_delay_ms, pressure, used_at_ms
     FROM guard_challenges_v2 WHERE id = ?1 LIMIT 1`
  ).bind(id).first();

  if (!row || row.used_at_ms != null || Number(row.expires_at_ms) < nowMs) throw new Error("GUARD_EXPIRED");
  if (row.action !== expectedAction || row.guard_id !== guardId) throw new Error("GUARD_BAD_PROOF");
  const binding = await clientBinding(env, request);
  if (binding !== row.client_binding) throw new Error("GUARD_BAD_PROOF");

  const computedGuardId = await publicGuardId(publicKeyJwk);
  if (computedGuardId !== guardId) throw new Error("GUARD_BAD_PROOF");

  const knownRow = await env.DB.prepare(
    "SELECT success_count, failure_count, blocked_until_ms FROM guard_devices_v2 WHERE guard_id = ?1 LIMIT 1"
  ).bind(guardId).first();
  if (Number(knownRow?.blocked_until_ms || 0) > nowMs) throw new Error("GUARD_BLOCKED");

  const ageMs = Math.max(0, nowMs - Number(row.created_at_ms));
  if (ageMs < Number(row.min_delay_ms || 0)) throw new Error("GUARD_TOO_FAST");

  let verified = false;
  try {
    const publicKey = await crypto.subtle.importKey(
      "jwk",
      publicKeyJwk,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"]
    );
    verified = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      fromBase64Url(signature),
      encoder.encode(guardPayload(row))
    );
  } catch {
    verified = false;
  }
  if (!verified) {
    await recordFailure(env, guardId);
    throw new Error("GUARD_BAD_PROOF");
  }

  const decision = await coreGuardDecision({
    action: expectedAction,
    ageMs,
    pressure: Number(row.pressure || 0),
    knownDevice: Number(knownRow?.success_count || 0) >= 3,
    headerFlags: headerFlags(request),
    failures: Number(knownRow?.failure_count || 0),
  });
  if (!decision.allowed) {
    await recordFailure(env, guardId);
    throw new Error("GUARD_RISK");
  }

  const claimed = await env.DB.prepare(
    `UPDATE guard_challenges_v2 SET used_at_ms = ?1
     WHERE id = ?2 AND used_at_ms IS NULL AND expires_at_ms >= ?1`
  ).bind(nowMs, id).run();
  if (!claimed.meta?.changes) throw new Error("GUARD_REPLAY");

  await env.DB.prepare(
    `INSERT INTO guard_devices_v2
      (guard_id, first_seen_ms, last_seen_ms, success_count, failure_count, blocked_until_ms)
     VALUES (?1, ?2, ?2, 1, 0, 0)
     ON CONFLICT(guard_id) DO UPDATE SET
       last_seen_ms = excluded.last_seen_ms,
       success_count = success_count + 1,
       failure_count = CASE WHEN failure_count > 0 THEN failure_count - 1 ELSE 0 END,
       blocked_until_ms = 0`
  ).bind(guardId, nowMs).run();

  return { ok: true, score: decision.score };
}

export async function cleanupSecurity(env) {
  const now = Math.floor(Date.now() / 1000);
  const nowMs = Date.now();
  await env.DB.prepare("DELETE FROM jend_replay WHERE expires_at <= ?1").bind(now).run();
  await env.DB.prepare("DELETE FROM rate_limits WHERE expires_at <= ?1").bind(now).run();
  await env.DB.prepare(
    "DELETE FROM guard_challenges_v2 WHERE expires_at_ms <= ?1 OR (used_at_ms IS NOT NULL AND used_at_ms <= ?2)"
  ).bind(nowMs, nowMs - 60_000).run();
}
