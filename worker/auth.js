const encoder = new TextEncoder();
const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;
const QR_TTL_SECONDS = 2 * 60;

export function toBase64Url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function fromBase64Url(value) {
  if (typeof value !== "string" || value.length > 4096) throw new Error("BAD_BASE64URL");
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4);
  const binary = atob(base64);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

export function randomToken(bytes = 32) {
  const value = new Uint8Array(bytes);
  crypto.getRandomValues(value);
  return toBase64Url(value);
}

async function importHmacKey(secret) {
  if (!secret || secret.length < 32) throw new Error("Server secret is missing or too short");
  return crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
}

async function hmac(secret, data) {
  const key = await importHmacKey(secret);
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(data));
  return new Uint8Array(signature);
}

export function normalizeNickname(raw) {
  if (typeof raw !== "string") throw new Error("INVALID_NICKNAME");
  const nickname = raw.normalize("NFKC").trim().toLowerCase();
  const length = [...nickname].length;
  if (length < 3 || length > 32) throw new Error("INVALID_NICKNAME");
  if (!/^[\p{L}\p{N}_.-]+$/u.test(nickname)) throw new Error("INVALID_NICKNAME");
  return nickname;
}

export async function makeLoginId(env, normalizedNickname) {
  return toBase64Url(await hmac(env.LOGIN_HMAC_KEY, normalizedNickname));
}

export async function sha256Text(value) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return toBase64Url(new Uint8Array(digest));
}

function timingSafeBytesEqual(a, b) {
  if (a.length !== b.length) return false;
  if (typeof crypto.subtle.timingSafeEqual === "function") {
    return crypto.subtle.timingSafeEqual(a, b);
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export async function secretMatches(expectedHashB64, providedSecret) {
  if (typeof providedSecret !== "string" || providedSecret.length < 20 || providedSecret.length > 256) return false;
  const actualHash = fromBase64Url(await sha256Text(providedSecret));
  const expectedHash = fromBase64Url(expectedHashB64);
  return timingSafeBytesEqual(actualHash, expectedHash);
}

export function validateDeviceId(value) {
  if (typeof value !== "string" || value.length < 16 || value.length > 128) throw new Error("INVALID_DEVICE");
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("INVALID_DEVICE");
  return value;
}

export async function validateAndNormalizePublicJwk(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("INVALID_PUBLIC_KEY");
  if (value.kty !== "EC" || value.crv !== "P-256" || typeof value.x !== "string" || typeof value.y !== "string") {
    throw new Error("INVALID_PUBLIC_KEY");
  }
  if ("d" in value) throw new Error("INVALID_PUBLIC_KEY");

  const normalized = {
    kty: "EC",
    crv: "P-256",
    x: value.x,
    y: value.y,
    ext: true,
  };

  await crypto.subtle.importKey(
    "jwk",
    normalized,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"]
  );

  return normalized;
}

export function qrSignPayload(id, challenge) {
  return `secure-auth-qr-v3\n${id}\n${challenge}`;
}

export async function verifyDeviceSignature(publicJwk, payload, signatureB64) {
  try {
    if (typeof signatureB64 !== "string" || signatureB64.length > 512) return false;
    const key = await crypto.subtle.importKey(
      "jwk",
      publicJwk,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"]
    );
    return crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      fromBase64Url(signatureB64),
      encoder.encode(payload)
    );
  } catch {
    return false;
  }
}

function parseCookies(request) {
  const result = {};
  const raw = request.headers.get("Cookie") || "";
  for (const part of raw.split(";")) {
    const pos = part.indexOf("=");
    if (pos < 0) continue;
    result[part.slice(0, pos).trim()] = part.slice(pos + 1).trim();
  }
  return result;
}

function cookieConfig(request) {
  const hostname = new URL(request.url).hostname;
  const local = hostname === "localhost" || hostname === "127.0.0.1";
  return {
    name: local ? "dev_session" : "__Host-session",
    secure: local ? "" : "; Secure",
  };
}

export async function createSession(env, request, userId) {
  const token = randomToken(32);
  const tokenHash = await sha256Text(token);
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + SESSION_TTL_SECONDS;

  await env.DB.prepare(
    "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)"
  ).bind(tokenHash, userId, now, expiresAt).run();

  const cfg = cookieConfig(request);
  const cookie = `${cfg.name}=${token}; Path=/; HttpOnly${cfg.secure}; SameSite=Strict; Max-Age=${SESSION_TTL_SECONDS}`;
  return cookie;
}

export async function getSession(env, request) {
  const cookies = parseCookies(request);
  const token = cookies["__Host-session"] || cookies.dev_session;
  if (!token || token.length > 128) return null;

  const tokenHash = await sha256Text(token);
  const now = Math.floor(Date.now() / 1000);
  const row = await env.DB.prepare(
    "SELECT user_id, expires_at FROM sessions WHERE token_hash = ?1 AND expires_at > ?2 LIMIT 1"
  ).bind(tokenHash, now).first();

  return row ? { userId: row.user_id, tokenHash } : null;
}

export async function revokeCurrentSession(env, request) {
  const session = await getSession(env, request);
  if (session) {
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?1").bind(session.tokenHash).run();
  }
  const cfg = cookieConfig(request);
  return `${cfg.name}=; Path=/; HttpOnly${cfg.secure}; SameSite=Strict; Max-Age=0`;
}

export function requireSameOrigin(request) {
  const origin = request.headers.get("Origin");
  if (!origin) return;
  const expected = new URL(request.url).origin;
  if (origin !== expected) throw new Error("BAD_ORIGIN");
}

export async function readJson(request) {
  const length = Number(request.headers.get("Content-Length") || "0");
  if (length > 8192) throw new Error("BODY_TOO_LARGE");
  const type = request.headers.get("Content-Type") || "";
  if (!type.toLowerCase().startsWith("application/json")) throw new Error("BAD_CONTENT_TYPE");
  return request.json();
}

export function json(data, status = 200, headers = {}) {
  const out = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    ...headers,
  });
  return new Response(JSON.stringify(data), { status, headers: out });
}

export async function cleanupExpired(env) {
  const now = Math.floor(Date.now() / 1000);
  await env.DB.prepare("DELETE FROM sessions WHERE expires_at <= ?1").bind(now).run();
  await env.DB.prepare(
    "UPDATE qr_sessions SET status = 'expired' WHERE status IN ('pending', 'approved') AND expires_at <= ?1"
  ).bind(now).run();
}

export function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

export function qrExpiresAt() {
  return nowSeconds() + QR_TTL_SECONDS;
}
