import {
  cleanupExpired,
  createSession,
  getSession,
  json,
  makeLoginId,
  normalizeNickname,
  nowSeconds,
  qrExpiresAt,
  qrSignPayload,
  randomToken,
  readJson,
  requireSameOrigin,
  revokeCurrentSession,
  secretMatches,
  sha256Text,
  validateAndNormalizePublicJwk,
  validateDeviceId,
  verifyDeviceSignature,
} from "./auth.js";
import { ensureSchema } from "./schema.js";

async function register(request, env) {
  try {
    requireSameOrigin(request);
    const { nickname, deviceId, publicKeyJwk } = await readJson(request);
    const normalized = normalizeNickname(nickname);
    const safeDeviceId = validateDeviceId(deviceId);
    const safePublicJwk = await validateAndNormalizePublicJwk(publicKeyJwk);

    const loginId = await makeLoginId(env, normalized);
    const userId = crypto.randomUUID();
    const now = nowSeconds();

    await env.DB.batch([
      env.DB.prepare("INSERT INTO users (id, login_id, created_at) VALUES (?1, ?2, ?3)")
        .bind(userId, loginId, now),
      env.DB.prepare(
        "INSERT INTO devices (id, user_id, public_jwk, created_at, revoked_at) VALUES (?1, ?2, ?3, ?4, NULL)"
      ).bind(safeDeviceId, userId, JSON.stringify(safePublicJwk), now),
    ]);

    await cleanupExpired(env);
    const cookie = await createSession(env, request, userId);
    return json({ ok: true }, 201, { "Set-Cookie": cookie });
  } catch (error) {
    if (error?.message === "INVALID_NICKNAME") {
      return json({ ok: false, error: "Ник: 3–32 символа; буквы, цифры, _, . и -." }, 400);
    }
    if (["INVALID_DEVICE", "INVALID_PUBLIC_KEY", "BAD_ORIGIN", "BAD_CONTENT_TYPE", "BODY_TOO_LARGE"].includes(error?.message)) {
      return json({ ok: false, error: "Запрос отклонён." }, 400);
    }

    const message = String(error?.message || "");
    if (message.includes("UNIQUE")) {
      return json({ ok: false, error: "Не удалось создать аккаунт." }, 409);
    }
    if (message.includes("password_salt") || message.includes("password_hash") || message.includes("kdf")) {
      console.error("register_failed", "LEGACY_DB_SCHEMA");
      return json({ ok: false, error: "К базе подключена старая несовместимая схема." }, 503);
    }
    if (message.includes("Server secret is missing or too short")) {
      console.error("register_failed", "MISSING_LOGIN_HMAC_KEY");
      return json({ ok: false, error: "Не настроен секрет LOGIN_HMAC_KEY." }, 503);
    }

    console.error("register_failed", error?.name || "Error", message);
    return json({ ok: false, error: "Не удалось создать аккаунт." }, 500);
  }
}

async function me(request, env) {
  const session = await getSession(env, request);
  if (!session) return json({ authenticated: false }, 401);
  return json({ authenticated: true });
}

async function logout(request, env) {
  try {
    requireSameOrigin(request);
    const cookie = await revokeCurrentSession(env, request);
    return json({ ok: true }, 200, { "Set-Cookie": cookie });
  } catch {
    return json({ ok: false, error: "Запрос отклонён." }, 400);
  }
}

async function qrCreate(request, env) {
  try {
    requireSameOrigin(request);
    await cleanupExpired(env);

    const id = randomToken(18);
    const approvalSecret = randomToken(32);
    const claimSecret = randomToken(32);
    const challenge = randomToken(32);
    const now = nowSeconds();
    const expiresAt = qrExpiresAt();

    await env.DB.prepare(
      `INSERT INTO qr_sessions
       (id, approval_secret_hash, claim_secret_hash, challenge, status, user_id, approved_device_id, created_at, expires_at, claimed_at)
       VALUES (?1, ?2, ?3, ?4, 'pending', NULL, NULL, ?5, ?6, NULL)`
    ).bind(
      id,
      await sha256Text(approvalSecret),
      await sha256Text(claimSecret),
      challenge,
      now,
      expiresAt
    ).run();

    const approvalUrl = new URL("/", request.url);
    approvalUrl.searchParams.set("approve", id);
    approvalUrl.hash = new URLSearchParams({ s: approvalSecret }).toString();

    return json({
      ok: true,
      id,
      claimSecret,
      expiresAt,
      approvalUrl: approvalUrl.toString(),
    }, 201);
  } catch (error) {
    if (error?.message === "BAD_ORIGIN") {
      return json({ ok: false, error: "Запрос отклонён." }, 400);
    }
    console.error("qr_create_failed", error?.name || "Error", String(error?.message || ""));
    return json({ ok: false, error: "Не удалось создать QR." }, 500);
  }
}

async function qrDetails(request, env) {
  try {
    requireSameOrigin(request);
    const { id, approvalSecret } = await readJson(request);
    if (typeof id !== "string" || id.length > 128) throw new Error("BAD_QR");

    await cleanupExpired(env);
    const row = await env.DB.prepare(
      "SELECT approval_secret_hash, challenge, status, expires_at FROM qr_sessions WHERE id = ?1 LIMIT 1"
    ).bind(id).first();

    if (!row || !(await secretMatches(row.approval_secret_hash, approvalSecret))) {
      return json({ ok: false, error: "QR недействителен." }, 404);
    }
    if (row.status !== "pending") {
      return json({ ok: false, error: "QR уже использован или истёк." }, 409);
    }

    return json({ ok: true, challenge: row.challenge, expiresAt: row.expires_at });
  } catch (error) {
    if (["BAD_QR", "BAD_ORIGIN", "BAD_CONTENT_TYPE", "BODY_TOO_LARGE"].includes(error?.message)) {
      return json({ ok: false, error: "Запрос отклонён." }, 400);
    }
    console.error("qr_details_failed", error?.name || "Error", String(error?.message || ""));
    return json({ ok: false, error: "Не удалось проверить QR." }, 500);
  }
}

async function qrApprove(request, env) {
  try {
    requireSameOrigin(request);
    const session = await getSession(env, request);
    if (!session) return json({ ok: false, error: "Сначала войдите в аккаунт." }, 401);

    const { id, approvalSecret, deviceId, signature } = await readJson(request);
    const safeDeviceId = validateDeviceId(deviceId);
    if (typeof id !== "string" || id.length > 128) throw new Error("BAD_QR");

    await cleanupExpired(env);
    const qr = await env.DB.prepare(
      "SELECT approval_secret_hash, challenge, status FROM qr_sessions WHERE id = ?1 LIMIT 1"
    ).bind(id).first();

    if (!qr || !(await secretMatches(qr.approval_secret_hash, approvalSecret))) {
      return json({ ok: false, error: "QR недействителен." }, 404);
    }
    if (qr.status !== "pending") {
      return json({ ok: false, error: "QR уже использован или истёк." }, 409);
    }

    const device = await env.DB.prepare(
      "SELECT public_jwk FROM devices WHERE id = ?1 AND user_id = ?2 AND revoked_at IS NULL LIMIT 1"
    ).bind(safeDeviceId, session.userId).first();

    if (!device) {
      return json({ ok: false, error: "Это устройство не является доверенным." }, 403);
    }

    const publicJwk = JSON.parse(device.public_jwk);
    const valid = await verifyDeviceSignature(
      publicJwk,
      qrSignPayload(id, qr.challenge),
      signature
    );

    if (!valid) {
      return json({ ok: false, error: "Криптографическое подтверждение отклонено." }, 403);
    }

    const result = await env.DB.prepare(
      `UPDATE qr_sessions
       SET status = 'approved', user_id = ?1, approved_device_id = ?2
       WHERE id = ?3 AND status = 'pending'`
    ).bind(session.userId, safeDeviceId, id).run();

    if (!result.meta?.changes) {
      return json({ ok: false, error: "QR уже использован." }, 409);
    }

    return json({ ok: true, approved: true });
  } catch (error) {
    if (["INVALID_DEVICE", "BAD_QR", "BAD_ORIGIN", "BAD_CONTENT_TYPE", "BODY_TOO_LARGE"].includes(error?.message)) {
      return json({ ok: false, error: "Запрос отклонён." }, 400);
    }
    console.error("qr_approve_failed", error?.name || "Error", String(error?.message || ""));
    return json({ ok: false, error: "Не удалось подтвердить вход." }, 500);
  }
}

async function qrStatus(request, env) {
  try {
    requireSameOrigin(request);
    const { id, claimSecret } = await readJson(request);
    if (typeof id !== "string" || id.length > 128) throw new Error("BAD_QR");

    await cleanupExpired(env);
    const row = await env.DB.prepare(
      "SELECT claim_secret_hash, status, user_id FROM qr_sessions WHERE id = ?1 LIMIT 1"
    ).bind(id).first();

    if (!row || !(await secretMatches(row.claim_secret_hash, claimSecret))) {
      return json({ ok: false, error: "QR недействителен." }, 404);
    }

    if (row.status === "pending") {
      return json({ ok: true, status: "pending" }, 202);
    }
    if (row.status === "expired" || row.status === "denied") {
      return json({ ok: false, status: row.status, error: "QR больше недействителен." }, 410);
    }
    if (row.status === "claimed") {
      return json({ ok: false, status: "claimed", error: "QR уже использован." }, 409);
    }
    if (row.status !== "approved" || !row.user_id) {
      return json({ ok: false, error: "Некорректное состояние QR." }, 409);
    }

    const lock = await env.DB.prepare(
      "UPDATE qr_sessions SET status = 'claimed', claimed_at = ?1 WHERE id = ?2 AND status = 'approved'"
    ).bind(nowSeconds(), id).run();

    if (!lock.meta?.changes) {
      return json({ ok: false, error: "QR уже использован." }, 409);
    }

    try {
      const cookie = await createSession(env, request, row.user_id);
      return json({ ok: true, status: "approved" }, 200, { "Set-Cookie": cookie });
    } catch (error) {
      await env.DB.prepare(
        "UPDATE qr_sessions SET status = 'approved', claimed_at = NULL WHERE id = ?1 AND status = 'claimed'"
      ).bind(id).run();
      throw error;
    }
  } catch (error) {
    if (["BAD_QR", "BAD_ORIGIN", "BAD_CONTENT_TYPE", "BODY_TOO_LARGE"].includes(error?.message)) {
      return json({ ok: false, error: "Запрос отклонён." }, 400);
    }
    console.error("qr_status_failed", error?.name || "Error", String(error?.message || ""));
    return json({ ok: false, error: "Не удалось проверить QR." }, 500);
  }
}

const routes = {
  "/api/auth/register": { POST: register },
  "/api/auth/me": { GET: me },
  "/api/auth/logout": { POST: logout },
  "/api/auth/qr/create": { POST: qrCreate },
  "/api/auth/qr/details": { POST: qrDetails },
  "/api/auth/qr/approve": { POST: qrApprove },
  "/api/auth/qr/status": { POST: qrStatus },
};

async function handleApi(request, env) {
  const url = new URL(request.url);
  const route = routes[url.pathname];
  if (!route) return json({ ok: false, error: "Not found" }, 404);

  const handler = route[request.method];
  if (!handler) {
    return json(
      { ok: false, error: "Method not allowed" },
      405,
      { Allow: Object.keys(route).join(", ") }
    );
  }

  try {
    await ensureSchema(env);
    return await handler(request, env);
  } catch (error) {
    const message = String(error?.message || "");
    if (message === "MISSING_DB_BINDING") {
      console.error("api_failed", "MISSING_DB_BINDING");
      return json({ ok: false, error: "Не настроена база D1 (binding DB)." }, 503);
    }
    console.error("api_failed", error?.name || "Error", message);
    return json({ ok: false, error: "Ошибка сервера." }, 500);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/api/")) {
      return handleApi(request, env);
    }

    if (!env.ASSETS) {
      return new Response("Static assets binding is missing", { status: 500 });
    }
    return env.ASSETS.fetch(request);
  },
};
