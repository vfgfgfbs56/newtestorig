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

const QR_PASSWORD_MAX_FAILURES = 5;
const QR_PAIR_TTL_SECONDS = 2 * 60;

function isToken(value, min = 16, max = 256) {
  return typeof value === "string" && value.length >= min && value.length <= max && /^[A-Za-z0-9_-]+$/.test(value);
}

function isCipherField(value, max = 1024) {
  return typeof value === "string" && value.length >= 8 && value.length <= max && /^[A-Za-z0-9_-]+$/.test(value);
}

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
    const { id, approvalToken, claimVerifier } = await readJson(request);
    if (!isToken(id, 20, 64) || !isToken(approvalToken, 40, 96) || !isToken(claimVerifier, 40, 96)) {
      throw new Error("BAD_QR");
    }

    await cleanupExpired(env);

    const challenge = randomToken(32);
    const now = nowSeconds();
    const expiresAt = qrExpiresAt();

    await env.DB.prepare(
      `INSERT INTO qr_sessions
       (id, approval_secret_hash, claim_secret_hash, challenge, status, user_id, approved_device_id,
        created_at, expires_at, claimed_at, phase, password_attempt_id, password_iv, password_cipher,
        password_failures, password_result)
       VALUES (?1, ?2, ?3, ?4, 'pending', NULL, NULL, ?5, ?6, NULL,
               'waiting_scan', NULL, NULL, NULL, 0, NULL)`
    ).bind(
      id,
      await sha256Text(approvalToken),
      claimVerifier,
      challenge,
      now,
      expiresAt
    ).run();

    return json({ ok: true, id, expiresAt }, 201);
  } catch (error) {
    if (["BAD_QR", "BAD_ORIGIN", "BAD_CONTENT_TYPE", "BODY_TOO_LARGE"].includes(error?.message)) {
      return json({ ok: false, error: "Запрос отклонён." }, 400);
    }
    const message = String(error?.message || "");
    if (message.includes("UNIQUE")) {
      return json({ ok: false, error: "Не удалось создать QR." }, 409);
    }
    console.error("qr_create_failed", error?.name || "Error", message);
    return json({ ok: false, error: "Не удалось создать QR." }, 500);
  }
}

async function qrPair(request, env) {
  try {
    requireSameOrigin(request);
    const session = await getSession(env, request);
    if (!session) return json({ ok: false, error: "Сначала войдите в аккаунт." }, 401);

    const { id, approvalToken, deviceId } = await readJson(request);
    const safeDeviceId = validateDeviceId(deviceId);
    if (!isToken(id, 20, 64) || !isToken(approvalToken, 40, 96)) throw new Error("BAD_QR");

    await cleanupExpired(env);
    const qr = await env.DB.prepare(
      `SELECT approval_secret_hash, challenge, status, phase, user_id, approved_device_id, expires_at
       FROM qr_sessions WHERE id = ?1 LIMIT 1`
    ).bind(id).first();

    if (!qr || !(await secretMatches(qr.approval_secret_hash, approvalToken))) {
      return json({ ok: false, error: "QR недействителен." }, 404);
    }
    if (qr.status !== "pending") {
      return json({ ok: false, error: "QR уже использован или истёк." }, 409);
    }

    const device = await env.DB.prepare(
      "SELECT id FROM devices WHERE id = ?1 AND user_id = ?2 AND revoked_at IS NULL LIMIT 1"
    ).bind(safeDeviceId, session.userId).first();
    if (!device) {
      return json({ ok: false, error: "Это устройство не является доверенным." }, 403);
    }

    if (qr.phase === "paired" || qr.phase === "password_pending") {
      if (qr.user_id === session.userId && qr.approved_device_id === safeDeviceId) {
        return json({ ok: true, paired: true, challenge: qr.challenge, expiresAt: qr.expires_at });
      }
      return json({ ok: false, error: "Этот QR уже отсканирован другим устройством." }, 409);
    }

    if (qr.phase !== "waiting_scan") {
      return json({ ok: false, error: "QR находится в неверном состоянии." }, 409);
    }

    const expiresAt = nowSeconds() + QR_PAIR_TTL_SECONDS;
    const result = await env.DB.prepare(
      `UPDATE qr_sessions
       SET phase = 'paired', user_id = ?1, approved_device_id = ?2, expires_at = ?3,
           password_result = NULL, password_attempt_id = NULL, password_iv = NULL, password_cipher = NULL
       WHERE id = ?4 AND status = 'pending' AND phase = 'waiting_scan'`
    ).bind(session.userId, safeDeviceId, expiresAt, id).run();

    if (!result.meta?.changes) {
      return json({ ok: false, error: "QR уже был отсканирован." }, 409);
    }

    return json({ ok: true, paired: true, challenge: qr.challenge, expiresAt });
  } catch (error) {
    if (["INVALID_DEVICE", "BAD_QR", "BAD_ORIGIN", "BAD_CONTENT_TYPE", "BODY_TOO_LARGE"].includes(error?.message)) {
      return json({ ok: false, error: "Запрос отклонён." }, 400);
    }
    console.error("qr_pair_failed", error?.name || "Error", String(error?.message || ""));
    return json({ ok: false, error: "Не удалось подтвердить QR." }, 500);
  }
}

async function qrPassword(request, env) {
  try {
    requireSameOrigin(request);
    const { id, claimSecret, attemptId, iv, ciphertext } = await readJson(request);
    if (!isToken(id, 20, 64) || !isToken(attemptId, 16, 96) || !isCipherField(iv, 64) || !isCipherField(ciphertext, 1024)) {
      throw new Error("BAD_QR");
    }

    await cleanupExpired(env);
    const qr = await env.DB.prepare(
      `SELECT claim_secret_hash, status, phase, password_failures
       FROM qr_sessions WHERE id = ?1 LIMIT 1`
    ).bind(id).first();

    if (!qr || !(await secretMatches(qr.claim_secret_hash, claimSecret))) {
      return json({ ok: false, error: "QR недействителен." }, 404);
    }
    if (qr.status !== "pending") {
      return json({ ok: false, error: "QR уже использован или истёк." }, 409);
    }
    if (qr.phase !== "paired") {
      return json({ ok: false, error: qr.phase === "password_pending" ? "Пароль уже проверяется." : "Сначала отсканируйте QR с телефона." }, 409);
    }
    if (Number(qr.password_failures || 0) >= QR_PASSWORD_MAX_FAILURES) {
      return json({ ok: false, error: "Слишком много неверных попыток." }, 429);
    }

    const result = await env.DB.prepare(
      `UPDATE qr_sessions
       SET phase = 'password_pending', password_attempt_id = ?1, password_iv = ?2,
           password_cipher = ?3, password_result = NULL
       WHERE id = ?4 AND status = 'pending' AND phase = 'paired'`
    ).bind(attemptId, iv, ciphertext, id).run();

    if (!result.meta?.changes) {
      return json({ ok: false, error: "Пароль уже проверяется." }, 409);
    }

    return json({ ok: true, status: "checking" }, 202);
  } catch (error) {
    if (["BAD_QR", "BAD_ORIGIN", "BAD_CONTENT_TYPE", "BODY_TOO_LARGE"].includes(error?.message)) {
      return json({ ok: false, error: "Запрос отклонён." }, 400);
    }
    console.error("qr_password_failed", error?.name || "Error", String(error?.message || ""));
    return json({ ok: false, error: "Не удалось отправить пароль на проверку." }, 500);
  }
}

async function qrPhoneStatus(request, env) {
  try {
    requireSameOrigin(request);
    const session = await getSession(env, request);
    if (!session) return json({ ok: false, error: "Сессия на телефоне завершена." }, 401);

    const { id, approvalToken, deviceId } = await readJson(request);
    const safeDeviceId = validateDeviceId(deviceId);
    if (!isToken(id, 20, 64) || !isToken(approvalToken, 40, 96)) throw new Error("BAD_QR");

    await cleanupExpired(env);
    const row = await env.DB.prepare(
      `SELECT approval_secret_hash, status, phase, user_id, approved_device_id,
              password_attempt_id, password_iv, password_cipher, password_failures, password_result
       FROM qr_sessions WHERE id = ?1 LIMIT 1`
    ).bind(id).first();

    if (!row || !(await secretMatches(row.approval_secret_hash, approvalToken))) {
      return json({ ok: false, error: "QR недействителен." }, 404);
    }
    if (row.user_id !== session.userId || row.approved_device_id !== safeDeviceId) {
      return json({ ok: false, error: "QR привязан к другому устройству." }, 403);
    }
    if (row.status === "expired" || row.status === "denied") {
      return json({ ok: false, status: row.status, error: "Попытка входа завершена." }, 410);
    }
    if (row.status === "approved" || row.status === "claimed") {
      return json({ ok: true, status: "approved" }, 200);
    }

    if (row.phase === "password_pending" && row.password_attempt_id && row.password_iv && row.password_cipher) {
      return json({
        ok: true,
        status: "password_pending",
        attemptId: row.password_attempt_id,
        iv: row.password_iv,
        ciphertext: row.password_cipher,
      }, 200);
    }

    return json({
      ok: true,
      status: "waiting_password",
      failures: Number(row.password_failures || 0),
      lastResult: row.password_result || null,
    }, 202);
  } catch (error) {
    if (["INVALID_DEVICE", "BAD_QR", "BAD_ORIGIN", "BAD_CONTENT_TYPE", "BODY_TOO_LARGE"].includes(error?.message)) {
      return json({ ok: false, error: "Запрос отклонён." }, 400);
    }
    console.error("qr_phone_status_failed", error?.name || "Error", String(error?.message || ""));
    return json({ ok: false, error: "Не удалось проверить состояние входа." }, 500);
  }
}

async function qrResult(request, env) {
  try {
    requireSameOrigin(request);
    const session = await getSession(env, request);
    if (!session) return json({ ok: false, error: "Сессия на телефоне завершена." }, 401);

    const { id, approvalToken, deviceId, attemptId, valid, signature } = await readJson(request);
    const safeDeviceId = validateDeviceId(deviceId);
    if (!isToken(id, 20, 64) || !isToken(approvalToken, 40, 96) || !isToken(attemptId, 16, 96) || typeof valid !== "boolean") {
      throw new Error("BAD_QR");
    }

    await cleanupExpired(env);
    const qr = await env.DB.prepare(
      `SELECT approval_secret_hash, challenge, status, phase, user_id, approved_device_id,
              password_attempt_id, password_failures
       FROM qr_sessions WHERE id = ?1 LIMIT 1`
    ).bind(id).first();

    if (!qr || !(await secretMatches(qr.approval_secret_hash, approvalToken))) {
      return json({ ok: false, error: "QR недействителен." }, 404);
    }
    if (qr.status !== "pending" || qr.phase !== "password_pending" || qr.password_attempt_id !== attemptId) {
      return json({ ok: false, error: "Эта попытка пароля уже не актуальна." }, 409);
    }
    if (qr.user_id !== session.userId || qr.approved_device_id !== safeDeviceId) {
      return json({ ok: false, error: "Попытка привязана к другому устройству." }, 403);
    }

    if (!valid) {
      const failures = Number(qr.password_failures || 0) + 1;
      const denied = failures >= QR_PASSWORD_MAX_FAILURES;
      await env.DB.prepare(
        `UPDATE qr_sessions
         SET status = ?1, phase = ?2, password_failures = ?3, password_result = 'wrong',
             password_attempt_id = NULL, password_iv = NULL, password_cipher = NULL
         WHERE id = ?4 AND status = 'pending' AND phase = 'password_pending' AND password_attempt_id = ?5`
      ).bind(
        denied ? "denied" : "pending",
        denied ? "done" : "paired",
        failures,
        id,
        attemptId
      ).run();

      return json({
        ok: true,
        valid: false,
        denied,
        attemptsLeft: Math.max(0, QR_PASSWORD_MAX_FAILURES - failures),
      });
    }

    const device = await env.DB.prepare(
      "SELECT public_jwk FROM devices WHERE id = ?1 AND user_id = ?2 AND revoked_at IS NULL LIMIT 1"
    ).bind(safeDeviceId, session.userId).first();

    if (!device) {
      return json({ ok: false, error: "Это устройство больше не является доверенным." }, 403);
    }

    const publicJwk = JSON.parse(device.public_jwk);
    const signatureValid = await verifyDeviceSignature(
      publicJwk,
      qrSignPayload(id, qr.challenge, attemptId),
      signature
    );

    if (!signatureValid) {
      return json({ ok: false, error: "Криптографическое подтверждение отклонено." }, 403);
    }

    const result = await env.DB.prepare(
      `UPDATE qr_sessions
       SET status = 'approved', phase = 'done', password_result = 'ok',
           password_attempt_id = NULL, password_iv = NULL, password_cipher = NULL
       WHERE id = ?1 AND status = 'pending' AND phase = 'password_pending' AND password_attempt_id = ?2`
    ).bind(id, attemptId).run();

    if (!result.meta?.changes) {
      return json({ ok: false, error: "Попытка уже завершена." }, 409);
    }

    return json({ ok: true, valid: true, approved: true });
  } catch (error) {
    if (["INVALID_DEVICE", "BAD_QR", "BAD_ORIGIN", "BAD_CONTENT_TYPE", "BODY_TOO_LARGE"].includes(error?.message)) {
      return json({ ok: false, error: "Запрос отклонён." }, 400);
    }
    console.error("qr_result_failed", error?.name || "Error", String(error?.message || ""));
    return json({ ok: false, error: "Не удалось завершить проверку пароля." }, 500);
  }
}

async function qrStatus(request, env) {
  try {
    requireSameOrigin(request);
    const { id, claimSecret } = await readJson(request);
    if (!isToken(id, 20, 64)) throw new Error("BAD_QR");

    await cleanupExpired(env);
    const row = await env.DB.prepare(
      `SELECT claim_secret_hash, status, phase, user_id, password_failures, password_result
       FROM qr_sessions WHERE id = ?1 LIMIT 1`
    ).bind(id).first();

    if (!row || !(await secretMatches(row.claim_secret_hash, claimSecret))) {
      return json({ ok: false, error: "QR недействителен." }, 404);
    }

    if (row.status === "pending") {
      return json({
        ok: true,
        status: "pending",
        phase: row.phase,
        failures: Number(row.password_failures || 0),
        passwordResult: row.password_result || null,
      }, 202);
    }
    if (row.status === "expired" || row.status === "denied") {
      return json({ ok: false, status: row.status, error: row.status === "denied" ? "Слишком много неверных попыток пароля." : "QR истёк." }, 410);
    }
    if (row.status === "claimed") {
      return json({ ok: false, status: "claimed", error: "QR уже использован." }, 409);
    }
    if (row.status !== "approved" || row.password_result !== "ok" || !row.user_id) {
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
  "/api/auth/qr/pair": { POST: qrPair },
  "/api/auth/qr/password": { POST: qrPassword },
  "/api/auth/qr/phone-status": { POST: qrPhoneStatus },
  "/api/auth/qr/result": { POST: qrResult },
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
