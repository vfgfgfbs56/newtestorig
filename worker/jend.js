const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

const MAGIC = [0x4a, 0x45, 0x4e, 0x44]; // JEND
const VERSION = 1;
const REQUEST_KIND = 0;
const RESPONSE_KIND = 1;
const REQUEST_HEADER_LENGTH = 103;
const RESPONSE_HEADER_LENGTH = 38;
const MAX_JEND_BYTES = 24 * 1024;
const MAX_CLOCK_SKEW_SECONDS = 75;

function toBase64Url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function assertMagic(bytes) {
  if (bytes.length < 6) throw new Error("BAD_JEND");
  for (let i = 0; i < MAGIC.length; i++) {
    if (bytes[i] !== MAGIC[i]) throw new Error("BAD_JEND");
  }
  if (bytes[4] !== VERSION) throw new Error("UNSUPPORTED_JEND_VERSION");
}

function readPrivateJwk(env) {
  if (!env.JEND_PRIVATE_JWK) throw new Error("MISSING_JEND_KEY");
  let jwk;
  try {
    jwk = JSON.parse(env.JEND_PRIVATE_JWK);
  } catch {
    throw new Error("INVALID_JEND_KEY");
  }
  if (!jwk || jwk.kty !== "EC" || jwk.crv !== "P-256" || !jwk.d || !jwk.x || !jwk.y) {
    throw new Error("INVALID_JEND_KEY");
  }
  return jwk;
}

export function getJendPublicJwk(env) {
  const privateJwk = readPrivateJwk(env);
  return {
    kty: "EC",
    crv: "P-256",
    x: privateJwk.x,
    y: privateJwk.y,
    ext: true,
  };
}

async function deriveDirectionalKey({ privateJwk, peerPublicRaw, requestId, path, direction }) {
  const privateKey = await crypto.subtle.importKey(
    "jwk",
    privateJwk,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"]
  );
  const publicKey = await crypto.subtle.importKey(
    "raw",
    peerPublicRaw,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );
  const shared = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "ECDH", public: publicKey },
    privateKey,
    256
  ));
  const hkdfBase = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: requestId,
      info: encoder.encode(`JEND/1/${direction}/${path}`),
    },
    hkdfBase,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function requestAad(path, issuedAt, requestId) {
  return encoder.encode(`JEND/1/request\n${path}\n${issuedAt}\n${toBase64Url(requestId)}`);
}

function responseAad(path, issuedAt, requestId) {
  return encoder.encode(`JEND/1/response\n${path}\n${issuedAt}\n${toBase64Url(requestId)}`);
}

async function claimReplay(env, requestId) {
  const id = toBase64Url(requestId);
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + 180;
  await env.DB.prepare("DELETE FROM jend_replay WHERE expires_at <= ?1").bind(now).run();
  try {
    await env.DB.prepare(
      "INSERT INTO jend_replay (request_id, expires_at) VALUES (?1, ?2)"
    ).bind(id, expiresAt).run();
  } catch (error) {
    if (String(error?.message || "").includes("UNIQUE")) throw new Error("JEND_REPLAY");
    throw error;
  }
}

export async function openJendRequest(request, env, { replayProtected = true } = {}) {
  const contentType = (request.headers.get("Content-Type") || "").toLowerCase();
  if (!contentType.startsWith("application/jend")) throw new Error("JEND_REQUIRED");

  const length = Number(request.headers.get("Content-Length") || "0");
  if (length > MAX_JEND_BYTES) throw new Error("BODY_TOO_LARGE");
  const body = new Uint8Array(await request.arrayBuffer());
  if (body.length > MAX_JEND_BYTES || body.length < REQUEST_HEADER_LENGTH + 16) throw new Error("BAD_JEND");

  assertMagic(body);
  if (body[5] !== REQUEST_KIND) throw new Error("BAD_JEND");

  const view = new DataView(body.buffer, body.byteOffset, body.byteLength);
  const issuedAt = view.getUint32(6);
  const requestId = body.slice(10, 26);
  const peerPublicRaw = body.slice(26, 91);
  const iv = body.slice(91, 103);
  const ciphertext = body.slice(103);
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - issuedAt) > MAX_CLOCK_SKEW_SECONDS) throw new Error("JEND_EXPIRED");

  const path = new URL(request.url).pathname;
  const privateJwk = readPrivateJwk(env);
  const requestKey = await deriveDirectionalKey({
    privateJwk,
    peerPublicRaw,
    requestId,
    path,
    direction: "request",
  });
  const responseKey = await deriveDirectionalKey({
    privateJwk,
    peerPublicRaw,
    requestId,
    path,
    direction: "response",
  });

  let plaintext;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: requestAad(path, issuedAt, requestId) },
      requestKey,
      ciphertext
    );
  } catch {
    throw new Error("BAD_JEND_AUTH");
  }

  let payload;
  try {
    payload = JSON.parse(decoder.decode(plaintext));
  } catch {
    throw new Error("BAD_JEND_PAYLOAD");
  }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new Error("BAD_JEND_PAYLOAD");

  if (replayProtected) await claimReplay(env, requestId);

  return {
    payload,
    context: { requestId, responseKey, path },
  };
}

export async function wrapJendResponse(context, response) {
  const plainText = await response.text();
  const issuedAt = Math.floor(Date.now() / 1000);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = new Uint8Array(await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      additionalData: responseAad(context.path, issuedAt, context.requestId),
    },
    context.responseKey,
    encoder.encode(plainText)
  ));

  const body = new Uint8Array(RESPONSE_HEADER_LENGTH + encrypted.length);
  body.set(MAGIC, 0);
  body[4] = VERSION;
  body[5] = RESPONSE_KIND;
  const view = new DataView(body.buffer);
  view.setUint32(6, issuedAt);
  body.set(context.requestId, 10);
  body.set(iv, 26);
  body.set(encrypted, RESPONSE_HEADER_LENGTH);

  const headers = new Headers(response.headers);
  headers.set("Content-Type", "application/jend");
  headers.set("Cache-Control", "no-store");
  headers.set("X-JEND-Version", "1");
  headers.delete("Content-Length");
  return new Response(body, { status: response.status, headers });
}
