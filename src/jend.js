import { getSecurityConfig } from "./security.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const MAGIC = [0x4a, 0x45, 0x4e, 0x44];
const VERSION = 1;
const REQUEST_KIND = 0;
const RESPONSE_KIND = 1;
const REQUEST_HEADER_LENGTH = 103;
const RESPONSE_HEADER_LENGTH = 38;

function randomBytes(length) {
  const value = new Uint8Array(length);
  crypto.getRandomValues(value);
  return value;
}

function toBase64Url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function requestAad(path, issuedAt, requestId) {
  return encoder.encode(`JEND/1/request\n${path}\n${issuedAt}\n${toBase64Url(requestId)}`);
}

function responseAad(path, issuedAt, requestId) {
  return encoder.encode(`JEND/1/response\n${path}\n${issuedAt}\n${toBase64Url(requestId)}`);
}

function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function deriveKeys(serverPublicJwk, ephemeralPrivateKey, requestId, path) {
  const serverPublicKey = await crypto.subtle.importKey(
    "jwk",
    serverPublicJwk,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );
  const shared = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "ECDH", public: serverPublicKey },
    ephemeralPrivateKey,
    256
  ));
  const base = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const make = (direction) => crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: requestId,
      info: encoder.encode(`JEND/1/${direction}/${path}`),
    },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
  return {
    requestKey: await make("request"),
    responseKey: await make("response"),
  };
}

async function buildRequestPacket(path, payload) {
  const config = await getSecurityConfig();
  const publicJwk = config.jend?.publicKeyJwk;
  if (!config.jend?.configured || !publicJwk) throw new Error("JEND_NOT_CONFIGURED");

  const ephemeral = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );
  const publicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", ephemeral.publicKey));
  if (publicRaw.length !== 65) throw new Error("JEND_KEY_ERROR");

  const requestId = randomBytes(16);
  const issuedAt = Math.floor(Date.now() / 1000);
  const iv = randomBytes(12);
  const { requestKey, responseKey } = await deriveKeys(publicJwk, ephemeral.privateKey, requestId, path);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: requestAad(path, issuedAt, requestId) },
    requestKey,
    encoder.encode(JSON.stringify(payload || {}))
  ));

  const packet = new Uint8Array(REQUEST_HEADER_LENGTH + ciphertext.length);
  packet.set(MAGIC, 0);
  packet[4] = VERSION;
  packet[5] = REQUEST_KIND;
  new DataView(packet.buffer).setUint32(6, issuedAt);
  packet.set(requestId, 10);
  packet.set(publicRaw, 26);
  packet.set(iv, 91);
  packet.set(ciphertext, REQUEST_HEADER_LENGTH);

  return { packet, requestId, responseKey };
}

async function decryptResponse(response, path, requestId, responseKey) {
  const contentType = (response.headers.get("Content-Type") || "").toLowerCase();
  if (!contentType.startsWith("application/jend")) {
    return response.json().catch(() => ({ error: "Некорректный ответ сервера." }));
  }

  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.length < RESPONSE_HEADER_LENGTH + 16) throw new Error("BAD_JEND_RESPONSE");
  for (let i = 0; i < MAGIC.length; i++) if (bytes[i] !== MAGIC[i]) throw new Error("BAD_JEND_RESPONSE");
  if (bytes[4] !== VERSION || bytes[5] !== RESPONSE_KIND) throw new Error("BAD_JEND_RESPONSE");

  const issuedAt = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(6);
  const responseRequestId = bytes.slice(10, 26);
  if (!equalBytes(requestId, responseRequestId)) throw new Error("BAD_JEND_RESPONSE");
  const iv = bytes.slice(26, 38);
  const ciphertext = bytes.slice(RESPONSE_HEADER_LENGTH);

  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv, additionalData: responseAad(path, issuedAt, requestId) },
    responseKey,
    ciphertext
  );
  return JSON.parse(decoder.decode(plain));
}

export async function jendApi(path, payload = {}) {
  const { packet, requestId, responseKey } = await buildRequestPacket(path, payload);
  const response = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    cache: "no-store",
    headers: {
      "Content-Type": "application/jend",
      "X-JEND-Version": "1",
    },
    body: packet,
  });
  const data = await decryptResponse(response, path, requestId, responseKey);
  return { response, data };
}
