const DB_NAME = "secure-auth-local-v3";
const DB_VERSION = 1;
const STORE = "vaults";
const ACTIVE_DEVICE_KEY = "secure_auth_active_device_v3";
const PBKDF2_ITERATIONS = 600_000;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function toBase64Url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function fromBase64Url(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(base64);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}
function randomBytes(length) { const v = new Uint8Array(length); crypto.getRandomValues(v); return v; }
function randomId(bytes = 24) { return toBase64Url(randomBytes(bytes)); }
function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => { if (!req.result.objectStoreNames.contains(STORE)) req.result.createObjectStore(STORE, { keyPath: "id" }); };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error || new Error("INDEXEDDB_ERROR"));
  });
}
async function putRecord(record) {
  const db = await openDb();
  await new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).put(record);
    tx.oncomplete = resolve; tx.onerror = () => reject(tx.error); tx.onabort = () => reject(tx.error);
  });
}
async function getRecord(id) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readonly");
    const req = tx.objectStore(STORE).get(id);
    req.onsuccess = () => resolve(req.result || null); req.onerror = () => reject(req.error);
  });
}
async function deleteRecord(id) {
  const db = await openDb();
  await new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).delete(id); tx.oncomplete = resolve; tx.onerror = () => reject(tx.error);
  });
}
async function derivePasswordKey(password, salt) {
  if (typeof password !== "string" || [...password].length < 12 || [...password].length > 128 || encoder.encode(password).length > 256) throw new Error("INVALID_PASSWORD");
  const base = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITERATIONS },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}
export async function createDeviceVault(password) {
  if (!crypto?.subtle || !indexedDB) throw new Error("UNSUPPORTED_BROWSER");
  const deviceId = randomId();
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const privateJwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  delete publicJwk.key_ops; delete publicJwk.alg; delete publicJwk.use;

  const salt = randomBytes(16), iv = randomBytes(12);
  const passwordKey = await derivePasswordKey(password, salt);
  const aad = encoder.encode(`secure-auth-password-v3:${deviceId}`);
  const privateCipher = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad }, passwordKey, encoder.encode(JSON.stringify(privateJwk))));

  const wrapKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const outerIv = randomBytes(12);
  const outerAad = encoder.encode(`secure-auth-device-v3:${deviceId}`);
  const inner = encoder.encode(JSON.stringify({ salt: toBase64Url(salt), iv: toBase64Url(iv), privateCipher: toBase64Url(privateCipher) }));
  const outerCipher = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: outerIv, additionalData: outerAad }, wrapKey, inner));
  await putRecord({ id: deviceId, version: 3, wrapKey, outerIv: toBase64Url(outerIv), outerCipher: toBase64Url(outerCipher), createdAt: Date.now() });
  localStorage.setItem(ACTIVE_DEVICE_KEY, deviceId);
  return { deviceId, publicKeyJwk: publicJwk };
}
export async function unlockDeviceVault(password) {
  const deviceId = localStorage.getItem(ACTIVE_DEVICE_KEY);
  if (!deviceId) return null;
  const record = await getRecord(deviceId);
  if (!record?.wrapKey || record.version !== 3) return null;
  try {
    const innerBytes = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromBase64Url(record.outerIv), additionalData: encoder.encode(`secure-auth-device-v3:${deviceId}`) }, record.wrapKey, fromBase64Url(record.outerCipher));
    const inner = JSON.parse(decoder.decode(innerBytes));
    const passwordKey = await derivePasswordKey(password, fromBase64Url(inner.salt));
    const privateBytes = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromBase64Url(inner.iv), additionalData: encoder.encode(`secure-auth-password-v3:${deviceId}`) }, passwordKey, fromBase64Url(inner.privateCipher));
    const privateJwk = JSON.parse(decoder.decode(privateBytes));
    const privateKey = await crypto.subtle.importKey("jwk", privateJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
    return { deviceId, privateKey };
  } catch { return null; }
}
export async function signQrApproval(privateKey, id, challenge) {
  const payload = encoder.encode(`secure-auth-qr-v3\n${id}\n${challenge}`);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, payload));
  return toBase64Url(sig);
}
export function hasTrustedDevice() { return Boolean(localStorage.getItem(ACTIVE_DEVICE_KEY)); }
export async function removeActiveVault() {
  const id = localStorage.getItem(ACTIVE_DEVICE_KEY);
  if (id) await deleteRecord(id).catch(() => {});
  localStorage.removeItem(ACTIVE_DEVICE_KEY);
}
