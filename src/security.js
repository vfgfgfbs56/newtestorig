let configPromise = null;
const proofCache = new Map();
const encoder = new TextEncoder();

const DB_NAME = "jend-guard-v2";
const STORE = "identity";
const RECORD_KEY = "active";

export async function getSecurityConfig() {
  if (!configPromise) {
    configPromise = fetch("/api/security/config", {
      credentials: "same-origin",
      cache: "no-store",
    }).then(async (response) => {
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || "SECURITY_CONFIG_ERROR");
      return data;
    }).catch((error) => {
      configPromise = null;
      throw error;
    });
  }
  return configPromise;
}

function toBase64Url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      if (!req.result.objectStoreNames.contains(STORE)) req.result.createObjectStore(STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error || new Error("GUARD_IDB_ERROR"));
  });
}

async function idbGet() {
  const db = await openDb();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readonly");
      const req = tx.objectStore(STORE).get(RECORD_KEY);
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => reject(req.error || new Error("GUARD_IDB_ERROR"));
    });
  } finally {
    db.close();
  }
}

async function idbPut(value) {
  const db = await openDb();
  try {
    await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      tx.objectStore(STORE).put(value, RECORD_KEY);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error || new Error("GUARD_IDB_ERROR"));
      tx.onabort = () => reject(tx.error || new Error("GUARD_IDB_ERROR"));
    });
  } finally {
    db.close();
  }
}

async function fingerprintPublicJwk(jwk) {
  const canonical = `${jwk.crv || ""}.${jwk.x || ""}.${jwk.y || ""}`;
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(canonical)));
  return toBase64Url(digest);
}

async function getGuardIdentity() {
  const stored = await idbGet().catch(() => null);
  if (stored?.privateKey instanceof CryptoKey && stored?.publicKeyJwk && stored?.guardId) return stored;

  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign", "verify"]
  );
  const publicKeyJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const guardId = await fingerprintPublicJwk(publicKeyJwk);
  const identity = {
    privateKey: pair.privateKey,
    publicKeyJwk,
    guardId,
    createdAt: Date.now(),
  };
  await idbPut(identity);
  return identity;
}

async function requestChallenge(action, guardId) {
  const url = new URL("/api/security/challenge", location.origin);
  url.searchParams.set("action", action);
  url.searchParams.set("guard", guardId);
  const response = await fetch(url, {
    credentials: "same-origin",
    cache: "no-store",
    headers: { "X-JEND-Guard": "2" },
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || "GUARD_CHALLENGE_FAILED");
  return data;
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, Math.max(0, ms)));
}

function guardPayload(challenge, guardId) {
  return `JEND-GUARD/2\n${challenge.id}\n${challenge.action}\n${challenge.nonce}\n${guardId}\n${challenge.createdAtMs}`;
}

async function signChallenge(identity, challenge) {
  const signature = new Uint8Array(await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    identity.privateKey,
    encoder.encode(guardPayload(challenge, identity.guardId))
  ));
  return {
    id: challenge.id,
    guardId: identity.guardId,
    publicKeyJwk: identity.publicKeyJwk,
    signature: toBase64Url(signature),
  };
}

export async function prepareGuard(action, onStatus) {
  const cached = proofCache.get(action);
  const now = Date.now();
  if (cached && cached.expiresAtMs > now + 1500) return cached.proof;

  onStatus?.("Проверяем устройство…");
  const identity = await getGuardIdentity();
  const challenge = await requestChallenge(action, identity.guardId);
  if (challenge.algorithm !== "ecdsa-browser-v2") throw new Error("GUARD_ALGORITHM_UNSUPPORTED");

  const notBefore = Number(challenge.createdAtMs || 0) + Number(challenge.minDelayMs || 0);
  const delay = Math.max(0, notBefore - Date.now() + 40);
  if (delay) await wait(delay);

  const proof = await signChallenge(identity, challenge);
  proofCache.set(action, {
    proof,
    expiresAtMs: Number(challenge.expiresAtMs || 0),
  });
  onStatus?.("Проверка устройства пройдена.");
  return proof;
}

export function takeGuardProof(action) {
  const cached = proofCache.get(action);
  proofCache.delete(action);
  if (!cached || cached.expiresAtMs <= Date.now() + 750) return null;
  return cached.proof;
}

export function clearGuardProof(action) {
  proofCache.delete(action);
}
