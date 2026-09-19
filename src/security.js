let configPromise = null;
let wasmPromise = null;
const proofCache = new Map();

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

function decodeBase64Url(value) {
  let s = value.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const binary = atob(s);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

async function loadGuardWasm() {
  if (wasmPromise) return wasmPromise;
  wasmPromise = (async () => {
    const response = await fetch("/guard/jend-guard-v1.wasm", { cache: "force-cache" });
    if (!response.ok) throw new Error("GUARD_WASM_LOAD_FAILED");
    try {
      const { instance } = await WebAssembly.instantiateStreaming(response.clone(), {});
      if (typeof instance.exports.solve !== "function") throw new Error("GUARD_WASM_INVALID");
      return instance.exports;
    } catch {
      const bytes = await response.arrayBuffer();
      const { instance } = await WebAssembly.instantiate(bytes, {});
      if (typeof instance.exports.solve !== "function") throw new Error("GUARD_WASM_INVALID");
      return instance.exports;
    }
  })().catch((error) => {
    wasmPromise = null;
    throw error;
  });
  return wasmPromise;
}

async function requestChallenge(action) {
  const response = await fetch(`/api/security/challenge?action=${encodeURIComponent(action)}`, {
    credentials: "same-origin",
    cache: "no-store",
    headers: { "X-JEND-Guard": "1" },
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || "GUARD_CHALLENGE_FAILED");
  return data;
}

function yieldToBrowser() {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

async function solveChallenge(challenge, onProgress) {
  if (challenge.algorithm !== "sha256-pow-v1") throw new Error("GUARD_ALGORITHM_UNSUPPORTED");
  const seed = decodeBase64Url(challenge.seed || "");
  if (seed.length !== 32) throw new Error("GUARD_CHALLENGE_INVALID");
  const dv = new DataView(seed.buffer, seed.byteOffset, seed.byteLength);
  const words = [];
  for (let i = 0; i < 8; i++) words.push(dv.getUint32(i * 4, true));

  const wasm = await loadGuardWasm();
  let start = 0;
  const chunk = 50000;
  const started = performance.now();

  while (Math.floor(Date.now() / 1000) < Number(challenge.expiresAt || 0)) {
    const found = wasm.solve(...words, Number(challenge.difficulty), start, chunk);
    if (found >= 0) {
      return {
        id: challenge.id,
        counter: found,
        solvedMs: Math.max(1, Math.round(performance.now() - started)),
      };
    }
    start += chunk;
    if (start > 0x70000000) throw new Error("GUARD_SOLVE_FAILED");
    onProgress?.(start);
    await yieldToBrowser();
  }
  throw new Error("GUARD_EXPIRED");
}

export async function prepareGuard(action, onStatus) {
  const cached = proofCache.get(action);
  const now = Math.floor(Date.now() / 1000);
  if (cached && cached.expiresAt > now + 5) return cached.proof;

  onStatus?.("Проверяем устройство…");
  const challenge = await requestChallenge(action);
  const proof = await solveChallenge(challenge, () => onStatus?.("Проверяем устройство…"));
  proofCache.set(action, { proof, expiresAt: Number(challenge.expiresAt || 0) });
  onStatus?.("Проверка устройства пройдена.");
  return proof;
}

export function takeGuardProof(action) {
  const cached = proofCache.get(action);
  proofCache.delete(action);
  if (!cached) return null;
  const now = Math.floor(Date.now() / 1000);
  if (cached.expiresAt <= now + 2) return null;
  return cached.proof;
}

export function clearGuardProof(action) {
  proofCache.delete(action);
}
