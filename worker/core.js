import coreModule from "./core/jend-core.wasm";

let corePromise = null;

async function getCore() {
  if (!corePromise) {
    corePromise = WebAssembly.instantiate(coreModule, {}).then((result) => {
      const instance = result instanceof WebAssembly.Instance ? result : result.instance;
      const e = instance.exports;
      for (const name of ["jend_core_version", "jend_guard_min_delay", "jend_guard_score", "jend_guard_allow"]) {
        if (typeof e[name] !== "function") throw new Error("JEND_CORE_INVALID");
      }
      return e;
    }).catch((error) => {
      corePromise = null;
      throw error;
    });
  }
  return corePromise;
}

function actionCode(action) {
  if (action === "register") return 1;
  if (action === "qr-create") return 2;
  return 0;
}

export async function coreVersion() {
  const core = await getCore();
  return Number(core.jend_core_version()) >>> 0;
}

export async function coreMinDelay(action, pressure, knownDevice) {
  const core = await getCore();
  return Number(core.jend_guard_min_delay(
    actionCode(action),
    Math.max(0, Number(pressure) || 0),
    knownDevice ? 1 : 0
  )) >>> 0;
}

export async function coreGuardDecision({ action, ageMs, pressure, knownDevice, headerFlags, failures }) {
  const core = await getCore();
  const args = [
    actionCode(action),
    Math.max(0, Number(ageMs) || 0),
    Math.max(0, Number(pressure) || 0),
    knownDevice ? 1 : 0,
    Math.max(0, Number(headerFlags) || 0),
    Math.max(0, Number(failures) || 0),
  ];
  return {
    score: Number(core.jend_guard_score(...args)),
    allowed: Number(core.jend_guard_allow(...args)) === 1,
  };
}
