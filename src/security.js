let configPromise = null;
let turnstileScriptPromise = null;
const widgets = new Map();

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

function loadTurnstileScript() {
  if (window.turnstile) return Promise.resolve(window.turnstile);
  if (turnstileScriptPromise) return turnstileScriptPromise;

  turnstileScriptPromise = new Promise((resolve, reject) => {
    const existing = document.querySelector('script[data-secure-turnstile="1"]');
    if (existing) {
      const wait = () => window.turnstile ? resolve(window.turnstile) : setTimeout(wait, 50);
      wait();
      return;
    }

    const script = document.createElement("script");
    script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
    script.defer = true;
    script.async = true;
    script.dataset.secureTurnstile = "1";
    script.onload = () => window.turnstile ? resolve(window.turnstile) : reject(new Error("TURNSTILE_LOAD_FAILED"));
    script.onerror = () => reject(new Error("TURNSTILE_LOAD_FAILED"));
    document.head.appendChild(script);
  }).catch((error) => {
    turnstileScriptPromise = null;
    throw error;
  });

  return turnstileScriptPromise;
}

export async function ensureTurnstile(name, selector, action, onToken) {
  if (widgets.has(name)) return widgets.get(name);
  const config = await getSecurityConfig();
  if (!config.turnstile?.configured || !config.turnstile.siteKey) {
    throw new Error("TURNSTILE_NOT_CONFIGURED");
  }

  const turnstile = await loadTurnstileScript();
  const container = document.querySelector(selector);
  if (!container) throw new Error("TURNSTILE_CONTAINER_MISSING");

  const state = { id: null, token: "", action, selector };
  state.id = turnstile.render(container, {
    sitekey: config.turnstile.siteKey,
    theme: "auto",
    size: "flexible",
    action,
    callback(token) {
      state.token = token || "";
      onToken?.(state.token);
    },
    "expired-callback"() {
      state.token = "";
    },
    "error-callback"() {
      state.token = "";
    },
    "timeout-callback"() {
      state.token = "";
      try { turnstile.reset(state.id); } catch {}
    },
  });
  widgets.set(name, state);
  return state;
}

export function getTurnstileToken(name) {
  return widgets.get(name)?.token || "";
}

export function resetTurnstile(name) {
  const state = widgets.get(name);
  if (!state || !window.turnstile) return;
  state.token = "";
  try {
    window.turnstile.reset(state.id);
  } catch {}
}
