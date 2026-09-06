import "./style.css";
import qrcode from "qrcode-generator";
import { BrowserQRCodeReader } from "@zxing/browser";
import {
  approvalTokenFromQr,
  createDeviceVault,
  createQrClientState,
  decryptQrPassword,
  encryptQrPassword,
  getTrustedDeviceId,
  hasTrustedDevice,
  randomUrlToken,
  removeActiveVault,
  signQrApproval,
  unlockDeviceVault,
} from "./vault.js";

const $ = (selector) => document.querySelector(selector);
const views = [
  "guest-view",
  "register-view",
  "account-view",
  "camera-view",
  "phone-wait-view",
  "login-password-view",
];

const message = $("#message");
const qrBox = $("#qr-box");
const qrTitle = $("#qr-title");
const qrCountdown = $("#qr-countdown");
const openCamera = $("#open-camera");
const cameraVideo = $("#camera-video");
const cameraStatus = $("#camera-status");
const loginSubmit = $("#login-submit");

let qrState = null;
let qrRefreshTimer = null;
let qrPollTimer = null;
let countdownTimer = null;
let scannerControls = null;
let scanningLocked = false;
let phonePair = null;
let phonePollTimer = null;
let phoneProcessing = false;

function showView(id) {
  views.forEach((view) => {
    $("#" + view).hidden = view !== id;
  });
  clearMessage();
}

function setMessage(text = "", type = "") {
  message.textContent = text;
  message.dataset.type = type;
}

function clearMessage() {
  setMessage();
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin",
    cache: "no-store",
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });
  const data = await response.json().catch(() => ({ error: "Некорректный ответ сервера." }));
  return { response, data };
}

function renderQr(text) {
  const qr = qrcode(0, "M");
  qr.addData(text);
  qr.make();
  qrBox.innerHTML = qr.createSvgTag({ cellSize: 5, margin: 2, scalable: true });
}

function stopQrVisualTimers() {
  if (qrRefreshTimer) clearTimeout(qrRefreshTimer);
  if (countdownTimer) clearInterval(countdownTimer);
  qrRefreshTimer = countdownTimer = null;
}

function stopQrPoll() {
  if (qrPollTimer) clearTimeout(qrPollTimer);
  qrPollTimer = null;
}

function clearQrTimers() {
  stopQrVisualTimers();
  stopQrPoll();
}

function stopPhonePoll() {
  if (phonePollTimer) clearTimeout(phonePollTimer);
  phonePollTimer = null;
  phoneProcessing = false;
}

function updateCountdown(expiresAt) {
  const tick = () => {
    const left = Math.max(0, expiresAt - Math.floor(Date.now() / 1000));
    qrCountdown.textContent = `Автообновление через ${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`;
  };
  tick();
  countdownTimer = setInterval(tick, 1000);
}

function buildApprovalUrl(id, pairingSecret) {
  const url = new URL("/", location.origin);
  url.searchParams.set("approve", id);
  url.hash = new URLSearchParams({ s: pairingSecret }).toString();
  return url.toString();
}

async function createQr() {
  clearQrTimers();
  qrState = null;
  qrBox.innerHTML = '<div class="qr-placeholder"></div>';
  qrTitle.textContent = "Создаём QR…";
  qrCountdown.textContent = "Обновляется автоматически каждые 2 минуты";

  try {
    const local = await createQrClientState();
    const { response, data } = await api("/api/auth/qr/create", {
      method: "POST",
      body: JSON.stringify({
        id: local.id,
        approvalToken: local.approvalToken,
        claimVerifier: local.claimVerifier,
      }),
    });
    if (!response.ok) throw new Error(data.error || "QR_ERROR");

    qrState = {
      ...local,
      expiresAt: data.expiresAt,
      phase: "waiting_scan",
      lastPasswordResult: null,
    };

    renderQr(buildApprovalUrl(local.id, local.pairingSecret));
    qrTitle.textContent = "Отсканируйте QR";
    updateCountdown(data.expiresAt);
    qrRefreshTimer = setTimeout(
      createQr,
      Math.max(1000, (data.expiresAt * 1000) - Date.now() - 500)
    );
    pollQr();
  } catch (error) {
    qrTitle.textContent = "Не удалось создать QR";
    setMessage(error.message || "Проверьте соединение и Cloudflare Worker.", "error");
    qrRefreshTimer = setTimeout(createQr, 5000);
  }
}

function showPasswordAfterPair() {
  if (!qrState) return;
  stopQrVisualTimers();
  qrState.phase = "paired";
  $("#login-password").value = "";
  loginSubmit.disabled = false;
  showView("login-password-view");
  setMessage("QR подтверждён. Теперь введите пароль на этом устройстве.", "ok");
  $("#login-password").focus();
}

async function pollQr() {
  if (!qrState) return;

  try {
    const { response, data } = await api("/api/auth/qr/status", {
      method: "POST",
      body: JSON.stringify({ id: qrState.id, claimSecret: qrState.claimSecret }),
    });

    if (response.status === 202 && data.status === "pending") {
      if (data.phase === "paired" && qrState.phase === "waiting_scan") {
        showPasswordAfterPair();
      }

      if (data.phase === "password_pending") {
        qrState.phase = "password_pending";
        loginSubmit.disabled = true;
        if (!$("#login-password-view").hidden) {
          setMessage("Проверяем пароль на доверенном телефоне…", "");
        }
      }

      if (data.phase === "paired" && data.passwordResult === "wrong" && qrState.lastPasswordResult !== "wrong") {
        qrState.phase = "paired";
        qrState.lastPasswordResult = "wrong";
        loginSubmit.disabled = false;
        showView("login-password-view");
        const attemptsLeft = Math.max(0, 5 - Number(data.failures || 0));
        setMessage(`Пароль неверный. Осталось попыток: ${attemptsLeft}.`, "error");
        $("#login-password").focus();
      }

      qrPollTimer = setTimeout(pollQr, 1000);
      return;
    }

    if (response.ok && data.status === "approved") {
      clearQrTimers();
      qrState = null;
      await refreshSession();
      setMessage("Вы вошли.", "ok");
      return;
    }

    if ([409, 410, 429].includes(response.status)) {
      const errorText = data.error || "Попытка входа завершена.";
      clearQrTimers();
      qrState = null;
      showView("guest-view");
      setMessage(errorText, "error");
      setTimeout(createQr, 1400);
      return;
    }

    qrPollTimer = setTimeout(pollQr, 1800);
  } catch {
    qrPollTimer = setTimeout(pollQr, 1800);
  }
}

async function refreshSession() {
  try {
    const response = await fetch("/api/auth/me", {
      credentials: "same-origin",
      cache: "no-store",
    });
    const data = await response.json().catch(() => ({}));

    if (response.ok && data.authenticated) {
      clearQrTimers();
      showView("account-view");
      const trusted = hasTrustedDevice();
      $("#account-device-state").textContent = trusted
        ? "Это доверенное устройство. Оно может сканировать QR для входа на других устройствах."
        : "Сессия активна. Это устройство вошло по QR и пока не может подтверждать другие QR-входы.";
      openCamera.disabled = !trusted;
      return true;
    }
  } catch {}

  showView("guest-view");
  createQr();
  return false;
}

function parseApprovalUrl(raw) {
  try {
    const url = new URL(raw, location.origin);
    if (url.origin !== location.origin) return null;
    const id = url.searchParams.get("approve");
    const hash = new URLSearchParams(url.hash.replace(/^#/, ""));
    const pairingSecret = hash.get("s");
    if (!id || !pairingSecret) return null;
    return { id, pairingSecret };
  } catch {
    return null;
  }
}

async function stopCamera() {
  try {
    scannerControls?.stop();
  } catch {}
  scannerControls = null;

  if (cameraVideo.srcObject) {
    for (const track of cameraVideo.srcObject.getTracks()) track.stop();
    cameraVideo.srcObject = null;
  }
}

async function preparePhonePair(qr) {
  if (!hasTrustedDevice()) {
    setMessage("На этом устройстве нет доверенного ключа.", "error");
    return;
  }

  const deviceId = getTrustedDeviceId();
  if (!deviceId) {
    setMessage("Не найден ключ доверенного устройства.", "error");
    return;
  }

  try {
    const approvalToken = await approvalTokenFromQr(qr.pairingSecret, qr.id);
    const { response, data } = await api("/api/auth/qr/pair", {
      method: "POST",
      body: JSON.stringify({ id: qr.id, approvalToken, deviceId }),
    });

    if (!response.ok) {
      showView("account-view");
      setMessage(data.error || "QR недействителен.", "error");
      return;
    }

    phonePair = {
      ...qr,
      approvalToken,
      deviceId,
      challenge: data.challenge,
      expiresAt: data.expiresAt,
    };
    showView("phone-wait-view");
    $("#phone-wait-status").textContent = "QR принят. Теперь введите пароль на компьютере. Телефон проверит его локально.";
    pollPhonePair();
  } catch {
    showView("account-view");
    setMessage("Не удалось связать устройства.", "error");
  }
}

async function processPhonePassword(data) {
  if (!phonePair || phoneProcessing) return;
  phoneProcessing = true;

  try {
    let password = await decryptQrPassword({
      pairingSecret: phonePair.pairingSecret,
      id: phonePair.id,
      attemptId: data.attemptId,
      iv: data.iv,
      ciphertext: data.ciphertext,
    });

    if (password === null) {
      await api("/api/auth/qr/result", {
        method: "POST",
        body: JSON.stringify({
          id: phonePair.id,
          approvalToken: phonePair.approvalToken,
          deviceId: phonePair.deviceId,
          attemptId: data.attemptId,
          valid: false,
        }),
      });
      $("#phone-wait-status").textContent = "Зашифрованный пароль не удалось проверить. Можно попробовать ещё раз на компьютере.";
      return;
    }

    const unlocked = await unlockDeviceVault(password);
    password = null;

    if (!unlocked) {
      const { data: resultData } = await api("/api/auth/qr/result", {
        method: "POST",
        body: JSON.stringify({
          id: phonePair.id,
          approvalToken: phonePair.approvalToken,
          deviceId: phonePair.deviceId,
          attemptId: data.attemptId,
          valid: false,
        }),
      });
      $("#phone-wait-status").textContent = resultData.denied
        ? "Слишком много неверных попыток. Вход отменён."
        : "Пароль неверный. На компьютере можно попробовать ещё раз.";
      return;
    }

    const signature = await signQrApproval(
      unlocked.privateKey,
      phonePair.id,
      phonePair.challenge,
      data.attemptId
    );

    const { response, data: resultData } = await api("/api/auth/qr/result", {
      method: "POST",
      body: JSON.stringify({
        id: phonePair.id,
        approvalToken: phonePair.approvalToken,
        deviceId: phonePair.deviceId,
        attemptId: data.attemptId,
        valid: true,
        signature,
      }),
    });

    if (!response.ok) {
      $("#phone-wait-status").textContent = resultData.error || "Не удалось подтвердить вход.";
      return;
    }

    stopPhonePoll();
    phonePair = null;
    showView("account-view");
    setMessage("Пароль верный. Вход на другом устройстве разрешён. Аккаунт на этом телефоне не изменился.", "ok");
  } catch {
    $("#phone-wait-status").textContent = "Ошибка проверки. Ожидаем повторную попытку…";
  } finally {
    phoneProcessing = false;
  }
}

async function pollPhonePair() {
  if (!phonePair) return;

  try {
    const { response, data } = await api("/api/auth/qr/phone-status", {
      method: "POST",
      body: JSON.stringify({
        id: phonePair.id,
        approvalToken: phonePair.approvalToken,
        deviceId: phonePair.deviceId,
      }),
    });

    if (response.ok && data.status === "password_pending") {
      await processPhonePassword(data);
    } else if (response.ok && data.status === "approved") {
      stopPhonePoll();
      phonePair = null;
      showView("account-view");
      setMessage("Вход на другом устройстве подтверждён.", "ok");
      return;
    } else if ([401, 403, 404, 410].includes(response.status)) {
      stopPhonePoll();
      const text = data.error || "Попытка входа завершена.";
      phonePair = null;
      showView("account-view");
      setMessage(text, "error");
      return;
    }
  } catch {}

  if (phonePair) phonePollTimer = setTimeout(pollPhonePair, 900);
}

async function startCamera() {
  if (!hasTrustedDevice()) return;
  showView("camera-view");
  cameraStatus.textContent = "Запрашиваем доступ к камере…";

  try {
    const reader = new BrowserQRCodeReader();
    scanningLocked = false;
    scannerControls = await reader.decodeFromConstraints(
      { audio: false, video: { facingMode: { ideal: "environment" } } },
      cameraVideo,
      async (result, _error, controls) => {
        if (!result || scanningLocked) return;
        const parsed = parseApprovalUrl(result.getText());
        if (!parsed) {
          cameraStatus.textContent = "Это не QR-код входа этого сайта.";
          return;
        }

        scanningLocked = true;
        try {
          controls?.stop();
        } catch {}
        await stopCamera();
        await preparePhonePair(parsed);
      }
    );
    cameraStatus.textContent = "Наведите камеру на QR-код входа.";
  } catch {
    cameraStatus.textContent = "Не удалось открыть камеру. Проверьте разрешение браузера и HTTPS.";
    setMessage("Камера недоступна.", "error");
  }
}

$("#open-register").addEventListener("click", () => {
  clearQrTimers();
  showView("register-view");
});

$("#register-back").addEventListener("click", () => {
  showView("guest-view");
  createQr();
});

$("#refresh-qr").addEventListener("click", createQr);

$("#register-view").addEventListener("submit", async (event) => {
  event.preventDefault();
  clearMessage();
  const submit = $("#register-submit");
  submit.disabled = true;
  let localCreated = false;

  try {
    const password = $("#register-password").value;
    const local = await createDeviceVault(password);
    localCreated = true;

    const { response, data } = await api("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({
        nickname: $("#nickname").value,
        deviceId: local.deviceId,
        publicKeyJwk: local.publicKeyJwk,
      }),
    });

    $("#register-password").value = "";
    if (!response.ok) {
      await removeActiveVault();
      localCreated = false;
      setMessage(data.error || "Не удалось создать аккаунт.", "error");
      return;
    }

    $("#nickname").value = "";
    await refreshSession();
    setMessage("Аккаунт создан. Пароль на сервер не отправлялся.", "ok");
  } catch (error) {
    if (localCreated) await removeActiveVault();
    $("#register-password").value = "";
    setMessage(
      error?.message === "INVALID_PASSWORD"
        ? "Пароль должен быть длиной от 12 до 128 символов."
        : "Не удалось создать защищённый ключ устройства.",
      "error"
    );
  } finally {
    submit.disabled = false;
  }
});

openCamera.addEventListener("click", startCamera);

$("#camera-back").addEventListener("click", async () => {
  await stopCamera();
  showView("account-view");
});

$("#login-cancel").addEventListener("click", () => {
  clearQrTimers();
  qrState = null;
  showView("guest-view");
  createQr();
});

$("#login-password-view").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!qrState || qrState.phase !== "paired") return;

  clearMessage();
  loginSubmit.disabled = true;
  const passwordInput = $("#login-password");
  const password = passwordInput.value;
  passwordInput.value = "";

  try {
    const attemptId = randomUrlToken(18);
    const encrypted = await encryptQrPassword(
      password,
      qrState.pairingSecret,
      qrState.id,
      attemptId
    );

    qrState.lastPasswordResult = null;
    const { response, data } = await api("/api/auth/qr/password", {
      method: "POST",
      body: JSON.stringify({
        id: qrState.id,
        claimSecret: qrState.claimSecret,
        attemptId,
        iv: encrypted.iv,
        ciphertext: encrypted.ciphertext,
      }),
    });

    if (!response.ok) {
      loginSubmit.disabled = false;
      setMessage(data.error || "Не удалось проверить пароль.", "error");
      return;
    }

    qrState.phase = "password_pending";
    setMessage("Проверяем пароль на доверенном телефоне…", "");
  } catch (error) {
    loginSubmit.disabled = false;
    setMessage(
      error?.message === "INVALID_PASSWORD"
        ? "Пароль должен быть длиной от 12 до 128 символов."
        : "Не удалось зашифровать пароль.",
      "error"
    );
  }
});

$("#logout").addEventListener("click", async () => {
  await api("/api/auth/logout", { method: "POST", body: "{}" }).catch(() => {});
  stopPhonePoll();
  phonePair = null;
  await stopCamera();
  showView("guest-view");
  createQr();
  setMessage("Вы вышли из аккаунта.", "ok");
});

async function boot() {
  const external = parseApprovalUrl(location.href);
  if (external) history.replaceState(null, "", location.pathname);

  const authed = await refreshSession();
  if (external) {
    if (!authed || !hasTrustedDevice()) {
      setMessage("Этот QR нужно открыть на уже зарегистрированном доверенном устройстве.", "error");
      return;
    }
    await preparePhonePair(external);
  }
}

boot();
