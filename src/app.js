import "./style.css";
import qrcode from "qrcode-generator";
import { BrowserQRCodeReader } from "@zxing/browser";
import { createDeviceVault, unlockDeviceVault, signQrApproval, hasTrustedDevice, removeActiveVault } from "./vault.js";

const $ = s => document.querySelector(s);
const views = ["guest-view", "register-view", "account-view", "camera-view", "approve-view"];
const message = $("#message");
const qrBox = $("#qr-box");
const qrTitle = $("#qr-title");
const qrCountdown = $("#qr-countdown");
const openCamera = $("#open-camera");
const cameraVideo = $("#camera-video");
const cameraStatus = $("#camera-status");
let qrState = null;
let qrRefreshTimer = null;
let qrPollTimer = null;
let countdownTimer = null;
let scannerControls = null;
let pendingApproval = null;
let scanningLocked = false;

function showView(id) { views.forEach(v => $("#" + v).hidden = v !== id); clearMessage(); }
function setMessage(text = "", type = "") { message.textContent = text; message.dataset.type = type; }
function clearMessage() { setMessage(); }
async function api(path, options = {}) {
  const response = await fetch(path, { credentials: "same-origin", cache: "no-store", ...options, headers: { "Content-Type": "application/json", ...(options.headers || {}) } });
  const data = await response.json().catch(() => ({ error: "Некорректный ответ сервера." }));
  return { response, data };
}
function renderQr(text) {
  const qr = qrcode(0, "M"); qr.addData(text); qr.make();
  qrBox.innerHTML = qr.createSvgTag({ cellSize: 5, margin: 2, scalable: true });
}
function clearQrTimers() {
  if (qrRefreshTimer) clearTimeout(qrRefreshTimer);
  if (qrPollTimer) clearTimeout(qrPollTimer);
  if (countdownTimer) clearInterval(countdownTimer);
  qrRefreshTimer = qrPollTimer = countdownTimer = null;
}
function updateCountdown(expiresAt) {
  const tick = () => {
    const left = Math.max(0, expiresAt - Math.floor(Date.now() / 1000));
    qrCountdown.textContent = `Автообновление через ${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`;
  };
  tick(); countdownTimer = setInterval(tick, 1000);
}
async function createQr() {
  if (qrState?.claimSecret) { /* previous QR naturally expires server-side */ }
  clearQrTimers();
  qrState = null;
  qrBox.innerHTML = '<div class="qr-placeholder"></div>';
  qrTitle.textContent = "Создаём QR…";
  qrCountdown.textContent = "Обновляется автоматически каждые 2 минуты";
  try {
    const { response, data } = await api("/api/auth/qr/create", { method: "POST", body: "{}" });
    if (!response.ok) throw new Error(data.error || "QR_ERROR");
    qrState = { id: data.id, claimSecret: data.claimSecret, expiresAt: data.expiresAt };
    renderQr(data.approvalUrl);
    qrTitle.textContent = "Отсканируйте QR";
    updateCountdown(data.expiresAt);
    qrRefreshTimer = setTimeout(createQr, Math.max(1000, (data.expiresAt * 1000) - Date.now() - 500));
    pollQr();
  } catch (e) {
    qrTitle.textContent = "Не удалось создать QR";
    setMessage(e.message === "QR_ERROR" ? "Ошибка QR." : "Проверьте соединение и Cloudflare Worker.", "error");
    qrRefreshTimer = setTimeout(createQr, 5000);
  }
}
async function pollQr() {
  if (!qrState) return;
  try {
    const { response, data } = await api("/api/auth/qr/status", { method: "POST", body: JSON.stringify({ id: qrState.id, claimSecret: qrState.claimSecret }) });
    if (response.status === 202 && data.status === "pending") { qrPollTimer = setTimeout(pollQr, 1500); return; }
    if (response.ok && data.status === "approved") {
      clearQrTimers(); qrState = null; await refreshSession(); setMessage("Вход подтверждён.", "ok"); return;
    }
    if ([409, 410].includes(response.status)) { createQr(); return; }
    qrPollTimer = setTimeout(pollQr, 2500);
  } catch { qrPollTimer = setTimeout(pollQr, 2500); }
}
async function refreshSession() {
  try {
    const res = await fetch("/api/auth/me", { credentials: "same-origin", cache: "no-store" });
    const data = await res.json().catch(() => ({}));
    if (res.ok && data.authenticated) {
      clearQrTimers(); showView("account-view");
      const trusted = hasTrustedDevice();
      $("#account-device-state").textContent = trusted ? "Это доверенное устройство. Оно может подтверждать QR-входы." : "Сессия активна. Это устройство вошло по QR и пока не является доверенным для подтверждения других входов.";
      openCamera.disabled = !trusted;
      return true;
    }
  } catch {}
  showView("guest-view"); createQr(); return false;
}
function parseApprovalUrl(raw) {
  try {
    const url = new URL(raw, location.origin);
    if (url.origin !== location.origin) return null;
    const id = url.searchParams.get("approve");
    const hash = new URLSearchParams(url.hash.replace(/^#/, ""));
    const approvalSecret = hash.get("s");
    if (!id || !approvalSecret) return null;
    return { id, approvalSecret };
  } catch { return null; }
}
async function prepareApproval(qr) {
  if (!hasTrustedDevice()) { setMessage("На этом устройстве нет доверенного ключа.", "error"); return; }
  const { response, data } = await api("/api/auth/qr/details", { method: "POST", body: JSON.stringify(qr) });
  if (!response.ok) { setMessage(data.error || "QR недействителен.", "error"); return; }
  pendingApproval = { ...qr, challenge: data.challenge };
  showView("approve-view");
  $("#approve-password").value = ""; $("#approve-password").focus();
}
async function stopCamera() {
  try { scannerControls?.stop(); } catch {}
  scannerControls = null;
  if (cameraVideo.srcObject) { for (const t of cameraVideo.srcObject.getTracks()) t.stop(); cameraVideo.srcObject = null; }
}
async function startCamera() {
  if (!hasTrustedDevice()) return;
  showView("camera-view"); cameraStatus.textContent = "Запрашиваем доступ к камере…";
  try {
    const reader = new BrowserQRCodeReader();
    scanningLocked = false;
    scannerControls = await reader.decodeFromConstraints({ audio: false, video: { facingMode: { ideal: "environment" } } }, cameraVideo, async (result, _error, controls) => {
      if (!result || scanningLocked) return;
      const parsed = parseApprovalUrl(result.getText());
      if (!parsed) { cameraStatus.textContent = "Это не QR-код входа этого сайта."; return; }
      scanningLocked = true;
      try { controls?.stop(); } catch {}
      await stopCamera();
      await prepareApproval(parsed);
    });
    cameraStatus.textContent = "Наведите камеру на QR-код входа.";
  } catch (e) {
    cameraStatus.textContent = "Не удалось открыть камеру. Проверьте разрешение браузера и HTTPS.";
    setMessage("Камера недоступна.", "error");
  }
}

$("#open-register").addEventListener("click", () => { clearQrTimers(); showView("register-view"); });
$("#register-back").addEventListener("click", () => { showView("guest-view"); createQr(); });
$("#refresh-qr").addEventListener("click", createQr);
$("#register-view").addEventListener("submit", async e => {
  e.preventDefault(); clearMessage(); const submit = $("#register-submit"); submit.disabled = true;
  let localCreated = false;
  try {
    const password = $("#register-password").value;
    const local = await createDeviceVault(password); localCreated = true;
    const { response, data } = await api("/api/auth/register", { method: "POST", body: JSON.stringify({ nickname: $("#nickname").value, deviceId: local.deviceId, publicKeyJwk: local.publicKeyJwk }) });
    $("#register-password").value = "";
    if (!response.ok) { await removeActiveVault(); localCreated = false; setMessage(data.error || "Не удалось создать аккаунт.", "error"); return; }
    $("#nickname").value = ""; await refreshSession(); setMessage("Аккаунт создан. Пароль на сервер не отправлялся.", "ok");
  } catch (err) {
    if (localCreated) await removeActiveVault(); $("#register-password").value = "";
    setMessage(err?.message === "INVALID_PASSWORD" ? "Пароль должен быть длиной от 12 до 128 символов." : "Не удалось создать защищённый ключ устройства.", "error");
  } finally { submit.disabled = false; }
});
openCamera.addEventListener("click", startCamera);
$("#camera-back").addEventListener("click", async () => { await stopCamera(); showView("account-view"); });
$("#approve-back").addEventListener("click", () => { pendingApproval = null; showView("account-view"); });
$("#approve-cancel").addEventListener("click", () => { pendingApproval = null; showView("account-view"); });
$("#approve-view").addEventListener("submit", async e => {
  e.preventDefault(); if (!pendingApproval) return; clearMessage(); const submit = $("#approve-submit"); submit.disabled = true;
  try {
    const unlocked = await unlockDeviceVault($("#approve-password").value); $("#approve-password").value = "";
    if (!unlocked) { setMessage("Пароль неверный.", "error"); return; }
    const signature = await signQrApproval(unlocked.privateKey, pendingApproval.id, pendingApproval.challenge);
    const { response, data } = await api("/api/auth/qr/approve", { method: "POST", body: JSON.stringify({ id: pendingApproval.id, approvalSecret: pendingApproval.approvalSecret, deviceId: unlocked.deviceId, signature }) });
    if (!response.ok) { setMessage(data.error || "Подтверждение отклонено.", "error"); return; }
    pendingApproval = null; showView("account-view"); setMessage("Вход на другом устройстве подтверждён. Здесь аккаунт остался без изменений.", "ok");
  } catch { setMessage("Не удалось подтвердить вход.", "error"); }
  finally { submit.disabled = false; }
});
$("#logout").addEventListener("click", async () => {
  await api("/api/auth/logout", { method: "POST", body: "{}" }).catch(() => {});
  await stopCamera(); showView("guest-view"); createQr(); setMessage("Вы вышли из аккаунта.", "ok");
});

async function boot() {
  const external = parseApprovalUrl(location.href);
  if (external) history.replaceState(null, "", location.pathname);
  const authed = await refreshSession();
  if (external) {
    if (!authed) { setMessage("Чтобы подтвердить QR, сначала откройте его на уже авторизованном доверенном устройстве.", "error"); return; }
    await prepareApproval(external);
  }
}
boot();
