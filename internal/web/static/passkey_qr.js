// passkey_qr.js — клиент мобильной аутентификации Passkey через QR-код.
"use strict";

function b64uToBytes(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToB64u(buf) {
  let s = "";
  for (const b of new Uint8Array(buf)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decodeRequestOptions(o) {
  if (!o) return o;
  const copy = Object.assign({}, o);
  if (typeof copy.challenge === "string") {
    copy.challenge = b64uToBytes(copy.challenge);
  }
  if (copy.allowCredentials && Array.isArray(copy.allowCredentials)) {
    copy.allowCredentials = copy.allowCredentials.map(function(c) {
      const credCopy = Object.assign({}, c);
      if (typeof credCopy.id === "string") {
        credCopy.id = b64uToBytes(credCopy.id);
      }
      return credCopy;
    });
  }
  return copy;
}

function encodeAssertion(cred) {
  const resp = cred.response;
  const out = {
    id: cred.id || bytesToB64u(cred.rawId),
    rawId: bytesToB64u(cred.rawId),
    type: cred.type,
    response: {
      authenticatorData: bytesToB64u(resp.authenticatorData),
      clientDataJSON: bytesToB64u(resp.clientDataJSON),
      signature: bytesToB64u(resp.signature),
    },
  };
  if (resp.userHandle && resp.userHandle.byteLength > 0) {
    out.response.userHandle = bytesToB64u(resp.userHandle);
  }
  return out;
}

let isAuthenticating = false;

async function runPasskeyAuth() {
  if (isAuthenticating) return;
  const container = document.getElementById("passkey-qr-container");
  if (!container) return;

  const btn = document.getElementById("auth-btn");
  const statusEl = document.getElementById("auth-status");
  const promptView = document.getElementById("prompt-view");
  const successView = document.getElementById("success-view");

  if (!window.PublicKeyCredential) {
    if (statusEl) {
      statusEl.className = "flash err";
      statusEl.textContent = "Ваш браузер не поддерживает WebAuthn / Passkeys.";
      statusEl.style.display = "block";
    }
    return;
  }

  const handle = container.getAttribute("data-handle");
  const rawOptsStr = container.getAttribute("data-options");
  if (!handle || !rawOptsStr) return;

  isAuthenticating = true;
  if (btn) {
    btn.disabled = true;
    btn.textContent = "Ожидание Passkey…";
  }
  if (statusEl) {
    statusEl.className = "flash ok";
    statusEl.textContent = "Подтвердите Face ID / Touch ID / Ключ безопасности…";
    statusEl.style.display = "block";
  }

  try {
    const rawOpts = JSON.parse(rawOptsStr);
    const options = decodeRequestOptions(rawOpts);
    const cred = await navigator.credentials.get({ publicKey: options });
    if (!cred) {
      throw new Error("Операция отменена");
    }

    if (btn) btn.textContent = "Проверка подписи…";
    if (statusEl) {
      statusEl.textContent = "Проверка ключа на сервере…";
    }

    const finishRes = await fetch("/api/v1/auth/webauthn/finish?handle=" + encodeURIComponent(handle), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(encodeAssertion(cred)),
    });

    if (!finishRes.ok) {
      const errJson = await finishRes.json().catch(function() { return {}; });
      throw new Error(errJson.error || ("Ошибка сервера (HTTP " + finishRes.status + ")"));
    }

    // Успех!
    if (navigator.vibrate) {
      try { navigator.vibrate([100, 50, 100]); } catch (e) {}
    }
    if (promptView) promptView.style.display = "none";
    if (successView) successView.style.display = "block";

  } catch (err) {
    isAuthenticating = false;
    if (btn) {
      btn.disabled = false;
      btn.textContent = "Попробовать снова";
    }
    if (statusEl) {
      statusEl.className = "flash err";
      if (err.name === "NotAllowedError") {
        statusEl.textContent = "Запрос отклонен или отменен. Нажмите кнопку, чтобы повторить.";
      } else {
        statusEl.textContent = "Ошибка: " + err.message;
      }
      statusEl.style.display = "block";
    }
  }
}

window.addEventListener("DOMContentLoaded", function() {
  const btn = document.getElementById("auth-btn");
  if (btn) {
    btn.addEventListener("click", runPasskeyAuth);
  }
  // Автоматический запуск церемонии
  setTimeout(function() {
    runPasskeyAuth();
  }, 250);
});
