// twofa: минимальный WebAuthn-клиент привязки passkey (единственный JS).
// Самодостаточен, без фреймворков: base64url-хелперы + две фазы регистрации.
// UI-обвязка: кнопка «Добавить passkey» получает состояние загрузки, ошибки
// выводятся в .flash (контейнер #passkey-flash) вместо alert.
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

// CSRF-токен текущей сессии из скрытого поля формы (или любого csrf_token
// на странице); подставляется в заголовок X-CSRF-Token JSON-запросов.
function csrfToken(form) {
  const el = (form && form.elements["csrf_token"]) ||
    document.querySelector('input[name="csrf_token"]');
  return el ? el.value : "";
}

// showErr выводит ошибку церемонии контейнером .flash над формой; alert
// больше не блокирует страницу.
function showErr(msg) {
  const box = document.getElementById("passkey-flash");
  if (!box) { alert(msg); return; }
  box.innerHTML = "";
  const div = document.createElement("div");
  div.className = "flash err";
  const icon = document.createElement("span");
  icon.className = "flash-icon";
  icon.textContent = "⚠️";
  div.appendChild(icon);
  div.appendChild(document.createTextNode(msg));
  box.appendChild(div);
}

// setBusy переключает кнопку формы в состояние загрузки и обратно.
function setBusy(btn, busy, text) {
  if (!btn) return;
  if (busy) {
    if (!btn.dataset.label) btn.dataset.label = btn.textContent;
    btn.disabled = true;
    btn.textContent = text || "Загрузка…";
  } else {
    if (btn.dataset.label) btn.textContent = btn.dataset.label;
    btn.disabled = false;
  }
}

// PublicKeyCredentialCreationOptions: строки base64url → Uint8Array.
function decodeCreationOptions(o) {
  o.challenge = b64uToBytes(o.challenge);
  if (o.user && o.user.id) o.user.id = b64uToBytes(o.user.id);
  if (o.excludeCredentials) {
    o.excludeCredentials = o.excludeCredentials.map(c => ({...c, id: b64uToBytes(c.id)}));
  }
  return o;
}

async function twofaRegisterPasskey(form) {
  const btn = form.querySelector('button[type="button"]');
  const name = form.elements["name"].value.trim();
  const code = form.elements["code"].value.trim();
  if (!name) { showErr("Укажите имя ключа."); return false; }
  setBusy(btn, true);
  try {
    const begin = await fetch("/api/v1/me/webauthn/register/begin", {
      method: "POST",
      headers: {"Content-Type": "application/json", "X-CSRF-Token": csrfToken(form)},
      credentials: "same-origin",
      body: JSON.stringify({name: name, code: code}),
    });
    if (!begin.ok) throw new Error("начало регистрации: HTTP " + begin.status);
    const data = await begin.json();
    const cred = await finishCreation(data.handle, decodeCreationOptions(data.options || data));
    await finishRegistration(data.handle, name, cred);
    window.location.reload();
  } catch (e) {
    setBusy(btn, false);
    showErr("Не удалось добавить passkey: " + e.message);
  }
  return false;
}

// finishCreation — диалог браузера создания ключа.
async function finishCreation(handle, options) {
  return navigator.credentials.create({publicKey: options});
}

// finishRegistration — вторая фаза: сырой PublicKeyCredential + handle.
async function finishRegistration(handle, name, cred) {
  const finish = await fetch("/api/v1/me/webauthn/register/finish?handle=" +
      encodeURIComponent(handle), {
    method: "POST",
    headers: {"Content-Type": "application/json", "X-CSRF-Token": csrfToken(null)},
    credentials: "same-origin",
    body: JSON.stringify({
      name: name,
      id: bytesToB64u(cred.rawId),
      rawId: bytesToB64u(cred.rawId),
      type: cred.type,
      response: {
        attestationObject: bytesToB64u(cred.response.attestationObject),
        clientDataJSON: bytesToB64u(cred.response.clientDataJSON),
      },
    }),
  });
  if (!finish.ok) throw new Error("завершение регистрации: HTTP " + finish.status);
}

// PublicKeyCredentialRequestOptions: base64url challenge и id учётных данных → Uint8Array.
function decodeRequestOptions(o) {
  if (!o) return o;
  const copy = Object.assign({}, o);
  if (typeof copy.challenge === "string") {
    copy.challenge = b64uToBytes(copy.challenge);
  }
  if (copy.allowCredentials && Array.isArray(copy.allowCredentials)) {
    copy.allowCredentials = copy.allowCredentials.map(c => {
      const credCopy = Object.assign({}, c);
      if (typeof credCopy.id === "string") {
        credCopy.id = b64uToBytes(credCopy.id);
      }
      return credCopy;
    });
  }
  return copy;
}

// encodeAssertion собирает JSON-структуру для /api/v1/auth/webauthn/finish.
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

function showLoginErr(msg) {
  const box = document.getElementById("login-flash") || document.getElementById("passkey-flash");
  if (!box) {
    if (msg) alert(msg);
    return;
  }
  box.innerHTML = "";
  if (!msg) return;
  const div = document.createElement("div");
  div.className = "flash err";
  const icon = document.createElement("span");
  icon.className = "flash-icon";
  icon.textContent = "⚠️";
  div.appendChild(icon);
  div.appendChild(document.createTextNode(" " + msg));
  box.appendChild(div);
}

function showLoginInfo(msg) {
  const box = document.getElementById("login-flash");
  if (!box) return;
  box.innerHTML = "";
  if (!msg) return;
  const div = document.createElement("div");
  div.className = "flash ok";
  const icon = document.createElement("span");
  icon.className = "flash-icon";
  icon.textContent = "🔑";
  div.appendChild(icon);
  div.appendChild(document.createTextNode(" " + msg));
  box.appendChild(div);
}

// safeNext — та же валидация адреса возврата, что и на сервере (pages.go):
// только локальные пути без «//» (протокол-относительный URL) и без «\»
// (браузеры трактуют backslash как «/» — /\evil.com уводит с сайта).
// Чужое значение заменяется на /me.
function safeNext(next) {
  return typeof next === "string" &&
    next.startsWith("/") &&
    !next.startsWith("//") &&
    !next.includes("\\")
    ? next
    : "";
}

// twofaLoginPasskey проводит WebAuthn-церемонию входа (Touch ID / Face ID / Windows Hello / YubiKey).
// isAuto = true при автоматическом вызове на сабмите формы (если passkey нет — тихий fallback на POST).
async function twofaLoginPasskey(form, isAuto) {
  if (!form) return false;
  if (!window.PublicKeyCredential) {
    if (!isAuto) showLoginErr("Ваш браузер не поддерживает WebAuthn / Passkeys.");
    return false;
  }
  const usernameInput = form.elements["username"];
  const passwordInput = form.elements["password"];
  const username = usernameInput ? usernameInput.value.trim() : "";
  const password = passwordInput ? passwordInput.value : "";
  const remember = form.elements["remember"] ? form.elements["remember"].checked : false;
  const nextInput = form.elements["next"];
  const next = nextInput ? nextInput.value : "";

  if (!username) {
    if (!isAuto) {
      showLoginErr("Укажите имя пользователя.");
      if (usernameInput) usernameInput.focus();
    }
    return false;
  }
  if (!password) {
    if (!isAuto) {
      showLoginErr("Укажите пароль.");
      if (passwordInput) passwordInput.focus();
    }
    return false;
  }

  const passkeyBtn = form.querySelector("[data-passkey-login]");
  const submitBtn = form.querySelector('button[type="submit"]');
  const targetBtn = passkeyBtn || submitBtn;
  setBusy(targetBtn, true, "Проверка…");

  try {
    const beginRes = await fetch("/api/v1/auth/webauthn/begin", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      credentials: "same-origin",
      body: JSON.stringify({username: username, password: password}),
    });

    if (beginRes.status === 409) {
      // У пользователя нет зарегистрированных passkeys
      setBusy(targetBtn, false);
      if (!isAuto) {
        showLoginErr("У пользователя нет привязанных passkeys.");
      }
      return false;
    }
    if (beginRes.status === 401) {
      setBusy(targetBtn, false);
      showLoginErr("Неверное имя пользователя или пароль.");
      return false;
    }
    if (beginRes.status === 423) {
      setBusy(targetBtn, false);
      showLoginErr("Учётная запись временно заблокирована.");
      return false;
    }
    if (!beginRes.ok) {
      setBusy(targetBtn, false);
      if (!isAuto) showLoginErr("Ошибка WebAuthn (HTTP " + beginRes.status + ")");
      return false;
    }

    const data = await beginRes.json();
    const handle = data.handle;
    const rawOpts = data.options || data;
    const options = decodeRequestOptions(rawOpts);

    setBusy(targetBtn, true, "Ожидание ключа…");
    showLoginInfo("Подтвердите вход в диалоге браузера (Touch ID / Face ID / Ключ безопасности)…");

    let cred;
    try {
      cred = await navigator.credentials.get({publicKey: options});
    } catch (e) {
      setBusy(targetBtn, false);
      showLoginInfo("");
      if (e.name === "NotAllowedError") {
        // Пользователь нажал «Отмена»
        return false;
      }
      showLoginErr("Ошибка passkey: " + e.message);
      return false;
    }

    if (!cred) {
      setBusy(targetBtn, false);
      showLoginInfo("");
      return false;
    }

    setBusy(targetBtn, true, "Вход…");

    // Завершение WebAuthn
    const finishRes = await fetch("/api/v1/auth/webauthn/finish?handle=" + encodeURIComponent(handle), {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      credentials: "same-origin",
      body: JSON.stringify(encodeAssertion(cred)),
    });

    if (!finishRes.ok) {
      setBusy(targetBtn, false);
      showLoginInfo("");
      showLoginErr("Не удалось подтвердить passkey.");
      return false;
    }

    // Выпуск сессии через /api/v1/login/2fa с пустым кодом (webauthn_web_pending)
    const loginRes = await fetch("/api/v1/login/2fa", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      credentials: "same-origin",
      body: JSON.stringify({
        username: username,
        password: password,
        code: "",
        remember_device: remember,
      }),
    });

    if (!loginRes.ok) {
      setBusy(targetBtn, false);
      showLoginInfo("");
      showLoginErr("Не удалось выпустить сессию.");
      return false;
    }

    // Успех! Переходим в личный кабинет / на целевую страницу
    // (next проходит safeNext — открытый редирект через /\ или // отсечён).
    window.location.href = safeNext(next) || "/me";
    return true;

  } catch (err) {
    setBusy(targetBtn, false);
    showLoginInfo("");
    if (!isAuto) showLoginErr("Ошибка входа: " + err.message);
    return false;
  }
}

// Кнопка «Добавить passkey» (data-passkey-register) в кабинете
document.addEventListener("DOMContentLoaded", () => {
  const btn = document.querySelector("[data-passkey-register]");
  if (btn) {
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      twofaRegisterPasskey(btn.form);
    });
  }

  // Кнопка явного входа по passkey
  const passkeyLoginBtn = document.querySelector("[data-passkey-login]");
  if (passkeyLoginBtn) {
    passkeyLoginBtn.addEventListener("click", (e) => {
      e.preventDefault();
      twofaLoginPasskey(passkeyLoginBtn.closest("form"), false);
    });
  }

  // Форма входа: если код пуст, автоматически предлагаем Passkey при наличии привязанного ключа
  const loginForm = document.querySelector(".login-card form");
  if (loginForm) {
    let submitting = false;
    loginForm.addEventListener("submit", async (e) => {
      if (submitting) return;
      const codeInput = loginForm.elements["code"];
      if (codeInput && codeInput.value.trim() !== "") {
        return; // код введён — обычная отправка
      }
      if (e.submitter && (e.submitter.value === "send_email" || e.submitter.value === "send_sms")) {
        return; // вспомогательные действия
      }
      const usernameInput = loginForm.elements["username"];
      const passwordInput = loginForm.elements["password"];
      if (!usernameInput || !usernameInput.value.trim() || !passwordInput || !passwordInput.value) {
        return; // сработает HTML5 required-валидация браузера
      }
      if (window.PublicKeyCredential) {
        e.preventDefault();
        const handled = await twofaLoginPasskey(loginForm, true);
        if (!handled) {
          submitting = true;
          loginForm.submit();
        }
      }
    });
  }
});

// Продолжение регистрации, начатой с сервера: POST /me/webauthn/credentials
document.addEventListener("DOMContentLoaded", async () => {
  const pend = document.getElementById("passkey-pending");
  if (!pend) return;
  try {
    const options = decodeCreationOptions(JSON.parse(pend.dataset.options));
    const cred = await finishCreation(pend.dataset.handle, options);
    await finishRegistration(pend.dataset.handle, pend.dataset.name || "", cred);
    window.location.reload();
  } catch (e) {
    if (e.name !== "NotAllowedError") {
      showErr("Не удалось добавить passkey: " + e.message);
    }
  }
});

