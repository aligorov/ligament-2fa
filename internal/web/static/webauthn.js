// twofa: минимальный WebAuthn-клиент привязки passkey (единственный JS).
// Самодостаточен, без фреймворков: base64url-хелперы + две фазы регистрации.
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
  const name = form.elements["name"].value.trim();
  const code = form.elements["code"].value.trim();
  if (!name) { alert("Укажите имя ключа."); return false; }
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
    alert("Не удалось добавить passkey: " + e.message);
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

// Продолжение регистрации, начатой с сервера: POST /me/webauthn/credentials
// (форма без JS-fallback) перерендеривает страницу с data-атрибутами
// handle/name/options — проводим церемонию сразу и завершаем через JSON API.
document.addEventListener("DOMContentLoaded", async () => {
  const pend = document.getElementById("passkey-pending");
  if (!pend) return;
  try {
    const options = decodeCreationOptions(JSON.parse(pend.dataset.options));
    const cred = await finishCreation(pend.dataset.handle, options);
    await finishRegistration(pend.dataset.handle, pend.dataset.name || "", cred);
    window.location.reload();
  } catch (e) {
    if (e.name !== "NotAllowedError") { // отмена диалога — не ошибка
      alert("Не удалось добавить passkey: " + e.message);
    }
  }
});
