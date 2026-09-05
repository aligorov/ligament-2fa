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
      headers: {"Content-Type": "application/json"},
      credentials: "same-origin",
      body: JSON.stringify({name: name, code: code}),
    });
    if (!begin.ok) throw new Error("начало регистрации: HTTP " + begin.status);
    const data = await begin.json();
    const options = decodeCreationOptions(data.options || data);
    const cred = await navigator.credentials.create({publicKey: options});
    const finish = await fetch("/api/v1/me/webauthn/register/finish", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
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
    window.location.reload();
  } catch (e) {
    alert("Не удалось добавить passkey: " + e.message);
  }
  return false;
}
