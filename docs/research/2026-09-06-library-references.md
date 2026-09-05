# Справочник библиотек (проверено агентами 2026-09-06 по первоисточникам)

Для реализации `twofa`. Каждый блок — выжимка точных API + гочхи, нужные при кодировании.

## Go / go.mod

- **Go 1.25+** (требование `go-webauthn` v0.18.0: `go 1.25.0`).

## 1. go-webauthn/webauthn — v0.18.0 (авг 2026)

Импорты: `github.com/go-webauthn/webauthn/webauthn` + `.../protocol`.

```go
w, err := webauthn.New(&webauthn.Config{
    RPDisplayName: "twofa",
    RPID:          "2fa.example.com",            // только домен, без схемы/порта
    RPOrigins:     []string{"https://2fa.example.com"}, // scheme+host(+порт), БЕЗ пути и слэша
})
```

- Интерфейс `webauthn.User`: `WebAuthnID() []byte` (стабильный случайный handle ≤64 байт — **хранить в users.webauthn_id**), `WebAuthnName() string`, `WebAuthnDisplayName() string`, `WebAuthnCredentials() []Credential`. Метода `WebAuthnCredentialIDs()` больше нет.
- Регистрация: `w.BeginRegistration(user, opts...) (*protocol.CredentialCreation, *webauthn.SessionData, error)`; `w.FinishRegistration(user, session, r *http.Request) (*Credential, error)` — принимает сам `*http.Request` (парсит тело). Для passkeys: `webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementRequired, UserVerification: protocol.VerificationRequired})` + `webauthn.WithExclusions(webauthn.Credentials(creds).CredentialDescriptors())`.
- Логин: `w.BeginLogin(user, opts...)`; `w.FinishLogin(user, session, r *http.Request)`. **После каждого успешного логина сохранять обновлённый `Authenticator.SignCount`/`Flags` из возвращённого credential** — иначе сломается следующий вход. `Authenticator.CloneWarning == true` → возможен клон, алерт в аудит.
- `webauthn.SessionData` сериализуется обычным `encoding/json`; хранить на сервере (наш cookie/БД), декодировать в свежий объект, удалять после использования; передавать в Finish **по значению**.
- `webauthn.Credential` хранится JSON-целиком (ID, PublicKey COSE, Transport, Flags, Authenticator{AAGUID, SignCount}, ...).
- Гочхи: RPOrigins сверяются по scheme+host с портом, без trailing slash; пустые RPOrigins/невалидный RPID валит `New()`; v0.18 — незапрошенные client-extensions фейлят церемонию по умолчанию; `LoginOption/RegistrationOption` теперь возвращают error.

## 2. layeh.com/radius (стабильно заморожена; активный drop-in форк github.com/maddsua/layeh-radius)

Сервер называется **`radius.PacketServer`**:

```go
srv := radius.PacketServer{
    Addr:         ":1812",
    Handler:      radius.HandlerFunc(handler),
    SecretSource: radius.StaticSecretSource([]byte(secret)), // или per-NAS: radius.RADIUSSecret(ctx, remoteAddr)
}
go srv.ListenAndServe()
```

- Handler: `func(w radius.ResponseWriter, r *radius.Request)`; коды `radius.CodeAccessRequest`, `radius.CodeAccountingRequest`.
- Чтение PAP: `rfc2865.UserName_GetString(r.Packet)`, `rfc2865.UserPassword_GetString(r.Packet)` — **User-Password расшифровывается автоматически** секретом пакета; для ошибок использовать `*_LookupString` (`radius.ErrNoAttribute`).
- Ответ: `resp := r.Response(radius.CodeAccessAccept)`; атрибуты: `rfc2865.ReplyMessage_SetString(resp, ...)`; MikroTik VSA — готовый пакет `layeh.com/radius/vendors/mikrotik` (`MikrotikGroup_SetString`, `MikrotikRateLimit_SetString`, `MikrotikAddressList_SetString`, vendor 14988 вшит). Своя VSA: `radius.NewVendorSpecific(14988, tlv)` + `p.Add(rfc2865.VendorSpecific_Type, vsa)`.
- Accounting: отвечать `CodeAccountingResponse` обязательно (иначе NAS ретрансмитит).
- Тест-клиент: `radius.New(radius.CodeAccessRequest, []byte(secret))` + `rfc2865.UserPassword_SetString` + `radius.Exchange(ctx, packet, "127.0.0.1:1812")` (ретраи 1 c — в тестах учесть).
- Гочхи: неверный secret → пакет молча дропается (клиент просто таймаутится); параллельный handler на пакет (горутина на датаграмму) — общее состояние под мьютексом; MaxPacketLength 4096; дедуп ретрансмиссий по IP+Identifier уже есть.

## 3. Telegram Bot API 10.3 (net/http, без библиотек)

- База: `POST https://api.telegram.org/bot<TOKEN>/<метод>`, JSON-тела, ответ `{"ok":bool,"result":...|error_code,description,parameters.retry_after}`.
- Long polling: `getUpdates {offset, timeout:50, allowed_updates:["message","callback_query"]}`; `offset = last_update_id + 1`; HTTP-клиент с таймаутом > timeout.
- Push: `sendMessage {chat_id, text, reply_markup:{inline_keyboard:[[{"text":"✅ Подтвердить","callback_data":"approve:<uuid>"},{"text":"❌ Это не я","callback_data":"deny:<uuid>"}]]}}`; `callback_data` ≤64 байт — `approve:`+UUID помещается.
- Кнопка приходит как `update.callback_query{id, from.id, message.chat.id, data}`; **всегда отвечать** `answerCallbackQuery {callback_query_id}` (иначе крутится спиннер).
- Лимиты: 1 сообщение/сек на чат (троттлить per-chat), ~30/сек глобально; 429 → `parameters.retry_after` секунд подождать; 403 = бот заблокирован (терминально).
- Обновления: `update_id` не глобально монотонен после недели простоя — не полагаться.

## 4. pquerna/otp — v1.5.0 (TOTP)

- Генерация: `totp.Generate(totp.GenerateOpts{Issuer, AccountName, Period:30, Digits:otp.DigitsSix, Algorithm:otp.AlgorithmSHA1})` → `*otp.Key`; `key.Secret()` (base32 — хранить шифрованным, НЕ хешем), `key.URL()` (otpauth:// для QR).
- Проверка: `totp.ValidateCustom(code, secret, time.Now().UTC(), totp.ValidateOpts{Period:30, Skew:1, Digits:otp.DigitsSix, Algorithm:otp.AlgorithmSHA1})`.
- **Библиотека stateless — replay-защиты нет**: один и тот же код валиден весь ±Skew (до ~90 c). Обязательно самим хранить `last_timestep` (счётчик `unix/30`) и отвергать коды со счётчиком ≤ последнего принятого (с учётом Skew).
- Секрет хранить восстанавливаемым (AES-GCM), никогда хешем; SHA1/6/30 — стандарт совместимости с приложениями-аутентификаторами.

## Источники

go-webauthn: github.com/go-webauthn/webauthn (tag v0.18.0, types.go/registration.go/login.go/types_session.go/credential.go/MIGRATION.md), pkg.go.dev.
radius: pkg.go.dev/layeh.com/radius (+ rfc2865, vendors/mikrotik), github.com/layeh/radius (server.go, server-packet.go), github.com/maddsua/layeh-radius.
Telegram: core.telegram.org/bots/api, core.telegram.org/bots/faq.
otp: pkg.go.dev/github.com/pquerna/otp, github.com/pquerna/otp/blob/master/totp/totp.go.
