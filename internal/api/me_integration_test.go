//go:build integration

// Интеграционные тесты кабинета /api/v1/me: TOTP enroll→confirm→backup-коды,
// смена контактов с кодом, prefer-каналы, привязка Telegram, устройства,
// webauthn-регистрация (begin; finish — E2E T15).
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/aligorov/twofa/internal/channel"
	"github.com/aligorov/twofa/internal/secrets"
	"github.com/aligorov/twofa/internal/store"
	"github.com/aligorov/twofa/internal/webauthn"
)

// loginSession — вход пользователя без второго фактора; возвращает клиент
// с активной сессией.
func loginSession(t *testing.T, h http.Handler, username string) *webClient {
	t.Helper()
	c := newWebClient(t, h)
	rec := c.login(username, testPassword, false)
	wantStatus(t, rec, http.StatusOK)
	c.adoptCSRF(rec)
	return c
}

// TestMeTOTPFlow: enroll → {secret, otpauth_url}; неверный код → 401;
// верный → подтверждение + backup-коды (10, формат XXXXX-XXXXX, показ один
// раз); профиль отражает totp_confirmed; delete с резервным кодом.
func TestMeTOTPFlow(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	h, _ := newWebRouter(t, st, set, box, nil)
	user := mkUser(t, ctx, st, "metotp", nil)
	c := loginSession(t, h, user.Username)

	// Enroll: секрет и otpauth-URL.
	rec := c.do(http.MethodPost, "/api/v1/me/totp/enroll", map[string]string{})
	wantStatus(t, rec, http.StatusOK)
	body := jsonBody(t, rec)
	secret, _ := body["secret"].(string)
	url, _ := body["otpauth_url"].(string)
	if secret == "" || !regexp.MustCompile(`^otpauth://`).MatchString(url) {
		t.Fatalf("enroll: secret=%q url=%q", secret, url)
	}

	// Confirm с неверным кодом → 401.
	rec = c.do(http.MethodPost, "/api/v1/me/totp/confirm", map[string]string{"code": "000000"})
	wantStatus(t, rec, http.StatusUnauthorized)
	if jsonBody(t, rec)["error"] != "bad_code" {
		t.Fatalf("confirm(неверный): body = %s", rec.Body.String())
	}

	// Confirm с верным кодом → backup-коды показаны один раз.
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("totp.GenerateCode: %v", err)
	}
	rec = c.do(http.MethodPost, "/api/v1/me/totp/confirm", map[string]string{"code": code})
	wantStatus(t, rec, http.StatusOK)
	codesRaw := jsonBody(t, rec)["backup_codes"]
	codes, ok := codesRaw.([]any)
	if !ok || len(codes) != 10 {
		t.Fatalf("confirm: backup_codes = %v, want 10", codesRaw)
	}
	codeRe := regexp.MustCompile(`^[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{5}-[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{5}$`)
	for _, bc := range codes {
		if s, ok := bc.(string); !ok || !codeRe.MatchString(s) {
			t.Fatalf("backup-код неверного формата: %v", bc)
		}
	}

	// Секрет подтверждён; код подтверждения «сожжён» — повторно не принимает.
	rec = c.do(http.MethodGet, "/api/v1/me", nil)
	wantStatus(t, rec, http.StatusOK)
	if jsonBody(t, rec)["totp_confirmed"] != true {
		t.Fatalf("профиль: totp_confirmed != true: %s", rec.Body.String())
	}
	rec = c.do(http.MethodPost, "/api/v1/login/2fa",
		map[string]string{"username": user.Username, "password": testPassword, "code": code})
	wantStatus(t, rec, http.StatusUnauthorized)

	// Хеши кодов — в БД (открытые значения нигде не хранятся).
	var n int
	if err := st.Pool().QueryRow(ctx,
		`SELECT count(*) FROM backup_codes WHERE user_id = $1`, user.ID).Scan(&n); err != nil || n != 10 {
		t.Fatalf("backup_codes в БД = %d (err %v), want 10", n, err)
	}

	// Delete с резервным кодом (чувствительная операция).
	rec = c.do(http.MethodPost, "/api/v1/me/totp/delete",
		map[string]string{"code": codes[0].(string)})
	wantStatus(t, rec, http.StatusOK)
	rec = c.do(http.MethodGet, "/api/v1/me", nil)
	wantStatus(t, rec, http.StatusOK)
	if jsonBody(t, rec)["totp_confirmed"] != false {
		t.Fatalf("профиль: totp_confirmed != false после delete: %s", rec.Body.String())
	}
}

// TestMePasswordChangeLDAPBlocked (FIX-1): смена пароля LDAP-пользователя
// блокируется СЕРВЕРОМ, а не только скрытой формой UI: пароль живёт в
// каталоге, локальная замена записала бы непригодный хеш и отозвала
// сессии → lockout. 400 ldap_managed, хеш не меняется, сессия жива.
func TestMePasswordChangeLDAPBlocked(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	h, _ := newWebRouter(t, st, set, box, nil)
	user := mkUser(t, ctx, st, "meldap", func(u *store.User) {
		u.Source = store.SourceLDAP
	})
	hashBefore := user.PasswordHash
	c := loginSession(t, h, user.Username)

	rec := c.do(http.MethodPatch, "/api/v1/me/password",
		map[string]string{"old": testPassword, "new": "new-ldap-pass-123"})
	wantStatus(t, rec, http.StatusBadRequest)
	if jsonBody(t, rec)["error"] != "ldap_managed" {
		t.Fatalf("body = %s, want error=ldap_managed", rec.Body.String())
	}

	// Хеш не перезаписан «случайным непригодным», сессия не отозвана.
	fresh, err := st.UserByUsername(ctx, user.Username)
	if err != nil {
		t.Fatalf("UserByUsername: %v", err)
	}
	if fresh.PasswordHash != hashBefore {
		t.Fatal("password_hash изменён заблокированной сменой пароля")
	}
	rec = c.do(http.MethodGet, "/api/v1/me", nil)
	wantStatus(t, rec, http.StatusOK)
}

// TestMeContacts: вход со вторым фактором TOTP, код подтверждения на старый
// email (send-code), смена email с кодом; неверный код → 401; prefer PUT.
func TestMeContacts(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	h, email := newWebRouter(t, st, set, box, nil)
	user := mkUser(t, ctx, st, "mecontact", func(u *store.User) {
		u.Email = "old-contact@example.com"
		u.PreferChannels = []channel.Channel{channel.TOTP, channel.Email}
	})
	key := enrollTOTP(t, ctx, st, set, box, user)

	// Вход: второй шаг TOTP.
	c := newWebClient(t, h)
	rec := c.login(user.Username, testPassword, false)
	wantStatus(t, rec, http.StatusOK)
	if jsonBody(t, rec)["two_factor"] != "required" {
		t.Fatalf("login: %s", rec.Body.String())
	}
	code, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("totp.GenerateCode: %v", err)
	}
	rec = c.login2FA(user.Username, testPassword, code, false)
	wantStatus(t, rec, http.StatusOK)
	c.adoptCSRF(rec)

	// send-code — код на СТАРЫЙ email (первый доступный из prefer).
	rec = c.do(http.MethodPut, "/api/v1/me/contacts/send-code", map[string]string{})
	wantStatus(t, rec, http.StatusOK)
	body := jsonBody(t, rec)
	if body["channel"] != "email" {
		t.Fatalf("send-code: body = %v, want channel=email", body)
	}

	// Смена email с неверным кодом → 401.
	rec = c.do(http.MethodPut, "/api/v1/me/contacts",
		map[string]any{"email": "new-contact@example.com", "code": "000000"})
	wantStatus(t, rec, http.StatusUnauthorized)
	if jsonBody(t, rec)["error"] != "bad_code" {
		t.Fatalf("contacts(неверный код): body = %s", rec.Body.String())
	}

	// Смена email с доставленным кодом.
	sent := email.lastCode()
	if sent == "" {
		t.Fatal("код доставки не захвачен")
	}
	rec = c.do(http.MethodPut, "/api/v1/me/contacts",
		map[string]any{"email": "new-contact@example.com", "code": sent})
	wantStatus(t, rec, http.StatusOK)
	fresh, err := st.UserByUsername(ctx, user.Username)
	if err != nil || fresh.Email != "new-contact@example.com" {
		t.Fatalf("email в БД = %q (err %v), want new-contact@example.com", fresh.Email, err)
	}

	// prefer: валидная смена и неверное имя канала.
	rec = c.do(http.MethodPut, "/api/v1/me/prefer",
		map[string]any{"channels": []string{"email", "totp"}})
	wantStatus(t, rec, http.StatusOK)
	rec = c.do(http.MethodGet, "/api/v1/me", nil)
	wantStatus(t, rec, http.StatusOK)
	if !hasStr(jsonBody(t, rec)["prefer_channels"], "email") {
		t.Fatalf("prefer_channels после PUT: %s", rec.Body.String())
	}
	rec = c.do(http.MethodPut, "/api/v1/me/prefer",
		map[string]any{"channels": []string{"email", "fax"}})
	wantStatus(t, rec, http.StatusBadRequest)
}

// TestMeBackupCodesRegenerate: POST /api/v1/me/backup-codes/regenerate {code}
// (спека §7): пустой код → 400, неверный → 401 + аудит, верный → {codes:[10]}
// один раз; старая партия аннулируется (в БД ровно 10 свежих хешей).
func TestMeBackupCodesRegenerate(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	h, _ := newWebRouter(t, st, set, box, nil)
	user := mkUser(t, ctx, st, "mebackup", nil)
	c := loginSession(t, h, user.Username)
	key := enrollTOTP(t, ctx, st, set, box, user)

	// Пустой код → 400 code_required.
	rec := c.do(http.MethodPost, "/api/v1/me/backup-codes/regenerate", map[string]string{})
	wantStatus(t, rec, http.StatusBadRequest)
	if jsonBody(t, rec)["error"] != "code_required" {
		t.Fatalf("пустой код: body = %s", rec.Body.String())
	}

	// Неверный код → 401 bad_code.
	rec = c.do(http.MethodPost, "/api/v1/me/backup-codes/regenerate",
		map[string]string{"code": "000000"})
	wantStatus(t, rec, http.StatusUnauthorized)
	if jsonBody(t, rec)["error"] != "bad_code" {
		t.Fatalf("неверный код: body = %s", rec.Body.String())
	}

	// Верный TOTP-код → {codes: [10 кодов XXXXX-XXXXX]}.
	code, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("totp.GenerateCode: %v", err)
	}
	rec = c.do(http.MethodPost, "/api/v1/me/backup-codes/regenerate",
		map[string]string{"code": code})
	wantStatus(t, rec, http.StatusOK)
	codesRaw, ok := jsonBody(t, rec)["codes"].([]any)
	if !ok || len(codesRaw) != 10 {
		t.Fatalf("codes = %v, want 10", codesRaw)
	}
	codeRe := regexp.MustCompile(`^[A-Z2-9]{5}-[A-Z2-9]{5}$`)
	for _, bc := range codesRaw {
		if s, ok := bc.(string); !ok || !codeRe.MatchString(s) {
			t.Fatalf("код неверного формата: %v", bc)
		}
	}

	// В БД ровно 10 свежих хешей (старая партия аннулирована); аудит ok.
	var n int
	if err := st.Pool().QueryRow(ctx,
		`SELECT count(*) FROM backup_codes WHERE user_id = $1`, user.ID).Scan(&n); err != nil || n != 10 {
		t.Fatalf("backup_codes в БД = %d (err %v), want 10", n, err)
	}
	rows, err := st.AuditList(ctx, store.AuditFilter{Username: user.Username, Event: "backup_regen"})
	if err != nil || len(rows) == 0 {
		t.Fatalf("аудит backup_regen: rows=%d err=%v", len(rows), err)
	}
}

// TestMeDevices: remember_device создаёт устройство; список; отзыв;
// отозванное устройство снова требует второй фактор.
func TestMeDevices(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	h, _ := newWebRouter(t, st, set, box, nil)
	user := mkUser(t, ctx, st, "medev", nil)
	key := enrollTOTP(t, ctx, st, set, box, user)

	c := newWebClient(t, h)
	c.userAgent = "me-devices-test-UA"
	code, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("totp.GenerateCode: %v", err)
	}
	rec := c.login2FA(user.Username, testPassword, code, true)
	wantStatus(t, rec, http.StatusOK)
	c.adoptCSRF(rec)
	if c.device == nil {
		t.Fatal("cookie twofa_device не установлен")
	}

	// Список устройств.
	rec = c.do(http.MethodGet, "/api/v1/me/devices", nil)
	wantStatus(t, rec, http.StatusOK)
	devices := jsonBody(t, rec)["devices"].([]any)
	if len(devices) != 1 {
		t.Fatalf("devices = %d, want 1: %s", len(devices), rec.Body.String())
	}
	d := devices[0].(map[string]any)
	if d["ua"] != "me-devices-test-UA" {
		t.Fatalf("ua = %v, want me-devices-test-UA", d["ua"])
	}
	devID := int64(d["id"].(float64))

	// Чужое устройство удалить нельзя (несуществующий id → 404).
	rec = c.do(http.MethodDelete, "/api/v1/me/devices/999999", nil)
	wantStatus(t, rec, http.StatusNotFound)

	// Отзыв своего устройства.
	rec = c.do(http.MethodDelete, "/api/v1/me/devices/"+strconv.FormatInt(devID, 10), nil)
	wantStatus(t, rec, http.StatusOK)
	rec = c.do(http.MethodGet, "/api/v1/me/devices", nil)
	wantStatus(t, rec, http.StatusOK)
	if devices = jsonBody(t, rec)["devices"].([]any); len(devices) != 0 {
		t.Fatalf("devices после отзыва = %d, want 0", len(devices))
	}

	// Cookie устройства больше не даёт fast-path: снова второй фактор.
	revoked := newWebClient(t, h)
	revoked.device = c.device
	rec = revoked.login(user.Username, testPassword, false)
	wantStatus(t, rec, http.StatusOK)
	if jsonBody(t, rec)["two_factor"] != "required" {
		t.Fatalf("отозванное устройство дало вход без 2FA: %s", rec.Body.String())
	}
}

// TestMeTelegramLink: выдача кода привязки — чувствительная операция
// (SEC-002): без кода подтверждения → 400, с неверным → 401, с верным
// (TOTP) → код XXXX-XXXXX, челлендж purpose=tg_link с SHA-256-хешем;
// отвязка Telegram.
func TestMeTelegramLink(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	h, _ := newWebRouter(t, st, set, box, nil)
	user := mkUser(t, ctx, st, "metg", func(u *store.User) {
		chat := int64(111222333)
		u.TelegramChatID = &chat
	})
	c := loginSession(t, h, user.Username)
	key := enrollTOTP(t, ctx, st, set, box, user)

	// Есть второй фактор (TOTP + привязанный чат) — код подтверждения
	// обязателен: пустой → 400, неверный → 401.
	rec := c.do(http.MethodPost, "/api/v1/me/telegram/link", map[string]string{})
	wantStatus(t, rec, http.StatusBadRequest)
	if jsonBody(t, rec)["error"] != "code_required" {
		t.Fatalf("link(без кода): body = %s, want code_required", rec.Body.String())
	}
	rec = c.do(http.MethodPost, "/api/v1/me/telegram/link", map[string]string{"code": "000000"})
	wantStatus(t, rec, http.StatusUnauthorized)
	if jsonBody(t, rec)["error"] != "bad_code" {
		t.Fatalf("link(неверный код): body = %s, want bad_code", rec.Body.String())
	}
	rows, err := st.AuditList(ctx, store.AuditFilter{Username: user.Username, Event: "tg_link_start"})
	if err != nil || len(rows) < 2 {
		t.Fatalf("аудит tg_link_start(fail) не записан: rows=%d err=%v", len(rows), err)
	}

	totpCode, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("totp.GenerateCode: %v", err)
	}
	rec = c.do(http.MethodPost, "/api/v1/me/telegram/link",
		map[string]string{"code": totpCode})
	wantStatus(t, rec, http.StatusOK)
	body := jsonBody(t, rec)
	linkCode, _ := body["link_code"].(string)
	if !regexp.MustCompile(`^[A-Z2-9]{4}-[A-Z2-9]{4}$`).MatchString(linkCode) {
		t.Fatalf("link_code = %q, want XXXX-XXXX", linkCode)
	}
	if body["instructions"] == "" {
		t.Fatalf("instructions пуст: %s", rec.Body.String())
	}

	// Челлендж по хешу кода находит бота (T8), purpose=tg_link.
	var purpose string
	if err := st.Pool().QueryRow(ctx, `
		SELECT purpose FROM challenges
		WHERE code_hash = $1 AND used_at IS NULL AND expires_at > now()`,
		secrets.SHA256(linkCode)).Scan(&purpose); err != nil || purpose != "tg_link" {
		t.Fatalf("tg_link-челлендж: purpose=%q err=%v", purpose, err)
	}

	// Отвязка.
	rec = c.do(http.MethodDelete, "/api/v1/me/telegram", nil)
	wantStatus(t, rec, http.StatusOK)
	fresh, err := st.UserByID(ctx, user.ID)
	if err != nil || fresh.TelegramChatID != nil {
		t.Fatalf("telegram_chat_id после отвязки = %v (err %v), want nil", fresh.TelegramChatID, err)
	}
}

// TestMeWebauthn: begin требует код второго фактора (пустой → 400, неверный
// → 401 bad_code, верный → {handle, options} с creation-опциями); finish
// с мусорным ответом → 400; список ключей; удаление чужого/несуществующего.
func TestMeWebauthn(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	if err := set.Put(ctx, "webauthn", json.RawMessage(`{"rp_id":"localhost","rp_name":"twofa-test"}`)); err != nil {
		t.Fatalf("settings.Put(webauthn): %v", err)
	}
	wa, err := webauthn.New(st, set)
	if err != nil {
		t.Fatalf("webauthn.New: %v", err)
	}
	h, email := newWebRouter(t, st, set, box, wa)
	// Email есть — вход требует второй фактор; TOTP настроен напрямую,
	// коды подтверждения операций придут на email (fallback send-code).
	user := mkUser(t, ctx, st, "mewa", func(u *store.User) {
		u.Email = "mewa@example.com"
	})
	key := enrollTOTP(t, ctx, st, set, box, user)
	c := newWebClient(t, h)
	rec := c.login(user.Username, testPassword, false)
	wantStatus(t, rec, http.StatusOK)
	totpCode, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("totp.GenerateCode: %v", err)
	}
	rec = c.login2FA(user.Username, testPassword, totpCode, false)
	wantStatus(t, rec, http.StatusOK)
	c.adoptCSRF(rec)

	// Ключ уже вставлен напрямую — список показывает метаданные.
	if err := st.WACredUpsert(ctx, user.ID, &store.WACred{
		CredentialID: []byte("me-wa-cred-1"), RPID: "localhost",
		PublicKey: []byte("pk"), Name: "Тестовый ключ",
		AttestationType: "none", Present: true, Verified: true,
	}); err != nil {
		t.Fatalf("WACredUpsert: %v", err)
	}
	rec = c.do(http.MethodGet, "/api/v1/me/webauthn/credentials", nil)
	wantStatus(t, rec, http.StatusOK)
	creds := jsonBody(t, rec)["credentials"].([]any)
	if len(creds) != 1 {
		t.Fatalf("credentials = %d, want 1: %s", len(creds), rec.Body.String())
	}
	cred := creds[0].(map[string]any)
	if cred["name"] != "Тестовый ключ" {
		t.Fatalf("name = %v", cred["name"])
	}
	if _, has := cred["public_key"]; has {
		t.Fatalf("список раскрывает public_key: %v", cred)
	}

	// Код подтверждения для чувствительной операции: доставленный на email.
	rec = c.do(http.MethodPut, "/api/v1/me/contacts/send-code", map[string]string{})
	wantStatus(t, rec, http.StatusOK)
	goodCode := email.lastCode()
	if goodCode == "" {
		t.Fatal("код доставки не захвачен")
	}

	// Register begin без кода → 400 code_required (UI собирает код — сервер
	// обязан его проверить).
	rec = c.do(http.MethodPost, "/api/v1/me/webauthn/register/begin",
		map[string]string{"name": "Новый ключ"})
	wantStatus(t, rec, http.StatusBadRequest)
	if jsonBody(t, rec)["error"] != "code_required" {
		t.Fatalf("begin(без кода): body = %s, want code_required", rec.Body.String())
	}

	// Неверный код → 401 bad_code (аудит webauthn_register fail).
	rec = c.do(http.MethodPost, "/api/v1/me/webauthn/register/begin",
		map[string]string{"name": "Новый ключ", "code": "000000"})
	wantStatus(t, rec, http.StatusUnauthorized)
	if jsonBody(t, rec)["error"] != "bad_code" {
		t.Fatalf("begin(неверный код): body = %s, want bad_code", rec.Body.String())
	}
	rows, err := st.AuditList(ctx, store.AuditFilter{Username: user.Username, Event: "webauthn_register"})
	if err != nil || len(rows) == 0 {
		t.Fatalf("аудит webauthn_register(fail) не записан: rows=%d err=%v", len(rows), err)
	}

	// Верный код: 200 {handle, options.challenge} — options верхнего
	// уровня, без обёртки publicKey (webauthn.js ждёт challenge наверху).
	rec = c.do(http.MethodPost, "/api/v1/me/webauthn/register/begin",
		map[string]string{"name": "Новый ключ", "code": goodCode})
	wantStatus(t, rec, http.StatusOK)
	body := jsonBody(t, rec)
	handle, _ := body["handle"].(string)
	if handle == "" {
		t.Fatalf("handle пуст: %s", rec.Body.String())
	}
	opts := body["options"].(map[string]any)
	if _, wrapped := opts["publicKey"]; wrapped {
		t.Fatalf("options завёрнуты в publicKey: %v", opts)
	}
	if opts["challenge"] == nil {
		t.Fatalf("options.challenge отсутствует: %v", opts)
	}

	// Finish с мусорным ответом аутентификатора → 400 (сессия церемонии
	// погашается begin-handle'ом).
	rec = c.do(http.MethodPost, "/api/v1/me/webauthn/register/finish",
		map[string]any{"handle": handle, "name": "Новый ключ",
			"id": "x", "rawId": "eA", "type": "public-key", "response": map[string]any{}})
	wantStatus(t, rec, http.StatusBadRequest)

	// Finish без handle → 400.
	rec = c.do(http.MethodPost, "/api/v1/me/webauthn/register/finish",
		map[string]any{"id": "x", "type": "public-key"})
	wantStatus(t, rec, http.StatusBadRequest)

	// Удаление несуществующего ключа → 404.
	rec = c.do(http.MethodDelete, "/api/v1/me/webauthn/credentials/999999", nil)
	wantStatus(t, rec, http.StatusNotFound)
}

// TestLoginRejectsScreenCodes (SEC-001): экранные коди не работают как
// второй фактор входа — ни код привязки Telegram (tg_link), ни код
// подтверждения операций кабинета (ui_confirm из send-code).
func TestLoginRejectsScreenCodes(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	// Тест дважды берёт email-код подряд (send-code и auth/start) — без
	// ускорения cooldown второй запрос упрётся в 429.
	if err := set.Put(ctx, "policy", json.RawMessage(`{"resend_cooldown":"1ms"}`)); err != nil {
		t.Fatalf("set.Put(policy): %v", err)
	}
	t.Cleanup(func() {
		_ = set.Put(ctx, "policy", json.RawMessage(`{"resend_cooldown":"1m0s"}`))
	})
	h, email := newWebRouter(t, st, set, box, nil)
	user := mkUser(t, ctx, st, "screencode", func(u *store.User) {
		u.Email = "screencode@example.com"
		u.PreferChannels = []channel.Channel{channel.TOTP, channel.Email}
	})
	key := enrollTOTP(t, ctx, st, set, box, user)
	backupCodes, err := replaceBackupCodes(ctx, st, user.ID)
	if err != nil {
		t.Fatalf("replaceBackupCodes: %v", err)
	}

	// Полный 2FA-вход (TOTP-код расходуется на вход).
	c := newWebClient(t, h)
	rec := c.login(user.Username, testPassword, false)
	wantStatus(t, rec, http.StatusOK)
	totpCode, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("totp.GenerateCode: %v", err)
	}
	rec = c.login2FA(user.Username, testPassword, totpCode, false)
	wantStatus(t, rec, http.StatusOK)
	c.adoptCSRF(rec)

	// 1) tg_link-код: выдача с подтверждением резервным кодом (фактор
	// пользователя подходит для ui_confirm).
	rec = c.do(http.MethodPost, "/api/v1/me/telegram/link",
		map[string]string{"code": backupCodes[0]})
	wantStatus(t, rec, http.StatusOK)
	linkCode, _ := jsonBody(t, rec)["link_code"].(string)
	if linkCode == "" {
		t.Fatalf("link_code пуст: %s", rec.Body.String())
	}
	// Логин вторым шагом с ЭКРАННЫМ кодом привязки → 401 bad_code.
	rec = c.do(http.MethodPost, "/api/v1/login/2fa",
		map[string]string{"username": user.Username, "password": testPassword, "code": linkCode})
	wantStatus(t, rec, http.StatusUnauthorized)
	if jsonBody(t, rec)["error"] != "bad_code" {
		t.Fatalf("login/2fa с tg_link-кодом: body = %s, want bad_code", rec.Body.String())
	}
	// Тот же код не подтверждает и операцию кабинета (не его purpose).
	rec = c.do(http.MethodPost, "/api/v1/me/totp/delete",
		map[string]string{"code": linkCode})
	wantStatus(t, rec, http.StatusUnauthorized)

	// 2) ui_confirm-код (send-code для смены контактов) → входом не
	// принимается, но сменой контактов — принимается.
	rec = c.do(http.MethodPut, "/api/v1/me/contacts/send-code", map[string]string{})
	wantStatus(t, rec, http.StatusOK)
	uiCode := email.lastCode()
	if uiCode == "" {
		t.Fatal("код доставки не захвачен")
	}
	rec = c.do(http.MethodPost, "/api/v1/login/2fa",
		map[string]string{"username": user.Username, "password": testPassword, "code": uiCode})
	wantStatus(t, rec, http.StatusUnauthorized)
	if jsonBody(t, rec)["error"] != "bad_code" {
		t.Fatalf("login/2fa с ui_confirm-кодом: body = %s, want bad_code", rec.Body.String())
	}
	rec = c.do(http.MethodPut, "/api/v1/me/contacts",
		map[string]any{"email": "screencode2@example.com", "code": uiCode})
	wantStatus(t, rec, http.StatusOK)
	fresh, err := st.UserByUsername(ctx, user.Username)
	if err != nil || fresh.Email != "screencode2@example.com" {
		t.Fatalf("email после смены = %q (err %v)", fresh.Email, err)
	}

	// 3) Контроль: код входа (purpose api из /auth/start) логином
	// принимается. Отдельный пользователь с email первым в prefer —
	// auth/start отправляет именно email-код.
	ctl := mkUser(t, ctx, st, "screencodectl", func(u *store.User) {
		u.Email = "screencodectl@example.com"
		u.PreferChannels = []channel.Channel{channel.Email}
	})
	rec = c.do(http.MethodPost, "/api/v1/auth/start",
		map[string]string{"username": ctl.Username, "password": testPassword})
	wantStatus(t, rec, http.StatusOK)
	rec = c.do(http.MethodPost, "/api/v1/login/2fa",
		map[string]string{"username": ctl.Username, "password": testPassword, "code": email.lastCode()})
	wantStatus(t, rec, http.StatusOK)
	if jsonBody(t, rec)["ok"] != true {
		t.Fatalf("login/2fa с api-кодом: body = %s, want ok", rec.Body.String())
	}
}
