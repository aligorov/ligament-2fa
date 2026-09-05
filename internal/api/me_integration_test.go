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

// TestMeTelegramLink: код привязки XXXX-XXXXX, челлендж purpose=tg_link с
// SHA-256-хешем; отвязка Telegram.
func TestMeTelegramLink(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	h, _ := newWebRouter(t, st, set, box, nil)
	user := mkUser(t, ctx, st, "metg", func(u *store.User) {
		chat := int64(111222333)
		u.TelegramChatID = &chat
	})
	c := loginSession(t, h, user.Username)

	rec := c.do(http.MethodPost, "/api/v1/me/telegram/link", map[string]string{})
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
	err := st.Pool().QueryRow(ctx, `
		SELECT purpose FROM challenges
		WHERE code_hash = $1 AND used_at IS NULL AND expires_at > now()`,
		secrets.SHA256(linkCode)).Scan(&purpose)
	if err != nil || purpose != "tg_link" {
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

// TestMeWebauthn: begin выдаёт {handle, options} с creation-опциями; finish
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
	h, _ := newWebRouter(t, st, set, box, wa)
	user := mkUser(t, ctx, st, "mewa", nil)
	c := loginSession(t, h, user.Username)

	// Ключ уже вставлен напрямую — список показывает метаданные.
	if err := st.WACredUpsert(ctx, user.ID, &store.WACred{
		CredentialID: []byte("me-wa-cred-1"), RPID: "localhost",
		PublicKey: []byte("pk"), Name: "Тестовый ключ",
		AttestationType: "none", Present: true, Verified: true,
	}); err != nil {
		t.Fatalf("WACredUpsert: %v", err)
	}
	rec := c.do(http.MethodGet, "/api/v1/me/webauthn/credentials", nil)
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

	// Register begin: {handle, options.publicKey.challenge}.
	rec = c.do(http.MethodPost, "/api/v1/me/webauthn/register/begin",
		map[string]string{"name": "Новый ключ"})
	wantStatus(t, rec, http.StatusOK)
	body := jsonBody(t, rec)
	handle, _ := body["handle"].(string)
	if handle == "" {
		t.Fatalf("handle пуст: %s", rec.Body.String())
	}
	opts := body["options"].(map[string]any)
	pk := opts["publicKey"].(map[string]any)
	if pk["challenge"] == nil {
		t.Fatalf("options.publicKey.challenge отсутствует: %v", pk)
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
