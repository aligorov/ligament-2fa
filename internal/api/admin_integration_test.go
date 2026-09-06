//go:build integration

// Интеграционные тесты админ API: Bearer-токен, users CRUD, сбросы второго
// фактора, аудит, активные челленджи, настройки (маскирование, мерж PUT,
// регенерация секретов).
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/aligorov/twofa/internal/secrets"
	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
)

// mkUUID — случайный несуществующий id пользователя.
func mkUUID() string { return uuid.New().String() }

// TestAdminTokenAuth: без заголовка и с неверным токеном — 401, с верным — 200.
func TestAdminTokenAuth(t *testing.T) {
	st, set, box := setup(t)
	h, _ := newWebRouter(t, st, set, box, nil)

	rec := adminReq(t, h, http.MethodGet, "/api/v1/admin/users", nil, "")
	wantStatus(t, rec, http.StatusUnauthorized)

	rec = adminReq(t, h, http.MethodGet, "/api/v1/admin/users", nil, "wrong-token")
	wantStatus(t, rec, http.StatusUnauthorized)

	rec = adminReq(t, h, http.MethodGet, "/api/v1/admin/users", nil, set.Get().AdminToken)
	wantStatus(t, rec, http.StatusOK)
	body := jsonBody(t, rec)
	if _, ok := body["users"].([]any); !ok {
		t.Fatalf("body = %s, want users[]", rec.Body.String())
	}
}

// TestAdminUsersCRUD: создание (201, без password_hash), дубликат имени 409,
// список/чтение, PATCH enabled+password, удаление → 404.
func TestAdminUsersCRUD(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	h, _ := newWebRouter(t, st, set, box, nil)
	tok := set.Get().AdminToken

	// Создание.
	rec := adminReq(t, h, http.MethodPost, "/api/v1/admin/users", map[string]any{
		"username": "admincr", "password": "first-pass-1", "email": "admincr@example.com",
	}, tok)
	wantStatus(t, rec, http.StatusCreated)
	body := jsonBody(t, rec)
	if body["username"] != "admincr" || body["enabled"] != true {
		t.Fatalf("create: body = %v", body)
	}
	if strings.Contains(rec.Body.String(), "argon2") {
		t.Fatalf("ответ раскрывает password_hash: %s", rec.Body.String())
	}
	id, _ := body["id"].(string)
	if id == "" {
		t.Fatalf("create: id пуст: %s", rec.Body.String())
	}

	// Дубликат имени → 409.
	rec = adminReq(t, h, http.MethodPost, "/api/v1/admin/users",
		map[string]any{"username": "admincr", "password": "x-pass-1234"}, tok)
	wantStatus(t, rec, http.StatusConflict)

	// Пустой username/password → 400.
	rec = adminReq(t, h, http.MethodPost, "/api/v1/admin/users",
		map[string]any{"username": "", "password": ""}, tok)
	wantStatus(t, rec, http.StatusBadRequest)

	// Список содержит нового пользователя.
	rec = adminReq(t, h, http.MethodGet, "/api/v1/admin/users", nil, tok)
	wantStatus(t, rec, http.StatusOK)
	found := false
	for _, u := range jsonBody(t, rec)["users"].([]any) {
		if m, ok := u.(map[string]any); ok && m["username"] == "admincr" {
			found = true
		}
	}
	if !found {
		t.Fatal("admincr отсутствует в списке пользователей")
	}

	// Чтение по id.
	rec = adminReq(t, h, http.MethodGet, "/api/v1/admin/users/"+id, nil, tok)
	wantStatus(t, rec, http.StatusOK)
	if jsonBody(t, rec)["email"] != "admincr@example.com" {
		t.Fatalf("get: body = %s", rec.Body.String())
	}

	// Отключение → вход 401.
	rec = adminReq(t, h, http.MethodPatch, "/api/v1/admin/users/"+id,
		map[string]any{"enabled": false}, tok)
	wantStatus(t, rec, http.StatusOK)
	c := newWebClient(t, h)
	rec = c.login("admincr", "first-pass-1", false)
	wantStatus(t, rec, http.StatusUnauthorized)

	// Включение + смена пароля одним PATCH → вход с новым паролем.
	rec = adminReq(t, h, http.MethodPatch, "/api/v1/admin/users/"+id,
		map[string]any{"enabled": true, "password": "second-pass-2"}, tok)
	wantStatus(t, rec, http.StatusOK)
	c = newWebClient(t, h)
	rec = c.login("admincr", "second-pass-2", false)
	wantStatus(t, rec, http.StatusOK)

	// Несуществующий id → 404; битый id → 400.
	rec = adminReq(t, h, http.MethodGet, "/api/v1/admin/users/"+mkUUID(), nil, tok)
	wantStatus(t, rec, http.StatusNotFound)
	rec = adminReq(t, h, http.MethodGet, "/api/v1/admin/users/not-a-uuid", nil, tok)
	wantStatus(t, rec, http.StatusBadRequest)

	// Удаление → повторное чтение 404.
	rec = adminReq(t, h, http.MethodDelete, "/api/v1/admin/users/"+id, nil, tok)
	wantStatus(t, rec, http.StatusOK)
	rec = adminReq(t, h, http.MethodGet, "/api/v1/admin/users/"+id, nil, tok)
	wantStatus(t, rec, http.StatusNotFound)

	// admin_action пишется в аудит.
	rows, err := st.AuditList(ctx, store.AuditFilter{Event: "admin_action", Limit: 200})
	if err != nil {
		t.Fatalf("AuditList: %v", err)
	}
	saw := false
	for _, row := range rows {
		if row.Detail != nil && row.Detail["action"] == "user_create" {
			saw = true
		}
	}
	if !saw {
		t.Fatal("аудит admin_action/user_create не записан")
	}
}

// TestAdminResetTOTP: reset-totp удаляет секрет, старые резервные коды
// аннулируются, новая партия возвращается один раз.
func TestAdminResetTOTP(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	h, _ := newWebRouter(t, st, set, box, nil)
	tok := set.Get().AdminToken

	user := mkUser(t, ctx, st, "adminrst", nil)
	enrollTOTP(t, ctx, st, set, box, user)
	oldCodes := secrets.GenBackupCodes()
	hashes := make([][]byte, len(oldCodes))
	for i, c := range oldCodes {
		hashes[i] = secrets.SHA256(c)
	}
	if err := st.BackupReplace(ctx, user.ID, hashes); err != nil {
		t.Fatalf("BackupReplace: %v", err)
	}

	rec := adminReq(t, h, http.MethodPost, "/api/v1/admin/users/"+user.ID.String()+"/reset-totp", nil, tok)
	wantStatus(t, rec, http.StatusOK)
	body := jsonBody(t, rec)
	newCodes, ok := body["backup_codes"].([]any)
	if !ok || len(newCodes) != 10 {
		t.Fatalf("reset-totp: backup_codes = %v, want 10 кодов", body["backup_codes"])
	}

	// TOTP-секрет удалён.
	if _, _, _, _, _, err := st.TOTPGet(ctx, user.ID); err != store.ErrNotFound {
		t.Fatalf("TOTPGet после reset = %v, want ErrNotFound", err)
	}

	// Старый резервный код больше не работает, новый — работает
	// (проверяем комбинированным входом публичного API).
	rec = doReq(t, h, http.MethodPost, "/api/v1/auth/combined",
		map[string]string{"username": user.Username, "password": testPassword, "code": oldCodes[0]})
	wantStatus(t, rec, http.StatusUnauthorized)
	rec = doReq(t, h, http.MethodPost, "/api/v1/auth/combined",
		map[string]string{"username": user.Username, "password": testPassword, "code": newCodes[0].(string)})
	wantStatus(t, rec, http.StatusOK)
}

// TestAdminResetWebauthnAndTelegram: reset-webauthn чистит ключи,
// unlink-telegram отвязывает чат, devices DELETE отзывает устройства.
func TestAdminResetWebauthnAndTelegram(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	h, _ := newWebRouter(t, st, set, box, nil)
	tok := set.Get().AdminToken

	user := mkUser(t, ctx, st, "adminrst2", func(u *store.User) {
		chat := int64(4242)
		u.TelegramChatID = &chat
	})
	if err := st.WACredUpsert(ctx, user.ID, &store.WACred{
		CredentialID: []byte("admin-rst-cred"), RPID: "localhost",
		PublicKey: []byte("pk"), AttestationType: "none",
		Present: true, Verified: true,
	}); err != nil {
		t.Fatalf("WACredUpsert: %v", err)
	}
	if err := st.DeviceCreate(ctx, &store.Device{
		UserID: user.ID, TokenHash: secrets.SHA256("admin-rst-device"),
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("DeviceCreate: %v", err)
	}
	id := user.ID.String()

	rec := adminReq(t, h, http.MethodPost, "/api/v1/admin/users/"+id+"/reset-webauthn", nil, tok)
	wantStatus(t, rec, http.StatusOK)
	if creds, err := st.WACredListForUser(ctx, user.ID); err != nil || len(creds) != 0 {
		t.Fatalf("passkeys после reset = %d (err %v), want 0", len(creds), err)
	}

	rec = adminReq(t, h, http.MethodPost, "/api/v1/admin/users/"+id+"/unlink-telegram", nil, tok)
	wantStatus(t, rec, http.StatusOK)
	fresh, err := st.UserByID(ctx, user.ID)
	if err != nil || fresh.TelegramChatID != nil {
		t.Fatalf("telegram_chat_id после unlink = %v (err %v), want nil", fresh.TelegramChatID, err)
	}

	rec = adminReq(t, h, http.MethodDelete, "/api/v1/admin/users/"+id+"/devices", nil, tok)
	wantStatus(t, rec, http.StatusOK)
	if devs, err := st.DeviceListForUser(ctx, user.ID); err != nil || len(devs) != 0 {
		t.Fatalf("устройства после отзыва = %d (err %v), want 0", len(devs), err)
	}
}

// TestAdminAuditAndChallenges: фильтры аудита, активные челленджи — только
// метаданные (без code_hash).
func TestAdminAuditAndChallenges(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	h, _ := newWebRouter(t, st, set, box, nil)
	tok := set.Get().AdminToken

	user := mkUser(t, ctx, st, "adminaud", nil)
	if err := st.Audit(ctx, user.Username, "api_start", nil, "127.0.0.1", "ok"); err != nil {
		t.Fatalf("Audit: %v", err)
	}
	ch := &store.Challenge{
		UserID: user.ID, Channel: "email", CodeHash: secrets.SHA256("top-secret-code"),
		ExpiresAt: time.Now().Add(time.Minute), AttemptsLeft: 5, Purpose: "api",
	}
	if err := st.ChallengeCreate(ctx, ch); err != nil {
		t.Fatalf("ChallengeCreate: %v", err)
	}

	// Аудит: фильтр по username+event, битый since → 400.
	rec := adminReq(t, h, http.MethodGet, "/api/v1/admin/audit?username="+user.Username+"&event=api_start", nil, tok)
	wantStatus(t, rec, http.StatusOK)
	events := jsonBody(t, rec)["events"].([]any)
	if len(events) == 0 {
		t.Fatalf("аудит пуст: %s", rec.Body.String())
	}
	rec = adminReq(t, h, http.MethodGet, "/api/v1/admin/audit?since=not-a-time", nil, tok)
	wantStatus(t, rec, http.StatusBadRequest)

	// Челленджи: строка есть, code_hash не раскрывается.
	rec = adminReq(t, h, http.MethodGet, "/api/v1/admin/challenges", nil, tok)
	wantStatus(t, rec, http.StatusOK)
	body := rec.Body.String()
	if !strings.Contains(body, user.ID.String()) {
		t.Fatalf("челлендж пользователя отсутствует: %s", body)
	}
	if strings.Contains(body, "code_hash") {
		t.Fatalf("ответ раскрывает code_hash: %s", body)
	}
	for _, row := range jsonBody(t, rec)["challenges"].([]any) {
		m := row.(map[string]any)
		if m["id"] == ch.ID.String() && m["channel"] != "email" {
			t.Fatalf("челлендж %v: канал не email", m)
		}
	}
}

// TestAdminSettingsMaskedAndPut: GET маскирует секреты; PUT с маской/пустым
// значением не меняет секрет; объекты мержатся; неизвестный ключ — 400.
func TestAdminSettingsMaskedAndPut(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	h, _ := newWebRouter(t, st, set, box, nil)
	tok := set.Get().AdminToken

	// Установка реального значения smtp.password для проверки «маска не
	// трогает секрет» (дефолт пуст — неотличим).
	rec := adminReq(t, h, http.MethodPut, "/api/v1/admin/settings",
		map[string]any{"smtp": map[string]any{"password": "real-smtp-secret"}}, tok)
	wantStatus(t, rec, http.StatusOK)
	if set.Get().SMTP.Password != "real-smtp-secret" {
		t.Fatalf("smtp.password = %q после PUT", set.Get().SMTP.Password)
	}

	// GET: секреты замаскированы, реальное значение не встречается в теле.
	rec = adminReq(t, h, http.MethodGet, "/api/v1/admin/settings", nil, tok)
	wantStatus(t, rec, http.StatusOK)
	if strings.Contains(rec.Body.String(), "real-smtp-secret") {
		t.Fatalf("GET settings раскрывает секрет: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), set.Get().AdminToken) {
		t.Fatalf("GET settings раскрывает admin_token: %s", rec.Body.String())
	}
	body := jsonBody(t, rec)
	smtp := body["smtp"].(map[string]any)
	pw := smtp["password"].(map[string]any)
	if pw["value"] != settingsMask || pw["set"] != true {
		t.Fatalf("smtp.password в GET = %v, want маска {set:true,value:••••}", pw)
	}
	adminTok := body["admin_token"].(map[string]any)
	if adminTok["value"] != settingsMask {
		t.Fatalf("admin_token в GET = %v, want маска", adminTok)
	}

	// PUT с маской: секрет не тронут, соседнее поле обновлено.
	rec = adminReq(t, h, http.MethodPut, "/api/v1/admin/settings",
		map[string]any{
			"smtp":        map[string]any{"host": "smtp.test.example", "password": settingsMask},
			"admin_token": settingsMask,
		}, tok)
	wantStatus(t, rec, http.StatusOK)
	if set.Get().SMTP.Password != "real-smtp-secret" {
		t.Fatalf("маска изменила секрет: %q", set.Get().SMTP.Password)
	}
	if set.Get().SMTP.Host != "smtp.test.example" {
		t.Fatalf("smtp.host = %q, want smtp.test.example", set.Get().SMTP.Host)
	}
	oldTok := set.Get().AdminToken

	// PUT меняет группу, deep-merge сохраняет остальные поля.
	rec = adminReq(t, h, http.MethodPut, "/api/v1/admin/settings",
		map[string]any{"totp": map[string]any{"issuer": "changed-issuer"}}, tok)
	wantStatus(t, rec, http.StatusOK)
	if set.Get().TOTP.Issuer != "changed-issuer" {
		t.Fatalf("totp.issuer = %q, want changed-issuer", set.Get().TOTP.Issuer)
	}
	if set.Get().TOTP.Digits == 0 {
		t.Fatal("deep-merge потерял totp.digits")
	}
	// Восстановление затронутых ключей (настройки общие на пакет тестов).
	defer func() {
		if err := set.Put(ctx, "totp", json.RawMessage(`{"issuer":"twofa","digits":6,"period":30,"skew":1}`)); err != nil {
			t.Fatalf("восстановление totp: %v", err)
		}
		if err := set.Put(ctx, "smtp", json.RawMessage(`{"host":"","port":0,"starttls":false,"user":"","password":"","from":"","subject":"","timeout":"0s"}`)); err != nil {
			t.Fatalf("восстановление smtp: %v", err)
		}
	}()

	// PUT с пустым значением = «не менять» (спека §7).
	rec = adminReq(t, h, http.MethodPut, "/api/v1/admin/settings",
		map[string]any{"smtp": map[string]any{"host": ""}}, tok)
	wantStatus(t, rec, http.StatusOK)
	if set.Get().SMTP.Host != "smtp.test.example" {
		t.Fatalf("пустая строка изменила поле: %q", set.Get().SMTP.Host)
	}

	// Неизвестный ключ → 400; admin_token не изменился маской.
	rec = adminReq(t, h, http.MethodPut, "/api/v1/admin/settings",
		map[string]any{"no-such-key": 1}, tok)
	wantStatus(t, rec, http.StatusBadRequest)
	if set.Get().AdminToken != oldTok {
		t.Fatal("admin_token изменился PUT-ом с маской")
	}
}

// TestAdminSettingsRegenerate: только admin_token/radius.secret; новое
// значение возвращается один раз, старый токен отзывается.
func TestAdminSettingsRegenerate(t *testing.T) {
	st, set, box := setup(t)
	h, _ := newWebRouter(t, st, set, box, nil)
	oldTok := set.Get().AdminToken

	// Плохой ключ → 400.
	rec := adminReq(t, h, http.MethodPost, "/api/v1/admin/settings/regenerate",
		map[string]string{"key": "smtp"}, oldTok)
	wantStatus(t, rec, http.StatusBadRequest)

	rec = adminReq(t, h, http.MethodPost, "/api/v1/admin/settings/regenerate",
		map[string]string{"key": "admin_token"}, oldTok)
	wantStatus(t, rec, http.StatusOK)
	body := jsonBody(t, rec)
	newTok, _ := body["value"].(string)
	if newTok == "" || newTok == oldTok {
		t.Fatalf("regenerate: value = %q, want новый токен", newTok)
	}

	// Старый токен отвергнут, новый работает.
	rec = adminReq(t, h, http.MethodGet, "/api/v1/admin/users", nil, oldTok)
	wantStatus(t, rec, http.StatusUnauthorized)
	rec = adminReq(t, h, http.MethodGet, "/api/v1/admin/users", nil, newTok)
	wantStatus(t, rec, http.StatusOK)

	// GET по-прежнему маскирует.
	rec = adminReq(t, h, http.MethodGet, "/api/v1/admin/settings", nil, newTok)
	wantStatus(t, rec, http.StatusOK)
	if strings.Contains(rec.Body.String(), newTok) {
		t.Fatalf("GET settings раскрыл новый токен: %s", rec.Body.String())
	}
}

// TestAdminSettingsPutAtomic: PUT {валидный+неизвестный} → 400 unknown_key,
// причём ВАЛИДНЫЙ ключ не применён ни в снимке, ни в БД (проверка всех
// ключей до записи любого); PUT только с валидными ключами применяется;
// settings_update пишется только для применённого запроса.
func TestAdminSettingsPutAtomic(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	h, _ := newWebRouter(t, st, set, box, nil)
	tok := set.Get().AdminToken
	defer func() {
		if err := set.Put(ctx, "totp", json.RawMessage(`{"issuer":"twofa","digits":6,"period":30,"skew":1}`)); err != nil {
			t.Fatalf("восстановление totp: %v", err)
		}
	}()

	// Один PUT с валидным и неизвестным ключом → 400 unknown_key с именем ключа.
	rec := adminReq(t, h, http.MethodPut, "/api/v1/admin/settings", map[string]any{
		"totp":             map[string]any{"issuer": "atomic-issuer"},
		"totp.bogus.group": 1,
	}, tok)
	wantStatus(t, rec, http.StatusBadRequest)
	body := jsonBody(t, rec)
	if body["error"] != "unknown_key" {
		t.Fatalf("body = %s, want unknown_key", rec.Body.String())
	}
	if body["key"] != "totp.bogus.group" {
		t.Fatalf("body = %s, want key=totp.bogus.group", rec.Body.String())
	}

	// Валидный ключ НЕ применён: ни в снимке, ни в БД.
	if set.Get().TOTP.Issuer == "atomic-issuer" {
		t.Fatal("валидный ключ применён при отклонённом PUT — запись неатомарна")
	}
	var raw json.RawMessage
	if err := st.Pool().QueryRow(ctx, `SELECT value FROM settings WHERE key = 'totp'`).Scan(&raw); err != nil {
		t.Fatalf("select totp: %v", err)
	}
	if strings.Contains(string(raw), "atomic-issuer") {
		t.Fatalf("totp записан в БД при отклонённом PUT: %s", raw)
	}

	// Отклонённый PUT не пишет settings_update с неизвестным ключом.
	rows, err := st.AuditList(ctx, store.AuditFilter{Event: "admin_action", Limit: 200})
	if err != nil {
		t.Fatalf("AuditList: %v", err)
	}
	for _, row := range rows {
		if row.Detail != nil && row.Detail["action"] == "settings_update" {
			if keys, _ := row.Detail["keys"].([]any); keys != nil {
				for _, k := range keys {
					if s, _ := k.(string); s == "totp.bogus.group" {
						t.Fatal("отклонённый PUT попал в аудит settings_update")
					}
				}
			}
		}
	}

	// PUT только с валидным ключом применяется как раньше.
	rec = adminReq(t, h, http.MethodPut, "/api/v1/admin/settings",
		map[string]any{"totp": map[string]any{"issuer": "atomic-issuer"}}, tok)
	wantStatus(t, rec, http.StatusOK)
	if set.Get().TOTP.Issuer != "atomic-issuer" {
		t.Fatalf("totp.issuer = %q после валидного PUT, want atomic-issuer", set.Get().TOTP.Issuer)
	}
	// И аудит settings_update записан с применённым ключом.
	saw := false
	rows, err = st.AuditList(ctx, store.AuditFilter{Event: "admin_action", Limit: 200})
	if err != nil {
		t.Fatalf("AuditList: %v", err)
	}
	for _, row := range rows {
		if row.Detail == nil || row.Detail["action"] != "settings_update" {
			continue
		}
		if keys, _ := row.Detail["keys"].([]any); keys != nil {
			for _, k := range keys {
				if s, _ := k.(string); s == "totp" {
					saw = true
				}
			}
		}
	}
	if !saw {
		t.Fatal("валидный PUT не записал settings_update с ключом totp")
	}
}

// TestAdminMergedValueDBErrors: mergedValue различает «ключа нет в БД»
// (pgx.ErrNoRows — входящее значение пишется как есть) и прочую ошибку БД
// (проглатывалась как «нет значения» — теперь возвращается наверх → 500).
func TestAdminMergedValueDBErrors(t *testing.T) {
	st, set, box := setup(t)
	_ = box
	ctx := context.Background()
	a := NewAdminAPI(st, set, nil)

	// ErrNoRows: строка ключа удалена — текущего значения нет, входное
	// возвращается без мержа.
	if _, err := st.Pool().Exec(ctx, `DELETE FROM settings WHERE key = 'totp'`); err != nil {
		t.Fatalf("удаление ключа totp: %v", err)
	}
	t.Cleanup(func() {
		if err := set.Put(ctx, "totp", json.RawMessage(`{"issuer":"twofa","digits":6,"period":30,"skew":1}`)); err != nil {
			t.Errorf("восстановление totp: %v", err)
		}
	})
	merged, err := a.mergedValue(ctx, "totp", json.RawMessage(`{"issuer":"fresh"}`))
	if err != nil {
		t.Fatalf("mergedValue при отсутствии ключа: %v (хотел «нет значения», не ошибку)", err)
	}
	if string(merged) != `{"issuer":"fresh"}` {
		t.Fatalf("merged = %s, want входное значение как есть", merged)
	}

	// Прочая ошибка БД (закрытый пул) возвращается наверх, а не трактуется
	// как «нет значения».
	dead, err := store.Open(ctx, testDSN)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	dead.Close()
	if _, err := (NewAdminAPI(dead, set, nil)).mergedValue(ctx, "totp", json.RawMessage(`{}`)); err == nil {
		t.Fatal("mergedValue проглотил ошибку БД (закрытый пул)")
	}
}

// TestAdminSettingsSMSGatewayMasked (SEC-004): креды SMS-шлюза не
// раскрываются JSON API (GET /admin/settings), а html-форма с масками
// (MaskedJSONTree) сохраняет креды при отправке без изменений и заменяет
// их при вводе новых.
func TestAdminSettingsSMSGatewayMasked(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	h, _ := newWebRouter(t, st, set, box, nil)
	tok := set.Get().AdminToken

	// Реальный конфиг шлюза с кредами всех типов.
	gw := `{"preset":"smsaero","method":"POST","url":"https://gate.example/send",` +
		`"headers":{"auth_base64":"REAL-BASE64","login":"REAL-LOGIN","api_key":"REAL-KEY","id":"REAL-ID","sender":"N"},` +
		`"success":{"http_status":200}}`
	rec := adminReq(t, h, http.MethodPut, "/api/v1/admin/settings",
		map[string]any{"sms.gateway": json.RawMessage(gw)}, tok)
	wantStatus(t, rec, http.StatusOK)

	// JSON API: ни один кред не встречается в GET-дереве.
	rec = adminReq(t, h, http.MethodGet, "/api/v1/admin/settings", nil, tok)
	wantStatus(t, rec, http.StatusOK)
	for _, secret := range []string{"REAL-BASE64", "REAL-LOGIN", "REAL-KEY", "REAL-ID"} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Fatalf("GET settings раскрывает кред %q: %s", secret, rec.Body.String())
		}
	}

	// PUT с маскированным деревом (как отправила бы html-форма): креды
	// не меняются, соседние поля — меняются.
	masked := settings.MaskedJSONTree(set.Get().SMS)
	rec = adminReq(t, h, http.MethodPut, "/api/v1/admin/settings",
		map[string]any{"sms.gateway": json.RawMessage(masked)}, tok)
	wantStatus(t, rec, http.StatusOK)
	after, err := set.Get().SMSGateway()
	if err != nil {
		t.Fatalf("SMSGateway: %v", err)
	}
	if after.Headers["auth_base64"] != "REAL-BASE64" || after.Headers["login"] != "REAL-LOGIN" ||
		after.Headers["api_key"] != "REAL-KEY" || after.Headers["id"] != "REAL-ID" {
		t.Fatalf("маскированное дерево изменило креды: %v", after.Headers)
	}

	// PUT с новыми кредами: заменяются.
	rec = adminReq(t, h, http.MethodPut, "/api/v1/admin/settings",
		map[string]any{"sms.gateway": map[string]any{"headers": map[string]any{"login": "NEW-LOGIN"}}}, tok)
	wantStatus(t, rec, http.StatusOK)
	after, err = set.Get().SMSGateway()
	if err != nil {
		t.Fatalf("SMSGateway: %v", err)
	}
	if after.Headers["login"] != "NEW-LOGIN" || after.Headers["auth_base64"] != "REAL-BASE64" {
		t.Fatalf("мерж новых кредов: %v", after.Headers)
	}

	// Восстановление дефолта для остальных тестов пакета.
	t.Cleanup(func() {
		_ = set.Put(ctx, "sms.gateway", json.RawMessage(`{}`))
	})
}

// TestAdminAuthFailAudited (SEC-010): неверный Bearer-токен — 401 И запись
// admin_auth_fail в аудит (с ip, без секретов); успешный запрос аудита не
// оставляет.
func TestAdminAuthFailAudited(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	h, _ := newWebRouter(t, st, set, box, nil)
	tok := set.Get().AdminToken

	// База: соседние тесты тоже пишут admin_auth_fail (общий контейнер).
	countFails := func() int {
		t.Helper()
		rows, err := st.AuditList(ctx, store.AuditFilter{Event: "admin_auth_fail"})
		if err != nil {
			t.Fatalf("AuditList: %v", err)
		}
		return len(rows)
	}
	before := countFails()

	rec := adminReq(t, h, http.MethodGet, "/api/v1/admin/users", nil, "wrong-token")
	wantStatus(t, rec, http.StatusUnauthorized)

	deadline := time.Now().Add(3 * time.Second)
	for {
		if n := countFails(); n > before {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("admin_auth_fail не появился в audit_log за 3с")
		}
		time.Sleep(50 * time.Millisecond)
	}
	rows, err := st.AuditList(ctx, store.AuditFilter{Event: "admin_auth_fail"})
	if err != nil || len(rows) == 0 {
		t.Fatalf("admin_auth_fail: rows=%d err=%v", len(rows), err)
	}
	if rows[0].Result != "fail" {
		t.Fatalf("admin_auth_fail.result = %q, want fail", rows[0].Result)
	}

	// Успешный запрос новых записей не оставляет.
	rec = adminReq(t, h, http.MethodGet, "/api/v1/admin/users", nil, tok)
	wantStatus(t, rec, http.StatusOK)
	if n := countFails(); n != before+1 {
		t.Fatalf("admin_auth_fail после успешного запроса: delta=%d (before=%d after=%d), want 1", n-before, before, n)
	}
}
