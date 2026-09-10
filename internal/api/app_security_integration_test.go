//go:build integration

// Интеграционные тесты ужесточений безопасности app/admin API (аудит
// раунд-2, Фаза 2a): rate-limit и fail-блокировка app-логина, TTL и отзыв
// device-токенов, защищённые ключи PUT /settings, перешифровка TOTP при
// переименовании, ownership support-сессий.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"

	"github.com/aligorov/twofa/internal/auth"
	"github.com/aligorov/twofa/internal/secrets"
	"github.com/aligorov/twofa/internal/store"
)

// appLogin выполняет POST /api/v1/app/login и возвращает recorder.
func appLogin(t *testing.T, h http.Handler, username, password string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"username": username, "password": password, "platform": "test",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/app/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// appBearer выполняет запрос с Bearer-токеном устройства.
func appBearer(t *testing.T, h http.Handler, method, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestAppLoginRateLimit: 6-я попытка входа с неверным паролем в минуту —
// 429 (корзины username+IP, как у web-входа).
func TestAppLoginRateLimit(t *testing.T) {
	st, set, box := setup(t)
	_ = st
	ctx := context.Background()
	user := mkUser(t, ctx, st, "apprl", nil)
	rt := newPagesRouter(t, st, set, box)
	t.Cleanup(rt.Stop)

	for i := 1; i <= 5; i++ {
		rec := appLogin(t, rt.Handler, user.Username, "wrong-password")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("попытка %d: status = %d, want 401 (body %s)", i, rec.Code, rec.Body.String())
		}
	}
	rec := appLogin(t, rt.Handler, user.Username, "wrong-password")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("6-я попытка: status = %d, want 429 (body %s)", rec.Code, rec.Body.String())
	}
	if jsonBody(t, rec)["error"] != "rate_limited" {
		t.Fatalf("6-я попытка: body = %s", rec.Body.String())
	}
}

// TestAppDeviceTokenTTL: истёкший device-токен → 401; при использовании в
// окне продления (<30 дней до истечения) expires продлевается скользяще.
func TestAppDeviceTokenTTL(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	user := mkUser(t, ctx, st, "appttl", nil)
	rt := newPagesRouter(t, st, set, box)
	t.Cleanup(rt.Stop)

	rec := appLogin(t, rt.Handler, user.Username, testPassword)
	wantStatus(t, rec, http.StatusOK)
	tok, _ := jsonBody(t, rec)["token"].(string)
	if tok == "" {
		t.Fatalf("login без токена: %s", rec.Body.String())
	}

	// Живой токен работает.
	wantStatus(t, appBearer(t, rt.Handler, http.MethodGet, "/api/v1/app/me/profile", tok), http.StatusOK)

	// Истёкший — нет (даже активный).
	if _, err := st.Pool().Exec(ctx,
		`UPDATE app_devices SET expires_at = now() - interval '1 hour' WHERE user_id = $1`, user.ID); err != nil {
		t.Fatalf("backdate expires_at: %v", err)
	}
	rec = appBearer(t, rt.Handler, http.MethodGet, "/api/v1/app/me/profile", tok)
	wantStatus(t, rec, http.StatusUnauthorized)
	if jsonBody(t, rec)["error"] != "invalid_token" {
		t.Fatalf("истёкший токен: body = %s", rec.Body.String())
	}

	// Продление: до истечения 10 дней (< окна 30) — запрос продлевает
	// до ~90 дней (лениво, без записи при свежем токене).
	rec = appLogin(t, rt.Handler, user.Username, testPassword)
	wantStatus(t, rec, http.StatusOK)
	tok2, _ := jsonBody(t, rec)["token"].(string)
	if _, err := st.Pool().Exec(ctx,
		`UPDATE app_devices SET expires_at = now() + interval '10 days' WHERE user_id = $1 AND token_hash = $2`,
		user.ID, secrets.SHA256(tok2)); err != nil {
		t.Fatalf("выставить expires +10d: %v", err)
	}
	wantStatus(t, appBearer(t, rt.Handler, http.MethodGet, "/api/v1/app/me/profile", tok2), http.StatusOK)
	var expires time.Time
	if err := st.Pool().QueryRow(ctx,
		`SELECT expires_at FROM app_devices WHERE user_id = $1 AND token_hash = $2`,
		user.ID, secrets.SHA256(tok2)).Scan(&expires); err != nil {
		t.Fatalf("чтение expires_at: %v", err)
	}
	if left := time.Until(expires); left < 80*24*time.Hour {
		t.Fatalf("после касания до истечения %v, want >= 80 дней (продление не сработало)", left)
	}
}

// TestAppTokenQueryNonStream: ?token= работает только для WS/SSE; обычный
// JSON-запрос с токеном в query — 401 (токены не должны оседать в логах).
func TestAppTokenQueryNonStream(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	user := mkUser(t, ctx, st, "appquery", nil)
	rt := newPagesRouter(t, st, set, box)
	t.Cleanup(rt.Stop)

	rec := appLogin(t, rt.Handler, user.Username, testPassword)
	wantStatus(t, rec, http.StatusOK)
	tok, _ := jsonBody(t, rec)["token"].(string)

	// Обычный JSON: только заголовок.
	rec = appBearer(t, rt.Handler, http.MethodGet, "/api/v1/app/me/profile?token="+tok, "")
	wantStatus(t, rec, http.StatusUnauthorized)

	// Тот же URL с Upgrade-заголовком (WS) — токен из query легален.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/app/me/profile?token="+tok, nil)
	req.Header.Set("Upgrade", "websocket")
	reqrr := httptest.NewRecorder()
	rt.Handler.ServeHTTP(reqrr, req)
	wantStatus(t, reqrr, http.StatusOK)
}

// TestPasswordChangeRevokesAppDevices: смена пароля отзывает и app-устройства
// (раньше device-токен переживал смену пароля — перманентный approve-доступ).
func TestPasswordChangeRevokesAppDevices(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	user := mkUser(t, ctx, st, "apppwd", nil)
	rt := newPagesRouter(t, st, set, box)
	t.Cleanup(rt.Stop)

	rec := appLogin(t, rt.Handler, user.Username, testPassword)
	wantStatus(t, rec, http.StatusOK)
	tok, _ := jsonBody(t, rec)["token"].(string)
	wantStatus(t, appBearer(t, rt.Handler, http.MethodGet, "/api/v1/app/me/profile", tok), http.StatusOK)

	// Смена пароля через кабинет (сессия + CSRF).
	c := loginSession(t, rt.Handler, user.Username)
	rec = c.do(http.MethodPatch, "/api/v1/me/password",
		map[string]string{"old": testPassword, "new": "NewPassword#42"})
	wantStatus(t, rec, http.StatusOK)

	rec = appBearer(t, rt.Handler, http.MethodGet, "/api/v1/app/me/profile", tok)
	wantStatus(t, rec, http.StatusUnauthorized)
}

// TestAdminRevokeDevicesCoversAppDevices: DELETE /admin/users/{id}/devices
// отзывает не только доверенные web-устройства, но и app-устройства.
func TestAdminRevokeDevicesCoversAppDevices(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	user := mkUser(t, ctx, st, "apprevoke", nil)
	rt := newPagesRouter(t, st, set, box)
	t.Cleanup(rt.Stop)

	rec := appLogin(t, rt.Handler, user.Username, testPassword)
	wantStatus(t, rec, http.StatusOK)
	tok, _ := jsonBody(t, rec)["token"].(string)
	wantStatus(t, appBearer(t, rt.Handler, http.MethodGet, "/api/v1/app/me/profile", tok), http.StatusOK)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/users/"+user.ID.String()+"/devices", nil)
	req.Header.Set("Authorization", "Bearer "+set.Get().AdminToken)
	reqrr := httptest.NewRecorder()
	rt.Handler.ServeHTTP(reqrr, req)
	wantStatus(t, reqrr, http.StatusOK)

	wantStatus(t, appBearer(t, rt.Handler, http.MethodGet, "/api/v1/app/me/profile", tok), http.StatusUnauthorized)
}

// TestAdminSettingsPutProtectedIntegration: реальное значение master_key —
// 400 protected_key; маска «••••» = «не менять» (round-trip GET→PUT жив),
// ключ не меняется.
func TestAdminSettingsPutProtectedIntegration(t *testing.T) {
	st, set, box := setup(t)
	rt := newPagesRouter(t, st, set, box)
	t.Cleanup(rt.Stop)
	before := set.Get().MasterKeyB64

	put := func(body map[string]any) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings", bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer "+set.Get().AdminToken)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		rt.Handler.ServeHTTP(rec, req)
		return rec
	}

	rec := put(map[string]any{"master_key": "attacker-controlled"})
	wantStatus(t, rec, http.StatusBadRequest)
	if jsonBody(t, rec)["error"] != "protected_key" {
		t.Fatalf("PUT master_key: body = %s", rec.Body.String())
	}

	rec = put(map[string]any{"master_key": "••••"})
	wantStatus(t, rec, http.StatusOK)
	if after := set.Get().MasterKeyB64; after != before {
		t.Fatal("master_key изменился через PUT с маской")
	}
}

// TestAdminRenameReencryptsTOTP: переименование перешифровывает ОБА секрета;
// TOTP работает под новым именем (код проходит ядро), подтверждённость
// сохраняется. Битый секрет — 400 totp_reset_required, имя не меняется.
func TestAdminRenameReencryptsTOTP(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	rt := newPagesRouter(t, st, set, box)
	t.Cleanup(rt.Stop)

	// Пользователь с подтверждённым TOTP.
	user := mkUser(t, ctx, st, "apptorename", nil)
	secret := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	if err := st.TOTPSave(ctx, user.ID, box.EncryptAAD(auth.AADTOTP(user.Username), []byte(secret)), 6, 30); err != nil {
		t.Fatalf("TOTPSave: %v", err)
	}
	if err := st.TOTPConfirm(ctx, user.ID); err != nil {
		t.Fatalf("TOTPConfirm: %v", err)
	}

	// Переименование через admin PATCH.
	newName := "apptorename2"
	body, _ := json.Marshal(map[string]any{"username": newName})
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/admin/users/"+user.ID.String(), bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+set.Get().AdminToken)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	rt.Handler.ServeHTTP(rec, req)
	wantStatus(t, rec, http.StatusOK)

	// Секрет читается под НОВЫМ AAD и тем же открытым значением;
	// подтверждённость не сброшена.
	enc, _, _, confirmed, _, err := st.TOTPGet(ctx, user.ID)
	if err != nil {
		t.Fatalf("TOTPGet после rename: %v", err)
	}
	dec, err := box.DecryptAAD(auth.AADTOTP(newName), enc)
	if err != nil {
		t.Fatalf("расшифровка под новым AAD: %v", err)
	}
	if string(dec) != secret || !confirmed {
		t.Fatalf("секрет после rename: %q confirmed=%v, want исходный/true", dec, confirmed)
	}

	// «Вход работает»: код из секрета проходит ядро под новым именем.
	if _, err := st.UserByUsername(ctx, newName); err != nil {
		t.Fatalf("UserByUsername(%s): %v", newName, err)
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("totp.GenerateCode: %v", err)
	}
	rt2 := newPagesRouter(t, st, set, box)
	t.Cleanup(rt2.Stop)
	c := newWebClient(t, rt2.Handler)
	rec = c.login2FA(newName, testPassword, code, false)
	wantStatus(t, rec, http.StatusOK)

	// Битый TOTP-шифротекст: rename → 400 totp_reset_required, имя НЕ меняется.
	user2 := mkUser(t, ctx, st, "appbadtotp", nil)
	if err := st.TOTPSave(ctx, user2.ID, []byte("not-a-valid-ciphertext"), 6, 30); err != nil {
		t.Fatalf("TOTPSave(битый): %v", err)
	}
	body2, _ := json.Marshal(map[string]any{"username": "appbadtotp2"})
	req2 := httptest.NewRequest(http.MethodPatch, "/api/v1/admin/users/"+user2.ID.String(), bytes.NewReader(body2))
	req2.Header.Set("Authorization", "Bearer "+set.Get().AdminToken)
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	rt.Handler.ServeHTTP(rec2, req2)
	wantStatus(t, rec2, http.StatusBadRequest)
	if jsonBody(t, rec2)["error"] != "totp_reset_required" {
		t.Fatalf("rename с битым TOTP: body = %s", rec2.Body.String())
	}
	if _, err := st.UserByUsername(ctx, "appbadtotp2"); err == nil {
		t.Fatal("имя изменилось несмотря на ошибку перешифровки TOTP")
	}

	// Rename на ЗАНЯТОЕ имя: 409 ДО перешифровки — TOTP жертвы и
	// переименуемого остаются рабочими под своими (старыми) AAD
	// (ревью-фикс: детерминированная порча TOTP при позднем 23505).
	user4 := mkUser(t, ctx, st, "apprenametaken", nil)
	secret4 := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	if err := st.TOTPSave(ctx, user4.ID, box.EncryptAAD(auth.AADTOTP(user4.Username), []byte(secret4)), 6, 30); err != nil {
		t.Fatalf("TOTPSave(user4): %v", err)
	}
	if err := st.TOTPConfirm(ctx, user4.ID); err != nil {
		t.Fatalf("TOTPConfirm(user4): %v", err)
	}
	body4, _ := json.Marshal(map[string]any{"username": "apptorename2"}) // занято первым кейсом
	req4 := httptest.NewRequest(http.MethodPatch, "/api/v1/admin/users/"+user4.ID.String(), bytes.NewReader(body4))
	req4.Header.Set("Authorization", "Bearer "+set.Get().AdminToken)
	req4.Header.Set("Content-Type", "application/json")
	rec4 := httptest.NewRecorder()
	rt.Handler.ServeHTTP(rec4, req4)
	wantStatus(t, rec4, http.StatusConflict)
	if jsonBody(t, rec4)["error"] != "username_taken" {
		t.Fatalf("rename на занятое имя: body = %s", rec4.Body.String())
	}
	if _, err := st.UserByUsername(ctx, "apprenametaken"); err != nil {
		t.Fatalf("имя изменилось при 409: %v", err)
	}
	// TOTP переименуемого по-прежнему расшифровывается под СТАРЫМ AAD.
	enc4, _, _, confirmed4, _, err := st.TOTPGet(ctx, user4.ID)
	if err != nil {
		t.Fatalf("TOTPGet(user4) после 409: %v", err)
	}
	dec4, err := box.DecryptAAD(auth.AADTOTP("apprenametaken"), enc4)
	if err != nil {
		t.Fatalf("расшифровка под старым AAD после 409: %v", err)
	}
	if string(dec4) != secret4 || !confirmed4 {
		t.Fatalf("TOTP после 409: %q confirmed=%v, want исходный/true", dec4, confirmed4)
	}

	// Битый password_enc: rename → 400 password_enc_undecryptable (диагностика
	// вместо тихой порчи PEAP), имя не меняется.
	user3 := mkUser(t, ctx, st, "appbadenc", nil)
	user3.PasswordEnc = []byte("not-a-valid-ciphertext")
	if err := st.UserUpdate(ctx, user3); err != nil {
		t.Fatalf("UserUpdate(битый password_enc): %v", err)
	}
	body3, _ := json.Marshal(map[string]any{"username": "appbadenc2"})
	req3 := httptest.NewRequest(http.MethodPatch, "/api/v1/admin/users/"+user3.ID.String(), bytes.NewReader(body3))
	req3.Header.Set("Authorization", "Bearer "+set.Get().AdminToken)
	req3.Header.Set("Content-Type", "application/json")
	rec3 := httptest.NewRecorder()
	rt.Handler.ServeHTTP(rec3, req3)
	wantStatus(t, rec3, http.StatusBadRequest)
	if jsonBody(t, rec3)["error"] != "password_enc_undecryptable" {
		t.Fatalf("rename с битым password_enc: body = %s", rec3.Body.String())
	}
	if _, err := st.UserByUsername(ctx, "appbadenc2"); err == nil {
		t.Fatal("имя изменилось несмотря на ошибку перешифровки password_enc")
	}
}

// TestSupportSignalEndOwnership: signal/end чужой сессии — 403 (раньше —
// IDOR: любой device-токен мог слать сигналы/чат/обрыв в ЛЮБУЮ сессию).
func TestSupportSignalEndOwnership(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	rt := newPagesRouter(t, st, set, box)
	t.Cleanup(rt.Stop)

	owner := mkUser(t, ctx, st, "ssowner", nil)
	stranger := mkUser(t, ctx, st, "ssstranger", nil)

	rec := appLogin(t, rt.Handler, owner.Username, testPassword)
	wantStatus(t, rec, http.StatusOK)
	ownerTok, _ := jsonBody(t, rec)["token"].(string)
	ownerDevID, _ := jsonBody(t, rec)["device_id"].(string)

	rec = appLogin(t, rt.Handler, stranger.Username, testPassword)
	wantStatus(t, rec, http.StatusOK)
	strangerTok, _ := jsonBody(t, rec)["token"].(string)

	// Сессия владельца (как будто SOS отправлен).
	ss := &store.SupportSession{
		UserID:         owner.ID,
		DeviceID:       uuidMustParse(t, ownerDevID),
		Category:       "it",
		Status:         "requested",
		ProblemSummary: "не работает принтер",
		AccessMode:     "view_only",
	}
	if err := st.SupportSessionCreate(ctx, ss); err != nil {
		t.Fatalf("SupportSessionCreate: %v", err)
	}

	// Чужой сигнал → 403; чужой end → 403.
	sig, _ := json.Marshal(map[string]any{"type": "sdp", "sdp": "v=0"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/app/support/"+ss.ID.String()+"/signal", bytes.NewReader(sig))
	req.Header.Set("Authorization", "Bearer "+strangerTok)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	rt.Handler.ServeHTTP(rec, req)
	wantStatus(t, rec, http.StatusForbidden)

	req = httptest.NewRequest(http.MethodPost, "/api/v1/app/support/"+ss.ID.String()+"/end", nil)
	req.Header.Set("Authorization", "Bearer "+strangerTok)
	rec = httptest.NewRecorder()
	rt.Handler.ServeHTTP(rec, req)
	wantStatus(t, rec, http.StatusForbidden)

	// Сессия не тронута чужаком.
	got, err := st.SupportSessionGet(ctx, ss.ID)
	if err != nil || got.Status != "requested" {
		t.Fatalf("сессия после чужих запросов: status=%s err=%v, want requested nil", got.Status, err)
	}

	// Владелец завершает свою сессию.
	req = httptest.NewRequest(http.MethodPost, "/api/v1/app/support/"+ss.ID.String()+"/end", nil)
	req.Header.Set("Authorization", "Bearer "+ownerTok)
	rec = httptest.NewRecorder()
	rt.Handler.ServeHTTP(rec, req)
	wantStatus(t, rec, http.StatusOK)
	got, err = st.SupportSessionGet(ctx, ss.ID)
	if err != nil || got.Status != "completed" {
		t.Fatalf("после end владельца: status=%s err=%v, want completed nil", got.Status, err)
	}
}

// TestSupportDecisionRequiresOperator: approve без назначенного оператора —
// 409 (раньше requested→active без connect).
func TestSupportDecisionRequiresOperator(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	rt := newPagesRouter(t, st, set, box)
	t.Cleanup(rt.Stop)

	user := mkUser(t, ctx, st, "ssdecide", nil)
	rec := appLogin(t, rt.Handler, user.Username, testPassword)
	wantStatus(t, rec, http.StatusOK)
	tok, _ := jsonBody(t, rec)["token"].(string)
	devID, _ := jsonBody(t, rec)["device_id"].(string)

	ss := &store.SupportSession{
		UserID: user.ID, DeviceID: uuidMustParse(t, devID),
		Category: "it", Status: "requested", ProblemSummary: "нет интернета",
	}
	if err := st.SupportSessionCreate(ctx, ss); err != nil {
		t.Fatalf("SupportSessionCreate: %v", err)
	}

	body, _ := json.Marshal(map[string]string{"decision": "approve"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/app/support/"+ss.ID.String()+"/decision", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	rt.Handler.ServeHTTP(rec, req)
	wantStatus(t, rec, http.StatusConflict)
}

// uuidMustParse парсит UUID или роняет тест.
func uuidMustParse(t *testing.T, s string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(s)
	if err != nil {
		t.Fatalf("uuid %q: %v", s, err)
	}
	return id
}
