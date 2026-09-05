//go:build integration

// Интеграционные тесты web-сессий: вход без второго фактора, два шага с
// TOTP, доверенные устройства, CSRF, смена пароля. Харнесс — общий с
// public_integration_test.go (postgres testcontainer + фейковый Sender).
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/aligorov/twofa/internal/auth"
	"github.com/aligorov/twofa/internal/channel"
	"github.com/aligorov/twofa/internal/delivery"
	"github.com/aligorov/twofa/internal/secrets"
	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
	"github.com/aligorov/twofa/internal/webauthn"
)

// newWebRouter собирает полную композицию API веба (публичный + сессии +
// кабинет + админ) на реальном ядре с фейковой доставкой email.
func newWebRouter(t *testing.T, st *store.Store, set *settings.M, box *secrets.Box, wa *webauthn.Svc) (http.Handler, *fakeSender) {
	t.Helper()
	email := &fakeSender{ch: channel.Email}
	core := auth.NewCore(st, set, box,
		map[channel.Channel]delivery.Sender{channel.Email: email},
		auth.NewLocalVerifier(st), nil)
	pv := auth.NewLocalVerifier(st)
	pub := NewPublicAPI(core, wa, st, pv, set)
	t.Cleanup(pub.Stop)
	sess := NewSessionAPI(core, st, pv, set)
	t.Cleanup(sess.Stop)
	me := NewMeAPI(core, wa, st, box, pv, set)
	admin := NewAdminAPI(st, set)
	r := chi.NewRouter()
	pub.Register(r)
	sess.Register(r)
	me.Register(r)
	admin.Register(r)
	return r, email
}

// webClient — «браузер» теста: держит cookie twofa_session/twofa_device и
// CSRF-токен, подставляя их в каждый запрос.
type webClient struct {
	t         *testing.T
	h         http.Handler
	session   *http.Cookie
	device    *http.Cookie
	csrf      string
	sendCSRF  bool // false — не подставлять заголовок (проверка 403)
	userAgent string
}

func newWebClient(t *testing.T, h http.Handler) *webClient {
	return &webClient{t: t, h: h, sendCSRF: true, userAgent: "integration-test"}
}

// do выполняет JSON-запрос с cookie/CSRF клиента и подхватывает Set-Cookie.
func (c *webClient) do(method, path string, body any) *httptest.ResponseRecorder {
	c.t.Helper()
	rec := doReqUA(c.t, c.h, method, path, body, c.userAgent, c.cookies(), c.headers())
	for _, ck := range rec.Result().Cookies() {
		switch ck.Name {
		case cookieSession:
			c.session = pickCookie(c.t, ck, c.session)
		case cookieDevice:
			c.device = pickCookie(c.t, ck, c.device)
		}
	}
	return rec
}

func (c *webClient) cookies() []*http.Cookie {
	var out []*http.Cookie
	if c.session != nil {
		out = append(out, c.session)
	}
	if c.device != nil {
		out = append(out, c.device)
	}
	return out
}

func (c *webClient) headers() map[string]string {
	if !c.sendCSRF || c.csrf == "" {
		return nil
	}
	return map[string]string{csrfHeader: c.csrf}
}

// pickCookie обновляет cookie из Set-Cookie; MaxAge<0 — удаление (nil).
func pickCookie(t *testing.T, got, _ *http.Cookie) *http.Cookie {
	t.Helper()
	if got.MaxAge < 0 {
		return nil
	}
	return got
}

// adoptCSRF забирает CSRF-токен из тела ответа (login, login/2fa, /me).
func (c *webClient) adoptCSRF(rec *httptest.ResponseRecorder) {
	c.t.Helper()
	body := jsonBody(c.t, rec)
	csrf, _ := body["csrf"].(string)
	if csrf == "" {
		c.t.Fatalf("csrf пуст в ответе: %s", rec.Body.String())
	}
	c.csrf = csrf
}

func (c *webClient) login(username, password string, remember bool) *httptest.ResponseRecorder {
	return c.do(http.MethodPost, "/api/v1/login",
		map[string]any{"username": username, "password": password, "remember_device": remember})
}

func (c *webClient) login2FA(username, password, code string, remember bool) *httptest.ResponseRecorder {
	return c.do(http.MethodPost, "/api/v1/login/2fa",
		map[string]any{"username": username, "password": password, "code": code, "remember_device": remember})
}

// doReqUA — doReq с User-Agent, cookie и заголовками.
func doReqUA(t *testing.T, h http.Handler, method, path string, body any, ua string, cookies []*http.Cookie, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var raw []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal тела запроса: %v", err)
		}
		raw = b
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// adminReq — запрос с Bearer-токеном админа.
func adminReq(t *testing.T, h http.Handler, method, path string, body any, token string) *httptest.ResponseRecorder {
	t.Helper()
	headers := map[string]string{}
	if token != "" {
		headers["Authorization"] = "Bearer " + token
	}
	return doReqUA(t, h, method, path, body, "integration-test", nil, headers)
}

// enrollTOTP — прямой доступ (без UI): сгенерировать секрет, зашифровать,
// сохранить и подтвердить; возвращает ключ для генерации кодов.
func enrollTOTP(t *testing.T, ctx context.Context, st *store.Store, set *settings.M, box *secrets.Box, u *store.User) *otp.Key {
	t.Helper()
	k, err := totp.Generate(totp.GenerateOpts{Issuer: set.Get().TOTP.Issuer, AccountName: u.Username})
	if err != nil {
		t.Fatalf("totp.Generate: %v", err)
	}
	enc := box.EncryptAAD(auth.AADTOTP(u.Username), []byte(k.Secret()))
	if err := st.TOTPSave(ctx, u.ID, enc, set.Get().TOTP.Digits, set.Get().TOTP.Period); err != nil {
		t.Fatalf("TOTPSave: %v", err)
	}
	if err := st.TOTPConfirm(ctx, u.ID); err != nil {
		t.Fatalf("TOTPConfirm: %v", err)
	}
	return k
}

// ---- тесты ----

// TestWebLoginNo2FA: пользователь без второго фактора получает сессию сразу;
// неверный пароль → 401; профиль читается по cookie; logout завершает сессию.
func TestWebLoginNo2FA(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	h, _ := newWebRouter(t, st, set, box, nil)
	user := mkUser(t, ctx, st, "webbare", nil)
	c := newWebClient(t, h)

	// Неверный пароль → единый 401.
	rec := c.login(user.Username, "wrong-password", false)
	wantStatus(t, rec, http.StatusUnauthorized)
	if jsonBody(t, rec)["error"] != "bad_credentials" {
		t.Fatalf("body = %s, want bad_credentials", rec.Body.String())
	}

	// Верный пароль → сессия сразу, без второго шага.
	rec = c.login(user.Username, testPassword, false)
	wantStatus(t, rec, http.StatusOK)
	body := jsonBody(t, rec)
	if body["ok"] != true {
		t.Fatalf("login: body = %v", body)
	}
	if _, has := body["two_factor"]; has {
		t.Fatalf("второй шаг не должен требоваться: %v", body)
	}
	if c.session == nil {
		t.Fatal("cookie twofa_session не установлен")
	}
	c.adoptCSRF(rec)

	// Профиль по сессии.
	rec = c.do(http.MethodGet, "/api/v1/me", nil)
	wantStatus(t, rec, http.StatusOK)
	if jsonBody(t, rec)["username"] != user.Username {
		t.Fatalf("профиль: %s", rec.Body.String())
	}

	// Logout (POST требует CSRF) → сессия удалена.
	rec = c.do(http.MethodPost, "/api/v1/logout", nil)
	wantStatus(t, rec, http.StatusOK)
	rec = c.do(http.MethodGet, "/api/v1/me", nil)
	wantStatus(t, rec, http.StatusUnauthorized)
}

// TestWebLoginTwoStepTOTP: подтверждённый TOTP → первый шаг отвечает
// two_factor:required с методом totp; неверный код → 401; верный → сессия
// + доверенное устройство (remember_device); повторный вход с cookie
// twofa_device — сессия без второго фактора.
func TestWebLoginTwoStepTOTP(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	h, _ := newWebRouter(t, st, set, box, nil)
	user := mkUser(t, ctx, st, "webtotp", nil)
	key := enrollTOTP(t, ctx, st, set, box, user)
	c := newWebClient(t, h)

	rec := c.login(user.Username, testPassword, false)
	wantStatus(t, rec, http.StatusOK)
	body := jsonBody(t, rec)
	if body["two_factor"] != "required" {
		t.Fatalf("login: body = %v, want two_factor required", body)
	}
	if !hasStr(body["methods"], "totp") {
		t.Fatalf("methods = %v, want содержит totp", body["methods"])
	}
	if c.session != nil {
		t.Fatal("сессия-кандидат не должна создаваться на первом шаге")
	}

	// Неверный код → 401 bad_code (пароль не проверяется — код дешевле).
	rec = c.login2FA(user.Username, testPassword, "000000", false)
	wantStatus(t, rec, http.StatusUnauthorized)
	if jsonBody(t, rec)["error"] != "bad_code" {
		t.Fatalf("body = %s, want bad_code", rec.Body.String())
	}

	// Верные пароль+код + remember_device.
	code, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("totp.GenerateCode: %v", err)
	}
	rec = c.login2FA(user.Username, testPassword, code, true)
	wantStatus(t, rec, http.StatusOK)
	body = jsonBody(t, rec)
	if body["ok"] != true || body["username"] != user.Username {
		t.Fatalf("login/2fa: body = %v", body)
	}
	if c.session == nil || c.device == nil {
		t.Fatalf("cookie сессии/устройства не установлены: session=%v device=%v", c.session, c.device)
	}
	c.adoptCSRF(rec)

	// TOTP-код одноразовый (replay-защита ядра): тот же код снова → 401.
	fresh := newWebClient(t, h)
	rec = fresh.login2FA(user.Username, testPassword, code, false)
	wantStatus(t, rec, http.StatusUnauthorized)
	if jsonBody(t, rec)["error"] != "bad_code" {
		t.Fatalf("replay: body = %s, want bad_code", rec.Body.String())
	}

	// Доверенное устройство: вход по паролю без второго фактора.
	fast := newWebClient(t, h)
	fast.device = c.device
	rec = fast.login(user.Username, testPassword, false)
	wantStatus(t, rec, http.StatusOK)
	body = jsonBody(t, rec)
	if body["ok"] != true {
		t.Fatalf("trusted-device login: body = %v", body)
	}
	if _, has := body["two_factor"]; has {
		t.Fatalf("доверенное устройство не должно требовать 2FA: %v", body)
	}
}

// TestWebCSRF: мутирующий запрос без X-CSRF-Token → 403; с заголовком → 200;
// GET без заголовка проходит.
func TestWebCSRF(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	h, _ := newWebRouter(t, st, set, box, nil)
	user := mkUser(t, ctx, st, "webcsrf", nil)
	c := newWebClient(t, h)
	rec := c.login(user.Username, testPassword, false)
	wantStatus(t, rec, http.StatusOK)
	c.adoptCSRF(rec)

	c.sendCSRF = false
	rec = c.do(http.MethodPost, "/api/v1/me/totp/enroll", map[string]string{})
	wantStatus(t, rec, http.StatusForbidden)
	if jsonBody(t, rec)["error"] != "csrf" {
		t.Fatalf("body = %s, want csrf", rec.Body.String())
	}

	c.sendCSRF = true
	rec = c.do(http.MethodPost, "/api/v1/me/totp/enroll", map[string]string{})
	wantStatus(t, rec, http.StatusOK)

	// GET CSRF-заголовка не требует.
	c.sendCSRF = false
	rec = c.do(http.MethodGet, "/api/v1/me", nil)
	wantStatus(t, rec, http.StatusOK)
}

// TestWebPasswordChange: неверный старый пароль → 401; верный → все сессии и
// устройства отозваны, вход — только с новым паролем.
func TestWebPasswordChange(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	h, _ := newWebRouter(t, st, set, box, nil)
	user := mkUser(t, ctx, st, "webpwd", nil)
	c := newWebClient(t, h)
	rec := c.login(user.Username, testPassword, false)
	wantStatus(t, rec, http.StatusOK)
	c.adoptCSRF(rec)

	rec = c.do(http.MethodPatch, "/api/v1/me/password",
		map[string]string{"old": "wrong-password", "new": "new-pass-123"})
	wantStatus(t, rec, http.StatusUnauthorized)

	rec = c.do(http.MethodPatch, "/api/v1/me/password",
		map[string]string{"old": testPassword, "new": "new-pass-123"})
	wantStatus(t, rec, http.StatusOK)

	// Текущая сессия отозвана.
	rec = c.do(http.MethodGet, "/api/v1/me", nil)
	wantStatus(t, rec, http.StatusUnauthorized)

	// Старый пароль больше не работает, новый — да.
	c2 := newWebClient(t, h)
	rec = c2.login(user.Username, testPassword, false)
	wantStatus(t, rec, http.StatusUnauthorized)
	rec = c2.login(user.Username, "new-pass-123", false)
	wantStatus(t, rec, http.StatusOK)

	// Пароль в БД действительно сменён (argon2-хеш проверяется входом выше).
	fresh, err := st.UserByUsername(ctx, user.Username)
	if err != nil || !secrets.VerifyPassword(fresh.PasswordHash, "new-pass-123") {
		t.Fatalf("пароль в БД не сменён: %v", err)
	}
}

// hasStr проверяет вхождение строки в []any (JSON-массив из тела ответа).
func hasStr(v any, want string) bool {
	list, ok := v.([]any)
	if !ok {
		return false
	}
	for _, item := range list {
		if s, ok := item.(string); ok && s == want {
			return true
		}
	}
	return false
}
