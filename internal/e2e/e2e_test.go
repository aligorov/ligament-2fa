//go:build integration

// Сквозной (E2E) сценарий сервера twofa: postgres-контейнер (testcontainers)
// + ПОЛНАЯ композиция зависимостей как в cmd/twofa/main.go (store →
// настройки → box → бутстрап админа → каналы доставки → ядро → webauthn →
// роутер api.BuildRouter + RADIUS ServeAuth/ServeAcct на ephemeral-портах).
// HTTP гоняется через настоящий httptest.Server (cookie-jar, реальный TCP),
// RADIUS — клиентом layeh.com/radius. Доставка email и Telegram-push —
// детерминированные фейки (коды/челленджи захватываются тестом).
//
// Сценарий (порядок важен, состояние накапливается):
//
//	a) бутстрап пустой БД → создан ровно один admin;
//	b) админ через REST создаёт user1 (пароль + email);
//	c) /auth/start → email-код → verify (неверный код 401 attempts_left,
//	   верный — 200);
//	d) web-логин user1 (шаг 2 кодом email) → сессия+CSRF → TOTP
//	   enroll/confirm через HTTP (секрет приходит в ответе enroll для QR) →
//	   резервные коды;
//	e) RADIUS пароль+TOTP-код (PAP-сплит) → Access-Accept; неверный код →
//	   Access-Reject;
//	f) push-режим: radius_push + telegram_chat_id, фейк-бот одобряет
//	   челлендж → пароль-only запрос завершается Access-Accept;
//	g) HTML-логин: GET /login 200 → форма с паролем (перерендер «введите
//	   код») → форма с TOTP-кодом → 302 /me → GET /me 200;
//	h) audit_log содержит события всех шагов.
//
// Запуск: make e2e (нужен Docker).
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/hotp"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"

	"github.com/aligorov/twofa/internal/api"
	"github.com/aligorov/twofa/internal/auth"
	"github.com/aligorov/twofa/internal/channel"
	"github.com/aligorov/twofa/internal/delivery"
	"github.com/aligorov/twofa/internal/radiusserver"
	"github.com/aligorov/twofa/internal/secrets"
	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
	"github.com/aligorov/twofa/internal/web"
	"github.com/aligorov/twofa/internal/webauthn"
)

const (
	userName    = "user1"
	userPass    = "hunter2pass"
	userEmail   = "user1@example.com"
	tgChatID    = int64(424242)
	httpTimeout = 10 * time.Second
)

// ---- фейки доставки (паттерн internal/api / internal/radiusserver) ----

// fakeEmail захватывает отправленные email-коды.
type fakeEmail struct {
	mu    sync.Mutex
	codes []string
}

func (f *fakeEmail) Name() channel.Channel { return channel.Email }

func (f *fakeEmail) Send(_ context.Context, _, code string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.codes = append(f.codes, code)
	return nil
}

func (f *fakeEmail) lastCode() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.codes) == 0 {
		return ""
	}
	return f.codes[len(f.codes)-1]
}

// fakePush — PushNotifier-«бот»: не меняет состояние сам, а отдаёт ID
// челленджа горутине-«пользователю», которая нажимает «Подтвердить».
type fakePush struct {
	seen chan uuid.UUID
}

func (p *fakePush) SendPush(_ context.Context, _ int64, _, _, _ string, chID uuid.UUID) error {
	select {
	case p.seen <- chID:
	default:
	}
	return nil
}

func (p *fakePush) SendNotification(_ context.Context, _ int64, _ string) error {
	return nil
}

// ---- HTTP-клиент с cookie-jar (как браузер) ----

type httpClient struct {
	t    *testing.T
	base string
	cl   *http.Client
	csrf string
}

func newHTTPClient(t *testing.T, base string) *httpClient {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	return &httpClient{t: t, base: base, cl: &http.Client{Jar: jar, Timeout: httpTimeout}}
}

// doJSON выполняет JSON-запрос; hdr добавляется к заголовкам (CSRF, bearer).
func (c *httpClient) doJSON(method, path string, body any, hdr map[string]string) (int, map[string]any) {
	c.t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		c.t.Fatalf("marshal %s: %v", path, err)
	}
	req, err := http.NewRequest(method, c.base+path, bytes.NewReader(raw))
	if err != nil {
		c.t.Fatalf("request %s: %v", path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.cl.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	rbody, err := io.ReadAll(resp.Body)
	if err != nil {
		c.t.Fatalf("body %s: %v", path, err)
	}
	var m map[string]any
	if len(rbody) > 0 {
		_ = json.Unmarshal(rbody, &m) // HTML-ответы дают nil — ок
	}
	return resp.StatusCode, m
}

// doForm отправляет HTML-форму (application/x-www-form-urlencoded) БЕЗ
// следования за редиректами: 302 и его Location проверяет тест. Cookie из
// Set-Cookie попадают в jar (клиент применяет их и без следования).
func (c *httpClient) doForm(path string, form url.Values) (int, string, string) {
	c.t.Helper()
	noRedirect := *c.cl
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	req, err := http.NewRequest(http.MethodPost, c.base+path, strings.NewReader(form.Encode()))
	if err != nil {
		c.t.Fatalf("request %s: %v", path, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := noRedirect.Do(req)
	if err != nil {
		c.t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.t.Fatalf("body %s: %v", path, err)
	}
	return resp.StatusCode, resp.Header.Get("Location"), string(body)
}

// doGet выполняет GET (следует редиректам, cookie из jar) и возвращает
// статус и тело.
func (c *httpClient) doGet(path string) (int, string) {
	c.t.Helper()
	req, err := http.NewRequest(http.MethodGet, c.base+path, nil)
	if err != nil {
		c.t.Fatalf("request %s: %v", path, err)
	}
	resp, err := c.cl.Do(req)
	if err != nil {
		c.t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.t.Fatalf("body %s: %v", path, err)
	}
	return resp.StatusCode, string(body)
}

func jsonStr(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

func dockerAvailable() bool {
	return exec.Command("docker", "info").Run() == nil
}

// ---- композиция (как в cmd/twofa/main.go) ----

type env struct {
	st       *store.Store
	m        *settings.M
	box      *secrets.Box
	email    *fakeEmail
	push     *fakePush
	httpSrv  *httptest.Server
	radAddr  string // RADIUS auth-слушатель
	acctAddr string // RADIUS acct-слушатель
}

// bootstrapAdmin — копия main.bootstrapAdmin: первый администратор на
// пустой базе, пароль печатается в лог один раз (тесту не нужен — админ
// работает через admin_token).
func bootstrapAdmin(ctx context.Context, t *testing.T, st *store.Store) {
	t.Helper()
	n, err := st.UserCount(ctx)
	if err != nil {
		t.Fatalf("подсчёт пользователей: %v", err)
	}
	if n != 0 {
		t.Fatalf("база не пуста: %d пользователей", n)
	}
	pwd := secrets.RandomToken(12)
	u := &store.User{
		Username:     "admin",
		Role:         "admin",
		Enabled:      true,
		PasswordHash: secrets.HashPassword(pwd),
	}
	if err := st.UserCreate(ctx, u); err != nil {
		t.Fatalf("создание администратора: %v", err)
	}
	t.Logf("ADMIN PASSWORD: %s", pwd)
}

func startEnv(t *testing.T) *env {
	t.Helper()
	if !dockerAvailable() {
		t.Skip("docker недоступен (docker info завершается с ошибкой) — e2e-тест пропущен")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	pg, err := tcpostgres.RunContainer(ctx,
		testcontainers.WithImage("postgres:16-alpine"),
		tcpostgres.WithDatabase("twofa"),
		tcpostgres.WithUsername("twofa"),
		tcpostgres.WithPassword("twofa"),
		// postgres:*-alpine при initdb печатает ready-сообщение дважды.
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("postgres-контейнер: %v", err)
	}
	t.Cleanup(func() {
		sctx, scancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer scancel()
		_ = pg.Terminate(sctx)
	})
	dsn, err := pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("dsn: %v", err)
	}

	// Композиция зависимостей — по cmd/twofa/main.go.
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("миграции: %v", err)
	}
	m, err := settings.NewManager(ctx, st)
	if err != nil {
		t.Fatalf("настройки: %v", err)
	}
	box, err := secrets.NewBox(m.Get().MasterKeyB64)
	if err != nil {
		t.Fatalf("мастер-ключ: %v", err)
	}

	// Тестовые ускорения: resend_cooldown 1с (несколько email-кодов за
	// сценарий), TOTP-период 5с (replay-счётчики шагают быстро). Остальные
	// значения — продакшн-дефолты (max_fail 5/5м/15м, push_wait 20с...).
	mustPut(t, ctx, m, "policy", `{"code_ttl":"5m","code_length":6,"max_attempts":5,"resend_cooldown":"1s","default_prefer_channels":["totp","telegram","email","sms"],"push_cooldown":"30s","push_per_hour":10,"trusted_device_ttl":"720h","max_fail":5,"fail_window":"5m","ban_time":"15m"}`)
	mustPut(t, ctx, m, "totp", `{"issuer":"twofa-e2e","digits":6,"period":5,"skew":1}`)
	mustPut(t, ctx, m, "webauthn", `{"rp_id":"localhost","rp_name":"twofa-e2e"}`)

	bootstrapAdmin(ctx, t, st)

	email := &fakeEmail{}
	push := &fakePush{seen: make(chan uuid.UUID, 4)}
	pv := auth.NewLocalVerifier(st)
	core := auth.NewCore(st, m, box,
		map[channel.Channel]delivery.Sender{channel.Email: email}, pv, push)

	wa, err := webauthn.New(st, m)
	if err != nil {
		t.Fatalf("webauthn (rp_id=localhost должен работать): %v", err)
	}
	rend, err := web.New()
	if err != nil {
		t.Fatalf("шаблоны: %v", err)
	}
	rt := api.BuildRouter(api.Deps{
		Core: core, WA: wa, St: st, Box: box, PV: pv, M: m, Rend: rend,
	})
	t.Cleanup(rt.Stop)

	// HTTP — настоящий сервер на 127.0.0.1: cookie-jar ведёт себя как браузер.
	httpSrv := httptest.NewServer(rt.Handler)
	t.Cleanup(httpSrv.Close)

	// RADIUS auth+acct на ephemeral-портах.
	radiusSrv := radiusserver.New(core, st, m)
	radCtx, radCancel := context.WithCancel(context.Background())
	t.Cleanup(radCancel)
	lc := net.ListenConfig{}
	authConn, err := lc.ListenPacket(radCtx, "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen radius auth: %v", err)
	}
	acctConn, err := lc.ListenPacket(radCtx, "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen radius acct: %v", err)
	}
	radDone := make(chan error, 2)
	go func() { radDone <- radiusSrv.ServeAuth(radCtx, authConn) }()
	go func() { radDone <- radiusSrv.ServeAcct(radCtx, acctConn) }()
	t.Cleanup(func() {
		radCancel()
		for i := 0; i < 2; i++ {
			select {
			case err := <-radDone:
				if err != nil {
					t.Logf("radius-слушатель: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Error("radius-слушатель не остановился за 10с")
				return
			}
		}
	})

	return &env{
		st: st, m: m, box: box, email: email, push: push,
		httpSrv:  httpSrv,
		radAddr:  authConn.LocalAddr().String(),
		acctAddr: acctConn.LocalAddr().String(),
	}
}

func mustPut(t *testing.T, ctx context.Context, m *settings.M, key, val string) {
	t.Helper()
	if err := m.Put(ctx, key, json.RawMessage(val)); err != nil {
		t.Fatalf("settings.Put(%s): %v", key, err)
	}
}

// wrongCodeFrom детерминированно портит код (первая цифра) — гарантированно
// неверный, но той же длины.
func wrongCodeFrom(code string) string {
	b := []byte(code)
	if b[0] == '9' {
		b[0] = '8'
	} else {
		b[0] = '9'
	}
	return string(b)
}

// totpCodeAt генерирует код по явному счётчику HOTP (эквивалент TOTP на
// границе окна counter*period).
func totpCodeAt(secret string, counter int64) string {
	code, err := hotp.GenerateCode(secret, uint64(counter))
	if err != nil {
		panic(fmt.Sprintf("hotp.GenerateCode: %v", err))
	}
	return code
}

// freshTOTPCode генерирует код по счётчику last_timestep+1: строго больше
// израсходованного (replay-защита) и внутри окна skew сервера. Если окно
// ещё не наступило — ждёт ближайшей границы периода (период сокращён до 5с).
func freshTOTPCode(t *testing.T, ctx context.Context, e *env, username string) string {
	t.Helper()
	u, err := e.st.UserByUsername(ctx, username)
	if err != nil {
		t.Fatalf("пользователь %s: %v", username, err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		enc, _, period, confirmed, last, err := e.st.TOTPGet(ctx, u.ID)
		if err != nil {
			t.Fatalf("TOTPGet: %v", err)
		}
		if !confirmed {
			t.Fatal("TOTP не подтверждён")
		}
		secret, err := e.box.DecryptAAD(auth.AADTOTP(username), enc)
		if err != nil {
			t.Fatalf("расшифровка TOTP-секрета: %v", err)
		}
		cur := time.Now().Unix() / int64(period)
		if need := last + 1; need <= cur+1 {
			return totpCodeAt(string(secret), need)
		}
		if time.Now().After(deadline) {
			t.Fatal("не дождались окна TOTP-счётчика за 30с")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// radiusExchange — Access-Request (PAP) с таймаутом сверх radius.push_wait.
func radiusExchange(t *testing.T, addr string, secret []byte, username, password string) *radius.Packet {
	t.Helper()
	p := radius.New(radius.CodeAccessRequest, secret)
	rfc2865.UserName_SetString(p, username)
	rfc2865.UserPassword_SetString(p, password)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	resp, err := radius.Exchange(ctx, p, addr)
	if err != nil {
		t.Fatalf("radius.Exchange(%s): %v", username, err)
	}
	return resp
}

// ---- сценарий ----

func TestE2EFullScenario(t *testing.T) {
	e := startEnv(t)
	ctx := context.Background()
	admin := map[string]string{"Authorization": "Bearer " + e.m.Get().AdminToken}
	c := newHTTPClient(t, e.httpSrv.URL)
	secret := []byte(e.m.Get().RadiusSecret)

	// Смоук: составной роутер жив.
	t.Run("healthz", func(t *testing.T) {
		status, body := c.doGet("/healthz")
		if status != http.StatusOK || !strings.Contains(body, "ok") {
			t.Fatalf("GET /healthz: %d %q", status, body)
		}
	})

	// a) бутстрап: ровно один пользователь — admin с ролью admin.
	t.Run("bootstrap_admin", func(t *testing.T) {
		n, err := e.st.UserCount(ctx)
		if err != nil {
			t.Fatalf("UserCount: %v", err)
		}
		if n != 1 {
			t.Fatalf("пользователей после бутстрапа: %d, хочу 1", n)
		}
		u, err := e.st.UserByUsername(ctx, "admin")
		if err != nil {
			t.Fatalf("admin: %v", err)
		}
		if u.Role != "admin" || !u.Enabled {
			t.Fatalf("admin: role=%q enabled=%v", u.Role, u.Enabled)
		}
	})

	// b) админ создаёт user1 (пароль + email, prefer totp→email).
	t.Run("admin_creates_user", func(t *testing.T) {
		status, body := c.doJSON(http.MethodPost, "/api/v1/admin/users", map[string]any{
			"username":        userName,
			"password":        userPass,
			"email":           userEmail,
			"prefer_channels": []string{"totp", "email"},
		}, admin)
		if status != http.StatusCreated {
			t.Fatalf("POST /admin/users: %d %v", status, body)
		}
		if jsonStr(body, "username") != userName || jsonStr(body, "role") != "user" {
			t.Fatalf("неожиданный ответ создания: %v", body)
		}
	})

	// c) публичный API: start → код email → verify (неверный, затем верный).
	t.Run("api_start_verify_email", func(t *testing.T) {
		status, body := c.doJSON(http.MethodPost, "/api/v1/auth/start", map[string]any{
			"username": userName, "password": userPass,
		}, nil)
		if status != http.StatusOK {
			t.Fatalf("auth/start: %d %v", status, body)
		}
		if jsonStr(body, "channel") != "email" {
			t.Fatalf("канал = %q, хочу email (TOTP ещё не настроен)", jsonStr(body, "channel"))
		}
		challengeID := jsonStr(body, "challenge_id")
		if challengeID == "" {
			t.Fatalf("пустой challenge_id: %v", body)
		}

		// Неверный код: 401 + attempts_left (декрементирован с 5 до 4).
		code := e.email.lastCode()
		if code == "" {
			t.Fatal("email-код не доставлен фейком")
		}
		status, body = c.doJSON(http.MethodPost, "/api/v1/auth/verify", map[string]any{
			"challenge_id": challengeID, "code": wrongCodeFrom(code),
		}, nil)
		if status != http.StatusUnauthorized {
			t.Fatalf("verify(неверный): %d %v, хочу 401", status, body)
		}
		if left, ok := body["attempts_left"].(float64); !ok || left != 4 {
			t.Fatalf("attempts_left = %v, хочу 4: %v", body["attempts_left"], body)
		}

		// Верный код.
		status, body = c.doJSON(http.MethodPost, "/api/v1/auth/verify", map[string]any{
			"challenge_id": challengeID, "code": code,
		}, nil)
		if status != http.StatusOK || body["ok"] != true {
			t.Fatalf("verify(верный): %d %v", status, body)
		}
	})

	// d) web-логин user1 (код email) → сессия+CSRF → TOTP enroll/confirm.
	t.Run("web_login_totp_enroll", func(t *testing.T) {
		// Шаг 1: пароль → двухфакторка обязательна.
		status, body := c.doJSON(http.MethodPost, "/api/v1/login", map[string]any{
			"username": userName, "password": userPass,
		}, nil)
		if status != http.StatusOK || jsonStr(body, "two_factor") != "required" {
			t.Fatalf("login: %d %v, хочу two_factor=required", status, body)
		}

		// Свежий email-код (cooldown в тесте 1с).
		time.Sleep(1100 * time.Millisecond)
		status, body = c.doJSON(http.MethodPost, "/api/v1/auth/start", map[string]any{
			"username": userName, "password": userPass,
		}, nil)
		if status != http.StatusOK {
			t.Fatalf("auth/start (2): %d %v", status, body)
		}

		// Шаг 2: пароль + код → сессия (cookie в jar) + CSRF в теле.
		status, body = c.doJSON(http.MethodPost, "/api/v1/login/2fa", map[string]any{
			"username": userName, "password": userPass, "code": e.email.lastCode(),
		}, nil)
		if status != http.StatusOK || body["ok"] != true {
			t.Fatalf("login/2fa: %d %v", status, body)
		}
		csrf := jsonStr(body, "csrf")
		if csrf == "" {
			t.Fatalf("пустой csrf: %v", body)
		}
		c.csrf = csrf
		csrfHdr := map[string]string{"X-CSRF-Token": csrf}

		// Enroll: секрет приходит открыто (для QR в web-UI).
		status, body = c.doJSON(http.MethodPost, "/api/v1/me/totp/enroll", map[string]any{}, csrfHdr)
		if status != http.StatusOK {
			t.Fatalf("totp/enroll: %d %v", status, body)
		}
		secret := jsonStr(body, "secret")
		if secret == "" || !strings.Contains(jsonStr(body, "otpauth_url"), "otpauth://") {
			t.Fatalf("enroll не вернул секрет/otpauth_url: %v", body)
		}

		// Confirm кодом, сгенерированным по секрету из ответа enroll
		// (период — из настроек сервера, потому HOTP по явному счётчику).
		period := int64(e.m.Get().TOTP.Period)
		code := totpCodeAt(secret, time.Now().Unix()/period)
		status, body = c.doJSON(http.MethodPost, "/api/v1/me/totp/confirm", map[string]any{
			"code": code,
		}, csrfHdr)
		if status != http.StatusOK {
			t.Fatalf("totp/confirm: %d %v", status, body)
		}
		raw, _ := body["backup_codes"].([]any)
		if len(raw) < 5 {
			t.Fatalf("резервных кодов %d, хочу не меньше 5: %v", len(raw), body)
		}

		// Профиль подтверждает статус.
		status, body = c.doJSON(http.MethodGet, "/api/v1/me", nil, nil)
		if status != http.StatusOK || body["totp_confirmed"] != true {
			t.Fatalf("GET /me: %d %v (totp_confirmed?)", status, body)
		}
	})

	// e) RADIUS: пароль+TOTP-код (PAP-сплит) → Accept; неверный код → Reject.
	t.Run("radius_totp", func(t *testing.T) {
		code := freshTOTPCode(t, ctx, e, userName)
		resp := radiusExchange(t, e.radAddr, secret, userName, userPass+code)
		if resp.Code != radius.CodeAccessAccept {
			t.Fatalf("пароль+верный TOTP: %v, хочу Access-Accept", resp.Code)
		}

		bad := wrongCodeFrom(freshTOTPCode(t, ctx, e, userName))
		resp = radiusExchange(t, e.radAddr, secret, userName, userPass+bad)
		if resp.Code != radius.CodeAccessReject {
			t.Fatalf("пароль+неверный код: %v, хочу Access-Reject", resp.Code)
		}
	})

	// f) push-режим: radius_push + telegram_chat_id, фейк-бот одобряет.
	t.Run("radius_push", func(t *testing.T) {
		// radius_push — через админ-API; chat_id привязывает «бот» напрямую
		// в хранилище (в реальности — код привязки @BotFather-боту).
		status, body := c.doJSON(http.MethodGet, "/api/v1/admin/users", nil, admin)
		if status != http.StatusOK {
			t.Fatalf("GET /admin/users: %d %v", status, body)
		}
		list, _ := body["users"].([]any)
		userID := ""
		for _, it := range list {
			um, _ := it.(map[string]any)
			if jsonStr(um, "username") == userName {
				userID = jsonStr(um, "id")
			}
		}
		if userID == "" {
			t.Fatalf("user1 не найден в /admin/users: %v", body)
		}
		status, body = c.doJSON(http.MethodPatch, "/api/v1/admin/users/"+userID,
			map[string]any{"radius_push": true}, admin)
		if status != http.StatusOK || body["radius_push"] != true {
			t.Fatalf("PATCH radius_push: %d %v", status, body)
		}

		u, err := e.st.UserByUsername(ctx, userName)
		if err != nil {
			t.Fatalf("user1: %v", err)
		}
		chat := tgChatID
		u.TelegramChatID = &chat
		if err := e.st.UserUpdate(ctx, u); err != nil {
			t.Fatalf("привязка telegram_chat_id: %v", err)
		}

		// Горутина-«пользователь»: получила push — через 300мс «Подтвердить».
		approved := make(chan struct{})
		go func() {
			defer close(approved)
			chID := <-e.push.seen
			time.Sleep(300 * time.Millisecond)
			if err := e.st.ChallengeSetPush(context.Background(), chID, "approved"); err != nil {
				t.Errorf("ChallengeSetPush(approved): %v", err)
			}
		}()

		// Пароль БЕЗ кода: сервер удерживает запрос до одобрения (push_wait).
		resp := radiusExchange(t, e.radAddr, secret, userName, userPass)
		select {
		case <-approved:
		case <-time.After(5 * time.Second):
			t.Error("push не дошёл до фейк-бота за 5с")
		}
		if resp.Code != radius.CodeAccessAccept {
			t.Fatalf("push-режим: %v, хочу Access-Accept", resp.Code)
		}
	})

	// g) HTML-форма: GET /login → шаг с паролем → шаг с TOTP-кодом → /me.
	t.Run("web_form_login", func(t *testing.T) {
		form := newHTTPClient(t, e.httpSrv.URL) // чистый «браузер» без сессий

		status, body := form.doGet("/login")
		if status != http.StatusOK || !strings.Contains(body, "<form") {
			t.Fatalf("GET /login: %d (форма?)", status)
		}

		// Шаг 1: только пароль → перерендер «введите код второго фактора».
		code, _, html := form.doForm("/login", url.Values{
			"username": {userName}, "password": {userPass},
		})
		if code != http.StatusOK || !strings.Contains(html, "Введите код второго фактора") {
			t.Fatalf("POST /login (без кода): %d, жду 200 с подсказкой кода", code)
		}

		// Шаг 2: пароль + свежий TOTP → 302 на /me.
		code, location, _ := form.doForm("/login", url.Values{
			"username": {userName}, "password": {userPass},
			"code": {freshTOTPCode(t, ctx, e, userName)},
		})
		if code != http.StatusFound || !strings.HasPrefix(location, "/me") {
			t.Fatalf("POST /login (с кодом): %d Location=%q, хочу 302 на /me", code, location)
		}

		status, meHTML := form.doGet("/me")
		if status != http.StatusOK || !strings.Contains(meHTML, userName) {
			t.Fatalf("GET /me после входа: %d (пользователь на странице?)", status)
		}
	})

	// h) аудит: события всех шагов сценария.
	t.Run("audit_log", func(t *testing.T) {
		rows, err := e.st.AuditList(ctx, store.AuditFilter{Username: userName, Limit: 500})
		if err != nil {
			t.Fatalf("AuditList: %v", err)
		}
		got := map[string]bool{}
		for _, r := range rows {
			got[r.Event] = true
		}
		for _, want := range []string{
			"code_sent",       // c: доставка email-кода
			"api_start",       // c: /auth/start
			"api_verify_fail", // c: неверный код
			"api_verify_ok",   // c: верный код
			"login_ok",        // d+g: web-вход (json и html)
			"totp_enroll",     // d
			"totp_confirm",    // d
			"radius_auth",     // e+f: Accept/Reject/push
			"radius_fail",     // e: неверный код
		} {
			if !got[want] {
				t.Errorf("аудит не содержит событие %q (есть: %v)", want, keysOf(got))
			}
		}
		// Админские действия пишутся как admin_action с detail.action
		// (username NULL — отдельной выборкой по имени события).
		adminRows, err := e.st.AuditList(ctx, store.AuditFilter{Event: "admin_action", Limit: 50})
		if err != nil {
			t.Fatalf("AuditList(admin_action): %v", err)
		}
		actions := map[string]bool{}
		for _, r := range adminRows {
			if a, ok := r.Detail["action"].(string); ok {
				actions[a] = true
			}
		}
		for _, want := range []string{"user_create", "user_update"} {
			if !actions[want] {
				t.Errorf("аудит не содержит admin_action %q (есть: %v)", want, keysOf(actions))
			}
		}
	})
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
