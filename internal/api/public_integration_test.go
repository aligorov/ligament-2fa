//go:build integration

// Интеграционные тесты публичного REST API: реальное ядро auth.NewCore на
// postgres-контейнере (testcontainers-go), chi-роутер и httptest-запросы.
// Коды доставки захватываются фейковым Sender (паттерн internal/auth).
// Запуск:
//
//	go test -tags integration ./internal/api/
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/aligorov/twofa/internal/auth"
	"github.com/aligorov/twofa/internal/channel"
	"github.com/aligorov/twofa/internal/delivery"
	"github.com/aligorov/twofa/internal/secrets"
	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
	"github.com/aligorov/twofa/internal/webauthn"
)

const testPassword = "hunter2pass"

// ---- тестовое окружение: один контейнер на пакет ----

var (
	initOnce sync.Once
	testSt   *store.Store
	testSet  *settings.M
	testBox  *secrets.Box
	testDSN  string
	initErr  error
)

func dockerAvailable() bool {
	return exec.Command("docker", "info").Run() == nil
}

// setup лениво поднимает postgres-контейнер, применяет миграции, создаёт
// менеджер настроек (дефолты записываются в БД) и Box на master_key
// (паттерн internal/auth/core_test.go).
func setup(t *testing.T) (*store.Store, *settings.M, *secrets.Box) {
	t.Helper()
	if !dockerAvailable() {
		t.Skip("docker недоступен (docker info завершается с ошибкой) — интеграционный тест пропущен")
	}
	initOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		pg, err := tcpostgres.RunContainer(ctx,
			testcontainers.WithImage("postgres:16-alpine"),
			tcpostgres.WithDatabase("twofa"),
			tcpostgres.WithUsername("twofa"),
			tcpostgres.WithPassword("twofa"),
			// postgres:*-alpine при initdb поднимает временный сервер, печатает
			// ready-сообщение и перезапускается — ждём второе вхождение.
			testcontainers.WithWaitStrategy(
				wait.ForLog("database system is ready to accept connections").
					WithOccurrence(2).
					WithStartupTimeout(60*time.Second),
			),
		)
		if err != nil {
			initErr = err
			return
		}
		dsn, err := pg.ConnectionString(ctx, "sslmode=disable")
		if err != nil {
			initErr = err
			return
		}
		testDSN = dsn
		if testSt, err = store.Open(ctx, dsn); err != nil {
			initErr = err
			return
		}
		if err = testSt.Migrate(ctx); err != nil {
			initErr = err
			return
		}
		if testSet, err = settings.NewManager(ctx, testSt); err != nil {
			initErr = err
			return
		}
		testBox, err = secrets.NewBox(testSet.Get().MasterKeyB64)
		if err != nil {
			initErr = err
			return
		}
	})
	if initErr != nil {
		t.Fatalf("инициализация тестового окружения: %v", initErr)
	}
	return testSt, testSet, testBox
}

// ---- фейки и утилиты ----

// fakeSender — захват кодов вместо реальной доставки (delivery.NewLog
// пишет в slog; тестам нужен детерминированный захват).
type fakeSender struct {
	ch    channel.Channel
	mu    sync.Mutex
	codes []string
}

func (f *fakeSender) Name() channel.Channel { return f.ch }

func (f *fakeSender) Send(_ context.Context, _, code string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.codes = append(f.codes, code)
	return nil
}

func (f *fakeSender) lastCode() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.codes) == 0 {
		return ""
	}
	return f.codes[len(f.codes)-1]
}

func mkUser(t *testing.T, ctx context.Context, st *store.Store, name string, mutate func(*store.User)) *store.User {
	t.Helper()
	u := &store.User{
		Username:     name,
		Role:         "user",
		Enabled:      true,
		PasswordHash: secrets.HashPassword(testPassword),
	}
	if mutate != nil {
		mutate(u)
	}
	if err := st.UserCreate(ctx, u); err != nil {
		t.Fatalf("создать пользователя %s: %v", name, err)
	}
	return u
}

func ptr(s string) *string { return &s }

// newTestRouter собирает PublicAPI на реальном ядре с фейковой доставкой
// email и монтирует в свежий chi-роутер (как это сделает композиция
// сервера). Отправитель возвращается тесту для чтения захваченных кодов.
func newTestRouter(t *testing.T, st *store.Store, set *settings.M, box *secrets.Box, wa *webauthn.Svc) (http.Handler, *fakeSender) {
	t.Helper()
	email := &fakeSender{ch: channel.Email}
	core := auth.NewCore(st, set, box,
		map[channel.Channel]delivery.Sender{channel.Email: email},
		auth.NewLocalVerifier(st), nil)
	p := NewPublicAPI(core, wa, st, auth.NewLocalVerifier(st), set)
	t.Cleanup(p.Stop)
	r := chi.NewRouter()
	p.Register(r)
	return r, email
}

// doReq выполняет JSON-запрос через роутер и возвращает recorder.
func doReq(t *testing.T, h http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal тела запроса: %v", err)
		}
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "integration-test")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// jsonBody разбирает JSON-тело recorder в map.
func jsonBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("разбор тела %q: %v", rec.Body.String(), err)
	}
	return m
}

func wantStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, want, rec.Body.String())
	}
}

// ---- тесты ----

// TestAPIStartVerifyHappyPath: start → 200 {challenge_id,channel,expires_in},
// неверный код → 401 с attempts_left--, верный → 200 {ok,username},
// повторно → 410; аудит api_start/api_verify_*.
func TestAPIStartVerifyHappyPath(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	h, email := newTestRouter(t, st, set, box, nil)

	user := mkUser(t, ctx, st, "apiuser", func(u *store.User) {
		u.Email = "apiuser@example.com"
		u.PreferChannels = []channel.Channel{channel.Email}
	})

	rec := doReq(t, h, http.MethodPost, "/api/v1/auth/start",
		map[string]string{"username": user.Username, "password": testPassword})
	wantStatus(t, rec, http.StatusOK)
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	body := jsonBody(t, rec)
	cid, _ := body["challenge_id"].(string)
	if _, err := uuid.Parse(cid); err != nil {
		t.Fatalf("challenge_id = %q, want UUID", cid)
	}
	if body["channel"] != "email" {
		t.Fatalf("channel = %v, want email", body["channel"])
	}
	if exp, ok := body["expires_in"].(float64); !ok || exp < 290 || exp > 300 {
		t.Fatalf("expires_in = %v, want ~300 (code_ttl)", body["expires_in"])
	}

	// Неверный код: 401 {ok:false, attempts_left:max-1}.
	rec = doReq(t, h, http.MethodPost, "/api/v1/auth/verify",
		map[string]string{"challenge_id": cid, "code": "000000"})
	wantStatus(t, rec, http.StatusUnauthorized)
	body = jsonBody(t, rec)
	if body["ok"] != false {
		t.Fatalf("ok = %v, want false", body["ok"])
	}
	if left, ok := body["attempts_left"].(float64); !ok || int(left) != set.Get().Policy.MaxAttempts-1 {
		t.Fatalf("attempts_left = %v, want %d", body["attempts_left"], set.Get().Policy.MaxAttempts-1)
	}

	// Верный код (захвачен фейк-отправителем): 200 {ok:true,username}.
	rec = doReq(t, h, http.MethodPost, "/api/v1/auth/verify",
		map[string]string{"challenge_id": cid, "code": email.lastCode()})
	wantStatus(t, rec, http.StatusOK)
	body = jsonBody(t, rec)
	if body["ok"] != true || body["username"] != user.Username {
		t.Fatalf("verify ok: body = %v", body)
	}

	// Одноразовость: тот же код снова → 410.
	rec = doReq(t, h, http.MethodPost, "/api/v1/auth/verify",
		map[string]string{"challenge_id": cid, "code": email.lastCode()})
	wantStatus(t, rec, http.StatusGone)

	// Неизвестный challenge_id → 410 (неотличим от удалённого просроченного).
	rec = doReq(t, h, http.MethodPost, "/api/v1/auth/verify",
		map[string]string{"challenge_id": uuid.New().String(), "code": "000000"})
	wantStatus(t, rec, http.StatusGone)

	// Битый uuid → 400.
	rec = doReq(t, h, http.MethodPost, "/api/v1/auth/verify",
		map[string]string{"challenge_id": "not-a-uuid", "code": "000000"})
	wantStatus(t, rec, http.StatusBadRequest)

	// Битый JSON → 400.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/verify", bytes.NewReader([]byte("{nope")))
	req.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	wantStatus(t, rec2, http.StatusBadRequest)

	// Аудит: api_start ok и api_verify_ok записаны.
	for _, event := range []string{"api_start", "api_verify_ok"} {
		rows, err := st.AuditList(ctx, store.AuditFilter{Username: user.Username, Event: event})
		if err != nil || len(rows) == 0 {
			t.Fatalf("аудит %s: rows=%d err=%v", event, len(rows), err)
		}
	}
}

// TestAPIStartBadCredentials: неверный пароль и несуществующий пользователь —
// единый 401 {"error":"bad_credentials"}.
func TestAPIStartBadCredentials(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	h, _ := newTestRouter(t, st, set, box, nil)
	mkUser(t, ctx, st, "apiuser401", nil)

	rec := doReq(t, h, http.MethodPost, "/api/v1/auth/start",
		map[string]string{"username": "apiuser401", "password": "wrong-password"})
	wantStatus(t, rec, http.StatusUnauthorized)
	if jsonBody(t, rec)["error"] != "bad_credentials" {
		t.Fatalf("body = %s, want bad_credentials", rec.Body.String())
	}

	rec = doReq(t, h, http.MethodPost, "/api/v1/auth/start",
		map[string]string{"username": "ghost-user", "password": "whatever"})
	wantStatus(t, rec, http.StatusUnauthorized)
	if jsonBody(t, rec)["error"] != "bad_credentials" {
		t.Fatalf("body = %s, want bad_credentials (анти-перечисление)", rec.Body.String())
	}
}

// TestAPIStartNoChannel: пользователь без привязок → 409 no_channel.
func TestAPIStartNoChannel(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	h, _ := newTestRouter(t, st, set, box, nil)
	mkUser(t, ctx, st, "apibare", nil) // дефолтный prefer: totp/telegram/email/sms — ничего не привязано

	rec := doReq(t, h, http.MethodPost, "/api/v1/auth/start",
		map[string]string{"username": "apibare", "password": testPassword})
	wantStatus(t, rec, http.StatusConflict)
	if jsonBody(t, rec)["error"] != "no_channel" {
		t.Fatalf("body = %s, want no_channel", rec.Body.String())
	}
}

// TestAPIStartCooldown: повторный start в пределах resend_cooldown →
// 429 {"error":"cooldown","retry_after":N} + заголовок Retry-After.
func TestAPIStartCooldown(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	h, _ := newTestRouter(t, st, set, box, nil)
	mkUser(t, ctx, st, "apicool", func(u *store.User) {
		u.Email = "apicool@example.com"
		u.PreferChannels = []channel.Channel{channel.Email}
	})

	rec := doReq(t, h, http.MethodPost, "/api/v1/auth/start",
		map[string]string{"username": "apicool", "password": testPassword})
	wantStatus(t, rec, http.StatusOK)

	rec = doReq(t, h, http.MethodPost, "/api/v1/auth/start",
		map[string]string{"username": "apicool", "password": testPassword})
	wantStatus(t, rec, http.StatusTooManyRequests)
	body := jsonBody(t, rec)
	if body["error"] != "cooldown" {
		t.Fatalf("body = %s, want cooldown", rec.Body.String())
	}
	if ra, ok := body["retry_after"].(float64); !ok || ra < 1 {
		t.Fatalf("retry_after = %v, want >= 1", body["retry_after"])
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("заголовок Retry-After отсутствует")
	}
}

// TestAPIVerifyExhaustsAttempts: исчерпание попыток кода закрывает
// челлендж — верный код после этого даёт 410.
func TestAPIVerifyExhaustsAttempts(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	h, email := newTestRouter(t, st, set, box, nil)
	user := mkUser(t, ctx, st, "apiexhaust", func(u *store.User) {
		u.Email = "apiexhaust@example.com"
		u.PreferChannels = []channel.Channel{channel.Email}
	})

	rec := doReq(t, h, http.MethodPost, "/api/v1/auth/start",
		map[string]string{"username": user.Username, "password": testPassword})
	wantStatus(t, rec, http.StatusOK)
	cid, _ := jsonBody(t, rec)["challenge_id"].(string)

	for i := 0; i < set.Get().Policy.MaxAttempts; i++ {
		rec = doReq(t, h, http.MethodPost, "/api/v1/auth/verify",
			map[string]string{"challenge_id": cid, "code": "000000"})
		wantStatus(t, rec, http.StatusUnauthorized)
	}
	if left, ok := jsonBody(t, rec)["attempts_left"].(float64); !ok || int(left) != 0 {
		t.Fatalf("attempts_left последнего отказа = %v, want 0", jsonBody(t, rec)["attempts_left"])
	}
	// Челлендж закрыт: даже верный код → 410.
	rec = doReq(t, h, http.MethodPost, "/api/v1/auth/verify",
		map[string]string{"challenge_id": cid, "code": email.lastCode()})
	wantStatus(t, rec, http.StatusGone)
}

// TestAPICombined: комбинированный вход «пароль+код» — успех и 401.
func TestAPICombined(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	h, email := newTestRouter(t, st, set, box, nil)
	user := mkUser(t, ctx, st, "apicomb", func(u *store.User) {
		u.Email = "apicomb@example.com"
		u.PreferChannels = []channel.Channel{channel.Email}
	})

	rec := doReq(t, h, http.MethodPost, "/api/v1/auth/start",
		map[string]string{"username": user.Username, "password": testPassword})
	wantStatus(t, rec, http.StatusOK)

	rec = doReq(t, h, http.MethodPost, "/api/v1/auth/combined",
		map[string]string{"username": user.Username, "password": testPassword, "code": "000000"})
	wantStatus(t, rec, http.StatusUnauthorized)

	rec = doReq(t, h, http.MethodPost, "/api/v1/auth/combined",
		map[string]string{"username": user.Username, "password": testPassword, "code": email.lastCode()})
	wantStatus(t, rec, http.StatusOK)
	body := jsonBody(t, rec)
	if body["ok"] != true || body["username"] != user.Username {
		t.Fatalf("combined ok: body = %v", body)
	}
}

// TestAPICombinedLocked: серия неудач (login_fail от ядра) достигает
// max_fail → ErrLocked → 423 у combined и start.
func TestAPICombinedLocked(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	h, _ := newTestRouter(t, st, set, box, nil)
	user := mkUser(t, ctx, st, "apilocked", nil)

	for i := 0; i < set.Get().Policy.MaxFail; i++ {
		rec := doReq(t, h, http.MethodPost, "/api/v1/auth/combined",
			map[string]string{"username": user.Username, "password": "wrong-password", "code": "000000"})
		wantStatus(t, rec, http.StatusUnauthorized)
	}
	rec := doReq(t, h, http.MethodPost, "/api/v1/auth/combined",
		map[string]string{"username": user.Username, "password": testPassword, "code": "000000"})
	wantStatus(t, rec, http.StatusLocked)
	if jsonBody(t, rec)["error"] != "locked" {
		t.Fatalf("body = %s, want locked", rec.Body.String())
	}

	// /start для заблокированного тоже 423 (FailLocked до выдачи кода).
	rec = doReq(t, h, http.MethodPost, "/api/v1/auth/start",
		map[string]string{"username": user.Username, "password": testPassword})
	wantStatus(t, rec, http.StatusLocked)
}

// TestAPIPollStatuses: pending → approved после ChallengeSetPush,
// denied, expired и погашенные состояния.
func TestAPIPollStatuses(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	h, _ := newTestRouter(t, st, set, box, nil)
	user := mkUser(t, ctx, st, "apipoll", nil)
	poll := func(id uuid.UUID) string {
		rec := doReq(t, h, http.MethodPost, "/api/v1/auth/poll",
			map[string]string{"challenge_id": id.String()})
		wantStatus(t, rec, http.StatusOK)
		s, _ := jsonBody(t, rec)["status"].(string)
		return s
	}

	// push: pending → approved (после «Подтвердить» в боте) → approved
	// и после одноразового погашения.
	push := &store.Challenge{
		UserID: user.ID, Channel: channel.TelegramPush,
		PushState: ptr("pending"), ExpiresAt: time.Now().Add(time.Minute), AttemptsLeft: 1,
	}
	if err := st.ChallengeCreate(ctx, push); err != nil {
		t.Fatalf("создать push-челлендж: %v", err)
	}
	if got := poll(push.ID); got != "pending" {
		t.Fatalf("poll(push) = %q, want pending", got)
	}
	if err := st.ChallengeSetPush(ctx, push.ID, "approved"); err != nil {
		t.Fatalf("ChallengeSetPush(approved): %v", err)
	}
	if got := poll(push.ID); got != "approved" {
		t.Fatalf("poll(push approved) = %q, want approved", got)
	}
	if err := st.ChallengeMarkUsed(ctx, push.ID); err != nil {
		t.Fatalf("ChallengeMarkUsed: %v", err)
	}
	if got := poll(push.ID); got != "approved" {
		t.Fatalf("poll(push consumed) = %q, want approved", got)
	}

	// denied.
	push2 := &store.Challenge{
		UserID: user.ID, Channel: channel.TelegramPush,
		PushState: ptr("denied"), ExpiresAt: time.Now().Add(time.Minute), AttemptsLeft: 1,
	}
	if err := st.ChallengeCreate(ctx, push2); err != nil {
		t.Fatalf("создать push2: %v", err)
	}
	if got := poll(push2.ID); got != "denied" {
		t.Fatalf("poll(push denied) = %q, want denied", got)
	}

	// Кодовый челлендж: pending до verify, использованный — «expired».
	code := &store.Challenge{
		UserID: user.ID, Channel: channel.Email,
		CodeHash: secrets.SHA256("111111"), ExpiresAt: time.Now().Add(time.Minute), AttemptsLeft: 3,
	}
	if err := st.ChallengeCreate(ctx, code); err != nil {
		t.Fatalf("создать code-челлендж: %v", err)
	}
	if got := poll(code.ID); got != "pending" {
		t.Fatalf("poll(code) = %q, want pending", got)
	}
	if err := st.ChallengeMarkUsed(ctx, code.ID); err != nil {
		t.Fatalf("ChallengeMarkUsed(code): %v", err)
	}
	if got := poll(code.ID); got != "expired" {
		t.Fatalf("poll(code consumed) = %q, want expired", got)
	}

	// Просроченный создаётся последним: janitor в ChallengeCreate удаляет
	// просроченные ДО вставки — строка живёт до следующего create.
	expired := &store.Challenge{
		UserID: user.ID, Channel: channel.Email,
		CodeHash: secrets.SHA256("222222"), ExpiresAt: time.Now().Add(-time.Second), AttemptsLeft: 3,
	}
	if err := st.ChallengeCreate(ctx, expired); err != nil {
		t.Fatalf("создать просроченный: %v", err)
	}
	if got := poll(expired.ID); got != "expired" {
		t.Fatalf("poll(expired) = %q, want expired", got)
	}

	// Неизвестный UUID — терминальный «expired» (мог быть удалён janitor'ом).
	if got := poll(uuid.New()); got != "expired" {
		t.Fatalf("poll(unknown) = %q, want expired", got)
	}
}

// TestAPIWebauthnBeginFinish: begin — happy path и 401 на плохой пароль,
// 409 без ключей; finish — 400 без handle, 401 с мусорным телом.
func TestAPIWebauthnBeginFinish(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	if err := set.Put(ctx, "webauthn", json.RawMessage(`{"rp_id":"localhost","rp_name":"twofa-test"}`)); err != nil {
		t.Fatalf("settings.Put(webauthn): %v", err)
	}
	wa, err := webauthn.New(st, set)
	if err != nil {
		t.Fatalf("webauthn.New: %v", err)
	}
	h, _ := newTestRouter(t, st, set, box, wa)

	user := mkUser(t, ctx, st, "apiwa", func(u *store.User) {
		u.Email = "apiwa@example.com"
		u.PreferChannels = []channel.Channel{channel.Email}
	})
	// Наличие ключа достаточно для BeginLogin (сама церемония — E2E T15).
	if err := st.WACredUpsert(ctx, user.ID, &store.WACred{
		CredentialID:    []byte("test-credential-id"),
		RPID:            "localhost",
		PublicKey:       []byte("public-key-blob"),
		AttestationType: "none",
		Present:         true,
		Verified:        true,
	}); err != nil {
		t.Fatalf("WACredUpsert: %v", err)
	}

	// Плохой пароль → 401.
	rec := doReq(t, h, http.MethodPost, "/api/v1/auth/webauthn/begin",
		map[string]string{"username": user.Username, "password": "wrong"})
	wantStatus(t, rec, http.StatusUnauthorized)

	// Happy path: 200 {handle, options} с PublicKeyCredentialRequestOptions.
	rec = doReq(t, h, http.MethodPost, "/api/v1/auth/webauthn/begin",
		map[string]string{"username": user.Username, "password": testPassword})
	wantStatus(t, rec, http.StatusOK)
	body := jsonBody(t, rec)
	handle, _ := body["handle"].(string)
	if handle == "" {
		t.Fatalf("handle пуст: %s", rec.Body.String())
	}
	opts, ok := body["options"].(map[string]any)
	if !ok {
		t.Fatalf("options не объект: %s", rec.Body.String())
	}
	// go-webauthn сериализует CredentialAssertion как {"publicKey": {...}}.
	pk, ok := opts["publicKey"].(map[string]any)
	if !ok {
		t.Fatalf("options.publicKey не объект: %v", opts)
	}
	if pk["challenge"] == nil || pk["rpId"] != "localhost" {
		t.Fatalf("options.publicKey некорректен: %v", pk)
	}

	// Finish без handle → 400.
	rec = doReq(t, h, http.MethodPost, "/api/v1/auth/webauthn/finish",
		map[string]any{"id": "x", "type": "public-key"})
	wantStatus(t, rec, http.StatusBadRequest)
	if jsonBody(t, rec)["error"] != "handle_required" {
		t.Fatalf("body = %s, want handle_required", rec.Body.String())
	}

	// Finish с неизвестным handle → 401.
	rec = doReq(t, h, http.MethodPost, "/api/v1/auth/webauthn/finish?handle=no-such-handle",
		map[string]any{"id": "x", "rawId": "eA", "type": "public-key", "response": map[string]any{}})
	wantStatus(t, rec, http.StatusUnauthorized)

	// Finish с настоящим handle, но мусорным ответом аутентификатора:
	// сессия погашается, go-webauthn отклоняет ответ → 401.
	rec = doReq(t, h, http.MethodPost, "/api/v1/auth/webauthn/finish?handle="+handle,
		map[string]any{"id": "x", "rawId": "eA", "type": "public-key", "response": map[string]any{}})
	wantStatus(t, rec, http.StatusUnauthorized)

	// Handle можно передать и полем JSON-тела (query пуст).
	rec = doReq(t, h, http.MethodPost, "/api/v1/auth/webauthn/finish",
		map[string]any{"handle": "json-handle", "id": "x", "type": "public-key"})
	wantStatus(t, rec, http.StatusUnauthorized)

	// Пользователь без ключей → 409.
	bare := mkUser(t, ctx, st, "apiwanokey", nil)
	rec = doReq(t, h, http.MethodPost, "/api/v1/auth/webauthn/begin",
		map[string]string{"username": bare.Username, "password": testPassword})
	wantStatus(t, rec, http.StatusConflict)
	if jsonBody(t, rec)["error"] != "no_credentials" {
		t.Fatalf("body = %s, want no_credentials", rec.Body.String())
	}
}

// TestAPIStartCountsLoginFail: неверный пароль на /auth/start пишет И
// login_fail (раньше — только api_start, единый fail-счётчик не считал эти
// попытки); достигнув policy.max_fail, /auth/start отвечает 423 даже с
// верным паролем.
func TestAPIStartCountsLoginFail(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	h, _ := newTestRouter(t, st, set, box, nil)
	user := mkUser(t, ctx, st, "startfail", nil)

	// Неверный пароль → 401 и login_fail в аудите.
	rec := doReq(t, h, http.MethodPost, "/api/v1/auth/start",
		map[string]string{"username": user.Username, "password": "wrong-password"})
	wantStatus(t, rec, http.StatusUnauthorized)
	rows, err := st.AuditList(ctx, store.AuditFilter{Username: user.Username, Event: "login_fail"})
	if err != nil || len(rows) != 1 {
		t.Fatalf("login_fail после start(неверный пароль): rows=%d err=%v, want 1", len(rows), err)
	}

	// Добиваем счётчик до порога прямым аудитом и проверяем 423.
	for i := 1; i < set.Get().Policy.MaxFail; i++ {
		if err := st.Audit(ctx, user.Username, "login_fail", nil, "10.9.9.9", "fail"); err != nil {
			t.Fatalf("seed login_fail: %v", err)
		}
	}
	rec = doReq(t, h, http.MethodPost, "/api/v1/auth/start",
		map[string]string{"username": user.Username, "password": testPassword})
	wantStatus(t, rec, http.StatusLocked)
	if jsonBody(t, rec)["error"] != "locked" {
		t.Fatalf("body = %s, want locked", rec.Body.String())
	}
}

// TestAPIWABeginCountsLoginFail: неверный пароль на /auth/webauthn/begin
// пишет login_fail (путь раньше был тихим) и кормит fail-счётчик — после
// порога begin отвечает 423.
func TestAPIWABeginCountsLoginFail(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	if err := set.Put(ctx, "webauthn", json.RawMessage(`{"rp_id":"localhost","rp_name":"twofa-test"}`)); err != nil {
		t.Fatalf("settings.Put(webauthn): %v", err)
	}
	wa, err := webauthn.New(st, set)
	if err != nil {
		t.Fatalf("webauthn.New: %v", err)
	}
	h, _ := newTestRouter(t, st, set, box, wa)
	user := mkUser(t, ctx, st, "wabeginfail", nil)

	// Неверный пароль → 401 и login_fail в аудите.
	rec := doReq(t, h, http.MethodPost, "/api/v1/auth/webauthn/begin",
		map[string]string{"username": user.Username, "password": "wrong-password"})
	wantStatus(t, rec, http.StatusUnauthorized)
	rows, err := st.AuditList(ctx, store.AuditFilter{Username: user.Username, Event: "login_fail"})
	if err != nil || len(rows) != 1 {
		t.Fatalf("login_fail после webauthn/begin(неверный пароль): rows=%d err=%v, want 1", len(rows), err)
	}

	for i := 1; i < set.Get().Policy.MaxFail; i++ {
		if err := st.Audit(ctx, user.Username, "login_fail", nil, "10.9.9.9", "fail"); err != nil {
			t.Fatalf("seed login_fail: %v", err)
		}
	}
	rec = doReq(t, h, http.MethodPost, "/api/v1/auth/webauthn/begin",
		map[string]string{"username": user.Username, "password": testPassword})
	wantStatus(t, rec, http.StatusLocked)
}

// TestAPIRateLimit429OnBurst: 6-й start подряд по тому же username+IP →
// 429 rate_limited с Retry-After; корзины username и IP независимы.
func TestAPIRateLimit429OnBurst(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	h, _ := newTestRouter(t, st, set, box, nil)
	mkUser(t, ctx, st, "apiflood", nil)

	start := func(username string) *httptest.ResponseRecorder {
		return doReq(t, h, http.MethodPost, "/api/v1/auth/start",
			map[string]string{"username": username, "password": "wrong"})
	}

	// Первые burst (5) — 401 (пароль неверен), 6-й — 429 rate_limited.
	for i := 0; i < rlBurst; i++ {
		wantStatus(t, start("apiflood"), http.StatusUnauthorized)
	}
	rec := start("apiflood")
	wantStatus(t, rec, http.StatusTooManyRequests)
	if jsonBody(t, rec)["error"] != "rate_limited" {
		t.Fatalf("body = %s, want rate_limited", rec.Body.String())
	}
	if ra := rec.Header().Get("Retry-After"); ra == "" {
		t.Fatal("заголовок Retry-After отсутствует")
	}

	// Корзина имени исчерпана: смена IP не помогает.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/start",
		bytes.NewReader([]byte(`{"username":"apiflood","password":"wrong"}`)))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.7:5555"
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	wantStatus(t, rec2, http.StatusTooManyRequests)

	// Корзина IP тоже исчерпана: другое имя с того же IP → 429.
	wantStatus(t, start("apiflood-other"), http.StatusTooManyRequests)
}

// TestAPIWebauthnFinishNoPendingOnFail: неудачный finish НЕ создаёт
// «webauthn_web_pending»-окно — оно появляется только после успешной
// проверки подписи passkey (сама подпись — E2E T15; создание окна
// напрямую проверяет TestWebLogin2FAPasskeyWindow через тот же помощник).
func TestAPIWebauthnFinishNoPendingOnFail(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	if err := set.Put(ctx, "webauthn", json.RawMessage(`{"rp_id":"localhost","rp_name":"twofa-test"}`)); err != nil {
		t.Fatalf("settings.Put(webauthn): %v", err)
	}
	wa, err := webauthn.New(st, set)
	if err != nil {
		t.Fatalf("webauthn.New: %v", err)
	}
	h, _ := newTestRouter(t, st, set, box, wa)

	user := mkUser(t, ctx, st, "apiwanopend", func(u *store.User) {
		u.Email = "apiwanopend@example.com"
	})
	if err := st.WACredUpsert(ctx, user.ID, &store.WACred{
		CredentialID:    []byte("nopend-credential-id"),
		RPID:            "localhost",
		PublicKey:       []byte("public-key-blob"),
		AttestationType: "none",
		Present:         true,
		Verified:        true,
	}); err != nil {
		t.Fatalf("WACredUpsert: %v", err)
	}

	// Begin → настоящий handle; finish с мусорным телом → 401.
	rec := doReq(t, h, http.MethodPost, "/api/v1/auth/webauthn/begin",
		map[string]string{"username": user.Username, "password": testPassword})
	wantStatus(t, rec, http.StatusOK)
	handle, _ := jsonBody(t, rec)["handle"].(string)
	if handle == "" {
		t.Fatalf("handle пуст: %s", rec.Body.String())
	}
	rec = doReq(t, h, http.MethodPost, "/api/v1/auth/webauthn/finish?handle="+handle,
		map[string]any{"id": "x", "rawId": "eA", "type": "public-key", "response": map[string]any{}})
	wantStatus(t, rec, http.StatusUnauthorized)

	// Окно web-логина не создано: пустой код login/2fa не пройдёт.
	var n int
	if err := st.Pool().QueryRow(ctx, `
		SELECT count(*) FROM challenges
		WHERE user_id = $1 AND purpose = 'webauthn_web_pending'`,
		user.ID).Scan(&n); err != nil {
		t.Fatalf("подсчёт pending-окон: %v", err)
	}
	if n != 0 {
		t.Fatalf("после неудачного finish pending-окон = %d, want 0", n)
	}
}
