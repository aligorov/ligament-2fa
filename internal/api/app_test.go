package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/aligorov/twofa/internal/delivery"
	"github.com/aligorov/twofa/internal/store"
)

func TestAppConfigHandler(t *testing.T) {
	api := NewAppAPI(nil, nil, nil, nil, nil, nil)
	r := chi.NewRouter()
	api.Register(r)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/app/config", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("ожидался статус 200, получен %d", rec.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("ошибка разбора JSON: %v", err)
	}

	if resp["server_name"] != "Ligament 2FA" {
		t.Errorf("ожидалось имя сервера Ligament 2FA, получено %v", resp["server_name"])
	}
	if resp["version"] != "1.0.0" {
		t.Errorf("ожидалась версия 1.0.0, получено %v", resp["version"])
	}
}

func TestAppLoginValidation(t *testing.T) {
	api := NewAppAPI(nil, nil, nil, nil, nil, nil)
	r := chi.NewRouter()
	api.Register(r)

	// 1. Невалидный JSON
	reqBadJSON := httptest.NewRequest(http.MethodPost, "/api/v1/app/login", bytes.NewBufferString("{invalid"))
	recBadJSON := httptest.NewRecorder()
	r.ServeHTTP(recBadJSON, reqBadJSON)
	if recBadJSON.Code != http.StatusBadRequest {
		t.Errorf("ожидался 400 на плохой JSON, получен %d", recBadJSON.Code)
	}

	// 2. Пустые логин/пароль
	bodyEmpty, _ := json.Marshal(map[string]string{"username": "", "password": ""})
	reqEmpty := httptest.NewRequest(http.MethodPost, "/api/v1/app/login", bytes.NewReader(bodyEmpty))
	recEmpty := httptest.NewRecorder()
	r.ServeHTTP(recEmpty, reqEmpty)
	if recEmpty.Code != http.StatusBadRequest {
		t.Errorf("ожидался 400 на пустые учетные данные, получен %d", recEmpty.Code)
	}
}

func TestAppAuthMiddlewareMissingToken(t *testing.T) {
	api := NewAppAPI(nil, nil, nil, nil, nil, nil)
	r := chi.NewRouter()
	api.Register(r)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/app/me/profile", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("ожидался 401 при отсутствии токена, получен %d", rec.Code)
	}
}

func TestAppSupportQueueUnauthorized(t *testing.T) {
	api := NewAppAPI(nil, nil, nil, nil, nil, nil)
	r := chi.NewRouter()
	api.Register(r)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/app/support/queue", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("ожидался 401 при отсутствии токена, получен %d", rec.Code)
	}
}

// TestChallengeDecisionRateLimited — decision (перебираемый number_match)
// ограничен теми же корзинами username+IP, что /app/login: burst
// исчерпывается → 429, хендлер не вызывается.
func TestChallengeDecisionRateLimited(t *testing.T) {
	a := NewAppAPI(nil, nil, nil, nil, nil, nil)
	defer a.Stop()

	user := &store.User{Username: "rluser"}
	calls := 0
	h := a.rateLimitByUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
	}))
	req := func() *httptest.ResponseRecorder {
		ctx := context.WithValue(context.Background(), appKeyUser, user)
		r := httptest.NewRequest(http.MethodPost, "/api/v1/app/challenges/00000000-0000-0000-0000-000000000000/decision", nil).WithContext(ctx)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}
	for i := 0; i < rlBurst; i++ {
		if rec := req(); rec.Code == http.StatusTooManyRequests {
			t.Fatalf("запрос %d: неожиданный 429 (body %s)", i+1, rec.Body.String())
		}
	}
	if calls != rlBurst {
		t.Fatalf("хендлер вызван %d раз, want %d", calls, rlBurst)
	}
	if rec := req(); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("после burst: %d (body %s), want 429", rec.Code, rec.Body.String())
	}
	if calls != rlBurst {
		t.Fatalf("хендлер вызван при 429: %d вызовов, want %d", calls, rlBurst)
	}
}

// TestSSENoCORSHeader — аутентифицированный SSE не отдаёт
// Access-Control-Allow-Origin: * (аудит 2026-09-11): поток доставляет
// push-челленджи по Bearer-токену устройства.
func TestSSENoCORSHeader(t *testing.T) {
	hub := delivery.NewAppHub()
	a := NewAppAPI(nil, nil, nil, nil, hub, nil)
	defer a.Stop()

	base := context.WithValue(context.Background(), appKeyUser,
		&store.User{ID: uuid.New(), Username: "sseuser"})
	// Отменяем контекст до вызова: SSE-цикл завершается сразу,
	// заголовки к этому моменту уже выставлены.
	ctx, cancel := context.WithCancel(base)
	cancel()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/app/sse", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	a.handleSSE(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("SSE Access-Control-Allow-Origin = %q, want пусто", got)
	}
	if rec.Header().Get("Content-Type") != "text/event-stream" {
		t.Fatalf("SSE Content-Type = %q, want text/event-stream", rec.Header().Get("Content-Type"))
	}
}
