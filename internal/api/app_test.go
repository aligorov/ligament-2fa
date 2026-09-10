package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
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

