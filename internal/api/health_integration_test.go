//go:build integration

// Интеграционные тесты /healthz: с реальным хранилищем SELECT 1 даёт 200 ok;
// недоступная БД — 503 db_error.
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aligorov/twofa/internal/store"
)

// TestHealthzDB: полная композиция с живым пулом → 200 {"status":"ok"};
// закрытый пул → 503 {"status":"db_error"}.
func TestHealthzDB(t *testing.T) {
	st, set, box := setup(t)
	rt := newPagesRouter(t, st, set, box)

	rec := httptest.NewRecorder()
	rt.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if got, want := strings.TrimSpace(rec.Body.String()), `{"status":"ok"}`; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}

	// Мёртвый пул: SELECT 1 падает → 503 db_error (не 200 и не 500-текст).
	dead, err := store.Open(context.Background(), testDSN)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	dead.Close()
	deadRT := BuildRouter(Deps{St: dead, M: set})
	defer deadRT.Stop()
	rec = httptest.NewRecorder()
	deadRT.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("healthz(мёртвая БД) = %d, want 503 (body %s)", rec.Code, rec.Body.String())
	}
	if got, want := strings.TrimSpace(rec.Body.String()), `{"status":"db_error"}`; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}
