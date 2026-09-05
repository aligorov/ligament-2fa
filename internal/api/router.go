// Package api содержит HTTP-маршруты сервера twofa.
package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// NewRouter собирает HTTP-маршруты приложения.
func NewRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/healthz", handleHealthz)
	return r
}
