// Package api содержит HTTP-маршруты сервера twofa: JSON REST API
// (публичный, сессии, кабинет, админ) и HTML-обвязку web-интерфейса.
package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/aligorov/twofa/internal/auth"
	"github.com/aligorov/twofa/internal/secrets"
	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
	"github.com/aligorov/twofa/internal/web"
	"github.com/aligorov/twofa/internal/webauthn"
)

// NewRouter собирает минимальный роутер (healthz) — для smoke-тестов;
// полная композиция — BuildRouter.
func NewRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/healthz", handleHealthz)
	return r
}

// Deps — зависимости полной HTTP-композиции; заполняется main (и
// интеграционными тестами).
type Deps struct {
	Core *auth.Core
	WA   *webauthn.Svc // nil — WebAuthn выключен (роуты отвечают 503)
	St   *store.Store
	Box  *secrets.Box
	PV   auth.PasswordVerifier
	M    *settings.M
	Rend *web.Renderer
}

// Router — собранный обработчик со стоп-функциями компонентов.
type Router struct {
	Handler http.Handler
	stops   []func()
}

// Stop освобождает фоновые ресурсы (rate-limiter'ы API); вызывается main
// при graceful shutdown.
func (rt *Router) Stop() {
	for _, stop := range rt.stops {
		stop()
	}
}

// BuildRouter собирает полный HTTP-сервер: /healthz, JSON API /api/v1
// (публичный + сессии + кабинет + админ), HTML-страницы, статика и
// HTML-404. Вызывается из main и интеграционных тестов.
func BuildRouter(d Deps) *Router {
	r := chi.NewRouter()
	r.Get("/healthz", handleHealthz)

	pub := NewPublicAPI(d.Core, d.WA, d.St, d.PV, d.M)
	sess := NewSessionAPI(d.Core, d.St, d.PV, d.M)
	me := NewMeAPI(d.Core, d.WA, d.St, d.Box, d.PV, d.M)
	admin := NewAdminAPI(d.St, d.M)
	pages := NewPagesAPI(d.Rend, sess, admin, d.Core, d.WA, d.St, d.Box, d.PV, d.M)

	pub.Register(r)
	sess.Register(r)
	me.Register(r)
	admin.Register(r)
	pages.Register(r)

	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(web.Static())))
	r.NotFound(pages.NotFound)

	return &Router{Handler: r, stops: []func(){pub.Stop, sess.Stop}}
}
