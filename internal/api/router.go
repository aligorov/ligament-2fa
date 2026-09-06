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

// contentSecurityPolicy — CSP всех HTML-ответов: только собственные
// скрипты/стили (инлайн-обработчики вынесены в app.js/webauthn.js),
// QR-коды — data:-URI (img-src data:).
const contentSecurityPolicy = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'"

// securityHeaders — базовые заголовки безопасности каждого ответа (SEC-011):
// nosniff против MIME-сниффинга, DENY против кликджекинга, no-referrer
// против утечки URL (в них — коды/токены query), CSP против XSS/инъекций.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		next.ServeHTTP(w, r)
	})
}

// NewRouter собирает минимальный роутер (healthz без БД) — для smoke-тестов;
// полная композиция — BuildRouter.
func NewRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/healthz", healthzHandler(nil))
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
	r.Use(securityHeaders)
	r.Get("/healthz", healthzHandler(d.St))

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
