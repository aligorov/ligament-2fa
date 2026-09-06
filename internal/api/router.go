// Package api содержит HTTP-маршруты сервера twofa: JSON REST API
// (публичный, сессии, кабинет, админ) и HTML-обвязку web-интерфейса.
package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/aligorov/twofa/internal/auth"
	"github.com/aligorov/twofa/internal/firewall"
	"github.com/aligorov/twofa/internal/license"
	"github.com/aligorov/twofa/internal/oidc"
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

// contentSecurityPolicyAds — CSP при активной рекламе РСЯ: домены Яндекса
// для загрузчика context.js, рендера блоков и их картинок/фреймов.
const contentSecurityPolicyAds = "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; script-src 'self' https://yandex.st https://an.yandex.ru; frame-src https://an.yandex.ru https://yandex.st; connect-src 'self' https://an.yandex.ru"

// securityHeaders — базовые заголовки безопасности каждого ответа (SEC-011):
// nosniff против MIME-сниффинга, DENY против кликджекинга, no-referrer
// против утечки URL (в них — коды/токены query), CSP против XSS/инъекций.
// securityHeaders — базовые заголовки безопасности каждого ответа (SEC-011).
// adsActive: на запросе активна реклама РСЯ → CSP расширяется доменами
// Яндекса (остальные ответы остаются под строгой политикой).
func securityHeaders(adsActive func(*http.Request) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			csp := contentSecurityPolicy
			if adsActive != nil && adsActive(r) {
				csp = contentSecurityPolicyAds
			}
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("Content-Security-Policy", csp)
			next.ServeHTTP(w, r)
		})
	}
}

// adsFor — решатель показа рекламы: блоки РСЯ видны только на НЕ платной
// лицензии (free/trial) при ads.enabled и заполненных ID блоков.
// Лицензия читается на каждый запрос — загрузка платного файла через
// админку отключает рекламу без рестарта.
func adsFor(lic *license.Manager, m *settings.M) func(*http.Request) web.AdsData {
	return func(r *http.Request) web.AdsData {
		if lic == nil || m == nil {
			return web.AdsData{}
		}
		snap := m.Get()
		if snap == nil || !snap.Ads.Enabled {
			return web.AdsData{}
		}
		st, err := lic.Effective(r.Context())
		if err != nil || st.Mode == license.ModeLicensed {
			return web.AdsData{}
		}
		return web.AdsData{Show: true,
			LoginLeft:  snap.Ads.Blocks.LoginLeft,
			LoginRight: snap.Ads.Blocks.LoginRight,
			Sidebar:    snap.Ads.Blocks.Sidebar}
	}
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
	Lic  *license.Manager // nil — лицензирование не смонтировано
	FW   *firewall.Guard  // nil — файрвол/fail2ban выключен
	Oidc *oidc.Manager    // nil — OIDC не смонтирован (роуты отвечают 503); main всегда инициализирует
}

// firewallMiddleware фильтрует запросы по IP ДО маршрутов и обработчиков:
// чёрный список → 403, активный автобан → 429 (Retry-After); легитимный
// IP кладётся в контекст — auth.Core считает по нему неудачи (fail2ban).
// Белый список проходит без подсчёта (см. guard.Fail).
func firewallMiddleware(g *firewall.Guard) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r)
			switch g.Check(r.Context(), ip) {
			case firewall.Denied:
				writeError(w, http.StatusForbidden, "ip_denied")
				return
			case firewall.Banned:
				w.Header().Set("Retry-After", "300")
				writeError(w, http.StatusTooManyRequests, "ip_banned")
				return
			}
			next.ServeHTTP(w, r.WithContext(firewall.WithIP(r.Context(), ip)))
		})
	}
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
	ads := adsFor(d.Lic, d.M)
	r.Use(securityHeaders(func(r *http.Request) bool {
		a := ads(r)
		return a.Show && (a.LoginLeft != "" || a.LoginRight != "" || a.Sidebar != "")
	}))
	if d.FW != nil {
		r.Use(firewallMiddleware(d.FW))
	}
	r.Get("/healthz", healthzHandler(d.St))

	pub := NewPublicAPI(d.Core, d.WA, d.St, d.PV, d.M)
	sess := NewSessionAPI(d.Core, d.St, d.PV, d.M)
	me := NewMeAPI(d.Core, d.WA, d.St, d.Box, d.PV, d.M)
	admin := NewAdminAPI(d.St, d.M, d.Lic)
	if d.FW != nil {
		admin.SetFirewall(d.FW)
	}
	pages := NewPagesAPI(d.Rend, sess, admin, d.Core, d.WA, d.St, d.Box, d.PV, d.M)
	if d.FW != nil {
		pages.SetFirewall(d.FW)
	}
	pages.SetAds(ads)

	pub.Register(r)
	sess.Register(r)
	me.Register(r)
	admin.Register(r)
	pages.Register(r)
	d.Oidc.Register(r) // nil-безопасно: маршруты остаются, отвечают 503

	registerOpenAPI(r)

	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(web.Static())))
	r.NotFound(pages.NotFound)

	return &Router{Handler: r, stops: []func(){pub.Stop, sess.Stop}}
}
