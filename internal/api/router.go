// Package api содержит HTTP-маршруты сервера twofa: JSON REST API
// (публичный, сессии, кабинет, админ) и HTML-обвязку web-интерфейса.
package api

import (
	"encoding/json"
	"math/rand"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/aligorov/twofa/internal/acme"
	"github.com/aligorov/twofa/internal/auth"
	"github.com/aligorov/twofa/internal/delivery"
	"github.com/aligorov/twofa/internal/firewall"
	"github.com/aligorov/twofa/internal/license"
	"github.com/aligorov/twofa/internal/oidc"
	"github.com/aligorov/twofa/internal/radiusserver"
	"github.com/aligorov/twofa/internal/secrets"
	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
	"github.com/aligorov/twofa/internal/web"
	"github.com/aligorov/twofa/internal/webauthn"
)

// securityHeaders — базовые заголовки безопасности каждого ответа (SEC-011):
// nosniff против MIME-сниффинга, DENY против кликджекинга, no-referrer
// против утечки URL (в них — коды/токены query), CSP против XSS/инъекций.
// CSP — всегда СТРОГАЯ базовая (web.ContentSecurityPolicy): relaxed-политику
// с доменами Яндекса ставит точечно рендер страницы с активными рекламными
// слотами (web.RenderHTML) — админка и страницы без слотов не расширяются.
func securityHeaders() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("Content-Security-Policy", web.ContentSecurityPolicy)
			next.ServeHTTP(w, r)
		})
	}
}

// brandFor — белый лейбл: кастомный бренд доступен в ЛЮБОМ платном
// статусе — демо (trial), подписка, бессрочная; только НЕ free.
func brandFor(lic *license.Manager, m *settings.M) func(*http.Request) web.BrandData {
	return func(r *http.Request) web.BrandData {
		if lic == nil || m == nil {
			return web.BrandData{}
		}
		snap := m.Get()
		if snap == nil {
			return web.BrandData{}
		}
		st, err := lic.Effective(r.Context())
		if err != nil || st.Mode == license.ModeFree {
			return web.BrandData{}
		}
		return web.BrandData{
			Name:        snap.Branding.Name,
			Mark:        snap.Branding.Mark,
			Logo:        snap.Branding.Logo,
			Description: snap.Branding.Description,
		}
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
		directURL := snap.Ads.Direct.URL
		if pool := snap.Ads.Direct.URLs; len(pool) > 0 {
			directURL = pool[rand.Intn(len(pool))] // ротация на каждую отрисовку
		}
		return web.AdsData{Show: true, Provider: snap.Ads.Provider,
			LoginLeft:   snap.Ads.Blocks.LoginLeft,
			LoginRight:  snap.Ads.Blocks.LoginRight,
			Sidebar:     snap.Ads.Blocks.Sidebar,
			DirectURL:   directURL,
			DirectLabel: snap.Ads.Direct.Label,
			DirectImage: snap.Ads.Direct.Image}
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
	Core            *auth.Core
	WA              *webauthn.Svc // nil — WebAuthn выключен (роуты отвечают 503)
	St              *store.Store
	Box             *secrets.Box
	PV              auth.PasswordVerifier
	M               *settings.M
	Rend            *web.Renderer
	Lic             *license.Manager          // nil — лицензирование не смонтировано
	FW              *firewall.Guard           // nil — файрвол/fail2ban выключен
	Oidc            *oidc.Manager             // nil — OIDC не смонтирован (роуты отвечают 503); main всегда инициализирует
	ACME            *acme.Manager             // nil — ACME выключен
	Radius          *radiusserver.Server      // nil — RADIUS не смонтирован
	AppHub          *delivery.AppHub          // nil — push в мобильные/десктопные приложения отключен
	SupportNotifier *delivery.SupportNotifier // nil — оповещения техподдержки
}

// retryAfterSeconds — значение заголовка Retry-After при 429 автобана:
// реальный остаток бана до banned_until (целые секунды с округлением вверх,
// минимум 1), а не константа.
func retryAfterSeconds(until, now time.Time) int {
	d := until.Sub(now)
	if d <= 0 {
		return 1
	}
	s := int(d / time.Second)
	if d%time.Second != 0 {
		s++
	}
	if s < 1 {
		s = 1
	}
	return s
}

// firewallMiddleware фильтрует запросы по IP ДО маршрутов и обработчиков:
// чёрный список → 403, активный автобан → 429 (Retry-After — остаток бана);
// легитимный IP кладётся в контекст — auth.Core считает по нему неудачи
// (fail2ban). Белый список проходит без подсчёта (см. guard.Fail).
func firewallMiddleware(g *firewall.Guard) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := g.RealIP(r) // реальный IP: RemoteAddr или XFF за доверенным прокси
			verdict, bannedUntil := g.CheckUntil(r.Context(), ip)
			switch verdict {
			case firewall.Denied:
				writeError(w, http.StatusForbidden, "ip_denied")
				return
			case firewall.Banned:
				w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(bannedUntil, time.Now())))
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
	r.Use(securityHeaders())
	if d.FW != nil {
		r.Use(firewallMiddleware(d.FW))
	}
	r.Get("/healthz", healthzHandler(d.St))

	if d.ACME != nil {
		r.Get("/.well-known/acme-challenge/{token}", func(w http.ResponseWriter, r *http.Request) {
			d.ACME.HTTPHandler(nil).ServeHTTP(w, r)
		})
		r.Get("/.well-known/acme-challenge/*", func(w http.ResponseWriter, r *http.Request) {
			d.ACME.HTTPHandler(nil).ServeHTTP(w, r)
		})
	}
	r.Get("/ca.crt", caCertDownloadHandler(d.Radius, d.M))
	r.Get("/api/v1/public/ca.crt", caCertDownloadHandler(d.Radius, d.M))

	pub := NewPublicAPI(d.Core, d.WA, d.St, d.PV, d.M)
	sess := NewSessionAPI(d.Core, d.St, d.PV, d.M)
	if d.FW != nil {
		// Неудачные web-логины (JSON/HTML) и логины публичного API кормят
		// fail2ban наравне с RADIUS (аудит раунд-2, N3: эти пути писали
		// аудит в обход core.audit — мимо guard).
		pub.SetFirewall(d.FW)
		sess.SetFirewall(d.FW)
	}
	me := NewMeAPI(d.Core, d.WA, d.St, d.Box, d.PV, d.M)
	admin := NewAdminAPI(d.St, d.M, d.Lic)
	if d.FW != nil {
		admin.SetFirewall(d.FW)
		// Неудачные проверки admin-токена кормят fail2ban
		// (аудит раунд-2, N7: онлайн-брут статического секрета).
		admin.SetFail2ban(d.FW)
	}
	if d.Radius != nil {
		admin.SetRadius(d.Radius)
	}
	if d.ACME != nil {
		admin.SetACME(d.ACME)
	}
	pages := NewPagesAPI(d.Rend, sess, admin, d.Core, d.WA, d.St, d.Box, d.PV, d.M)
	if d.FW != nil {
		pages.SetFirewall(d.FW)
	}
	pages.SetAds(ads)
	pages.SetBrand(brandFor(d.Lic, d.M))

	if d.Oidc != nil {
		d.Oidc.SetAds(ads)
		d.Oidc.SetBrand(brandFor(d.Lic, d.M))
	}

	pub.Register(r)
	sess.Register(r)
	me.Register(r)
	admin.Register(r)
	pages.Register(r)
	d.Oidc.Register(r) // nil-безопасно: маршруты остаются, отвечают 503

	appAPI := NewAppAPI(d.Core, d.St, d.PV, d.M, d.AppHub, d.Oidc)
	if d.FW != nil {
		// Неудачные app-логины кормят fail2ban наравне с web-входом
		// (аудит раунд-2: app-путь был невидим guard'у).
		appAPI.SetFirewall(d.FW)
	}
	if d.AppHub != nil {
		admin.SetAppHub(d.AppHub)
	}
	if d.SupportNotifier != nil {
		admin.SetSupportNotifier(d.SupportNotifier)
		appAPI.SetSupportNotifier(d.SupportNotifier)
	}
	appAPI.Register(r)

	registerOpenAPI(r)

	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(web.Static())))
	r.NotFound(pages.NotFound)

	return &Router{Handler: r, stops: []func(){pub.Stop, sess.Stop, admin.Stop, appAPI.Stop}}
}

func caCertDownloadHandler(radius *radiusserver.Server, m *settings.M) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var pemBytes []byte
		if radius != nil {
			pemBytes = radius.CurrentEAPCertPEM()
		}
		if len(pemBytes) == 0 && m != nil {
			if raw := m.Get().Radius.EAPCert; len(raw) > 0 {
				var pair struct {
					CertPEM string `json:"cert_pem"`
				}
				if json.Unmarshal(raw, &pair) == nil && pair.CertPEM != "" {
					pemBytes = []byte(pair.CertPEM)
				}
			}
		}
		if len(pemBytes) == 0 {
			writeError(w, http.StatusNotFound, "cert_not_found")
			return
		}
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Header().Set("Content-Disposition", "attachment; filename=\"ligament-ca.crt\"")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(pemBytes)
	}
}
