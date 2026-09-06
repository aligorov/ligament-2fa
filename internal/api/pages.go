// HTML-обвязка web-интерфейса (спека §7): server-side рендер страниц из
// internal/web поверх ТОГО же сервисного слоя, что и JSON API (переиспользуются
// loginStep1/loginStep2/startSession SessionAPI и хелперы me.go/admin.go).
// Формы отправляются form-encoded; мутации завершаются редиректом с флешем
// ?flash=...&kind=ok|err (POST/Redirect/GET). CSRF — скрытое поле
// csrf_token, проверяемое middleware requirePage (вместо заголовка JSON API).
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/aligorov/twofa/internal/auth"
	"github.com/aligorov/twofa/internal/channel"
	"github.com/aligorov/twofa/internal/delivery"
	"github.com/aligorov/twofa/internal/license"
	"github.com/aligorov/twofa/internal/oidc"
	"github.com/aligorov/twofa/internal/secrets"
	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
	"github.com/aligorov/twofa/internal/telegram"
	"github.com/aligorov/twofa/internal/web"
	"github.com/aligorov/twofa/internal/webauthn"
)

// loginErrText — русские сообщения ошибок входа по машинным кодам
// loginStep1/loginStep2.
var loginErrText = map[string]string{
	"bad_credentials": "Неверное имя пользователя или пароль.",
	"locked":          "Вход временно заблокирован после серии неудач. Попробуйте позже.",
	"bad_code":        "Неверный код второго фактора.",
	"rate_limited":    "Слишком много попыток входа. Подождите немного.",
}

// PagesAPI — зависимости и маршруты HTML-страниц.
type PagesAPI struct {
	rend  *web.Renderer
	sess  *SessionAPI // вход web (loginStep1/loginStep2/startSession)
	admin *AdminAPI   // mergedValue/audit для настроек
	core  *auth.Core
	wa    *webauthn.Svc // nil — webauthn не сконфигурирован
	st    *store.Store
	box   *secrets.Box
	pv    auth.PasswordVerifier
	m     *settings.M
	fw    firewallInvalidator               // nil — кэш списков не сбрасывается
	ads   func(*http.Request) web.AdsData   // nil — реклама не показывается
	brand func(*http.Request) web.BrandData // nil — бренд Ligament
}

// firewallInvalidator — узкий интерфейс firewall.Guard (без цикла импортов).
type firewallInvalidator interface{ Invalidate() }

// SetFirewall подключает guard (сброс кэша списков при мутациях из UI).
func (p *PagesAPI) SetFirewall(f firewallInvalidator) { p.fw = f }

// SetAds подключает решатель показа рекламы РСЯ (free/trial-лицензия +
// включённые блоки; nil — реклама выключена).
func (p *PagesAPI) SetAds(f func(*http.Request) web.AdsData) { p.ads = f }

// SetBrand подключает решатель белого лейбла (только платная лицензия).
func (p *PagesAPI) SetBrand(f func(*http.Request) web.BrandData) { p.brand = f }

// NewPagesAPI собирает HTML-обвязку; rend — рендерер internal/web,
// sess/admin — переиспользуемые API-компоненты.
func NewPagesAPI(rend *web.Renderer, sess *SessionAPI, admin *AdminAPI, core *auth.Core, wa *webauthn.Svc, st *store.Store, box *secrets.Box, pv auth.PasswordVerifier, m *settings.M) *PagesAPI {
	return &PagesAPI{rend: rend, sess: sess, admin: admin, core: core, wa: wa, st: st, box: box, pv: pv, m: m}
}

// Register монтирует HTML-страницы в chi-роутер.
func (p *PagesAPI) Register(r chi.Router) {
	r.Get("/", p.handleRoot)
	r.Get("/login", p.handleLoginPage)
	r.Post("/login", p.handleLoginPost)

	r.With(p.requirePage).Post("/logout", p.handleLogout)

	authed := r.With(p.requirePage)
	authed.Get("/me", p.handleMe)
	authed.Post("/me/contacts", p.handleContacts)
	authed.Post("/me/contacts/send-code", p.handleContactsSendCode)
	authed.Post("/me/prefer", p.handlePrefer)
	authed.Post("/me/password", p.handlePassword)
	authed.Get("/me/totp", p.handleTOTPPage)
	authed.Post("/me/totp/enroll", p.handleTOTPEnroll)
	authed.Post("/me/totp/confirm", p.handleTOTPConfirm)
	authed.Post("/me/totp/delete", p.handleTOTPDelete)
	authed.Get("/me/backup", p.handleBackupPage)
	authed.Post("/me/backup/regenerate", p.handleBackupRegen)
	authed.Get("/me/telegram", p.handleTelegramPage)
	authed.Post("/me/telegram/link", p.handleTelegramLink)
	authed.Post("/me/telegram/delete", p.handleTelegramDelete)
	authed.Get("/me/passkeys", p.handlePasskeysPage)
	authed.Post("/me/webauthn/credentials", p.handleWARegisterBegin)
	authed.Post("/me/webauthn/credentials/{id}/delete", p.handleWACredDelete)
	authed.Get("/me/devices", p.handleDevicesPage)
	authed.Post("/me/devices/{id}/delete", p.handleDeviceDelete)

	admin := r.With(p.requirePage, p.requireAdmin)
	admin.Get("/admin", p.handleAdminRoot)
	admin.Get("/admin/users", p.handleAdminUsers)
	admin.Post("/admin/users", p.handleAdminUserCreate)
	admin.Get("/admin/users/{id}", p.handleAdminUserEdit)
	admin.Post("/admin/users/{id}", p.handleAdminUserAction)
	admin.Get("/admin/audit", p.handleAdminAudit)
	admin.Get("/admin/firewall", p.handleAdminFirewall)
	admin.Post("/admin/firewall/ip", p.handleAdminFirewallIPAdd)
	admin.Post("/admin/firewall/ip/{id}/delete", p.handleAdminFirewallIPDelete)
	admin.Post("/admin/firewall/bans/{ip}/delete", p.handleAdminFirewallUnban)
	admin.Get("/admin/oidc", p.handleAdminOIDC)
	admin.Post("/admin/oidc/clients", p.handleAdminOIDCClientCreate)
	admin.Post("/admin/oidc/clients/{id}/delete", p.handleAdminOIDCClientDelete)
	admin.Get("/admin/challenges", p.handleAdminChallenges)
	admin.Get("/admin/settings", p.handleAdminSettings)
	admin.Post("/admin/settings", p.handleAdminSettingsPost)
	admin.Get("/admin/settings/export", p.handlePageSettingsExport)
	admin.Post("/admin/settings/import", p.handlePageSettingsImport)
	admin.Get("/admin/backup", p.handlePageBackup)
	admin.Get("/admin/license", p.handleAdminLicense)
	admin.Post("/admin/license", p.handleAdminLicensePost)
}

// NotFound — HTML-404 (монтируется в корневой роутер BuildRouter).
func (p *PagesAPI) NotFound(w http.ResponseWriter, r *http.Request) {
	p.render(w, http.StatusNotFound, "error", web.ErrorData{
		BaseData: p.baseData(r, "Не найдено", ""),
		Code:     http.StatusNotFound,
		Message:  "Страница не найдена.",
	})
}

// ---- middleware ----

// requirePage — сессия HTML-страниц: без валидной сессии — редирект /login
// (вместо 401 JSON); мутирующие методы требуют CSRF-токен — заголовок
// X-CSRF-Token (как в JSON API) ИЛИ поле формы csrf_token (HTML-формы),
// сравнение в постоянном времени, иначе 403.
func (p *PagesAPI) requirePage(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieSession)
		if err != nil || c.Value == "" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		tokenHash := secrets.SHA256(c.Value)
		userID, csrf, err := p.st.SessionGet(r.Context(), tokenHash)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		user, err := p.st.UserByID(r.Context(), userID)
		if err != nil || !user.Enabled {
			// Отключённый админом пользователь теряет сессию сразу.
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if mutatingMethod(r.Method) {
			token := r.Header.Get(csrfHeader)
			if token == "" {
				// Формы бывают urlencoded и multipart (загрузка файла
				// импорта): ParseForm тело multipart не разбирает — CSRF-поле
				// ищется в разобранной multipart-форме.
				if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
					_ = r.ParseMultipartForm(32 << 20)
				} else {
					_ = r.ParseForm()
				}
				token = r.PostFormValue("csrf_token")
			}
			if subtle.ConstantTimeCompare([]byte(token), []byte(csrf)) != 1 {
				http.Error(w, "запрос без CSRF-токена сессии", http.StatusForbidden)
				return
			}
		}
		ctx := context.WithValue(r.Context(), ctxKeyUser, user)
		ctx = context.WithValue(ctx, ctxKeyCSRF, csrf)
		ctx = context.WithValue(ctx, ctxKeySessionHash, tokenHash)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// requireAdmin — страницы /admin только для роли admin; остальные — /me.
func (p *PagesAPI) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, ok := userFrom(r.Context()); ok && u.Role == "admin" {
			next.ServeHTTP(w, r)
			return
		}
		http.Redirect(w, r, "/me", http.StatusFound)
	})
}

// ---- общие помощники ----

// baseData собирает общие данные макета: заголовок, идентификатор активного
// пункта бокового меню (nav), текущий пользователь, CSRF сессии и флеш из
// query (?flash=...&kind=ok|err — после редиректа).
func (p *PagesAPI) baseData(r *http.Request, title, nav string) web.BaseData {
	b := web.BaseData{Title: title, Nav: nav}
	if p.ads != nil {
		b.Ads = p.ads(r)
	}
	if p.brand != nil {
		b.Brand = p.brand(r)
	}
	if q := r.URL.Query(); q.Get("flash") != "" {
		if q.Get("kind") == "err" {
			b.FlashErr = q.Get("flash")
		} else {
			b.Flash = q.Get("flash")
		}
	}
	if u, ok := userFrom(r.Context()); ok {
		b.Username = u.Username
		b.IsAdmin = u.Role == "admin"
	}
	if csrf, ok := r.Context().Value(ctxKeyCSRF).(string); ok {
		b.CSRF = csrf
	}
	b.LicenseWarnings = p.licenseWarnings(r)
	return b
}

// licenseWarnings — баннер лицензии для АДМИНА на каждой странице
// (report §3.3): достижение/превышение лимита, демо ≤7 дн., подписка
// ≤14 дн. (включая grace), окно обновлений ≤30 дн., отзыв/истечение.
func (p *PagesAPI) licenseWarnings(r *http.Request) []string {
	u, ok := userFrom(r.Context())
	if !ok || u.Role != "admin" || p.admin == nil || p.admin.licEmpty() {
		return nil
	}
	st, err := p.admin.licenseStatus(r)
	if err != nil {
		slog.Warn("pages: статус лицензии для баннера", "error", err)
		return nil
	}
	var msgs []string
	if st.Revoked {
		msgs = append(msgs, "Лицензия отозвана — сервер работает в бесплатном режиме (5 пользователей).")
	}
	if st.Expired {
		msgs = append(msgs, "Подписка истекла — сервер работает в бесплатном режиме (5 пользователей).")
	}
	// Превышение лимита — в ЛЮБОМ режиме (free после удаления лицензии или
	// истечения демо с >5 активными; licensed с урезанным лимитом).
	if st.UserLimit > 0 && st.UsersActive > st.UserLimit {
		if st.Mode == license.ModeFree {
			msgs = append(msgs, fmt.Sprintf(
				"Превышен лимит бесплатного режима (%d): создание пользователей заблокировано.",
				st.UserLimit))
		} else {
			msgs = append(msgs, fmt.Sprintf(
				"Превышен лимит лицензии (%d): создание пользователей заблокировано.",
				st.UserLimit))
		}
	} else if st.Mode == license.ModeLicensed && st.UserLimit > 0 && st.AtLimit {
		msgs = append(msgs, fmt.Sprintf(
			"Достигнут лимит лицензии: %d/%d активных пользователей — обновите лицензию или отключите других.",
			st.UsersActive, st.UserLimit))
	}
	if st.Mode == license.ModeTrial && st.TrialDaysLeft <= 7 {
		msgs = append(msgs, fmt.Sprintf("Демо-режим: осталось %d дн. — загрузите лицензию.", st.TrialDaysLeft))
	}
	if st.Mode == license.ModeLicensed && st.Plan == license.PlanSubscription {
		switch {
		case st.Grace:
			msgs = append(msgs, "Подписка истекла, действует grace-окно (5 дн.) — продлите лицензию.")
		case st.DaysLeft <= 14:
			msgs = append(msgs, fmt.Sprintf("Срок подписки истекает через %d дн. — продлите лицензию.", st.DaysLeft))
		}
	}
	if st.Mode == license.ModeLicensed && !st.UpdatesUntil.IsZero() &&
		time.Until(st.UpdatesUntil) <= 30*24*time.Hour {
		msgs = append(msgs, fmt.Sprintf(
			"Обновления доступны до %s — продлите maintenance, чтобы ставить новые версии.",
			st.UpdatesUntil.Format("02.01.2006")))
	}
	return msgs
}

// render исполняет страницу шаблонизатором; ошибка рендера логируется
// (частично записанный ответ уже не откатить).
func (p *PagesAPI) render(w http.ResponseWriter, status int, page string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := p.rend.Render(w, page, data); err != nil {
		slog.Error("pages: рендер страницы", "page", page, "error", err)
	}
}

// redirectFlash — POST/Redirect/GET: 302 на path с флешем kind=ok|err.
// Флеш вливается в СУЩЕСТВУЮЩИЙ query path: next-возврат после входа
// может нести свои параметры (например, /oidc/authorize?…).
func redirectFlash(w http.ResponseWriter, r *http.Request, path, msg string, ok bool) {
	kind := "ok"
	if !ok {
		kind = "err"
	}
	u, err := url.Parse(path)
	if err != nil {
		u = &url.URL{Path: path}
	}
	q := u.Query()
	q.Set("flash", msg)
	q.Set("kind", kind)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// auditPage пишет событие аудита, не ломая основной поток.
func (p *PagesAPI) auditPage(ctx context.Context, username, event, ip, result string, detail map[string]any) {
	if err := p.st.Audit(ctx, username, event, detail, ip, result); err != nil {
		slog.Warn("pages: аудит не записан", "event", event, "error", err)
	}
}

// backupRemaining — число неиспользованных резервных кодов пользователя.
func backupRemaining(ctx context.Context, st *store.Store, userID uuid.UUID) (int, error) {
	var n int
	err := st.Pool().QueryRow(ctx,
		`SELECT count(*) FROM backup_codes WHERE user_id = $1 AND used_at IS NULL`, userID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("подсчёт backup-кодов: %w", err)
	}
	return n, nil
}

// flash500 — редирект с текстом внутренней ошибки (после логирования).
func flash500(w http.ResponseWriter, r *http.Request, path string, err error) {
	slog.Error("pages: внутренняя ошибка", "error", err)
	redirectFlash(w, r, path, "Внутренняя ошибка, попробуйте позже.", false)
}

// ---- корень и вход ----

// handleRoot: / — на /me при валидной сессии, иначе на /login.
func (p *PagesAPI) handleRoot(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieSession); err == nil && c.Value != "" {
		if _, _, err := p.st.SessionGet(r.Context(), secrets.SHA256(c.Value)); err == nil {
			http.Redirect(w, r, "/me", http.StatusFound)
			return
		}
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

// safeNext — проверка адреса возврата после входа (?next=...): только
// локальные пути (ведут с «/», но не «//» — защита от открытого редиректа
// на внешний сайт).
func safeNext(next string) string {
	if strings.HasPrefix(next, "/") && !strings.HasPrefix(next, "//") {
		return next
	}
	return ""
}

// handleLoginPage — GET /login: форма входа; next — адрес возврата после
// входа (например, /oidc/authorize?...), проксируется hidden-полем.
func (p *PagesAPI) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	p.render(w, http.StatusOK, "login", web.LoginData{
		BaseData: p.baseData(r, "Вход", ""),
		Next:     safeNext(r.URL.Query().Get("next")),
	})
}

// renderLoginErr — рендер формы входа с ошибкой (401) либо подсказкой
// «введите код» (200): решение о шаге 2FA принимает сервер. next — адрес
// возврата (проксируется hidden-полем формы).
func (p *PagesAPI) renderLoginErr(w http.ResponseWriter, r *http.Request, status int, prefill, msg string, needCode bool, next string) {
	p.render(w, status, "login", web.LoginData{
		BaseData: p.baseData(r, "Вход", ""),
		Err:      msg,
		Prefill:  prefill,
		NeedCode: needCode,
		Next:     next,
	})
}

// handleLoginPost — POST /login: одна форма «имя+пароль+код(опц)». Без кода —
// логика первого шага (доверенное устройство/без второго фактора → сессия
// сразу; иначе перерендер с NeedCode); с кодом — «пароль + код» одним
// запросом (loginStep2). Успех — 302 на next (локальный путь, например
// /oidc/authorize?...), по умолчанию /me (админу — /admin).
func (p *PagesAPI) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		p.renderLoginErr(w, r, http.StatusBadRequest, "", "Некорректная форма.", false, "")
		return
	}
	username := r.PostFormValue("username")
	password := r.PostFormValue("password")
	code := strings.TrimSpace(r.PostFormValue("code"))
	remember := r.PostFormValue("remember") != ""
	next := safeNext(r.PostFormValue("next"))
	ctx := r.Context()

	fail := func(status int, errCode string) {
		msg := loginErrText[errCode]
		if msg == "" {
			msg = "Внутренняя ошибка, попробуйте позже."
		}
		p.renderLoginErr(w, r, status, username, msg, false, next)
	}

	if !p.sess.allowReq(r, username) {
		fail(http.StatusTooManyRequests, "rate_limited")
		return
	}

	if code == "" {
		user, status, errCode := p.sess.loginStep1(ctx, clientIP(r), username, password, "web_html")
		if status != 0 {
			fail(status, errCode)
			return
		}
		if p.sess.trustedDevice(r, user) {
			p.loginDone(w, r, user, remember, next, "trusted_device")
			return
		}
		if methods := p.sess.twoFactorMethods(ctx, user); len(methods) > 0 {
			// Второй фактор обязателен — та же форма с подсказкой.
			p.renderLoginErr(w, r, http.StatusOK, username, "", true, next)
			return
		}
		p.loginDone(w, r, user, remember, next, "password_only")
		return
	}

	user, status, errCode := p.sess.loginStep2(ctx, r, username, password, code, "web_html_2fa")
	if status != 0 {
		fail(status, errCode)
		return
	}
	p.loginDone(w, r, user, remember, next, "password+code")
}

// loginDone выпускает сессию (startSession) и редиректит на next
// (локальный путь) либо по роли: админ — /admin, остальные — /me.
func (p *PagesAPI) loginDone(w http.ResponseWriter, r *http.Request, user *store.User, remember bool, next, mode string) {
	if _, err := p.sess.startSession(w, r, user, remember, mode); err != nil {
		slog.Error("pages: создать сессию", "error", err)
		p.renderLoginErr(w, r, http.StatusInternalServerError, user.Username, "Не удалось создать сессию.", false, next)
		return
	}
	to := next
	if to == "" {
		to = "/me"
		if user.Role == "admin" {
			to = "/admin"
		}
	}
	redirectFlash(w, r, to, "Вы вошли.", true)
}

// handleLogout — POST /logout: удаляет сессию и чистит cookie.
func (p *PagesAPI) handleLogout(w http.ResponseWriter, r *http.Request) {
	hash, _ := r.Context().Value(ctxKeySessionHash).([]byte)
	if len(hash) > 0 {
		if err := p.st.SessionDelete(r.Context(), hash); err != nil && !errors.Is(err, store.ErrNotFound) {
			slog.Warn("pages: удалить сессию", "error", err)
		}
	}
	if u, ok := userFrom(r.Context()); ok {
		p.auditPage(r.Context(), u.Username, "logout", clientIP(r), "ok", nil)
	}
	setCookie(w, cookieSession, "", -1)
	redirectFlash(w, r, "/login", "Вы вышли.", true)
}

// ---- кабинет: профиль ----

// handleMe — GET /me: профиль, контакты, prefer-каналы, статус каналов.
func (p *PagesAPI) handleMe(w http.ResponseWriter, r *http.Request) {
	user, _ := userFrom(r.Context())
	ctx := r.Context()
	d := web.MeProfileData{BaseData: p.baseData(r, "Профиль", "me"), User: *user}
	if _, _, _, confirmed, _, err := p.st.TOTPGet(ctx, user.ID); err == nil {
		d.TOTPConfirmed = confirmed
	} else if !errors.Is(err, store.ErrNotFound) {
		flash500(w, r, "/me", err)
		return
	}
	d.TelegramLinked = user.TelegramChatID != nil
	if n, err := backupRemaining(ctx, p.st, user.ID); err == nil {
		d.BackupRemaining = n
	}
	if creds, err := p.st.WACredListForUser(ctx, user.ID); err == nil {
		d.PasskeyCount = len(creds)
	}
	p.render(w, http.StatusOK, "me_profile", d)
}

// handleContacts — POST /me/contacts: смена email/phone с кодом на старый
// канал (та же логика, что PUT /api/v1/me/contacts).
func (p *PagesAPI) handleContacts(w http.ResponseWriter, r *http.Request) {
	user, _ := userFrom(r.Context())
	ctx := r.Context()
	code := strings.TrimSpace(r.PostFormValue("code"))
	if code == "" {
		redirectFlash(w, r, "/me", "Введите код подтверждения.", false)
		return
	}
	if _, err := p.core.VerifyAnyCode(ctx, user, code, purposeUIConfirm); err != nil {
		p.auditPage(ctx, user.Username, "contacts_change", clientIP(r), "fail",
			map[string]any{"reason": "bad_code"})
		redirectFlash(w, r, "/me", "Неверный код подтверждения.", false)
		return
	}
	user.Email = strings.TrimSpace(r.PostFormValue("email"))
	user.Phone = strings.TrimSpace(r.PostFormValue("phone"))
	if err := p.st.UserUpdate(ctx, user); err != nil {
		flash500(w, r, "/me", err)
		return
	}
	p.auditPage(ctx, user.Username, "contacts_change", clientIP(r), "ok", nil)
	redirectFlash(w, r, "/me", "Контакты сохранены.", true)
}

// handleContactsSendCode — POST /me/contacts/send-code: код подтверждения
// на выбранный в форме канал (email/sms/telegram); автоподбор — как в
// JSON API.
func (p *PagesAPI) handleContactsSendCode(w http.ResponseWriter, r *http.Request) {
	user, _ := userFrom(r.Context())

	var prefer []channel.Channel
	switch ch := channel.Channel(r.PostFormValue("channel")); ch {
	case channel.Email, channel.SMS, channel.Telegram:
		prefer = []channel.Channel{ch}
	default:
		// Канал не выбран/неизвестен — email/telegram из prefer_channels.
		for _, c := range user.PreferChannels {
			if c == channel.Email || c == channel.Telegram {
				prefer = append(prefer, c)
			}
		}
		if len(prefer) == 0 {
			prefer = []channel.Channel{channel.Email, channel.Telegram}
		}
	}
	slim := *user // копия с ограниченным набором каналов; ядро не мутирует user
	slim.PreferChannels = prefer

	_, err := p.core.StartWithMeta(r.Context(), &slim, purposeUIConfirm, clientIP(r), r.UserAgent())
	switch {
	case err == nil:
		redirectFlash(w, r, "/me", "Код подтверждения отправлен.", true)
	case errors.Is(err, auth.ErrNoChannel):
		redirectFlash(w, r, "/me", "Нет доступного канала доставки кода.", false)
	case errors.Is(err, auth.ErrCooldown):
		redirectFlash(w, r, "/me", "Подождите перед повторной отправкой кода.", false)
	default:
		flash500(w, r, "/me", err)
	}
}

// handlePrefer — POST /me/prefer: порядок prefer_channels (валидные имена
// каналов, хотя бы один).
func (p *PagesAPI) handlePrefer(w http.ResponseWriter, r *http.Request) {
	user, _ := userFrom(r.Context())
	chs, ok := parseChannels(r.PostForm["channels"])
	if !ok {
		redirectFlash(w, r, "/me", "Выберите хотя бы один корректный канал.", false)
		return
	}
	user.PreferChannels = chs
	if err := p.st.UserUpdate(r.Context(), user); err != nil {
		flash500(w, r, "/me", err)
		return
	}
	p.auditPage(r.Context(), user.Username, "prefer_change", clientIP(r), "ok",
		map[string]any{"channels": r.PostForm["channels"]})
	redirectFlash(w, r, "/me", "Каналы второго фактора сохранены.", true)
}

// handlePassword — POST /me/password: смена пароля и отзыв всех сессий и
// устройств (как PATCH /api/v1/me/password); после смены — выход на /login.
// LDAP-пользователям операция запрещена сервером (форма в шаблоне скрыта,
// но прямой POST должен упереться в страж — пароль меняется в каталоге).
func (p *PagesAPI) handlePassword(w http.ResponseWriter, r *http.Request) {
	user, _ := userFrom(r.Context())
	if user.Source == store.SourceLDAP {
		p.auditPage(r.Context(), user.Username, "password_change", clientIP(r), "fail",
			map[string]any{"reason": "ldap_managed"})
		redirectFlash(w, r, "/me", "Пароль LDAP-пользователя меняется в Active Directory.", false)
		return
	}
	newPwd := r.PostFormValue("new_password")
	if newPwd == "" || newPwd != r.PostFormValue("new_password2") {
		redirectFlash(w, r, "/me", "Новые пароли не совпадают.", false)
		return
	}
	ctx := r.Context()
	if _, err := p.pv.Verify(ctx, user.Username, r.PostFormValue("old_password")); err != nil {
		p.auditPage(ctx, user.Username, "password_change", clientIP(r), "fail",
			map[string]any{"reason": "bad_credentials"})
		redirectFlash(w, r, "/me", "Текущий пароль неверен.", false)
		return
	}
	user.PasswordHash = secrets.HashPassword(newPwd)
	if err := p.st.UserUpdate(ctx, user); err != nil {
		flash500(w, r, "/me", err)
		return
	}
	if err := p.st.SessionDeleteAllForUser(ctx, user.ID); err != nil {
		slog.Warn("pages: отзыв сессий после смены пароля", "error", err)
	}
	if err := p.st.DeviceDeleteAllForUser(ctx, user.ID); err != nil {
		slog.Warn("pages: отзыв устройств после смены пароля", "error", err)
	}
	setCookie(w, cookieSession, "", -1)
	setCookie(w, cookieDevice, "", -1)
	p.auditPage(ctx, user.Username, "password_change", clientIP(r), "ok", nil)
	redirectFlash(w, r, "/login", "Пароль изменён. Войдите с новым паролем.", true)
}

// ---- кабинет: TOTP ----

// handleTOTPPage — GET /me/totp: не привязан / ждёт подтверждения (QR) /
// подтверждён.
func (p *PagesAPI) handleTOTPPage(w http.ResponseWriter, r *http.Request) {
	user, _ := userFrom(r.Context())
	ctx := r.Context()
	d := web.MeTOTPData{BaseData: p.baseData(r, "TOTP-приложение", "totp")}
	enc, digits, period, confirmed, _, err := p.st.TOTPGet(ctx, user.ID)
	switch {
	case err == nil && confirmed:
		d.Confirmed = true
	case err == nil:
		// Секрет выдан, но не подтверждён — показать QR повторно.
		secret, derr := p.box.DecryptAAD(auth.AADTOTP(user.Username), enc)
		if derr != nil {
			flash500(w, r, "/me/totp", derr)
			return
		}
		d.OtpauthURL = otpauthURL(p.m.Get().TOTP.Issuer, user.Username, string(secret), digits, period)
	case errors.Is(err, store.ErrNotFound):
		// не привязан — форма энроллмента
	default:
		flash500(w, r, "/me/totp", err)
		return
	}
	p.render(w, http.StatusOK, "me_totp", d)
}

// otpauthURL строит otpauth://-ссылку в формате pquerna/otp (для QR).
func otpauthURL(issuer, account, secret string, digits, period int) string {
	v := url.Values{
		"secret": {secret},
		"digits": {strconv.Itoa(digits)},
		"period": {strconv.Itoa(period)},
	}
	if issuer != "" {
		v.Set("issuer", issuer)
		return fmt.Sprintf("otpauth://totp/%s:%s?%s",
			url.PathEscape(issuer), url.PathEscape(account), v.Encode())
	}
	return fmt.Sprintf("otpauth://totp/%s?%s", url.PathEscape(account), v.Encode())
}

// handleTOTPEnroll — POST /me/totp/enroll: новый секрет (как в JSON API),
// затем редирект на /me/totp с QR.
func (p *PagesAPI) handleTOTPEnroll(w http.ResponseWriter, r *http.Request) {
	user, _ := userFrom(r.Context())
	t := p.m.Get().TOTP
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      t.Issuer,
		AccountName: user.Username,
		Period:      uint(t.Period),
		Digits:      otp.Digits(t.Digits),
	})
	if err != nil {
		flash500(w, r, "/me/totp", err)
		return
	}
	enc := p.box.EncryptAAD(auth.AADTOTP(user.Username), []byte(key.Secret()))
	if err := p.st.TOTPSave(r.Context(), user.ID, enc, t.Digits, t.Period); err != nil {
		flash500(w, r, "/me/totp", err)
		return
	}
	p.auditPage(r.Context(), user.Username, "totp_enroll", clientIP(r), "ok", nil)
	redirectFlash(w, r, "/me/totp", "Секрет выдан: отсканируйте QR и введите код.", true)
}

// handleTOTPConfirm — POST /me/totp/confirm: проверка кода по расшифрованному
// секрету, TOTPConfirm и новая партия резервных кодов — коды рендерятся на
// странице backup ОДИН раз (аналог backup_codes в JSON-ответе).
func (p *PagesAPI) handleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	user, _ := userFrom(r.Context())
	code := strings.TrimSpace(r.PostFormValue("code"))
	if code == "" {
		redirectFlash(w, r, "/me/totp", "Введите код из приложения.", false)
		return
	}
	ctx := r.Context()
	enc, digits, period, confirmed, _, err := p.st.TOTPGet(ctx, user.ID)
	if errors.Is(err, store.ErrNotFound) {
		redirectFlash(w, r, "/me/totp", "Сначала получите секрет.", false)
		return
	}
	if err != nil {
		flash500(w, r, "/me/totp", err)
		return
	}
	if confirmed {
		redirectFlash(w, r, "/me/totp", "TOTP уже подтверждён.", true)
		return
	}
	secret, err := p.box.DecryptAAD(auth.AADTOTP(user.Username), enc)
	if err != nil {
		flash500(w, r, "/me/totp", err)
		return
	}
	ok, err := totp.ValidateCustom(code, string(secret), time.Now().UTC(), totp.ValidateOpts{
		Period:    uint(period),
		Skew:      p.m.Get().TOTP.Skew,
		Digits:    otp.Digits(digits),
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		flash500(w, r, "/me/totp", err)
		return
	}
	if !ok {
		p.auditPage(ctx, user.Username, "totp_confirm", clientIP(r), "fail",
			map[string]any{"reason": "bad_code"})
		redirectFlash(w, r, "/me/totp", "Код не подошёл, попробуйте ещё раз.", false)
		return
	}
	if err := p.st.TOTPConfirm(ctx, user.ID); err != nil {
		flash500(w, r, "/me/totp", err)
		return
	}
	// Replay-защита подтверждённого кода (как в JSON API): только подъём
	// last_timestep TOTP-фактора, доставленные коды не расходуются.
	if _, err := p.core.VerifyAnyCode(ctx, user, code); err != nil {
		slog.Warn("pages: burn кода после totp confirm", "error", err)
	}
	codes, err := replaceBackupCodes(ctx, p.st, user.ID)
	if err != nil {
		flash500(w, r, "/me/totp", err)
		return
	}
	p.auditPage(ctx, user.Username, "totp_confirm", clientIP(r), "ok", nil)
	p.renderBackupCodes(w, r, codes)
}

// handleTOTPDelete — POST /me/totp/delete: отвязка с кодом (чувствительная
// операция).
func (p *PagesAPI) handleTOTPDelete(w http.ResponseWriter, r *http.Request) {
	user, _ := userFrom(r.Context())
	code := strings.TrimSpace(r.PostFormValue("code"))
	if code == "" {
		redirectFlash(w, r, "/me/totp", "Введите код.", false)
		return
	}
	ctx := r.Context()
	if _, err := p.core.VerifyAnyCode(ctx, user, code, purposeUIConfirm); err != nil {
		p.auditPage(ctx, user.Username, "totp_delete", clientIP(r), "fail",
			map[string]any{"reason": "bad_code"})
		redirectFlash(w, r, "/me/totp", "Неверный код.", false)
		return
	}
	if err := p.st.TOTPDelete(ctx, user.ID); err != nil {
		flash500(w, r, "/me/totp", err)
		return
	}
	p.auditPage(ctx, user.Username, "totp_delete", clientIP(r), "ok", nil)
	redirectFlash(w, r, "/me/totp", "TOTP отвязан.", true)
}

// ---- кабинет: резервные коды ----

// handleBackupPage — GET /me/backup: остаток кодов.
func (p *PagesAPI) handleBackupPage(w http.ResponseWriter, r *http.Request) {
	user, _ := userFrom(r.Context())
	d := web.MeBackupData{BaseData: p.baseData(r, "Резервные коды", "backup")}
	if n, err := backupRemaining(r.Context(), p.st, user.ID); err == nil {
		d.Remaining = n
	}
	p.render(w, http.StatusOK, "me_backup", d)
}

// handleBackupRegen — POST /me/backup/regenerate: код подтверждения → новая
// партия (показ один раз).
func (p *PagesAPI) handleBackupRegen(w http.ResponseWriter, r *http.Request) {
	user, _ := userFrom(r.Context())
	code := strings.TrimSpace(r.PostFormValue("code"))
	if code == "" {
		redirectFlash(w, r, "/me/backup", "Введите код подтверждения.", false)
		return
	}
	ctx := r.Context()
	if _, err := p.core.VerifyAnyCode(ctx, user, code, purposeUIConfirm); err != nil {
		p.auditPage(ctx, user.Username, "backup_regen", clientIP(r), "fail",
			map[string]any{"reason": "bad_code"})
		redirectFlash(w, r, "/me/backup", "Неверный код.", false)
		return
	}
	codes, err := replaceBackupCodes(ctx, p.st, user.ID)
	if err != nil {
		flash500(w, r, "/me/backup", err)
		return
	}
	p.auditPage(ctx, user.Username, "backup_regen", clientIP(r), "ok", nil)
	p.renderBackupCodes(w, r, codes)
}

// renderBackupCodes — страница me_backup с НОВЫМИ кодами (ровно один раз).
func (p *PagesAPI) renderBackupCodes(w http.ResponseWriter, r *http.Request, codes []string) {
	d := web.MeBackupData{BaseData: p.baseData(r, "Резервные коды", "backup"), Generated: true, Codes: codes}
	if user, ok := userFrom(r.Context()); ok {
		if n, err := backupRemaining(r.Context(), p.st, user.ID); err == nil {
			d.Remaining = n
		}
	}
	p.render(w, http.StatusOK, "me_backup", d)
}

// ---- кабинет: Telegram ----

// handleTelegramPage — GET /me/telegram: статус привязки либо код привязки.
func (p *PagesAPI) handleTelegramPage(w http.ResponseWriter, r *http.Request) {
	user, _ := userFrom(r.Context())
	p.render(w, http.StatusOK, "me_telegram", web.MeTelegramData{
		BaseData: p.baseData(r, "Telegram", "telegram"),
		Linked:   user.TelegramChatID != nil,
		ChatID:   user.TelegramChatID,
		NeedCode: hasSecondFactor(r.Context(), p.st, user),
	})
}

// handleTelegramLink — POST /me/telegram/link (form: code): код привязки
// (XXXX-XXXX) рендерится на странице один раз. Выдача — чувствительная
// операция (SEC-002): при наличии второго фактора требуется код
// подтверждения (ui_confirm).
func (p *PagesAPI) handleTelegramLink(w http.ResponseWriter, r *http.Request) {
	user, _ := userFrom(r.Context())
	ctx := r.Context()
	reason, ok := tgLinkCodeCheck(ctx, p.core, p.st, user, r.PostFormValue("code"))
	if !ok {
		p.auditPage(ctx, user.Username, "tg_link_start", clientIP(r), "fail",
			map[string]any{"reason": reason})
		if reason == "code_required" {
			redirectFlash(w, r, "/me/telegram", "Введите код подтверждения.", false)
		} else {
			redirectFlash(w, r, "/me/telegram", "Неверный код подтверждения.", false)
		}
		return
	}
	code := telegram.GenerateLinkCode()
	ch := &store.Challenge{
		UserID:       user.ID,
		Channel:      channel.Telegram,
		CodeHash:     secrets.SHA256(code),
		ExpiresAt:    time.Now().Add(tgLinkTTL),
		AttemptsLeft: 1,
		Purpose:      "tg_link",
	}
	if err := p.st.ChallengeCreate(r.Context(), ch); err != nil {
		flash500(w, r, "/me/telegram", err)
		return
	}
	p.auditPage(r.Context(), user.Username, "tg_link_start", clientIP(r), "ok", nil)
	p.render(w, http.StatusOK, "me_telegram", web.MeTelegramData{
		BaseData: p.baseData(r, "Telegram", "telegram"),
		LinkCode: code,
	})
}

// handleTelegramDelete — POST /me/telegram/delete: отвязка с кодом
// (шаблон требует код подтверждения — чувствительная операция).
func (p *PagesAPI) handleTelegramDelete(w http.ResponseWriter, r *http.Request) {
	user, _ := userFrom(r.Context())
	code := strings.TrimSpace(r.PostFormValue("code"))
	if code == "" {
		redirectFlash(w, r, "/me/telegram", "Введите код подтверждения.", false)
		return
	}
	ctx := r.Context()
	if _, err := p.core.VerifyAnyCode(ctx, user, code, purposeUIConfirm); err != nil {
		p.auditPage(ctx, user.Username, "telegram_unlink", clientIP(r), "fail",
			map[string]any{"reason": "bad_code"})
		redirectFlash(w, r, "/me/telegram", "Неверный код.", false)
		return
	}
	user.TelegramChatID = nil
	if err := p.st.UserUpdate(ctx, user); err != nil {
		flash500(w, r, "/me/telegram", err)
		return
	}
	p.auditPage(ctx, user.Username, "telegram_unlink", clientIP(r), "ok", nil)
	redirectFlash(w, r, "/me/telegram", "Telegram отвязан.", true)
}

// ---- кабинет: passkeys ----

// handlePasskeysPage — GET /me/passkeys.
func (p *PagesAPI) handlePasskeysPage(w http.ResponseWriter, r *http.Request) {
	user, _ := userFrom(r.Context())
	creds, err := p.st.WACredListForUser(r.Context(), user.ID)
	if err != nil {
		flash500(w, r, "/me/passkeys", err)
		return
	}
	p.render(w, http.StatusOK, "me_passkeys", web.MePasskeysData{
		BaseData: p.baseData(r, "Passkeys", "passkeys"), Creds: creds,
	})
}

// handleWARegisterBegin — POST /me/webauthn/credentials (form: name, code):
// чувствительная операция — код второго фактора проверяется ДО старта
// церемонии (VerifyAnyCode: доставленный/TOTP/резервный). Затем сервер
// начинает регистрацию (BeginRegister) и перерендеривает страницу с
// handle+options в data-атрибутах #passkey-pending — webauthn.js создаёт
// ключ и завершает через /api/v1/me/webauthn/register/finish (graceful
// fallback без JS — просто перерендер, JSON API остаётся основным путём).
func (p *PagesAPI) handleWARegisterBegin(w http.ResponseWriter, r *http.Request) {
	if p.wa == nil {
		redirectFlash(w, r, "/me/passkeys",
			"WebAuthn не сконфигурирован (задайте webauthn.rp_id и перезапустите).", false)
		return
	}
	user, _ := userFrom(r.Context())
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" {
		redirectFlash(w, r, "/me/passkeys", "Укажите имя ключа.", false)
		return
	}
	code := strings.TrimSpace(r.PostFormValue("code"))
	if code == "" {
		redirectFlash(w, r, "/me/passkeys", "Введите код подтверждения.", false)
		return
	}
	if _, err := p.core.VerifyAnyCode(r.Context(), user, code, purposeUIConfirm); err != nil {
		p.auditPage(r.Context(), user.Username, "webauthn_register", clientIP(r), "fail",
			map[string]any{"reason": "bad_code"})
		redirectFlash(w, r, "/me/passkeys", "Неверный код подтверждения.", false)
		return
	}
	opts, handle, err := p.wa.BeginRegister(r.Context(), user)
	if err != nil {
		flash500(w, r, "/me/passkeys", err)
		return
	}
	creds, err := p.st.WACredListForUser(r.Context(), user.ID)
	if err != nil {
		flash500(w, r, "/me/passkeys", err)
		return
	}
	p.render(w, http.StatusOK, "me_passkeys", web.MePasskeysData{
		BaseData:    p.baseData(r, "Passkeys", "passkeys"),
		Creds:       creds,
		Handle:      handle,
		RegName:     name,
		OptionsJSON: string(opts),
	})
}

// handleWACredDelete — POST /me/webauthn/credentials/{id}/delete.
func (p *PagesAPI) handleWACredDelete(w http.ResponseWriter, r *http.Request) {
	user, _ := userFrom(r.Context())
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id < 1 {
		redirectFlash(w, r, "/me/passkeys", "Некорректный идентификатор ключа.", false)
		return
	}
	if err := p.st.WACredDelete(r.Context(), id, user.ID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			redirectFlash(w, r, "/me/passkeys", "Ключ не найден.", false)
			return
		}
		flash500(w, r, "/me/passkeys", err)
		return
	}
	p.auditPage(r.Context(), user.Username, "webauthn_cred_delete", clientIP(r), "ok",
		map[string]any{"credential_row": id})
	redirectFlash(w, r, "/me/passkeys", "Ключ удалён.", true)
}

// ---- кабинет: доверенные устройства ----

// handleDevicesPage — GET /me/devices.
func (p *PagesAPI) handleDevicesPage(w http.ResponseWriter, r *http.Request) {
	user, _ := userFrom(r.Context())
	list, err := p.st.DeviceListForUser(r.Context(), user.ID)
	if err != nil {
		flash500(w, r, "/me/devices", err)
		return
	}
	devices := make([]store.Device, len(list))
	for i, d := range list {
		devices[i] = *d
	}
	p.render(w, http.StatusOK, "me_devices", web.MeDevicesData{
		BaseData: p.baseData(r, "Устройства", "devices"),
		Devices:  devices,
	})
}

// handleDeviceDelete — POST /me/devices/{id}/delete: отзыв устройства.
func (p *PagesAPI) handleDeviceDelete(w http.ResponseWriter, r *http.Request) {
	user, _ := userFrom(r.Context())
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id < 1 {
		redirectFlash(w, r, "/me/devices", "Некорректный идентификатор устройства.", false)
		return
	}
	if err := p.st.DeviceDelete(r.Context(), id, user.ID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			redirectFlash(w, r, "/me/devices", "Устройство не найдено.", false)
			return
		}
		flash500(w, r, "/me/devices", err)
		return
	}
	p.auditPage(r.Context(), user.Username, "device_revoke", clientIP(r), "ok",
		map[string]any{"device_id": id})
	redirectFlash(w, r, "/me/devices", "Устройство отозвано.", true)
}

// ---- админ ----

// handleAdminRoot — GET /admin: главная админки — список пользователей.
func (p *PagesAPI) handleAdminRoot(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/admin/users", http.StatusFound)
}

// handleAdminUsers — GET /admin/users: таблица + форма создания.
func (p *PagesAPI) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	users, err := p.st.UserList(r.Context())
	if err != nil {
		flash500(w, r, "/admin/users", err)
		return
	}
	p.render(w, http.StatusOK, "admin_users", web.AdminUsersData{
		BaseData: p.baseData(r, "Пользователи", "admin-users"),
		Users:    derefUsers(users),
	})
}

// derefUsers — []*User → []User (тип данных страницы).
func derefUsers(list []*store.User) []store.User {
	out := make([]store.User, len(list))
	for i, u := range list {
		out[i] = *u
	}
	return out
}

// userFormFields — общее чтение формы создания/редактирования
// пользователя; возвращает пароль (пустой — не менять). display_name
// читается только для локальных: у LDAP-поле_disabled в шаблоне (не
// отправляется) и значение синхронизируется каталогом.
func (p *PagesAPI) userFormFields(r *http.Request, u *store.User) string {
	u.Username = strings.TrimSpace(r.PostFormValue("username"))
	u.Role = r.PostFormValue("role")
	if u.Role != "admin" {
		u.Role = "user"
	}
	u.Source = r.PostFormValue("source")
	if u.Source != store.SourceLDAP {
		u.Source = store.SourceLocal
	}
	u.Enabled = r.PostFormValue("enabled") != ""
	u.Email = strings.TrimSpace(r.PostFormValue("email"))
	u.Phone = strings.TrimSpace(r.PostFormValue("phone"))
	if u.Source != store.SourceLDAP {
		u.DisplayName = strings.TrimSpace(r.PostFormValue("display_name"))
	}
	if chs, ok := parseChannels(r.PostForm["prefer_channels"]); ok {
		u.PreferChannels = chs
	}
	u.RadiusPush = r.PostFormValue("radius_push") != ""
	return strings.TrimSpace(r.PostFormValue("password"))
}

// radiusReplyFromForm разбирает textarea radius_reply (JSON-объект или пусто).
func radiusReplyFromForm(raw string) (map[string]string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, true
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, false
	}
	return m, true
}

// handleAdminUserCreate — POST /admin/users (форма «Новый пользователь»).
// Создание активного пользователя сверх лимита лицензии — флеш-ошибка
// (параллель 403 JSON API; report §3.3).
func (p *PagesAPI) handleAdminUserCreate(w http.ResponseWriter, r *http.Request) {
	u := &store.User{}
	pwd := p.userFormFields(r, u)
	// LDAP-пользователю пароль не нужен: он проверяется каталогом; вместо
	// опционального пароля — случайный непригодный хеш.
	if u.Username == "" || (pwd == "" && u.Source != store.SourceLDAP) {
		redirectFlash(w, r, "/admin/users", "Имя пользователя и пароль обязательны.", false)
		return
	}
	if u.Enabled {
		if exceeded, st := p.admin.licenseExceeded(r); exceeded {
			p.admin.audit(r.Context(), "license_limit", map[string]any{
				"via": "html", "limit": st.UserLimit, "active_users": st.UsersActive,
			})
			redirectFlash(w, r, "/admin/users", fmt.Sprintf(
				"Превышен лимит лицензии %d — обновите лицензию или отключите других пользователей.",
				st.UserLimit), false)
			return
		}
	}
	reply, ok := radiusReplyFromForm(r.PostFormValue("radius_reply"))
	if !ok {
		redirectFlash(w, r, "/admin/users", "RADIUS Reply: ожидается JSON-объект.", false)
		return
	}
	u.RadiusReply = reply
	if pwd == "" {
		u.PasswordHash = secrets.HashPassword(secrets.RandomToken(32))
	} else {
		u.PasswordHash = secrets.HashPassword(pwd)
	}
	if err := p.st.UserCreate(r.Context(), u); err != nil {
		if isUniqueViolation(err) {
			redirectFlash(w, r, "/admin/users", "Это имя пользователя уже занято.", false)
			return
		}
		flash500(w, r, "/admin/users", err)
		return
	}
	p.admin.audit(r.Context(), "user_create", map[string]any{"username": u.Username})
	redirectFlash(w, r, "/admin/users", "Пользователь создан.", true)
}

// isUniqueViolation — нарушение уникальности PostgreSQL (23505).
func isUniqueViolation(err error) bool {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "23505"
	}
	return false
}

// handleAdminUserEdit — GET /admin/users/{id}: таблица + форма редактирования.
func (p *PagesAPI) handleAdminUserEdit(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		redirectFlash(w, r, "/admin/users", "Некорректный идентификатор.", false)
		return
	}
	u, err := p.st.UserByID(r.Context(), id)
	if err != nil {
		redirectFlash(w, r, "/admin/users", "Пользователь не найден.", false)
		return
	}
	users, err := p.st.UserList(r.Context())
	if err != nil {
		flash500(w, r, "/admin/users", err)
		return
	}
	replyJSON := ""
	if u.RadiusReply != nil {
		if b, err := json.MarshalIndent(u.RadiusReply, "", "  "); err == nil {
			replyJSON = string(b)
		}
	}
	p.render(w, http.StatusOK, "admin_users", web.AdminUsersData{
		BaseData:      p.baseData(r, "Пользователи", "admin-users"),
		Users:         derefUsers(users),
		Edit:          u,
		EditReplyJSON: replyJSON,
	})
}

// handleAdminUserAction — POST /admin/users/{id}: do=save|reset-totp|
// reset-webauthn|unlink-telegram|revoke-devices|delete (кнопки таблицы и
// форма редактирования).
func (p *PagesAPI) handleAdminUserAction(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		redirectFlash(w, r, "/admin/users", "Некорректный идентификатор.", false)
		return
	}
	back := "/admin/users/" + id.String()
	u, err := p.st.UserByID(r.Context(), id)
	if err != nil {
		redirectFlash(w, r, "/admin/users", "Пользователь не найден.", false)
		return
	}
	ctx := r.Context()

	switch r.PostFormValue("do") {
	case "save":
		wasEnabled := u.Enabled // до перезаписи формой (userFormFields)
		pwd := p.userFormFields(r, u)
		if u.Username == "" {
			redirectFlash(w, r, back, "Имя пользователя не может быть пустым.", false)
			return
		}
		// Включение ранее отключённого пользователя = +1 активный: лимит
		// лицензии действует и здесь (выключение не ограничивается).
		if !wasEnabled {
			if exceeded, st := p.admin.licenseExceeded(r); exceeded {
				p.admin.audit(ctx, "license_limit", map[string]any{
					"via": "html", "limit": st.UserLimit, "active_users": st.UsersActive,
				})
				redirectFlash(w, r, back, fmt.Sprintf(
					"Превышен лимит лицензии %d — обновите лицензию или отключите других пользователей.",
					st.UserLimit), false)
				return
			}
		}
		if pwd != "" {
			u.PasswordHash = secrets.HashPassword(pwd)
		}
		reply, ok := radiusReplyFromForm(r.PostFormValue("radius_reply"))
		if !ok {
			redirectFlash(w, r, back, "RADIUS Reply: ожидается JSON-объект.", false)
			return
		}
		u.RadiusReply = reply
		if err := p.st.UserUpdate(ctx, u); err != nil {
			if isUniqueViolation(err) {
				redirectFlash(w, r, back, "Это имя пользователя уже занято.", false)
				return
			}
			flash500(w, r, back, err)
			return
		}
		p.admin.audit(ctx, "user_update", map[string]any{"user_id": u.ID.String()})
		redirectFlash(w, r, back, "Пользователь сохранён.", true)

	case "reset-totp":
		if err := p.st.TOTPDelete(ctx, u.ID); err != nil {
			flash500(w, r, "/admin/users", err)
			return
		}
		codes, err := replaceBackupCodes(ctx, p.st, u.ID)
		if err != nil {
			flash500(w, r, "/admin/users", err)
			return
		}
		p.admin.audit(ctx, "user_reset_totp", map[string]any{"user_id": u.ID.String()})
		// Коды показываются ровно один раз в ТЕЛЕ ответа (200), как в JSON
		// API; редирект с кодами в query уносил бы их в Location, историю
		// браузера и логи прокси.
		users, err := p.st.UserList(ctx)
		if err != nil {
			flash500(w, r, "/admin/users", err)
			return
		}
		p.render(w, http.StatusOK, "admin_users", web.AdminUsersData{
			BaseData:    p.baseData(r, "Пользователи", "admin-users"),
			Users:       derefUsers(users),
			BackupCodes: codes,
		})

	case "reset-webauthn":
		if err := p.st.WACredsDeleteForUser(ctx, u.ID); err != nil {
			flash500(w, r, "/admin/users", err)
			return
		}
		p.admin.audit(ctx, "user_reset_webauthn", map[string]any{"user_id": u.ID.String()})
		redirectFlash(w, r, "/admin/users", "Все passkeys пользователя удалены.", true)

	case "unlink-telegram":
		u.TelegramChatID = nil
		if err := p.st.UserUpdate(ctx, u); err != nil {
			flash500(w, r, "/admin/users", err)
			return
		}
		p.admin.audit(ctx, "user_unlink_telegram", map[string]any{"user_id": u.ID.String()})
		redirectFlash(w, r, "/admin/users", "Telegram отвязан.", true)

	case "revoke-devices":
		if err := p.st.DeviceDeleteAllForUser(ctx, u.ID); err != nil {
			flash500(w, r, "/admin/users", err)
			return
		}
		p.admin.audit(ctx, "user_devices_revoke", map[string]any{"user_id": u.ID.String()})
		redirectFlash(w, r, "/admin/users", "Устройства отозваны.", true)

	case "delete":
		if err := p.st.UserDelete(ctx, id); err != nil {
			flash500(w, r, "/admin/users", err)
			return
		}
		p.admin.audit(ctx, "user_delete", map[string]any{"user_id": id.String()})
		redirectFlash(w, r, "/admin/users", "Пользователь удалён.", true)

	default:
		redirectFlash(w, r, back, "Неизвестное действие.", false)
	}
}

// handleAdminAudit — GET /admin/audit: последние записи журнала.
func (p *PagesAPI) handleAdminAudit(w http.ResponseWriter, r *http.Request) {
	rows, err := p.st.AuditList(r.Context(), store.AuditFilter{Limit: 100})
	if err != nil {
		flash500(w, r, "/admin/audit", err)
		return
	}
	out := make([]store.AuditRow, len(rows))
	for i, row := range rows {
		out[i] = *row
	}
	p.render(w, http.StatusOK, "admin_audit", web.AdminAuditData{
		BaseData: p.baseData(r, "Журнал аудита", "admin-audit"),
		Rows:     out,
	})
}

// handleAdminChallenges — GET /admin/challenges: активные челленджи
// (только метаданные, code_hash не выбирается) + имена пользователей.
// push_state — только для telegram_push: у webauthn_session в этой колонке
// лежит сессия церемонии, которая не должна покидать сервер (тот же
// CASE-щит, что у JSON API handleChallenges).
func (p *PagesAPI) handleAdminChallenges(w http.ResponseWriter, r *http.Request) {
	rows, err := p.st.Pool().Query(r.Context(), `
		SELECT id, user_id, channel,
		       CASE WHEN channel = 'telegram_push' THEN COALESCE(push_state, '') ELSE '' END,
		       expires_at, attempts_left, purpose, created_at
		FROM challenges
		WHERE expires_at > now() AND used_at IS NULL
		ORDER BY created_at DESC
		LIMIT 200`)
	if err != nil {
		flash500(w, r, "/admin/challenges", err)
		return
	}
	defer rows.Close()

	d := web.AdminChallengesData{BaseData: p.baseData(r, "Активные challenge", "admin-challenges"), Usernames: map[uuid.UUID]string{}}
	seen := map[uuid.UUID]struct{}{}
	for rows.Next() {
		var (
			c         store.Challenge
			pushState string
		)
		if err := rows.Scan(&c.ID, &c.UserID, &c.Channel, &pushState,
			&c.ExpiresAt, &c.AttemptsLeft, &c.Purpose, &c.CreatedAt); err != nil {
			flash500(w, r, "/admin/challenges", err)
			return
		}
		if pushState != "" {
			c.PushState = &pushState
		}
		d.Challenges = append(d.Challenges, c)
		if _, ok := seen[c.UserID]; !ok {
			seen[c.UserID] = struct{}{}
			if u, err := p.st.UserByID(r.Context(), c.UserID); err == nil {
				d.Usernames[c.UserID] = u.Username
			}
		}
	}
	if err := rows.Err(); err != nil {
		flash500(w, r, "/admin/challenges", err)
		return
	}
	p.render(w, http.StatusOK, "admin_challenges", d)
}

// ---- админ: настройки ----

// handleAdminSettings — GET /admin/settings: снимок по секциям; секреты —
// только флаги «задано» (маска «••••»).
func (p *PagesAPI) handleAdminSettings(w http.ResponseWriter, r *http.Request) {
	p.render(w, http.StatusOK, "admin_settings", p.adminSettingsData(r))
}

// adminSettingsData — данные страницы настроек: снимок по секциям, секреты —
// только флаги «задано». Общий код GET-рендера и ответа регенерации секрета
// (страница регенерации — те же данные + одноразовое значение).
func (p *PagesAPI) adminSettingsData(r *http.Request) web.AdminSettingsData {
	t := p.m.Get()
	replyJSON := ""
	if t.Radius.ReplyAttributes != nil {
		if b, err := json.MarshalIndent(t.Radius.ReplyAttributes, "", "  "); err == nil {
			replyJSON = string(b)
		}
	}
	allowJSON, roleJSON := "", ""
	if t.LDAP.AllowGroups != nil {
		if b, err := json.MarshalIndent(t.LDAP.AllowGroups, "", "  "); err == nil {
			allowJSON = string(b)
		}
	}
	if t.LDAP.RoleMap != nil {
		if b, err := json.MarshalIndent(t.LDAP.RoleMap, "", "  "); err == nil {
			roleJSON = string(b)
		}
	}
	return web.AdminSettingsData{
		BaseData:        p.baseData(r, "Настройки сервера", "admin-settings"),
		S:               t,
		RadiusSecretSet: t.RadiusSecret != "",
		SMTPPasswordSet: t.SMTP.Password != "",
		TGBotTokenSet:   t.TG.BotToken != "",
		LDAPPasswordSet: t.LDAP.BindPassword != "",
		// SEC-004: сырой JSON шлюза содержит креды — в textarea рендерится
		// маскированное дерево; POST с масками мерж оставляет без изменений.
		SMSGatewayJSON:   settings.MaskedJSONTree(t.SMS),
		SMSPresetsJSON:   settings.MaskedJSONTree(t.SMSPresets),
		SMSPresetChoices: smsPresetChoices(),
		ReplyAttrsJSON:   replyJSON,
		LDAPAllowGroups:  allowJSON,
		LDAPRoleMap:      roleJSON,
	}
}

// smsPresetChoices — пресеты SMS-шлюзов для select на странице настроек:
// delivery.Presets() → web-тип (web не зависит от delivery). ConfigJSON —
// конфиг с пустыми кредами-заглушками; выбор пункта в UI подставляет его
// в textarea sms.gateway (app.js), администратор вписывает свои креды.
func smsPresetChoices() []web.SMSPresetChoice {
	list := delivery.Presets()
	out := make([]web.SMSPresetChoice, 0, len(list))
	for _, p := range list {
		b, err := json.Marshal(p.Config)
		if err != nil {
			continue // не может случиться: структура из строк и int
		}
		out = append(out, web.SMSPresetChoice{
			Name:        p.Name,
			Title:       p.Title,
			Description: p.Description,
			ConfigJSON:  string(b),
		})
	}
	return out
}

// settingsField — одно поле формы /admin/settings: имя поля формы (то же,
// что рендерит шаблон admin_settings.gohtml), ключ настроек (объектный или
// скалярный) и тип значения. JSON-поле объектного ключа выводится из имени
// отсечением префикса «key.» (поле smtp.host → ключ smtp, поле host).
// kind 'n' — вложенное поле второго уровня: имя «key.group.field» пишется
// в JSON-объект {group: {field: …}} (ldap.attrs.email → attrs.email).
type settingsField struct {
	name string // имя поля формы (совпадает с шаблоном)
	key  string // ключ настроек (объектный или скалярный)
	kind byte   // 's' строка (по умолчанию), 'i' целое, 'b' чекбокс, 'j' сырой JSON, 'n' вложенное поле
}

// setPartialField записывает значение поля формы в карту «JSON-поле →
// значение» объектного ключа; dotted-имена после префикса ключа дают
// вложенные объекты (ldap.attrs.email → {"attrs":{"email":…}}).
func setPartialField(partial map[string]map[string]json.RawMessage, key, name string, v json.RawMessage) {
	if partial[key] == nil {
		partial[key] = make(map[string]json.RawMessage)
	}
	rest := strings.TrimPrefix(name, key+".")
	if i := strings.IndexByte(rest, '.'); i >= 0 {
		group := rest[:i]
		if partial[key][group] == nil {
			partial[key][group] = json.RawMessage("{}")
		}
		var nested map[string]json.RawMessage
		if err := json.Unmarshal(partial[key][group], &nested); err != nil || nested == nil {
			nested = make(map[string]json.RawMessage)
		}
		nested[rest[i+1:]] = v
		b, err := json.Marshal(nested)
		if err == nil {
			partial[key][group] = b
		}
		return
	}
	partial[key][rest] = v
}

// settingsForm — поля форм по секциям; имена В ТОЧНОСТИ как в шаблоне
// admin_settings.gohtml (контракт проверяет TestPagesAdminSettingsFormContract:
// расхождение имени = молчаливая потеря значения при сохранении).
var settingsForm = map[string][]settingsField{
	"listen": {
		{name: "listen.http", key: "listen.http"},
		{name: "listen.radius_auth", key: "listen.radius_auth"},
		{name: "listen.radius_acct", key: "listen.radius_acct"},
	},
	"radius": {
		{name: "radius.secret", key: "radius.secret"},
		{name: "radius.code_lengths", key: "radius.code_lengths", kind: 'j'},
		{name: "radius.max_fail_per_user", key: "radius.max_fail_per_user", kind: 'i'},
		{name: "radius.fail_window", key: "radius.fail_window"},
		{name: "radius.push_wait", key: "radius.push_wait"},
		{name: "radius.reply_attributes", key: "radius.reply_attributes", kind: 'j'},
	},
	"proxy": {
		{name: "proxy.trusted_networks", key: "proxy"},
	},
	"branding": {
		{name: "branding.name", key: "branding"},
		{name: "branding.mark", key: "branding"},
		{name: "branding.logo", key: "branding"},
		{name: "branding.description", key: "branding"},
	},
	"ads": {
		{name: "ads.enabled", key: "ads", kind: 'b'},
		{name: "ads.provider", key: "ads"},
		{name: "ads.message_footer", key: "ads"},
		{name: "ads.direct.url", key: "ads"},
		{name: "ads.direct.urls", key: "ads"},
		{name: "ads.direct.label", key: "ads"},
		{name: "ads.direct.image", key: "ads"},
		{name: "ads.blocks.login_left", key: "ads"},
		{name: "ads.blocks.login_right", key: "ads"},
		{name: "ads.blocks.sidebar", key: "ads"},
	},
	"fail2ban": {
		{name: "fail2ban.enabled", key: "fail2ban", kind: 'b'},
		{name: "fail2ban.max_fail", key: "fail2ban", kind: 'i'},
		{name: "fail2ban.window", key: "fail2ban"},
		{name: "fail2ban.ban_time", key: "fail2ban"},
	},
	"messages": {
		{name: "server.domain", key: "server.domain"},
		{name: "messages.email_body", key: "messages"},
		{name: "messages.sms_text", key: "messages"},
		{name: "messages.telegram_code_text", key: "messages"},
		{name: "messages.telegram_push_text", key: "messages"},
	},
	"smtp": {
		{name: "smtp.host", key: "smtp"}, {name: "smtp.port", key: "smtp", kind: 'i'},
		{name: "smtp.user", key: "smtp"},
		{name: "smtp.password", key: "smtp"},
		{name: "smtp.from", key: "smtp"},
		{name: "smtp.subject", key: "smtp"},
		{name: "smtp.timeout", key: "smtp"},
		{name: "smtp.starttls", key: "smtp", kind: 'b'},
	},
	"sms": {
		{name: "sms.gateway", key: "sms.gateway", kind: 'j'},
		{name: "sms.presets", key: "sms.presets", kind: 'j'},
	},
	"telegram": {
		{name: "telegram.bot_token", key: "telegram"},
	},
	"totp": {
		{name: "totp.issuer", key: "totp"},
		{name: "totp.digits", key: "totp", kind: 'i'},
		{name: "totp.period", key: "totp", kind: 'i'},
		{name: "totp.skew", key: "totp", kind: 'i'},
	},
	"webauthn": {
		{name: "webauthn.rp_id", key: "webauthn"},
		{name: "webauthn.rp_name", key: "webauthn"},
		{name: "webauthn.origins", key: "webauthn", kind: 'j'},
	},
	"ldap": {
		{name: "ldap.enabled", key: "ldap", kind: 'b'},
		{name: "ldap.url", key: "ldap"},
		{name: "ldap.starttls", key: "ldap", kind: 'b'},
		{name: "ldap.bind_dn", key: "ldap"},
		{name: "ldap.bind_password", key: "ldap"},
		{name: "ldap.base_dn", key: "ldap"},
		{name: "ldap.user_filter", key: "ldap"},
		{name: "ldap.group_base_dn", key: "ldap"},
		{name: "ldap.group_filter", key: "ldap"},
		{name: "ldap.attrs.email", key: "ldap", kind: 'n'},
		{name: "ldap.attrs.phone", key: "ldap", kind: 'n'},
		{name: "ldap.attrs.display_name", key: "ldap", kind: 'n'},
		{name: "ldap.allow_groups", key: "ldap", kind: 'j'},
		{name: "ldap.role_map", key: "ldap", kind: 'j'},
	},
	"policy": {
		{name: "policy.code_ttl", key: "policy"},
		{name: "policy.code_length", key: "policy", kind: 'i'},
		{name: "policy.max_attempts", key: "policy", kind: 'i'},
		{name: "policy.resend_cooldown", key: "policy"},
		{name: "policy.push_cooldown", key: "policy"},
		{name: "policy.push_per_hour", key: "policy", kind: 'i'},
		{name: "policy.trusted_device_ttl", key: "policy"},
		{name: "policy.max_fail", key: "policy", kind: 'i'},
		{name: "policy.fail_window", key: "policy"},
		{name: "policy.ban_time", key: "policy"},
		{name: "policy.default_prefer_channels", key: "policy", kind: 'j'},
		{name: "web.session_ttl", key: "web.session_ttl"},
	},
}

// handleAdminSettingsPost — POST /admin/settings: секция формы → flatten в
// settings-ключи; пустые значения и маска «••••» = «не менять»; мерж с
// текущим значением (deep merge, как PUT JSON API) через m.Put. Кнопка
// regenerate — генерируемые секреты (admin_token/radius.secret), новое
// значение показывается один раз в теле ответа (не в redirect URL/flash).
func (p *PagesAPI) handleAdminSettingsPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		redirectFlash(w, r, "/admin/settings", "Некорректная форма.", false)
		return
	}
	ctx := r.Context()

	// Кнопка «Перегенерировать» (name=regenerate value=<key>).
	if key := r.PostFormValue("regenerate"); key != "" {
		if _, ok := regenerableKeys[key]; !ok {
			redirectFlash(w, r, "/admin/settings", "Этот ключ нельзя перегенерировать.", false)
			return
		}
		val := secrets.RandomToken(tokenBytes)
		b, err := json.Marshal(val)
		if err == nil {
			err = p.m.Put(ctx, key, b)
		}
		if err != nil {
			flash500(w, r, "/admin/settings", err)
			return
		}
		p.admin.audit(ctx, "settings_regenerate", map[string]any{"key": key, "via": "html"})
		// Новое значение рендерится в ТЕЛЕ ответа (200) ровно один раз:
		// редирект с ним в query уносил бы секрет в Location, историю
		// браузера и логи прокси. Остальная страница — как при GET (маски).
		d := p.adminSettingsData(r)
		d.OneTimeLabel = key
		d.OneTimeValue = val
		p.render(w, http.StatusOK, "admin_settings", d)
		return
	}

	fields, ok := settingsForm[r.PostFormValue("section")]
	if !ok {
		redirectFlash(w, r, "/admin/settings", "Неизвестная секция настроек.", false)
		return
	}

	// Частичные значения по ключам настроек: скалярный ключ — значение
	// целиком, объектный — карта «JSON-поле → значение» (имя формы без
	// префикса «key.», потом deep merge).
	scalar := map[string]json.RawMessage{}
	partial := map[string]map[string]json.RawMessage{}
	for _, f := range fields {
		raw := strings.TrimSpace(r.PostFormValue(f.name))
		if f.kind == 'b' {
			// Чекбокс: отсутствие в форме — явное «выключено».
			v, _ := json.Marshal(r.PostFormValue(f.name) != "")
			setPartialField(partial, f.key, f.name, v)
			continue
		}
		if raw == "" || raw == settingsMask {
			continue // пустое/маска — «не менять» (спека §7)
		}
		var v json.RawMessage
		switch f.kind {
		case 'i':
			n, err := strconv.Atoi(raw)
			if err != nil {
				redirectFlash(w, r, "/admin/settings",
					"Поле "+f.name+": ожидается целое число.", false)
				return
			}
			v, _ = json.Marshal(n)
		case 'j':
			if !json.Valid([]byte(raw)) {
				redirectFlash(w, r, "/admin/settings",
					"Поле "+f.name+": неверный JSON.", false)
				return
			}
			v = json.RawMessage(raw)
		default:
			v, _ = json.Marshal(raw)
		}
		if f.name == f.key {
			scalar[f.key] = v
		} else {
			setPartialField(partial, f.key, f.name, v)
		}
	}

	changed := make([]string, 0, len(scalar)+len(partial))
	apply := func(key string, inc json.RawMessage) bool {
		if !settings.IsKnownKey(key) {
			redirectFlash(w, r, "/admin/settings", "Неизвестный ключ "+key+".", false)
			return false
		}
		merged, err := p.admin.mergedValue(ctx, key, inc)
		if err != nil {
			// Ошибка чтения БД — внутренняя, а не «неверное значение».
			flash500(w, r, "/admin/settings", err)
			return false
		}
		if err := p.m.Put(ctx, key, merged); err != nil {
			flash500(w, r, "/admin/settings", err)
			return false
		}
		changed = append(changed, key)
		return true
	}
	keys := make([]string, 0, len(scalar)+len(partial))
	for k := range scalar {
		keys = append(keys, k)
	}
	for k := range partial {
		if _, done := scalar[k]; done {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if v, done := scalar[key]; done {
			if !apply(key, v) {
				return
			}
			continue
		}
		obj, err := json.Marshal(partial[key])
		if err != nil {
			flash500(w, r, "/admin/settings", err)
			return
		}
		if !apply(key, obj) {
			return
		}
	}
	p.admin.audit(ctx, "settings_update", map[string]any{"keys": changed, "via": "html"})
	redirectFlash(w, r, "/admin/settings", "Настройки сохранены.", true)
}

// ---- админ: лицензия ----

// handleAdminLicense — GET /admin/license: статус-карточка (режим, клиент,
// lic_id, X/Y пользователей, демо/подписка/обновления до) + формы загрузки
// лицензии и CRL-отзыва (report §3.7).
func (p *PagesAPI) handleAdminLicense(w http.ResponseWriter, r *http.Request) {
	d := web.AdminLicenseData{BaseData: p.baseData(r, "Лицензия", "admin-license")}
	st, err := p.admin.licenseStatus(r)
	if err != nil {
		flash500(w, r, "/admin/license", err)
		return
	}
	d.Status = st
	if st.UserLimit <= 0 {
		d.LimitText = "не ограничено"
	} else {
		d.LimitText = fmt.Sprintf("%d/%d", st.UsersActive, st.UserLimit)
	}
	if !st.UpdatesUntil.IsZero() {
		d.UpdatesUntil = st.UpdatesUntil.Format("02.01.2006")
	}
	d.ModeText = map[license.Mode]string{
		license.ModeFree:     "Free — без лицензии",
		license.ModeTrial:    "Демо (30 дней, полный функционал)",
		license.ModeLicensed: "Лицензия",
	}[st.Mode]
	p.render(w, http.StatusOK, "admin_license", d)
}

// handleAdminLicensePost — POST /admin/license: do=upload|crl|remove.
// Ошибки проверки блоба — флешем на ту же страницу.
func (p *PagesAPI) handleAdminLicensePost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		redirectFlash(w, r, "/admin/license", "Некорректная форма.", false)
		return
	}
	ctx := r.Context()
	switch r.PostFormValue("do") {
	case "upload":
		blob := strings.TrimSpace(r.PostFormValue("blob"))
		if blob == "" {
			redirectFlash(w, r, "/admin/license", "Вставьте license-файл (содержимое -----BEGIN LIGAMENT LICENSE-----).", false)
			return
		}
		lic, err := p.admin.lic.Upload(ctx, blob)
		if err != nil {
			redirectFlash(w, r, "/admin/license", licenseErrText(err), false)
			return
		}
		p.admin.audit(ctx, "license_upload", map[string]any{
			"via": "html", "lic_id": lic.LicID, "plan": lic.Plan, "customer": lic.Customer,
		})
		redirectFlash(w, r, "/admin/license",
			"Лицензия загружена: "+lic.Customer+" ("+lic.Plan+").", true)

	case "crl":
		blob := strings.TrimSpace(r.PostFormValue("crl"))
		if blob == "" {
			redirectFlash(w, r, "/admin/license", "Вставьте CRL-файл (-----BEGIN LIGAMENT REVOCATION-----).", false)
			return
		}
		rev, err := p.admin.lic.UploadCRL(ctx, blob)
		if err != nil {
			redirectFlash(w, r, "/admin/license", licenseErrText(err), false)
			return
		}
		p.admin.audit(ctx, "license_crl_upload", map[string]any{"via": "html", "lic_id": rev.LicID})
		redirectFlash(w, r, "/admin/license", "CRL-отзыв принят: "+rev.LicID+".", true)

	case "remove":
		if err := p.admin.lic.Remove(ctx); err != nil {
			flash500(w, r, "/admin/license", err)
			return
		}
		p.admin.audit(ctx, "license_remove", map[string]any{"via": "html"})
		redirectFlash(w, r, "/admin/license", "Лицензия удалена — сервер работает в бесплатном режиме (5 пользователей).", true)

	default:
		redirectFlash(w, r, "/admin/license", "Неизвестное действие.", false)
	}
}

// licenseErrText — русские тексты ошибок загрузки блоба.
func licenseErrText(err error) string {
	switch {
	case errors.Is(err, license.ErrMalformed):
		return "Некорректный формат license-файла."
	case errors.Is(err, license.ErrBadSignature), errors.Is(err, license.ErrUnknownKid):
		return "Подпись лицензии не прошла проверку (неверный файл или ключ)."
	case errors.Is(err, license.ErrRevoked):
		return "Лицензия отозвана (CRL) — загрузите новую."
	default:
		slog.Error("pages: загрузка лицензии", "error", err)
		return "Внутренняя ошибка, попробуйте позже."
	}
}

// ---- админка: файрвол/fail2ban ----

// handleAdminFirewall — GET /admin/firewall.
func (p *PagesAPI) handleAdminFirewall(w http.ResponseWriter, r *http.Request) {
	lists, err := p.st.IPLists(r.Context())
	if err != nil {
		flash500(w, r, "/admin/firewall", err)
		return
	}
	bans, err := p.st.BansActive(r.Context())
	if err != nil {
		flash500(w, r, "/admin/firewall", err)
		return
	}
	var allow, deny []store.IPList
	for _, l := range lists {
		if l.Kind == "allow" {
			allow = append(allow, l)
		} else {
			deny = append(deny, l)
		}
	}
	p.render(w, http.StatusOK, "admin_firewall", web.AdminFirewallData{
		BaseData: p.baseData(r, "Файрвол", "admin-firewall"),
		Allow:    allow, Deny: deny, Bans: bans,
	})
}

// handleAdminFirewallIPAdd — POST /admin/firewall/ip (form: kind, cidr, note).
func (p *PagesAPI) handleAdminFirewallIPAdd(w http.ResponseWriter, r *http.Request) {
	kind := r.PostFormValue("kind")
	cidr := strings.TrimSpace(r.PostFormValue("cidr"))
	note := strings.TrimSpace(r.PostFormValue("note"))
	if kind != "allow" && kind != "deny" {
		redirectFlash(w, r, "/admin/firewall", "Список может быть allow или deny.", false)
		return
	}
	row, err := p.st.IPListAdd(r.Context(), kind, cidr, note)
	if err != nil {
		redirectFlash(w, r, "/admin/firewall", "Некорректный IP или CIDR: "+cidr, false)
		return
	}
	if p.fw != nil {
		p.fw.Invalidate()
	}
	p.auditPage(r.Context(), "admin", "firewall_ip_add", clientIP(r), "ok",
		map[string]any{"kind": kind, "cidr": row.CIDR})
	redirectFlash(w, r, "/admin/firewall", "Добавлено в список "+kind+": "+row.CIDR, true)
}

// handleAdminFirewallIPDelete — POST /admin/firewall/ip/{id}/delete.
func (p *PagesAPI) handleAdminFirewallIPDelete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		redirectFlash(w, r, "/admin/firewall", "Некорректный id.", false)
		return
	}
	if err := p.st.IPListDelete(r.Context(), id); err != nil {
		redirectFlash(w, r, "/admin/firewall", "Запись не найдена.", false)
		return
	}
	if p.fw != nil {
		p.fw.Invalidate()
	}
	redirectFlash(w, r, "/admin/firewall", "Запись удалена.", true)
}

// handleAdminFirewallUnban — POST /admin/firewall/bans/{ip}/delete.
func (p *PagesAPI) handleAdminFirewallUnban(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	if net.ParseIP(ip) == nil {
		redirectFlash(w, r, "/admin/firewall", "Некорректный IP.", false)
		return
	}
	if err := p.st.BanDelete(r.Context(), ip); err != nil {
		flash500(w, r, "/admin/firewall", err)
		return
	}
	p.auditPage(r.Context(), "admin", "firewall_unban", clientIP(r), "ok",
		map[string]any{"ip": ip})
	redirectFlash(w, r, "/admin/firewall", "Бан снят: "+ip, true)
}

// ---- админка: OpenID Connect ----

// handleAdminOIDC — GET /admin/oidc: список клиентских приложений и форма
// создания.
func (p *PagesAPI) handleAdminOIDC(w http.ResponseWriter, r *http.Request) {
	clients, err := p.st.OIDCClients(r.Context())
	if err != nil {
		flash500(w, r, "/admin/oidc", err)
		return
	}
	p.render(w, http.StatusOK, "admin_oidc", web.AdminOIDCClientsData{
		BaseData: p.baseData(r, "OIDC", "admin-oidc"),
		Clients:  clients,
	})
}

// handleAdminOIDCClientCreate — POST /admin/oidc/clients (form: name,
// redirect_uris по одному в строке, is_public). Секрет показывается ровно
// один раз — ответ 200 телом страницы (без PRG-редиректа, иначе секрет
// пришлось бы класть в URL).
func (p *PagesAPI) handleAdminOIDCClientCreate(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	name := strings.TrimSpace(r.PostFormValue("name"))
	var uris []string
	for _, line := range strings.Split(r.PostFormValue("redirect_uris"), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			uris = append(uris, line)
		}
	}
	isPublic := r.PostFormValue("is_public") != ""

	renderErr := func(msg string) {
		clients, err := p.st.OIDCClients(r.Context())
		if err != nil {
			flash500(w, r, "/admin/oidc", err)
			return
		}
		p.render(w, http.StatusBadRequest, "admin_oidc", web.AdminOIDCClientsData{
			BaseData: func() web.BaseData {
				b := p.baseData(r, "OIDC", "admin-oidc")
				b.FlashErr = msg
				return b
			}(),
			Clients: clients,
		})
	}
	if name == "" {
		renderErr("Введите название приложения.")
		return
	}
	uris, err := validateRedirectURIs(uris)
	if err != nil {
		renderErr("Каждый redirect_uri должен быть абсолютным http(s)-URL.")
		return
	}

	c := &store.OIDCClient{
		ClientID:     oidc.NewClientID(),
		Name:         name,
		RedirectURIs: uris,
		IsPublic:     isPublic,
	}
	d := web.AdminOIDCClientsData{
		BaseData:        p.baseData(r, "OIDC", "admin-oidc"),
		OneTimeClientID: c.ClientID,
	}
	if !isPublic {
		secret := oidc.NewClientSecret()
		c.ClientSecretHash = oidc.HashClientSecret(secret)
		d.OneTimeSecret = secret
	}
	if err := p.st.OIDCClientUpsert(r.Context(), c); err != nil {
		flash500(w, r, "/admin/oidc", err)
		return
	}
	p.auditPage(r.Context(), "admin", "oidc_client_create", clientIP(r), "ok",
		map[string]any{"client_id": c.ClientID, "via": "html"})
	d.Clients, err = p.st.OIDCClients(r.Context())
	if err != nil {
		flash500(w, r, "/admin/oidc", err)
		return
	}
	p.render(w, http.StatusOK, "admin_oidc", d)
}

// handleAdminOIDCClientDelete — POST /admin/oidc/clients/{id}/delete.
func (p *PagesAPI) handleAdminOIDCClientDelete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		redirectFlash(w, r, "/admin/oidc", "Некорректный id.", false)
		return
	}
	if err := p.st.OIDCClientDelete(r.Context(), id); err != nil {
		redirectFlash(w, r, "/admin/oidc", "Клиент не найден.", false)
		return
	}
	p.auditPage(r.Context(), "admin", "oidc_client_delete", clientIP(r), "ok",
		map[string]any{"id": id.String()})
	redirectFlash(w, r, "/admin/oidc", "Клиент удалён.", true)
}
