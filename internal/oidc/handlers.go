// HTTP-эндпоинты OIDC Provider: discovery, JWKS, authorize (страница
// согласия поверх web-сессии), token, userinfo. Маршруты публичные (без
// admin-токена); авторизация пользователя — та же cookie twofa_session,
// что и в web-интерфейсе.
package oidc

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-ldap/ldap/v3"

	"github.com/aligorov/twofa/internal/firewall"
	"github.com/aligorov/twofa/internal/secrets"
	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
	"github.com/aligorov/twofa/internal/web"
)

// Сроки жизни одноразовых артефактов флоу.
const (
	// codeTTL — authorization-код живёт минуту: хватит на мгновенный
	// обмен, угона окна почти нет.
	codeTTL = 60 * time.Second
	// accessTokenTTL — access-токен /userinfo (совпадает с expires_in).
	accessTokenTTL = 5 * time.Minute
)

// cookieSession — имя cookie web-сессии (дублирует api.cookieSession:
// api импортирует oidc, константа сюда не пробрасывается).
const cookieSession = "twofa_session"

// Register монтирует публичные маршруты OIDC. Метод nil-безопасен:
// менеджер без ключей (компонент не смонтирован) оставляет маршруты на
// месте — все отвечают 503 oidc_disabled (роуты присутствуют в роутере и
// контракте OpenAPI независимо от конфигурации).
// Публичные JSON-эндпоинты (discovery, JWKS, token, userinfo) поддерживают CORS (RFC 8414 §3)
// для работы браузерных SPA-клиентов и инструментов тестирования (openidconnect.net).
func (mgr *Manager) Register(r chi.Router) {
	cors := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept")
			h(w, r)
		}
	}

	r.Get("/.well-known/openid-configuration", cors(mgr.serve(mgr.handleDiscovery)))
	r.Get("/.well-known/jwks.json", cors(mgr.serve(mgr.handleJWKS)))
	r.Get("/oidc/authorize", mgr.serve(mgr.handleAuthorize))
	r.Post("/oidc/authorize/confirm", mgr.serve(mgr.handleAuthorizeConfirm))
	r.Post("/oidc/token", cors(mgr.serve(mgr.handleToken)))
	r.Get("/oidc/userinfo", cors(mgr.serve(mgr.handleUserinfo)))

	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	})
}

// serve — обёртка nil-проверки менеджера (см. Register).
func (mgr *Manager) serve(h http.HandlerFunc) http.HandlerFunc {
	if mgr == nil {
		return func(w http.ResponseWriter, _ *http.Request) {
			writeOIDCError(w, http.StatusServiceUnavailable, "oidc_disabled")
		}
	}
	return h
}

// ---- общие помощники ----

// writeJSON пишет JSON-ответ с кодом.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeOIDCError — ошибка флоу в формате RFC 6749 §5.2: {"error":"..."}.
func writeOIDCError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

// clientIP — IP клиента для аудита и уведомлений: контекст файрвола
// (реальный IP за доверенным прокси) приоритетнее сокета.
func (mgr *Manager) clientIP(r *http.Request) string {
	if ip := firewall.IPFrom(r.Context()); ip != "" {
		return ip
	}
	var snap *settings.T
	if mgr != nil && mgr.m != nil {
		snap = mgr.m.Get()
	}
	return firewall.RealIPFrom(r, snap)
}

// audit пишет событие аудита, не ломая основной поток.
func (mgr *Manager) audit(r *http.Request, username, event, result string, detail map[string]any) {
	if err := mgr.st.Audit(r.Context(), username, event, detail, mgr.clientIP(r), result); err != nil {
		slog.Warn("oidc: аудит не записан", "event", event, "error", err)
	}
}

// issuer — базовый URL сервера: настройка server.domain, иначе схема+Host
// запроса (снимок настроек читается на каждый запрос — это дёшево, а
// смена domain применяется без рестарта).
func (mgr *Manager) issuer(r *http.Request) string {
	if mgr == nil || mgr.m == nil {
		return issuerFrom("", r)
	}
	return issuerFrom(mgr.m.Get().Server.Domain, r)
}

// issuerFrom — вычисление issuer: domain из настроек (без хвостового
// слэша), при пустом — «scheme://host» запроса (https при TLS).
func issuerFrom(domain string, r *http.Request) string {
	if d := strings.TrimRight(domain, "/"); d != "" {
		return d
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// renderPage рендерит HTML-страницу web-интерфейса.
func (mgr *Manager) renderPage(w http.ResponseWriter, status int, page string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := mgr.rend.Render(w, page, data); err != nil {
		slog.Error("oidc: рендер страницы", "page", page, "error", err)
	}
}

// renderErrorPage — страница ошибки 400 (ошибки клиента: неизвестный
// client_id, чужой redirect_uri — редиректить нельзя никуда).
func (mgr *Manager) renderErrorPage(w http.ResponseWriter, r *http.Request, status int, msg string) {
	mgr.renderPage(w, status, "error", web.ErrorData{
		BaseData: web.BaseData{Title: "Ошибка", Nav: ""},
		Code:     status,
		Message:  msg,
	})
}

// sessionUser — пользователь web-сессии по cookie twofa_session
// (включая отключённых: requirePage инвариант «отключённый теряет
// сессию»). Возвращает пользователя, CSRF и момент входа (auth_time).
func (mgr *Manager) sessionUser(r *http.Request) (*store.User, string, time.Time, bool) {
	c, err := r.Cookie(cookieSession)
	if err != nil || c.Value == "" {
		return nil, "", time.Time{}, false
	}
	userID, csrf, createdAt, err := mgr.st.OIDCSessionInfo(r.Context(), secrets.SHA256(c.Value))
	if err != nil {
		return nil, "", time.Time{}, false
	}
	user, err := mgr.st.UserByID(r.Context(), userID)
	if err != nil || !user.Enabled {
		return nil, "", time.Time{}, false
	}
	return user, csrf, createdAt, true
}

// redirectWithError — редирект на redirect_uri с error/state (ошибки
// запроса при ВАЛИДНОМ клиенте; RFC 6749 §4.1.2.1).
func redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, code, state string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "некорректный redirect_uri", http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("error", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// ---- discovery и JWKS ----

// handleDiscovery — GET /.well-known/openid-configuration: метаданные
// провайдера (issuer, эндпоинты, поддерживаемые scope/методы).
func (mgr *Manager) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	iss := mgr.issuer(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                iss,
		"authorization_endpoint":                iss + "/oidc/authorize",
		"token_endpoint":                        iss + "/oidc/token",
		"userinfo_endpoint":                     iss + "/oidc/userinfo",
		"jwks_uri":                              iss + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"plain", "S256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
	})
}

// handleJWKS — GET /.well-known/jwks.json: публичный ключ проверки
// подписи ID-токенов.
func (mgr *Manager) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, mgr.JWKS())
}

// ---- authorize ----

// authorizeReq — параметры запроса /oidc/authorize (общие для GET и
// подтверждения согласия: форма подтверждения проксирует их скрытыми
// полями).
type authorizeReq struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
}

// authorizeReqFromValues собирает запрос из query или полей формы
// (ключи совпадают).
func authorizeReqFromValues(get func(string) string) authorizeReq {
	return authorizeReq{
		ClientID:            get("client_id"),
		RedirectURI:         get("redirect_uri"),
		ResponseType:        get("response_type"),
		Scope:               strings.Join(strings.Fields(get("scope")), " "),
		State:               get("state"),
		Nonce:               get("nonce"),
		CodeChallenge:       get("code_challenge"),
		CodeChallengeMethod: get("code_challenge_method"),
	}
}

// hiddenFields — параметры запроса для скрытых полей формы согласия.
func (ar authorizeReq) hiddenFields() []web.FormField {
	return []web.FormField{
		{Key: "client_id", Val: ar.ClientID},
		{Key: "redirect_uri", Val: ar.RedirectURI},
		{Key: "response_type", Val: ar.ResponseType},
		{Key: "scope", Val: ar.Scope},
		{Key: "state", Val: ar.State},
		{Key: "nonce", Val: ar.Nonce},
		{Key: "code_challenge", Val: ar.CodeChallenge},
		{Key: "code_challenge_method", Val: ar.CodeChallengeMethod},
	}
}

// authorizeURL — полный URL authorize для возврата после входа
// (?next=... страницы /login).
func (ar authorizeReq) authorizeURL() string {
	q := url.Values{}
	for _, f := range ar.hiddenFields() {
		if f.Val != "" {
			q.Set(f.Key, f.Val)
		}
	}
	return "/oidc/authorize?" + q.Encode()
}

// firstRuneUpper возвращает первый символ строки в верхнем регистре (безопасно для UTF-8 / кириллицы).
func firstRuneUpper(s string) string {
	s = strings.TrimSpace(s)
	for _, r := range s {
		return strings.ToUpper(string(r))
	}
	return ""
}

// scopeDescriptions — человекочитаемые описания scope для страницы
// согласия (для обратной совместимости).
func scopeDescriptions(scope string) []string {
	out := []string{"подтверждение вашей личности (openid)"}
	if HasScope(scope, "profile") {
		out = append(out, "профиль: имя пользователя и роль (profile)")
	}
	if HasScope(scope, "email") {
		out = append(out, "адрес электронной почты (email)")
	}
	return out
}

// scopeDetails возвращает структурированные описания scope с иконками и понятными текстами.
func scopeDetails(scope string) []web.OIDCScopeInfo {
	details := []web.OIDCScopeInfo{
		{
			Scope:       "openid",
			Title:       "Подтверждение личности (OpenID)",
			Description: "Уникальный идентификатор учётной записи (sub) для авторизации в приложении",
			Icon:        "🪪",
		},
	}
	if HasScope(scope, "profile") {
		details = append(details, web.OIDCScopeInfo{
			Scope:       "profile",
			Title:       "Данные профиля (profile)",
			Description: "Имя пользователя, отображаемое имя и системная роль в организации",
			Icon:        "👤",
		})
	}
	if HasScope(scope, "email") {
		details = append(details, web.OIDCScopeInfo{
			Scope:       "email",
			Title:       "Адрес электронной почты (email)",
			Description: "Основной почтовый ящик для авторизации и служебных уведомлений",
			Icon:        "✉️",
		})
	}
	for _, s := range strings.Fields(scope) {
		if s != "openid" && s != "profile" && s != "email" {
			details = append(details, web.OIDCScopeInfo{
				Scope:       s,
				Title:       s,
				Description: "Дополнительное разрешение, запрошенное внешним приложением",
				Icon:        "🔑",
			})
		}
	}
	return details
}

// validateAuthorize проверяет запрос при УЖЕ найденном валидном клиенте
// (ошибки — редирект с error). Возвращает машинный код ошибки или "".
func validateAuthorize(ar authorizeReq, client *store.OIDCClient) string {
	switch {
	case ar.ResponseType != "code":
		return "unsupported_response_type"
	case !HasScope(ar.Scope, "openid"):
		return "invalid_scope"
	case ar.CodeChallenge == "" && ar.CodeChallengeMethod != "",
		ar.CodeChallenge != "" && ar.CodeChallengeMethod != "S256" && ar.CodeChallengeMethod != "plain":
		return "invalid_request"
	case client.IsPublic && (ar.CodeChallenge == "" || ar.CodeChallengeMethod != "S256"):
		// Public-клиент не имеет секрета — единственная защита обмена,
		// PKCE S256 обязателен.
		return "invalid_request"
	}
	return ""
}

// loadClient — клиент по client_id; ошибки КЛИЕНТА (неизвестный id,
// чужой redirect_uri) рендерятся страницей 400 без редиректа (куда бы мы
// ни перенаправляли — адрес не проверен). Возвращает nil, если ответ уже
// отправлен.
func (mgr *Manager) loadClient(w http.ResponseWriter, r *http.Request, ar authorizeReq) *store.OIDCClient {
	client, err := mgr.st.OIDCClientByClientID(r.Context(), ar.ClientID)
	if errors.Is(err, store.ErrNotFound) {
		mgr.renderErrorPage(w, r, http.StatusBadRequest,
			"Неизвестное клиентское приложение (client_id).")
		return nil
	}
	if err != nil {
		slog.Error("oidc: чтение клиента", "error", err)
		mgr.renderErrorPage(w, r, http.StatusInternalServerError, "Внутренняя ошибка, попробуйте позже.")
		return nil
	}
	if !containsString(client.RedirectURIs, ar.RedirectURI) {
		// redirect_uri не зарегистрирован — редиректить на него нельзя
		// (открытый редирект): страница ошибки.
		mgr.renderErrorPage(w, r, http.StatusBadRequest,
			"redirect_uri не зарегистрирован для этого приложения.")
		return nil
	}
	return client
}

// containsString — точное вхождение строки в срез.
func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// dnEqual сравнивает DN по правилам RFC 4517: регистр типов и значений не значим.
func dnEqual(a, b string) bool {
	dnA, errA := ldap.ParseDN(a)
	dnB, errB := ldap.ParseDN(b)
	if errA == nil && errB == nil {
		return dnA.EqualFold(dnB)
	}
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

// groupCN — значение первого RDN записи группы (обычно CN).
func groupCN(dn string) string {
	if parsed, err := ldap.ParseDN(dn); err == nil && len(parsed.RDNs) > 0 && len(parsed.RDNs[0].Attributes) > 0 {
		return parsed.RDNs[0].Attributes[0].Value
	}
	if i := strings.IndexByte(dn, '='); i >= 0 {
		v := dn[i+1:]
		if j := strings.IndexByte(v, ','); j >= 0 {
			v = v[:j]
		}
		return v
	}
	return dn
}

// uniqueStrings удаляет дубликаты из среза строк с сохранением порядка.
func uniqueStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

// isUserAllowed проверяет доступ пользователя к OIDC-клиенту.
// Если allowed_users и allowed_groups пусты — доступ разрешён всем.
// Пользователи с системной ролью "admin" имеют доступ всегда.
func (mgr *Manager) isUserAllowed(ctx context.Context, u *store.User, client *store.OIDCClient) bool {
	if u.Role == "admin" {
		return true
	}
	if len(client.AllowedUsers) == 0 && len(client.AllowedGroups) == 0 {
		return true
	}

	for _, au := range client.AllowedUsers {
		if strings.EqualFold(strings.TrimSpace(au), u.Username) {
			return true
		}
	}

	if len(client.AllowedGroups) > 0 {
		if mgr.st != nil {
			if localGroups, err := mgr.st.UserGroupNames(ctx, u.ID); err == nil {
				for _, lg := range localGroups {
					for _, ag := range client.AllowedGroups {
						if strings.EqualFold(strings.TrimSpace(ag), lg) {
							return true
						}
					}
				}
			}
		}

		for _, ug := range u.LDAPGroups {
			ugTrim := strings.TrimSpace(ug)
			ugCN := groupCN(ugTrim)
			for _, ag := range client.AllowedGroups {
				agTrim := strings.TrimSpace(ag)
				if strings.EqualFold(agTrim, ugTrim) ||
					(ugCN != "" && strings.EqualFold(agTrim, ugCN)) ||
					(strings.Contains(agTrim, "=") && dnEqual(agTrim, ugTrim)) {
					return true
				}
			}
		}
	}

	return false
}

// handleAuthorize — GET /oidc/authorize: валидация клиента и запроса,
// без сессии — редирект на /login?next=<authorize>, с сессией — страница
// согласия.
func (mgr *Manager) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	ar := authorizeReqFromValues(r.URL.Query().Get)
	client := mgr.loadClient(w, r, ar)
	if client == nil {
		return
	}
	if code := validateAuthorize(ar, client); code != "" {
		redirectWithError(w, r, ar.RedirectURI, code, ar.State)
		return
	}

	user, csrf, _, ok := mgr.sessionUser(r)
	if !ok {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(ar.authorizeURL()), http.StatusFound)
		return
	}
	if !mgr.isUserAllowed(r.Context(), user, client) {
		mgr.audit(r, user.Username, "oidc_access_denied", "forbidden", map[string]any{
			"client_id": client.ClientID,
		})
		mgr.renderErrorPage(w, r, http.StatusForbidden, "Доступ к приложению ограничен. У вашей учётной записи нет прав для входа.")
		return
	}
	mgr.renderConsent(w, r, ar, client, user, csrf)
}

// renderConsent — страница согласия «Приложение X запрашивает вход».
func (mgr *Manager) renderConsent(w http.ResponseWriter, r *http.Request, ar authorizeReq, client *store.OIDCClient, user *store.User, csrf string) {
	base := web.BaseData{Title: "Вход в приложение", Username: user.Username, CSRF: csrf}
	if mgr.ads != nil {
		base.Ads = mgr.ads(r)
	}
	if mgr.brand != nil {
		base.Brand = mgr.brand(r)
	}

	redirectHost := ""
	if u, err := url.Parse(ar.RedirectURI); err == nil && u.Host != "" {
		redirectHost = u.Host
	}

	clientName := client.Name
	if strings.TrimSpace(clientName) == "" {
		clientName = client.ClientID
	}

	userInitial := firstRuneUpper(user.DisplayName)
	if userInitial == "" {
		userInitial = firstRuneUpper(user.Username)
	}

	mgr.renderPage(w, http.StatusOK, "oidc_consent", web.OIDCConsentData{
		BaseData:        base,
		ClientName:      clientName,
		ClientID:        client.ClientID,
		ClientInitial:   firstRuneUpper(clientName),
		RedirectURI:     ar.RedirectURI,
		RedirectHost:    redirectHost,
		UserDisplayName: user.DisplayName,
		UserEmail:       user.Email,
		UserInitial:     userInitial,
		Scopes:          scopeDescriptions(ar.Scope),
		ScopeDetails:    scopeDetails(ar.Scope),
		Fields:          ar.hiddenFields(),
	})
}

// handleAuthorizeConfirm — POST /oidc/authorize/confirm: подтверждение
// согласия (CSRF + сессия) → выпуск authorization-кода и редирект на
// redirect_uri?code=...&state=....
func (mgr *Manager) handleAuthorizeConfirm(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		mgr.renderErrorPage(w, r, http.StatusBadRequest, "Некорректная форма.")
		return
	}
	ar := authorizeReqFromValues(r.PostFormValue)

	user, csrf, authTime, ok := mgr.sessionUser(r)
	if !ok {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(ar.authorizeURL()), http.StatusFound)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.PostFormValue("csrf_token")), []byte(csrf)) != 1 {
		http.Error(w, "запрос без CSRF-токена сессии", http.StatusForbidden)
		return
	}

	client := mgr.loadClient(w, r, ar)
	if client == nil {
		return
	}
	if code := validateAuthorize(ar, client); code != "" {
		redirectWithError(w, r, ar.RedirectURI, code, ar.State)
		return
	}
	if !mgr.isUserAllowed(r.Context(), user, client) {
		mgr.audit(r, user.Username, "oidc_access_denied", "forbidden", map[string]any{
			"client_id": client.ClientID,
		})
		mgr.renderErrorPage(w, r, http.StatusForbidden, "Доступ к приложению ограничен. У вашей учётной записи нет прав для входа.")
		return
	}

	code := secrets.RandomToken(32)
	if err := mgr.st.OIDCCodeSave(r.Context(), secrets.SHA256(code), &store.OIDCCode{
		ClientID:            client.ClientID,
		UserID:              user.ID,
		RedirectURI:         ar.RedirectURI,
		Scope:               FilterScopes(ar.Scope),
		Nonce:               ar.Nonce,
		AuthTime:            authTime,
		AMR:                 defaultAMR,
		CodeChallenge:       ar.CodeChallenge,
		CodeChallengeMethod: ar.CodeChallengeMethod,
	}, codeTTL); err != nil {
		slog.Error("oidc: сохранение кода", "error", err)
		redirectWithError(w, r, ar.RedirectURI, "server_error", ar.State)
		return
	}
	mgr.audit(r, user.Username, "oidc_consent", "ok", map[string]any{
		"client_id": client.ClientID, "scope": FilterScopes(ar.Scope),
	})

	if mgr.notifier != nil {
		appName := client.Name
		if strings.TrimSpace(appName) == "" {
			appName = client.ClientID
		}
		mgr.notifier.NotifyLoginSuccess(
			context.WithoutCancel(r.Context()),
			user.Username,
			"OIDC ("+appName+")",
			mgr.clientIP(r),
			r.UserAgent(),
		)
	}

	u, err := url.Parse(ar.RedirectURI)
	if err != nil {
		http.Error(w, "некорректный redirect_uri", http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("code", code)
	if ar.State != "" {
		q.Set("state", ar.State)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// ---- token ----

// handleToken — POST /oidc/token (grant_type=authorization_code):
// аутентификация клиента (Basic или form; public — только PKCE),
// атомарное погашение кода, проверка PKCE, выпуск access-токена и
// подписанного ID-токена. Ошибки — RFC 6749 §5.2.
func (mgr *Manager) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOIDCError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if r.PostFormValue("grant_type") != "authorization_code" {
		writeOIDCError(w, http.StatusBadRequest, "unsupported_grant_type")
		return
	}

	// Аутентификация клиента: Basic приоритетен над form-параметрами.
	clientID, clientSecret := r.PostFormValue("client_id"), r.PostFormValue("client_secret")
	if bid, bsec, ok := r.BasicAuth(); ok {
		// RFC 6749 §2.3.1: значения кодируются application/x-www-form-urlencoded.
		if dec, err := url.QueryUnescape(bid); err == nil {
			bid = dec
		}
		if dec, err := url.QueryUnescape(bsec); err == nil {
			bsec = dec
		}
		clientID, clientSecret = bid, bsec
	}
	client, err := mgr.st.OIDCClientByClientID(r.Context(), clientID)
	if errors.Is(err, store.ErrNotFound) {
		w.Header().Set("WWW-Authenticate", `Basic realm="oidc"`)
		writeOIDCError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	if err != nil {
		slog.Error("oidc: чтение клиента (token)", "error", err)
		writeOIDCError(w, http.StatusInternalServerError, "server_error")
		return
	}
	if !client.IsPublic {
		// Конфиденциальный клиент обязан предъявить верный секрет
		// (хеш — постоянное время).
		if !VerifyClientSecret(client.ClientSecretHash, clientSecret) {
			w.Header().Set("WWW-Authenticate", `Basic realm="oidc"`)
			writeOIDCError(w, http.StatusUnauthorized, "invalid_client")
			return
		}
	}

	code := r.PostFormValue("code")
	redirectURI := r.PostFormValue("redirect_uri")
	verifier := r.PostFormValue("code_verifier")
	if code == "" || redirectURI == "" {
		writeOIDCError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	// Погашение кода атомарно: повторное использование, истёкший и
	// неизвестный код неотличимы (invalid_grant).
	claimed, err := mgr.st.OIDCCodeClaim(r.Context(), secrets.SHA256(code))
	if errors.Is(err, store.ErrNotFound) {
		writeOIDCError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	if err != nil {
		slog.Error("oidc: погашение кода", "error", err)
		writeOIDCError(w, http.StatusInternalServerError, "server_error")
		return
	}
	if claimed.ClientID != client.ClientID || claimed.RedirectURI != redirectURI {
		writeOIDCError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	if !VerifyPKCE(claimed.CodeChallenge, claimed.CodeChallengeMethod, verifier) {
		writeOIDCError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	user, err := mgr.st.UserByID(r.Context(), claimed.UserID)
	if err != nil {
		// Пользователь удалён после выдачи кода.
		writeOIDCError(w, http.StatusBadRequest, "invalid_grant")
		return
	}

	access := secrets.RandomToken(32)
	if err := mgr.st.OIDCTokenSave(r.Context(), secrets.SHA256(access), &store.OIDCToken{
		UserID:   user.ID,
		ClientID: client.ClientID,
		Scope:    claimed.Scope,
		AMR:      claimed.AMR,
	}, accessTokenTTL); err != nil {
		slog.Error("oidc: сохранение access-токена", "error", err)
		writeOIDCError(w, http.StatusInternalServerError, "server_error")
		return
	}

	claims := mgr.IDTokenClaims(mgr.issuer(r), user, client.ClientID,
		claimed.Scope, claimed.Nonce, claimed.AMR, claimed.AuthTime, time.Now())
	idToken, err := mgr.SignIDToken(claims)
	if err != nil {
		slog.Error("oidc: подпись ID-токена", "error", err)
		writeOIDCError(w, http.StatusInternalServerError, "server_error")
		return
	}
	mgr.audit(r, user.Username, "oidc_token", "ok", map[string]any{
		"client_id": client.ClientID, "scope": claimed.Scope,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": access,
		"token_type":   "Bearer",
		"expires_in":   int(accessTokenTTL.Seconds()),
		"scope":        claimed.Scope,
		"id_token":     idToken,
	})
}

// ---- userinfo ----

// handleUserinfo — GET /oidc/userinfo (Authorization: Bearer): клеймы
// пользователя по access-токену; sub обязателен, профильные клеймы — по
// scope токена.
func (mgr *Manager) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="oidc"`)
		writeOIDCError(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	token := strings.TrimSpace(strings.TrimPrefix(h, prefix))
	t, err := mgr.st.OIDCTokenGet(r.Context(), secrets.SHA256(token))
	if errors.Is(err, store.ErrNotFound) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="oidc", error="invalid_token"`)
		writeOIDCError(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	if err != nil {
		slog.Error("oidc: чтение access-токена", "error", err)
		writeOIDCError(w, http.StatusInternalServerError, "server_error")
		return
	}
	user, err := mgr.st.UserByID(r.Context(), t.UserID)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="oidc", error="invalid_token"`)
		writeOIDCError(w, http.StatusUnauthorized, "invalid_token")
		return
	}

	out := map[string]any{"sub": user.ID.String()}
	if HasScope(t.Scope, "profile") {
		out["preferred_username"] = user.Username
		out["username"] = user.Username
		out["name"] = user.DisplayName
		if user.DisplayName == "" {
			out["name"] = user.Username
		}
		groups := []string{user.Role}
		if mgr.st != nil {
			if lgn, err := mgr.st.UserGroupNames(r.Context(), user.ID); err == nil {
				groups = append(groups, lgn...)
			}
		}
		groups = append(groups, user.LDAPGroups...)
		out["groups"] = uniqueStrings(groups)
	}
	if HasScope(t.Scope, "email") && user.Email != "" {
		out["email"] = user.Email
		out["email_verified"] = true
	}
	writeJSON(w, http.StatusOK, out)
}
