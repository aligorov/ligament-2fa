//go:build integration

// Интеграционные тесты HTML-обвязки (pages.go) на полной композиции
// BuildRouter — как в main: логин-флоу формами (302), сессия+CSRF форм,
// рендер страниц, админ-редиректы, сохранение форм, маскировка настроек.
package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/aligorov/twofa/internal/auth"
	"github.com/aligorov/twofa/internal/channel"
	"github.com/aligorov/twofa/internal/delivery"
	"github.com/aligorov/twofa/internal/license"
	"github.com/aligorov/twofa/internal/secrets"
	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
	"github.com/aligorov/twofa/internal/web"
	"github.com/aligorov/twofa/internal/webauthn"
)

// newPagesRouter — полная композиция через BuildRouter (как main).
func newPagesRouter(t *testing.T, st *store.Store, set *settings.M, box *secrets.Box) *Router {
	return newPagesRouterWA(t, st, set, box, nil)
}

// newPagesRouterWA — как newPagesRouter, но с включённым WebAuthn.
func newPagesRouterWA(t *testing.T, st *store.Store, set *settings.M, box *secrets.Box, wa *webauthn.Svc) *Router {
	t.Helper()
	email := &fakeSender{ch: channel.Email}
	core := auth.NewCore(st, set, box,
		map[channel.Channel]delivery.Sender{channel.Email: email},
		auth.NewLocalVerifier(st), nil)
	rend, err := web.New()
	if err != nil {
		t.Fatalf("web.New: %v", err)
	}
	rt := BuildRouter(Deps{
		Core: core, WA: wa, St: st, Box: box, PV: auth.NewLocalVerifier(st), M: set, Rend: rend,
	})
	t.Cleanup(rt.Stop)
	return rt
}

// htmlClient — «браузер»: держит cookie сессии, отправляет form-encoded POST.
type htmlClient struct {
	t       *testing.T
	h       http.Handler
	session *http.Cookie
}

func newHTMLClient(t *testing.T, h http.Handler) *htmlClient {
	return &htmlClient{t: t, h: h}
}

func (c *htmlClient) get(path string) *httptest.ResponseRecorder {
	c.t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if c.session != nil {
		req.AddCookie(c.session)
	}
	return c.do(req)
}

// postForm отправляет форму; csrf=true подставляет токен, выскобленный из
// предыдущей страницы (валидация скрытого поля csrf_token).
func (c *htmlClient) postForm(path string, form url.Values, csrf bool) *httptest.ResponseRecorder {
	c.t.Helper()
	if csrf {
		token := c.csrfFromPage()
		if token == "" {
			c.t.Fatal("csrf-токен не найден на странице /me")
		}
		form.Set("csrf_token", token)
	}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.session != nil {
		req.AddCookie(c.session)
	}
	return c.do(req)
}

func (c *htmlClient) postFetch(path string, form url.Values) *httptest.ResponseRecorder {
	c.t.Helper()
	token := c.csrfFromPage()
	if token == "" {
		c.t.Fatal("csrf-токен не найден на странице /me")
	}
	form.Set("csrf_token", token)
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-CSRF-Token", token)
	if c.session != nil {
		req.AddCookie(c.session)
	}
	return c.do(req)
}

func (c *htmlClient) do(req *http.Request) *httptest.ResponseRecorder {
	c.t.Helper()
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, req)
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == cookieSession {
			if ck.MaxAge < 0 {
				c.session = nil
			} else {
				c.session = ck
			}
		}
	}
	return rec
}

// csrfRe — скрытое CSRF-поле формы (значение — токен сессии).
var csrfRe = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

// csrfFromPage читает CSRF-токен со страницы /me (cookie HttpOnly, скрипт
// токен не прочитает — тест разбирает разметку, как это делает форма).
func (c *htmlClient) csrfFromPage() string {
	c.t.Helper()
	rec := c.get("/me")
	if rec.Code != http.StatusOK {
		c.t.Fatalf("GET /me: код %d, жду 200 (для CSRF)", rec.Code)
	}
	m := csrfRe.FindStringSubmatch(rec.Body.String())
	if m == nil {
		return ""
	}
	return m[1]
}

// login формами: успех — 302, cookie сессии подхвачена.
func (c *htmlClient) login(t *testing.T, username, password, code string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"username": {username}, "password": {password}}
	if code != "" {
		form.Set("code", code)
	}
	return c.postForm("/login", form, false)
}

// wantLocation проверяет код и Location редиректа.
func wantLocation(t *testing.T, rec *httptest.ResponseRecorder, code int, to string) {
	t.Helper()
	wantStatus(t, rec, code)
	if got := rec.Header().Get("Location"); got != to {
		t.Fatalf("Location = %q, want %q", got, to)
	}
}

// wantBody проверяет вхождение подстрок в HTML-ответ.
func wantBody(t *testing.T, rec *httptest.ResponseRecorder, parts ...string) {
	t.Helper()
	for _, p := range parts {
		if !strings.Contains(rec.Body.String(), p) {
			t.Fatalf("ответ не содержит %q; тело:\n%.600s", p, rec.Body.String())
		}
	}
}

// ---- тесты ----

// TestPagesLoginFlow: GET /login → форма; POST без второго фактора → 302 /me;
// GET /me → 200 с русским заголовком; POST без CSRF → 403; POST /me/prefer
// с CSRF → 302 и prefer_channels сохранены.
func TestPagesLoginFlow(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	rt := newPagesRouter(t, st, set, box)
	user := mkUser(t, ctx, st, "htmluser", nil)
	c := newHTMLClient(t, rt.Handler)

	rec := c.get("/login")
	wantStatus(t, rec, http.StatusOK)
	wantBody(t, rec, "<h1>Вход</h1>", `action="/login"`)

	rec = c.login(t, user.Username, testPassword, "")
	wantLocation(t, rec, http.StatusFound, "/me?flash=%D0%92%D1%8B+%D0%B2%D0%BE%D1%88%D0%BB%D0%B8.&kind=ok")
	if c.session == nil {
		t.Fatal("cookie twofa_session не установлена")
	}

	rec = c.get("/me")
	wantStatus(t, rec, http.StatusOK)
	wantBody(t, rec, "<h1>Профиль</h1>", "htmluser", `action="/me/prefer"`, `name="csrf_token"`)
	// Русский заголовок вкладки страницы.
	wantBody(t, rec, "<title>Профиль · 2FA</title>")

	// Мутирующий POST без CSRF-токена → 403.
	rec = c.postForm("/me/prefer", url.Values{"channels": {"totp", "email"}}, false)
	wantStatus(t, rec, http.StatusForbidden)

	// POST с CSRF → 302 и сохранение prefer_channels.
	rec = c.postForm("/me/prefer", url.Values{"channels": {"totp", "email"}}, true)
	wantStatus(t, rec, http.StatusFound)
	fresh, err := st.UserByUsername(ctx, user.Username)
	if err != nil {
		t.Fatalf("UserByUsername: %v", err)
	}
	if len(fresh.PreferChannels) != 2 ||
		fresh.PreferChannels[0] != channel.TOTP || fresh.PreferChannels[1] != channel.Email {
		t.Fatalf("prefer_channels = %v, want [totp email]", fresh.PreferChannels)
	}
}

// TestPagesLogin2FAHTML: TOTP-пользователь — первый шаг перерендеривает форму
// с подсказкой, неверный код — 401, верный «пароль+код» — 302 /me.
func TestPagesLogin2FAHTML(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	rt := newPagesRouter(t, st, set, box)
	user := mkUser(t, ctx, st, "htmltotp", nil)
	key := enrollTOTP(t, ctx, st, set, box, user)
	c := newHTMLClient(t, rt.Handler)

	// Первый шаг: пароль верен, код обязателен — рендер с подсказкой.
	rec := c.login(t, user.Username, testPassword, "")
	wantStatus(t, rec, http.StatusOK)
	wantBody(t, rec, "Введите код второго фактора.", user.Username)
	if c.session != nil {
		t.Fatal("сессия не должна выпускаться до второго фактора")
	}

	// Неверный код → 401 с ошибкой.
	rec = c.login(t, user.Username, testPassword, "000000")
	wantStatus(t, rec, http.StatusUnauthorized)
	wantBody(t, rec, "Неверный код второго фактора.")

	// Верный код → 302 /me.
	code, err := totp.GenerateCodeCustom(key.Secret(), time.Now(), totp.ValidateOpts{
		Period: 30, Skew: 1, Digits: 6,
	})
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	rec = c.login(t, user.Username, testPassword, code)
	wantStatus(t, rec, http.StatusFound)
	if !strings.HasPrefix(rec.Header().Get("Location"), "/me?") {
		t.Fatalf("Location = %q, want /me", rec.Header().Get("Location"))
	}
	rec = c.get("/me")
	wantStatus(t, rec, http.StatusOK)
}

// TestPagesAdminAccess: не-админ получает редирект /me со страниц /admin;
// админ видит пользователей и настройки с маской «••••».
func TestPagesAdminAccess(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	rt := newPagesRouter(t, st, set, box)
	user := mkUser(t, ctx, st, "plainuser", nil)
	admin := mkUser(t, ctx, st, "htmladmin", func(u *store.User) { u.Role = "admin" })
	c := newHTMLClient(t, rt.Handler)

	rec := c.login(t, user.Username, testPassword, "")
	wantStatus(t, rec, http.StatusFound)
	rec = c.get("/admin/users")
	wantLocation(t, rec, http.StatusFound, "/me")
	rec = c.get("/admin/settings")
	wantLocation(t, rec, http.StatusFound, "/me")

	// Админ: вход ведёт на /admin → /admin/users; настройки содержат маску.
	c2 := newHTMLClient(t, rt.Handler)
	rec = c2.login(t, admin.Username, testPassword, "")
	wantStatus(t, rec, http.StatusFound)
	if !strings.HasPrefix(rec.Header().Get("Location"), "/admin") {
		t.Fatalf("админ после входа должен попадать на /admin, got %q", rec.Header().Get("Location"))
	}
	rec = c2.get("/admin/users")
	wantStatus(t, rec, http.StatusOK)
	wantBody(t, rec, "<h1>Пользователи</h1>", "plainuser", `action="/admin/users"`)

	rec = c2.get("/admin/settings")
	wantStatus(t, rec, http.StatusOK)
	wantBody(t, rec, "<h1>Настройки сервера</h1>", "•••• (задано)", `action="/admin/settings"`)
	// Пресеты шлюзов: select наполнен реальными пресетами delivery.Presets
	// (маппинг smsPresetChoices), каждый option несёт JSON конфига.
	wantBody(t, rec, `data-sms-preset`, `value="smsaero"`, `value="smsgateway24"`, `data-config=`)
}

// TestPagesAdminSettingsPost: сохранение секции (мерж объектного ключа) и
// пропуск пустых секретных полей. Поля отправляются с ТЕМИ ЖЕ именами, что
// рендерит шаблон admin_settings.gohtml (контракт имён — TestPagesAdminSettingsFormContract).
// Настройки восстанавливаются — контейнер один на пакет, остальные тесты ждут дефолтов.
func TestPagesAdminSettingsPost(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	rt := newPagesRouter(t, st, set, box)
	admin := mkUser(t, ctx, st, "setadmin", func(u *store.User) { u.Role = "admin" })
	t.Cleanup(func() {
		restore := map[string]string{
			"totp":     `{"issuer":"twofa","digits":6,"period":30,"skew":1}`,
			"smtp":     `{"host":"","port":0,"starttls":false,"user":"","password":"","from":"","subject":"","timeout":"0s"}`,
			"telegram": `{"bot_token":""}`,
		}
		for key, val := range restore {
			if err := set.Put(ctx, key, json.RawMessage(val)); err != nil {
				t.Errorf("восстановление %s: %v", key, err)
			}
		}
	})
	c := newHTMLClient(t, rt.Handler)
	rec := c.login(t, admin.Username, testPassword, "")
	wantStatus(t, rec, http.StatusFound)

	form := url.Values{
		"section":     {"totp"},
		"totp.issuer": {"corp-2fa"},
		"totp.digits": {"8"},
		"totp.period": {"30"},
		"totp.skew":   {"1"},
	}
	rec = c.postForm("/admin/settings", form, true)
	wantStatus(t, rec, http.StatusFound)
	if set.Get().TOTP.Issuer != "corp-2fa" || set.Get().TOTP.Digits != 8 {
		t.Fatalf("totp не сохранён: issuer=%q digits=%d", set.Get().TOTP.Issuer, set.Get().TOTP.Digits)
	}

	// Секция smtp с пустым password: секрет не сбрасывается, объект мержится.
	before := set.Get().SMTP.Password
	form = url.Values{
		"section":       {"smtp"},
		"smtp.host":     {"smtp.corp.example"},
		"smtp.port":     {"587"},
		"smtp.user":     {"noreply"},
		"smtp.password": {""}, // пустое = «не менять»
		"smtp.from":     {"2fa@corp.example"},
		"smtp.subject":  {"Код"},
		"smtp.timeout":  {"10s"},
	}
	rec = c.postForm("/admin/settings", form, true)
	wantStatus(t, rec, http.StatusFound)
	if set.Get().SMTP.Host != "smtp.corp.example" || set.Get().SMTP.Port != 587 {
		t.Fatalf("smtp не сохранён: %+v", set.Get().SMTP)
	}
	if set.Get().SMTP.Password != before {
		t.Fatal("пустой password не должен менять секрет")
	}

	// Секция telegram: dotted-имя пишет bot_token ВНУТРИ объекта telegram.
	form = url.Values{
		"section":            {"telegram"},
		"telegram.bot_token": {"123456:AA-test-token"},
	}
	rec = c.postForm("/admin/settings", form, true)
	wantStatus(t, rec, http.StatusFound)
	if set.Get().TG.BotToken != "123456:AA-test-token" {
		t.Fatalf("telegram.bot_token не сохранён: %q", set.Get().TG.BotToken)
	}
}

// TestPagesAdminSettingsLDAP: секция LDAP сохраняется (включая вложенные
// ldap.attrs.*), пустой bind_password не сбрасывает секрет, флаг «задано»
// рендерится. Настройки восстанавливаются.
func TestPagesAdminSettingsLDAP(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	rt := newPagesRouter(t, st, set, box)
	admin := mkUser(t, ctx, st, "ldapsetadmin", func(u *store.User) { u.Role = "admin" })
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = set.Put(cctx, "ldap", json.RawMessage(`{"enabled":false,"url":"","starttls":false,"bind_dn":"","bind_password":"","base_dn":"","user_filter":"(&(objectClass=user)(sAMAccountName={login}))","group_base_dn":"","group_filter":"(&(objectClass=group)(member={dn}))","attrs":{"email":"mail","phone":"telephoneNumber","display_name":"displayName"},"allow_groups":[],"role_map":{}}`))
	})
	c := newHTMLClient(t, rt.Handler)
	rec := c.login(t, admin.Username, testPassword, "")
	wantStatus(t, rec, http.StatusFound)

	// Сохранение секции: поля первого уровня + вложенные attrs.
	form := url.Values{
		"section":                 {"ldap"},
		"ldap.enabled":            {"1"},
		"ldap.url":                {"ldaps://dc1.corp.example:636"},
		"ldap.bind_dn":            {"CN=svc-twofa,OU=Service,DC=corp,DC=example"},
		"ldap.bind_password":      {"dir-secret"},
		"ldap.base_dn":            {"DC=corp,DC=example"},
		"ldap.user_filter":        {"(&(objectClass=user)(sAMAccountName={login}))"},
		"ldap.group_base_dn":      {"OU=Groups,DC=corp,DC=example"},
		"ldap.group_filter":       {"(&(objectClass=group)(member={dn}))"},
		"ldap.attrs.email":        {"mail"},
		"ldap.attrs.phone":        {"mobile"},
		"ldap.attrs.display_name": {"displayName"},
		"ldap.allow_groups":       {`["CN=VPN-Users,OU=Groups,DC=corp,DC=example"]`},
		"ldap.role_map":           {`{"CN=VPN-Admins,OU=Groups,DC=corp,DC=example":"admin"}`},
	}
	rec = c.postForm("/admin/settings", form, true)
	wantStatus(t, rec, http.StatusFound)
	got := set.Get().LDAP
	if !got.Enabled || got.URL != "ldaps://dc1.corp.example:636" || got.BindPassword != "dir-secret" ||
		got.BaseDN != "DC=corp,DC=example" || got.GroupBaseDN != "OU=Groups,DC=corp,DC=example" {
		t.Fatalf("ldap не сохранён: %+v", got)
	}
	if got.Attrs.Phone != "mobile" {
		t.Fatalf("ldap.attrs.phone (вложенное поле) = %q, want mobile", got.Attrs.Phone)
	}
	if len(got.AllowGroups) != 1 || len(got.RoleMap) != 1 || got.RoleMap["CN=VPN-Admins,OU=Groups,DC=corp,DC=example"] != "admin" {
		t.Fatalf("allow_groups/role_map не сохранены: %v / %v", got.AllowGroups, got.RoleMap)
	}

	// Страница рендерит секцию: флаг «задано» у bind_password, значения полей.
	rec = c.get("/admin/settings")
	wantStatus(t, rec, http.StatusOK)
	wantBody(t, rec, `name="ldap.bind_password"`, `ldaps://dc1.corp.example:636`, `name="ldap.attrs.phone"`)
	// Сам пароль не утекает в разметку; флаг задан — рядом с полем.
	if strings.Count(rec.Body.String(), "dir-secret") != 0 {
		t.Fatal("ldap.bind_password виден в разметке настроек")
	}

	// Пустой bind_password = «не менять»: остальные поля мержатся.
	form.Set("ldap.bind_password", "")
	form.Set("ldap.base_dn", "DC=corp2,DC=example")
	rec = c.postForm("/admin/settings", form, true)
	wantStatus(t, rec, http.StatusFound)
	got = set.Get().LDAP
	if got.BindPassword != "dir-secret" {
		t.Fatal("пустой bind_password не должен сбрасывать секрет")
	}
	if got.BaseDN != "DC=corp2,DC=example" {
		t.Fatalf("base_dn не обновился: %q", got.BaseDN)
	}

	// Создание LDAP-пользователя без пароля: случайный непригодный хеш.
	form = url.Values{
		"username": {"pages-ldapuser"},
		"source":   {"ldap"},
		"enabled":  {"1"},
	}
	rec = c.postForm("/admin/users", form, true)
	wantStatus(t, rec, http.StatusFound)
	u, err := st.UserByUsername(ctx, "pages-ldapuser")
	if err != nil {
		t.Fatalf("создание ldap-пользователя через форму: %v", err)
	}
	if u.Source != store.SourceLDAP || u.PasswordHash == "" {
		t.Fatalf("source/hash созданного: %q / %q", u.Source, u.PasswordHash)
	}
	// Список пользователей: бейдж источника.
	rec = c.get("/admin/users")
	wantStatus(t, rec, http.StatusOK)
	wantBody(t, rec, `>ldap</span>`, "pages-ldapuser")
}

// ---- контракт формы настроек: имена полей шаблона = имена settingsForm ----

// formRe — одна форма /admin/settings (с секцией или без).
var formRe = regexp.MustCompile(`(?s)<form action="/admin/settings".*?</form>`)

// sectionRe — скрытое поле секции формы.
var sectionRe = regexp.MustCompile(`<input type="hidden" name="section" value="([^"]+)"`)

// inputRe — любой input с именем (кроме кнопок: они не input).
var inputRe = regexp.MustCompile(`<input[^>]*name="([^"]+)"[^>]*>`)

// valueRe — значение input в двойных или одинарных кавычках (шаблон
// использует одинарные для JSON-значений jsonPretty).
var valueRe = regexp.MustCompile(`value=(?:"([^"]*)"|'([^']*)')`)

// textareaRe — textarea с именем; значение — внутренний текст.
var textareaRe = regexp.MustCompile(`(?s)<textarea[^>]*name="([^"]+)"[^>]*>(.*?)</textarea>`)

// selectRe — select с именем (ads.provider): значение — selected-опция.
var selectRe = regexp.MustCompile(`(?s)<select[^>]*name="([^"]+)"[^>]*>(.*?)</select>`)

// parseSettingsForm разбирает блок <form> на секцию и карту «имя → значение»
// (браузер отправил бы ровно это); checkbox без checked в форму не входит.
func parseSettingsForm(block string) (section string, fields map[string]string) {
	fields = map[string]string{}
	if m := sectionRe.FindStringSubmatch(block); m != nil {
		section = m[1]
	}
	for _, m := range inputRe.FindAllStringSubmatch(block, -1) {
		name, tag := m[1], m[0]
		if name == "csrf_token" || name == "section" || name == "regenerate" || name == "ldap_test_username" {
			// ldap_test_username — параметр действия «проверить пользователя»
			// (ldap_action=test_user), не ключ настроек.
			continue
		}
		if strings.Contains(tag, `type="checkbox"`) {
			// Поле есть в разметке всегда; неотмеченный чекбокс браузер не
			// отправляет — пустое значение (сервер трактует как «выключено»).
			if strings.Contains(tag, "checked") {
				fields[name] = "1"
			} else {
				fields[name] = ""
			}
			continue
		}
		if vm := valueRe.FindStringSubmatch(tag); vm != nil {
			v := vm[1]
			if v == "" {
				v = vm[2]
			}
			fields[name] = html.UnescapeString(v)
		} else {
			fields[name] = "" // секретные поля с placeholder — «не менять»
		}
	}
	for _, m := range selectRe.FindAllStringSubmatch(block, -1) {
		if m[1] == "csrf_token" || m[1] == "section" {
			continue
		}
		fields[m[1]] = "" // наличие важнее значения (контракт — по именам)
	}
	for _, m := range textareaRe.FindAllStringSubmatch(block, -1) {
		fields[m[1]] = html.UnescapeString(m[2])
	}
	return section, fields
}

// TestPagesAdminSettingsFormContract — контракт HTML-формы настроек:
//  1. каждое поле settingsForm[section] реально отрендерено в этой секции
//     (иначе POST молча сохраняет пустоту — как было с unprefixed-именами);
//  2. наоборот: каждый именованный input/textarea секции известен серверу;
//  3. отправка РОВНО разобранных полей (как сделал бы браузер) принимается —
//     каждая секция отвечает 302.
func TestPagesAdminSettingsFormContract(t *testing.T) {
	st, set, box := setup(t)
	rt := newPagesRouter(t, st, set, box)
	admin := mkUser(t, context.Background(), st, "contractadmin", func(u *store.User) { u.Role = "admin" })
	c := newHTMLClient(t, rt.Handler)
	rec := c.login(t, admin.Username, testPassword, "")
	wantStatus(t, rec, http.StatusFound)

	rec = c.get("/admin/settings")
	wantStatus(t, rec, http.StatusOK)
	body := rec.Body.String()

	sections := map[string]map[string]string{} // section → name → value
	for _, block := range formRe.FindAllString(body, -1) {
		sec, fields := parseSettingsForm(block)
		if sec == "" {
			continue // формы без section (кнопки regenerate) не несут полей
		}
		sections[sec] = fields
	}
	if len(sections) == 0 {
		t.Fatal("на странице /admin/settings не найдено ни одной формы с секцией")
	}
	if _, ok := sections["smtp"]; !ok {
		t.Fatal("форма секции smtp не найдена")
	}
	if _, ok := sections["ldap"]; !ok {
		t.Fatal("форма секции ldap не найдена")
	}

	// Встреча: settingsForm ↔ шаблон, в обе стороны по каждой секции.
	for sec, fields := range sections {
		want, ok := settingsForm[sec]
		if !ok {
			t.Fatalf("секция %q отрендерена, но неизвестна settingsForm", sec)
		}
		rendered := map[string]bool{}
		for name := range fields {
			rendered[name] = true
		}
		for _, f := range want {
			if !rendered[f.name] {
				t.Errorf("секция %s: поле %q из settingsForm не отрендерено в шаблоне", sec, f.name)
			}
		}
		for _, f := range want {
			delete(rendered, f.name)
		}
		for name := range rendered {
			t.Errorf("секция %s: поле %q отрендерено, но отсутствует в settingsForm (сохранено не будет)", sec, name)
		}
	}

	// Отправка разобранных полей как есть (значения не меняются — контейнер
	// общий) принимается: каждая секция отвечает 302 «Настройки сохранены».
	snapshot := set.Get()
	for _, sec := range slices.Sorted(maps.Keys(sections)) {
		form := url.Values{"section": {sec}}
		for name, val := range sections[sec] {
			form.Set(name, val)
		}
		rec = c.postForm("/admin/settings", form, true)
		if rec.Code != http.StatusFound {
			t.Fatalf("секция %s: POST разобранной формы = %d, want 302; тело:\n%.400s",
				sec, rec.Code, rec.Body.String())
		}
	}
	// Значения не изменились (перемены сломали бы остальные тесты пакета).
	after := set.Get()
	if after.TOTP.Issuer != snapshot.TOTP.Issuer || after.Radius.MaxFailPerUser != snapshot.Radius.MaxFailPerUser {
		t.Fatalf("контрактная отправка изменила настройки: totp.issuer %q→%q, max_fail_per_user %d→%d",
			snapshot.TOTP.Issuer, after.TOTP.Issuer, snapshot.Radius.MaxFailPerUser, after.Radius.MaxFailPerUser)
	}
}

// TestPagesPasskeyRegisterRequiresCode: форма /me/passkeys собирает код
// подтверждения — сервер обязан его проверить: пустой код и неверный код —
// флеш-ошибки без старта церемонии; верный код — страница с pending-блоком
// (дальше церемонию ведёт webauthn.js).
func TestPagesPasskeyRegisterRequiresCode(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	if err := set.Put(ctx, "webauthn", json.RawMessage(`{"rp_id":"localhost","rp_name":"twofa-test"}`)); err != nil {
		t.Fatalf("settings.Put(webauthn): %v", err)
	}
	wa, err := webauthn.New(st, set)
	if err != nil {
		t.Fatalf("webauthn.New: %v", err)
	}
	rt := newPagesRouterWA(t, st, set, box, wa)
	user := mkUser(t, ctx, st, "passcode", nil)
	key := enrollTOTP(t, ctx, st, set, box, user)
	// Резервный код для успешного пути (TOTP-код уже израсходован входом —
	// replay-защита по окну).
	backups, err := replaceBackupCodes(ctx, st, user.ID)
	if err != nil {
		t.Fatalf("replaceBackupCodes: %v", err)
	}
	c := newHTMLClient(t, rt.Handler)
	// Вход «пароль + TOTP-код» одним запросом.
	totpCode, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("totp.GenerateCode: %v", err)
	}
	rec := c.login(t, user.Username, testPassword, totpCode)
	wantStatus(t, rec, http.StatusFound)

	// Пустой код → флеш-ошибка, церемония не начинается (флеш живёт в
	// query редиректа — страница читается по Location целиком).
	followFlash := func(rec *httptest.ResponseRecorder, want string) {
		t.Helper()
		wantStatus(t, rec, http.StatusFound)
		loc := rec.Header().Get("Location")
		if !strings.HasPrefix(loc, "/me/passkeys?") {
			t.Fatalf("Location = %q, want /me/passkeys с флешем", loc)
		}
		page := c.get(loc)
		wantStatus(t, page, http.StatusOK)
		wantBody(t, page, want)
	}
	followFlash(c.postForm("/me/webauthn/credentials",
		url.Values{"name": {"Мой ключ"}, "code": {""}}, true), "Введите код подтверждения.")

	// Неверный код → флеш-ошибка.
	followFlash(c.postForm("/me/webauthn/credentials",
		url.Values{"name": {"Мой ключ"}, "code": {"000000"}}, true), "Неверный код подтверждения.")
	rows, err := st.AuditList(ctx, store.AuditFilter{Username: user.Username, Event: "webauthn_register"})
	if err != nil || len(rows) == 0 {
		t.Fatalf("аудит webauthn_register(fail) не записан: rows=%d err=%v", len(rows), err)
	}

	// Верный код (резервный) → страница с pending-блоком (handle + options).
	rec = c.postForm("/me/webauthn/credentials", url.Values{"name": {"Мой ключ"}, "code": {backups[0]}}, true)
	wantStatus(t, rec, http.StatusOK)
	wantBody(t, rec, `id="passkey-pending"`)
}

// TestPagesAdminChallengesHidesWebauthnSession: HTML /admin/challenges не
// раскрывает push_state строк webauthn_session (там лежит сессия церемонии
// WebAuthn, не покидающая сервер) — тот же CASE-щит, что у JSON API;
// состояние telegram_push остаётся видимым.
func TestPagesAdminChallengesHidesWebauthnSession(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	rt := newPagesRouter(t, st, set, box)
	admin := mkUser(t, ctx, st, "challadmin", func(u *store.User) { u.Role = "admin" })
	user := mkUser(t, ctx, st, "challvictim", nil)

	const sessionPayload = "TOP-SECRET-CEREMONY-SESSION-PAYLOAD"
	if err := st.ChallengeCreate(ctx, &store.Challenge{
		UserID:       user.ID,
		Channel:      channel.WebAuthn,
		CodeHash:     secrets.SHA256("wa-session-handle"),
		PushState:    ptr(sessionPayload),
		ExpiresAt:    time.Now().Add(time.Minute),
		AttemptsLeft: 1,
		Purpose:      "webauthn_session",
	}); err != nil {
		t.Fatalf("создать webauthn_session-челлендж: %v", err)
	}
	if err := st.ChallengeCreate(ctx, &store.Challenge{
		UserID:       user.ID,
		Channel:      channel.TelegramPush,
		PushState:    ptr("pending"),
		ExpiresAt:    time.Now().Add(time.Minute),
		AttemptsLeft: 1,
		Purpose:      "radius",
	}); err != nil {
		t.Fatalf("создать push-челлендж: %v", err)
	}

	c := newHTMLClient(t, rt.Handler)
	rec := c.login(t, admin.Username, testPassword, "")
	wantStatus(t, rec, http.StatusFound)
	rec = c.get("/admin/challenges")
	wantStatus(t, rec, http.StatusOK)
	if strings.Contains(rec.Body.String(), sessionPayload) {
		t.Fatal("HTML /admin/challenges раскрывает payload webauthn_session")
	}
	// Состояние telegram_push по-прежнему видно администратору.
	wantBody(t, rec, "pending")
}

// TestPagesPasswordChangeLDAPBlocked (FIX-1): HTML-смена пароля LDAP-юзера
// блокируется сервером (форма в шаблоне скрыта, но прямой POST обязан
// упереться в страж): флеш «меняется в Active Directory», хеш не меняется,
// сессия не отзывается.
func TestPagesPasswordChangeLDAPBlocked(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	rt := newPagesRouter(t, st, set, box)
	user := mkUser(t, ctx, st, "htmldap", func(u *store.User) {
		u.Source = store.SourceLDAP
	})
	hashBefore := user.PasswordHash
	c := newHTMLClient(t, rt.Handler)
	rec := c.login(t, user.Username, testPassword, "")
	wantStatus(t, rec, http.StatusFound)

	rec = c.postForm("/me/password", url.Values{
		"old_password":  {testPassword},
		"new_password":  {"new-ldap-pass-123"},
		"new_password2": {"new-ldap-pass-123"},
	}, true)
	wantStatus(t, rec, http.StatusFound)
	page := c.get(rec.Header().Get("Location"))
	wantStatus(t, page, http.StatusOK)
	wantBody(t, page, "Пароль LDAP-пользователя меняется в Active Directory")

	fresh, err := st.UserByUsername(ctx, user.Username)
	if err != nil {
		t.Fatalf("UserByUsername: %v", err)
	}
	if fresh.PasswordHash != hashBefore {
		t.Fatal("password_hash изменён заблокированной сменой пароля")
	}
	// Сессия жива: /me отвечает страницей, а не редиректом на /login.
	rec = c.get("/me")
	wantStatus(t, rec, http.StatusOK)
}

// TestPagesLogout: POST /logout с CSRF удаляет сессию (GET /me → /login).
func TestPagesLogout(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	rt := newPagesRouter(t, st, set, box)
	user := mkUser(t, ctx, st, "htmlout", nil)
	c := newHTMLClient(t, rt.Handler)
	rec := c.login(t, user.Username, testPassword, "")
	wantStatus(t, rec, http.StatusFound)

	rec = c.postForm("/logout", url.Values{}, true)
	wantStatus(t, rec, http.StatusFound)
	rec = c.get("/me")
	wantLocation(t, rec, http.StatusFound, "/login")
}

// TestPagesTOTPEnrollConfirmHTML: enroll → QR на странице; confirm кодом →
// страница резервных кодов (показ один раз).
func TestPagesTOTPEnrollConfirmHTML(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	rt := newPagesRouter(t, st, set, box)
	user := mkUser(t, ctx, st, "htmlconf", nil)
	c := newHTMLClient(t, rt.Handler)
	rec := c.login(t, user.Username, testPassword, "")
	wantStatus(t, rec, http.StatusFound)

	rec = c.postForm("/me/totp/enroll", url.Values{}, true)
	wantStatus(t, rec, http.StatusFound)
	if !strings.HasPrefix(rec.Header().Get("Location"), "/me/totp?") {
		t.Fatalf("Location = %q, want /me/totp", rec.Header().Get("Location"))
	}
	rec = c.get("/me/totp")
	wantStatus(t, rec, http.StatusOK)
	wantBody(t, rec, "otpauth://totp/", `action="/me/totp/confirm"`)

	// Секрет можно вытащить из otpauth-ссылки и сгенерировать код.
	m := regexp.MustCompile(`secret=([A-Z2-7]+)`).FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatal("otpauth-ссылка без secret")
	}
	code, err := totp.GenerateCode(m[1], time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	rec = c.postForm("/me/totp/confirm", url.Values{"code": {code}}, true)
	wantStatus(t, rec, http.StatusOK)
	wantBody(t, rec, "Сохраните эти коды", `<li><code>`)

	if _, _, _, confirmed, _, err := st.TOTPGet(ctx, user.ID); err != nil || !confirmed {
		t.Fatalf("TOTP не подтверждён: confirmed=%v err=%v", confirmed, err)
	}
}

// TestPagesAdminResetTOTPOneTimeCodes: сброс TOTP админом рендерит новые
// резервные коды в ТЕЛЕ ответа (200), а не в Location/flash — одноразовые
// секреты не должны попадать в URL, историю браузера и логи прокси.
func TestPagesAdminResetTOTPOneTimeCodes(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	rt := newPagesRouter(t, st, set, box)
	target := mkUser(t, ctx, st, "resetvictim", nil)
	admin := mkUser(t, ctx, st, "resetadmin", func(u *store.User) { u.Role = "admin" })
	c := newHTMLClient(t, rt.Handler)
	rec := c.login(t, admin.Username, testPassword, "")
	wantStatus(t, rec, http.StatusFound)

	rec = c.postForm("/admin/users/"+target.ID.String(),
		url.Values{"do": {"reset-totp"}}, true)
	wantStatus(t, rec, http.StatusOK)
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Fatalf("Location не должен нести коды, got %q", loc)
	}
	// В теле — формат резервных кодов (XXXXX-XXXXX) и предупреждение.
	if !regexp.MustCompile(`[A-Z2-9]{5}-`).MatchString(rec.Body.String()) {
		t.Fatalf("тело без резервных кодов (XXXXX-XXXXX):\n%.600s", rec.Body.String())
	}
	wantBody(t, rec, "Показываются только один раз")

	// Коды действительно заменены в БД (10 свежих, TOTP удалён).
	if n, err := backupRemaining(ctx, st, target.ID); err != nil || n != 10 {
		t.Fatalf("backupRemaining = %d (err %v), want 10", n, err)
	}
	if _, _, _, _, _, err := st.TOTPGet(ctx, target.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("TOTP-секрет не удалён: err = %v", err)
	}
}

// TestPagesAdminSettingsRegenerateOneTime: перегенерация секрета в
// /admin/settings рендерит новое значение в ТЕЛЕ ответа (200), не в
// Location/flash; остальная страница остаётся с масками «••••».
func TestPagesAdminSettingsRegenerateOneTime(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	rt := newPagesRouter(t, st, set, box)
	admin := mkUser(t, ctx, st, "regenadmin", func(u *store.User) { u.Role = "admin" })
	oldTok := set.Get().AdminToken
	t.Cleanup(func() { // контейнер один на пакет — возвращаем токен
		b, _ := json.Marshal(oldTok)
		if err := set.Put(ctx, "admin_token", b); err != nil {
			t.Errorf("восстановление admin_token: %v", err)
		}
	})
	c := newHTMLClient(t, rt.Handler)
	rec := c.login(t, admin.Username, testPassword, "")
	wantStatus(t, rec, http.StatusFound)

	rec = c.postForm("/admin/settings", url.Values{"regenerate": {"admin_token"}}, true)
	wantStatus(t, rec, http.StatusOK)
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Fatalf("Location не должен нести секрет, got %q", loc)
	}
	fresh := set.Get().AdminToken
	if fresh == "" || fresh == oldTok {
		t.Fatalf("admin_token не перегенерирован: %q", fresh)
	}
	// Новый токен — в теле, с меткой ключа и предупреждением.
	wantBody(t, rec, "admin_token", fresh, "Показывается только один раз")
	// Маски остальных секретов не раскрыты: радиусный секрет в теле отсутствует.
	if sec := set.Get().RadiusSecret; sec != "" && strings.Contains(rec.Body.String(), sec) {
		t.Fatal("тело ответа раскрывает radius.secret")
	}
}

// TestPagesAnonymousRedirects: / и защищённые страницы анонимом → /login.
func TestPagesAnonymousRedirects(t *testing.T) {
	st, set, box := setup(t)
	rt := newPagesRouter(t, st, set, box)
	c := newHTMLClient(t, rt.Handler)

	wantLocation(t, c.get("/"), http.StatusFound, "/login")
	wantLocation(t, c.get("/me"), http.StatusFound, "/login")
	wantLocation(t, c.get("/admin/users"), http.StatusFound, "/login")
	wantLocation(t, c.get("/me/devices"), http.StatusFound, "/login")

	// Неизвестный путь — HTML-404.
	rec := c.get("/no/such/page")
	wantStatus(t, rec, http.StatusNotFound)
	wantBody(t, rec, "Ошибка 404")
}

// TestPagesAdminSettingsSMSMasked (SEC-004): страница настроек рендерит
// sms.gateway замаскированным (креды не покидают сервер); отправка формы
// без изменений сохраняет креды, ввод новых — заменяет.
func TestPagesAdminSettingsSMSMasked(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	rt := newPagesRouter(t, st, set, box)
	admin := mkUser(t, ctx, st, "smsadmin", func(u *store.User) { u.Role = "admin" })
	t.Cleanup(func() {
		_ = set.Put(ctx, "sms.gateway", json.RawMessage(`{}`))
	})

	// Реальный конфиг с кредами.
	gw := json.RawMessage(`{"preset":"smsc","method":"GET","url":"https://gate.example/send",` +
		`"headers":{"login":"REAL-LOGIN","psw":"REAL-PSW"},"success":{"http_status":200}}`)
	if err := set.Put(ctx, "sms.gateway", gw); err != nil {
		t.Fatalf("set.Put(sms.gateway): %v", err)
	}

	c := newHTMLClient(t, rt.Handler)
	rec := c.login(t, admin.Username, testPassword, "")
	wantStatus(t, rec, http.StatusFound)

	// GET: маска в textarea, креды не в теле страницы.
	rec = c.get("/admin/settings")
	wantStatus(t, rec, http.StatusOK)
	for _, secret := range []string{"REAL-LOGIN", "REAL-PSW"} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Fatalf("страница настроек раскрывает кред %q", secret)
		}
	}
	// textarea sms.gateway содержит маски-объекты и подсказку.
	m := textareaRe.FindStringSubmatch(rec.Body.String())
	var found bool
	for _, mm := range textareaRe.FindAllStringSubmatch(rec.Body.String(), -1) {
		if mm[1] == "sms.gateway" {
			m = mm
			found = true
		}
	}
	if !found {
		t.Fatal("textarea sms.gateway не найдена на странице")
	}
	if !strings.Contains(m[2], "••••") {
		t.Fatalf("textarea sms.gateway без масок: %s", m[2])
	}

	// POST секции sms с замаскированным значением как есть → креды живы.
	form := url.Values{
		"section":     {"sms"},
		"sms.gateway": {html.UnescapeString(m[2])},
		"sms.presets": {"{}"},
	}
	rec = c.postForm("/admin/settings", form, true)
	wantStatus(t, rec, http.StatusFound)
	after, err := set.Get().SMSGateway()
	if err != nil {
		t.Fatalf("SMSGateway: %v", err)
	}
	if after.Headers["login"] != "REAL-LOGIN" || after.Headers["psw"] != "REAL-PSW" {
		t.Fatalf("отправка маскированной формы изменила креды: %v", after.Headers)
	}

	// POST с новыми кредами → заменены.
	form = url.Values{
		"section":     {"sms"},
		"sms.gateway": {`{"preset":"smsc","method":"GET","url":"https://gate.example/send","headers":{"login":"NEW-LOGIN","psw":"NEW-PSW"},"success":{"http_status":200}}`},
		"sms.presets": {"{}"},
	}
	rec = c.postForm("/admin/settings", form, true)
	wantStatus(t, rec, http.StatusFound)
	after, err = set.Get().SMSGateway()
	if err != nil {
		t.Fatalf("SMSGateway: %v", err)
	}
	if after.Headers["login"] != "NEW-LOGIN" || after.Headers["psw"] != "NEW-PSW" {
		t.Fatalf("новые креды не применились: %v", after.Headers)
	}
}

// TestSecurityHeaders (SEC-011): заголовки безопасности присутствуют на
// HTML-страницах (/ и /login) и статике полной композиции BuildRouter.
func TestSecurityHeaders(t *testing.T) {
	st, set, box := setup(t)
	rt := newPagesRouter(t, st, set, box)

	for _, path := range []string{"/", "/login"} {
		rec := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		rt.Handler.ServeHTTP(w, rec)
		h := w.Header()
		if got := h.Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s: X-Content-Type-Options = %q, want nosniff", path, got)
		}
		if got := h.Get("X-Frame-Options"); got != "DENY" {
			t.Errorf("%s: X-Frame-Options = %q, want DENY", path, got)
		}
		if got := h.Get("Referrer-Policy"); got != "no-referrer" {
			t.Errorf("%s: Referrer-Policy = %q, want no-referrer", path, got)
		}
		wantCSP := "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self' ws: wss:; media-src 'self' blob:"
		if got := h.Get("Content-Security-Policy"); got != wantCSP {
			t.Errorf("%s: CSP = %q, want %q", path, got, wantCSP)
		}
	}

	// Инлайн-обработчики вынесены в data-атрибуты (CSP без unsafe-*):
	// ни один шаблон не содержит onclick=/style=.
	files, err := filepath.Glob(filepath.Join("..", "web", "templates", "*.gohtml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("шаблоны не найдены: %v", err)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("чтение %s: %v", f, err)
		}
		for _, bad := range []string{"onclick=", "onchange=", "onsubmit=", "style="} {
			if strings.Contains(string(b), bad) {
				t.Errorf("%s содержит инлайн-атрибут %q (запрещён CSP)", filepath.Base(f), bad)
			}
		}
	}
}

// TestPagesLoginPasskey проверяет форму /login для пользователя с Passkey:
// показ кнопки и подсказки Passkey, а также успешный вход при наличии webauthn_web_pending.
func TestPagesLoginPasskey(t *testing.T) {
	st, set, box := setup(t)
	ctx := t.Context()
	rt := newPagesRouter(t, st, set, box)

	u := mkUser(t, ctx, st, "passkey-user", nil)
	// Добавляем зарегистрированный passkey
	if err := st.WACredUpsert(ctx, u.ID, &store.WACred{
		CredentialID:    []byte("cred-1"),
		RPID:            "localhost",
		PublicKey:       []byte("pk-1"),
		AttestationType: "none",
		Present:         true,
		Verified:        true,
	}); err != nil {
		t.Fatalf("WACredUpsert: %v", err)
	}

	cli := newHTMLClient(t, rt.Handler)

	// Шаг 1: попытка входа без кода при отсутствии активного pending-окна.
	// Должна отрендерить форму с NeedCode, подсказкой о Passkey и кнопкой Passkey.
	rec := cli.postForm("/login", url.Values{
		"username": {u.Username},
		"password": {testPassword},
		"code":     {""},
	}, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /login: status=%d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Passkey") {
		t.Errorf("страница входа не упоминает Passkey: %s", body)
	}
	if !strings.Contains(body, "data-passkey-login") {
		t.Errorf("на странице нет кнопки data-passkey-login: %s", body)
	}

	// Шаг 2: завершённая WebAuthn-церемония (создаётся webauthn_web_pending).
	if err := createWebPendingChallenge(ctx, st, u.ID); err != nil {
		t.Fatalf("createWebPendingChallenge: %v", err)
	}

	// Шаг 3: вход с пустым кодом после успешной церемонии -> редирект 302 на /me и выпуск сессии.
	rec = cli.postForm("/login", url.Values{
		"username": {u.Username},
		"password": {testPassword},
		"code":     {""},
	}, false)
	if rec.Code != http.StatusFound {
		t.Fatalf("POST /login с pending passkey: status=%d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "/me") {
		t.Errorf("Location = %q, want /me", loc)
	}
	if cli.session == nil {
		t.Error("cookie twofa_session не установлен после passkey-входа")
	}
}

func TestPagesSendCode(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	rt := newPagesRouter(t, st, set, box)

	user := mkUser(t, ctx, st, "sendcode_user", nil)
	cli := newHTMLClient(t, rt.Handler)
	rec := cli.login(t, user.Username, testPassword, "")
	wantStatus(t, rec, http.StatusFound)

	// Настраиваем Email пользователю
	user.Email = "sendcode@example.com"
	if err := st.UserUpdate(ctx, user); err != nil {
		t.Fatalf("UserUpdate: %v", err)
	}

	// 1. Стандартный POST формы без указания return_to -> редирект 302 на /me с флешем
	rec = cli.postForm("/me/send-code", url.Values{}, true)
	wantStatus(t, rec, http.StatusFound)
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/me?") || !strings.Contains(loc, "flash=") {
		t.Fatalf("Location = %q, want /me с флешем", loc)
	}
	page := cli.get(loc)
	wantStatus(t, page, http.StatusOK)
	wantBody(t, page, "Код подтверждения отправлен на Email.")

	// 2. Срабатывание cooldown при немедленном повторе (по форме) с return_to: /me/backup
	rec = cli.postForm("/me/send-code", url.Values{"return_to": {"/me/backup"}}, true)
	wantStatus(t, rec, http.StatusFound)
	loc = rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/me/backup?") {
		t.Fatalf("Location = %q, want /me/backup с флешем", loc)
	}
	page = cli.get(loc)
	wantStatus(t, page, http.StatusOK)
	wantBody(t, page, "Подождите перед повторной отправкой кода.")

	// 3. AJAX-запрос (Accept: application/json) во время cooldown -> 429 JSON
	rec = cli.postFetch("/me/send-code", url.Values{})
	wantStatus(t, rec, http.StatusTooManyRequests)
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal json: %v", err)
	}
	if resp["ok"] != false || resp["error"] != "cooldown" {
		t.Errorf("resp = %v, want ok:false, error:cooldown", resp)
	}

	// 4. Пользователь без каналов доставки -> ошибка no_channel
	uNoChan := mkUser(t, ctx, st, "nochan_user", nil)
	cliNoChan := newHTMLClient(t, rt.Handler)
	rec = cliNoChan.login(t, uNoChan.Username, testPassword, "")
	wantStatus(t, rec, http.StatusFound)

	rec = cliNoChan.postFetch("/me/send-code", url.Values{})
	wantStatus(t, rec, http.StatusBadRequest)
	var respNoChan map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &respNoChan); err != nil {
		t.Fatalf("unmarshal json: %v", err)
	}
	if respNoChan["ok"] != false || respNoChan["error"] != "no_channel" {
		t.Errorf("resp = %v, want ok:false, error:no_channel", respNoChan)
	}

	// 5. Успешный AJAX-запрос на свежем пользователе с Email
	uAjax := mkUser(t, ctx, st, "ajax_user", nil)
	cliAjax := newHTMLClient(t, rt.Handler)
	rec = cliAjax.login(t, uAjax.Username, testPassword, "")
	wantStatus(t, rec, http.StatusFound)
	uAjax.Email = "ajax@example.com"
	if err := st.UserUpdate(ctx, uAjax); err != nil {
		t.Fatalf("UserUpdate: %v", err)
	}

	rec = cliAjax.postFetch("/me/send-code", url.Values{})
	wantStatus(t, rec, http.StatusOK)
	var respAjax map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &respAjax); err != nil {
		t.Fatalf("unmarshal json: %v", err)
	}
	if respAjax["ok"] != true || respAjax["channel"] != "email" || !strings.Contains(respAjax["message"].(string), "Email") {
		t.Errorf("respAjax = %v, want ok:true, channel:email", respAjax)
	}
}

// TestPagesSafeNextBackslash: backslash в ?next не открывает редирект на
// внешний сайт (report 2026-09-11, P1 OIDC-1): «\» браузеры трактуют как «/»,
// поэтому /\evil.com должен отсекаться и на GET (hidden-поле), и на POST
// (Location после входа).
func TestPagesSafeNextBackslash(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	rt := newPagesRouter(t, st, set, box)
	c := newHTMLClient(t, rt.Handler)

	// GET /login?next=/\evil.com: backslash-адрес не проксируется в форму.
	rec := c.get("/login?next=" + url.QueryEscape(`/\evil.com`))
	wantStatus(t, rec, http.StatusOK)
	if strings.Contains(rec.Body.String(), `/\evil.com`) {
		t.Error("backslash-next попал в hidden-поле формы")
	}

	// POST /login с backslash-next: редирект остаётся локальным.
	user := mkUser(t, ctx, st, "nextuser", nil)
	rec = c.postForm("/login", url.Values{
		"username": {user.Username},
		"password": {testPassword},
		"next":     {`/\evil.com`},
	}, false)
	wantStatus(t, rec, http.StatusFound)
	loc := rec.Header().Get("Location")
	if strings.Contains(loc, "evil.com") {
		t.Fatalf("открытый редирект через backslash: %q", loc)
	}
	if !strings.HasPrefix(loc, "/me") {
		t.Fatalf("Location = %q, хочу локальный /me", loc)
	}

	// Санитарный контроль: валидный локальный next сохраняется.
	user2 := mkUser(t, ctx, st, "nextuser2", nil)
	rec = c.postForm("/login", url.Values{
		"username": {user2.Username},
		"password": {testPassword},
		"next":     {"/oidc/authorize?client_id=mfa_x"},
	}, false)
	wantStatus(t, rec, http.StatusFound)
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "/oidc/authorize?client_id=mfa_x") {
		t.Fatalf("Location = %q, хочу возврат на /oidc/authorize", loc)
	}
}

// TestPagesBrandingLogo — GET /branding/logo: same-origin раздача логотипа
// белого лейбла (report 2026-09-11, Web UI-2). data:URI декодируется с
// правильным Content-Type, https — 302, free-лицензия/пусто/битое — 404.
func TestPagesBrandingLogo(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	lic := license.NewManager(st)
	rt := newPagesRouterLic(t, st, set, box)

	const png1x1 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
	pngBytes, err := base64.StdEncoding.DecodeString(png1x1)
	if err != nil {
		t.Fatalf("декодирование PNG: %v", err)
	}
	dataURI := "data:image/png;base64," + png1x1
	if err := set.Put(ctx, "branding", json.RawMessage(`{"logo":"`+dataURI+`"}`)); err != nil {
		t.Fatalf("Put branding: %v", err)
	}

	get := func(path string) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		rt.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec
	}

	// Free-лицензия: бренд скрыт (тот же решатель, что у шаблонов) — 404.
	if rec := get("/branding/logo"); rec.Code != http.StatusNotFound {
		t.Fatalf("free: GET /branding/logo = %d, want 404", rec.Code)
	}

	// Платная лицензия: data:URI отдаётся как image/png.
	blob := signTestLicense(t, "k-logo", nil)
	if _, err := lic.Upload(ctx, blob); err != nil {
		t.Fatalf("Upload лицензии: %v", err)
	}
	rec := get("/branding/logo")
	wantStatus(t, rec, http.StatusOK)
	if ct := rec.Header().Get("Content-Type"); ct != "image/png" {
		t.Errorf("Content-Type = %q, want image/png", ct)
	}
	if rec.Body.Len() != len(pngBytes) || string(rec.Body.Bytes()) != string(pngBytes) {
		t.Errorf("тело ответа не совпадает с декодированным логотипом (%d байт)", rec.Body.Len())
	}
	if cc := rec.Header().Get("Cache-Control"); cc == "" {
		t.Error("нет Cache-Control у логотипа")
	}

	// Страница входа ссылается на same-origin маршрут, а не на data:/https.
	rec = newHTMLClient(t, rt.Handler).get("/login")
	wantStatus(t, rec, http.StatusOK)
	wantBody(t, rec, `src="/branding/logo"`)
	if strings.Contains(rec.Body.String(), "ZgotmplZ") || strings.Contains(rec.Body.String(), dataURI) {
		t.Error("логотип попал в разметку как data:URI")
	}

	// https-URL → 302 на внешний ресурс.
	if err := set.Put(ctx, "branding", json.RawMessage(`{"logo":"https://brand.example/logo.png"}`)); err != nil {
		t.Fatalf("Put branding: %v", err)
	}
	rec = get("/branding/logo")
	wantStatus(t, rec, http.StatusFound)
	if loc := rec.Header().Get("Location"); loc != "https://brand.example/logo.png" {
		t.Fatalf("Location = %q, want https://brand.example/logo.png", loc)
	}

	// SVG под запретом (исполняет скрипты при прямом открытии URL) и мусор → 404.
	for _, bad := range []string{
		"data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte("<svg onload=alert(1)>")),
		"data:image/png,not-base64!!",
		"javascript:alert(1)",
	} {
		if err := set.Put(ctx, "branding", json.RawMessage(`{"logo":"`+bad+`"}`)); err != nil {
			t.Fatalf("Put branding: %v", err)
		}
		if rec := get("/branding/logo"); rec.Code != http.StatusNotFound {
			t.Errorf("логотип %q: код %d, want 404", bad, rec.Code)
		}
	}

	// Пустое значение → 404.
	if err := set.Put(ctx, "branding", json.RawMessage(`{"logo":""}`)); err != nil {
		t.Fatalf("Put branding: %v", err)
	}
	if rec := get("/branding/logo"); rec.Code != http.StatusNotFound {
		t.Errorf("пустой логотип: код %d, want 404", rec.Code)
	}
}

// TestPagesAdsCSPPerPages — CSP расширяется доменами Яндекса только у
// страницы с фактически отрендеренными рекламными слотами (report
// 2026-09-11, Web UI-1), а не у всех ответов: админка без слотов остаётся
// под строгой политикой.
func TestPagesAdsCSPPerPages(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	rt := newPagesRouterLic(t, st, set, box)

	// РСЯ-слоты включены, лицензия free → реклама на страницах входа.
	ads := `{"enabled":true,"provider":"rsya","blocks":{"login_left":"R-A-1","login_right":"R-A-2"}}`
	if err := set.Put(ctx, "ads", json.RawMessage(ads)); err != nil {
		t.Fatalf("Put ads: %v", err)
	}

	c := newHTMLClient(t, rt.Handler)
	rec := c.get("/login")
	wantStatus(t, rec, http.StatusOK)
	wantBody(t, rec, `id="adv-login-left"`, `id="adv-login-right"`)
	if got := rec.Header().Get("Content-Security-Policy"); got != web.ContentSecurityPolicyAds {
		t.Errorf("/login: CSP = %q, want relaxed-вариант", got)
	}

	// Кабинет и админка без бокового слота — строгая CSP.
	admin := mkUser(t, ctx, st, "csp-admin", func(u *store.User) { u.Role = "admin" })
	rec = c.login(t, admin.Username, testPassword, "")
	wantStatus(t, rec, http.StatusFound)
	for _, path := range []string{"/me", "/admin/users", "/admin/settings"} {
		rec = c.get(path)
		wantStatus(t, rec, http.StatusOK)
		if got := rec.Header().Get("Content-Security-Policy"); got != web.ContentSecurityPolicy {
			t.Errorf("%s: CSP = %q, want строгая базовая", path, got)
		}
	}

	// Выключение рекламы возвращает строгую CSP и странице входа.
	if err := set.Put(ctx, "ads", json.RawMessage(`{"enabled":false}`)); err != nil {
		t.Fatalf("Put ads: %v", err)
	}
	rec = c.get("/login")
	if got := rec.Header().Get("Content-Security-Policy"); got != web.ContentSecurityPolicy {
		t.Errorf("/login без рекламы: CSP = %q, want строгая базовая", got)
	}

	// Direct-слот с внешней картинкой тоже требует relaxed-CSP (img-src https:).
	if err := set.Put(ctx, "ads", json.RawMessage(
		`{"enabled":true,"provider":"direct","direct":{"url":"https://ads.example/x","image":"https://ads.example/banner.png"}}`)); err != nil {
		t.Fatalf("Put ads: %v", err)
	}
	rec = c.get("/login")
	if got := rec.Header().Get("Content-Security-Policy"); got != web.ContentSecurityPolicyAds {
		t.Errorf("/login (direct-картинка): CSP = %q, want relaxed-вариант", got)
	}
}
