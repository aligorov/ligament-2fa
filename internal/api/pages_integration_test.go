//go:build integration

// Интеграционные тесты HTML-обвязки (pages.go) на полной композиции
// BuildRouter — как в main: логин-флоу формами (302), сессия+CSRF форм,
// рендер страниц, админ-редиректы, сохранение форм, маскировка настроек.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"html"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/aligorov/twofa/internal/auth"
	"github.com/aligorov/twofa/internal/channel"
	"github.com/aligorov/twofa/internal/delivery"
	"github.com/aligorov/twofa/internal/secrets"
	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
	"github.com/aligorov/twofa/internal/web"
)

// newPagesRouter — полная композиция через BuildRouter (как main).
func newPagesRouter(t *testing.T, st *store.Store, set *settings.M, box *secrets.Box) *Router {
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
		Core: core, St: st, Box: box, PV: auth.NewLocalVerifier(st), M: set, Rend: rend,
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
		"section":           {"telegram"},
		"telegram.bot_token": {"123456:AA-test-token"},
	}
	rec = c.postForm("/admin/settings", form, true)
	wantStatus(t, rec, http.StatusFound)
	if set.Get().TG.BotToken != "123456:AA-test-token" {
		t.Fatalf("telegram.bot_token не сохранён: %q", set.Get().TG.BotToken)
	}
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

// parseSettingsForm разбирает блок <form> на секцию и карту «имя → значение»
// (браузер отправил бы ровно это); checkbox без checked в форму не входит.
func parseSettingsForm(block string) (section string, fields map[string]string) {
	fields = map[string]string{}
	if m := sectionRe.FindStringSubmatch(block); m != nil {
		section = m[1]
	}
	for _, m := range inputRe.FindAllStringSubmatch(block, -1) {
		name, tag := m[1], m[0]
		if name == "csrf_token" || name == "section" || name == "regenerate" {
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
