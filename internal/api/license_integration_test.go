//go:build integration

// Интеграционные тесты лицензирования (postgres testcontainer, общий
// харнесс пакета): загрузка лицензии тестовым ключом (SetTrustedKeys),
// enforcement лимита на POST /users (403 license_limit + аудит), включение
// отключённых, вход существующим не блокируется, CRL-отзыв, кривые блобы,
// персистентность старта демо, баннер на /admin-страницах.
package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aligorov/twofa/internal/auth"
	"github.com/aligorov/twofa/internal/channel"
	"github.com/aligorov/twofa/internal/delivery"
	"github.com/aligorov/twofa/internal/license"
	"github.com/aligorov/twofa/internal/secrets"
	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
	"github.com/aligorov/twofa/internal/web"
)

// licenseCleanup вычищает ключи license.* (контейнер один на пакет — тесты
// не должны видеть лицензии друг друга).
func licenseCleanup(t *testing.T, st *store.Store) {
	t.Helper()
	if _, err := st.Pool().Exec(context.Background(),
		`DELETE FROM settings WHERE key IN ('license.blob','license.crl','license.trial_started')`); err != nil {
		t.Fatalf("очистка license.*: %v", err)
	}
}

// newPagesRouterLic — полная композиция BuildRouter с менеджером лицензий
// (как в main.go).
func newPagesRouterLic(t *testing.T, st *store.Store, set *settings.M, box *secrets.Box) *Router {
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
		Lic: license.NewManager(st),
	})
	t.Cleanup(rt.Stop)
	return rt
}

// activeUsers считает включённых пользователей.
func activeUsers(t *testing.T, st *store.Store) int {
	t.Helper()
	users, err := st.UserList(context.Background())
	if err != nil {
		t.Fatalf("UserList: %v", err)
	}
	n := 0
	for _, u := range users {
		if u.Enabled {
			n++
		}
	}
	return n
}

// signTestLicense выпускает лицензию свежей тестовой парой ключей kid и
// подменяет ею доверенные ключи (восстановление — t.Cleanup).
func signTestLicense(t *testing.T, kid string, mutate func(*license.Payload)) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	restore := license.SetTrustedKeys(map[string]ed25519.PublicKey{kid: pub})
	t.Cleanup(restore)

	exp := time.Now().Add(365 * 24 * time.Hour)
	p := license.Payload{
		LicID:              "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		Customer:           "ООО Тест",
		Plan:               license.PlanSubscription,
		UserLimit:          100,
		IssuedAt:           time.Now().UTC(),
		ExpiresAt:          &exp,
		MaintenanceExpires: exp,
		Kid:                kid,
	}
	if mutate != nil {
		mutate(&p)
	}
	blob, err := license.Sign(priv, p)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return blob
}

// signTestPair — пара ключей с регистрацией kid (для лицензии + CRL).
func signTestPair(t *testing.T, kid string) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	restore := license.SetTrustedKeys(map[string]ed25519.PublicKey{kid: pub})
	t.Cleanup(restore)
	return priv
}

// TestLicenseUploadEnforcesLimit: лицензия с лимитом = текущему числу
// активных → создание 403 license_limit (+аудит), выключение разрешено,
// включение под лимитом разрешено, вход существующего не блокируется;
// DELETE → free (лимит 5); страница /admin/license рендерится.
func TestLicenseUploadEnforcesLimit(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	licenseCleanup(t, st)
	defer licenseCleanup(t, st)

	admin := mkUser(t, ctx, st, "licadmin", func(u *store.User) { u.Role = "admin" })
	extra := mkUser(t, ctx, st, "licextra", nil)
	rt := newPagesRouterLic(t, st, set, box)
	tok := set.Get().AdminToken

	n := activeUsers(t, st)
	blob := signTestLicense(t, "it-key-1", func(p *license.Payload) { p.UserLimit = n })

	// Загрузка: статус licensed, X/Y = n/n, at_limit, БЕЗ блоба.
	rec := adminReq(t, rt.Handler, http.MethodPut, "/api/v1/admin/license",
		map[string]any{"blob": blob}, tok)
	wantStatus(t, rec, http.StatusOK)
	body := jsonBody(t, rec)
	if body["mode"] != "licensed" || body["user_limit"] != float64(n) ||
		body["active_users"] != float64(n) || body["at_limit"] != true {
		t.Fatalf("статус после загрузки: %v", body)
	}
	if strings.Contains(rec.Body.String(), "BEGIN LIGAMENT") {
		t.Fatal("статус раскрывает blob лицензии")
	}

	// Создание сверх лимита → 403 license_limit.
	rec = adminReq(t, rt.Handler, http.MethodPost, "/api/v1/admin/users",
		map[string]any{"username": "licover", "password": "over-limit-1"}, tok)
	wantStatus(t, rec, http.StatusForbidden)
	if jsonBody(t, rec)["error"] != "license_limit" {
		t.Fatalf("тело 403: %s", rec.Body.String())
	}

	// Аудит: license_upload и license_limit записаны.
	rows, err := st.AuditList(ctx, store.AuditFilter{Event: "admin_action", Limit: 200})
	if err != nil {
		t.Fatalf("AuditList: %v", err)
	}
	sawUpload, sawLimit := false, false
	for _, row := range rows {
		if row.Detail == nil {
			continue
		}
		switch row.Detail["action"] {
		case "license_upload":
			sawUpload = true
		case "license_limit":
			sawLimit = true
		}
	}
	if !sawUpload || !sawLimit {
		t.Fatalf("аудит: upload=%v limit=%v", sawUpload, sawLimit)
	}

	// Выключение разрешено (счётчик падает), обратное включение — по лимиту.
	rec = adminReq(t, rt.Handler, http.MethodPatch, "/api/v1/admin/users/"+extra.ID.String(),
		map[string]any{"enabled": false}, tok)
	wantStatus(t, rec, http.StatusOK)
	rec = adminReq(t, rt.Handler, http.MethodPatch, "/api/v1/admin/users/"+extra.ID.String(),
		map[string]any{"enabled": true}, tok)
	wantStatus(t, rec, http.StatusOK)

	// Вход существующего пользователя НЕ блокируется лицензией (report §3.3).
	c := newWebClient(t, rt.Handler)
	rec = c.login("licextra", testPassword, false)
	wantStatus(t, rec, http.StatusOK)

	// Удаление лицензии → free, лимит 5.
	rec = adminReq(t, rt.Handler, http.MethodDelete, "/api/v1/admin/license", nil, tok)
	wantStatus(t, rec, http.StatusOK)
	body = jsonBody(t, rec)
	if body["mode"] != "free" || body["user_limit"] != float64(license.FreeUserLimit) {
		t.Fatalf("статус после удаления: %v", body)
	}

	// Страница /admin/license рендерится с формами.
	c2 := newHTMLClient(t, rt.Handler)
	rec = c2.login(t, admin.Username, testPassword, "")
	wantStatus(t, rec, http.StatusFound)
	rec = c2.get("/admin/license")
	wantStatus(t, rec, http.StatusOK)
	wantBody(t, rec, "<h1>Лицензия</h1>", "BEGIN LIGAMENT LICENSE", `action="/admin/license"`)
}

// TestLicenseLimitBlocksEnabling: включение отключённого сверх лимита —
// 403 (это «создание» активного пользователя), выключение — нет.
func TestLicenseLimitBlocksEnabling(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	licenseCleanup(t, st)
	defer licenseCleanup(t, st)

	mkUser(t, ctx, st, "enadmin", func(u *store.User) { u.Role = "admin" })
	disabled := mkUser(t, ctx, st, "endisabled", func(u *store.User) { u.Enabled = false })
	rt := newPagesRouterLic(t, st, set, box)
	tok := set.Get().AdminToken

	n := activeUsers(t, st)
	blob := signTestLicense(t, "it-key-2", func(p *license.Payload) { p.UserLimit = n })
	rec := adminReq(t, rt.Handler, http.MethodPut, "/api/v1/admin/license",
		map[string]any{"blob": blob}, tok)
	wantStatus(t, rec, http.StatusOK)

	// Включение сверх лимита → 403 license_limit.
	rec = adminReq(t, rt.Handler, http.MethodPatch, "/api/v1/admin/users/"+disabled.ID.String(),
		map[string]any{"enabled": true}, tok)
	wantStatus(t, rec, http.StatusForbidden)
	if jsonBody(t, rec)["error"] != "license_limit" {
		t.Fatalf("тело 403 включения: %s", rec.Body.String())
	}

	// Выключение уже отключённого — разрешено (не меняет счётчик активных).
	rec = adminReq(t, rt.Handler, http.MethodPatch, "/api/v1/admin/users/"+disabled.ID.String(),
		map[string]any{"enabled": false}, tok)
	wantStatus(t, rec, http.StatusOK)
}

// TestLicenseInvalidUploads: мусор → invalid_format; подпись чужим ключом →
// invalid_signature; пустой blob → bad_request.
func TestLicenseInvalidUploads(t *testing.T) {
	st, set, box := setup(t)
	licenseCleanup(t, st)
	defer licenseCleanup(t, st)
	rt := newPagesRouterLic(t, st, set, box)
	tok := set.Get().AdminToken

	// Мусор.
	rec := adminReq(t, rt.Handler, http.MethodPut, "/api/v1/admin/license",
		map[string]any{"blob": "не лицензия"}, tok)
	wantStatus(t, rec, http.StatusBadRequest)
	if jsonBody(t, rec)["error"] != "invalid_format" {
		t.Fatalf("мусор: %s", rec.Body.String())
	}

	// Валидная подпись НЕдоверенным kid → invalid_signature.
	blob := signTestLicense(t, "it-unknown", func(p *license.Payload) { p.Kid = "stranger" })
	rec = adminReq(t, rt.Handler, http.MethodPut, "/api/v1/admin/license",
		map[string]any{"blob": blob}, tok)
	wantStatus(t, rec, http.StatusBadRequest)
	if jsonBody(t, rec)["error"] != "invalid_signature" {
		t.Fatalf("чужой ключ: %s", rec.Body.String())
	}

	// Пустой blob → bad_request.
	rec = adminReq(t, rt.Handler, http.MethodPut, "/api/v1/admin/license",
		map[string]any{"blob": ""}, tok)
	wantStatus(t, rec, http.StatusBadRequest)
	if jsonBody(t, rec)["error"] != "bad_request" {
		t.Fatalf("пустой blob: %s", rec.Body.String())
	}
}

// TestLicenseRevocationByCRL: подписка отозвана CRL → free+revoked;
// повторная загрузка той же лицензии → 400 revoked; битый CRL → 400.
func TestLicenseRevocationByCRL(t *testing.T) {
	st, set, box := setup(t)
	licenseCleanup(t, st)
	defer licenseCleanup(t, st)
	rt := newPagesRouterLic(t, st, set, box)
	tok := set.Get().AdminToken

	priv := signTestPair(t, "it-crl")
	exp := time.Now().Add(200 * 24 * time.Hour)
	p := license.Payload{
		LicID: "12345678-90ab-cdef-1234-567890abcdef", Customer: "ООО Отзыв",
		Plan: license.PlanSubscription, UserLimit: 100,
		IssuedAt: time.Now().UTC(), ExpiresAt: &exp,
		MaintenanceExpires: exp, Kid: "it-crl",
	}
	blob, err := license.Sign(priv, p)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	rec := adminReq(t, rt.Handler, http.MethodPut, "/api/v1/admin/license",
		map[string]any{"blob": blob}, tok)
	wantStatus(t, rec, http.StatusOK)

	// CRL на эту лицензию.
	crl, err := license.SignRevocation(priv, license.Revocation{
		LicID: p.LicID, RevokedAt: time.Now().UTC(), Kid: "it-crl",
	})
	if err != nil {
		t.Fatalf("SignRevocation: %v", err)
	}
	rec = adminReq(t, rt.Handler, http.MethodPut, "/api/v1/admin/license/crl",
		map[string]any{"blob": crl}, tok)
	wantStatus(t, rec, http.StatusOK)
	if jsonBody(t, rec)["lic_id"] != p.LicID {
		t.Fatalf("ответ CRL: %s", rec.Body.String())
	}

	// Статус: free + revoked (сервер не падает, лимит 5).
	rec = adminReq(t, rt.Handler, http.MethodGet, "/api/v1/admin/license", nil, tok)
	wantStatus(t, rec, http.StatusOK)
	body := jsonBody(t, rec)
	if body["mode"] != "free" || body["revoked"] != true || body["user_limit"] != float64(license.FreeUserLimit) {
		t.Fatalf("статус после CRL: %v", body)
	}

	// Повторная загрузка отозванной → 400 revoked.
	rec = adminReq(t, rt.Handler, http.MethodPut, "/api/v1/admin/license",
		map[string]any{"blob": blob}, tok)
	wantStatus(t, rec, http.StatusBadRequest)
	if jsonBody(t, rec)["error"] != "revoked" {
		t.Fatalf("повторная загрузка: %s", rec.Body.String())
	}

	// Битый CRL → invalid_format.
	rec = adminReq(t, rt.Handler, http.MethodPut, "/api/v1/admin/license/crl",
		map[string]any{"blob": "мусор"}, tok)
	wantStatus(t, rec, http.StatusBadRequest)
	if jsonBody(t, rec)["error"] != "invalid_format" {
		t.Fatalf("битый CRL: %s", rec.Body.String())
	}
}

// TestLicenseTrialPersistence: Init отмечает старт демо один раз (повторный
// Init не сдвигает), Effective даёт trial без лимита; старт 31 день назад —
// free/5 (деградация, не блокировка входа).
func TestLicenseTrialPersistence(t *testing.T) {
	st, _, _ := setup(t)
	ctx := context.Background()
	licenseCleanup(t, st)
	defer licenseCleanup(t, st)

	m := license.NewManager(st)
	if err := m.Init(ctx); err != nil {
		t.Fatalf("Init: %v", err)
	}
	st1, err := m.Effective(ctx)
	if err != nil {
		t.Fatalf("Effective: %v", err)
	}
	if st1.Mode != license.ModeTrial || st1.UserLimit > 0 {
		t.Fatalf("после Init: %+v, хочу trial без лимита", st1)
	}

	// Повторный Init не перезаписывает старт демо.
	if err := m.Init(ctx); err != nil {
		t.Fatalf("Init (повтор): %v", err)
	}
	st2, _ := m.Effective(ctx)
	if st2.Mode != license.ModeTrial || st2.TrialDaysLeft != st1.TrialDaysLeft {
		t.Fatalf("старт демо сдвинулся: %v → %v", st1, st2)
	}

	// Демо истекло (31 день назад) → free/5.
	if _, err := st.Pool().Exec(ctx,
		`UPDATE settings SET value = to_jsonb(to_char(now() - interval '31 days',
			 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
		 WHERE key = 'license.trial_started'`); err != nil {
		t.Fatalf("сдвиг trial_started: %v", err)
	}
	st3, err := m.Effective(ctx)
	if err != nil {
		t.Fatalf("Effective (истекло): %v", err)
	}
	if st3.Mode != license.ModeFree || st3.UserLimit != license.FreeUserLimit {
		t.Fatalf("после демо: %+v, хочу free/%d", st3, license.FreeUserLimit)
	}
}

// TestLicenseBannerOnAdminPages: баннер виден админу при достижении лимита,
// обычному пользователю — нет.
func TestLicenseBannerOnAdminPages(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	licenseCleanup(t, st)
	defer licenseCleanup(t, st)

	admin := mkUser(t, ctx, st, "banadmin", func(u *store.User) { u.Role = "admin" })
	plain := mkUser(t, ctx, st, "banplain", nil)
	rt := newPagesRouterLic(t, st, set, box)

	n := activeUsers(t, st)
	blob := signTestLicense(t, "it-banner", func(p *license.Payload) { p.UserLimit = n })
	rec := adminReq(t, rt.Handler, http.MethodPut, "/api/v1/admin/license",
		map[string]any{"blob": blob}, set.Get().AdminToken)
	wantStatus(t, rec, http.StatusOK)

	// Админ видит баннер лимита на страницах приложения.
	c := newHTMLClient(t, rt.Handler)
	rec = c.login(t, admin.Username, testPassword, "")
	wantStatus(t, rec, http.StatusFound)
	rec = c.get("/admin/users")
	wantStatus(t, rec, http.StatusOK)
	wantBody(t, rec, "Достигнут лимит лицензии")

	// Обычный пользователь баннера не видит.
	c2 := newHTMLClient(t, rt.Handler)
	rec = c2.login(t, plain.Username, testPassword, "")
	wantStatus(t, rec, http.StatusFound)
	rec = c2.get("/me")
	wantStatus(t, rec, http.StatusOK)
	if strings.Contains(rec.Body.String(), "лимита лицензии") {
		t.Fatal("баннер лицензии виден не-админу")
	}
}

// TestLicenseFormCreateBlocked: HTML-форма создания пользователя сверх
// лимита — редирект с флешем (PRG), не 500; аудит license_limit (via html).
func TestLicenseFormCreateBlocked(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	licenseCleanup(t, st)
	defer licenseCleanup(t, st)

	admin := mkUser(t, ctx, st, "formadmin", func(u *store.User) { u.Role = "admin" })
	rt := newPagesRouterLic(t, st, set, box)

	n := activeUsers(t, st)
	blob := signTestLicense(t, "it-form", func(p *license.Payload) { p.UserLimit = n })
	rec := adminReq(t, rt.Handler, http.MethodPut, "/api/v1/admin/license",
		map[string]any{"blob": blob}, set.Get().AdminToken)
	wantStatus(t, rec, http.StatusOK)

	c := newHTMLClient(t, rt.Handler)
	rec = c.login(t, admin.Username, testPassword, "")
	wantStatus(t, rec, http.StatusFound)
	form := url.Values{
		"username": {"formover"}, "password": {"form-pass-1"}, "enabled": {"on"},
	}
	rec = c.postForm("/admin/users", form, true)
	wantStatus(t, rec, http.StatusFound)
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/admin/users?") || !strings.Contains(loc, "kind=err") {
		t.Fatalf("ожидаем редирект с флешем-ошибкой, Location = %q", loc)
	}

	// Аудит license_limit через HTML-форму.
	rows, err := st.AuditList(ctx, store.AuditFilter{Event: "admin_action", Limit: 100})
	if err != nil {
		t.Fatalf("AuditList: %v", err)
	}
	saw := false
	for _, row := range rows {
		if row.Detail != nil && row.Detail["action"] == "license_limit" && row.Detail["via"] == "html" {
			saw = true
		}
	}
	if !saw {
		t.Fatal("аудит license_limit (via html) не записан")
	}
}
