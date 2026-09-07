// Unit-тесты чистых помощников admin/me/session API (без БД).
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aligorov/twofa/internal/acme"
	"github.com/aligorov/twofa/internal/channel"
	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
)

func TestIsNoChangeValue(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{"маска-строка", `"••••"`, true},
		{"пустая строка", `""`, true},
		{"null", `null`, true},
		{"объект маски задан", `{"set":true,"value":"••••"}`, true},
		{"объект маски не задан", `{"set":false,"value":"••••"}`, true},
		{"обычная строка", `"real-secret"`, false},
		{"объект без маски", `{"host":"smtp.example.com"}`, false},
		{"число", `42`, false},
		{"массив", `[1,2]`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isNoChangeValue(json.RawMessage(tc.raw)); got != tc.want {
				t.Fatalf("isNoChangeValue(%s) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

func TestMergeSettingValue(t *testing.T) {
	// Маска и пустая строка на верхнем и вложенном уровне не меняют текущее.
	cur := json.RawMessage(`{"host":"old","port":25,"password":"real","nested":{"a":1,"b":2}}`)
	inc := json.RawMessage(`{"host":"new","password":"••••","nested":{"a":9,"b":""}}`)
	got := mergeSettingValue(cur, inc)
	var m map[string]any
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatalf("разбор мержа %s: %v", got, err)
	}
	if m["host"] != "new" {
		t.Fatalf("host = %v, want new (замена)", m["host"])
	}
	if m["port"] != float64(25) {
		t.Fatalf("port = %v, want 25 (сохранён при отсутствии во входящем)", m["port"])
	}
	pw, _ := m["password"].(string)
	if pw != "real" {
		t.Fatalf("password = %q, want real (маска не меняет секрет)", pw)
	}
	nested, _ := m["nested"].(map[string]any)
	if nested["a"] != float64(9) || nested["b"] != float64(2) {
		t.Fatalf("nested = %v, want a=9 (заменён), b=2 (пустая строка = не менять)", nested)
	}
}

func TestMergeSettingValueReplace(t *testing.T) {
	// Скаляр/массив и не-объект заменяются целиком.
	cur := json.RawMessage(`[6,8]`)
	inc := json.RawMessage(`[8]`)
	if got := string(mergeSettingValue(cur, inc)); got != `[8]` {
		t.Fatalf("мерж массивов = %s, want [8]", got)
	}
	cur = json.RawMessage(`"a"`)
	inc = json.RawMessage(`"b"`)
	if got := string(mergeSettingValue(cur, inc)); got != `"b"` {
		t.Fatalf("мерж скаляров = %s, want \"b\"", got)
	}
}

func TestParseChannels(t *testing.T) {
	chs, ok := parseChannels([]string{"totp", "email", "telegram", "sms", "telegram_push"})
	if !ok || len(chs) != 5 {
		t.Fatalf("parseChannels(валидные) = %v, %v", chs, ok)
	}
	for _, bad := range [][]string{
		{"totp", "carrier-pigeon"},
		{"webauthn"}, // церемония — не канал prefer_channels
		{},
	} {
		if _, ok := parseChannels(bad); ok {
			t.Fatalf("parseChannels(%v) = ok, want false", bad)
		}
	}
}

func TestMutatingMethod(t *testing.T) {
	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		if mutatingMethod(m) {
			t.Fatalf("mutatingMethod(%s) = true, want false", m)
		}
	}
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		if !mutatingMethod(m) {
			t.Fatalf("mutatingMethod(%s) = false, want true", m)
		}
	}
}

func TestBearerToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if got := bearerToken(req); got != "" {
		t.Fatalf("без заголовка = %q, want \"\"", got)
	}
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	if got := bearerToken(req); got != "" {
		t.Fatalf("не-Bearer = %q, want \"\"", got)
	}
	req.Header.Set("Authorization", "Bearer the-admin-token")
	if got := bearerToken(req); got != "the-admin-token" {
		t.Fatalf("Bearer = %q, want the-admin-token", got)
	}
}

func TestToAdminUserNoSecrets(t *testing.T) {
	u := &store.User{
		Username: "u", Role: "user", Enabled: true, Email: "u@x",
		PreferChannels: []channel.Channel{channel.TOTP, channel.Email},
		PasswordHash:   "$argon2id$secret-hash",
	}
	out := toAdminUser(u)
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "argon2") {
		t.Fatalf("ответ содержит password_hash: %s", raw)
	}
	if len(out.PreferChannels) != 2 || out.PreferChannels[0] != "totp" {
		t.Fatalf("prefer_channels = %v", out.PreferChannels)
	}
}

// TestLicenseRoutesNilManager: лицензионные роуты регистрируются всегда;
// nil-менеджер (частичная композиция тестов) не паникует — GET даёт
// минимальный free-статус, мутации отвечают 503 licensing_disabled.
func TestLicenseRoutesNilManager(t *testing.T) {
	a := NewAdminAPI(nil, nil, nil)

	rec := httptest.NewRecorder()
	a.handleLicenseGet(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET: код = %d, хочу 200", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("GET: разбор тела %s: %v", rec.Body.String(), err)
	}
	if body["mode"] != "free" || body["user_limit"] != float64(5) {
		t.Fatalf("GET nil-менеджер: %v, хочу mode=free user_limit=5", body)
	}

	for _, tc := range []struct {
		name string
		call func(http.ResponseWriter, *http.Request)
		body string
	}{
		{"PUT", a.handleLicensePut, `{"blob":"-----BEGIN LIGAMENT LICENSE-----"}`},
		{"DELETE", a.handleLicenseDelete, ""},
		{"CRL", a.handleLicenseCRLPut, `{"blob":"-----BEGIN LIGAMENT REVOCATION-----"}`},
	} {
		var r *http.Request
		if tc.body == "" {
			r = httptest.NewRequest(http.MethodPut, "/", nil)
		} else {
			r = httptest.NewRequest(http.MethodPut, "/", strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		tc.call(rec, r) // не должно паниковать
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s nil-менеджер: код = %d (%s), хочу 503", tc.name, rec.Code, rec.Body.String())
		}
	}
}

func TestRadiusCertHandlers(t *testing.T) {
	m := settings.NewDefaultManager()
	a := NewAdminAPI(nil, m, nil)

	// 1. handleRadiusCertGet when no cert is set -> 404
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/radius/cert", nil)
	rec := httptest.NewRecorder()
	a.handleRadiusCertGet(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing cert, got %d", rec.Code)
	}

	// 2. handleRadiusACMERenew when acme is nil -> 503
	reqRenew := httptest.NewRequest(http.MethodPost, "/api/v1/admin/radius/acme/renew", nil)
	recRenew := httptest.NewRecorder()
	a.handleRadiusACMERenew(recRenew, reqRenew)
	if recRenew.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for nil acme, got %d", recRenew.Code)
	}

	// 3. caCertDownloadHandler when cert not found -> 404
	h := caCertDownloadHandler(nil, m)
	reqCA := httptest.NewRequest(http.MethodGet, "/ca.crt", nil)
	recCA := httptest.NewRecorder()
	h(recCA, reqCA)
	if recCA.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing CA cert, got %d", recCA.Code)
	}
}

func TestACMERouteInRouter(t *testing.T) {
	mgr := acme.NewManager(acme.Config{})
	mgr.SetChallenge("test-token", "keyauth123")
	m := settings.NewDefaultManager()
	rt := BuildRouter(Deps{
		M:    m,
		ACME: mgr,
	})
	req := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/test-token", nil)
	rec := httptest.NewRecorder()
	rt.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "keyauth123" {
		t.Fatalf("expected keyauth123, got %s", rec.Body.String())
	}
}


