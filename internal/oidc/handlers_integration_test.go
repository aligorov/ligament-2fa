//go:build integration

// Интеграционные тесты OIDC Provider против реальной PostgreSQL
// (env TWOFA_TEST_DSN, паттерн internal/firewall): полный authorization
// code flow через httptest + chi — клиент → authorize → согласие → code →
// token (PKCE S256) → ID-токен → userinfo, плюс негативные сценарии
// (replay кода, неверный verifier, чужой redirect_uri, public без PKCE).
package oidc

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/aligorov/twofa/internal/secrets"
	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
	"github.com/aligorov/twofa/internal/web"
)

var (
	pgSt  *store.Store
	pgM   *settings.M
	pgRt  http.Handler
	pgMgr *Manager
)

// pg поднимает хранилище, настройки и роутер OIDC (один раз на прогон).
func pg(t *testing.T) (*store.Store, *settings.M, http.Handler) {
	t.Helper()
	if pgSt != nil {
		return pgSt, pgM, pgRt
	}
	dsn := os.Getenv("TWOFA_TEST_DSN")
	if dsn == "" {
		t.Skip("TWOFA_TEST_DSN не задан — интеграционный тест пропущен")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	m, err := settings.NewManager(ctx, st)
	if err != nil {
		t.Fatalf("settings.NewManager: %v", err)
	}
	rend, err := web.New()
	if err != nil {
		t.Fatalf("web.New: %v", err)
	}
	mgr, err := NewManager(ctx, st, m, rend)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	r := chi.NewRouter()
	mgr.Register(r)
	pgSt, pgM, pgRt, pgMgr = st, m, r, mgr
	return pgSt, pgM, pgRt
}

// cleanOIDC чистит таблицы флоу (тестовая БД живёт между прогонами).
func cleanOIDC(t *testing.T, st *store.Store) {
	t.Helper()
	ctx := context.Background()
	if _, err := st.Pool().Exec(ctx,
		`DELETE FROM oidc_codes; DELETE FROM oidc_tokens; DELETE FROM oidc_clients`); err != nil {
		t.Fatalf("cleanup oidc: %v", err)
	}
}

// oidcFixture — подготовленные сущности теста: пользователь с сессией,
// конфиденциальный и public-клиент.
type oidcFixture struct {
	st           *store.Store
	mgr          *Manager
	h            http.Handler
	user         *store.User
	session      *http.Cookie
	csrf         string
	confClient   *store.OIDCClient
	confSecret   string
	pubClient    *store.OIDCClient
	sessionToken string
}

// newFixture создаёт пользователя, web-сессию (напрямую через стор — как
// startSession), клиентов и возвращает всё готовое к флоу.
func newFixture(t *testing.T) *oidcFixture {
	t.Helper()
	st, m, h := pg(t)
	cleanOIDC(t, st)
	ctx := context.Background()

	user := &store.User{
		Username: "oidc-" + uuid.NewString()[:8], Role: "user", Enabled: true,
		Email: "oidc@example.com", DisplayName: "Оидц Тестов",
		PasswordHash: secrets.HashPassword("pass-12345"),
	}
	if err := st.UserCreate(ctx, user); err != nil {
		t.Fatalf("UserCreate: %v", err)
	}
	token := secrets.RandomToken(32)
	csrf := secrets.RandomToken(16)
	if err := st.SessionCreate(ctx, secrets.SHA256(token), user.ID, csrf, time.Hour); err != nil {
		t.Fatalf("SessionCreate: %v", err)
	}

	confSecret := NewClientSecret()
	confClient := &store.OIDCClient{
		ClientID: NewClientID(), Name: "Grafana",
		ClientSecretHash: HashClientSecret(confSecret),
		RedirectURIs:     []string{"https://grafana.example.com/cb"},
	}
	pubClient := &store.OIDCClient{
		ClientID: NewClientID(), Name: "SPA App", IsPublic: true,
		RedirectURIs: []string{"https://spa.example.com/cb"},
	}
	for _, c := range []*store.OIDCClient{confClient, pubClient} {
		if err := st.OIDCClientUpsert(ctx, c); err != nil {
			t.Fatalf("OIDCClientUpsert: %v", err)
		}
	}
	_ = m // менеджер используется через pg()
	return &oidcFixture{
		st: st, mgr: pgMgr, h: h, user: user,
		session:    &http.Cookie{Name: cookieSession, Value: token},
		csrf:       csrf,
		confClient: confClient, confSecret: confSecret,
		pubClient: pubClient, sessionToken: token,
	}
}

// get — GET с cookie сессии.
func (f *oidcFixture) get(path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.AddCookie(f.session)
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	return rec
}

// postForm — POST form-encoded с cookie сессии и CSRF-полем.
func (f *oidcFixture) postForm(path string, form url.Values, withCSRF bool) *httptest.ResponseRecorder {
	if withCSRF {
		form.Set("csrf_token", f.csrf)
	}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(f.session)
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	return rec
}

// tokenReq — POST /oidc/token с Basic- или form-аутентификацией клиента.
func (f *oidcFixture) tokenReq(form url.Values, clientID, clientSecret string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if clientID != "" {
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	return rec
}

// authorizeQuery — стандартный запрос authorize для конфиденциального
// клиента (scope openid profile email, state, nonce).
func (f *oidcFixture) authorizeQuery() url.Values {
	return url.Values{
		"client_id":     {f.confClient.ClientID},
		"redirect_uri":  {"https://grafana.example.com/cb"},
		"response_type": {"code"},
		"scope":         {"openid profile email"},
		"state":         {"st-abc-123"},
		"nonce":         {"nonce-xyz-789"},
	}
}

// consentFields — скрытые поля из GET authorize (эмуляция браузера:
// значения прокси из консент-формы; тесту достаточно исходных значений).
func consentFields(q url.Values) url.Values {
	form := url.Values{}
	for _, k := range []string{"client_id", "redirect_uri", "response_type",
		"scope", "state", "nonce", "code_challenge", "code_challenge_method"} {
		if v := q.Get(k); v != "" {
			form.Set(k, v)
		}
	}
	return form
}

// runCodeFlow проводит authorize → confirm → возвращает code из
// редиректа и PKCE-пара (verifier, challenge).
func runCodeFlow(t *testing.T, f *oidcFixture, q url.Values) string {
	t.Helper()
	rec := f.get("/oidc/authorize?" + q.Encode())
	if rec.Code != http.StatusOK {
		t.Fatalf("authorize: статус %d, хочу 200 (страница согласия): %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Разрешить вход") {
		t.Fatalf("authorize: это не страница согласия: %.200s", rec.Body.String())
	}
	rec = f.postForm("/oidc/authorize/confirm", consentFields(q), true)
	if rec.Code != http.StatusFound {
		t.Fatalf("confirm: статус %d, хочу 302: %s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("confirm Location: %v", err)
	}
	if loc.Query().Get("state") != q.Get("state") {
		t.Errorf("state не проксирован: %q", loc.Query().Get("state"))
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("в редиректе нет code: %s", loc.String())
	}
	return code
}

// jwksPublicKey — публичный ключ из JWKS-эндпоинта (как видит клиент).
func jwksPublicKey(t *testing.T, h http.Handler) (*rsa.PublicKey, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("jwks: статус %d", rec.Code)
	}
	var ks struct {
		Keys []struct {
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &ks); err != nil {
		t.Fatalf("jwks json: %v", err)
	}
	if len(ks.Keys) != 1 {
		t.Fatalf("jwks: ключей %d, хочу 1", len(ks.Keys))
	}
	k := ks.Keys[0]
	n, _ := base64.RawURLEncoding.DecodeString(k.N)
	e, _ := base64.RawURLEncoding.DecodeString(k.E)
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(n),
		E: int(new(big.Int).SetBytes(e).Int64()),
	}, k.Kid
}

// parseIDToken разбирает и проверяет подпись ID-токена по JWKS-ключу.
func parseIDToken(t *testing.T, h http.Handler, token string) map[string]any {
	t.Helper()
	pub, kid := jwksPublicKey(t, h)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("id_token: %d частей", len(parts))
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	if err := json.Unmarshal(hb, &hdr); err != nil {
		t.Fatalf("id_token header: %v", err)
	}
	if hdr.Alg != "RS256" || hdr.Kid != kid {
		t.Errorf("id_token header: alg=%s kid=%s (jwks kid=%s)", hdr.Alg, hdr.Kid, kid)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatalf("подпись id_token не прошла проверку по JWKS: %v", err)
	}
	cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	if err := json.Unmarshal(cb, &claims); err != nil {
		t.Fatalf("id_token claims: %v", err)
	}
	return claims
}

// TestOIDCDiscoveryAndJWKS: discovery отдаёт согласованную картину
// эндпоинтов/методов, issuer = http://host запроса (server.domain пуст).
func TestOIDCDiscoveryAndJWKS(t *testing.T) {
	_, _, h := pg(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("discovery: статус %d", rec.Code)
	}
	var d map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
		t.Fatalf("discovery json: %v", err)
	}
	// httptest.NewRequest с путём: Host по умолчанию example.com, server.domain
	// пуст → issuer = http://example.com.
	if iss, _ := d["issuer"].(string); iss != "http://example.com" {
		t.Fatalf("issuer = %q, хочу http://example.com (fallback по Host)", iss)
	}
	for key, want := range map[string]string{
		"authorization_endpoint": "/oidc/authorize",
		"token_endpoint":         "/oidc/token",
		"userinfo_endpoint":      "/oidc/userinfo",
		"jwks_uri":               "/.well-known/jwks.json",
	} {
		got, _ := d[key].(string)
		if !strings.HasSuffix(got, want) {
			t.Errorf("%s = %q, хочу суффикс %s", key, got, want)
		}
	}
	for _, key := range []string{"response_types_supported", "grant_types_supported",
		"subject_types_supported", "id_token_signing_alg_values_supported",
		"code_challenge_methods_supported", "scopes_supported",
		"token_endpoint_auth_methods_supported"} {
		if _, ok := d[key]; !ok {
			t.Errorf("discovery без %s", key)
		}
	}
	if _, kid := jwksPublicKey(t, h); len(kid) != 16 {
		t.Errorf("kid = %q, хочу 16 символов", kid)
	}
}

// TestOIDCCodeFlowHappyPath: конфиденциальный клиент, PKCE S256, Basic
// auth — от authorize до userinfo, с проверкой ID-токена по JWKS.
func TestOIDCCodeFlowHappyPath(t *testing.T) {
	f := newFixture(t)
	q := f.authorizeQuery()
	verifier := secrets.RandomToken(48)
	q.Set("code_challenge", b64url(secrets.SHA256(verifier)))
	q.Set("code_challenge_method", "S256")

	code := runCodeFlow(t, f, q)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://grafana.example.com/cb"},
		"code_verifier": {verifier},
	}
	rec := f.tokenReq(form, f.confClient.ClientID, f.confSecret)
	if rec.Code != http.StatusOK {
		t.Fatalf("token: статус %d: %s", rec.Code, rec.Body.String())
	}
	var tok map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &tok); err != nil {
		t.Fatalf("token json: %v", err)
	}
	access, _ := tok["access_token"].(string)
	idToken, _ := tok["id_token"].(string)
	if access == "" || idToken == "" || tok["token_type"] != "Bearer" {
		t.Fatalf("token ответ неполный: %s", rec.Body.String())
	}
	if tok["expires_in"] != float64(300) {
		t.Errorf("expires_in = %v, хочу 300", tok["expires_in"])
	}
	if tok["scope"] != "openid profile email" {
		t.Errorf("scope = %v", tok["scope"])
	}

	// ID-токен: подпись по JWKS + клеймы.
	claims := parseIDToken(t, f.h, idToken)
	if claims["aud"] != f.confClient.ClientID {
		t.Errorf("aud = %v", claims["aud"])
	}
	if claims["sub"] != f.user.ID.String() {
		t.Errorf("sub = %v, хочу uuid пользователя", claims["sub"])
	}
	if claims["nonce"] != "nonce-xyz-789" {
		t.Errorf("nonce = %v", claims["nonce"])
	}
	if claims["preferred_username"] != f.user.Username {
		t.Errorf("preferred_username = %v", claims["preferred_username"])
	}
	if claims["username"] != f.user.Username {
		t.Errorf("username = %v", claims["username"])
	}
	if claims["email"] != "oidc@example.com" || claims["email_verified"] != true {
		t.Errorf("email/email_verified: %v/%v", claims["email"], claims["email_verified"])
	}
	if amr, ok := claims["amr"].([]any); !ok || len(amr) != 2 {
		t.Errorf("amr = %#v", claims["amr"])
	}

	// Userinfo по access-токену.
	req := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	rec = httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("userinfo: статус %d: %s", rec.Code, rec.Body.String())
	}
	var ui map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &ui); err != nil {
		t.Fatalf("userinfo json: %v", err)
	}
	if ui["sub"] != f.user.ID.String() || ui["preferred_username"] != f.user.Username || ui["username"] != f.user.Username {
		t.Errorf("userinfo: %s", rec.Body.String())
	}
	if ui["email"] != "oidc@example.com" {
		t.Errorf("userinfo email = %v", ui["email"])
	}
}

// freshCode выпускает новый код (PKCE S256) и возвращает его с verifier.
func freshCode(t *testing.T, f *oidcFixture) (code, verifier string) {
	t.Helper()
	q := f.authorizeQuery()
	verifier = secrets.RandomToken(48)
	q.Set("code_challenge", b64url(secrets.SHA256(verifier)))
	q.Set("code_challenge_method", "S256")
	return runCodeFlow(t, f, q), verifier
}

// TestOIDCTokenNegative: неверный verifier, чужой redirect_uri, неверный
// секрет клиента, form-аутентификация (client_secret_post), replay кода,
// неизвестный grant_type. Код одноразовый: первая же попытка обмена
// погашает его (в т.ч. неудачная — защита от перебора verifier).
func TestOIDCTokenNegative(t *testing.T) {
	f := newFixture(t)
	exchange := func(code, verifier, redirect, secret string) *httptest.ResponseRecorder {
		return f.tokenReq(url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {redirect},
			"code_verifier": {verifier},
		}, f.confClient.ClientID, secret)
	}

	// Неверный verifier → invalid_grant (код погашен).
	code, verifier := freshCode(t, f)
	rec := exchange(code, "wrong-verifier-0000000000000000", "https://grafana.example.com/cb", f.confSecret)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_grant") {
		t.Fatalf("неверный verifier: %d %s", rec.Code, rec.Body.String())
	}
	// Тот же код уже погашен → invalid_grant даже с корректным verifier.
	rec = exchange(code, verifier, "https://grafana.example.com/cb", f.confSecret)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_grant") {
		t.Fatalf("повторное использование кода: %d %s", rec.Code, rec.Body.String())
	}

	// Неверный секрет клиента → 401 invalid_client (код ещё не погашен —
	// аутентификация клиента идёт до claim); затем корректный обмен.
	code, verifier = freshCode(t, f)
	rec = exchange(code, verifier, "https://grafana.example.com/cb", "wrong-secret")
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "invalid_client") {
		t.Fatalf("неверный секрет: %d %s", rec.Code, rec.Body.String())
	}
	rec = exchange(code, verifier, "https://grafana.example.com/cb", f.confSecret)
	if rec.Code != http.StatusOK {
		t.Fatalf("обмен после неверного секрета: %d %s", rec.Code, rec.Body.String())
	}

	// Чужой redirect_uri → invalid_grant.
	code, verifier = freshCode(t, f)
	rec = exchange(code, verifier, "https://evil.example.com/cb", f.confSecret)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_grant") {
		t.Fatalf("чужой redirect_uri: %d %s", rec.Code, rec.Body.String())
	}

	// form-аутентификация (client_secret_post) вместо Basic.
	code, verifier = freshCode(t, f)
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://grafana.example.com/cb"},
		"code_verifier": {verifier},
		"client_id":     {f.confClient.ClientID},
		"client_secret": {f.confSecret},
	}
	req := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("client_secret_post: %d %s", rec.Code, rec.Body.String())
	}

	// Неизвестный grant_type → unsupported_grant_type.
	rec = f.tokenReq(url.Values{"grant_type": {"password"}}, f.confClient.ClientID, f.confSecret)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "unsupported_grant_type") {
		t.Fatalf("grant_type=password: %d %s", rec.Code, rec.Body.String())
	}
}

// TestOIDCAMRByAuthMode: клейм amr ID-токена отражает режим входа сессии
// (sessions.auth_mode), а не константу pwd,mfa (аудит раунд-2: заведомо
// ложное заверение для password_only/trusted_device). Легаси-сессия без
// auth_mode получает безопасный дефолт pwd,mfa.
func TestOIDCAMRByAuthMode(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want []string
	}{
		{"password+code", []string{"pwd", "mfa"}},
		{"password_only", []string{"pwd"}},
		{"trusted_device", []string{"pwd", "dvc"}},
		{"", []string{"pwd", "mfa"}}, // легаси
	} {
		t.Run("mode="+tc.mode, func(t *testing.T) {
			f := newFixture(t)
			// Свежая сессия с нужным auth_mode (как выпустил бы startSession).
			token := secrets.RandomToken(32)
			csrf := secrets.RandomToken(16)
			if err := f.st.SessionCreateMode(context.Background(),
				secrets.SHA256(token), f.user.ID, csrf, time.Hour, tc.mode); err != nil {
				t.Fatalf("SessionCreateMode: %v", err)
			}
			f.session = &http.Cookie{Name: cookieSession, Value: token}
			f.csrf = csrf

			verifier := secrets.RandomToken(48)
			q := f.authorizeQuery()
			q.Set("code_challenge", b64url(secrets.SHA256(verifier)))
			q.Set("code_challenge_method", "S256")
			code := runCodeFlow(t, f, q)

			form := url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {code},
				"redirect_uri":  {"https://grafana.example.com/cb"},
				"code_verifier": {verifier},
			}
			rec := f.tokenReq(form, f.confClient.ClientID, f.confSecret)
			if rec.Code != http.StatusOK {
				t.Fatalf("token: %d %s", rec.Code, rec.Body.String())
			}
			var tok map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &tok); err != nil {
				t.Fatalf("token json: %v", err)
			}
			claims := parseIDToken(t, f.h, tok["id_token"].(string))
			amr, ok := claims["amr"].([]any)
			if !ok || len(amr) != len(tc.want) {
				t.Fatalf("amr = %#v, хочу %v", claims["amr"], tc.want)
			}
			for i, want := range tc.want {
				if amr[i] != want {
					t.Errorf("amr[%d] = %v, хочу %q (mode=%q)", i, amr[i], want, tc.mode)
				}
			}
		})
	}
}

// TestOIDCTokenFailAudit: неудачная аутентификация клиента на /oidc/token
// (неверный секрет, неизвестный client_id) пишет аудит oidc_token_fail —
// брут client_secret виден в журнале (аудит раунд-2, N5: раньше событие не
// писалось вовсе).
func TestOIDCTokenFailAudit(t *testing.T) {
	f := newFixture(t)
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"whatever"},
		"redirect_uri": {"https://grafana.example.com/cb"},
	}
	// Неверный секрет известного клиента → 401 + oidc_token_fail(bad_secret).
	rec := f.tokenReq(form, f.confClient.ClientID, "wrong-secret")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("неверный секрет: %d %s", rec.Code, rec.Body.String())
	}
	// Неизвестный client_id → 401 + oidc_token_fail(unknown_client).
	rec = f.tokenReq(form, "mfa_nope", "whatever")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("неизвестный клиент: %d %s", rec.Code, rec.Body.String())
	}
	rows, err := f.st.AuditList(context.Background(), store.AuditFilter{Event: "oidc_token_fail", Limit: 50})
	if err != nil {
		t.Fatalf("AuditList: %v", err)
	}
	reasons := map[string]string{} // client_id → reason
	for _, row := range rows {
		if cid, _ := row.Detail["client_id"].(string); cid == f.confClient.ClientID || cid == "mfa_nope" {
			if reason, _ := row.Detail["reason"].(string); reason != "" {
				reasons[cid] = reason
			}
		}
	}
	if reasons[f.confClient.ClientID] != "bad_secret" {
		t.Errorf("oidc_token_fail(bad_secret) для %s не найден: %v", f.confClient.ClientID, reasons)
	}
	if reasons["mfa_nope"] != "unknown_client" {
		t.Errorf("oidc_token_fail(unknown_client) не найден: %v", reasons)
	}
}

// TestOIDCTokenRateLimited: серия обменов с одного IP сверх burst → 429
// rate_limited с Retry-After (аудит раунд-2, N5: эндпоинт не имел лимитов).
// Уникальный RemoteAddr — ip-корзина изолирована от остальных тестов
// пакета (менеджер один на процесс).
func TestOIDCTokenRateLimited(t *testing.T) {
	f := newFixture(t)
	form := url.Values{"grant_type": {"authorization_code"}}.Encode()
	for i := 0; i <= tokenRLBurst; i++ {
		req := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "203.0.113.99:44444"
		rec := httptest.NewRecorder()
		f.h.ServeHTTP(rec, req)
		if i < tokenRLBurst {
			// До исчернения — обычная ошибка флоу (кода нет → invalid_request),
			// а не лимит.
			if rec.Code == http.StatusTooManyRequests {
				t.Fatalf("запрос #%d: 429 раньше времени", i)
			}
			continue
		}
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("запрос #%d: %d, хочу 429 (%s)", i, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "rate_limited") {
			t.Errorf("тело 429: %s", rec.Body.String())
		}
		if rec.Header().Get("Retry-After") == "" {
			t.Error("заголовок Retry-After отсутствует")
		}
	}
}

// TestOIDCAuthorizeNegative: без сессии — /login?next=…, неизвестный
// клиент и чужой redirect_uri — страница 400, scope без openid — редирект
// с invalid_scope, public без PKCE — invalid_request.
func TestOIDCAuthorizeNegative(t *testing.T) {
	f := newFixture(t)

	// Без сессии — редирект на /login?next=<authorize>.
	req := httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+f.authorizeQuery().Encode(), nil)
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize без сессии: %d, хочу 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/login?next=") || !strings.Contains(loc, url.QueryEscape("/oidc/authorize")) {
		t.Errorf("redirect = %q, хочу /login?next=<authorize>", loc)
	}

	// Неизвестный client_id — страница 400 (без редиректа).
	q := f.authorizeQuery()
	q.Set("client_id", "mfa_unknown")
	rec = f.get("/oidc/authorize?" + q.Encode())
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("неизвестный клиент: %d, хочу 400", rec.Code)
	}

	// Незарегистрированный redirect_uri — страница 400.
	q = f.authorizeQuery()
	q.Set("redirect_uri", "https://evil.example.com/cb")
	rec = f.get("/oidc/authorize?" + q.Encode())
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("чужой redirect_uri: %d, хочу 400", rec.Code)
	}

	// scope без openid — редирект с error=invalid_scope и state.
	q = f.authorizeQuery()
	q.Set("scope", "profile email")
	rec = f.get("/oidc/authorize?" + q.Encode())
	if rec.Code != http.StatusFound {
		t.Fatalf("scope без openid: %d, хочу 302", rec.Code)
	}
	loc = rec.Header().Get("Location")
	if !strings.Contains(loc, "error=invalid_scope") || !strings.Contains(loc, "state=st-abc-123") {
		t.Errorf("редирект ошибки = %q", loc)
	}

	// public-клиент без PKCE — invalid_request; с S256 — согласие.
	q = url.Values{
		"client_id":     {f.pubClient.ClientID},
		"redirect_uri":  {"https://spa.example.com/cb"},
		"response_type": {"code"},
		"scope":         {"openid"},
	}
	rec = f.get("/oidc/authorize?" + q.Encode())
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "error=invalid_request") {
		t.Fatalf("public без PKCE: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	q.Set("code_challenge", "some-challenge")
	q.Set("code_challenge_method", "S256")
	rec = f.get("/oidc/authorize?" + q.Encode())
	if rec.Code != http.StatusOK {
		t.Fatalf("public с S256: %d, хочу страницу согласия", rec.Code)
	}

	// CSRF-токен подтверждения обязателен.
	q = f.authorizeQuery()
	rec = f.postForm("/oidc/authorize/confirm", consentFields(q), false)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("confirm без CSRF: %d, хочу 403", rec.Code)
	}
}

// TestOIDCUserinfoNegative: без токена, с мусорным токеном — 401.
func TestOIDCUserinfoNegative(t *testing.T) {
	f := newFixture(t)
	for name, auth := range map[string]string{
		"без заголовка":   "",
		"битый токен":     "Bearer garbage-token",
		"не-Bearer схемa": "Basic dXNlcjpwd2Q=",
	} {
		req := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		f.h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "invalid_token") {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
}

// TestOIDCStoreLifecycle: клиенты upsert/list/delete (+каскад кодов и
// токенов), атомарность погашения кода, чтение сессии для authorize.
func TestOIDCStoreLifecycle(t *testing.T) {
	f := newFixture(t)
	st, ctx := f.st, context.Background()

	// Список содержит обоих клиентов; поиск по client_id работает.
	clients, err := st.OIDCClients(ctx)
	if err != nil {
		t.Fatalf("OIDCClients: %v", err)
	}
	if len(clients) != 2 {
		t.Fatalf("клиентов %d, хочу 2", len(clients))
	}
	got, err := st.OIDCClientByClientID(ctx, f.confClient.ClientID)
	if err != nil || got.Name != "Grafana" || got.IsPublic {
		t.Fatalf("OIDCClientByClientID: %+v err=%v", got, err)
	}
	if _, err := st.OIDCClientByClientID(ctx, "mfa_nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("no client: %v, хочу ErrNotFound", err)
	}

	// Upsert обновляет по client_id без дубликата.
	upd := *f.confClient
	upd.Name = "Grafana Prod"
	if err := st.OIDCClientUpsert(ctx, &upd); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if clients, _ = st.OIDCClients(ctx); len(clients) != 2 {
		t.Fatalf("после upsert клиентов %d, хочу 2", len(clients))
	}
	if got, _ = st.OIDCClientByClientID(ctx, f.confClient.ClientID); got.Name != "Grafana Prod" {
		t.Fatalf("upsert не обновил имя: %s", got.Name)
	}

	// Код: сохранение, погашение, повторное погашение — ErrNotFound,
	// истёкший код не выдаётся.
	code := secrets.RandomToken(32)
	rec := &store.OIDCCode{
		ClientID: f.confClient.ClientID, UserID: f.user.ID,
		RedirectURI: "https://grafana.example.com/cb", Scope: "openid",
		AuthTime: time.Now(), AMR: AMRForMode("password+code"),
		CodeChallenge: "ch", CodeChallengeMethod: "S256",
	}
	if err := st.OIDCCodeSave(ctx, secrets.SHA256(code), rec, time.Minute); err != nil {
		t.Fatalf("OIDCCodeSave: %v", err)
	}
	claimed, err := st.OIDCCodeClaim(ctx, secrets.SHA256(code))
	if err != nil || claimed.UserID != f.user.ID || claimed.CodeChallenge != "ch" {
		t.Fatalf("OIDCCodeClaim: %+v err=%v", claimed, err)
	}
	if _, err := st.OIDCCodeClaim(ctx, secrets.SHA256(code)); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("повторное погашение кода должно давать ErrNotFound")
	}

	expired := secrets.RandomToken(32)
	if err := st.OIDCCodeSave(ctx, secrets.SHA256(expired), rec, -time.Minute); err != nil {
		t.Fatalf("OIDCCodeSave(expired): %v", err)
	}
	if _, err := st.OIDCCodeClaim(ctx, secrets.SHA256(expired)); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("истёкший код должен давать ErrNotFound")
	}

	// Access-токен: сохранение/чтение/удаление.
	access := secrets.RandomToken(32)
	tok := &store.OIDCToken{UserID: f.user.ID, ClientID: f.confClient.ClientID, Scope: "openid", AMR: AMRForMode("password+code")}
	if err := st.OIDCTokenSave(ctx, secrets.SHA256(access), tok, time.Minute); err != nil {
		t.Fatalf("OIDCTokenSave: %v", err)
	}
	if _, err := st.OIDCTokenGet(ctx, secrets.SHA256(access)); err != nil {
		t.Fatalf("OIDCTokenGet: %v", err)
	}
	if err := st.OIDCTokenDelete(ctx, secrets.SHA256(access)); err != nil {
		t.Fatalf("OIDCTokenDelete: %v", err)
	}
	if _, err := st.OIDCTokenGet(ctx, secrets.SHA256(access)); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("удалённый токен должен давать ErrNotFound")
	}

	// Сессия для authorize: пользователь, CSRF и момент входа.
	uid, csrf, createdAt, err := st.OIDCSessionInfo(ctx, secrets.SHA256(f.sessionToken))
	if err != nil || uid != f.user.ID || csrf != f.csrf || createdAt.IsZero() {
		t.Fatalf("OIDCSessionInfo: %s %s %v err=%v", uid, csrf, createdAt, err)
	}

	// Удаление клиента — каскад кодов и токенов; повторное удаление —
	// ErrNotFound.
	if err := st.OIDCClientDelete(ctx, f.confClient.ID); err != nil {
		t.Fatalf("OIDCClientDelete: %v", err)
	}
	var n int
	if err := st.Pool().QueryRow(ctx,
		`SELECT count(*) FROM oidc_codes WHERE client_id = $1`, f.confClient.ClientID).Scan(&n); err != nil || n != 0 {
		t.Errorf("кодов клиента после удаления: %d err=%v", n, err)
	}
	if err := st.OIDCClientDelete(ctx, f.confClient.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("повторное удаление клиента должно давать ErrNotFound")
	}
}

// TestOIDCConstantTimeSecret: верификация секрета не зависит от
// совпавшего префикса (тривиальная страховка длины сравнения).
func TestOIDCConstantTimeSecret(t *testing.T) {
	secret := NewClientSecret()
	stored := HashClientSecret(secret)
	prefix := secret[:len(secret)/2]
	_ = subtle.ConstantTimeCompare([]byte(stored), []byte(HashClientSecret(prefix)))
	if VerifyClientSecret(stored, prefix) {
		t.Error("префикс секрета не должен проходить")
	}
}

type fakeOIDCNotifier struct {
	sync.Mutex
	called   bool
	username string
	method   string
	ip       string
	ua       string
}

func (n *fakeOIDCNotifier) NotifyLoginSuccess(ctx context.Context, username, method, ip, ua string) {
	n.Lock()
	defer n.Unlock()
	n.called = true
	n.username = username
	n.method = method
	n.ip = ip
	n.ua = ua
}

// TestOIDCAuthorizeNotification проверяет, что при подтверждении согласия отправляется уведомление о входе.
func TestOIDCAuthorizeNotification(t *testing.T) {
	f := newFixture(t)
	notif := &fakeOIDCNotifier{}
	f.mgr.SetNotifier(notif)

	q := f.authorizeQuery()
	form := url.Values{
		"csrf_token":            {f.csrf},
		"client_id":             {q.Get("client_id")},
		"redirect_uri":          {q.Get("redirect_uri")},
		"response_type":         {q.Get("response_type")},
		"scope":                 {q.Get("scope")},
		"state":                 {q.Get("state")},
		"nonce":                 {q.Get("nonce")},
		"code_challenge":        {q.Get("code_challenge")},
		"code_challenge_method": {q.Get("code_challenge_method")},
	}
	req := httptest.NewRequest(http.MethodPost, "/oidc/authorize/confirm", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "TestBrowser/1.0 (Macintosh)")
	req.RemoteAddr = "192.168.1.100:12345"
	req.AddCookie(&http.Cookie{Name: cookieSession, Value: f.sessionToken})

	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("confirm: статус %d, хочу 302: %s", rec.Code, rec.Body.String())
	}

	notif.Lock()
	defer notif.Unlock()
	if !notif.called {
		t.Fatal("уведомление NotifyLoginSuccess не было вызвано")
	}
	if notif.username != f.user.Username {
		t.Errorf("username = %q, want %q", notif.username, f.user.Username)
	}
	if notif.method != "OIDC ("+f.confClient.Name+")" {
		t.Errorf("method = %q, want %q", notif.method, "OIDC ("+f.confClient.Name+")")
	}
	if notif.ip != "192.168.1.100" {
		t.Errorf("ip = %q, want 192.168.1.100", notif.ip)
	}
	if notif.ua != "TestBrowser/1.0 (Macintosh)" {
		t.Errorf("ua = %q, want TestBrowser/1.0 (Macintosh)", notif.ua)
	}
}
