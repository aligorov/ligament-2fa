// Юнит-тесты OIDC без БД: кодирование JWKS, подпись/проверка ID-токена,
// клеймы, issuer, PKCE, секреты клиентов и валидация authorize.
package oidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/aligorov/twofa/internal/store"
)

// testManager — менеджер со сгенерированной парой ключей (без БД и
// настроек: юнит-тесты трогают только ключевые части).
func testManager(t *testing.T) *Manager {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return &Manager{key: key, kid: KeyID(&key.PublicKey)}
}

// TestKeyIDDeterministic: kid — 16 hex-символов и стабилен для ключа.
func TestKeyIDDeterministic(t *testing.T) {
	mgr := testManager(t)
	kid := KeyID(&mgr.key.PublicKey)
	if len(kid) != 16 {
		t.Fatalf("kid = %q, хочу 16 символов", kid)
	}
	if kid != KeyID(&mgr.key.PublicKey) {
		t.Error("kid нестабилен для одного ключа")
	}
	if kid != mgr.kid {
		t.Errorf("kid менеджера %q != вычисленному %q", mgr.kid, kid)
	}
}

// TestJWKSEncoding: JWKS содержит RSA-параметры в base64url (n == модуль
// ключа, e == AQAB), kty/use/alg/kid на месте.
func TestJWKSEncoding(t *testing.T) {
	mgr := testManager(t)
	raw, err := json.Marshal(mgr.JWKS())
	if err != nil {
		t.Fatalf("Marshal(JWKS): %v", err)
	}
	var got struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("Unmarshal(JWKS): %v", err)
	}
	if len(got.Keys) != 1 {
		t.Fatalf("ключей в JWKS: %d, хочу 1", len(got.Keys))
	}
	k := got.Keys[0]
	if k.Kty != "RSA" || k.Use != "sig" || k.Alg != "RS256" || k.Kid != mgr.kid {
		t.Fatalf("поля JWKS: %+v", k)
	}
	n, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		t.Fatalf("n не base64url: %v", err)
	}
	if new(big.Int).SetBytes(n).Cmp(mgr.key.N) != 0 {
		t.Error("n (модуль) не совпадает с ключом")
	}
	e, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		t.Fatalf("e не base64url: %v", err)
	}
	if v := new(big.Int).SetBytes(e).Int64(); v != int64(mgr.key.E) {
		t.Errorf("e = %d, хочу %d", v, mgr.key.E)
	}
	if k.E != "AQAB" {
		t.Errorf("e = %q, хочу стандартный AQAB", k.E)
	}
}

// TestSignIDTokenVerify: подпись RS256 проверяется по JWKS-ключу, kid — в
// заголовке, подделанный payload отвергается.
func TestSignIDTokenVerify(t *testing.T) {
	mgr := testManager(t)
	claims := map[string]any{"sub": "user-1", "iss": "https://2fa.example.com"}
	token, err := mgr.SignIDToken(claims)
	if err != nil {
		t.Fatalf("SignIDToken: %v", err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT из %d частей, хочу 3", len(parts))
	}

	// Заголовок: alg/typ/kid.
	hdr, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("заголовок не base64url: %v", err)
	}
	var h struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hdr, &h); err != nil {
		t.Fatalf("разбор заголовка: %v", err)
	}
	if h.Alg != "RS256" || h.Typ != "JWT" {
		t.Fatalf("заголовок = %+v", h)
	}
	if h.Kid != mgr.kid {
		t.Errorf("kid в заголовке %q != %q", h.Kid, mgr.kid)
	}

	// Подпись по публичному ключу из JWKS (как это сделает клиент).
	keys := mgr.JWKS()["keys"].([]jwk)
	n, _ := base64.RawURLEncoding.DecodeString(keys[0].N)
	e, _ := base64.RawURLEncoding.DecodeString(keys[0].E)
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("подпись не base64url: %v", err)
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatalf("VerifyPKCS1v15: %v", err)
	}

	// Подделка payload ломает подпись.
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"evil"}`))
	sum2 := sha256.Sum256([]byte(tampered))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum2[:], sig); err == nil {
		t.Error("подпись прошла проверку после подмены payload")
	}
}

// TestIDTokenClaims: обязательные клеймы, nonce, profile/email по scope,
// amr/groups, name-fallback на username, auth_time в unix.
func TestIDTokenClaims(t *testing.T) {
	mgr := testManager(t)
	uid := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	authTime := time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	u := &store.User{ID: uid, Username: "vasya", Role: "user", Email: "vasya@example.com"}

	full := mgr.IDTokenClaims("https://2fa.example.com", u, "mfa_x", "openid profile email",
		"nonce-42", "pwd,mfa", authTime, now)
	if full["iss"] != "https://2fa.example.com" || full["sub"] != uid.String() || full["aud"] != "mfa_x" {
		t.Fatalf("iss/sub/aud: %+v", full)
	}
	if full["nonce"] != "nonce-42" {
		t.Errorf("nonce = %v", full["nonce"])
	}
	if full["exp"] != now.Add(idTokenTTL).Unix() || full["iat"] != now.Unix() {
		t.Errorf("exp/iat: %v/%v", full["exp"], full["iat"])
	}
	if full["auth_time"] != authTime.Unix() {
		t.Errorf("auth_time = %v, хочу %v", full["auth_time"], authTime.Unix())
	}
	if amr, ok := full["amr"].([]string); !ok || len(amr) != 2 || amr[0] != "pwd" || amr[1] != "mfa" {
		t.Errorf("amr = %#v", full["amr"])
	}
	if g, ok := full["groups"].([]string); !ok || len(g) != 1 || g[0] != "user" {
		t.Errorf("groups = %#v", full["groups"])
	}
	if full["preferred_username"] != "vasya" {
		t.Errorf("preferred_username = %v", full["preferred_username"])
	}
	// DisplayName пуст — name откатывается на username.
	if full["name"] != "vasya" {
		t.Errorf("name = %v, хочу username-fallback", full["name"])
	}
	if full["email"] != "vasya@example.com" || full["email_verified"] != true {
		t.Errorf("email/email_verified: %v/%v", full["email"], full["email_verified"])
	}

	// DisplayName задан; профильный scope всё ещё даёт name из DisplayName.
	u.DisplayName = "Василий П."
	named := mgr.IDTokenClaims("https://2fa.example.com", u, "mfa_x", "openid profile", "", "", authTime, now)
	if named["name"] != "Василий П." {
		t.Errorf("name = %v, хочу DisplayName", named["name"])
	}
	// scope только openid — профильных и email-клеймов нет, nonce не попал.
	bare := mgr.IDTokenClaims("https://2fa.example.com", u, "mfa_x", "openid", "", "", authTime, now)
	if _, ok := bare["nonce"]; ok {
		t.Error("nonce попал в токен без nonce")
	}
	for _, k := range []string{"preferred_username", "name", "email", "email_verified"} {
		if _, ok := bare[k]; ok {
			t.Errorf("клейм %s не должен входить при scope=openid", k)
		}
	}
}

// TestSplitAMR: разбор строки методов и дефолт [pwd mfa].
func TestSplitAMR(t *testing.T) {
	if got := SplitAMR("pwd,mfa"); len(got) != 2 || got[0] != "pwd" || got[1] != "mfa" {
		t.Errorf("SplitAMR(pwd,mfa) = %v", got)
	}
	if got := SplitAMR(""); len(got) != 2 || got[0] != "pwd" || got[1] != "mfa" {
		t.Errorf(`SplitAMR("") = %v, хочу дефолт [pwd mfa]`, got)
	}
	if got := SplitAMR("pwd , webauthn ,"); len(got) != 2 || got[1] != "webauthn" {
		t.Errorf("SplitAMR с пробелами = %v", got)
	}
}

// TestHasScopeAndFilter: точное вхождение scope; фильтр оставляет только
// поддерживаемые.
func TestHasScopeAndFilter(t *testing.T) {
	if !HasScope("openid profile", "openid") || HasScope("profile", "openid") {
		t.Error("HasScope")
	}
	if got := FilterScopes("openid read:stuff profile email offline_access"); got != "openid profile email" {
		t.Errorf("FilterScopes = %q", got)
	}
}

// TestIssuerFrom: server.domain приоритетен (без хвостового слэша), при
// пустом — scheme://host запроса (https при TLS).
func TestIssuerFrom(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/oidc/authorize", nil)
	if got := issuerFrom("https://corp.example.com/", req); got != "https://corp.example.com" {
		t.Errorf("issuerFrom(domain) = %q", got)
	}
	if got := issuerFrom("", req); got != "http://app.example.com" {
		t.Errorf("issuerFrom(без domain) = %q", got)
	}
	req.TLS = &tls.ConnectionState{}
	if got := issuerFrom("", req); got != "https://app.example.com" {
		t.Errorf("issuerFrom(TLS) = %q", got)
	}
}

// TestVerifyPKCE: S256/plain/отсутствие verifier/лишний verifier.
func TestVerifyPKCE(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	sum := sha256.Sum256([]byte(verifier))
	challenge := b64url(sum[:])

	if !VerifyPKCE(challenge, "S256", verifier) {
		t.Error("S256: верный verifier отвергнут")
	}
	if VerifyPKCE(challenge, "S256", "wrong-verifier") {
		t.Error("S256: неверный verifier прошёл")
	}
	if !VerifyPKCE(verifier, "plain", verifier) {
		t.Error("plain: верный verifier отвергнут")
	}
	if VerifyPKCE(verifier, "plain", "other") {
		t.Error("plain: неверный verifier прошёл")
	}
	if VerifyPKCE(challenge, "S256", "") {
		t.Error("пустой verifier прошёл при наличии challenge")
	}
	if !VerifyPKCE("", "", "") {
		t.Error("код без PKCE должен пропускать обмен без verifier")
	}
	if VerifyPKCE("", "", verifier) {
		t.Error("verifier без challenge (код выдан без PKCE) должен ломать обмен")
	}
	if VerifyPKCE(challenge, "SSS", verifier) {
		t.Error("неизвестный метод прошёл")
	}
}

// TestClientSecretHash: хеш верифицируется, неверный секрет отвергается,
// хеши уникальны (соль), битый формат — false.
func TestClientSecretHash(t *testing.T) {
	secret := NewClientSecret()
	if len(secret) < 32 {
		t.Fatalf("секрет подозрительно короткий: %q", secret)
	}
	stored := HashClientSecret(secret)
	if stored == secret || strings.Contains(stored, secret) {
		t.Fatal("хеш содержит открытый секрет")
	}
	if !VerifyClientSecret(stored, secret) {
		t.Error("верный секрет отвергнут")
	}
	if VerifyClientSecret(stored, "wrong-secret") {
		t.Error("неверный секрет прошёл")
	}
	if HashClientSecret(secret) == stored {
		t.Error("хеши одинакового секрета совпали (нет соли)")
	}
	if VerifyClientSecret("no-dollar-sign", secret) || VerifyClientSecret("", secret) {
		t.Error("битый формат хеша должен отвергаться")
	}
	if !strings.HasPrefix(NewClientID(), "mfa_") {
		t.Errorf("client_id без префикса mfa_: %q", NewClientID())
	}
}

// TestValidateAuthorize: таблица вердиктов валидации запроса authorize.
func TestValidateAuthorize(t *testing.T) {
	confidential := &store.OIDCClient{ClientID: "mfa_c", RedirectURIs: []string{"https://app.example.com/cb"}}
	public := &store.OIDCClient{ClientID: "mfa_p", IsPublic: true,
		RedirectURIs: []string{"https://app.example.com/cb"}}
	base := authorizeReq{
		ClientID: "mfa_x", RedirectURI: "https://app.example.com/cb",
		ResponseType: "code", Scope: "openid profile",
	}
	cases := []struct {
		name   string
		ar     authorizeReq
		client *store.OIDCClient
		want   string
	}{
		{"конфиденциальный без PKCE", base, confidential, ""},
		{"конфиденциальный S256", func() authorizeReq {
			ar := base
			ar.CodeChallenge, ar.CodeChallengeMethod = "abc", "S256"
			return ar
		}(), confidential, ""},
		{"public S256", func() authorizeReq {
			ar := base
			ar.CodeChallenge, ar.CodeChallengeMethod = "abc", "S256"
			return ar
		}(), public, ""},
		{"public без PKCE", base, public, "invalid_request"},
		{"public plain", func() authorizeReq {
			ar := base
			ar.CodeChallenge, ar.CodeChallengeMethod = "abc", "plain"
			return ar
		}(), public, "invalid_request"},
		{"response_type=token", func() authorizeReq {
			ar := base
			ar.ResponseType = "token"
			return ar
		}(), confidential, "unsupported_response_type"},
		{"scope без openid", func() authorizeReq {
			ar := base
			ar.Scope = "profile email"
			return ar
		}(), confidential, "invalid_scope"},
		{"challenge без метода", func() authorizeReq {
			ar := base
			ar.CodeChallenge = "abc"
			return ar
		}(), confidential, "invalid_request"},
		{"неизвестный метод", func() authorizeReq {
			ar := base
			ar.CodeChallenge, ar.CodeChallengeMethod = "abc", "SSS"
			return ar
		}(), confidential, "invalid_request"},
	}
	for _, tc := range cases {
		if got := validateAuthorize(tc.ar, tc.client); got != tc.want {
			t.Errorf("%s: validateAuthorize = %q, хочу %q", tc.name, got, tc.want)
		}
	}
}

// TestAuthorizeURL: адрес возврата содержит все непустые параметры.
func TestAuthorizeURL(t *testing.T) {
	ar := authorizeReq{
		ClientID: "mfa_x", RedirectURI: "https://app.example.com/cb",
		ResponseType: "code", Scope: "openid", State: "st-1", Nonce: "n-1",
		CodeChallenge: "ch", CodeChallengeMethod: "S256",
	}
	u := ar.authorizeURL()
	for _, want := range []string{
		"client_id=mfa_x", "state=st-1", "nonce=n-1",
		"code_challenge=ch", "code_challenge_method=S256",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("authorizeURL %q не содержит %q", u, want)
		}
	}
	if !strings.HasPrefix(u, "/oidc/authorize?") {
		t.Errorf("authorizeURL = %q, хочу локальный путь", u)
	}
}

// TestOIDCCORS: эндпоинты discovery, JWKS, token и userinfo отдают CORS-заголовки
// и корректно отвечают 204 No Content на preflight-запросы OPTIONS.
func TestOIDCCORS(t *testing.T) {
	mgr := testManager(t)
	r := chi.NewRouter()
	mgr.Register(r)

	endpoints := []string{
		"/.well-known/openid-configuration",
		"/.well-known/jwks.json",
		"/oidc/token",
		"/oidc/userinfo",
	}

	for _, ep := range endpoints {
		// 1. Проверка OPTIONS preflight
		reqOpt := httptest.NewRequest(http.MethodOptions, ep, nil)
		recOpt := httptest.NewRecorder()
		r.ServeHTTP(recOpt, reqOpt)

		if recOpt.Code != http.StatusNoContent {
			t.Errorf("OPTIONS %s: code = %d, want %d", ep, recOpt.Code, http.StatusNoContent)
		}
		if got := recOpt.Header().Get("Access-Control-Allow-Origin"); got != "*" {
			t.Errorf("OPTIONS %s: Access-Control-Allow-Origin = %q, want *", ep, got)
		}
		if !strings.Contains(recOpt.Header().Get("Access-Control-Allow-Methods"), "OPTIONS") {
			t.Errorf("OPTIONS %s: Access-Control-Allow-Methods missing OPTIONS", ep)
		}

		// 2. Проверка CORS-заголовка на целевом методе
		method := http.MethodGet
		if ep == "/oidc/token" {
			method = http.MethodPost
		}
		reqTarget := httptest.NewRequest(method, ep, nil)
		recTarget := httptest.NewRecorder()
		r.ServeHTTP(recTarget, reqTarget)

		if got := recTarget.Header().Get("Access-Control-Allow-Origin"); got != "*" {
			t.Errorf("%s %s: Access-Control-Allow-Origin = %q, want *", method, ep, got)
		}
	}
}

