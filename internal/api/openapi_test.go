// Юнит-тесты OpenAPI-документации (без БД): выдача /openapi.yaml и
// /api/docs, контракт «спека ↔ роутер» (каждый задокументированный
// JSON-эндпоинт существует в chi-роутере и наоборот) и соответствие
// рантайм-парсера страницы документации полной YAML-спеке.
package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	yaml "go.yaml.in/yaml/v3"
)

// specPath — путь к исходнику спеки относительно корня модуля (тесты
// internal/api запускаются с CWD = каталог пакета).
const specPath = "../../api/openapi.yaml"

// loadSpecJSON читает и разбирает openapi.yaml в map (тестовая зависимость
// yaml.v3 — полная проверка валидности YAML).
func loadSpecJSON(t *testing.T) map[string]any {
	t.Helper()
	b, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("прочитать %s: %v", specPath, err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatalf("разобрать openapi.yaml как YAML: %v", err)
	}
	return doc
}

// buildTestRouter — полный роутер с пустыми зависимостями: для
// интроспекции маршрутов БД не нужна (конструкторы только сохраняют ссылки).
func buildTestRouter(t *testing.T) *chi.Mux {
	t.Helper()
	rt := BuildRouter(Deps{})
	mux, ok := rt.Handler.(*chi.Mux)
	if !ok {
		t.Fatalf("Router.Handler — %T, ожидался *chi.Mux", rt.Handler)
	}
	return mux
}

// TestOpenAPISpecMetadata: спека валидна, info.version/title заполнены,
// securitySchemes и базовые секции на месте.
func TestOpenAPISpecMetadata(t *testing.T) {
	doc := loadSpecJSON(t)
	info, _ := doc["info"].(map[string]any)
	if info == nil {
		t.Fatal("нет секции info")
	}
	if v, _ := info["version"].(string); v == "" {
		t.Error("info.version пуст")
	}
	if v, _ := info["title"].(string); v == "" {
		t.Error("info.title пуст")
	}
	if _, ok := doc["paths"]; !ok {
		t.Error("нет секции paths")
	}
	comp, _ := doc["components"].(map[string]any)
	if comp == nil {
		t.Fatal("нет секции components")
	}
	schemes, _ := comp["securitySchemes"].(map[string]any)
	if schemes == nil {
		t.Fatal("нет components.securitySchemes")
	}
	for _, name := range []string{"adminBearer", "sessionCookie"} {
		if _, ok := schemes[name]; !ok {
			t.Errorf("нет securityScheme %q", name)
		}
	}
	if _, ok := comp["schemas"].(map[string]any); !ok {
		t.Error("нет components.schemas")
	}
}

// TestOpenAPIYAMLServed: GET /openapi.yaml отвечает 200, text/yaml и
// телом, совпадающим с файлом спеки.
func TestOpenAPIYAMLServed(t *testing.T) {
	srv := httptest.NewServer(buildTestRouter(t))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("статус /openapi.yaml = %d, хочу 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/yaml") {
		t.Errorf("Content-Type /openapi.yaml = %q, хочу text/yaml*", ct)
	}
	want, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Error("тело /openapi.yaml отличается от api/openapi.yaml")
	}
}

// TestAPIDocsServed: GET /api/docs отвечает 200 HTML со ссылками на
// ключевые эндпоинты и на сам YAML.
func TestAPIDocsServed(t *testing.T) {
	srv := httptest.NewServer(buildTestRouter(t))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/docs")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("статус /api/docs = %d, хочу 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type /api/docs = %q, хочу text/html*", ct)
	}
	pageBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	page := string(pageBytes)
	for _, want := range []string{
		"/openapi.yaml",
		"/api/v1/auth/start", "/api/v1/auth/verify", "/api/v1/auth/combined",
		"/api/v1/auth/poll", "/api/v1/auth/webauthn/begin", "/api/v1/auth/webauthn/finish",
		"/api/v1/login", "/api/v1/login/2fa", "/api/v1/logout",
		"/api/v1/me", "/api/v1/me/totp/enroll", "/api/v1/me/webauthn/credentials",
		"/api/v1/admin/users", "/api/v1/admin/audit", "/api/v1/admin/settings",
		"/api/v1/admin/license", "/api/v1/admin/license/crl",
		"/healthz",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("страница /api/docs не содержит %q", want)
		}
	}
	// CSP строгий (только self): инлайн-стили запрещены.
	if strings.Contains(page, "style=") || strings.Contains(page, "<style") {
		t.Error("страница /api/docs содержит инлайн-стили (запрещены CSP)")
	}
}

// specOperations извлекает из разобранной спеки пары «METHOD path».
func specOperations(t *testing.T, doc map[string]any) map[string]bool {
	t.Helper()
	ops := make(map[string]bool)
	paths, _ := doc["paths"].(map[string]any)
	if paths == nil {
		t.Fatal("paths пуст или не объект")
	}
	for path, item := range paths {
		methods, _ := item.(map[string]any)
		if methods == nil {
			t.Fatalf("path %s: не объект", path)
		}
		for method, op := range methods {
			switch method {
			case "get", "post", "put", "patch", "delete":
				if _, ok := op.(map[string]any); !ok {
					t.Fatalf("%s %s: операция не объект", method, path)
				}
				ops[strings.ToUpper(method)+" "+path] = true
			}
		}
	}
	return ops
}

// routerJSONOperations — операции chi-роутера, относящиеся к
// документируемому API: /api/v1/*, публичные OIDC-эндпоинты (/oidc/*,
// /.well-known/*) и /healthz (HTML-страницы, статика, /openapi.yaml и
// /api/docs в спеку REST API не входят).
func routerJSONOperations(t *testing.T, mux *chi.Mux) map[string]bool {
	t.Helper()
	ops := make(map[string]bool)
	err := chi.Walk(mux, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		pattern := strings.TrimSuffix(route, "/")
		if pattern == "" {
			pattern = "/"
		}
		if !strings.HasPrefix(pattern, "/api/v1") && pattern != "/healthz" &&
			!strings.HasPrefix(pattern, "/oidc") && !strings.HasPrefix(pattern, "/.well-known") {
			return nil
		}
		ops[method+" "+pattern] = true
		return nil
	})
	if err != nil {
		t.Fatalf("обход chi-роутера: %v", err)
	}
	return ops
}

// TestSpecMatchesRouter — контракт «спека ↔ роутер»: каждый JSON-эндпоинт
// chi-роутера задокументирован, и каждый задокументированный путь реально
// существует (в обе стороны; несовпадение = рассинхрон документации и кода).
func TestSpecMatchesRouter(t *testing.T) {
	spec := specOperations(t, loadSpecJSON(t))
	router := routerJSONOperations(t, buildTestRouter(t))

	if len(spec) < 40 {
		t.Fatalf("в спеке подозрительно мало операций: %d (ожидался полный API)", len(spec))
	}
	for op := range router {
		if !spec[op] {
			t.Errorf("эндпоинт роутера не задокументирован в openapi.yaml: %s", op)
		}
	}
	for op := range spec {
		if !router[op] {
			t.Errorf("задокументированной операции нет в роутере: %s", op)
		}
	}
}

// TestDocsEndpointsMatchSpec — рантайм-парсер страницы /api/docs обязан
// покрыть все операции спеки (сравнение с разбором yaml.v3).
func TestDocsEndpointsMatchSpec(t *testing.T) {
	spec := specOperations(t, loadSpecJSON(t))
	docs := make(map[string]bool)
	for _, ep := range parseOpenAPIDocsEndpoints() {
		docs[ep.Method+" "+ep.Path] = true
	}
	if len(docs) == 0 {
		t.Fatal("парсер /api/docs не нашёл ни одной операции")
	}
	for op := range spec {
		if !docs[op] {
			t.Errorf("операция спеки не попадёт на страницу /api/docs: %s", op)
		}
	}
	for op := range docs {
		if !spec[op] {
			t.Errorf("парсер /api/docs выдаёт операцию, которой нет в спеке: %s", op)
		}
	}
}

// TestDocsEndpointsGrouped: каждая операция несёт непустой тег и сводку.
func TestDocsEndpointsGrouped(t *testing.T) {
	eps := parseOpenAPIDocsEndpoints()
	if len(eps) == 0 {
		t.Fatal("нет операций")
	}
	seen := make(map[string]bool)
	for _, ep := range eps {
		if ep.Tag == "" {
			t.Errorf("%s %s: пустой тег", ep.Method, ep.Path)
		}
		if ep.Summary == "" {
			t.Errorf("%s %s: пустая сводка", ep.Method, ep.Path)
		}
		if len(ep.Codes) == 0 {
			t.Errorf("%s %s: не собраны коды ответов", ep.Method, ep.Path)
		}
		for _, c := range ep.Codes {
			if len(c) != 3 || c[0] < '1' || c[0] > '5' {
				t.Errorf("%s %s: подозрительный код ответа %q", ep.Method, ep.Path, c)
			}
		}
		seen[ep.Tag] = true
	}
	for _, want := range []string{"Public Auth", "Web Session", "Me", "Admin"} {
		if !seen[want] {
			t.Errorf("нет ни одной операции с тегом %q", want)
		}
	}
}

// TestSpecComponentsPresent: обязательные компоненты схем заявлены.
func TestSpecComponentsPresent(t *testing.T) {
	doc := loadSpecJSON(t)
	comp, _ := doc["components"].(map[string]any)
	schemas, _ := comp["schemas"].(map[string]any)
	for _, name := range []string{
		"Error", "Challenge", "User", "AuditRow", "SettingsMasked",
		"LoginTwoFactor", "WebauthnBegin", "LicenseStatus",
	} {
		if _, ok := schemas[name]; !ok {
			t.Errorf("нет компоненты schemas.%s", name)
		}
	}
}
