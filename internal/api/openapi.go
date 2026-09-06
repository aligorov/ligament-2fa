// OpenAPI-документация: GET /openapi.yaml (встроенная спека, text/yaml) и
// GET /api/docs (минимальная сервер-рендер страница: эндпоинты по тегам с
// методами, путями, сводками и кодами ответов). Страница без JS и инлайн-
// стилей (CSP — только self), стили — общий /static/style.css.
package api

import (
	"html"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"

	twofaapi "github.com/aligorov/twofa/api"
)

// registerOpenAPI монтирует маршруты документации (вызывается BuildRouter).
func registerOpenAPI(r chi.Router) {
	r.Get("/openapi.yaml", serveOpenAPISpec)
	r.Get("/api/docs", serveOpenAPIDocs)
}

// serveOpenAPISpec — GET /openapi.yaml: встроенный api/openapi.yaml.
func serveOpenAPISpec(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(twofaapi.OpenAPIYAML)
}

// docEndpoint — одна операция спеки для страницы документации.
type docEndpoint struct {
	Tag     string
	Method  string
	Path    string
	Summary string
	Codes   []string
}

// docsTagOrder — порядок групп на странице (прочие теги — в конце списка).
var docsTagOrder = []string{"Public Auth", "Web Session", "Me", "Admin", "OIDC"}

var (
	reDocTag    = regexp.MustCompile(`^tags: \[([^\]]*)\]$`)
	reDocCode   = regexp.MustCompile(`^'(\d{3})':$`)
	reDocMethod = regexp.MustCompile(`^(get|post|put|patch|delete):$`)
)

// parseOpenAPIDocsEndpoints разбирает встроенную спеку лёгким строчным
// парсером (без YAML-зависимости в рантайме). Он рассчитан на контролируемый
// формат api/openapi.yaml: пути на отступе 2, методы — 4, tags/summary и
// responses — 6, коды 'NNN' — 8 внутри responses; полнота покрытия
// сверяется юнит-тестом с полным разбором yaml.v3.
func parseOpenAPIDocsEndpoints() []docEndpoint { return parseOpenAPISpec(twofaapi.OpenAPIYAML) }

// parseOpenAPISpec — парсер описанного выше подмножества формата.
func parseOpenAPISpec(spec []byte) []docEndpoint {
	var (
		eps     []*docEndpoint
		cur     *docEndpoint
		curPath string
		inPaths bool
		inResp  bool
	)
	for _, line := range strings.Split(string(spec), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		trimmed := strings.TrimSpace(line)

		// Выход из поддерева responses: любая строка мельче отступа 8.
		if inResp && indent < 8 {
			inResp = false
		}
		// Коды ответов: 'NNN': на отступе 8.
		if inResp && cur != nil {
			if m := reDocCode.FindStringSubmatch(trimmed); m != nil && indent == 8 {
				cur.Codes = append(cur.Codes, m[1])
				continue
			}
		}

		if indent == 0 { // верхнеуровневые секции: интересна только paths
			inPaths = trimmed == "paths:"
			cur = nil
			continue
		}
		if !inPaths {
			continue
		}
		switch {
		case indent == 2 && strings.HasPrefix(trimmed, "/"):
			curPath = strings.TrimSuffix(trimmed, ":")
			cur = nil
		case indent == 4 && reDocMethod.MatchString(trimmed):
			method := strings.ToUpper(strings.TrimSuffix(trimmed, ":"))
			cur = &docEndpoint{Method: method, Path: curPath}
			eps = append(eps, cur)
			inResp = false
		case indent == 6 && cur != nil:
			switch {
			case reDocTag.MatchString(trimmed):
				cur.Tag = reDocTag.FindStringSubmatch(trimmed)[1]
			case strings.HasPrefix(trimmed, "summary: "):
				cur.Summary = strings.Trim(strings.TrimPrefix(trimmed, "summary: "), `"`)
			case trimmed == "responses:":
				inResp = true
			}
		}
	}
	out := make([]docEndpoint, len(eps))
	for i, ep := range eps {
		out[i] = *ep
	}
	return out
}

// serveOpenAPIDocs — GET /api/docs: таблица эндпоинтов по тегам.
func serveOpenAPIDocs(w http.ResponseWriter, _ *http.Request) {
	eps := parseOpenAPIDocsEndpoints()

	order := append([]string{}, docsTagOrder...)
	seen := make(map[string]bool, len(order))
	for _, t := range order {
		seen[t] = true
	}
	for _, ep := range eps {
		if ep.Tag != "" && !seen[ep.Tag] {
			seen[ep.Tag] = true
			order = append(order, ep.Tag)
		}
	}

	var b strings.Builder
	b.WriteString(`<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>API · 2FA</title>
<link rel="stylesheet" href="/static/style.css">
</head>
<body>
<main class="openapi-docs">
<header class="page-head">
  <h1>API twofa</h1>
  <p class="page-sub">JSON REST API: полный контракт — <a href="/openapi.yaml">/openapi.yaml</a> (OpenAPI 3.0.3). Админ-эндпоинты — Bearer admin_token; кабинет — cookie twofa_session + заголовок X-CSRF-Token на мутациях. RADIUS (:1812/:1813) описан в README.</p>
</header>
`)
	for _, tag := range order {
		var group []docEndpoint
		for _, ep := range eps {
			if ep.Tag == tag {
				group = append(group, ep)
			}
		}
		if len(group) == 0 {
			continue
		}
		b.WriteString(`<section class="card">
<div class="table-wrap">
<table class="table compact">
<tr><th>Метод</th><th>Путь</th><th>Описание</th><th>Коды</th></tr>
`)
		for _, ep := range group {
			b.WriteString(`<tr><td class="nowrap"><span class="badge neutral">`)
			b.WriteString(html.EscapeString(ep.Method))
			b.WriteString(`</span></td><td class="nowrap"><code>`)
			b.WriteString(html.EscapeString(ep.Path))
			b.WriteString(`</code></td><td>`)
			b.WriteString(html.EscapeString(ep.Summary))
			b.WriteString(`</td><td class="nowrap">`)
			b.WriteString(html.EscapeString(strings.Join(ep.Codes, ", ")))
			b.WriteString(`</td></tr>
`)
		}
		b.WriteString(`</table>
</div>
</section>
`)
	}
	b.WriteString(`</main>
</body>
</html>
`)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}
