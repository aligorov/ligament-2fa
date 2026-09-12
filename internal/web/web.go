// Package web — серверный рендер web-интерфейса twofa: html/template +
// go:embed для шаблонов и статики. Пакет standalone: данные передаются
// параметрами (pages.go), HTTP-обвязка и монтирование роутов — задача
// сборки (T14).
package web

import (
	"bytes"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/skip2/go-qrcode"

	"github.com/aligorov/twofa/internal/channel"
)

//go:embed templates
var tmplFS embed.FS

//go:embed static
var staticFS embed.FS

// layoutName — имя корневого шаблона-макета (base.gohtml); страницы
// определяют блок "content" и исполняются поверх макета.
const layoutName = "base.gohtml"

// Renderer — набор разобранных страниц: для каждой страницы клон макета
// с её блоком "content" (общий ParseFS всех файлов заменил бы "content"
// последней страницы).
type Renderer struct {
	tmpl map[string]*template.Template
}

// New разбирает макет и все страницы из embedded FS. Имена страниц —
// базовые имена файлов без .gohtml ("login", "admin_users", ...).
func New() (*Renderer, error) {
	base, err := template.New(layoutName).Funcs(funcs).ParseFS(tmplFS, "templates/"+layoutName)
	if err != nil {
		return nil, fmt.Errorf("web: разбор макета: %w", err)
	}
	entries, err := tmplFS.ReadDir("templates")
	if err != nil {
		return nil, fmt.Errorf("web: чтение templates: %w", err)
	}
	r := &Renderer{tmpl: make(map[string]*template.Template)}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || name == layoutName || !strings.HasSuffix(name, ".gohtml") {
			continue
		}
		t, err := base.Clone()
		if err != nil {
			return nil, fmt.Errorf("web: клон макета для %s: %w", name, err)
		}
		if _, err := t.ParseFS(tmplFS, "templates/"+name); err != nil {
			return nil, fmt.Errorf("web: разбор шаблона %s: %w", name, err)
		}
		r.tmpl[strings.TrimSuffix(name, ".gohtml")] = t
	}
	if len(r.tmpl) == 0 {
		return nil, errors.New("web: шаблоны страниц не найдены")
	}
	return r, nil
}

// Pages возвращает имена всех разобранных страниц (для тестов и T14).
func (r *Renderer) Pages() []string {
	out := make([]string, 0, len(r.tmpl))
	for name := range r.tmpl {
		out = append(out, name)
	}
	return out
}

// Render исполняет страницу name с данными data в w.
func (r *Renderer) Render(w io.Writer, name string, data any) error {
	t, ok := r.tmpl[name]
	if !ok {
		return fmt.Errorf("web: неизвестный шаблон %q", name)
	}
	if err := t.ExecuteTemplate(w, layoutName, data); err != nil {
		return fmt.Errorf("web: рендер %s: %w", name, err)
	}
	return nil
}

// ---- CSP HTML-рендер ----

// ContentSecurityPolicy — базовая строгая CSP всех HTML-ответов: только
// собственные скрипты/стили (инлайн-обработчики вынесены в
// app.js/webauthn.js/support_viewer.js), QR-коды — data:-URI (img-src data:),
// WebSocket (ws/wss) и WebRTC (media-src blob:). Ставится middleware
// securityHeaders (api/router.go) каждому ответу.
const ContentSecurityPolicy = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self' ws: wss:; media-src 'self' blob:"

// ContentSecurityPolicyAds — CSP страницы, на которой РЕАЛЬНО рендерится
// рекламный слот: домены Яндекса для загрузчика context.js, рендера блоков
// и их картинок/фреймов + unsafe-inline для стилей блоков РСЯ. Применяется
// точечно рендером страницы (RenderHTML), а не глобально: админка и прочие
// страницы без слотов остаются под строгой политикой.
const ContentSecurityPolicyAds = "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; script-src 'self' https://yandex.st https://an.yandex.ru; frame-src https://an.yandex.ru https://yandex.st; connect-src 'self' https://an.yandex.ru"

// AdsNeedsCSP — рендерится ли на этой странице слот, требующий расширения
// CSP. Слоты зависят от макета страницы (report 2026-09-11, Web UI-1 —
// решение по фактически отрендеренным слотам):
//   - layout_center (login, error, oidc_consent) — боковые слоты входа
//     LoginLeft/LoginRight;
//   - layout_app (кабинет и админка) — только Sidebar;
//   - полноэкранная консоль поддержки — рекламных мест нет вовсе.
//
// РСЯ требует домены Яндекса для загрузчика context.js; direct-слот
// рендерится в обоих макетах и расширяет CSP только при внешней
// https-картинке (чистая ссылка обходится строгой политикой).
func AdsNeedsCSP(page string, a AdsData) bool {
	if !a.Show {
		return false
	}
	if page == "admin_support_viewer" {
		return false
	}
	if a.Provider != "rsya" {
		return a.DirectImage != ""
	}
	if centerLayoutPages[page] {
		return a.LoginLeft != "" || a.LoginRight != ""
	}
	return a.Sidebar != ""
}

// centerLayoutPages — страницы с центрированным макетом (layout_center).
var centerLayoutPages = map[string]bool{
	"login":        true,
	"error":        true,
	"oidc_consent": true,
}

// pageAds извлекает BaseData.Ads из данных страницы: все структуры страниц
// встраивают BaseData (с полем Ads), поэтому CSP-решение делается reflection'ом
// — методы под каждый тип страницы не нужны.
func pageAds(data any) (AdsData, bool) {
	v := reflect.ValueOf(data)
	for v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return AdsData{}, false
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return AdsData{}, false
	}
	base := v.FieldByName("BaseData")
	if !base.IsValid() || base.Type() != reflect.TypeOf(BaseData{}) {
		return AdsData{}, false
	}
	ads := base.FieldByName("Ads")
	if !ads.IsValid() || !ads.CanInterface() {
		return AdsData{}, false
	}
	a, ok := ads.Interface().(AdsData)
	return a, ok
}

// RenderHTML — HTTP-рендер страницы для ResponseWriter: до первого Write
// ставит Content-Type и CSP. Базовая политика — строгая; страница с
// фактически отрендеренными рекламными слотами получает relaxed-вариант
// с доменами Яндекса (админка и страницы без слотов остаются строгими).
// После первого Write заголовки браузером игнорируются, поэтому тело
// исполняется в буфер и только потом уходит в сеть вместе с WriteHeader.
func (r *Renderer) RenderHTML(w http.ResponseWriter, status int, page string, data any) error {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	csp := ContentSecurityPolicy
	if ads, ok := pageAds(data); ok && AdsNeedsCSP(page, ads) {
		csp = ContentSecurityPolicyAds
	}
	h.Set("Content-Security-Policy", csp)
	var buf bytes.Buffer
	err := r.Render(&buf, page, data)
	w.WriteHeader(status)
	// Частично отрендеренное тело отдаётся как есть — записанную середину
	// ответа откатить нельзя (ошибку логирует вызывающий).
	_, _ = w.Write(buf.Bytes())
	return err
}

// Static возвращает файловую систему статики (style.css, webauthn.js)
// для http.FileServer / chi. Монтируется на /static (T14).
func Static() http.FileSystem {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		// Не может случиться: каталог "static" вшит embed-директивой.
		panic(fmt.Sprintf("web: static subdir: %v", err))
	}
	return http.FS(sub)
}

// ---- функции шаблонов ----

// csrf возвращает скрытое поле CSRF-токена для формы; пустой токен —
// пустая строка (формы без сессии, например /login до входа).
func csrf(token string) template.HTML {
	if token == "" {
		return ""
	}
	return template.HTML(`<input type="hidden" name="csrf_token" value="` +
		html.EscapeString(token) + `">`)
}

// jsonPretty форматирует значение как JSON с отступами (detail аудита,
// JSON-textarea настроек); не-форматируемое значение печатается как есть.
func jsonPretty(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

// qrPNG кодирует строку (otpauth://...) в PNG-QR и возвращает data-URI
// для <img src>. template.URL помечает data-URI безопасным: иначе
// фильтр URL контекста html/template заменит его на #ZgotmplZ.
func qrPNG(content string) (template.URL, error) {
	png, err := qrcode.Encode(content, qrcode.Medium, 200)
	if err != nil {
		return "", fmt.Errorf("web: QR-код: %w", err)
	}
	return template.URL("data:image/png;base64," +
		base64.StdEncoding.EncodeToString(png)), nil
}

// hasChan сообщает, входит ли канал в prefer_channels (чекбоксы форм).
func hasChan(chs []channel.Channel, name string) bool {
	for _, c := range chs {
		if string(c) == name {
			return true
		}
	}
	return false
}

// dt форматирует время в "02.01.2006 15:04"; nil — прочерк.
// templateDict — map[string]any из пар ключ-значение (для передачи
// нескольких аргументов во вложенный шаблон).
func templateDict(kv ...any) map[string]any {
	out := make(map[string]any, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		if k, ok := kv[i].(string); ok {
			out[k] = kv[i+1]
		}
	}
	return out
}

var (
	locMu sync.RWMutex
	locFn func() *time.Location
)

// SetLocationFunc задаёт поставщик текущего часового пояса для рендера дат в шаблонах.
func SetLocationFunc(fn func() *time.Location) {
	locMu.Lock()
	locFn = fn
	locMu.Unlock()
}

func currentLoc() *time.Location {
	locMu.RLock()
	fn := locFn
	locMu.RUnlock()
	if fn != nil {
		if l := fn(); l != nil {
			return l
		}
	}
	loc, err := time.LoadLocation("Europe/Moscow")
	if err == nil {
		return loc
	}
	return time.FixedZone("MSK", 3*3600)
}

func dt(v any) string {
	loc := currentLoc()
	switch t := v.(type) {
	case time.Time:
		return t.In(loc).Format("02.01.2006 15:04")
	case *time.Time:
		if t != nil {
			return t.In(loc).Format("02.01.2006 15:04")
		}
	}
	return "—"
}

// deref разыменовывает *string (PushState) для сравнения eq в шаблонах;
// nil и не-строка дают "".
func deref(v any) string {
	switch s := v.(type) {
	case *string:
		if s != nil {
			return *s
		}
	case string:
		return s
	}
	return ""
}

// vlanDesc форматирует отображение VLAN с названием профиля (VLAN 20 (IT отдел)).
func vlanDesc(profiles map[string]string, vlanID string) string {
	if vlanID == "" {
		return ""
	}
	if profiles != nil {
		if name, ok := profiles[vlanID]; ok && name != "" {
			return fmt.Sprintf("VLAN %s (%s)", vlanID, name)
		}
	}
	return "VLAN " + vlanID
}

// groupCN извлекает короткое имя (CN или OU) из Distinguished Name,
// отсекая атрибуты домена и контейнеров (DC=..., CN=Users, OU=...).
func groupCN(dn string) string {
	lower := strings.ToLower(dn)
	for _, prefix := range []string{"cn=", "ou="} {
		if idx := strings.Index(lower, prefix); idx >= 0 {
			start := idx + len(prefix)
			var sb strings.Builder
			runes := []rune(dn[start:])
			for i := 0; i < len(runes); i++ {
				if runes[i] == '\\' && i+1 < len(runes) {
					sb.WriteRune(runes[i+1])
					i++
					continue
				}
				if runes[i] == ',' {
					break
				}
				sb.WriteRune(runes[i])
			}
			val := strings.TrimSpace(sb.String())
			if val != "" {
				return val
			}
		}
	}
	return dn
}

// userInitials генерирует 1-2 символа инициалов для аватара пользователя.
func userInitials(name, username string) string {
	s := strings.TrimSpace(name)
	if s == "" {
		s = strings.TrimSpace(username)
	}
	parts := strings.Fields(s)
	if len(parts) >= 2 {
		r1 := []rune(parts[0])
		r2 := []rune(parts[1])
		if len(r1) > 0 && len(r2) > 0 {
			return strings.ToUpper(string(r1[0]) + string(r2[0]))
		}
	}
	runes := []rune(s)
	if len(runes) >= 2 {
		return strings.ToUpper(string(runes[:2]))
	}
	if len(runes) == 1 {
		return strings.ToUpper(string(runes[:1]))
	}
	return "?"
}

// userAvatarBg возвращает стильный цвет фона для аватара на основе хэша строки.
func userAvatarBg(s string) string {
	var hash uint32 = 2166136261
	for _, b := range []byte(s) {
		hash ^= uint32(b)
		hash *= 16777619
	}
	colors := []string{
		"#4f46e5", "#0284c7", "#0d9488", "#16a34a",
		"#d97706", "#dc2626", "#7c3aed", "#db2777",
		"#2563eb", "#059669", "#ea580c", "#9333ea",
	}
	return colors[hash%uint32(len(colors))]
}

// funcs — общие функции шаблонов.
var funcs = template.FuncMap{
	"csrf":         csrf,
	"jsonPretty":   jsonPretty,
	"qrPNG":        qrPNG,
	"hasChan":      hasChan,
	"dt":           dt,
	"dict":         templateDict,
	"deref":        deref,
	"vlanDesc":     vlanDesc,
	"groupCN":      groupCN,
	"userInitials": userInitials,
	"userAvatarBg": userAvatarBg,
	"sub":          func(a, b int) int { return a - b },
	"join":         strings.Join,
	"hasUUID": func(list []uuid.UUID, id uuid.UUID) bool {
		for _, x := range list {
			if x == id {
				return true
			}
		}
		return false
	},
	"hasStr": func(list []string, s string) bool {
		for _, x := range list {
			if strings.EqualFold(strings.TrimSpace(x), strings.TrimSpace(s)) {
				return true
			}
		}
		return false
	},
}
