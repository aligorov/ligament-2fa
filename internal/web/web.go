// Package web — серверный рендер web-интерфейса twofa: html/template +
// go:embed для шаблонов и статики. Пакет standalone: данные передаются
// параметрами (pages.go), HTTP-обвязка и монтирование роутов — задача
// сборки (T14).
package web

import (
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

// groupCN извлекает короткое имя (CN или OU) из Distinguished Name.
func groupCN(dn string) string {
	for _, part := range strings.Split(dn, ",") {
		part = strings.TrimSpace(part)
		if idx := strings.Index(part, "="); idx > 0 {
			key := strings.ToUpper(strings.TrimSpace(part[:idx]))
			val := strings.TrimSpace(part[idx+1:])
			if key == "CN" || key == "OU" {
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
