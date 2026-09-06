package delivery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aligorov/twofa/internal/channel"
)

// GatewayConfig описывает HTTP-шлюз отправки SMS. URL, Body и значения
// Headers — шаблоны с плейсхолдерами {phone} и {text} (номер и текст
// сообщения). Пресеты дополнительно подставляют свои значения из
// Headers по ключу плейсхолдера (см. Preset).
//
// JSON-теги совпадают с зеркальным типом settings.SMSGatewayConfig
// (ключ sms.gateway): конфиг, отданный в UI (Presets), кладётся в
// textarea настроек и читается обратно без потерь.
type GatewayConfig struct {
	Preset      string            `json:"preset"`
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Body        string            `json:"body"`
	ContentType string            `json:"content_type"`
	Headers     map[string]string `json:"headers"`
	Success     SuccessRule       `json:"success"`
}

// SuccessRule проверяет ответ шлюза: должны выполниться ВСЕ непустые
// поля (логическое И). JSONPath-сравнение строкифицирует JSON-значения:
// число 0 совпадает с "0", true — с "true".
type SuccessRule struct {
	HTTPStatus   int    `json:"http_status"`
	BodyContains string `json:"body_contains"`
	JSONPath     string `json:"json_path"`
	Equals       string `json:"equals"`
}

// SMSSender отправляет SMS через HTTP-шлюз, описанный GatewayConfig.
type SMSSender struct {
	gw GatewayConfig
	hc *http.Client
}

var _ Sender = (*SMSSender)(nil)

// NewSMS создаёт HTTP-отправитель SMS. Если hc равен nil, используется
// клиент с таймаутом 10 с; контекст передаётся в каждый запрос.
func NewSMS(gw GatewayConfig, hc *http.Client) Sender {
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	return &SMSSender{gw: gw, hc: hc}
}

// Name реализует Sender.
func (s *SMSSender) Name() channel.Channel { return channel.SMS }

// Send выполняет запрос к шлюзу и проверяет ответ по SuccessRule.
// Плейсхолдеры {phone} и {text} (номер и текст сообщения, построенный
// из BodyTemplate) подставляются в URL через url.QueryEscape, в значения
// заголовков — как есть, а в тело — как есть ЛИБО, при ContentType
// application/json, с экранированием JSON-строки (jsonEscape): кавычки,
// обратные слэши и переводы строк не ломают JSON-тело (prostor и т.п.).
func (s *SMSSender) Send(ctx context.Context, to, code string) error {
	text := strings.ReplaceAll(BodyTemplate, "{code}", code)
	method := s.gw.Method
	if method == "" {
		method = http.MethodGet
		if s.gw.Body != "" {
			method = http.MethodPost
		}
	}
	urlRepl := s.replacer(to, text, escURL)
	headerRepl := s.replacer(to, text, escNone)
	bodyRepl := headerRepl
	if isJSONContentType(s.gw.ContentType) {
		bodyRepl = s.replacer(to, text, escJSON)
	}

	var body io.Reader
	var contentType string
	switch {
	case s.gw.Body != "": // произвольный шаблон тела
		body = strings.NewReader(bodyRepl.Replace(s.gw.Body))
		contentType = s.gw.ContentType
	case s.gw.Preset == "twilio":
		// Пресет twilio: form-encoded To/From/Body (From из Headers["from"]);
		// url.Values.Encode() сам экранирует значения.
		form := url.Values{}
		form.Set("To", to)
		form.Set("From", s.gw.Headers["from"])
		form.Set("Body", text)
		body = strings.NewReader(form.Encode())
		contentType = s.gw.ContentType
		if contentType == "" {
			contentType = "application/x-www-form-urlencoded"
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, urlRepl.Replace(s.gw.URL), body)
	if err != nil {
		return fmt.Errorf("delivery: sms: собрать запрос: %w", err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range s.gw.Headers {
		req.Header.Set(k, headerRepl.Replace(v))
	}
	if s.gw.Preset == "twilio" { // basic-auth из учётных данных пресета
		req.SetBasicAuth(s.gw.Headers["sid"], s.gw.Headers["token"])
	}

	resp, err := s.hc.Do(req)
	if err != nil {
		return fmt.Errorf("delivery: sms: шлюз: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("delivery: sms: чтение ответа: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("delivery: sms: HTTP %d от шлюза: %s", resp.StatusCode, snippet(string(respBody)))
	}
	if err := s.gw.Success.check(resp.StatusCode, string(respBody)); err != nil {
		return fmt.Errorf("delivery: sms: ответ шлюза не прошёл проверку: %w (ответ: %s)", err, snippet(string(respBody)))
	}
	return nil
}

// escMode — способ подстановки значений плейсхолдеров.
type escMode int

const (
	escNone escMode = iota // как есть (значения заголовков)
	escURL                 // url.QueryEscape (URL запроса)
	escJSON                // экранирование JSON-строки (JSON-тело запроса)
)

// replacer собирает strings.Replacer для плейсхолдеров {phone} и {text},
// а также {<ключ>} для каждого ключа из Headers (значения пресетов:
// login/psw, sid/token/from и т.д.). mode задаёт способ экранирования
// значений (см. escMode).
func (s *SMSSender) replacer(phone, text string, mode escMode) *strings.Replacer {
	esc := func(v string) string {
		switch mode {
		case escURL:
			return url.QueryEscape(v)
		case escJSON:
			return jsonEscape(v)
		default:
			return v
		}
	}
	pairs := []string{
		"{phone}", esc(phone),
		"{text}", esc(text),
	}
	for k, v := range s.gw.Headers {
		pairs = append(pairs, "{"+k+"}", esc(v))
	}
	return strings.NewReplacer(pairs...)
}

// isJSONContentType — Content-Type объявляет JSON (допускает суффиксы вида
// «; charset=utf-8»), без учёта регистра и пробелов по краям.
func isJSONContentType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	return ct == "application/json" || strings.HasPrefix(ct, "application/json;")
}

// jsonEscape экранирует значение как содержимое JSON-строки: кавычки,
// обратные слэши и управляющие символы — по правилам encoding/json, БЕЗ
// HTML-экранирования (<, >, & остаются как есть — round-trip текста).
func jsonEscape(s string) string {
	need := false
	for _, r := range s {
		if r == '"' || r == '\\' || r < 0x20 {
			need = true
			break
		}
	}
	if !need {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&b, `\u%04x`, r)
				continue
			}
			b.WriteRune(r)
		}
	}
	return b.String()
}

// check проверяет ответ по правилу: все непустые поля — по И.
func (r SuccessRule) check(status int, body string) error {
	if r.HTTPStatus != 0 && status != r.HTTPStatus {
		return fmt.Errorf("HTTPStatus: получили %d, ожидается %d", status, r.HTTPStatus)
	}
	if r.BodyContains != "" && !strings.Contains(body, r.BodyContains) {
		return fmt.Errorf("BodyContains: %q не найдено в теле ответа", r.BodyContains)
	}
	if r.JSONPath != "" {
		got, ok := jsonPathValue(body, r.JSONPath)
		if !ok {
			return fmt.Errorf("JSONPath: путь %s не найден", r.JSONPath)
		}
		// Пустой Equals — достаточно существования пути.
		if r.Equals != "" && got != r.Equals {
			return fmt.Errorf("JSONPath: %s = %q, ожидается %q", r.JSONPath, got, r.Equals)
		}
	}
	return nil
}

// jsonPathValue извлекает значение по простому пути вида $.field (или
// $.a.b — только поля объектов). Индексы массивов, маски и фильтры не
// поддерживаются: этого достаточно для пресетов и типовых шлюзов.
// Числа и булевы значения приводятся к строке через fmt.Sprint.
func jsonPathValue(data, path string) (string, bool) {
	p := strings.TrimPrefix(path, "$.")
	if p == path || p == "" { // нет префикса "$." — некорректный путь
		return "", false
	}
	var cur any
	if err := json.Unmarshal([]byte(data), &cur); err != nil {
		return "", false
	}
	for _, part := range strings.Split(p, ".") {
		obj, ok := cur.(map[string]any)
		if !ok {
			return "", false
		}
		if cur, ok = obj[part]; !ok {
			return "", false
		}
	}
	switch v := cur.(type) {
	case string:
		return v, true
	case nil:
		return "null", true
	default:
		return fmt.Sprint(v), true
	}
}

// snippet обрезает тело ответа до 200 символов для сообщений об ошибках.
func snippet(s string) string {
	const max = 200
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
