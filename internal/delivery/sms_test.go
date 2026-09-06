package delivery

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aligorov/twofa/internal/channel"
)

func TestSMSName(t *testing.T) {
	if got := NewSMS(GatewayConfig{}, nil).Name(); got != channel.SMS {
		t.Fatalf("Name() = %q, want %q", got, channel.SMS)
	}
}

func TestSMSSuccessByStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	// Method пуст — по умолчанию GET (Body не задан).
	gw := GatewayConfig{URL: srv.URL, Success: SuccessRule{HTTPStatus: 200}}
	if err := NewSMS(gw, srv.Client()).Send(context.Background(), "+79161234567", "123456"); err != nil {
		t.Fatalf("Send: %v", err)
	}
}

func TestSMSSuccessByBodyContains(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"status":"ok","id":42}`)
	}))
	defer srv.Close()
	gw := GatewayConfig{Method: "GET", URL: srv.URL, Success: SuccessRule{BodyContains: `"status":"ok"`}}
	if err := NewSMS(gw, srv.Client()).Send(context.Background(), "+79161234567", "123456"); err != nil {
		t.Fatalf("Send: %v", err)
	}
}

func TestSMSSuccessByJSONPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"status":"ok","id":42}`)
	}))
	defer srv.Close()
	gw := GatewayConfig{Method: "GET", URL: srv.URL, Success: SuccessRule{JSONPath: "$.status", Equals: "ok"}}
	if err := NewSMS(gw, srv.Client()).Send(context.Background(), "+79161234567", "123456"); err != nil {
		t.Fatalf("Send: %v", err)
	}
}

func TestSMSFailedJSONPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"status":"error"}`)
	}))
	defer srv.Close()
	gw := GatewayConfig{Method: "GET", URL: srv.URL, Success: SuccessRule{JSONPath: "$.status", Equals: "ok"}}
	err := NewSMS(gw, srv.Client()).Send(context.Background(), "+79161234567", "123456")
	if err == nil {
		t.Fatal("ожидали ошибку: JSONPath $.status = \"error\" != \"ok\"")
	}
	if !strings.Contains(err.Error(), "$.status") {
		t.Errorf("ошибка %q не упоминает JSONPath", err)
	}
	if !strings.Contains(err.Error(), `{"status":"error"}`) {
		t.Errorf("ошибка %q не содержит фрагмент ответа", err)
	}
}

func TestSMSNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "boom")
	}))
	defer srv.Close()
	gw := GatewayConfig{Method: "GET", URL: srv.URL}
	err := NewSMS(gw, srv.Client()).Send(context.Background(), "+79161234567", "123456")
	if err == nil {
		t.Fatal("ожидали ошибку при HTTP 500")
	}
	if !strings.Contains(err.Error(), "500") || !strings.Contains(err.Error(), "boom") {
		t.Errorf("ошибка %q должна содержать статус 500 и фрагмент ответа", err)
	}
}

// TestSMSSuccessJSONPathStringifiedEquals — JSONPath-сравнение строкифицирует
// JSON-значения: число 0 совпадает с "0" (bytehand $.status, smsgateway24
// $.error), bool true — с "true" (smsaero $.success), число 1 — с "1"
// (smsc $.cnt). Без stringify числовые/булевы поля пресетов не матчатся.
func TestSMSSuccessJSONPathStringifiedEquals(t *testing.T) {
	cases := []struct {
		name string
		body string
		rule SuccessRule
	}{
		{"число 0 == \"0\" (bytehand $.status)", `{"status":0}`, SuccessRule{JSONPath: "$.status", Equals: "0"}},
		{"число 1 == \"1\" (smsc $.cnt)", `{"cnt":1,"id":42}`, SuccessRule{JSONPath: "$.cnt", Equals: "1"}},
		{"bool true == \"true\" (smsaero $.success)", `{"success":true,"data":null}`, SuccessRule{JSONPath: "$.success", Equals: "true"}},
		{"bool false == \"false\"", `{"success":false}`, SuccessRule{JSONPath: "$.success", Equals: "false"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, tc.body)
			}))
			defer srv.Close()
			if err := NewSMS(GatewayConfig{Method: "GET", URL: srv.URL, Success: tc.rule},
				srv.Client()).Send(context.Background(), "+79161234567", "123456"); err != nil {
				t.Fatalf("Send: %v (строкификация значения не сработала)", err)
			}
		})
	}
}

// TestSMSJSONBodyEscaping — при ContentType application/json значения
// плейсхолдеров ({phone}/{text} и креды из Headers, напр. {sender} у prostor)
// экранируются как JSON-строки: кавычки, обратные слэши и переводы строк не
// ломают тело. Проверка — полный round-trip через json.Unmarshal.
func TestSMSJSONBodyEscaping(t *testing.T) {
	const weirdPhone = "+7 916\nX\"Y\\Z"
	// В заголовках перевод строки запрещён протоколом — sender несёт
	// кавычки и обратный слэш, перевод строки проверяется через phone.
	const weirdSender = `My "SMS" \ Best`
	gotBody := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody <- string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	gw := GatewayConfig{
		Method:      "POST",
		URL:         srv.URL + "/send.json",
		Body:        `{"messages":[{"phone":"{phone}","sender":"{sender}","text":"{text}"}]}`,
		ContentType: "application/json",
		Headers:     map[string]string{"sender": weirdSender},
	}
	if err := NewSMS(gw, srv.Client()).Send(context.Background(), weirdPhone, "654321"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	var parsed struct {
		Messages []struct{ Phone, Sender, Text string } `json:"messages"`
	}
	if err := json.Unmarshal([]byte(<-gotBody), &parsed); err != nil {
		t.Fatalf("тело не валидный JSON (экранирование не сработало): %v", err)
	}
	if len(parsed.Messages) != 1 {
		t.Fatalf("messages: ожидался 1 элемент, получено %d", len(parsed.Messages))
	}
	m := parsed.Messages[0]
	if m.Phone != weirdPhone {
		t.Errorf("phone round-trip: got %q, want %q", m.Phone, weirdPhone)
	}
	if m.Sender != weirdSender {
		t.Errorf("sender round-trip: got %q, want %q", m.Sender, weirdSender)
	}
	if m.Text != "Ваш код подтверждения: 654321" {
		t.Errorf("text round-trip: got %q", m.Text)
	}
}

func TestSMSErrorSnippetTruncated(t *testing.T) {
	long := strings.Repeat("a", 500)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, long)
	}))
	defer srv.Close()
	gw := GatewayConfig{Method: "GET", URL: srv.URL}
	err := NewSMS(gw, srv.Client()).Send(context.Background(), "+79161234567", "123456")
	if err == nil {
		t.Fatal("ожидали ошибку при HTTP 400")
	}
	if !strings.Contains(err.Error(), strings.Repeat("a", 200)) {
		t.Errorf("ошибка должна содержать первые 200 символов ответа")
	}
	if strings.Contains(err.Error(), strings.Repeat("a", 201)) {
		t.Errorf("фрагмент ответа в ошибке не обрезан до 200 символов")
	}
}

func TestSMSPlaceholderURLQueryEscaped(t *testing.T) {
	const phone = "+7 916 123-45-67" // пробелы и плюс требуют экранирования
	gotQuery := make(chan url.Values, 1)
	gotMethod := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery <- r.URL.Query()
		gotMethod <- r.Method
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	gw := GatewayConfig{Method: "GET", URL: srv.URL + "/send?phone={phone}&text={text}"}
	if err := NewSMS(gw, srv.Client()).Send(context.Background(), phone, "654321"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	q := <-gotQuery
	if m := <-gotMethod; m != http.MethodGet {
		t.Errorf("метод = %s, want GET", m)
	}
	if got := q.Get("phone"); got != phone {
		t.Errorf("phone в URL = %q, want %q (подстановка без потерь после QueryEscape)", got, phone)
	}
	if got := q.Get("text"); got != "Ваш код подтверждения: 654321" {
		t.Errorf("text в URL = %q, want текст BodyTemplate с кодом", got)
	}
}

func TestSMSPlaceholderBodyAndHeadersRaw(t *testing.T) {
	const phone = "+7 916"
	got := make(chan *http.Request, 1)
	gotBody := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- r.Clone(context.Background())
		gotBody <- string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	gw := GatewayConfig{
		Method:      "POST",
		URL:         srv.URL + "/send",
		Body:        `{"phone":"{phone}","text":"{text}"}`,
		ContentType: "application/json",
		Headers:     map[string]string{"X-Phone": "{phone}", "X-Text": "{text}"},
	}
	if err := NewSMS(gw, srv.Client()).Send(context.Background(), phone, "112233"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	req := <-got
	body := <-gotBody

	wantText := "Ваш код подтверждения: 112233"
	if !strings.Contains(body, `"`+phone+`"`) {
		t.Errorf("тело %q должно содержать телефон %q как есть (raw)", body, phone)
	}
	if !strings.Contains(body, `"`+wantText+`"`) {
		t.Errorf("тело %q должно содержать текст сообщения как есть", body)
	}
	if got := req.Header.Get("X-Phone"); got != phone {
		t.Errorf("заголовок X-Phone = %q, want %q", got, phone)
	}
	if got := req.Header.Get("X-Text"); got != wantText {
		t.Errorf("заголовок X-Text = %q, want %q", got, wantText)
	}
	if ct := req.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestPresetUnknown(t *testing.T) {
	if _, ok := Preset("nope"); ok {
		t.Fatal("Preset(\"nope\") вернул ok=true, want false")
	}
}

// TestPresetTwilioSuccessStatuses — реальный Twilio на успешное создание
// сообщения отвечает 201 Created, поэтому успех пресета — любой 2xx
// (HTTPStatus не задан), а 4xx/5xx — ошибка.
func TestPresetTwilioSuccessStatuses(t *testing.T) {
	cases := []struct {
		name   string
		status int
		wantOK bool
	}{
		{"201 Created — реальный ответ Twilio при успехе", http.StatusCreated, true},
		{"200 OK — любой 2xx тоже успех", http.StatusOK, true},
		{"400 Bad Request — ошибка", http.StatusBadRequest, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()

			cfg, ok := Preset("twilio")
			if !ok {
				t.Fatal("Preset(\"twilio\") вернул ok=false")
			}
			cfg.URL = strings.Replace(cfg.URL, "https://api.twilio.com", srv.URL, 1)
			cfg.Headers = map[string]string{"sid": "AC123", "token": "tok456", "from": "+15005550006"}
			err := NewSMS(cfg, srv.Client()).Send(context.Background(), "+79161234567", "777888")
			if tc.wantOK && err != nil {
				t.Fatalf("Send при HTTP %d: %v (реальный Twilio отвечает 201 — это успех)", tc.status, err)
			}
			if !tc.wantOK && err == nil {
				t.Fatalf("Send при HTTP %d должен вернуть ошибку", tc.status)
			}
		})
	}
}

// capturedReq — зафиксированный шлюзом запрос.
type capturedReq struct {
	method   string
	path     string
	query    url.Values
	header   http.Header
	form     url.Values
	body     string
	user     string
	password string
}

// captureServer поднимает шлюз, который всегда отвечает 200 и фиксирует
// запрос (метод, путь, query, заголовки, тело, basic-auth, form-тело).
func captureServer(t *testing.T) (*capturedReq, *httptest.Server) {
	t.Helper()
	captured := &capturedReq{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.method = r.Method
		captured.path = r.URL.Path
		captured.query = r.URL.Query()
		captured.header = r.Header.Clone()
		b, _ := io.ReadAll(r.Body)
		captured.body = string(b)
		r.Body = io.NopCloser(bytes.NewReader(b)) // вернуть тело для ParseForm
		captured.user, captured.password, _ = r.BasicAuth()
		_ = r.ParseForm()
		captured.form = r.PostForm
		w.WriteHeader(http.StatusOK)
	}))
	return captured, srv
}

func TestPresetSMSC(t *testing.T) {
	cfg, ok := Preset("smsc")
	if !ok {
		t.Fatal("Preset(\"smsc\") вернул ok=false")
	}
	if cfg.Method != http.MethodGet {
		t.Fatalf("метод пресета = %s, want GET", cfg.Method)
	}
	if cfg.Success.HTTPStatus != 200 {
		t.Fatalf("Success.HTTPStatus = %d, want 200", cfg.Success.HTTPStatus)
	}
	// smsc с fmt=3 отвечает JSON: успех — числовое поле cnt (== 1),
	// ошибка — HTTP 200 без cnt → правило $.cnt=="1" обязательное.
	if cfg.Success.JSONPath != "$.cnt" || cfg.Success.Equals != "1" {
		t.Fatalf("Success = %+v, want JSONPath $.cnt == \"1\" (ошибки у smsc тоже HTTP 200)", cfg.Success)
	}
	captured := &capturedReq{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.method = r.Method
		captured.path = r.URL.Path
		captured.query = r.URL.Query()
		_, _ = io.WriteString(w, `{"cnt":1,"id":42}`)
	}))
	defer srv.Close()

	cfg.URL = strings.Replace(cfg.URL, "https://smsc.ru", srv.URL, 1)
	cfg.Headers = map[string]string{"login": "mylogin", "psw": "mypsw"}
	if err := NewSMS(cfg, srv.Client()).Send(context.Background(), "+79161234567", "424242"); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if captured.method != http.MethodGet {
		t.Errorf("метод = %s, want GET", captured.method)
	}
	if captured.path != "/sys/send.php" {
		t.Errorf("путь = %s, want /sys/send.php", captured.path)
	}
	for param, want := range map[string]string{
		"login":   "mylogin",
		"psw":     "mypsw",
		"phones":  "+79161234567",
		"mes":     "Ваш код подтверждения: 424242",
		"fmt":     "3",
		"charset": "utf-8",
	} {
		if got := captured.query.Get(param); got != want {
			t.Errorf("query[%s] = %q, want %q", param, got, want)
		}
	}
}

func TestPresetTwilio(t *testing.T) {
	cfg, ok := Preset("twilio")
	if !ok {
		t.Fatal("Preset(\"twilio\") вернул ok=false")
	}
	if cfg.Method != http.MethodPost {
		t.Fatalf("метод пресета = %s, want POST", cfg.Method)
	}
	// Нулевое правило успеха: Twilio отвечает 201 Created, точный
	// статус отсекал бы реальные успехи — остаётся общий 2xx-гейт.
	if cfg.Success != (SuccessRule{}) {
		t.Fatalf("Success = %+v, want нулевое значение (любой 2xx)", cfg.Success)
	}
	capReq, srv := captureServer(t)
	defer srv.Close()

	cfg.URL = strings.Replace(cfg.URL, "https://api.twilio.com", srv.URL, 1)
	cfg.Headers = map[string]string{"sid": "AC123", "token": "tok456", "from": "+15005550006"}
	if err := NewSMS(cfg, srv.Client()).Send(context.Background(), "+79161234567", "777888"); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if capReq.method != http.MethodPost {
		t.Errorf("метод = %s, want POST", capReq.method)
	}
	if capReq.path != "/2010-04-01/Accounts/AC123/Messages.json" {
		t.Errorf("путь = %s, want /2010-04-01/Accounts/AC123/Messages.json", capReq.path)
	}
	if capReq.user != "AC123" || capReq.password != "tok456" {
		t.Errorf("basic auth = %q:%q, want AC123:tok456", capReq.user, capReq.password)
	}
	if ct := capReq.header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q, want application/x-www-form-urlencoded", ct)
	}
	for param, want := range map[string]string{
		"To":   "+79161234567",
		"From": "+15005550006",
		"Body": "Ваш код подтверждения: 777888",
	} {
		if got := capReq.form.Get(param); got != want {
			t.Errorf("form[%s] = %q, want %q", param, got, want)
		}
	}
}

// ---- пресеты шлюзов РФ (research: docs/research/2026-09-06-sms-gateways-ru.md) ----

// rfPresetCase — ожидания по пресету из research-дока: форма запроса к
// шлюзу (метод/путь/query/заголовки) и ответы успеха/ошибки для проверки
// правила Success.
type rfPresetCase struct {
	name       string
	creds      map[string]string // креды пресета (значения Headers)
	wantMethod string
	wantPath   string
	wantQuery  map[string]string
	wantHeader map[string]string
	okBody     string // ответ шлюза при успехе
	errStatus  int    // ответ шлюза при ошибке
	errBody    string
}

// rfPresetCases — сверено с research-доком 2026-09-06 (эндпоинты и
// коды ответов проверены живыми запросами).
var rfPresetCases = []rfPresetCase{
	{
		name: "smsru", creds: map[string]string{"api_id": "ID-12345"},
		wantMethod: http.MethodGet, wantPath: "/sms/send",
		wantQuery: map[string]string{"api_id": "ID-12345", "to": "+79161234567", "msg": "Ваш код подтверждения: 135790", "json": "1"},
		okBody:    `{"status":"OK","sms":{"79161234567":{"id":123456}}}`,
		errStatus: http.StatusOK, errBody: `{"status":"ERROR","status_code":100}`,
	},
	{
		name: "smsaero", creds: map[string]string{"auth_base64": "dXNlckBleGFtcGxlLmNvbTprZXk=", "sender": "SMS Aero"},
		wantMethod: http.MethodGet, wantPath: "/v2/sms/send",
		wantQuery:  map[string]string{"number": "+79161234567", "text": "Ваш код подтверждения: 135790", "sign": "SMS Aero"},
		wantHeader: map[string]string{"Authorization": "Basic dXNlckBleGFtcGxlLmNvbTprZXk="},
		// smsaero: ошибочные ответы — не-200; успех — HTTP 200 (json_path пуст).
		okBody: `{"success":true,"data":[]}`, errStatus: http.StatusNotFound, errBody: `{"message":"API key not found"}`,
	},
	{
		name: "mainsms", creds: map[string]string{"project": "myproj", "api_key": "key123"},
		wantMethod: http.MethodGet, wantPath: "/api/mainsms/message/send",
		wantQuery: map[string]string{"project": "myproj", "apikey": "key123", "recipients": "+79161234567", "message": "Ваш код подтверждения: 135790"},
		okBody:    `{"status":"success","messages_id":"654321"}`,
		errStatus: http.StatusOK, errBody: `{"status":"error","message":"invalid api key"}`,
	},
	{
		name: "bytehand", creds: map[string]string{"id": "11", "key": "KEY", "sender": "SIGN"},
		wantMethod: http.MethodGet, wantPath: "/v1/send",
		wantQuery: map[string]string{"id": "11", "key": "KEY", "from": "SIGN", "to": "+79161234567", "text": "Ваш код подтверждения: 135790"},
		// bytehand: $.status — ЧИСЛО 0 при успехе (stringify-equals).
		okBody:    `{"status":0,"description":"ok"}`,
		errStatus: http.StatusOK, errBody: `{"status":11,"description":"invalid key"}`,
	},
	{
		name: "prostor", creds: map[string]string{"login": "user", "password": "pass", "sender": "MySign"},
		wantMethod: http.MethodPost, wantPath: "/messages/v2/send.json",
		okBody:    `{"status":"ok"}`,
		errStatus: http.StatusOK, errBody: `{"status":"error"}`,
	},
	{
		name: "unisender", creds: map[string]string{"api_key": "KEY123", "sender": "MySign"},
		wantMethod: http.MethodGet, wantPath: "/ru/api/sendSms",
		wantQuery: map[string]string{"format": "json", "api_key": "KEY123", "phone": "+79161234567", "sender": "MySign", "text": "Ваш код подтверждения: 135790"},
		// unisender: в теле нет константного поля успеха; ошибки — 4xx.
		okBody: `{"result":{"sms_id":"123","phone":"+79161234567"}}`, errStatus: http.StatusBadRequest, errBody: `{"error":"authentication failed","code":"1"}`,
	},
	{
		name: "smsgateway24", creds: map[string]string{"token": "tok", "device_id": "42"},
		wantMethod: http.MethodGet, wantPath: "/getdata/addsms",
		wantQuery: map[string]string{"token": "tok", "sendto": "+79161234567", "body": "Ваш код подтверждения: 135790", "device_id": "42", "sim": "0", "urgent": "1"},
		// smsgateway24: $.error — ЧИСЛО 0 при успехе, ошибки приходят с HTTP 200!
		okBody:    `{"error":0,"sms_id":12345}`,
		errStatus: http.StatusOK, errBody: `{"error":2,"message":"bad token"}`,
	},
}

// TestPresetsRFRequests — сформированный пресетом запрос совпадает с
// ожиданием research-дока; правило успеха отличает успех от ошибки.
func TestPresetsRFRequests(t *testing.T) {
	for _, tc := range rfPresetCases {
		t.Run(tc.name, func(t *testing.T) {
			newCfg := func() GatewayConfig {
				cfg, ok := Preset(tc.name)
				if !ok {
					t.Fatalf("Preset(%q) вернул ok=false", tc.name)
				}
				if cfg.Headers == nil {
					cfg.Headers = make(map[string]string, len(tc.creds))
				}
				for k, v := range tc.creds {
					cfg.Headers[k] = v // креды пользователя поверх дефолтов
				}
				return cfg
			}

			// Фаза 1: форма запроса (сервер фиксирует его, отвечает успехом).
			capReq := &capturedReq{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capReq.method = r.Method
				capReq.path = r.URL.Path
				capReq.query = r.URL.Query()
				capReq.header = r.Header.Clone()
				b, _ := io.ReadAll(r.Body)
				capReq.body = string(b)
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, tc.okBody)
			}))
			defer srv.Close()
			cfg := newCfg()
			cfg.URL = strings.Replace(cfg.URL, "https://"+hostOf(tc.name), srv.URL, 1)
			if err := NewSMS(cfg, srv.Client()).Send(context.Background(), "+79161234567", "135790"); err != nil {
				t.Fatalf("Send (успешный ответ %q): %v", tc.okBody, err)
			}

			if capReq.method != tc.wantMethod {
				t.Errorf("метод = %s, want %s", capReq.method, tc.wantMethod)
			}
			if capReq.path != tc.wantPath {
				t.Errorf("путь = %s, want %s", capReq.path, tc.wantPath)
			}
			for param, want := range tc.wantQuery {
				if got := capReq.query.Get(param); got != want {
					t.Errorf("query[%s] = %q, want %q", param, got, want)
				}
			}
			for h, want := range tc.wantHeader {
				if got := capReq.header.Get(h); got != want {
					t.Errorf("header[%s] = %q, want %q", h, got, want)
				}
			}

			// Фаза 2: ответ ошибки должен отвергаться правилом успеха.
			errSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.errStatus)
				_, _ = io.WriteString(w, tc.errBody)
			}))
			defer errSrv.Close()
			cfg2 := newCfg()
			cfg2.URL = strings.Replace(cfg.URL, srv.URL, errSrv.URL, 1)
			if err := NewSMS(cfg2, errSrv.Client()).Send(context.Background(), "+79161234567", "135790"); err == nil {
				t.Fatalf("ошибочный ответ (HTTP %d, %q) принят за успех", tc.errStatus, tc.errBody)
			}
		})
	}
}

// hostOf — хост пресета по имени (для подмены базового URL на httptest).
func hostOf(name string) string {
	switch name {
	case "smsru":
		return "sms.ru"
	case "smsaero":
		return "gate.smsaero.ru"
	case "mainsms":
		return "mainsms.ru"
	case "bytehand":
		return "api.bytehand.com"
	case "prostor":
		return "api.prostor-sms.ru"
	case "unisender":
		return "api.unisender.com"
	case "smsgateway24":
		return "smsgateway24.com"
	case "smsc":
		return "smsc.ru"
	}
	return name
}

// TestPresetProstorJSONBody — тело prostor: валидный JSON с phone/sender/
// text в messages[0] и login/password на верхнем уровне; кавычки в кредах
// (sender) не ломают тело (JSON-экранирование).
func TestPresetProstorJSONBody(t *testing.T) {
	const weirdSender = `My "Sign" \ Inc`
	gotBody := make(chan string, 1)
	gotCT := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody <- string(b)
		gotCT <- r.Header.Get("Content-Type")
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	}))
	defer srv.Close()

	cfg, ok := Preset("prostor")
	if !ok {
		t.Fatal("Preset(\"prostor\") вернул ok=false")
	}
	cfg.URL = strings.Replace(cfg.URL, "https://api.prostor-sms.ru", srv.URL, 1)
	cfg.Headers = map[string]string{"login": "user", "password": "pass", "sender": weirdSender}
	if err := NewSMS(cfg, srv.Client()).Send(context.Background(), "+79161234567", "246810"); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if ct := <-gotCT; ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var body struct {
		Messages []struct{ Phone, Sender, Text string } `json:"messages"`
		Login    string                                 `json:"login"`
		Password string                                 `json:"password"`
	}
	if err := json.Unmarshal([]byte(<-gotBody), &body); err != nil {
		t.Fatalf("тело prostor не валидный JSON: %v", err)
	}
	if len(body.Messages) != 1 {
		t.Fatalf("messages: ожидался 1 элемент, получено %d", len(body.Messages))
	}
	m := body.Messages[0]
	if m.Phone != "+79161234567" {
		t.Errorf("messages[0].phone = %q, want +79161234567", m.Phone)
	}
	if m.Sender != weirdSender {
		t.Errorf("messages[0].sender = %q, want %q (round-trip)", m.Sender, weirdSender)
	}
	if m.Text != "Ваш код подтверждения: 246810" {
		t.Errorf("messages[0].text = %q", m.Text)
	}
	if body.Login != "user" || body.Password != "pass" {
		t.Errorf("login/password = %q/%q, want user/pass", body.Login, body.Password)
	}
}

// TestPresetsList — Presets() отдаёт все 9 пресетов, отсортированные по
// имени, с метаданными для UI (заголовок и русское описание непусты,
// Config.Preset совпадает с Name).
func TestPresetsList(t *testing.T) {
	list := Presets()
	got := make([]string, len(list))
	for i, p := range list {
		got[i] = p.Name
		if p.Title == "" || p.Description == "" {
			t.Errorf("пресет %s: Title/Description пусты (нужны для UI)", p.Name)
		}
		if p.Config.Preset != p.Name {
			t.Errorf("пресет %s: Config.Preset = %q", p.Name, p.Config.Preset)
		}
	}
	if !slices.IsSorted(got) {
		t.Errorf("Presets() не отсортированы: %v", got)
	}
	for _, name := range []string{"smsc", "smsru", "smsaero", "mainsms", "bytehand", "prostor", "unisender", "smsgateway24", "twilio"} {
		if !slices.Contains(got, name) {
			t.Errorf("Presets(): нет пресета %q (есть %v)", name, got)
		}
	}
	if len(list) != 9 {
		t.Errorf("Presets(): %d пресетов, want 9 (%v)", len(list), got)
	}
}

// TestPresetConfigJSONRoundTrip — конфиг пресета маршалится в JSON в форме
// настроек sms.gateway (snake_case: preset/method/url/headers/body/
// content_type/success.http_status...) и читается обратно без потерь:
// UI подставляет этот JSON в textarea настроек.
func TestPresetConfigJSONRoundTrip(t *testing.T) {
	for _, p := range Presets() {
		t.Run(p.Name, func(t *testing.T) {
			b, err := json.Marshal(p.Config)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var m map[string]any
			if err := json.Unmarshal(b, &m); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			for _, key := range []string{"preset", "method", "url", "success"} {
				if _, ok := m[key]; !ok {
					t.Errorf("JSON %s: нет ключа %q (форма настроек sms.gateway)", b, key)
				}
			}
			var back GatewayConfig
			if err := json.Unmarshal(b, &back); err != nil {
				t.Fatalf("обратный unmarshal: %v", err)
			}
			if !reflect.DeepEqual(back, p.Config) {
				t.Errorf("round-trip: got %+v, want %+v", back, p.Config)
			}
		})
	}
}

// TestSMSTransportErrorRedacted (SEC-003): сетевая ошибка шлюза несёт полный
// URL (креды и текст SMS в query) — текст ошибки не должен их раскрывать;
// хост и метод остаются для диагностики.
func TestSMSTransportErrorRedacted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	host := strings.TrimPrefix(srv.URL, "http://")
	srv.Close()

	gw := GatewayConfig{
		Method: "GET",
		URL:    srv.URL + "/send?login={login}&psw={psw}&phones={phone}&mes={text}",
		Headers: map[string]string{
			"login": "SECRET-LOGIN",
			"psw":   "SECRET-PASSWORD",
		},
	}
	sender := NewSMS(gw, &http.Client{Timeout: 2 * time.Second})
	err := sender.Send(context.Background(), "+79990001122", "654321")
	if err == nil {
		t.Fatal("Send на закрытый шлюз не вернул ошибку")
	}
	msg := err.Error()
	for _, secret := range []string{"SECRET-LOGIN", "SECRET-PASSWORD", "+79990001122", "654321", "/send?"} {
		if strings.Contains(msg, secret) {
			t.Fatalf("ошибка раскрывает %q: %q", secret, msg)
		}
	}
	if !strings.Contains(msg, host) {
		t.Fatalf("ошибка не содержит хост для диагностики: %q (want %s)", msg, host)
	}
	if !strings.Contains(msg, "GET") {
		t.Fatalf("ошибка не содержит метод: %q", msg)
	}
}
