package delivery

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

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
	user     string
	password string
}

// captureServer поднимает шлюз, который всегда отвечает 200 и фиксирует
// запрос (метод, путь, query, заголовки, basic-auth, form-тело).
func captureServer(t *testing.T) (*capturedReq, *httptest.Server) {
	t.Helper()
	captured := &capturedReq{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.method = r.Method
		captured.path = r.URL.Path
		captured.query = r.URL.Query()
		captured.header = r.Header.Clone()
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
	capReq, srv := captureServer(t)
	defer srv.Close()

	cfg.URL = strings.Replace(cfg.URL, "https://smsc.ru", srv.URL, 1)
	cfg.Headers = map[string]string{"login": "mylogin", "psw": "mypsw"}
	if err := NewSMS(cfg, srv.Client()).Send(context.Background(), "+79161234567", "424242"); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if capReq.method != http.MethodGet {
		t.Errorf("метод = %s, want GET", capReq.method)
	}
	if capReq.path != "/sys/send.php" {
		t.Errorf("путь = %s, want /sys/send.php", capReq.path)
	}
	for param, want := range map[string]string{
		"login":  "mylogin",
		"psw":    "mypsw",
		"phones": "+79161234567",
		"mes":    "Ваш код подтверждения: 424242",
	} {
		if got := capReq.query.Get(param); got != want {
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
