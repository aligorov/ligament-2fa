package telegram

// fake_test.go — httptest-сервер, изображающий Telegram Bot API: очередь
// обновлений для getUpdates, захват исходящих запросов, инъекция 429/403.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// getUpdatesReq — разобранное тело getUpdates (для проверки offset/timeout/
// allowed_updates).
type getUpdatesReq struct {
	Offset         int64    `json:"offset"`
	Timeout        int      `json:"timeout"`
	AllowedUpdates []string `json:"allowed_updates"`
}

// fakeAPI — подделка Bot API.
type fakeAPI struct {
	t     *testing.T
	token string
	srv   *httptest.Server

	mu         sync.Mutex
	queue      []json.RawMessage // обновления на выдачу
	getReqs    []getUpdatesReq
	sent       []map[string]any // тела sendMessage
	answers    []map[string]any // тела answerCallbackQuery
	edits      []map[string]any // тела editMessageText
	failCode   int              // 0 = выдавать очередь; иначе error_code
	failOnce   bool             // сбросить failCode после первой ошибки
	retryAfter int              // parameters.retry_after для 429
	emptyWait  time.Duration    // пауза при пустой очереди (анти busy-loop)
}

// newFakeAPI поднимает сервер и регистрирует его закрытие.
func newFakeAPI(t *testing.T, token string) *fakeAPI {
	t.Helper()
	f := &fakeAPI{t: t, token: token, emptyWait: 15 * time.Millisecond}
	mux := http.NewServeMux()
	prefix := "/bot" + token + "/"
	mux.HandleFunc(prefix+"getUpdates", f.hGetUpdates)
	mux.HandleFunc(prefix+"sendMessage", f.hCapture(&f.sent))
	mux.HandleFunc(prefix+"answerCallbackQuery", f.hCapture(&f.answers))
	mux.HandleFunc(prefix+"editMessageText", f.hCapture(&f.edits))
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		f.writeError(w, http.StatusNotFound, 0, "unknown method")
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// pushUpdate добавляет обновление в очередь getUpdates (сырой JSON).
func (f *fakeAPI) pushUpdate(raw string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queue = append(f.queue, json.RawMessage(raw))
}

// setFail настраивает однократный/постоянный ошибочный ответ getUpdates.
func (f *fakeAPI) setFail(code, retryAfter int, once bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failCode, f.retryAfter, f.failOnce = code, retryAfter, once
}

// snapshot возвращает снимки захваченных данных (копии).
func (f *fakeAPI) snapshot() (getReqs []getUpdatesReq, sent, answers, edits []map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]getUpdatesReq{}, f.getReqs...),
		append([]map[string]any{}, f.sent...),
		append([]map[string]any{}, f.answers...),
		append([]map[string]any{}, f.edits...)
}

// hGetUpdates раздаёт очередь; при пустой очереди коротко ждёт, чтобы цикл
// бота не крутился вхолостую.
func (f *fakeAPI) hGetUpdates(w http.ResponseWriter, r *http.Request) {
	var req getUpdatesReq
	_ = json.NewDecoder(r.Body).Decode(&req)

	f.mu.Lock()
	f.getReqs = append(f.getReqs, req)
	if f.failCode != 0 {
		code, retryAfter, once := f.failCode, f.retryAfter, f.failOnce
		if once {
			f.failCode = 0
		}
		f.mu.Unlock()
		f.writeError(w, code, retryAfter, "injected error")
		return
	}
	take := f.queue
	if len(take) > 100 {
		take = take[:100]
	}
	f.queue = f.queue[len(take):]
	emptyWait := f.emptyWait
	f.mu.Unlock()

	if len(take) == 0 {
		time.Sleep(emptyWait)
	}
	f.writeResult(w, take)
}

// hCapture декодирует тело запроса в map и складывает в *dst.
func (f *fakeAPI) hCapture(dst *[]map[string]any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			f.t.Errorf("fake api: разбор тела %s: %v", r.URL.Path, err)
			f.writeError(w, http.StatusBadRequest, 0, "bad json")
			return
		}
		f.mu.Lock()
		*dst = append(*dst, body)
		f.mu.Unlock()
		f.writeResult(w, nil)
	}
}

func (f *fakeAPI) writeResult(w http.ResponseWriter, result any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": result})
}

func (f *fakeAPI) writeError(w http.ResponseWriter, code, retryAfter int, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	body := map[string]any{"ok": false, "error_code": code, "description": desc}
	if retryAfter > 0 {
		body["parameters"] = map[string]any{"retry_after": retryAfter}
	}
	_ = json.NewEncoder(w).Encode(body)
}

// waitFor опрашивает cond до 2 секунд; по истечении — t.Fatal.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("условие не наступило за 2с: %s", what)
}
