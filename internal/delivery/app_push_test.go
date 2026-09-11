package delivery

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// wsPair — живая пара websocket-соединений: server регистрируется в хабе,
// client читается тестом (направление сервер -> клиент).
type wsPair struct {
	server *websocket.Conn
	client *websocket.Conn
}

// newWSPair поднимает httptest-сервер с апгрейдом и дозванивается клиентом.
func newWSPair(t *testing.T) *wsPair {
	t.Helper()
	serverCh := make(chan *websocket.Conn, 1)
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		serverCh <- c
		// Держим серверную сторону открытой, входящие кадры игнорируем.
		go func() {
			for {
				if _, _, err := c.ReadMessage(); err != nil {
					return
				}
			}
		}()
	}))
	t.Cleanup(srv.Close)

	client, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	server := <-serverCh
	t.Cleanup(func() { _ = server.Close() })
	return &wsPair{server: server, client: client}
}

// drainConn считает прочитанные сервером сообщения до обрыва соединения.
func drainConn(c *websocket.Conn, counter *atomic.Int64) {
	for {
		if _, _, err := c.ReadMessage(); err != nil {
			return
		}
		counter.Add(1)
	}
}

func waitForCondition(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("условие не выполнено за отведённое время")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestHubConcurrentBroadcast: N горутин одновременно бьют в BroadcastPrompt /
// broadcastToUser / broadcastToAdmin по одному живому соединению; прогон под
// -race подтверждает отсутствие конкурентных WriteMessage в один conn
// (старый код паниковал "concurrent write to websocket connection").
//
// Учёт доставки по спецификации переполнения: при шторме, когда писатели
// коннектов не успевают разгребать очередь (ёмкость wsSendQueueSize), хаб
// обязан закрыть перегруженное соединение и снять его с реестра. Поэтому
// корректный исход для каждой стороны строго один из двух: либо всё
// поставленное в очередь доставлено, либо соединение тирдауннуто и убрано
// из реестра.
func TestHubConcurrentBroadcast(t *testing.T) {
	h := NewAppHub()
	userID := uuid.New()
	sessionID := uuid.New()

	up := newWSPair(t)
	ap := newWSPair(t)
	h.RegisterWS(userID, up.server)
	h.RegisterAdminWS(sessionID, ap.server)

	var gotUser, gotAdmin atomic.Int64
	go drainConn(up.client, &gotUser)
	go drainConn(ap.client, &gotAdmin)

	const workers = 8
	const iters = 50
	var wantUser, wantAdmin atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				switch n % 3 {
				case 0:
					wantUser.Add(int64(h.SendSupportSignal(userID, sessionID, map[string]any{"j": j})))
				case 1:
					wantAdmin.Add(int64(h.SendEventToAdmin(sessionID, "approved", nil)))
				case 2:
					// BroadcastPrompt того же юзера: sse-каналов нет, значит
					// счётчик = поставки ровно в тот же ws-канал.
					wantUser.Add(int64(h.BroadcastPrompt(userID, &AppPushPrompt{
						Type:        "challenge_prompt",
						ChallengeID: uuid.New(),
						Timestamp:   time.Now(),
					})))
				}
			}
		}(i)
	}
	wg.Wait()

	// Каждая сторона приходит к консистентному исходу: полная доставка
	// либо тирдаун с удалением из реестра (хаб не течёт и не теряет
	// зарегистрированные мёртвые коннекты).
	registryEmpty := func() bool {
		h.mu.RLock()
		defer h.mu.RUnlock()
		return len(h.wsClients) == 0 && len(h.adminConns) == 0
	}
	settled := func() bool {
		delivered := gotUser.Load() == wantUser.Load() && gotAdmin.Load() == wantAdmin.Load()
		return delivered || registryEmpty()
	}
	waitForCondition(t, 5*time.Second, settled)
	t.Logf("исход штурма: доставлено user %d/%d, admin %d/%d, реестры пусты: %v",
		gotUser.Load(), wantUser.Load(), gotAdmin.Load(), wantAdmin.Load(), registryEmpty())
	if gotUser.Load() == 0 && wantUser.Load() > 0 && !registryEmpty() {
		t.Fatal("живое соединение не получило ни одного сообщения и не снято с реестра")
	}

	// Явное снятие с реестра после шторма — идемпотентно в любом исходе.
	h.UnregisterWS(userID, up.server)
	h.UnregisterAdminWS(sessionID, ap.server)
	h.mu.RLock()
	wsLeft, adminLeft := len(h.wsClients), len(h.adminConns)
	h.mu.RUnlock()
	if wsLeft != 0 || adminLeft != 0 {
		t.Fatalf("реестры не пусты после Unregister: ws=%d admin=%d", wsLeft, adminLeft)
	}
}

// TestHubConcurrentBroadcastNoLoss: при умеренном темпе рассылки (writer
// успевает разгребать очередь) каждое принятое в очередь сообщение обязано
// доехать до клиента — потерь быть не должно.
func TestHubConcurrentBroadcastNoLoss(t *testing.T) {
	h := NewAppHub()
	userID := uuid.New()
	sessionID := uuid.New()

	up := newWSPair(t)
	ap := newWSPair(t)
	h.RegisterWS(userID, up.server)
	h.RegisterAdminWS(sessionID, ap.server)

	var gotUser, gotAdmin atomic.Int64
	go drainConn(up.client, &gotUser)
	go drainConn(ap.client, &gotAdmin)

	const workers = 4
	const iters = 25
	var wantUser, wantAdmin atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				if n%2 == 0 {
					wantUser.Add(int64(h.SendSupportSignal(userID, sessionID, map[string]any{"j": j})))
				} else {
					wantAdmin.Add(int64(h.SendEventToAdmin(sessionID, "approved", nil)))
				}
				time.Sleep(2 * time.Millisecond) // темп ниже пропускной способности writer-а
			}
		}(i)
	}
	wg.Wait()

	waitForCondition(t, 5*time.Second, func() bool {
		return gotUser.Load() == wantUser.Load() && gotAdmin.Load() == wantAdmin.Load()
	})
	t.Logf("без потерь: user %d/%d, admin %d/%d",
		gotUser.Load(), wantUser.Load(), gotAdmin.Load(), wantAdmin.Load())
}

// TestHubOverflowClosesConn: переполнение буфера отправки закрывает соединение
// и снимает его с реестра без явного Unregister.
func TestHubOverflowClosesConn(t *testing.T) {
	h := NewAppHub()
	userID := uuid.New()
	p := newWSPair(t)

	// Кладём соединение в реестр без запуска writer-горутины — очередь
	// гарантированно не разгружается, переполнение детерминировано.
	c := newWSClient(p.server, func() { h.UnregisterWS(userID, p.server) })
	h.mu.Lock()
	h.wsClients[userID] = map[*websocket.Conn]*wsClient{p.server: c}
	h.mu.Unlock()

	data := []byte(`{"overflow":true}`)
	for i := 0; i < wsSendQueueSize; i++ {
		if !tryEnqueue(c, data) {
			t.Fatalf("сообщение %d не должно переполнять буфер (ёмкость %d)", i, wsSendQueueSize)
		}
	}
	if tryEnqueue(c, data) {
		t.Fatal("переполнение буфера должно отвергать сообщение и закрывать соединение")
	}

	// Мёртвое соединение само покидает реестр (async unregister из enqueue).
	waitForCondition(t, 3*time.Second, func() bool {
		h.mu.RLock()
		defer h.mu.RUnlock()
		return len(h.wsClients[userID]) == 0
	})
	// Клиентская сторона видит обрыв.
	_ = p.client.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, err := p.client.ReadMessage(); err == nil {
		t.Fatal("ожидали обрыв соединения после переполнения буфера")
	}
	// Повторная постановка после снятия с реестра — соединения больше нет в хабе.
	if got := h.broadcastToUser(userID, data); got != 0 {
		t.Fatalf("broadcastToUser после снятия = %d, want 0", got)
	}
}

// TestHubWriterErrorUnregistersDeadConn: обрыв клиента -> ошибка записи в
// writer-горутине -> соединение покидает реестр (нет накопления мёртвых).
func TestHubWriterErrorUnregistersDeadConn(t *testing.T) {
	h := NewAppHub()
	userID := uuid.New()
	p := newWSPair(t)
	h.RegisterWS(userID, p.server)

	// Обрываем клиентскую сторону: следующая запись в writer-горутине упадёт.
	_ = p.client.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_ = h.SendSupportSignal(userID, uuid.New(), map[string]any{"x": 1})
		h.mu.RLock()
		empty := len(h.wsClients) == 0
		h.mu.RUnlock()
		if empty {
			return // мёртвое соединение снято с реестра без явного Unregister
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("мёртвое соединение не покинуло реестр после ошибки записи")
}

// TestBroadcastPromptDelivers: сообщение доходит и по ws, и по sse.
func TestBroadcastPromptDelivers(t *testing.T) {
	h := NewAppHub()
	userID := uuid.New()
	p := newWSPair(t)
	h.RegisterWS(userID, p.server)
	sse := h.RegisterSSE(userID)

	prompt := &AppPushPrompt{
		Type:        "challenge_prompt",
		ChallengeID: uuid.New(),
		Who:         "u",
		Timestamp:   time.Now(),
	}
	if got := h.BroadcastPrompt(userID, prompt); got != 2 {
		t.Fatalf("BroadcastPrompt = %d, want 2 (ws + sse)", got)
	}

	_ = p.client.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, data, err := p.client.ReadMessage()
	if err != nil {
		t.Fatalf("чтение из websocket: %v", err)
	}
	var parsed AppPushPrompt
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("разбор prompt: %v", err)
	}
	if parsed.ChallengeID != prompt.ChallengeID {
		t.Errorf("challenge_id = %s, want %s", parsed.ChallengeID, prompt.ChallengeID)
	}

	select {
	case b := <-sse:
		if !strings.Contains(string(b), "challenge_prompt") {
			t.Errorf("sse payload: %s", b)
		}
	default:
		t.Error("sse канал не получил prompt")
	}
	h.UnregisterSSE(userID, sse)
}

// TestSendAppPushCounted: счёт живых получателей фан-аута app-push —
// 0 при отсутствии соединений (pending-список остаётся фолбэком),
// ws+sse при подключенных, SendAppPush всегда возвращает nil.
func TestSendAppPushCounted(t *testing.T) {
	h := NewAppHub()
	userID := uuid.New()

	// 1) Ни одного соединения: доставки нет, но ошибки тоже — челлендж
	// останется доступен приложению через pending-список.
	got, err := h.SendAppPushCounted(context.Background(), userID, "u", "10.0.0.1", "ua", "Wi-Fi", "", uuid.New(), 60)
	if err != nil {
		t.Fatalf("SendAppPushCounted без клиентов: %v", err)
	}
	if got != 0 {
		t.Fatalf("SendAppPushCounted без клиентов = %d, want 0", got)
	}
	if err := h.SendAppPush(context.Background(), userID, "u", "10.0.0.1", "ua", "Wi-Fi", "", uuid.New(), 60); err != nil {
		t.Fatalf("SendAppPush без клиентов: %v", err)
	}

	// 2) ws + sse: счёт по обоим транспортам.
	p := newWSPair(t)
	h.RegisterWS(userID, p.server)
	sse := h.RegisterSSE(userID)
	defer h.UnregisterSSE(userID, sse)

	chalID := uuid.New()
	got, err = h.SendAppPushCounted(context.Background(), userID, "u", "10.0.0.1", "ua", "Wi-Fi", "", chalID, 90)
	if err != nil {
		t.Fatalf("SendAppPushCounted: %v", err)
	}
	if got != 2 {
		t.Fatalf("SendAppPushCounted = %d, want 2 (ws + sse)", got)
	}

	// Payload доходит по ws и содержит параметры prompt.
	_ = p.client.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, data, err := p.client.ReadMessage()
	if err != nil {
		t.Fatalf("чтение из websocket: %v", err)
	}
	var parsed AppPushPrompt
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("разбор prompt: %v", err)
	}
	if parsed.ChallengeID != chalID || parsed.Who != "u" || parsed.IP != "10.0.0.1" || parsed.Service != "Wi-Fi" {
		t.Errorf("prompt = %+v (challenge=%s who=%q ip=%q service=%q)", parsed, chalID, parsed.Who, parsed.IP, parsed.Service)
	}

	select {
	case b := <-sse:
		if !strings.Contains(string(b), chalID.String()) {
			t.Errorf("sse payload без challenge_id: %s", b)
		}
	default:
		t.Error("sse канал не получил prompt")
	}
}

// TestCheckOriginPolicy: без Origin — пропуск (нативные клиенты), при
// наличии — строго same-origin.
func TestCheckOriginPolicy(t *testing.T) {
	check := NewAppHub().Upgrader().CheckOrigin
	cases := []struct {
		name   string
		host   string
		origin string
		want   bool
	}{
		{"нет origin — нативный клиент", "api.example.com", "", true},
		{"same-origin", "console.example.com", "https://console.example.com", true},
		{"same-origin с портом", "localhost:8080", "http://localhost:8080", true},
		{"порт по умолчанию опущен", "example.com:443", "https://example.com", true},
		{"чужой origin", "console.example.com", "https://evil.example.net", false},
		{"чужой порт", "localhost:8080", "http://localhost:9999", false},
		{"чужой субдомен", "console.example.com", "https://evil.example.com", false},
		{"битый origin", "console.example.com", "http://[::1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := http.NewRequest(http.MethodGet, "http://"+tc.host+"/ws", nil)
			if err != nil {
				t.Fatal(err)
			}
			r.Host = tc.host
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			if got := check(r); got != tc.want {
				t.Errorf("CheckOrigin(host=%q, origin=%q) = %v, want %v", tc.host, tc.origin, got, tc.want)
			}
		})
	}
}

// TestUpgraderOriginEndToEnd: политика происхождения на реальном апгрейде —
// без Origin и same-origin проходят, чужой Origin получает 403.
func TestUpgraderOriginEndToEnd(t *testing.T) {
	up := NewAppHub().Upgrader()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		_ = c.Close()
	}))
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	// Нативный клиент без Origin — апгрейд проходит.
	if c, _, err := websocket.DefaultDialer.Dial(wsURL, nil); err != nil {
		t.Fatalf("dial без Origin должен проходить: %v", err)
	} else {
		_ = c.Close()
	}

	// Браузер same-origin (Origin = http://<host>:<port> сервера) — проходит.
	if c, _, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Origin": []string{srv.URL}}); err != nil {
		t.Fatalf("dial same-origin должен проходить: %v", err)
	} else {
		_ = c.Close()
	}

	// Чужой Origin — отказ на апгрейде (403).
	if c, resp, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Origin": []string{"https://evil.example.net"}}); err == nil {
		_ = c.Close()
		t.Fatal("dial с чужим Origin должен быть отвергнут")
	} else if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("ожидали 403, получено: resp=%v err=%v", resp, err)
	}
}
