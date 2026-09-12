// Package delivery: диспетчер push-подтверждений для клиентских приложений (Windows, Android, iOS).
package delivery

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

const (
	// wsSendQueueSize — ёмкость исходящего буфера одного соединения.
	wsSendQueueSize = 16
	// wsWriteTimeout — дедлайн на запись одного кадра в writer-горутине.
	wsWriteTimeout = 3 * time.Second
)

// AppPushPrompt — структура оповещения о входящем запросе на авторизацию.
type AppPushPrompt struct {
	Type             string    `json:"type"` // challenge_prompt
	ChallengeID      uuid.UUID `json:"challenge_id"`
	Who              string    `json:"who"`
	IP               string    `json:"ip"`
	ClientIP         string    `json:"client_ip,omitempty"`
	HostIP           string    `json:"host_ip,omitempty"`
	Host             string    `json:"host,omitempty"`
	UA               string    `json:"ua"`
	Device           string    `json:"device,omitempty"`
	Service          string    `json:"service"`
	NumberMatch      string    `json:"number_match"`
	ExpiresInSeconds int       `json:"expires_in_seconds"`
	Timestamp        time.Time `json:"timestamp"`
}

// wsClient — обёртка WebSocket-соединения с выделенной горутиной-писателем.
//
// gorilla/websocket допускает ровно ОДНОГО конкурентного писателя на соединение:
// параллельный вызов WriteMessage/SetWriteDeadline детонирует панику
// "concurrent write to websocket connection" (conn.go), а после первой паники
// флаг isWriting залипает и паникует каждый следующий писатель. Поэтому все
// исходящие data-кадры ставятся в канал send и пишутся единственной
// горутиной serveWSWriter. Рассылка в хабе никогда не пишет в conn напрямую
// и не блокируется на медленных клиентах.
type wsClient struct {
	conn       *websocket.Conn
	send       chan []byte
	done       chan struct{}
	closeOnce  sync.Once
	unregister func() // асинхронное снятие соединения с реестра хаба
}

func newWSClient(conn *websocket.Conn, unregister func()) *wsClient {
	// Отключаем алгоритм Нагла на серверной стороне: push-кадры маленькие,
	// и связка Nagle с отложенными ACK TCP на мелких сегментах способна
	// задерживать доставку на сотни миллисекунд (замечено на macOS-хостах),
	// при том что запись через WriteMessage ошибок не возвращает.
	if tcp, ok := conn.NetConn().(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
	return &wsClient{
		conn:       conn,
		send:       make(chan []byte, wsSendQueueSize),
		done:       make(chan struct{}),
		unregister: unregister,
	}
}

// shutdown закрывает соединение и останавливает writer-горутину; безопасен
// для повторного и конкурентного вызова (Close в gorilla разрешён параллельно
// с любыми методами).
func (c *wsClient) shutdown() {
	c.closeOnce.Do(func() {
		close(c.done)
		_ = c.conn.Close()
	})
}

// serveWSWriter — единственный писатель data-кадров соединения: читает канал
// send, ставит дедлайн и пишет в conn. Ошибка записи = соединение мертво:
// writer останавливается, conn закрывается, соединение асинхронно снимается
// с реестра хаба. Вызов unregister именно через go обязателен: постановка в
// очередь выполняется под RLock хаба, а Unregister* берёт write-lock, поэтому
// синхронный вызов из writer-горутины при живом RLock — дедлок.
//
// Контрольные кадры (Pong из read-loop в internal/api) сюда НЕ заведены и в
// этом нет нужды: gorilla/websocket явно документирует (doc.go, раздел
// Concurrency): "The Close and WriteControl methods can be called concurrently
// with all other methods" — в отличие от WriteMessage/SetWriteDeadline.
// Read-loop отвечает на Ping напрямую через Conn.WriteControl, что безопасно
// параллельно с WriteMessage этой горутины.
func serveWSWriter(c *wsClient) {
	for {
		select {
		case <-c.done:
			return
		case msg := <-c.send:
			_ = c.conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
			if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				slog.Debug("app_push: writer остановлен, соединение потеряно", "error", err)
				c.shutdown()
				go c.unregister()
				return
			}
		}
	}
}

// tryEnqueue ставит сообщение в очередь writer-горутины строго без блокировки:
// переполнение буфера означает медленного/мёртвого клиента — соединение
// закрывается и асинхронно снимается с реестра (go — см. комментарий к
// serveWSWriter), а рассылка продолжает двигаться дальше, не удерживая
// блокировку хаба дольше необходимого.
func tryEnqueue(c *wsClient, msg []byte) bool {
	select {
	case c.send <- msg:
		return true
	default:
		slog.Warn("app_push: буфер отправки переполнен, соединение закрывается")
		c.shutdown()
		go c.unregister()
		return false
	}
}

// AppHub управляет постоянными WebSocket и SSE соединениями авторизованных клиентских приложений и веб-консолей.
type AppHub struct {
	mu         sync.RWMutex
	wsClients  map[uuid.UUID]map[*websocket.Conn]*wsClient
	sseClients map[uuid.UUID]map[chan []byte]bool
	adminConns map[uuid.UUID]map[*websocket.Conn]*wsClient // session_id -> websocket connections
	upgrader   websocket.Upgrader
}

// checkWSOrigin — политика происхождения WebSocket-апгрейда:
//   - заголовка Origin нет — разрешаем (нативные десктопные и мобильные
//     клиенты, включая Flutter, Origin не отправляют);
//   - Origin есть (браузер) — требуется совпадение host-части Origin с r.Host
//     (same-origin для веб-консоли), иначе апгрейд отвергается с 403.
func checkWSOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return normalizeWSHost(u.Host) == normalizeWSHost(r.Host)
}

// normalizeWSHost приводит host[:port] к каноническому виду: имя хоста в
// нижнем регистре, опущенные порты по умолчанию (80/443) не различаются
// с явно указанными.
func normalizeWSHost(hostport string) string {
	h, p, err := net.SplitHostPort(hostport)
	if err != nil {
		return strings.ToLower(hostport)
	}
	if p == "80" || p == "443" {
		return strings.ToLower(h)
	}
	return strings.ToLower(h) + ":" + p
}

// NewAppHub создает новый экземпляр брокера оповещений.
func NewAppHub() *AppHub {
	return &AppHub{
		wsClients:  make(map[uuid.UUID]map[*websocket.Conn]*wsClient),
		sseClients: make(map[uuid.UUID]map[chan []byte]bool),
		adminConns: make(map[uuid.UUID]map[*websocket.Conn]*wsClient),
		upgrader: websocket.Upgrader{
			CheckOrigin: checkWSOrigin,
		},
	}
}

// Upgrader возвращает websocket.Upgrader с настроенными политиками.
func (h *AppHub) Upgrader() *websocket.Upgrader {
	return &h.upgrader
}

// RegisterWS регистрирует открытое WebSocket-соединение для пользователя
// и запускает его выделенную writer-горутину.
func (h *AppHub) RegisterWS(userID uuid.UUID, conn *websocket.Conn) {
	c := newWSClient(conn, func() { h.UnregisterWS(userID, conn) })
	h.mu.Lock()
	if _, exists := h.wsClients[userID][conn]; exists {
		// Повторная регистрация того же conn — идемпотентность.
		h.mu.Unlock()
		return
	}
	if h.wsClients[userID] == nil {
		h.wsClients[userID] = make(map[*websocket.Conn]*wsClient)
	}
	h.wsClients[userID][conn] = c
	h.mu.Unlock()
	go serveWSWriter(c)
	slog.Debug("app_push: зарегистрирован websocket клиент", "user_id", userID)
}

// UnregisterWS удаляет WebSocket-соединение и останавливает его writer-горутину.
func (h *AppHub) UnregisterWS(userID uuid.UUID, conn *websocket.Conn) {
	h.mu.Lock()
	c := h.wsClients[userID][conn]
	if c != nil {
		delete(h.wsClients[userID], conn)
		if len(h.wsClients[userID]) == 0 {
			delete(h.wsClients, userID)
		}
	}
	h.mu.Unlock()
	if c != nil {
		c.shutdown()
	} else {
		_ = conn.Close()
	}
	slog.Debug("app_push: отключен websocket клиент", "user_id", userID)
}

// RegisterSSE регистрирует новый канал для Server-Sent Events.
func (h *AppHub) RegisterSSE(userID uuid.UUID) chan []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	ch := make(chan []byte, 16)
	if h.sseClients[userID] == nil {
		h.sseClients[userID] = make(map[chan []byte]bool)
	}
	h.sseClients[userID][ch] = true
	slog.Debug("app_push: зарегистрирован sse клиент", "user_id", userID)
	return ch
}

// UnregisterSSE удаляет SSE канал.
func (h *AppHub) UnregisterSSE(userID uuid.UUID, ch chan []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if channels, ok := h.sseClients[userID]; ok {
		delete(channels, ch)
		if len(channels) == 0 {
			delete(h.sseClients, userID)
		}
	}
	close(ch)
	slog.Debug("app_push: отключен sse клиент", "user_id", userID)
}

// BroadcastPrompt рассылает карточку запроса во все активные соединения
// пользователя. Возвращает число соединений, в очередь которых сообщение
// принято (доставка асинхронная, выполняется writer-горутинами).
func (h *AppHub) BroadcastPrompt(userID uuid.UUID, prompt *AppPushPrompt) int {
	data, err := json.Marshal(prompt)
	if err != nil {
		slog.Error("app_push: маршалинг prompt", "error", err)
		return 0
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	sentCount := 0

	// 1. Рассылка по WebSockets (Windows Desktop и активные мобильные
	// приложения): неблокирующаяся постановка в очередь writer-горутины,
	// мёртвые/медленные соединения закрываются и снимаются с реестра самим
	// enqueue, RLock хаба не удерживается дольше итерации по карте.
	if conns, ok := h.wsClients[userID]; ok {
		for _, c := range conns {
			if tryEnqueue(c, data) {
				sentCount++
			}
		}
	}

	// 2. Рассылка по SSE
	if channels, ok := h.sseClients[userID]; ok {
		for ch := range channels {
			select {
			case ch <- data:
				sentCount++
			default:
				slog.Warn("app_push: буфер sse переполнен")
			}
		}
	}

	return sentCount
}

// SendAppPush отправляет запрос на авторизацию в приложение пользователя.
func (h *AppHub) SendAppPush(ctx context.Context, userID uuid.UUID, who, ip, ua, service, numberMatch string, challengeID uuid.UUID, expiresInSeconds int) error {
	_, err := h.SendAppPushCounted(ctx, userID, who, ip, ua, service, numberMatch, challengeID, expiresInSeconds)
	return err
}

// SendAppPushWithMeta отправляет запрос на авторизацию в приложение пользователя с расширенными метаданными («Куда, Где, Чем»).
func (h *AppHub) SendAppPushWithMeta(ctx context.Context, userID uuid.UUID, who, ip, clientIP, hostIP, host, ua, device, service, numberMatch string, challengeID uuid.UUID, expiresInSeconds int) (int, error) {
	if expiresInSeconds <= 0 {
		expiresInSeconds = 60
	}
	prompt := &AppPushPrompt{
		Type:             "challenge_prompt",
		ChallengeID:      challengeID,
		Who:              who,
		IP:               ip,
		ClientIP:         clientIP,
		HostIP:           hostIP,
		Host:             host,
		UA:               ua,
		Device:           device,
		Service:          service,
		NumberMatch:      numberMatch,
		ExpiresInSeconds: expiresInSeconds,
		Timestamp:        time.Now(),
	}

	delivered := h.BroadcastPrompt(userID, prompt)
	slog.Info("app_push: отправлен push-запрос",
		"user_id", userID, "who", who, "challenge_id", challengeID, "online_clients", delivered, "expires_in", expiresInSeconds,
		"service", service, "client_ip", clientIP, "host_ip", hostIP)
	return delivered, nil
}

// SendAppPushCounted — SendAppPush с возвратом числа соединений, принявших
// prompt в очередь (WebSocket writer-горутины + SSE-каналы). 0 — живых
// клиентов нет: мгновенной доставки не произошло, челлендж остаётся
// доступным приложению через pending-список (/api/v1/app/challenges/pending,
// polling-фолбэк клиента). Ошибки не возвращает: рассылка полностью
// асинхронна (per-conn writer), BroadcastPrompt не блокируется на клиентах.
func (h *AppHub) SendAppPushCounted(ctx context.Context, userID uuid.UUID, who, ip, ua, service, numberMatch string, challengeID uuid.UUID, expiresInSeconds int) (int, error) {
	return h.SendAppPushWithMeta(ctx, userID, who, ip, "", "", "", ua, "", service, numberMatch, challengeID, expiresInSeconds)
}

// SupportPushPrompt — структура оповещения о запросе на удаленное подключение от инженера.
type SupportPushPrompt struct {
	Type           string    `json:"type"` // "support_prompt"
	SessionID      uuid.UUID `json:"session_id"`
	AdminName      string    `json:"admin_name"`
	Category       string    `json:"category"`
	NumberMatch    string    `json:"number_match"`
	AccessMode     string    `json:"access_mode"`
	ProblemSummary string    `json:"problem_summary"`
	Timestamp      time.Time `json:"timestamp"`
}

// RegisterAdminWS регистрирует WebSocket-соединение веб-консоли оператора для
// данной сессии и запускает его выделенную writer-горутину.
func (h *AppHub) RegisterAdminWS(sessionID uuid.UUID, conn *websocket.Conn) {
	c := newWSClient(conn, func() { h.UnregisterAdminWS(sessionID, conn) })
	h.mu.Lock()
	if _, exists := h.adminConns[sessionID][conn]; exists {
		h.mu.Unlock()
		return
	}
	if h.adminConns[sessionID] == nil {
		h.adminConns[sessionID] = make(map[*websocket.Conn]*wsClient)
	}
	h.adminConns[sessionID][conn] = c
	h.mu.Unlock()
	go serveWSWriter(c)
	slog.Debug("app_push: зарегистрирована веб-консоль оператора", "session_id", sessionID)
}

// UnregisterAdminWS удаляет WebSocket-соединение веб-консоли оператора
// и останавливает его writer-горутину.
func (h *AppHub) UnregisterAdminWS(sessionID uuid.UUID, conn *websocket.Conn) {
	h.mu.Lock()
	c := h.adminConns[sessionID][conn]
	if c != nil {
		delete(h.adminConns[sessionID], conn)
		if len(h.adminConns[sessionID]) == 0 {
			delete(h.adminConns, sessionID)
		}
	}
	h.mu.Unlock()
	if c != nil {
		c.shutdown()
	} else {
		_ = conn.Close()
	}
	slog.Debug("app_push: отключена веб-консоль оператора", "session_id", sessionID)
}

// SendSupportPrompt отправляет 2FA-челлендж на подключение инженера в приложение пользователя.
func (h *AppHub) SendSupportPrompt(userID uuid.UUID, prompt *SupportPushPrompt) int {
	data, err := json.Marshal(prompt)
	if err != nil {
		slog.Error("app_push: маршалинг support_prompt", "error", err)
		return 0
	}
	return h.broadcastToUser(userID, data)
}

// SendSupportSignal отправляет сигнальное WebRTC-сообщение (SDP Offer/Answer/ICE) на клиент пользователя.
func (h *AppHub) SendSupportSignal(userID uuid.UUID, sessionID uuid.UUID, data map[string]any) int {
	payload := map[string]any{
		"type":       "support_signal",
		"session_id": sessionID,
		"data":       data,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return 0
	}
	return h.broadcastToUser(userID, b)
}

// SendSupportTransferred оповещает пользователя на клиенте о передаче сеанса новому специалисту.
func (h *AppHub) SendSupportTransferred(userID uuid.UUID, sessionID uuid.UUID, newAdminName, category string) int {
	payload := map[string]any{
		"type":           "support_transferred",
		"session_id":     sessionID,
		"new_admin_name": newAdminName,
		"category":       category,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return 0
	}
	return h.broadcastToUser(userID, b)
}

// SendSupportEnd оповещает клиента о завершении сеанса поддержки.
func (h *AppHub) SendSupportEnd(userID uuid.UUID, sessionID uuid.UUID) int {
	payload := map[string]any{
		"type":       "support_ended",
		"session_id": sessionID,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return 0
	}
	return h.broadcastToUser(userID, b)
}

// BroadcastSupportRequest оповещает подключенных инженеров о новом SOS-запросе.
func (h *AppHub) BroadcastSupportRequest(userIDs []uuid.UUID, session any) int {
	payload := map[string]any{
		"type":    "support_incoming_request",
		"session": session,
	}
	if b, err := json.Marshal(session); err == nil {
		var m map[string]any
		if err := json.Unmarshal(b, &m); err == nil {
			for k, v := range m {
				if k != "type" {
					payload[k] = v
				}
			}
			if sid, ok := m["id"]; ok && payload["session_id"] == nil {
				payload["session_id"] = sid
			}
		}
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return 0
	}
	count := 0
	for _, uid := range userIDs {
		count += h.broadcastToUser(uid, b)
	}
	return count
}

// SendSignalToAdmin пересылает WebRTC SDP/ICE от клиента в браузерную консоль оператора.
func (h *AppHub) SendSignalToAdmin(sessionID uuid.UUID, data map[string]any) int {
	payload := map[string]any{
		"type":       "webrtc_signal",
		"session_id": sessionID,
		"data":       data,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return 0
	}
	return h.broadcastToAdmin(sessionID, b)
}

// SendEventToAdmin отправляет статусное событие (approved, denied, ended) в браузерную консоль оператора.
func (h *AppHub) SendEventToAdmin(sessionID uuid.UUID, eventType string, extra map[string]any) int {
	payload := map[string]any{
		"type":       eventType,
		"session_id": sessionID,
	}
	for k, v := range extra {
		payload[k] = v
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return 0
	}
	return h.broadcastToAdmin(sessionID, b)
}

func (h *AppHub) broadcastToUser(userID uuid.UUID, data []byte) int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	count := 0
	if conns, ok := h.wsClients[userID]; ok {
		for _, c := range conns {
			if tryEnqueue(c, data) {
				count++
			}
		}
	}
	return count
}

func (h *AppHub) broadcastToAdmin(sessionID uuid.UUID, data []byte) int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	count := 0
	if conns, ok := h.adminConns[sessionID]; ok {
		for _, c := range conns {
			if tryEnqueue(c, data) {
				count++
			}
		}
	}
	return count
}

// SendSupportChatMessage рассылает сообщение чата обеим сторонам (пользователю и всем консолям оператора).
func (h *AppHub) SendSupportChatMessage(sessionID uuid.UUID, userID uuid.UUID, msg any) {
	chatPayload := map[string]any{
		"type":       "chat_message",
		"session_id": sessionID.String(),
	}
	if b, err := json.Marshal(msg); err == nil {
		var m map[string]any
		if err := json.Unmarshal(b, &m); err == nil {
			for k, v := range m {
				chatPayload[k] = v
			}
		}
	}
	chatPayload["type"] = "chat_message"
	chatPayload["session_id"] = sessionID.String()

	// 1. Доставка операторам (консоли админа по sessionID)
	adminPayload := map[string]any{
		"type":       "chat_message",
		"session_id": sessionID,
		"data":       chatPayload,
	}
	for k, v := range chatPayload {
		adminPayload[k] = v
	}
	if b, err := json.Marshal(adminPayload); err == nil {
		h.broadcastToAdmin(sessionID, b)
	}

	// 2. Доставка клиенту пользователя (через постоянный сокет /api/v1/app/ws)
	userPayload := map[string]any{
		"type":       "support_signal",
		"session_id": sessionID,
		"data":       chatPayload,
	}
	if b, err := json.Marshal(userPayload); err == nil {
		h.broadcastToUser(userID, b)
	}
}
