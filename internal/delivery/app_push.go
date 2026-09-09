// Package delivery: диспетчер push-подтверждений для клиентских приложений (Windows, Android, iOS).
package delivery

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// AppPushPrompt — структура оповещения о входящем запросе на авторизацию.
type AppPushPrompt struct {
	Type             string    `json:"type"` // challenge_prompt
	ChallengeID      uuid.UUID `json:"challenge_id"`
	Who              string    `json:"who"`
	IP               string    `json:"ip"`
	UA               string    `json:"ua"`
	Service          string    `json:"service"`
	NumberMatch      string    `json:"number_match"`
	ExpiresInSeconds int       `json:"expires_in_seconds"`
	Timestamp        time.Time `json:"timestamp"`
}

// AppHub управляет постоянными WebSocket и SSE соединениями авторизованных клиентских приложений.
type AppHub struct {
	mu         sync.RWMutex
	wsClients  map[uuid.UUID]map[*websocket.Conn]bool
	sseClients map[uuid.UUID]map[chan []byte]bool
	upgrader   websocket.Upgrader
}

// NewAppHub создает новый экземпляр брокера оповещений.
func NewAppHub() *AppHub {
	return &AppHub{
		wsClients:  make(map[uuid.UUID]map[*websocket.Conn]bool),
		sseClients: make(map[uuid.UUID]map[chan []byte]bool),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				// Разрешаем подключения от нативных десктопных и мобильных клиентов
				return true
			},
		},
	}
}

// Upgrader возвращает websocket.Upgrader с настроенными политиками.
func (h *AppHub) Upgrader() *websocket.Upgrader {
	return &h.upgrader
}

// RegisterWS регистрирует открытое WebSocket-соединение для пользователя.
func (h *AppHub) RegisterWS(userID uuid.UUID, conn *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.wsClients[userID] == nil {
		h.wsClients[userID] = make(map[*websocket.Conn]bool)
	}
	h.wsClients[userID][conn] = true
	slog.Debug("app_push: зарегистрирован websocket клиент", "user_id", userID)
}

// UnregisterWS удаляет WebSocket-соединение.
func (h *AppHub) UnregisterWS(userID uuid.UUID, conn *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if conns, ok := h.wsClients[userID]; ok {
		delete(conns, conn)
		if len(conns) == 0 {
			delete(h.wsClients, userID)
		}
	}
	_ = conn.Close()
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

// BroadcastPrompt рассылает карточку запроса во все активные соединения пользователя.
func (h *AppHub) BroadcastPrompt(userID uuid.UUID, prompt *AppPushPrompt) int {
	data, err := json.Marshal(prompt)
	if err != nil {
		slog.Error("app_push: маршалинг prompt", "error", err)
		return 0
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	sentCount := 0

	// 1. Рассылка по WebSockets (Windows Desktop и активные мобильные приложения)
	if conns, ok := h.wsClients[userID]; ok {
		for conn := range conns {
			_ = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
			if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
				slog.Warn("app_push: ошибка записи в websocket", "error", err)
			} else {
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
	if expiresInSeconds <= 0 {
		expiresInSeconds = 60
	}
	prompt := &AppPushPrompt{
		Type:             "challenge_prompt",
		ChallengeID:      challengeID,
		Who:              who,
		IP:               ip,
		UA:               ua,
		Service:          service,
		NumberMatch:      numberMatch,
		ExpiresInSeconds: expiresInSeconds,
		Timestamp:        time.Now(),
	}

	delivered := h.BroadcastPrompt(userID, prompt)
	slog.Info("app_push: отправлен push-запрос",
		"user_id", userID, "who", who, "challenge_id", challengeID, "online_clients", delivered, "expires_in", expiresInSeconds)
	return nil
}
