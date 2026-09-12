// Rate-limit публичного REST API: in-memory token-корзины по имени
// пользователя и по IP (спека §3.2: «не более ~10 start-запросов в
// минуту»; фактические параметры — burst 5, затем 0.2 токена/с ≈ 12/мин
// sustained, см. rlRate/rlBurst). Ключи изолированы: "u:"+username и
// "ip:"+ip — злоумышленник с одного IP не исчерпывает бюджет жертвы
// по имени и наоборот.
package api

import (
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// Параметры корзины: 0.2 токена/с (12/мин при непрерывном потоке) с
// burst 5 — «~10/мин» из спеки с запасом на пачку одновременных вкладок.
// rlRetryAfterSec — время восстановления одного токена (1/rate), им
// отвечаем в Retry-After при 429.
const (
	rlRate  = rate.Limit(0.2)
	rlBurst = 5
	// rlRetryAfterSec — секунд до появления нового токена (1/0.2).
	rlRetryAfterSec = 5
	// rlMaxKeys — защитный потолок числа корзин (защита от исчерпания
	// памяти спуфингом IP); при достижении запускается внеплановая
	// очистка, переполненная карта отказывает (fail-closed).
	rlMaxKeys = 100_000
	// rlCleanupEvery — период фоновой очистки простаивающих корзин.
	rlCleanupEvery = 5 * time.Minute
	// rlCleanupIdle — корзина без обращений дольше этого срока удаляется.
	rlCleanupIdle = 15 * time.Minute
)

// limiterEntry — корзина ключа и метка последнего обращения (atomic:
// обновляется в быстром пути без write-lock карты).
type limiterEntry struct {
	lim  *rate.Limiter
	seen atomic.Int64 // unix nano последнего Allow
}

// limiterMap — карта token-корзин с RWMutex: чтение существующей корзины
// без блокировки записи, создание — под lock с повторной проверкой.
// Фоновая горутина (newLimiterMap) удаляет простаивающие корзины, чтобы
// карта не росла неограниченно на итерациях IP-адресов.
type limiterMap struct {
	mu      sync.RWMutex
	entries map[string]*limiterEntry
	r       rate.Limit // параметры корзин этой карты
	b       int
	stop    chan struct{}
	done    chan struct{}
}

// newLimiterMap — карта с боевыми параметрами (0.2/s, burst 5) и
// запущенной фоновой очисткой. Освобождение — Stop.
func newLimiterMap() *limiterMap {
	return newLimiterMapParams(rlRate, rlBurst)
}

// newLimiterMapParams — карта с произвольными параметрами (тесты:
// быстрая скорость для детерминированной проверки восполнения).
func newLimiterMapParams(r rate.Limit, b int) *limiterMap {
	m := &limiterMap{
		entries: make(map[string]*limiterEntry),
		r:       r,
		b:       b,
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	go m.cleanupLoop()
	return m
}

// Allow пропускает запрос по корзине ключа; новая корзина создаётся
// заполненной (burst). Отказ — когда токены исчерпаны.
func (m *limiterMap) Allow(key string) bool {
	now := time.Now().UnixNano()

	m.mu.RLock()
	e, ok := m.entries[key]
	m.mu.RUnlock()
	if ok {
		e.seen.Store(now)
		return e.lim.Allow()
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	// Повторная проверка под write-lock: конкурентный запрос мог создать
	// корзину между RUnlock и Lock.
	if e, ok = m.entries[key]; ok {
		e.seen.Store(now)
		return e.lim.Allow()
	}
	if len(m.entries) >= rlMaxKeys {
		m.cleanup(time.Now())
		if len(m.entries) >= rlMaxKeys {
			return false // fail-closed: карта переполнена
		}
	}
	e = &limiterEntry{lim: rate.NewLimiter(m.r, m.b)}
	e.seen.Store(now)
	m.entries[key] = e
	return e.lim.Allow()
}

// Stop останавливает фоновую очистку и ждёт её завершения.
// Повторный вызов — no-op.
func (m *limiterMap) Stop() {
	select {
	case <-m.stop:
		return
	default:
		close(m.stop)
	}
	<-m.done
}

// cleanupLoop периодически удаляет простаивающие корзины.
func (m *limiterMap) cleanupLoop() {
	defer close(m.done)
	t := time.NewTicker(rlCleanupEvery)
	defer t.Stop()
	for {
		select {
		case <-m.stop:
			return
		case now := <-t.C:
			m.mu.Lock()
			m.cleanup(now)
			m.mu.Unlock()
		}
	}
}

// cleanup удаляет корзины без обращений дольше rlCleanupIdle
// (вызывается под write-lock; метка seen — atomic, гонок нет).
func (m *limiterMap) cleanup(now time.Time) {
	for k, e := range m.entries {
		if now.Sub(time.Unix(0, e.seen.Load())) > rlCleanupIdle {
			delete(m.entries, k)
		}
	}
}

// isStreamPath — известные WS/SSE-маршруты API (композиция роутера:
// app.Register — /api/v1/app/{ws,sse}; admin.Register — операторский WS
// поддержки /api/v1/support/ws/{id} и /api/v1/admin/support/sessions/{id}/ws).
// SSE-маршрутов вне /api/v1/app/sse в сервере нет.
func isStreamPath(path string) bool {
	switch {
	case path == "/api/v1/app/ws", path == "/api/v1/app/sse":
		return true
	case strings.HasPrefix(path, "/api/v1/support/ws/"):
		return true
	case strings.HasPrefix(path, "/api/v1/admin/support/sessions/") && strings.HasSuffix(path, "/ws"):
		return true
	default:
		return false
	}
}

// isStreamRequest сообщает, что запрос открывает потоковый канал
// (WebSocket-апгрейд или SSE): только для таких запросов легитимен токен
// в query-строке (?token= / ?admin_token=) — браузерный EventSource и
// браузерный WebSocket не умеют ставить заголовок Authorization. Для
// обычных JSON-запросов токен принимается исключительно из заголовка:
// query-строка оседает в логах прокси и истории браузера.
//
// Главный критерий — ПУТЬ запроса (аудит 2026-09-11: прежняя проверка
// «Upgrade != ""» пропускала JSON-запрос с подделанным заголовком
// «Upgrade: foo» к query-аутентификации). Заголовки — вторичный признак,
// причём только РЕАЛЬНОГО апгрейда: WebSocket требует ровно токен
// «websocket» (Connection/Sec-WebSocket-* валидирует апгрейдер), SSE —
// Accept: text/event-stream; это покрывает клиенты за прокси с
// переписанными путями, не выдавая произвольный «Upgrade: foo» за стрим.
func isStreamRequest(r *http.Request) bool {
	if isStreamPath(r.URL.Path) {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket") {
		return true
	}
	return strings.Contains(r.Header.Get("Accept"), "text/event-stream")
}
