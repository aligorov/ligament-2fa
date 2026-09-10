// Rate-limit POST /oidc/token: token-корзины по IP и client_id (аудит
// раунд-2, N5 — эндпоинт не имел лимитов: онлайн-брут client_secret был
// неограничен). Компактная версия api.limiterMap: api импортирует oidc
// (роутер), поэтому общая карта в oidc недоступна без цикла импортов.
package oidc

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Параметры корзин: 1 запрос/с sustained с burst 30 — обмен кода редок
// (один вызов на вход пользователя), но несколько пользователей одного
// reverse-proxy/NAT и тестовые прогоны не должны трипаться на каждый чих.
const (
	tokenRLRate   = rate.Limit(1)
	tokenRLBurst  = 30
	tokenRLMaxKey = 100_000 // потолок корзин (client_id — вход атакующего)
	tokenRLIdle   = 15 * time.Minute
	tokenRLRetry  = 5 // Retry-After (сек) — время восстановления токена
)

// tokenBucket — корзина ключа и метка последнего обращения.
type tokenBucket struct {
	lim  *rate.Limiter
	seen time.Time
}

// tokenLimiter — карта token-корзин под мьютексом (без фоновой горутины:
// очистка простаивающих корзин запускается при достижении потолка ключей —
// токен-эндпоинт не настолько горячий, чтобы чистить по расписанию).
// Лениво инициализируется в Manager (тесты собирают Manager литералом).
type tokenLimiter struct {
	mu sync.Mutex
	m  map[string]*tokenBucket
}

// Allow пропускает запрос по корзине ключа; новая корзина создаётся
// заполненной (burst). Переполнение карты — fail-closed.
func (t *tokenLimiter) Allow(key string) bool {
	if t == nil {
		return true // лимитер не смонтирован (Manager, собранный литералом)
	}
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if b, ok := t.m[key]; ok {
		b.seen = now
		return b.lim.Allow()
	}
	if len(t.m) >= tokenRLMaxKey {
		for k, b := range t.m {
			if now.Sub(b.seen) > tokenRLIdle {
				delete(t.m, k)
			}
		}
		if len(t.m) >= tokenRLMaxKey {
			return false
		}
	}
	b := &tokenBucket{lim: rate.NewLimiter(tokenRLRate, tokenRLBurst), seen: now}
	if t.m == nil {
		t.m = make(map[string]*tokenBucket)
	}
	t.m[key] = b
	return b.lim.Allow()
}

// allowTokenRequest проверяет корзины IP и client_id запроса к
// /oidc/token; при исчерпании сам отвечает 429 (OAuth-код ошибки в теле,
// Retry-After — как у JSON API).
func (mgr *Manager) allowTokenRequest(w http.ResponseWriter, r *http.Request, clientID string) bool {
	mgr.rlOnce.Do(func() {
		mgr.rl = &tokenLimiter{m: make(map[string]*tokenBucket)}
	})
	ip := mgr.clientIP(r)
	if mgr.rl.Allow("ip:"+ip) && mgr.rl.Allow("cid:"+clientID) {
		return true
	}
	w.Header().Set("Retry-After", strconv.Itoa(tokenRLRetry))
	writeJSON(w, http.StatusTooManyRequests, map[string]any{
		"error":       "rate_limited",
		"retry_after": tokenRLRetry,
	})
	return false
}
