// Per-NAS rate limit (token bucket) — первый гейт обработки RADIUS-пакетов,
// ДО любой тяжёлой работы (расшифровка PAP, БД, argon2 в BurnDummyVerify —
// 64 MiB памяти на пакет): неаутентифицированный флуд с одного источника не
// должен доходить до ядра аутентификации (анти-DoS, АГЕНТ 5 аудита).
// Превышение — молчаливый drop + счётчик (не аудит-шторм: аудит пишется
// volume-ом самого трафика и сам стал бы вектором исчерпания БД).
package radiusserver

import (
	"sync"
	"time"
)

// Параметры bucket-а. Скорость — из настроек (radius.rate_limit_pps,
// дефолт 20); burst — двойная скорость (дефолт 40): обычный NAS с
// ретрансмитами и EAP-фрагментами укладывается, флуд — нет.
const (
	rateBurstMult = 2
	// rateBucketIdle — сколько bucket неактивного источника живёт в карте
	// перед выметанием (защита карты от роста на сканировании псевдо-IP).
	rateBucketIdle = 5 * time.Minute
	// rateSweepInterval — период полной чистки карты устаревших bucket-ов.
	rateSweepInterval = time.Minute
)

// tokenBucket — классический корзинный счётчик: tokens ≤ burst, пополняется
// rate токенов в секунду. Один токен — один пакет.
type tokenBucket struct {
	tokens    float64
	lastRefil time.Time
}

// refill доливает токены по прошествию времени (мьютекс limiter захвачен).
func (b *tokenBucket) refill(rate float64, burst float64, now time.Time) {
	elapsed := now.Sub(b.lastRefil).Seconds()
	if elapsed <= 0 {
		return
	}
	b.tokens += elapsed * rate
	if b.tokens > burst {
		b.tokens = burst
	}
	b.lastRefil = now
}

// rateLimiter — карта per-source bucket-ов под мьютексом. Нулевое значение
// не готово к работе — см. newRateLimiter.
type rateLimiter struct {
	mu        sync.Mutex
	buckets   map[string]*tokenBucket
	dropped   int64
	lastSweep time.Time
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{buckets: make(map[string]*tokenBucket), lastSweep: time.Now()}
}

// allow пропускает пакет или нет. rate <= 0 — лимит выключен (всё
// пропускается). Ключ — IP источника (hostOnly от RemoteAddr).
func (rl *rateLimiter) allow(ip string, rate int, now time.Time) bool {
	if rate <= 0 {
		return true
	}
	burst := float64(rate * rateBurstMult)
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.sweepLocked(now)
	b, ok := rl.buckets[ip]
	if !ok {
		rl.buckets[ip] = &tokenBucket{tokens: burst - 1, lastRefil: now}
		return true
	}
	b.refill(float64(rate), burst, now)
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	rl.dropped++
	return false
}

// sweepLocked изредка выметает bucket-ы источников, молчащих дольше
// rateBucketIdle (мьютекс захвачен).
func (rl *rateLimiter) sweepLocked(now time.Time) {
	if now.Sub(rl.lastSweep) < rateSweepInterval {
		return
	}
	rl.lastSweep = now
	for ip, b := range rl.buckets {
		if now.Sub(b.lastRefil) > rateBucketIdle {
			delete(rl.buckets, ip)
		}
	}
}

// droppedCount — сколько пакетов отброшено лимитом (метрика/тесты).
func (rl *rateLimiter) droppedCount() int64 {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.dropped
}
