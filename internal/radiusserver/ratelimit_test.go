// Юнит-тесты per-source rate limit (token bucket): без БД и сети,
// время передаётся явно — детерминированно.
package radiusserver

import (
	"testing"
	"time"
)

func TestRateLimiterBurstThenDrop(t *testing.T) {
	rl := newRateLimiter()
	now := time.Now()

	// rate=5 pps → burst=10: первые 10 пакетов подряд проходят.
	for i := 0; i < 10; i++ {
		if !rl.allow("10.0.0.1", 5, now) {
			t.Fatalf("пакет #%d внутри burst отклонён", i+1)
		}
	}
	// 11-й в ту же секунду — drop.
	if rl.allow("10.0.0.1", 5, now) {
		t.Fatal("пакет сверх burst пропущен")
	}
	if got := rl.droppedCount(); got != 1 {
		t.Fatalf("dropped = %d, хочу 1", got)
	}

	// Другой источник не делит bucket.
	if !rl.allow("10.0.0.2", 5, now) {
		t.Fatal("другой источник обязан получить свой burst")
	}

	// Через секунду (rate=5/s) накопилось 5 токенов — проходят, дальше drop.
	next := now.Add(time.Second)
	for i := 0; i < 5; i++ {
		if !rl.allow("10.0.0.1", 5, next) {
			t.Fatalf("пакет #%d после пополнения отклонён", i+1)
		}
	}
	if rl.allow("10.0.0.1", 5, next) {
		t.Fatal("пакет сверх пополнения пропущен")
	}

	// Долгая пауза не даёт больше burst.
	after := now.Add(time.Hour)
	for i := 0; i < 10; i++ {
		if !rl.allow("10.0.0.1", 5, after) {
			t.Fatalf("пакет #%d полного burst отклонён", i+1)
		}
	}
	if rl.allow("10.0.0.1", 5, after) {
		t.Fatal("bucket переполнился сверх burst")
	}
}

func TestRateLimiterDisabled(t *testing.T) {
	rl := newRateLimiter()
	now := time.Now()
	for i := 0; i < 1000; i++ {
		if !rl.allow("10.0.0.1", 0, now) {
			t.Fatalf("rate=0 (выключен): пакет #%d отклонён", i)
		}
	}
	if got := rl.droppedCount(); got != 0 {
		t.Fatalf("dropped = %d при выключенном лимите, хочу 0", got)
	}
}

func TestRateLimiterSweepsIdleBuckets(t *testing.T) {
	rl := newRateLimiter()
	now := time.Now()
	rl.allow("10.9.9.9", 5, now)

	rl.mu.Lock()
	if len(rl.buckets) != 1 {
		rl.mu.Unlock()
		t.Fatalf("buckets = %d, хочу 1", len(rl.buckets))
	}
	rl.mu.Unlock()

	// Через 6 минут (idle > rateBucketIdle=5m, sweep при новом обращении)
	// bucket выметается — карта не растёт от сканирования псевдо-IP.
	later := now.Add(6 * time.Minute)
	rl.allow("10.8.8.8", 5, later)
	rl.mu.Lock()
	n := len(rl.buckets)
	rl.mu.Unlock()
	if n != 1 {
		t.Fatalf("после sweep buckets = %d, хочу 1 (только свежий)", n)
	}
}
