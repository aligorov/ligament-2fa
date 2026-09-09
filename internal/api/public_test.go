// Юнит-тесты rate-limiter публичного API (без БД). Полные HTTP-флоу —
// public_integration_test.go (тег integration, testcontainers).
package api

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/aligorov/twofa/internal/store"
)

// TestLimiterMapBurstAndDeny: burst допусков, затем отказ до восстановления.
func TestLimiterMapBurstAndDeny(t *testing.T) {
	m := newLimiterMap()
	defer m.Stop()
	for i := 0; i < rlBurst; i++ {
		if !m.Allow("u:alice") {
			t.Fatalf("запрос #%d в пределах burst отклонён", i+1)
		}
	}
	if m.Allow("u:alice") {
		t.Fatal("запрос сверх burst пропущен")
	}
}

// TestLimiterMapReplenish: отказ сменяется допуском после восстановления
// одного токена (быстрая скорость — детерминированно).
func TestLimiterMapReplenish(t *testing.T) {
	m := newLimiterMapParams(rate.Limit(100), 1) // 100 токенов/с, burst 1
	defer m.Stop()
	if !m.Allow("k") {
		t.Fatal("первый запрос отклонён")
	}
	if m.Allow("k") {
		t.Fatal("второй запрос в пределах burst=1 пропущен")
	}
	time.Sleep(20 * time.Millisecond)
	if !m.Allow("k") {
		t.Fatal("токен не восстановился за 20мс при 100 токенах/с")
	}
}

// TestLimiterMapKeysIsolated: исчерпание одной корзины не трогает соседние.
func TestLimiterMapKeysIsolated(t *testing.T) {
	m := newLimiterMap()
	defer m.Stop()
	for i := 0; i < rlBurst; i++ {
		if !m.Allow("u:alice") {
			t.Fatalf("запрос #%d корзины u:alice отклонён", i+1)
		}
	}
	if m.Allow("u:alice") {
		t.Fatal("корзина u:alice не исчерпана")
	}
	for _, key := range []string{"u:bob", "ip:10.0.0.1", "ip:10.0.0.2"} {
		if !m.Allow(key) {
			t.Fatalf("независимая корзина %q исчерпана чужими запросами", key)
		}
	}
}

// TestLimiterMapConcurrent: конкурентные запросы одного ключа допускаются
// ровно burst раз (проверка гонок карты; см. также -race).
func TestLimiterMapConcurrent(t *testing.T) {
	m := newLimiterMap()
	defer m.Stop()
	const n = 50
	var allowed atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if m.Allow("u:same") {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := allowed.Load(); got != rlBurst {
		t.Fatalf("допущено %d из %d конкурентных запросов, хочу ровно %d (burst)",
			got, n, rlBurst)
	}
}

// TestLimiterMapStopIdempotent: повторный Stop не паникует.
func TestLimiterMapStopIdempotent(t *testing.T) {
	m := newLimiterMap()
	m.Stop()
	m.Stop()
}

// TestPollStatusMapping: вывод статуса poll из состояния челленджа.
func TestPollStatusMapping(t *testing.T) {
	now := time.Now()
	pending := "pending"
	approved := "approved"
	denied := "denied"
	used := now.Add(-time.Second)
	cases := []struct {
		name string
		ch   store.Challenge
		want string
	}{
		{"push pending", store.Challenge{Channel: "telegram_push", PushState: &pending, ExpiresAt: now.Add(time.Minute), AttemptsLeft: 1}, "pending"},
		{"push approved", store.Challenge{Channel: "telegram_push", PushState: &approved, ExpiresAt: now.Add(time.Minute), AttemptsLeft: 1}, "approved"},
		{"push denied", store.Challenge{Channel: "telegram_push", PushState: &denied, ExpiresAt: now.Add(time.Minute), AttemptsLeft: 1}, "denied"},
		{"push denied consumed", store.Challenge{Channel: "app_push", PushState: &denied, UsedAt: &used, ExpiresAt: now.Add(time.Minute), AttemptsLeft: 1}, "denied"},
		{"push consumed", store.Challenge{Channel: "telegram_push", PushState: &approved, UsedAt: &used, ExpiresAt: now.Add(time.Minute), AttemptsLeft: 1}, "approved"},
		{"push expired by time", store.Challenge{Channel: "telegram_push", PushState: &pending, ExpiresAt: now.Add(-time.Second), AttemptsLeft: 1}, "expired"},
		{"code pending", store.Challenge{Channel: "email", ExpiresAt: now.Add(time.Minute), AttemptsLeft: 5}, "pending"},
		{"code consumed", store.Challenge{Channel: "email", UsedAt: &used, ExpiresAt: now.Add(time.Minute), AttemptsLeft: 5}, "expired"},
		{"code exhausted", store.Challenge{Channel: "email", ExpiresAt: now.Add(time.Minute), AttemptsLeft: 0}, "expired"},
		{"code expired by time", store.Challenge{Channel: "email", ExpiresAt: now.Add(-time.Second), AttemptsLeft: 5}, "expired"},
	}
	for _, tc := range cases {
		if got := pollStatus(&tc.ch, now); got != tc.want {
			t.Errorf("%s: pollStatus = %q, want %q", tc.name, got, tc.want)
		}
	}
}
