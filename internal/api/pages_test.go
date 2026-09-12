// Юнит-тесты страниц без БД: чистые функции pages.go/router.go.
package api

import (
	"testing"
	"time"
)

// TestSafeNext — адрес возврата после входа: только локальные пути.
// Открытый редирект отсекается по трём признакам: чужая схема,
// протокол-относительный «//» и backslash «\» (браузеры трактуют его как
// «/»: Location: /\evil.com уводит на evil.com — report 2026-09-11, P1 OIDC-1).
func TestSafeNext(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"/me", "/me"},
		{"/oidc/authorize?client_id=mfa_x&state=st", "/oidc/authorize?client_id=mfa_x&state=st"},
		{"//evil.com", ""},            // протокол-относительный внешний URL
		{"/\\evil.com", ""},           // backslash = «/» для браузера
		{`\evil.com`, ""},             // относительный путь с backslash — не «/»
		{"/me\\..\\..\\evil.com", ""}, // backslash внутри пути
		{"https://evil.com", ""},      // чужая схема
		{"http://evil.com", ""},
		{"me", ""},    // не начинается с «/»
		{"../me", ""}, // выход за корень
		{"/me?next=/x", "/me?next=/x"},
	}
	for _, tc := range cases {
		if got := safeNext(tc.in); got != tc.want {
			t.Errorf("safeNext(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestRetryAfterSeconds — Retry-After при 429 автобана: целые секунды до
// окончания бана (округление вверх, минимум 1) вместо константы 300.
func TestRetryAfterSeconds(t *testing.T) {
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		until time.Time
		want  int
	}{
		{now, 1},                        // истекает сейчас — минимум 1
		{now.Add(-time.Second), 1},      // уже истёк
		{now.Add(90 * time.Second), 90}, // ровные секунды
		{now.Add(90*time.Second + 500*time.Millisecond), 91}, // вверх
		{now.Add(300 * time.Second), 300},
	}
	for _, tc := range cases {
		if got := retryAfterSeconds(tc.until, now); got != tc.want {
			t.Errorf("retryAfterSeconds(%v) = %d, want %d", tc.until.Sub(now), got, tc.want)
		}
	}
}
