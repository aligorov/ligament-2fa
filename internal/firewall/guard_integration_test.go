//go:build integration

// Интеграция guard с реальной PostgreSQL (testcontainers, как в auth).
package firewall

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
)

var (
	pgSt *store.Store
	pgM  *settings.M
)

func pg(t *testing.T) (*store.Store, *settings.M) {
	t.Helper()
	ctx, contextCancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer contextCancel()
	if pgSt != nil {
		return pgSt, pgM
	}
	dsn := os.Getenv("TWOFA_TEST_DSN")
	if dsn == "" {
		t.Skip("TWOFA_TEST_DSN не задан — интеграционный тест пропущен")
	}
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	m, err := settings.NewManager(ctx, st)
	if err != nil {
		t.Fatalf("settings.NewManager: %v", err)
	}
	pgSt, pgM = st, m
	return st, m
}

// TestGuardListsAndBans: чёрный/белый списки дают вердикты; счётчик
// неудач автобанит IP; белый список не баним; разбан снимает блокировку.
func TestGuardListsAndBans(t *testing.T) {
	st, m := pg(t)
	ctx := context.Background()
	// Чистые списки/баны (тестовая БД живёт между прогонами).
	if _, err := st.Pool().Exec(ctx, `DELETE FROM ip_bans; DELETE FROM ip_lists`); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	g := New(st, m)

	if _, err := st.IPListAdd(ctx, "deny", "203.0.113.0/24", "сканер"); err != nil {
		t.Fatalf("deny add: %v", err)
	}
	if _, err := st.IPListAdd(ctx, "allow", "198.51.100.7", "свой"); err != nil {
		t.Fatalf("allow add: %v", err)
	}
	if _, err := st.IPListAdd(ctx, "deny", "198.51.100.7", "в обоих — чёрный приоритетен"); err != nil {
		t.Fatalf("deny add 2: %v", err)
	}
	if _, err := st.IPListAdd(ctx, "allow", "198.51.100.8", "не банится"); err != nil {
		t.Fatalf("allow add 2: %v", err)
	}
	g.Invalidate()

	if v := g.Check(ctx, "203.0.113.9"); v != Denied {
		t.Errorf("Check(203.0.113.9) = %v, want Denied", v)
	}
	if v := g.Check(ctx, "198.51.100.7"); v != Denied {
		t.Errorf("IP в обоих списках: %v, want Denied (fail-closed)", v)
	}
	if v := g.Check(ctx, "203.0.114.1"); v != Pass {
		t.Errorf("Check(вне списков) = %v, want Pass", v)
	}

	// Автобан: порог 10 (дефолт fail2ban) — 9 неудач ещё Pass, 10-я баним.
	for i := 0; i < 9; i++ {
		g.Fail(ctx, "203.0.114.1:5555", "login_fail")
	}
	if v := g.Check(ctx, "203.0.114.1"); v != Pass {
		t.Fatalf("после 9 неудач = %v, want Pass", v)
	}
	g.Fail(ctx, "203.0.114.1", "login_fail")
	if v := g.Check(ctx, "203.0.114.1"); v != Banned {
		t.Fatal("после 10 неудач нет бана")
	}
	// CheckUntil сообщает момент окончания бана (для Retry-After в HTTP-слое).
	vBanned, until := g.CheckUntil(ctx, "203.0.114.1")
	if vBanned != Banned {
		t.Fatalf("CheckUntil = %v, want Banned", vBanned)
	}
	if until.Before(time.Now()) {
		t.Fatalf("CheckUntil: banned_until в прошлом: %v", until)
	}
	if _, until := g.CheckUntil(ctx, "203.0.115.5"); !until.IsZero() {
		t.Fatalf("CheckUntil небаненого IP: until = %v, хочу нулевой", until)
	}

	// Белый список: неудачи не считаются.
	for i := 0; i < 15; i++ {
		g.Fail(ctx, "198.51.100.8", "radius_fail")
	}
	if v := g.Check(ctx, "198.51.100.8"); v != Pass {
		t.Fatal("белый IP не должен баниться")
	}

	// Разбан.
	if err := st.BanDelete(ctx, "203.0.114.1"); err != nil {
		t.Fatalf("unban: %v", err)
	}
	if v := g.Check(ctx, "203.0.114.1"); v != Pass {
		t.Fatal("после разбана всё ещё Banned")
	}
}

// TestBanFailExpiredWindow: окно в прошлом — счётчик каждый раз
// начинается заново, бан не ставится.
func TestBanFailExpiredWindow(t *testing.T) {
	st, _ := pg(t)
	b, err := st.BanFail(context.Background(), "192.0.2.9", "code_fail", -time.Hour, time.Minute, 2)
	if err != nil {
		t.Fatalf("BanFail: %v", err)
	}
	if b.Fails != 1 || b.BannedUntil.After(time.Now()) {
		t.Fatalf("окно истекло, а счётчик/бан активны: %+v", b)
	}
}
