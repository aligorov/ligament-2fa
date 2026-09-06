// Package firewall — fail2ban- guard: чёрные/белые списки CIDR и автобан
// IP по счётчику неудач (login/code/radius). Белый список не банится и не
// блокируется; чёрный всегда отклоняется (при попадании в оба — чёрный
// приоритетен, fail-closed). Списки кэшируются в памяти (TTL 15 с + сброс
// при локальных мутациях): авторизация — редкий трафик, RADIUS ходит мимо
// HTTP-пути и тоже читает кэш.
package firewall

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
)

// ipCtxKey — ключ клиентского IP в контексте запроса: middleware HTTP
// кладёт реальный RemoteAddr, auth.Core читает для guard.Fail.
type ipCtxKey struct{}

// WithIP кладёт клиентский IP в контекст.
func WithIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, ipCtxKey{}, ip)
}

// IPFrom достаёт клиентский IP из контекста ("" — не положен).
func IPFrom(ctx context.Context) string {
	if v, ok := ctx.Value(ipCtxKey{}).(string); ok {
		return v
	}
	return ""
}

// listTTL — время жизни кэша списков (мутации из этого процесса сбрасывают
// кэш сразу; внешние изменения подхватываются не дольше чем за listTTL).
const listTTL = 15 * time.Second

// Verdict — решение по IP.
type Verdict int

const (
	Pass   Verdict = iota // не в списках, бана нет
	Denied                // чёрный список
	Banned                // автобан fail2ban
)

// Guard — потокобезопасный проверщик. Неизменяем после создания.
type Guard struct {
	st *store.Store
	m  *settings.M

	mu     sync.Mutex
	loaded time.Time
	allow  []netip.Prefix
	deny   []netip.Prefix
}

// New создаёт guard; списки подгружаются лениво при первом запросе.
func New(st *store.Store, m *settings.M) *Guard {
	return &Guard{st: st, m: m}
}

// Invalidate сбрасывает кэш списков (вызывается после мутаций списков).
func (g *Guard) Invalidate() {
	g.mu.Lock()
	g.loaded = time.Time{}
	g.mu.Unlock()
}

// loadIfStale подгружает списки, если кэш старше listTTL.
func (g *Guard) loadIfStale(ctx context.Context) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if time.Since(g.loaded) < listTTL {
		return
	}
	rows, err := g.st.IPLists(ctx)
	if err != nil {
		slog.Warn("firewall: список IP не прочитан, работаю по кэшу", "error", err)
		return
	}
	var allow, deny []netip.Prefix
	for _, l := range rows {
		if p, err := netip.ParsePrefix(l.CIDR); err == nil {
			if l.Kind == "allow" {
				allow = append(allow, p)
			} else {
				deny = append(deny, p)
			}
		}
	}
	g.allow, g.deny = allow, deny
	g.loaded = time.Now()
}

// contains — принадлежность IP любому из префиксов (без аллокаций масок:
// префиксы в кэше уже Masked).
func contains(list []netip.Prefix, ip netip.Addr) bool {
	for _, p := range list {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// Check выносит вердикт по IP: чёрный список → Denied; иначе активный бан →
// Banned; белый список гасит бан (Pass). Некорректный IP — Pass (фильтрация
// не должна ронять легитимный трафик с экзотических прокси).
func (g *Guard) Check(ctx context.Context, ip string) Verdict {
	a, err := netip.ParseAddr(hostOnly(ip))
	if err != nil {
		return Pass
	}
	a = a.Unmap()
	g.loadIfStale(ctx)
	g.mu.Lock()
	deny, allow := g.deny, g.allow
	g.mu.Unlock()

	if contains(deny, a) {
		return Denied
	}
	if contains(allow, a) {
		return Pass
	}
	active, _, err := g.st.BanActive(ctx, a.String())
	if err != nil {
		slog.Warn("firewall: проверка бана не удалась, пропускаю", "error", err)
		return Pass
	}
	if active {
		return Banned
	}
	return Pass
}

// Fail регистрирует неудачу с IP (reason — login_fail/code_fail/
// radius_fail): чёрный список уже отклоняется (счётчик не нужен), белый
// не баним; при достижении порога в окне IP банится на ban_time.
// Вызывается из auth.Core на каждой неудаче.
func (g *Guard) Fail(ctx context.Context, ip, reason string) {
	if g == nil || g.st == nil {
		return
	}
	a, err := netip.ParseAddr(hostOnly(ip))
	if err != nil || a.IsLoopback() {
		return // 127.0.0.1 не банится (локальные тесты/health-пробы)
	}
	snap := g.m.Get()
	if snap == nil || !snap.Fail2ban.Enabled {
		return
	}
	if containsListed(ctx, g, a, "deny") || containsListed(ctx, g, a, "allow") {
		return
	}
	b, err := g.st.BanFail(ctx, a.String(), reason,
		snap.Fail2ban.Window, snap.Fail2ban.BanTime, snap.Fail2ban.MaxFail)
	if err != nil {
		slog.Warn("firewall: неудача не засчитана", "ip", a.String(), "error", err)
		return
	}
	if b.BannedUntil.After(time.Now()) && b.Fails >= snap.Fail2ban.MaxFail {
		slog.Warn("firewall: IP забанен", "ip", a.String(), "reason", reason,
			"fails", b.Fails, "until", b.BannedUntil.Format(time.RFC3339))
	}
}

// containsListed — IP в указанном списке (для белого).
func containsListed(ctx context.Context, g *Guard, a netip.Addr, kind string) bool {
	g.loadIfStale(ctx)
	g.mu.Lock()
	list := g.allow
	if kind == "deny" {
		list = g.deny
	}
	g.mu.Unlock()
	return contains(list, a)
}

// hostOnly срезает порт из "ip:port"/"[v6]:port" (IPv6-адрес порта не
// содержит — SplitHostPort различает формы надёжно).
func hostOnly(s string) string {
	if h, _, err := net.SplitHostPort(s); err == nil {
		return strings.Trim(h, "[]")
	}
	return strings.Trim(s, "[]")
}
