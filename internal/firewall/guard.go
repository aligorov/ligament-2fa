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
	"net/http"
	"net/netip"
	"os"
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

// DefaultTrustedNetworks — стандартные приватные подсети обратных прокси
// и локальных сетей (RFC 1918, loopback, ULA/link-local IPv6).
// С них безопасно принимать заголовки X-Forwarded-For, X-Real-IP и CF-Connecting-IP,
// так как из публичного интернета пакет с таким сокетным адресом прийти не может.
var DefaultTrustedNetworks = []string{
	"127.0.0.0/8",
	"::1/128",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"fc00::/7",
	"fe80::/10",
}

func isExplicitlyDisabled(nets []string) bool {
	if len(nets) == 1 {
		s := strings.ToLower(strings.TrimSpace(nets[0]))
		return s == "none" || s == "off" || s == "disable" || s == "disabled"
	}
	return false
}

// RealIP вычисляет клиентский IP запроса с учётом доверенного прокси:
// если RemoteAddr входит в доверенные сети (настройка proxy.
// trusted_networks), берётся крайний справа X-Forwarded-For, НЕ
// принадлежащий доверенным сетям (цепочка "клиент, npm"), — реальный
// внешний адрес. Иначе (запрос напрямую или прокси недоверенный)
// заголовок игнорируется: только RemoteAddr — спуфингом бан не обойти.
func (g *Guard) RealIP(r *http.Request) string {
	var snap *settings.T
	if g != nil && g.m != nil {
		snap = g.m.Get()
	}
	return RealIPFrom(r, snap)
}

// RealIPFrom вычисляет клиентский IP запроса с учётом доверенного прокси:
// если RemoteAddr входит в доверенные сети (настройка proxy.trusted_networks,
// env TRUSTED_PROXIES или стандартные приватные сети DefaultTrustedNetworks),
// извлекается клиентский IP из X-Forwarded-For, X-Real-IP или CF-Connecting-IP.
// Иначе (прямой публичный запрос или недоверенный источник) заголовкам не верим
// и возвращается RemoteAddr без порта.
func RealIPFrom(r *http.Request, snap *settings.T) string {
	remote := hostOnly(r.RemoteAddr)
	a, err := netip.ParseAddr(remote)
	if err != nil {
		return remote
	}
	var trustedNets []string
	if snap != nil {
		trustedNets = snap.Proxy.TrustedNetworks
	}
	if len(trustedNets) == 0 {
		if env := os.Getenv("TRUSTED_PROXIES"); env != "" {
			for _, s := range strings.Split(env, ",") {
				if s = strings.TrimSpace(s); s != "" {
					trustedNets = append(trustedNets, s)
				}
			}
		} else {
			trustedNets = DefaultTrustedNetworks
		}
	} else if isExplicitlyDisabled(trustedNets) {
		return remote
	}

	trusted := parsePrefixes(trustedNets)
	if !contains(trusted, a.Unmap()) {
		return remote // не доверенный источник — заголовку не верим
	}

	xff := r.Header.Get("X-Forwarded-For")
	if strings.TrimSpace(xff) != "" {
		parts := strings.Split(xff, ",")
		// Крайний справа ВНЕ доверенных сетей — реальный внешний клиент
		// (слева направо: клиент, посредники; правее — прокси, которым верим).
		for i := len(parts) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(parts[i])
			if ip == "" {
				continue
			}
			p, err := netip.ParseAddr(hostOnly(ip))
			if err != nil {
				continue
			}
			if !contains(trusted, p.Unmap()) {
				return p.Unmap().String()
			}
		}
		// Вся цепочка — доверенные прокси / локальные сети (например, клиент на LAN
		// подключается через reverse proxy в Docker).
		// Возвращаем крайний левый валидный IP (исходный инициатор запроса).
		for i := 0; i < len(parts); i++ {
			ip := strings.TrimSpace(parts[i])
			if ip == "" {
				continue
			}
			if p, err := netip.ParseAddr(hostOnly(ip)); err == nil {
				return p.Unmap().String()
			}
		}
	}

	if xReal := strings.TrimSpace(r.Header.Get("X-Real-IP")); xReal != "" {
		if p, err := netip.ParseAddr(hostOnly(xReal)); err == nil {
			return p.Unmap().String()
		}
	}
	if cfIP := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cfIP != "" {
		if p, err := netip.ParseAddr(hostOnly(cfIP)); err == nil {
			return p.Unmap().String()
		}
	}

	return remote
}

// realIPFrom оставлен для обратной совместимости.
func realIPFrom(r *http.Request, snap *settings.T) string {
	return RealIPFrom(r, snap)
}

// parsePrefixes — CIDR/IP строки → префиксы (битые пропускаются молча:
// ошибка конфигурации не должна ронять разбор IP).
func parsePrefixes(list []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
			continue
		}
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
		}
	}
	return out
}
