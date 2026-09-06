package firewall

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aligorov/twofa/internal/settings"
)

func snapTrusted(nets ...string) *settings.T {
	t := &settings.T{}
	t.Proxy.TrustedNetworks = nets
	return t
}

func req(remote, xff string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/login", nil)
	r.RemoteAddr = remote
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	return r
}

// TestRealIP: доверенный прокси отдаёт реальный клиентский IP из
// X-Forwarded-For (крайний справа вне доверенных); недоверенный и прямой
// запрос — RemoteAddr; заголовку с недоверенного адреса не верим.
func TestRealIP(t *testing.T) {
	trusted := snapTrusted("172.18.0.0/16")

	cases := []struct {
		name, remote, xff, want string
		snap                    *settings.T
	}{
		{"доверенный прокси, клиент вне доверенных", "203.0.113.9:443", "203.0.113.9, 172.18.0.5", "203.0.113.9", trusted},
		{"цепочка: клиент, два доверенных прокси", "172.18.0.2:443", "203.0.113.9, 172.18.0.5, 172.18.0.2", "203.0.113.9", trusted},
		{"недоверенный источник с XFF — игнорируем", "198.51.100.7:443", "1.1.1.1", "198.51.100.7", trusted},
		{"доверенный, но заголовка нет", "172.18.0.2:443", "", "172.18.0.2", trusted},
		{"вся цепочка доверенная", "172.18.0.2:443", "172.18.0.5, 172.18.0.2", "172.18.0.2", trusted},
		{"без настройки — всегда сокет", "172.18.0.2:443", "203.0.113.9", "172.18.0.2", nil},
		{"битый RemoteAddr — как есть", "not-an-addr", "203.0.113.9", "not-an-addr", trusted},
	}
	for _, c := range cases {
		if got := realIPFrom(req(c.remote, c.xff), c.snap); got != c.want {
			t.Errorf("%s: RealIP = %q, want %q", c.name, got, c.want)
		}
	}
}
