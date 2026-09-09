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

func reqHeaders(remote string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/login", nil)
	r.RemoteAddr = remote
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

// TestRealIP: доверенный прокси отдаёт реальный клиентский IP из
// X-Forwarded-For, X-Real-IP, CF-Connecting-IP; недоверенный и прямой
// запрос — RemoteAddr; заголовку с недоверенного адреса не верим.
func TestRealIP(t *testing.T) {
	trusted := snapTrusted("172.18.0.0/16")
	defaultEmpty := snapTrusted() // пусто = использует DefaultTrustedNetworks

	cases := []struct {
		name, remote, xff, want string
		headers                 map[string]string
		snap                    *settings.T
	}{
		{name: "доверенный прокси, клиент вне доверенных", remote: "203.0.113.9:443", xff: "203.0.113.9, 172.18.0.5", want: "203.0.113.9", snap: trusted},
		{name: "цепочка: клиент, два доверенных прокси", remote: "172.18.0.2:443", xff: "203.0.113.9, 172.18.0.5, 172.18.0.2", want: "203.0.113.9", snap: trusted},
		{name: "недоверенный источник с XFF — игнорируем", remote: "198.51.100.7:443", xff: "1.1.1.1", want: "198.51.100.7", snap: trusted},
		{name: "доверенный, но заголовка нет", remote: "172.18.0.2:443", xff: "", want: "172.18.0.2", snap: trusted},
		{name: "вся цепочка доверенная (клиент внутри LAN сети)", remote: "172.18.0.2:443", xff: "172.18.0.5, 172.18.0.2", want: "172.18.0.5", snap: trusted},
		{name: "snap nil использует DefaultTrustedNetworks (Docker прокси)", remote: "172.18.0.2:443", xff: "203.0.113.9", want: "203.0.113.9", snap: nil},
		{name: "snap nil не доверяет публичному сокету", remote: "198.51.100.7:443", xff: "1.1.1.1", want: "198.51.100.7", snap: nil},
		{name: "пустой список сетей по умолчанию доверяет Docker и извлекает XFF", remote: "172.18.0.2:443", xff: "203.0.113.9", want: "203.0.113.9", snap: defaultEmpty},
		{name: "пустой список сетей не доверяет публичному сокету", remote: "198.51.100.7:443", xff: "1.1.1.1", want: "198.51.100.7", snap: defaultEmpty},
		{name: "X-Real-IP поддерживается если XFF пуст", remote: "172.18.0.2:443", headers: map[string]string{"X-Real-IP": "203.0.113.15"}, want: "203.0.113.15", snap: defaultEmpty},
		{name: "CF-Connecting-IP поддерживается если XFF пуст", remote: "172.18.0.2:443", headers: map[string]string{"CF-Connecting-IP": "203.0.113.20"}, want: "203.0.113.20", snap: defaultEmpty},
		{name: "явное отключение none игнорирует заголовки", remote: "172.18.0.2:443", xff: "203.0.113.9", want: "172.18.0.2", snap: snapTrusted("none")},
		{name: "битый RemoteAddr — как есть", remote: "not-an-addr", xff: "203.0.113.9", want: "not-an-addr", snap: trusted},
	}
	for _, c := range cases {
		var r *http.Request
		if c.headers != nil {
			r = reqHeaders(c.remote, c.headers)
		} else {
			r = req(c.remote, c.xff)
		}
		if got := RealIPFrom(r, c.snap); got != c.want {
			t.Errorf("%s: RealIP = %q, want %q", c.name, got, c.want)
		}
	}
}
