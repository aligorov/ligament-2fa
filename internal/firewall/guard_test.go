package firewall

import "testing"

func TestHostOnly(t *testing.T) {
	for in, want := range map[string]string{
		"1.2.3.4:1812": "1.2.3.4", "1.2.3.4": "1.2.3.4",
		"[2001:db8::1]:443": "2001:db8::1", "2001:db8::1": "2001:db8::1",
	} {
		if got := hostOnly(in); got != want {
			t.Errorf("hostOnly(%q) = %q, want %q", in, got, want)
		}
	}
}
