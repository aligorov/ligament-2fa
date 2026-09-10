// Unit-тесты ужесточений безопасности app/admin API (аудит раунд-2,
// Фаза 2a): protected-ключи PUT /settings и правила приёма токена из
// query-строки (только WS/SSE).
package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aligorov/twofa/internal/settings"
)

// TestSettingsPutProtectedKey: реальное значение защищённого ключа
// (master_key/admin_token/oidc.keys/radius.eap_cert) отклоняется 400
// protected_key — перезапись master_key разрушала бы всю криптографию
// (аудит раунд-2, PUT-дыра).
func TestSettingsPutProtectedKey(t *testing.T) {
	a := NewAdminAPI(nil, settings.NewDefaultManager(), nil)

	for _, key := range []string{"master_key", "admin_token", "oidc.keys", "radius.eap_cert"} {
		body, _ := json.Marshal(map[string]any{key: "attacker-controlled-value"})
		req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		a.handleSettingsPut(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("PUT %s: status = %d, want 400 (body %s)", key, rec.Code, rec.Body.String())
		}
		var m map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
			t.Fatalf("PUT %s: тело не JSON: %v", key, err)
		}
		if m["error"] != "protected_key" || m["key"] != key {
			t.Fatalf("PUT %s: error=%v key=%v, want protected_key/%s", key, m["error"], m["key"], key)
		}
	}
}

// TestAdminTokenFromQueryOnlyStreams: ?admin_token= принимается только
// для WS/SSE-запросов (Upgrade / text/event-stream); обычный JSON-запрос —
// только заголовок Authorization.
func TestAdminTokenFromQueryOnlyStreams(t *testing.T) {
	plain := httptest.NewRequest(http.MethodGet, "/api/v1/admin/support/sessions?admin_token=tok", nil)
	if got := adminTokenFrom(plain); got != "" {
		t.Fatalf("plain JSON: adminTokenFrom = %q, want \"\"", got)
	}

	ws := httptest.NewRequest(http.MethodGet, "/api/v1/admin/support/sessions/{id}/ws?admin_token=tok", nil)
	ws.Header.Set("Upgrade", "websocket")
	ws.Header.Set("Connection", "Upgrade")
	if got := adminTokenFrom(ws); got != "tok" {
		t.Fatalf("WS: adminTokenFrom = %q, want tok", got)
	}

	sse := httptest.NewRequest(http.MethodGet, "/api/v1/admin/support/sessions?admin_token=tok", nil)
	sse.Header.Set("Accept", "text/event-stream")
	if got := adminTokenFrom(sse); got != "tok" {
		t.Fatalf("SSE: adminTokenFrom = %q, want tok", got)
	}

	hdr := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", nil)
	hdr.Header.Set("Authorization", "Bearer from-header")
	if got := adminTokenFrom(hdr); got != "from-header" {
		t.Fatalf("заголовок: adminTokenFrom = %q, want from-header", got)
	}
}

// TestIsStreamRequest: распознавание потоковых запросов.
func TestIsStreamRequest(t *testing.T) {
	cases := []struct {
		name    string
		upgrade string
		accept  string
		want    bool
	}{
		{"plain", "", "", false},
		{"json", "", "application/json", false},
		{"ws", "websocket", "", true},
		{"sse", "", "text/event-stream", true},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if c.upgrade != "" {
			req.Header.Set("Upgrade", c.upgrade)
		}
		if c.accept != "" {
			req.Header.Set("Accept", c.accept)
		}
		if got := isStreamRequest(req); got != c.want {
			t.Errorf("%s: isStreamRequest = %v, want %v", c.name, got, c.want)
		}
	}
}
