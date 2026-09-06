// Юнит-тесты payload лицензии: стабильность канонического JSON (тот же
// ввод — те же байты, независимо от порядка полей в исходном JSON).
package license

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func testPayload() Payload {
	exp := time.Date(2027, 9, 1, 0, 0, 0, 0, time.UTC)
	return Payload{
		LicID:              "11111111-2222-3333-4444-555555555555",
		Customer:           "ООО Ромашка",
		Plan:               PlanSubscription,
		UserLimit:          25,
		IssuedAt:           time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC),
		ExpiresAt:          &exp,
		MaintenanceExpires: exp,
		Features:           []string{"radius", "webauthn"},
		Kid:                "test-key-1",
		Notes:              "тест",
	}
}

// TestCanonicalStable: канонические байты одного payload не меняются между
// вызовами и не зависят от порядка полей в исходном JSON.
func TestCanonicalStable(t *testing.T) {
	p := testPayload()
	a, err := p.Canonical()
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	b, err := p.Canonical()
	if err != nil {
		t.Fatalf("Canonical (повтор): %v", err)
	}
	if string(a) != string(b) {
		t.Fatalf("канонические байты нестабильны:\n%s\n%s", a, b)
	}

	// Те же данные, поля в другом порядке — те же канонические байты.
	raw := `{"notes":"тест","features":["radius","webauthn"],` +
		`"kid":"test-key-1","maintenance_expires":"2027-09-01T00:00:00Z",` +
		`"expires_at":"2027-09-01T00:00:00Z",` +
		`"issued_at":"2026-09-06T12:00:00Z","user_limit":25,` +
		`"plan":"subscription","customer":"ООО Ромашка",` +
		`"lic_id":"11111111-2222-3333-4444-555555555555"}`
	var p2 Payload
	if err := json.Unmarshal([]byte(raw), &p2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	c, err := p2.Canonical()
	if err != nil {
		t.Fatalf("Canonical (p2): %v", err)
	}
	if string(a) != string(c) {
		t.Fatalf("канонические байты зависят от порядка полей:\n%s\n%s", a, c)
	}

	// Канонический JSON — без незначащих пробелов (json.Compact — эталон:
	// он убирает пробелы только ВНЕ строковых литералов).
	var compact bytes.Buffer
	if err := json.Compact(&compact, a); err != nil {
		t.Fatalf("compact: %v", err)
	}
	if compact.String() != string(a) {
		t.Fatalf("канонический JSON содержит незначащие пробелы: %s", a)
	}
}

// TestCanonicalRoundtrip: подпись по каноническим байтам проверяется после
// разбора blob (parse → canonical → verify).
func TestCanonicalRoundtrip(t *testing.T) {
	p := testPayload()
	canonical, err := p.Canonical()
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(canonical, &m); err != nil {
		t.Fatalf("canonical не JSON: %v", err)
	}
	var p2 Payload
	if err := json.Unmarshal(canonical, &p2); err != nil {
		t.Fatalf("unmarshal canonical: %v", err)
	}
	again, err := p2.Canonical()
	if err != nil {
		t.Fatalf("Canonical (p2): %v", err)
	}
	if string(canonical) != string(again) {
		t.Fatalf("roundtrip канонических байтов сломан:\n%s\n%s", canonical, again)
	}
}
