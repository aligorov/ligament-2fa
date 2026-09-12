package store

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// TestNormalizeRADIUSCSID — канонизация Calling-Station-Id: регистр и
// разделители не влияют на ключ доверия, пустой атрибут даёт пустой ключ
// (доверие неприменимо).
func TestNormalizeRADIUSCSID(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"   ", ""},
		{"AA-BB-CC-DD-EE-FF", "aabbccddeeff"},
		{"aa:bb:cc:dd:ee:ff", "aabbccddeeff"},
		{"Aa:Bb-Cc:Dd-Ee:Ff", "aabbccddeeff"},
		{"AA:BB-CC:DD-EE:FF", "aabbccddeeff"},
		{"  AA-BB-CC-DD-EE-FF  ", "aabbccddeeff"},
		{"wlan0", "wlan0"}, // произвольная строка NAS — нормализуется как есть
	}
	for _, c := range cases {
		if got := NormalizeRADIUSCSID(c.in); got != c.want {
			t.Errorf("NormalizeRADIUSCSID(%q) = %q, хочу %q", c.in, got, c.want)
		}
	}
}

// TestRadiusTrustEmptyGuards — защитные ветки до обращения к БД: пустой
// CSID и выключенное окно (days <= 0) — no-op без паники на нулевом пуле
// (unit-тест без БД); IsTrusted с пустым CSID — false (доверие
// неприменимо, fail-closed).
func TestRadiusTrustEmptyGuards(t *testing.T) {
	st := &Store{} // пул не задан: любое обращение к БД запаниковало бы
	ctx := context.Background()

	if st.RadiusTrustIsTrusted(ctx, uuid.New(), "") {
		t.Error("пустой CSID не может быть доверенным")
	}
	if st.RadiusTrustIsTrusted(ctx, uuid.Nil, "aabbccddeeff") {
		t.Error("нулевой userID не может быть доверенным")
	}
	if err := st.RadiusTrustUpsert(ctx, uuid.New(), "AA-BB-CC-DD-EE-FF", 0); err != nil {
		t.Errorf("Upsert при days=0 (окно выключено) — no-op, ошибка: %v", err)
	}
	if err := st.RadiusTrustUpsert(ctx, uuid.New(), "AA-BB-CC-DD-EE-FF", -3); err != nil {
		t.Errorf("Upsert при days<0 — no-op, ошибка: %v", err)
	}
	if err := st.RadiusTrustUpsert(ctx, uuid.New(), "", 7); err != nil {
		t.Errorf("Upsert с пустым CSID — no-op, ошибка: %v", err)
	}
}
