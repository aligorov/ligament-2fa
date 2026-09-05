//go:build integration

// Интеграционные тесты репозитория WebAuthn-учётных данных (плоские колонки).
package store

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

// newWACred — валидный WACred со случайным credential_id
// (колонка credential_id глобально UNIQUE).
func newWACred() *WACred {
	return &WACred{
		CredentialID:      []byte("cred-" + uuid.NewString()[:12]),
		RPID:              "2fa.example.com",
		PublicKey:         []byte{0x04, 0x01, 0x02},
		SignCount:         10,
		AAGUID:            "00000000-0000-0000-0000-000000000000",
		AttestationType:   "none",
		AttestationFormat: "packed",
		Attachment:        "platform",
		Transports:        "usb,nfc",
		Name:              "YubiKey 5",
		Present:           true,
		Verified:          true,
	}
}

func TestWACredUpsertListIntegration(t *testing.T) {
	st := sharedTestStore(t)
	ctx := t.Context()
	u := newTestUser(t)

	c := newWACred()
	if err := st.WACredUpsert(ctx, u.ID, c); err != nil {
		t.Fatalf("WACredUpsert: %v", err)
	}
	if c.ID == 0 {
		t.Fatal("ID не проставлен")
	}

	list, err := st.WACredListForUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("WACredListForUser: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("ожидалась 1 запись, got %d", len(list))
	}
	got := list[0]
	if got.ID != c.ID || string(got.CredentialID) != string(c.CredentialID) ||
		got.RPID != "2fa.example.com" || !bytes.Equal(got.PublicKey, []byte{0x04, 0x01, 0x02}) ||
		got.SignCount != 10 || got.CloneWarning ||
		got.AAGUID != "00000000-0000-0000-0000-000000000000" ||
		got.AttestationType != "none" || got.AttestationFormat != "packed" ||
		got.Attachment != "platform" || got.Transports != "usb,nfc" ||
		got.Name != "YubiKey 5" || !got.Present || !got.Verified ||
		got.BackupEligible || got.BackupState || got.LastUsedAt != nil {
		t.Fatalf("WACredListForUser: %+v", got)
	}

	// Upsert того же credential_id обновляет, а не дублирует.
	usedAt := time.Now().Add(-time.Hour)
	c.SignCount = 20
	c.CloneWarning = true
	c.Name = "YubiKey 5 (slot 2)"
	c.LastUsedAt = &usedAt
	if err := st.WACredUpsert(ctx, u.ID, c); err != nil {
		t.Fatalf("повторный WACredUpsert: %v", err)
	}
	list, err = st.WACredListForUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("WACredListForUser после upsert: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("после upsert %d записей, want 1", len(list))
	}
	if list[0].SignCount != 20 || !list[0].CloneWarning || list[0].Name != "YubiKey 5 (slot 2)" {
		t.Fatalf("upsert не обновил поля: %+v", list[0])
	}
	if list[0].LastUsedAt == nil {
		t.Fatal("last_used_at не обновился")
	}

	// Чужой пользователь не видит записей.
	u2 := newTestUser(t)
	foreign, err := st.WACredListForUser(ctx, u2.ID)
	if err != nil || len(foreign) != 0 {
		t.Fatalf("WACredListForUser(чужой): %d записей (%v), want 0", len(foreign), err)
	}
}

func TestWACredUpdateSignInIntegration(t *testing.T) {
	st := sharedTestStore(t)
	ctx := t.Context()
	u := newTestUser(t)

	c := newWACred()
	if err := st.WACredUpsert(ctx, u.ID, c); err != nil {
		t.Fatalf("WACredUpsert: %v", err)
	}
	if err := st.WACredUpdateSignIn(ctx, c.CredentialID, 555, true); err != nil {
		t.Fatalf("WACredUpdateSignIn: %v", err)
	}
	list, err := st.WACredListForUser(ctx, u.ID)
	if err != nil || len(list) != 1 {
		t.Fatalf("WACredListForUser: %d (%v), want 1", len(list), err)
	}
	if list[0].SignCount != 555 || !list[0].CloneWarning || list[0].LastUsedAt == nil {
		t.Fatalf("после UpdateSignIn: %+v", list[0])
	}

	if err := st.WACredUpdateSignIn(ctx, []byte("cred-unknown"), 1, false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("WACredUpdateSignIn(нет такого): err=%v, want ErrNotFound", err)
	}
}

func TestWACredDeleteIntegration(t *testing.T) {
	st := sharedTestStore(t)
	ctx := t.Context()
	u := newTestUser(t)

	c1 := newWACred()
	c2 := newWACred()
	if err := st.WACredUpsert(ctx, u.ID, c1); err != nil {
		t.Fatalf("WACredUpsert #1: %v", err)
	}
	if err := st.WACredUpsert(ctx, u.ID, c2); err != nil {
		t.Fatalf("WACredUpsert #2: %v", err)
	}

	// Чужой пользователь не может удалить.
	other := newTestUser(t)
	if err := st.WACredDelete(ctx, c1.ID, other.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("WACredDelete чужого: err=%v, want ErrNotFound", err)
	}
	if err := st.WACredDelete(ctx, c1.ID, u.ID); err != nil {
		t.Fatalf("WACredDelete: %v", err)
	}
	list, err := st.WACredListForUser(ctx, u.ID)
	if err != nil || len(list) != 1 || list[0].ID != c2.ID {
		t.Fatalf("после удаления %d записей (%v), want только %d", len(list), err, c2.ID)
	}

	if err := st.WACredsDeleteForUser(ctx, u.ID); err != nil {
		t.Fatalf("WACredsDeleteForUser: %v", err)
	}
	// Идемпотентно.
	if err := st.WACredsDeleteForUser(ctx, u.ID); err != nil {
		t.Fatalf("повторный WACredsDeleteForUser: %v", err)
	}
	list, err = st.WACredListForUser(ctx, u.ID)
	if err != nil || len(list) != 0 {
		t.Fatalf("после удаления всех %d записей (%v), want 0", len(list), err)
	}
}
