//go:build integration

// Интеграционные тесты репозитория доверенных устройств.
package store

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDeviceCRUDIntegration(t *testing.T) {
	st := sharedTestStore(t)
	ctx := t.Context()
	u := newTestUser(t)

	d := &Device{
		UserID:    u.ID,
		TokenHash: []byte("dev-" + uuid.NewString()[:12]),
		UA:        "Mozilla/5.0 (test)",
		IP:        "192.0.2.10",
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}
	if err := st.DeviceCreate(ctx, d); err != nil {
		t.Fatalf("DeviceCreate: %v", err)
	}
	if d.ID == 0 || d.CreatedAt.IsZero() || d.LastSeenAt.IsZero() {
		t.Fatalf("DeviceCreate не заполнил служебные поля: %+v", d)
	}

	got, err := st.DeviceGet(ctx, d.TokenHash)
	if err != nil {
		t.Fatalf("DeviceGet: %v", err)
	}
	if got.ID != d.ID || got.UserID != u.ID || string(got.TokenHash) != string(d.TokenHash) ||
		got.UA != "Mozilla/5.0 (test)" || got.IP != "192.0.2.10" {
		t.Fatalf("DeviceGet: %+v", got)
	}

	if err := st.DeviceTouch(ctx, d.TokenHash); err != nil {
		t.Fatalf("DeviceTouch: %v", err)
	}
	touched, err := st.DeviceGet(ctx, d.TokenHash)
	if err != nil {
		t.Fatalf("DeviceGet после touch: %v", err)
	}
	if touched.LastSeenAt.Before(d.CreatedAt) {
		t.Fatalf("last_seen_at = %v раньше created_at = %v", touched.LastSeenAt, d.CreatedAt)
	}

	// Удаление с чужим userID — ErrNotFound (проверка принадлежности).
	other := newTestUser(t)
	if err := st.DeviceDelete(ctx, d.ID, other.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeviceDelete чужого: err=%v, want ErrNotFound", err)
	}
	if err := st.DeviceDelete(ctx, d.ID, u.ID); err != nil {
		t.Fatalf("DeviceDelete: %v", err)
	}
	if _, err := st.DeviceGet(ctx, d.TokenHash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeviceGet после delete: err=%v, want ErrNotFound", err)
	}
}

func TestDeviceExpiredAndMissingIntegration(t *testing.T) {
	st := sharedTestStore(t)
	ctx := t.Context()
	u := newTestUser(t)

	expired := &Device{
		UserID:    u.ID,
		TokenHash: []byte("dev-" + uuid.NewString()[:12]),
		ExpiresAt: time.Now().Add(-time.Minute),
	}
	if err := st.DeviceCreate(ctx, expired); err != nil {
		t.Fatalf("DeviceCreate (просроченное): %v", err)
	}
	if _, err := st.DeviceGet(ctx, expired.TokenHash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("просроченное устройство: err=%v, want ErrNotFound", err)
	}
	if _, err := st.DeviceGet(ctx, []byte("no-such")); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeviceGet(нет такого): err=%v, want ErrNotFound", err)
	}
	if err := st.DeviceTouch(ctx, []byte("no-such")); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeviceTouch(нет такого): err=%v, want ErrNotFound", err)
	}
}

func TestDeviceListAndDeleteAllIntegration(t *testing.T) {
	st := sharedTestStore(t)
	ctx := t.Context()
	u := newTestUser(t)

	live := &Device{UserID: u.ID, TokenHash: []byte("dev-" + uuid.NewString()[:12]),
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour)}
	if err := st.DeviceCreate(ctx, live); err != nil {
		t.Fatalf("DeviceCreate(live): %v", err)
	}
	expired := &Device{UserID: u.ID, TokenHash: []byte("dev-" + uuid.NewString()[:12]),
		ExpiresAt: time.Now().Add(-time.Minute)}
	if err := st.DeviceCreate(ctx, expired); err != nil {
		t.Fatalf("DeviceCreate(expired): %v", err)
	}
	u2 := newTestUser(t)
	foreign := &Device{UserID: u2.ID, TokenHash: []byte("dev-" + uuid.NewString()[:12]),
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour)}
	if err := st.DeviceCreate(ctx, foreign); err != nil {
		t.Fatalf("DeviceCreate(foreign): %v", err)
	}

	list, err := st.DeviceListForUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("DeviceListForUser: %v", err)
	}
	if len(list) != 1 || list[0].ID != live.ID {
		t.Fatalf("DeviceListForUser: %d шт., want только live %d", len(list), live.ID)
	}

	if err := st.DeviceDeleteAllForUser(ctx, u.ID); err != nil {
		t.Fatalf("DeviceDeleteAllForUser: %v", err)
	}
	// Идемпотентно.
	if err := st.DeviceDeleteAllForUser(ctx, u.ID); err != nil {
		t.Fatalf("повторный DeviceDeleteAllForUser: %v", err)
	}
	list, err = st.DeviceListForUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("DeviceListForUser после delete all: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("осталось %d устройств, want 0", len(list))
	}
	// Чужое устройство не тронуто.
	if _, err := st.DeviceGet(ctx, foreign.TokenHash); err != nil {
		t.Fatalf("чужое устройство удалено: %v", err)
	}
}
