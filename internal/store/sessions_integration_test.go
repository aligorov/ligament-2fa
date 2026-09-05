//go:build integration

// Интеграционные тесты репозитория сессий web-UI.
package store

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSessionLifecycleIntegration(t *testing.T) {
	st := sharedTestStore(t)
	ctx := t.Context()
	u := newTestUser(t)

	token := []byte("sess-" + uuid.NewString()[:12])
	if err := st.SessionCreate(ctx, token, u.ID, "csrf-1", time.Hour); err != nil {
		t.Fatalf("SessionCreate: %v", err)
	}
	uid, csrf, err := st.SessionGet(ctx, token)
	if err != nil {
		t.Fatalf("SessionGet: %v", err)
	}
	if uid != u.ID || csrf != "csrf-1" {
		t.Fatalf("SessionGet: %s/%q, want %s/\"csrf-1\"", uid, csrf, u.ID)
	}

	if err := st.SessionDelete(ctx, token); err != nil {
		t.Fatalf("SessionDelete: %v", err)
	}
	if _, _, err := st.SessionGet(ctx, token); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SessionGet после delete: err=%v, want ErrNotFound", err)
	}
	if err := st.SessionDelete(ctx, token); !errors.Is(err, ErrNotFound) {
		t.Fatalf("повторный SessionDelete: err=%v, want ErrNotFound", err)
	}
}

func TestSessionExpiryIntegration(t *testing.T) {
	st := sharedTestStore(t)
	ctx := t.Context()
	u := newTestUser(t)

	// Отрицательный TTL — сессия сразу просрочена.
	expired := []byte("exp-" + uuid.NewString()[:12])
	if err := st.SessionCreate(ctx, expired, u.ID, "csrf", -time.Minute); err != nil {
		t.Fatalf("SessionCreate (просроченная): %v", err)
	}
	if _, _, err := st.SessionGet(ctx, expired); !errors.Is(err, ErrNotFound) {
		t.Fatalf("просроченная сессия: err=%v, want ErrNotFound", err)
	}
}

func TestSessionMissingIntegration(t *testing.T) {
	st := sharedTestStore(t)
	if _, _, err := st.SessionGet(t.Context(), []byte("no-such-token")); !errors.Is(err, ErrNotFound) {
		t.Errorf("SessionGet(нет такой): err=%v, want ErrNotFound", err)
	}
}

func TestSessionDeleteAllForUserIntegration(t *testing.T) {
	st := sharedTestStore(t)
	ctx := t.Context()
	u := newTestUser(t)

	for i := 0; i < 2; i++ {
		tok := []byte("all-" + uuid.NewString()[:12])
		if err := st.SessionCreate(ctx, tok, u.ID, "csrf", time.Hour); err != nil {
			t.Fatalf("SessionCreate #%d: %v", i, err)
		}
	}
	if err := st.SessionDeleteAllForUser(ctx, u.ID); err != nil {
		t.Fatalf("SessionDeleteAllForUser: %v", err)
	}
	// Идемпотентно — отсутствие сессий не ошибка.
	if err := st.SessionDeleteAllForUser(ctx, u.ID); err != nil {
		t.Fatalf("повторный SessionDeleteAllForUser: %v", err)
	}
	var n int
	if err := st.Pool().QueryRow(ctx,
		`SELECT count(*) FROM sessions WHERE user_id = $1`, u.ID).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("осталось %d сессий, want 0", n)
	}
}
