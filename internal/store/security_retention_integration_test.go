//go:build integration

// Интеграционные тесты ретеншна audit_log, TTL device-токенов и защиты
// transfer-токенов support-сессий (аудит раунд-2, Фаза 2a).
package store

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestAuditDeleteOlderThan: события старше порога удаляются, свежие остаются;
// days<=0 — no-op.
func TestAuditDeleteOlderThan(t *testing.T) {
	st := sharedTestStore(t)
	ctx := t.Context()
	u := newTestUser(t)

	oldID, err := st.Pool().Exec(ctx,
		`INSERT INTO audit_log (username, event, ts) VALUES ($1, 'login_fail', now() - interval '40 days')`, u.Username)
	if err != nil {
		t.Fatalf("вставка старого события: %v", err)
	}
	_ = oldID
	if err := st.Audit(ctx, u.Username, "login_ok", nil, "127.0.0.1", "ok"); err != nil {
		t.Fatalf("вставка свежего события: %v", err)
	}

	n, err := st.AuditDeleteOlderThan(ctx, 30)
	if err != nil {
		t.Fatalf("AuditDeleteOlderThan(30): %v", err)
	}
	if n == 0 {
		t.Fatal("AuditDeleteOlderThan(30) ничего не удалил (старое событие на месте?)")
	}

	var oldLeft, freshLeft int
	if err := st.Pool().QueryRow(ctx,
		`SELECT count(*) FROM audit_log WHERE username = $1 AND event = 'login_fail'`, u.Username).Scan(&oldLeft); err != nil {
		t.Fatalf("подсчёт старых: %v", err)
	}
	if err := st.Pool().QueryRow(ctx,
		`SELECT count(*) FROM audit_log WHERE username = $1 AND event = 'login_ok'`, u.Username).Scan(&freshLeft); err != nil {
		t.Fatalf("подсчёт свежих: %v", err)
	}
	if oldLeft != 0 || freshLeft != 1 {
		t.Fatalf("после ретеншна: старых=%d свежих=%d, want 0/1", oldLeft, freshLeft)
	}

	// Выключенный ретеншн — no-op.
	n, err = st.AuditDeleteOlderThan(ctx, 0)
	if err != nil || n != 0 {
		t.Fatalf("AuditDeleteOlderThan(0): n=%d err=%v, want 0 nil", n, err)
	}
}

// TestAppDeviceTokenExpiryAndTouch: истёкший токен не находится; продление
// срабатывает только внутри окна (<30 дней до истечения).
func TestAppDeviceTokenExpiryAndTouch(t *testing.T) {
	st := sharedTestStore(t)
	ctx := t.Context()
	u := newTestUser(t)

	d := &AppDevice{UserID: u.ID, DeviceName: "t", Platform: "test", TokenHash: []byte(uuid.NewString()), Active: true}
	if err := st.AppDeviceCreate(ctx, d); err != nil {
		t.Fatalf("AppDeviceCreate: %v", err)
	}

	// Свежий токен (миграционный дефолт ~90 дней) находится и продлевается
	// только при входе в окно.
	got, err := st.AppDeviceGetByTokenHash(ctx, d.TokenHash)
	if err != nil {
		t.Fatalf("свежий токен не найден: %v", err)
	}
	if left := time.Until(got.ExpiresAt); left < 80*24*time.Hour {
		t.Fatalf("дефолтный TTL = %v, want ~90 дней", left)
	}

	// Вне окна (осталось 60 дней) — Touch не пишет.
	if _, err := st.Pool().Exec(ctx,
		`UPDATE app_devices SET expires_at = now() + interval '60 days' WHERE id = $1`, d.ID); err != nil {
		t.Fatalf("выставить +60d: %v", err)
	}
	if err := st.AppDeviceTouch(ctx, d.ID); err != nil {
		t.Fatalf("AppDeviceTouch: %v", err)
	}
	var exp time.Time
	if err := st.Pool().QueryRow(ctx, `SELECT expires_at FROM app_devices WHERE id = $1`, d.ID).Scan(&exp); err != nil {
		t.Fatalf("чтение expires_at: %v", err)
	}
	if left := time.Until(exp); left >= 80*24*time.Hour {
		t.Fatalf("Touch вне окна продлил токен: осталось %v, want ~60 дней", left)
	}

	// В окне (осталось 10 дней) — Touch продлевает до ~90.
	if _, err := st.Pool().Exec(ctx,
		`UPDATE app_devices SET expires_at = now() + interval '10 days' WHERE id = $1`, d.ID); err != nil {
		t.Fatalf("выставить +10d: %v", err)
	}
	if err := st.AppDeviceTouch(ctx, d.ID); err != nil {
		t.Fatalf("AppDeviceTouch: %v", err)
	}
	if err := st.Pool().QueryRow(ctx, `SELECT expires_at FROM app_devices WHERE id = $1`, d.ID).Scan(&exp); err != nil {
		t.Fatalf("чтение expires_at: %v", err)
	}
	if left := time.Until(exp); left < 80*24*time.Hour {
		t.Fatalf("Touch в окне не продлил: осталось %v, want ~90 дней", left)
	}

	// Истёкший токен не находится.
	if _, err := st.Pool().Exec(ctx,
		`UPDATE app_devices SET expires_at = now() - interval '1 minute' WHERE id = $1`, d.ID); err != nil {
		t.Fatalf("истечь токен: %v", err)
	}
	if _, err := st.AppDeviceGetByTokenHash(ctx, d.TokenHash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("истёкший токен: err=%v, want ErrNotFound", err)
	}
}

// newSupportSession — сессия поддержки с устройством (FK device_id).
func newSupportSession(t *testing.T, status string) *SupportSession {
	t.Helper()
	st := sharedTestStore(t)
	u := newTestUser(t)
	d := &AppDevice{UserID: u.ID, DeviceName: "t", Platform: "test", TokenHash: []byte(uuid.NewString()), Active: true}
	if err := st.AppDeviceCreate(t.Context(), d); err != nil {
		t.Fatalf("AppDeviceCreate: %v", err)
	}
	ss := &SupportSession{
		UserID: u.ID, DeviceID: d.ID, Category: "it", Status: status,
		ProblemSummary: "test", AccessMode: "view_only",
	}
	if err := st.SupportSessionCreate(t.Context(), ss); err != nil {
		t.Fatalf("SupportSessionCreate: %v", err)
	}
	return ss
}

// TestSupportTransferTokenSingleUseAndTTL: transfer-токен одноразовый (после
// принятия хеш очищается) и живёт 10 минут от момента передачи.
func TestSupportTransferTokenSingleUseAndTTL(t *testing.T) {
	st := sharedTestStore(t)
	ctx := t.Context()
	ss := newSupportSession(t, "active")

	hash := []byte("transfer-hash-1")
	if err := st.SupportSessionTransfer(ctx, ss.ID, newTestUser(t).ID, nil, hash); err != nil {
		t.Fatalf("SupportSessionTransfer: %v", err)
	}
	if _, err := st.SupportSessionGetByTransferToken(ctx, hash); err != nil {
		t.Fatalf("свежий transfer-токен не найден: %v", err)
	}

	// Принятие: хеш очищается — повторно токен не работает.
	newAdmin := newTestUser(t).ID
	if err := st.SupportSessionAcceptTransfer(ctx, ss.ID, newAdmin); err != nil {
		t.Fatalf("SupportSessionAcceptTransfer: %v", err)
	}
	if _, err := st.SupportSessionGetByTransferToken(ctx, hash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("повторное использование transfer-токена: err=%v, want ErrNotFound", err)
	}

	// TTL: токен старше 10 минут мёртв даже без принятия.
	ss2 := newSupportSession(t, "active")
	hash2 := []byte("transfer-hash-2")
	if err := st.SupportSessionTransfer(ctx, ss2.ID, newTestUser(t).ID, nil, hash2); err != nil {
		t.Fatalf("SupportSessionTransfer(2): %v", err)
	}
	if _, err := st.Pool().Exec(ctx,
		`UPDATE support_sessions SET transferred_at = now() - interval '11 minutes' WHERE id = $1`, ss2.ID); err != nil {
		t.Fatalf("backdate transferred_at: %v", err)
	}
	if _, err := st.SupportSessionGetByTransferToken(ctx, hash2); !errors.Is(err, ErrNotFound) {
		t.Fatalf("просроченный transfer-токен: err=%v, want ErrNotFound", err)
	}
}

// TestSupportPendingSessionTTL: requested/connecting старше 15 минут не
// активны и переводятся cleanup'ом в expired (с удалением).
func TestSupportPendingSessionTTL(t *testing.T) {
	st := sharedTestStore(t)
	ctx := t.Context()
	stale := newSupportSession(t, "requested")
	fresh := newSupportSession(t, "requested")

	if _, err := st.Pool().Exec(ctx,
		`UPDATE support_sessions SET created_at = now() - interval '20 minutes' WHERE id = $1`, stale.ID); err != nil {
		t.Fatalf("backdate created_at: %v", err)
	}

	// Фильтр активных не видит залежавшуюся заявку.
	if _, err := st.SupportSessionActiveByUser(ctx, stale.UserID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stale ActiveByUser: err=%v, want ErrNotFound", err)
	}
	list, err := st.SupportSessionList(ctx, SupportFilter{ActiveOnly: true, Limit: 100})
	if err != nil {
		t.Fatalf("SupportSessionList: %v", err)
	}
	for _, s := range list {
		if s.ID == stale.ID {
			t.Fatal("stale-заявка попала в ActiveOnly-список")
		}
	}
	foundFresh := false
	for _, s := range list {
		if s.ID == fresh.ID {
			foundFresh = true
		}
	}
	if !foundFresh {
		t.Fatal("fresh-заявка не попала в ActiveOnly-список")
	}

	// Cleanup переводит stale в expired и удаляет закрытые.
	if _, err := st.SupportSessionCleanupClosed(ctx); err != nil {
		t.Fatalf("SupportSessionCleanupClosed: %v", err)
	}
	if _, err := st.SupportSessionGet(ctx, stale.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stale после cleanup: err=%v, want ErrNotFound (удалена)", err)
	}
}
