//go:build integration

// Интеграционные тесты TOTP-секретов и backup-кодов.
package store

import (
	"bytes"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestTOTPLifecycleIntegration(t *testing.T) {
	st := sharedTestStore(t)
	ctx := t.Context()
	u := newTestUser(t)

	// Без секрета — ErrNotFound.
	if _, _, _, _, _, err := st.TOTPGet(ctx, u.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("TOTPGet без секрета: err=%v, want ErrNotFound", err)
	}

	secret := []byte("enc-secret-1")
	if err := st.TOTPSave(ctx, u.ID, secret, 6, 30); err != nil {
		t.Fatalf("TOTPSave: %v", err)
	}
	got, digits, period, confirmed, ts, err := st.TOTPGet(ctx, u.ID)
	if err != nil {
		t.Fatalf("TOTPGet: %v", err)
	}
	if !bytes.Equal(got, secret) || digits != 6 || period != 30 || confirmed || ts != 0 {
		t.Fatalf("TOTPGet: %q %d %d %v %d", got, digits, period, confirmed, ts)
	}

	// Подтверждение.
	if err := st.TOTPConfirm(ctx, u.ID); err != nil {
		t.Fatalf("TOTPConfirm: %v", err)
	}
	if _, _, _, confirmed, _, err := st.TOTPGet(ctx, u.ID); err != nil || !confirmed {
		t.Fatalf("после Confirm: confirmed=%v err=%v, want true nil", confirmed, err)
	}

	// Повторная выдача сбрасывает подтверждение, timestep и секрет.
	if err := st.TOTPSave(ctx, u.ID, []byte("enc-secret-2"), 8, 60); err != nil {
		t.Fatalf("повторная TOTPSave: %v", err)
	}
	got, digits, period, confirmed, ts, err = st.TOTPGet(ctx, u.ID)
	if err != nil {
		t.Fatalf("TOTPGet после re-save: %v", err)
	}
	if !bytes.Equal(got, []byte("enc-secret-2")) || digits != 8 || period != 60 || confirmed || ts != 0 {
		t.Fatalf("после re-save: %q %d %d %v %d", got, digits, period, confirmed, ts)
	}

	// Подтверждение без секрета — ErrNotFound.
	u2 := newTestUser(t)
	if err := st.TOTPConfirm(ctx, u2.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("TOTPConfirm без секрета: err=%v, want ErrNotFound", err)
	}

	// Удаление — идемпотентно.
	if err := st.TOTPDelete(ctx, u.ID); err != nil {
		t.Fatalf("TOTPDelete: %v", err)
	}
	if _, _, _, _, _, err := st.TOTPGet(ctx, u.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("TOTPGet после delete: err=%v, want ErrNotFound", err)
	}
	if err := st.TOTPDelete(ctx, u.ID); err != nil {
		t.Fatalf("повторный TOTPDelete: %v", err)
	}
}

func TestTOTPSetTimestepGreatestIntegration(t *testing.T) {
	st := sharedTestStore(t)
	ctx := t.Context()
	u := newTestUser(t)
	if err := st.TOTPSave(ctx, u.ID, []byte("s"), 6, 30); err != nil {
		t.Fatalf("TOTPSave: %v", err)
	}

	steps := []struct {
		set  int64
		want int64
	}{
		{42, 42},
		{7, 42}, // не уменьшается
		{100, 100},
	}
	for _, step := range steps {
		if err := st.TOTPSetTimestep(ctx, u.ID, step.set); err != nil {
			t.Fatalf("TOTPSetTimestep(%d): %v", step.set, err)
		}
		_, _, _, _, got, err := st.TOTPGet(ctx, u.ID)
		if err != nil {
			t.Fatalf("TOTPGet: %v", err)
		}
		if got != step.want {
			t.Fatalf("после SetTimestep(%d) last_timestep=%d, want %d", step.set, got, step.want)
		}
	}

	// SetTimestep без секрета — ErrNotFound.
	u2 := newTestUser(t)
	if err := st.TOTPSetTimestep(ctx, u2.ID, 5); !errors.Is(err, ErrNotFound) {
		t.Fatalf("TOTPSetTimestep без секрета: err=%v, want ErrNotFound", err)
	}
}

func TestBackupCodesIntegration(t *testing.T) {
	st := sharedTestStore(t)
	ctx := t.Context()
	u := newTestUser(t)

	uniq := func() []byte { return []byte("bk-" + uuid.NewString()[:12]) }

	// Замена пачкой.
	hashes := [][]byte{uniq(), uniq(), uniq()}
	if err := st.BackupReplace(ctx, u.ID, hashes); err != nil {
		t.Fatalf("BackupReplace: %v", err)
	}
	// Каждый код потребляем ровно один раз.
	for i, h := range hashes {
		ok, err := st.BackupConsume(ctx, u.ID, h)
		if err != nil || !ok {
			t.Fatalf("BackupConsume #%d: ok=%v err=%v, want true nil", i, ok, err)
		}
	}
	// Повторное потребление того же кода — false.
	ok, err := st.BackupConsume(ctx, u.ID, hashes[0])
	if err != nil || ok {
		t.Fatalf("повторное BackupConsume: ok=%v err=%v, want false nil", ok, err)
	}
	// Неизвестный хеш — false.
	ok, err = st.BackupConsume(ctx, u.ID, uniq())
	if err != nil || ok {
		t.Fatalf("BackupConsume(неизвестный): ok=%v err=%v, want false nil", ok, err)
	}
	// Код другого пользователя не подходит.
	u2 := newTestUser(t)
	foreign := uniq()
	if err := st.BackupReplace(ctx, u2.ID, [][]byte{foreign}); err != nil {
		t.Fatalf("BackupReplace(u2): %v", err)
	}
	ok, err = st.BackupConsume(ctx, u2.ID, hashes[1])
	if err != nil || ok {
		t.Fatalf("чужой код: ok=%v err=%v, want false nil", ok, err)
	}

	// Полная замена: старые (не потреблённые) больше не действуют.
	u3 := newTestUser(t)
	old := uniq()
	if err := st.BackupReplace(ctx, u3.ID, [][]byte{old}); err != nil {
		t.Fatalf("BackupReplace(u3, old): %v", err)
	}
	fresh := uniq()
	if err := st.BackupReplace(ctx, u3.ID, [][]byte{fresh}); err != nil {
		t.Fatalf("BackupReplace(u3, fresh): %v", err)
	}
	if ok, _ := st.BackupConsume(ctx, u3.ID, old); ok {
		t.Fatal("заменённый код всё ещё действителен")
	}
	if ok, err := st.BackupConsume(ctx, u3.ID, fresh); err != nil || !ok {
		t.Fatalf("новый код: ok=%v err=%v, want true nil", ok, err)
	}

	// Пустая замена удаляет все коды.
	if err := st.BackupReplace(ctx, u3.ID, nil); err != nil {
		t.Fatalf("BackupReplace(nil): %v", err)
	}
	if ok, _ := st.BackupConsume(ctx, u3.ID, fresh); ok {
		t.Fatal("код действителен после пустой замены")
	}

	// Потребление без кодов — false, без ошибки.
	u4 := newTestUser(t)
	if ok, err := st.BackupConsume(ctx, u4.ID, uniq()); err != nil || ok {
		t.Fatalf("BackupConsume без кодов: ok=%v err=%v, want false nil", ok, err)
	}
}
