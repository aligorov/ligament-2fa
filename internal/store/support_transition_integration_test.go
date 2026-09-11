//go:build integration

// Интеграционные тесты серверной таблицы переходов support_sessions:
// атомарные guard'ы хранилища (без HTTP-слоя): повторное подключение к
// завершённой сессии, перехват чужой сессии, transfer только из
// active/transferred, дедупликация живых сессий пользователя, TTL 4 часа
// для active, гашение после перебора number-match.
package store

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

// mustConn — подключение оператора через guard (или падение теста).
func mustConn(t *testing.T, st *Store, id uuid.UUID, actor SupportActor, adminID *uuid.UUID, nm string) {
	t.Helper()
	if err := st.SupportSessionConnect(t.Context(), id, actor, adminID, nm); err != nil {
		t.Fatalf("SupportSessionConnect(%s): %v", id, err)
	}
}

// TestSupportStoreNoResurrect — завершённую сессию нельзя подключить,
// переадресовать, «пере-approve», завершить повторно.
func TestSupportStoreNoResurrect(t *testing.T) {
	st := sharedTestStore(t)
	ctx := t.Context()

	for _, terminal := range []string{"completed", "rejected", "cancelled", "expired", "ended_by_admin"} {
		ss := newSupportSession(t, terminal)
		op := newTestUser(t).ID

		if err := st.SupportSessionConnect(ctx, ss.ID, SupportActorOperator, &op, "42"); !errors.Is(err, ErrInvalidTransition) {
			t.Errorf("connect к %s: err=%v, want ErrInvalidTransition", terminal, err)
		}
		if err := st.SupportSessionApprove(ctx, ss.ID); !errors.Is(err, ErrInvalidTransition) {
			t.Errorf("approve %s: err=%v, want ErrInvalidTransition", terminal, err)
		}
		if err := st.SupportSessionTransfer(ctx, ss.ID, op, nil, []byte("h")); !errors.Is(err, ErrInvalidTransition) {
			t.Errorf("transfer из %s: err=%v, want ErrInvalidTransition", terminal, err)
		}
		if err := st.SupportSessionEnd(ctx, ss.ID, "completed", SupportActorUser); !errors.Is(err, ErrInvalidTransition) {
			t.Errorf("повторный end %s: err=%v, want ErrInvalidTransition", terminal, err)
		}
	}
}

// TestSupportStoreTransferOnlyFromActive — переадресация неподтверждённой
// сессии (requested/connecting) невозможна: transfer-токен не может стать
// обходом подтверждения пользователя.
func TestSupportStoreTransferOnlyFromActive(t *testing.T) {
	st := sharedTestStore(t)
	ctx := t.Context()

	for _, from := range []string{"requested", "connecting"} {
		ss := newSupportSession(t, from)
		op := newTestUser(t).ID
		if err := st.SupportSessionTransfer(ctx, ss.ID, op, nil, []byte("h")); !errors.Is(err, ErrInvalidTransition) {
			t.Errorf("transfer из %s: err=%v, want ErrInvalidTransition", from, err)
		}
	}
}

// TestSupportStoreConnectGuards — connect только к живой pending-сессии;
// чужую (уже занятую другим оператором) подключить нельзя.
func TestSupportStoreConnectGuards(t *testing.T) {
	st := sharedTestStore(t)
	ctx := t.Context()

	// Занятая оператором сессия.
	ss := newSupportSession(t, "requested")
	op1 := newTestUser(t).ID
	op2 := newTestUser(t).ID
	mustConn(t, st, ss.ID, SupportActorOperator, &op1, "11")
	if err := st.SupportSessionConnect(ctx, ss.ID, SupportActorOperator, &op2, "22"); !errors.Is(err, ErrSessionTaken) {
		t.Fatalf("перехват чужой сессии: err=%v, want ErrSessionTaken", err)
	}
	// Тот же оператор может перезапросить код.
	mustConn(t, st, ss.ID, SupportActorOperator, &op1, "33")
	// Админ может перезапросить код без смены владельца.
	mustConn(t, st, ss.ID, SupportActorAdmin, nil, "44")
	got, err := st.SupportSessionGet(ctx, ss.ID)
	if err != nil {
		t.Fatalf("SupportSessionGet: %v", err)
	}
	if got.AssignedAdminID == nil || *got.AssignedAdminID != op1 {
		t.Fatalf("assigned_admin_id перезаписан админом: %v, want %s", got.AssignedAdminID, op1)
	}

	// Подключение к active запрещено: сессия уже подтверждена и занята.
	ssA := newSupportSession(t, "active")
	if err := st.SupportSessionConnect(ctx, ssA.ID, SupportActorOperator, &op1, "55"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("connect к active: err=%v, want ErrInvalidTransition", err)
	}

	// Пользователь не может «подключиться» к сам себе.
	ssU := newSupportSession(t, "requested")
	if err := st.SupportSessionConnect(ctx, ssU.ID, SupportActorUser, &ssU.UserID, "66"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("connect пользователем: err=%v, want ErrInvalidTransition", err)
	}
}

// TestSupportStoreOneLiveSessionPerUser — вторая живая сессия того же
// пользователя не создаётся (partial unique index).
func TestSupportStoreOneLiveSessionPerUser(t *testing.T) {
	st := sharedTestStore(t)
	ctx := t.Context()

	ss := newSupportSession(t, "active")
	dup := &SupportSession{
		UserID: ss.UserID, DeviceID: ss.DeviceID, Category: "it",
		Status: "requested", ProblemSummary: "dup", AccessMode: "view_only",
	}
	if err := st.SupportSessionCreate(ctx, dup); !errors.Is(err, ErrDuplicateSession) {
		t.Fatalf("дубль живой сессии: err=%v, want ErrDuplicateSession", err)
	}

	// После завершения первой — можно создать новую.
	if err := st.SupportSessionEnd(ctx, ss.ID, "completed", SupportActorUser); err != nil {
		t.Fatalf("SupportSessionEnd: %v", err)
	}
	if err := st.SupportSessionCreate(ctx, dup); err != nil {
		t.Fatalf("создание после завершения: %v", err)
	}
}

// TestSupportStoreActiveTTL — active/transferred старше 4 часов
// завершаются автоматикой (sweep) и исчезают из активных фильтров.
func TestSupportStoreActiveTTL(t *testing.T) {
	st := sharedTestStore(t)
	ctx := t.Context()

	ss := newSupportSession(t, "active")
	if _, err := st.Pool().Exec(ctx,
		`UPDATE support_sessions SET started_at = now() - interval '5 hours' WHERE id = $1`, ss.ID); err != nil {
		t.Fatalf("backdate started_at: %v", err)
	}
	if err := st.SupportSessionSweepStale(ctx); err != nil {
		t.Fatalf("SupportSessionSweepStale: %v", err)
	}
	got, err := st.SupportSessionGet(ctx, ss.ID)
	if err != nil {
		t.Fatalf("SupportSessionGet: %v", err)
	}
	if got.Status != "completed" {
		t.Fatalf("active старше 4ч: status=%s, want completed", got.Status)
	}
	if _, err := st.SupportSessionActiveByUser(ctx, ss.UserID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ActiveByUser после TTL: err=%v, want ErrNotFound", err)
	}
}

// TestSupportStoreNumberMatchAttempts — три несовпадения кода гасят сессию.
func TestSupportStoreNumberMatchAttempts(t *testing.T) {
	st := sharedTestStore(t)
	ctx := t.Context()

	ss := newSupportSession(t, "connecting")
	for i := 1; i <= SupportMaxNMAttempts; i++ {
		attempts, err := st.SupportSessionFailNumberMatch(ctx, ss.ID)
		if err != nil {
			t.Fatalf("FailNumberMatch(%d): %v", i, err)
		}
		if attempts != i {
			t.Fatalf("attempts = %d, want %d", attempts, i)
		}
	}
	got, err := st.SupportSessionGet(ctx, ss.ID)
	if err != nil {
		t.Fatalf("SupportSessionGet: %v", err)
	}
	if got.Status != "rejected" {
		t.Fatalf("после %d несовпадений: status=%s, want rejected", SupportMaxNMAttempts, got.Status)
	}
	// Подобрать код к погашенной сессии больше нельзя.
	if err := st.SupportSessionApprove(ctx, ss.ID); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("approve погашенной сессии: err=%v, want ErrInvalidTransition", err)
	}
}

// TestSupportStoreApproveClearsCode — approve гасит number_match и
// фиксирует started_at; access_mode не меняется (неизменяем после approve).
func TestSupportStoreApproveClearsCode(t *testing.T) {
	st := sharedTestStore(t)
	ctx := t.Context()

	ss := newSupportSession(t, "requested")
	op := newTestUser(t).ID
	mustConn(t, st, ss.ID, SupportActorOperator, &op, "77")
	if err := st.SupportSessionApprove(ctx, ss.ID); err != nil {
		t.Fatalf("SupportSessionApprove: %v", err)
	}
	got, err := st.SupportSessionGet(ctx, ss.ID)
	if err != nil {
		t.Fatalf("SupportSessionGet: %v", err)
	}
	if got.Status != "active" || got.NumberMatch != "" || got.StartedAt == nil {
		t.Fatalf("после approve: status=%s nm=%q started=%v", got.Status, got.NumberMatch, got.StartedAt)
	}
	if got.AccessMode != "view_only" {
		t.Fatalf("access_mode изменился при approve: %s, want view_only", got.AccessMode)
	}
}
