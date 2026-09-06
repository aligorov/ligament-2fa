//go:build integration

// Интеграционные тесты репозитория challenges: жизненный цикл кода,
// ленивый janitor, push-запросы (telegram_push).
package store

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/aligorov/twofa/internal/channel"
)

// sptr — хелпер для *string.
func sptr(s string) *string { return &s }

// newCodeChallenge — валидный кодовый челлендж со случайным code_hash
// (колонка code_hash глобально UNIQUE).
func newCodeChallenge(t *testing.T, userID uuid.UUID) *Challenge {
	t.Helper()
	return &Challenge{
		UserID:       userID,
		Channel:      channel.Email,
		CodeHash:     []byte("hash-" + uuid.NewString()[:12]),
		ExpiresAt:    time.Now().Add(10 * time.Minute),
		AttemptsLeft: 3,
		Purpose:      "api",
	}
}

func TestChallengeLifecycleIntegration(t *testing.T) {
	st := sharedTestStore(t)
	ctx := t.Context()
	u := newTestUser(t)

	c := newCodeChallenge(t, u.ID)
	if err := st.ChallengeCreate(ctx, c); err != nil {
		t.Fatalf("ChallengeCreate: %v", err)
	}
	if c.ID == uuid.Nil {
		t.Fatal("ID не проставлен")
	}
	if c.CreatedAt.IsZero() {
		t.Fatal("CreatedAt не проставлен")
	}

	got, err := st.ChallengeGet(ctx, c.ID)
	if err != nil {
		t.Fatalf("ChallengeGet: %v", err)
	}
	if got.UserID != u.ID || got.Channel != channel.Email ||
		string(got.CodeHash) != string(c.CodeHash) || got.PushState != nil ||
		got.AttemptsLeft != 3 || got.UsedAt != nil || got.Purpose != "api" {
		t.Fatalf("ChallengeGet вернул %+v", got)
	}

	// Декремент попыток до нуля; дальше — floor 0.
	for want := 2; want >= 0; want-- {
		left, err := st.ChallengeDecrAttempt(ctx, c.ID)
		if err != nil {
			t.Fatalf("ChallengeDecrAttempt: %v", err)
		}
		if left != want {
			t.Fatalf("ChallengeDecrAttempt: left=%d, want %d", left, want)
		}
	}
	if left, err := st.ChallengeDecrAttempt(ctx, c.ID); err != nil || left != 0 {
		t.Fatalf("floor на нуле: left=%d err=%v, want 0 nil", left, err)
	}

	// Использование — одноразовый claim.
	if err := st.ChallengeMarkUsed(ctx, c.ID); err != nil {
		t.Fatalf("ChallengeMarkUsed: %v", err)
	}
	if err := st.ChallengeMarkUsed(ctx, c.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("повторный MarkUsed: err=%v, want ErrNotFound", err)
	}
	used, err := st.ChallengeGet(ctx, c.ID)
	if err != nil {
		t.Fatalf("ChallengeGet после mark used: %v", err)
	}
	if used.UsedAt == nil {
		t.Fatal("used_at не проставлен")
	}
}

func TestChallengeNotFoundIntegration(t *testing.T) {
	st := sharedTestStore(t)
	ctx := t.Context()
	id := uuid.New()
	if _, err := st.ChallengeGet(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Errorf("ChallengeGet: err=%v, want ErrNotFound", err)
	}
	if _, err := st.ChallengeDecrAttempt(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Errorf("ChallengeDecrAttempt: err=%v, want ErrNotFound", err)
	}
	if err := st.ChallengeMarkUsed(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Errorf("ChallengeMarkUsed: err=%v, want ErrNotFound", err)
	}
	if err := st.ChallengeSetPush(ctx, id, "approved"); !errors.Is(err, ErrNotFound) {
		t.Errorf("ChallengeSetPush: err=%v, want ErrNotFound", err)
	}
}

func TestActiveCodeChallengesIntegration(t *testing.T) {
	st := sharedTestStore(t)
	ctx := t.Context()
	u := newTestUser(t)
	future := time.Now().Add(10 * time.Minute)

	live := newCodeChallenge(t, u.ID)
	if err := st.ChallengeCreate(ctx, live); err != nil {
		t.Fatalf("создание live: %v", err)
	}

	usedC := newCodeChallenge(t, u.ID)
	if err := st.ChallengeCreate(ctx, usedC); err != nil {
		t.Fatalf("создание used: %v", err)
	}
	if err := st.ChallengeMarkUsed(ctx, usedC.ID); err != nil {
		t.Fatalf("mark used: %v", err)
	}

	// expired создаём с будущим expires_at: ленивый janitor внутри каждого
	// ChallengeCreate (DELETE ... WHERE expires_at < now()) не должен выметать
	// строку до вызова ActiveCodeChallenges. Просроченным её делаем прямым
	// UPDATE уже после всех созданий (ниже) — иначе проверка исключения
	// vacuous: janitor следующих созданий удалял бы строку до запроса.
	expired := newCodeChallenge(t, u.ID)
	if err := st.ChallengeCreate(ctx, expired); err != nil {
		t.Fatalf("создание expired: %v", err)
	}

	totp := &Challenge{UserID: u.ID, Channel: channel.TOTP,
		ExpiresAt: future, AttemptsLeft: 3, Purpose: "api"}
	if err := st.ChallengeCreate(ctx, totp); err != nil {
		t.Fatalf("создание totp: %v", err)
	}

	push := &Challenge{UserID: u.ID, Channel: channel.TelegramPush,
		PushState: sptr("pending"), ExpiresAt: future, AttemptsLeft: 1, Purpose: "api"}
	if err := st.ChallengeCreate(ctx, push); err != nil {
		t.Fatalf("создание push: %v", err)
	}

	// Все создания позади — janitor больше не запустится. Делаем expired
	// просроченным прямым UPDATE (паттерн как с created_at выше): строка
	// гарантированно остаётся в таблице, и исключить её обязан сам запрос
	// ActiveCodeChallenges через условие expires_at > now().
	if _, err := st.Pool().Exec(ctx,
		`UPDATE challenges SET expires_at = now() - make_interval(secs => $1) WHERE id = $2`,
		(1 * time.Minute).Seconds(), expired.ID); err != nil {
		t.Fatalf("backdate expires_at: %v", err)
	}
	// Предусловие: просроченная строка физически лежит в таблице.
	if got, err := st.ChallengeGet(ctx, expired.ID); err != nil {
		t.Fatalf("просроченный челлендж должен лежать в таблице до запроса: %v", err)
	} else if !got.ExpiresAt.Before(time.Now()) {
		t.Fatalf("expires_at = %v, want в прошлом", got.ExpiresAt)
	}

	list, err := st.ActiveCodeChallenges(ctx, u.ID, "api")
	if err != nil {
		t.Fatalf("ActiveCodeChallenges: %v", err)
	}
	if len(list) != 1 || list[0].ID != live.ID {
		t.Fatalf("ActiveCodeChallenges: %d шт. (%v), want только live %s",
			len(list), list, live.ID)
	}

	// Purpose-фильтр (SEC-001): код чужого purpose не возвращается.
	if _, err := st.ActiveCodeChallenges(ctx, u.ID, "ui_confirm"); err != nil {
		t.Fatalf("ActiveCodeChallenges(ui_confirm): %v", err)
	} else if got, err := st.ActiveCodeChallenges(ctx, u.ID, "ui_confirm"); err != nil || len(got) != 0 {
		t.Fatalf("ActiveCodeChallenges(ui_confirm): %d шт. (err %v), want 0", len(got), err)
	}
	if got, err := st.ActiveCodeChallenges(ctx, u.ID, "tg_link"); err != nil || len(got) != 0 {
		t.Fatalf("ActiveCodeChallenges(tg_link): %d шт. (err %v), want 0", len(got), err)
	}
	if got, err := st.ActiveCodeChallenges(ctx, u.ID, "ui_confirm", "radius_prefetch"); err != nil || len(got) != 0 {
		t.Fatalf("ActiveCodeChallenges(набор без api): %d шт. (err %v), want 0", len(got), err)
	}

	// Пустой набор purposes — программная ошибка (изоляция обязательна).
	if _, err := st.ActiveCodeChallenges(ctx, u.ID); err == nil {
		t.Fatal("ActiveCodeChallenges без purposes: err=nil, want ошибка")
	}

	// Челлендж другого purpose возвращаетcя только своим фильтром.
	ui := newCodeChallenge(t, u.ID)
	ui.Purpose = "ui_confirm"
	if err := st.ChallengeCreate(ctx, ui); err != nil {
		t.Fatalf("создание ui_confirm: %v", err)
	}
	if got, err := st.ActiveCodeChallenges(ctx, u.ID, "ui_confirm"); err != nil || len(got) != 1 || got[0].ID != ui.ID {
		t.Fatalf("ActiveCodeChallenges(ui_confirm) после вставки: %d шт. (err %v), want ui %s", len(got), err, ui.ID)
	}
	if got, err := st.ActiveCodeChallenges(ctx, u.ID, "api", "ui_confirm"); err != nil || len(got) != 2 {
		t.Fatalf("ActiveCodeChallenges(api+ui_confirm): %d шт. (err %v), want 2", len(got), err)
	}
}

func TestChallengeJanitorIntegration(t *testing.T) {
	st := sharedTestStore(t)
	ctx := t.Context()
	u := newTestUser(t)

	expired := newCodeChallenge(t, u.ID)
	expired.ExpiresAt = time.Now().Add(-time.Minute)
	if err := st.ChallengeCreate(ctx, expired); err != nil {
		t.Fatalf("создание просроченного челленджа: %v", err)
	}
	if _, err := st.ChallengeGet(ctx, expired.ID); err != nil {
		t.Fatalf("просроченный существует до janitor: %v", err)
	}

	// Любое следующее создание запускает janitor и выметает просроченные.
	if err := st.ChallengeCreate(ctx, newCodeChallenge(t, u.ID)); err != nil {
		t.Fatalf("ChallengeCreate после просроченного: %v", err)
	}
	if _, err := st.ChallengeGet(ctx, expired.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("после janitor: err=%v, want ErrNotFound", err)
	}
}

func TestChallengeSetPushIntegration(t *testing.T) {
	st := sharedTestStore(t)
	ctx := t.Context()
	u := newTestUser(t)

	push := &Challenge{UserID: u.ID, Channel: channel.TelegramPush,
		PushState: sptr("pending"), ExpiresAt: time.Now().Add(10 * time.Minute),
		AttemptsLeft: 1, Purpose: "api"}
	if err := st.ChallengeCreate(ctx, push); err != nil {
		t.Fatalf("ChallengeCreate: %v", err)
	}
	if err := st.ChallengeSetPush(ctx, push.ID, "approved"); err != nil {
		t.Fatalf("ChallengeSetPush: %v", err)
	}
	got, err := st.ChallengeGet(ctx, push.ID)
	if err != nil {
		t.Fatalf("ChallengeGet: %v", err)
	}
	if got.PushState == nil || *got.PushState != "approved" {
		t.Fatalf("push_state = %v, want approved", got.PushState)
	}
}

func TestLastPushAtIntegration(t *testing.T) {
	st := sharedTestStore(t)
	ctx := t.Context()

	u1 := newTestUser(t)
	mk := func() uuid.UUID {
		c := &Challenge{UserID: u1.ID, Channel: channel.TelegramPush,
			PushState: sptr("pending"), ExpiresAt: time.Now().Add(time.Hour),
			AttemptsLeft: 1, Purpose: "api"}
		if err := st.ChallengeCreate(ctx, c); err != nil {
			t.Fatalf("создание push: %v", err)
		}
		return c.ID
	}
	old := mk()
	if _, err := st.Pool().Exec(ctx,
		`UPDATE challenges SET created_at = now() - make_interval(secs => $1) WHERE id = $2`,
		(10 * time.Minute).Seconds(), old); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	mk() // свежий

	last, err := st.LastPushAt(ctx, u1.ID)
	if err != nil {
		t.Fatalf("LastPushAt: %v", err)
	}
	if last.Before(time.Now().Add(-time.Minute)) {
		t.Fatalf("LastPushAt = %v, want недавнее now()", last)
	}

	u2 := newTestUser(t)
	zero, err := st.LastPushAt(ctx, u2.ID)
	if err != nil {
		t.Fatalf("LastPushAt без пушей: %v", err)
	}
	if !zero.IsZero() {
		t.Fatalf("LastPushAt без пушей = %v, want zero", zero)
	}
}

func TestPushCountSinceIntegration(t *testing.T) {
	st := sharedTestStore(t)
	ctx := t.Context()
	u := newTestUser(t)

	var ids []uuid.UUID
	for i := 0; i < 3; i++ {
		c := &Challenge{UserID: u.ID, Channel: channel.TelegramPush,
			PushState: sptr("pending"), ExpiresAt: time.Now().Add(time.Hour),
			AttemptsLeft: 1, Purpose: "api"}
		if err := st.ChallengeCreate(ctx, c); err != nil {
			t.Fatalf("создание push: %v", err)
		}
		ids = append(ids, c.ID)
	}
	for _, id := range ids[:2] {
		if _, err := st.Pool().Exec(ctx,
			`UPDATE challenges SET created_at = now() - make_interval(secs => $1) WHERE id = $2`,
			(2 * time.Hour).Seconds(), id); err != nil {
			t.Fatalf("backdate: %v", err)
		}
	}

	n, err := st.PushCountSince(ctx, u.ID, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("PushCountSince(-1h): %v", err)
	}
	if n != 1 {
		t.Fatalf("PushCountSince(-1h) = %d, want 1", n)
	}
	n, err = st.PushCountSince(ctx, u.ID, time.Now().Add(-3*time.Hour))
	if err != nil {
		t.Fatalf("PushCountSince(-3h): %v", err)
	}
	if n != 3 {
		t.Fatalf("PushCountSince(-3h) = %d, want 3", n)
	}
}
