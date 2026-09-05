// Репозиторий challenges: выданные коды и push-подтверждения второго фактора.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aligorov/twofa/internal/channel"
)

// Challenge — строка таблицы challenges: один выданный код/пуш.
type Challenge struct {
	ID           uuid.UUID
	UserID       uuid.UUID
	Channel      channel.Channel
	CodeHash     []byte  // nil для channel=totp
	PushState    *string // pending|approved|denied — только telegram_push
	ExpiresAt    time.Time
	AttemptsLeft int
	UsedAt       *time.Time
	Purpose      string // api|radius_prefetch|ui_confirm|webauthn_session|tg_link
	CreatedAt    time.Time
}

// challengeCols — список колонок challenges для SELECT/сканирования.
const challengeCols = `id, user_id, channel, code_hash, push_state, expires_at,
	attempts_left, used_at, purpose, created_at`

// scanChallenge сканирует строку challenges (колонки в порядке challengeCols).
func scanChallenge(row scanner) (*Challenge, error) {
	var c Challenge
	if err := row.Scan(
		&c.ID, &c.UserID, &c.Channel, &c.CodeHash, &c.PushState,
		&c.ExpiresAt, &c.AttemptsLeft, &c.UsedAt, &c.Purpose, &c.CreatedAt,
	); err != nil {
		return nil, err
	}
	return &c, nil
}

// ChallengeCreate сохраняет новый челлендж (ID генерируется при нулевом).
// Попутно выполняется ленивый janitor — удаление всех просроченных челленджей
// (паттерн privacyIDEA), чтобы таблица не росла без отдельной задачи чистки.
func (s *Store) ChallengeCreate(ctx context.Context, c *Challenge) error {
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	if _, err := s.Pool().Exec(ctx,
		`DELETE FROM challenges WHERE expires_at < now()`); err != nil {
		return fmt.Errorf("store: janitor challenges: %w", err)
	}
	err := s.Pool().QueryRow(ctx, `INSERT INTO challenges
		(id, user_id, channel, code_hash, push_state, expires_at, attempts_left, used_at, purpose)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING created_at`,
		c.ID, c.UserID, c.Channel, c.CodeHash, c.PushState, c.ExpiresAt,
		c.AttemptsLeft, c.UsedAt, c.Purpose).Scan(&c.CreatedAt)
	if err != nil {
		return fmt.Errorf("store: создать челлендж: %w", err)
	}
	return nil
}

// ChallengeGet возвращает челлендж по ID; ErrNotFound, если нет.
func (s *Store) ChallengeGet(ctx context.Context, id uuid.UUID) (*Challenge, error) {
	c, err := scanChallenge(s.Pool().QueryRow(ctx,
		`SELECT `+challengeCols+` FROM challenges WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: челлендж %s: %w", id, err)
	}
	return c, nil
}

// ChallengeMarkUsed помечает челлендж использованным — одноразовый claim:
// повторный вызов для уже использованного челленджа даёт ErrNotFound,
// что закрывает гонку двойного использования кода.
func (s *Store) ChallengeMarkUsed(ctx context.Context, id uuid.UUID) error {
	ct, err := s.Pool().Exec(ctx,
		`UPDATE challenges SET used_at = now() WHERE id = $1 AND used_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("store: пометить челлендж %s использованным: %w", id, err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ChallengeDecrAttempt атомарно уменьшает attempts_left на единицу, не опускаясь
// ниже нуля, и возвращает оставшееся число попыток.
func (s *Store) ChallengeDecrAttempt(ctx context.Context, id uuid.UUID) (left int, err error) {
	err = s.Pool().QueryRow(ctx, `UPDATE challenges
		SET attempts_left = GREATEST(attempts_left - 1, 0)
		WHERE id = $1
		RETURNING attempts_left`, id).Scan(&left)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("store: декремент попыток челленджа %s: %w", id, err)
	}
	return left, nil
}

// ChallengeSetPush обновляет состояние push-подтверждения
// (pending|approved|denied); ErrNotFound, если челленджа нет.
func (s *Store) ChallengeSetPush(ctx context.Context, id uuid.UUID, state string) error {
	ct, err := s.Pool().Exec(ctx,
		`UPDATE challenges SET push_state = $2 WHERE id = $1`, id, state)
	if err != nil {
		return fmt.Errorf("store: push_state челленджа %s: %w", id, err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ActiveCodeChallenges возвращает неиспользованные непросроченные кодовые
// челленджи пользователя (expires_at > now, used_at IS NULL, code_hash IS NOT
// NULL), свежие первыми.
func (s *Store) ActiveCodeChallenges(ctx context.Context, userID uuid.UUID) ([]*Challenge, error) {
	rows, err := s.Pool().Query(ctx, `SELECT `+challengeCols+` FROM challenges
		WHERE user_id = $1 AND expires_at > now() AND used_at IS NULL
		  AND code_hash IS NOT NULL
		ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: активные челленджи %s: %w", userID, err)
	}
	defer rows.Close()
	var out []*Challenge
	for rows.Next() {
		c, err := scanChallenge(rows)
		if err != nil {
			return nil, fmt.Errorf("store: активные челленджи %s: %w", userID, err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: активные челленджи %s: %w", userID, err)
	}
	return out, nil
}

// FreshApprovedPush возвращает самый свежий одобренный push пользователя,
// созданный не раньше now-maxAge и ещё не использованный; ErrNotFound, если
// такого нет.
func (s *Store) FreshApprovedPush(ctx context.Context, userID uuid.UUID, maxAge time.Duration) (*Challenge, error) {
	cutoff := time.Now().Add(-maxAge)
	c, err := scanChallenge(s.Pool().QueryRow(ctx, `SELECT `+challengeCols+` FROM challenges
		WHERE user_id = $1 AND channel = $2 AND push_state = 'approved'
		  AND used_at IS NULL AND created_at > $3
		ORDER BY created_at DESC
		LIMIT 1`, userID, channel.TelegramPush, cutoff))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: свежий approved push %s: %w", userID, err)
	}
	return c, nil
}

// LastPushAt возвращает время последнего push-челленджа пользователя
// (для cooldown/лимита в час); нулевое время, если пушей не было.
func (s *Store) LastPushAt(ctx context.Context, userID uuid.UUID) (time.Time, error) {
	var ts *time.Time
	err := s.Pool().QueryRow(ctx, `SELECT MAX(created_at) FROM challenges
		WHERE user_id = $1 AND channel = $2`, userID, channel.TelegramPush).Scan(&ts)
	if err != nil {
		return time.Time{}, fmt.Errorf("store: последний push %s: %w", userID, err)
	}
	if ts == nil {
		return time.Time{}, nil
	}
	return *ts, nil
}

// PushCountSince возвращает число push-челленджей пользователя, созданных
// после since.
func (s *Store) PushCountSince(ctx context.Context, userID uuid.UUID, since time.Time) (int, error) {
	var n int
	err := s.Pool().QueryRow(ctx, `SELECT count(*) FROM challenges
		WHERE user_id = $1 AND channel = $2 AND created_at > $3`,
		userID, channel.TelegramPush, since).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: счёт пушей %s: %w", userID, err)
	}
	return n, nil
}
