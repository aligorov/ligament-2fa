// Репозиторий challenges: выданные коды и push-подтверждения второго фактора.
package store

import (
	"context"
	"encoding/json"
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
	PushState    *string // pending|approved|denied — telegram_push и app_push
	ExpiresAt    time.Time
	AttemptsLeft int
	UsedAt       *time.Time
	Purpose      string // api|radius_prefetch|ui_confirm|webauthn_session|tg_link
	Metadata     map[string]any
	CreatedAt    time.Time
}

// challengeCols — список колонок challenges для SELECT/сканирования.
const challengeCols = `id, user_id, channel, code_hash, push_state, expires_at,
	attempts_left, used_at, purpose, COALESCE(metadata, '{}'::jsonb), created_at`

// scanChallenge сканирует строку challenges (колонки в порядке challengeCols).
func scanChallenge(row scanner) (*Challenge, error) {
	var c Challenge
	var metaBytes []byte
	if err := row.Scan(
		&c.ID, &c.UserID, &c.Channel, &c.CodeHash, &c.PushState,
		&c.ExpiresAt, &c.AttemptsLeft, &c.UsedAt, &c.Purpose, &metaBytes, &c.CreatedAt,
	); err != nil {
		return nil, err
	}
	if len(metaBytes) > 0 {
		_ = json.Unmarshal(metaBytes, &c.Metadata)
	}
	if c.Metadata == nil {
		c.Metadata = make(map[string]any)
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
	if c.Metadata == nil {
		c.Metadata = make(map[string]any)
	}
	metaJSON, _ := json.Marshal(c.Metadata)
	if _, err := s.Pool().Exec(ctx,
		`DELETE FROM challenges WHERE expires_at < now()`); err != nil {
		return fmt.Errorf("store: janitor challenges: %w", err)
	}
	err := s.Pool().QueryRow(ctx, `INSERT INTO challenges
		(id, user_id, channel, code_hash, push_state, expires_at, attempts_left, used_at, purpose, metadata)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		RETURNING created_at`,
		c.ID, c.UserID, c.Channel, c.CodeHash, c.PushState, c.ExpiresAt,
		c.AttemptsLeft, c.UsedAt, c.Purpose, metaJSON).Scan(&c.CreatedAt)
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
// NULL) с purpose из списка purposes, свежие первыми. Purpose-фильтр
// обязателен (SEC-001): код привязки Telegram (tg_link) или подтверждения
// операции в кабинете (ui_confirm) не должен работать как второй фактор
// входа — пустой список purposes означает ошибку программирования.
func (s *Store) ActiveCodeChallenges(ctx context.Context, userID uuid.UUID, purposes ...string) ([]*Challenge, error) {
	if len(purposes) == 0 {
		return nil, errors.New("store: ActiveCodeChallenges: список purposes пуст (изоляция кодов по назначению обязательна)")
	}
	rows, err := s.Pool().Query(ctx, `SELECT `+challengeCols+` FROM challenges
		WHERE user_id = $1 AND expires_at > now() AND used_at IS NULL
		  AND code_hash IS NOT NULL AND purpose = ANY($2)
		ORDER BY created_at DESC`, userID, purposes)
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

// LastPushAt возвращает время последнего push-челленджа пользователя
// (для cooldown/лимита в час); нулевое время, если пушей не было.
func (s *Store) LastPushAt(ctx context.Context, userID uuid.UUID) (time.Time, error) {
	var ts *time.Time
	err := s.Pool().QueryRow(ctx, `SELECT MAX(created_at) FROM challenges
		WHERE user_id = $1 AND channel IN ($2, $3)`, userID, channel.TelegramPush, channel.AppPush).Scan(&ts)
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
		WHERE user_id = $1 AND channel IN ($2, $3) AND created_at > $4`,
		userID, channel.TelegramPush, channel.AppPush, since).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: счёт пушей %s: %w", userID, err)
	}
	return n, nil
}

// ActiveAppPushChallenges возвращает активные непросроченные push-челленджи приложения для пользователя.
func (s *Store) ActiveAppPushChallenges(ctx context.Context, userID uuid.UUID) ([]*Challenge, error) {
	rows, err := s.Pool().Query(ctx, `SELECT `+challengeCols+` FROM challenges
		WHERE user_id = $1 AND channel = $2 AND push_state = 'pending'
		  AND expires_at > now() AND used_at IS NULL
		ORDER BY created_at DESC`, userID, channel.AppPush)
	if err != nil {
		return nil, fmt.Errorf("store: активные app_push челленджи %s: %w", userID, err)
	}
	defer rows.Close()
	var out []*Challenge
	for rows.Next() {
		c, err := scanChallenge(rows)
		if err != nil {
			return nil, fmt.Errorf("store: сканирование app_push челленджа: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
