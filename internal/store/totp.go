// Репозиторий TOTP-секретов и backup-кодов.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TOTPSave сохраняет (пере)выдачу TOTP-секрета: повторный вызов сбрасывает
// confirmed_at в NULL и last_timestep в 0 — новый секрет требует нового
// подтверждения.
func (s *Store) TOTPSave(ctx context.Context, userID uuid.UUID, secretEnc []byte, digits, period int) error {
	_, err := s.Pool().Exec(ctx, `
		INSERT INTO totp_secrets (user_id, secret_enc, digits, period, confirmed_at, last_timestep)
		VALUES ($1, $2, $3, $4, NULL, 0)
		ON CONFLICT (user_id) DO UPDATE SET
			secret_enc = EXCLUDED.secret_enc,
			digits = EXCLUDED.digits,
			period = EXCLUDED.period,
			confirmed_at = NULL,
			last_timestep = 0`,
		userID, secretEnc, digits, period)
	if err != nil {
		return fmt.Errorf("store: сохранить TOTP-секрет %s: %w", userID, err)
	}
	return nil
}

// TOTPConfirm подтверждает выданный секрет; ErrNotFound, если секрета нет.
func (s *Store) TOTPConfirm(ctx context.Context, userID uuid.UUID) error {
	ct, err := s.Pool().Exec(ctx,
		`UPDATE totp_secrets SET confirmed_at = now() WHERE user_id = $1`, userID)
	if err != nil {
		return fmt.Errorf("store: подтвердить TOTP %s: %w", userID, err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// TOTPGet возвращает секрет пользователя: зашифрованные байты, параметры
// (digits, period), подтверждённость и последний использованный timestep.
func (s *Store) TOTPGet(ctx context.Context, userID uuid.UUID) (secretEnc []byte, digits, period int, confirmed bool, lastTimestep int64, err error) {
	var confirmedAt *time.Time
	err = s.Pool().QueryRow(ctx, `
		SELECT secret_enc, digits, period, confirmed_at, last_timestep
		FROM totp_secrets WHERE user_id = $1`, userID).
		Scan(&secretEnc, &digits, &period, &confirmedAt, &lastTimestep)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, 0, 0, false, 0, ErrNotFound
	}
	if err != nil {
		return nil, 0, 0, false, 0, fmt.Errorf("store: чтение TOTP-секрета %s: %w", userID, err)
	}
	return secretEnc, digits, period, confirmedAt != nil, lastTimestep, nil
}

// TOTPSetTimestep атомарно поднимает last_timestep до ts — только если тот
// СТРОГО больше текущего (compare-and-set). Возвращает advanced=true, когда
// строка обновлена; advanced=false — счётчик уже был ≥ ts (replay кода или
// конкурентный победитель), значение в БД не меняется и не откатывается.
// CAS закрывает гонку записи: две параллельные проверки одного кода окна C
// обе читают last_timestep < C, но UPDATE проходит ровно у одной.
// ErrNotFound, если секрета нет.
func (s *Store) TOTPSetTimestep(ctx context.Context, userID uuid.UUID, ts int64) (bool, error) {
	ct, err := s.Pool().Exec(ctx,
		`UPDATE totp_secrets SET last_timestep = $2 WHERE user_id = $1 AND last_timestep < $2`,
		userID, ts)
	if err != nil {
		return false, fmt.Errorf("store: timestep TOTP %s: %w", userID, err)
	}
	if ct.RowsAffected() == 1 {
		return true, nil
	}
	// Ноль строк: либо секрета нет, либо replay (last_timestep >= ts).
	var exists bool
	if err := s.Pool().QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM totp_secrets WHERE user_id = $1)`, userID).Scan(&exists); err != nil {
		return false, fmt.Errorf("store: timestep TOTP %s: %w", userID, err)
	}
	if !exists {
		return false, ErrNotFound
	}
	return false, nil
}

// TOTPDelete удаляет секрет пользователя; идемпотентно (отсутствие — не ошибка).
func (s *Store) TOTPDelete(ctx context.Context, userID uuid.UUID) error {
	_, err := s.Pool().Exec(ctx, `DELETE FROM totp_secrets WHERE user_id = $1`, userID)
	if err != nil {
		return fmt.Errorf("store: удалить TOTP-секрет %s: %w", userID, err)
	}
	return nil
}

// BackupReplace атомарно заменяет резервные коды пользователя: старые
// удаляются, новые вставляются одной транзакцией.
func (s *Store) BackupReplace(ctx context.Context, userID uuid.UUID, hashes [][]byte) error {
	tx, err := s.Pool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: замена backup-кодов %s: начать транзакцию: %w", userID, err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx,
		`DELETE FROM backup_codes WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("store: замена backup-кодов %s: удалить старые: %w", userID, err)
	}
	for i, h := range hashes {
		if _, err := tx.Exec(ctx,
			`INSERT INTO backup_codes (user_id, code_hash) VALUES ($1, $2)`, userID, h); err != nil {
			return fmt.Errorf("store: замена backup-кодов %s: вставка %d: %w", userID, i, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: замена backup-кодов %s: коммит: %w", userID, err)
	}
	return nil
}

// BackupConsume атомарно потребляет код: помечает used_at = now() только если
// код принадлежит пользователю и ещё не использован; true — если строка
// обновлена (повторное потребление того же кода даёт false).
func (s *Store) BackupConsume(ctx context.Context, userID uuid.UUID, hash []byte) (bool, error) {
	ct, err := s.Pool().Exec(ctx, `UPDATE backup_codes SET used_at = now()
		WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL`, userID, hash)
	if err != nil {
		return false, fmt.Errorf("store: потребление backup-кода %s: %w", userID, err)
	}
	return ct.RowsAffected() == 1, nil
}
