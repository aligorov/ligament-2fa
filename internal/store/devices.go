// Репозиторий доверенных устройств (cookie twofa_device).
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Device — доверенное устройство (строка trusted_devices).
type Device struct {
	ID         int64
	UserID     uuid.UUID
	TokenHash  []byte
	UA         string
	IP         string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
}

// deviceCols — список колонок trusted_devices для SELECT/сканирования;
// nullable ua/ip читаются как пустые строки.
const deviceCols = `id, user_id, token_hash, COALESCE(ua, ''), COALESCE(ip, ''),
	created_at, last_seen_at, expires_at`

// scanDevice сканирует строку trusted_devices (колонки в порядке deviceCols).
func scanDevice(row scanner) (*Device, error) {
	var d Device
	if err := row.Scan(
		&d.ID, &d.UserID, &d.TokenHash, &d.UA, &d.IP,
		&d.CreatedAt, &d.LastSeenAt, &d.ExpiresAt,
	); err != nil {
		return nil, err
	}
	return &d, nil
}

// DeviceCreate создаёт доверенное устройство; ID/created_at/last_seen_at
// заполняются из БД (RETURNING).
func (s *Store) DeviceCreate(ctx context.Context, d *Device) error {
	err := s.Pool().QueryRow(ctx, `INSERT INTO trusted_devices
		(user_id, token_hash, ua, ip, expires_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at, last_seen_at`,
		d.UserID, d.TokenHash, d.UA, d.IP, d.ExpiresAt).
		Scan(&d.ID, &d.CreatedAt, &d.LastSeenAt)
	if err != nil {
		return fmt.Errorf("store: создать доверенное устройство: %w", err)
	}
	return nil
}

// DeviceGet возвращает действующее (не просроченное) устройство по хешу
// токена из cookie; просроченное или отсутствующее — ErrNotFound.
func (s *Store) DeviceGet(ctx context.Context, tokenHash []byte) (*Device, error) {
	d, err := scanDevice(s.Pool().QueryRow(ctx, `SELECT `+deviceCols+` FROM trusted_devices
		WHERE token_hash = $1 AND expires_at > now()`, tokenHash))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: доверенное устройство: %w", err)
	}
	return d, nil
}

// DeviceTouch обновляет last_seen_at устройства; ErrNotFound, если его нет.
func (s *Store) DeviceTouch(ctx context.Context, tokenHash []byte) error {
	ct, err := s.Pool().Exec(ctx,
		`UPDATE trusted_devices SET last_seen_at = now() WHERE token_hash = $1`, tokenHash)
	if err != nil {
		return fmt.Errorf("store: touch доверенного устройства: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeviceDelete отзывает устройство; userID — проверка принадлежности
// (пользователь не может удалить чужое); ErrNotFound, если не найдено.
func (s *Store) DeviceDelete(ctx context.Context, id int64, userID uuid.UUID) error {
	ct, err := s.Pool().Exec(ctx,
		`DELETE FROM trusted_devices WHERE id = $1 AND user_id = $2`, id, userID)
	if err != nil {
		return fmt.Errorf("store: удалить доверенное устройство %d: %w", id, err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeviceListForUser возвращает действующие устройства пользователя,
// старые первыми (по created_at).
func (s *Store) DeviceListForUser(ctx context.Context, userID uuid.UUID) ([]*Device, error) {
	rows, err := s.Pool().Query(ctx, `SELECT `+deviceCols+` FROM trusted_devices
		WHERE user_id = $1 AND expires_at > now()
		ORDER BY created_at, id`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: список доверенных устройств %s: %w", userID, err)
	}
	defer rows.Close()
	var out []*Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, fmt.Errorf("store: список доверенных устройств %s: %w", userID, err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: список доверенных устройств %s: %w", userID, err)
	}
	return out, nil
}

// DeviceDeleteAllForUser отзывает все устройства пользователя; идемпотентно.
func (s *Store) DeviceDeleteAllForUser(ctx context.Context, userID uuid.UUID) error {
	_, err := s.Pool().Exec(ctx, `DELETE FROM trusted_devices WHERE user_id = $1`, userID)
	if err != nil {
		return fmt.Errorf("store: удалить доверенные устройства %s: %w", userID, err)
	}
	return nil
}
