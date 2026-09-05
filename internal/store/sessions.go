// Репозиторий сессий web-UI (cookie twofa_session).
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SessionCreate создаёт сессию: tokenHash — хеш cookie-токена, срок жизни
// expires_at = now + ttl.
func (s *Store) SessionCreate(ctx context.Context, tokenHash []byte, userID uuid.UUID, csrf string, ttl time.Duration) error {
	_, err := s.Pool().Exec(ctx,
		`INSERT INTO sessions (token_hash, user_id, csrf, expires_at) VALUES ($1, $2, $3, $4)`,
		tokenHash, userID, csrf, time.Now().Add(ttl))
	if err != nil {
		return fmt.Errorf("store: создать сессию: %w", err)
	}
	return nil
}

// SessionGet возвращает пользователя и CSRF-токен по хешу cookie-токена.
// Просроченные сессии не возвращаются (ErrNotFound) — ленивая проверка
// срока без отдельной чистки.
func (s *Store) SessionGet(ctx context.Context, tokenHash []byte) (userID uuid.UUID, csrf string, err error) {
	err = s.Pool().QueryRow(ctx,
		`SELECT user_id, csrf FROM sessions WHERE token_hash = $1 AND expires_at > now()`,
		tokenHash).Scan(&userID, &csrf)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, "", ErrNotFound
	}
	if err != nil {
		return uuid.Nil, "", fmt.Errorf("store: чтение сессии: %w", err)
	}
	return userID, csrf, nil
}

// SessionDelete удаляет сессию по хешу токена; ErrNotFound, если её нет.
func (s *Store) SessionDelete(ctx context.Context, tokenHash []byte) error {
	ct, err := s.Pool().Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1`, tokenHash)
	if err != nil {
		return fmt.Errorf("store: удалить сессию: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SessionDeleteAllForUser завершает все сессии пользователя («выйти на всех
// устройствах»); идемпотентно — отсутствие сессий не ошибка.
func (s *Store) SessionDeleteAllForUser(ctx context.Context, userID uuid.UUID) error {
	_, err := s.Pool().Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID)
	if err != nil {
		return fmt.Errorf("store: удалить сессии %s: %w", userID, err)
	}
	return nil
}
