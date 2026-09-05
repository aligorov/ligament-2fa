// Package store — PostgreSQL-слой хранения 2FA-сервера (pgx/v5 + pgxpool).
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// pingTimeout — таймаут проверки подключения при Open.
const pingTimeout = 5 * time.Second

// Store — обёртка над пулом соединений PostgreSQL.
type Store struct {
	pool *pgxpool.Pool
}

// Open создаёт пул соединений по DSN и проверяет его пингом.
// При ошибке пул закрывается и возвращается nil.
func Open(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("store: создать пул соединений: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, pingTimeout)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: пинг БД (таймаут %s): %w", pingTimeout, err)
	}
	return &Store{pool: pool}, nil
}

// Pool возвращает пул pgx для использования репозиториями.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Close закрывает пул и освобождает все соединения.
func (s *Store) Close() { s.pool.Close() }
