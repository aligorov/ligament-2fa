package store

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/aligorov/twofa/migrations"
)

// migrationsFS — встроенные миграции (переменная для подстановки в тестах).
var migrationsFS fs.FS = migrations.FS

// errDuplicateVersion — две миграции с одинаковой числовой версией.
var errDuplicateVersion = errors.New("дубликат версии миграции")

// migration — одна SQL-миграция, извлечённая из встроенного FS.
type migration struct {
	version int    // числовая версия из префикса имени файла
	name    string // имя файла
	sql     string // тело миграции
}

// parseMigrations читает *.sql из fsys, валидирует имена вида NNNN_*.sql,
// сортирует по числовой версии и отклоняет дубликаты версий.
func parseMigrations(fsys fs.FS) ([]migration, error) {
	entries, err := fs.Glob(fsys, "*.sql")
	if err != nil {
		return nil, fmt.Errorf("store: выборка миграций: %w", err)
	}
	migs := make([]migration, 0, len(entries))
	for _, name := range entries {
		underscore := strings.IndexByte(name, '_')
		if underscore <= 0 {
			return nil, fmt.Errorf("store: имя миграции %q: ожидается префикс-версия NNNN_", name)
		}
		version, err := strconv.Atoi(name[:underscore])
		if err != nil {
			return nil, fmt.Errorf("store: имя миграции %q: версия не является числом: %w", name, err)
		}
		body, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, fmt.Errorf("store: чтение миграции %s: %w", name, err)
		}
		migs = append(migs, migration{version: version, name: name, sql: string(body)})
	}
	sort.Slice(migs, func(i, j int) bool { return migs[i].version < migs[j].version })
	seen := make(map[int]struct{}, len(migs))
	for _, m := range migs {
		if _, dup := seen[m.version]; dup {
			return nil, fmt.Errorf("store: %w: %d (%s)", errDuplicateVersion, m.version, m.name)
		}
		seen[m.version] = struct{}{}
	}
	return migs, nil
}

// Migrate применяет все неприменённые миграции из встроенного FS в порядке
// версий. Прогон идемпотентен: повторный вызов не применяет ничего нового.
// Каждая миграция выполняется в отдельной транзакции вместе с записью её
// версии в schema_migrations — при сбое миграция целиком откатывается.
func (s *Store) Migrate(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version INT PRIMARY KEY,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		return fmt.Errorf("store: создать schema_migrations: %w", err)
	}

	migs, err := parseMigrations(migrationsFS)
	if err != nil {
		return err
	}

	applied := make(map[int]struct{})
	rows, err := s.pool.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("store: чтение schema_migrations: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return fmt.Errorf("store: разбор schema_migrations: %w", err)
		}
		applied[v] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("store: schema_migrations: %w", err)
	}

	for _, m := range migs {
		if _, ok := applied[m.version]; ok {
			continue
		}
		if err := s.applyMigration(ctx, m); err != nil {
			return err
		}
	}
	return nil
}

// applyMigration выполняет одну миграцию атомарно: SQL + запись версии.
func (s *Store) applyMigration(ctx context.Context, m migration) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: миграция %d (%s): начать транзакцию: %w", m.version, m.name, err)
	}
	defer tx.Rollback(ctx)

	// Exec без аргументов использует простой протокол и допускает
	// несколько операторов в одном вызове.
	if _, err := tx.Exec(ctx, m.sql); err != nil {
		return fmt.Errorf("store: миграция %d (%s): %w", m.version, m.name, err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, m.version); err != nil {
		return fmt.Errorf("store: миграция %d (%s): запись версии: %w", m.version, m.name, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: миграция %d (%s): коммит: %w", m.version, m.name, err)
	}
	return nil
}
