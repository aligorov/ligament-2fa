//go:build integration

// Общая тестовая инфраструктура репозиториев: один postgres-контейнер
// (testcontainers, postgres:16-alpine) на весь прогон пакета — ленивый запуск
// при первом обращении и остановка в TestMain. Без Docker тесты пропускаются
// (как в migrate_test.go).
package store

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	sharedOnce  sync.Once
	sharedPG    *tcpostgres.PostgresContainer
	sharedStore *Store
	sharedErr   error
)

// sharedTestStore возвращает хранилище с применённой схемой; пропускает тест,
// если Docker недоступен.
func sharedTestStore(t *testing.T) *Store {
	t.Helper()
	if !dockerAvailable() {
		t.Skip("docker недоступен (docker info завершается с ошибкой) — интеграционный тест пропущен")
	}
	sharedOnce.Do(startSharedStore)
	if sharedErr != nil {
		t.Fatalf("подготовка общей тестовой БД: %v", sharedErr)
	}
	return sharedStore
}

// startSharedStore поднимает контейнер, открывает пул и применяет миграции.
func startSharedStore() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	pg, err := tcpostgres.RunContainer(ctx,
		testcontainers.WithImage("postgres:16-alpine"),
		tcpostgres.WithDatabase("twofa"),
		tcpostgres.WithUsername("twofa"),
		tcpostgres.WithPassword("twofa"),
		// postgres:*-alpine при initdb поднимает временный сервер, печатает
		// ready-сообщение и перезапускается — ждём второе вхождение.
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		sharedErr = err
		return
	}
	dsn, err := pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		sharedErr = err
		return
	}
	st, err := Open(ctx, dsn)
	if err != nil {
		sharedErr = err
		return
	}
	if err := st.Migrate(ctx); err != nil {
		st.Close()
		sharedErr = err
		return
	}
	sharedPG, sharedStore = pg, st
}

// TestMain закрывает пул и останавливает контейнер после всех тестов пакета.
func TestMain(m *testing.M) {
	code := m.Run()
	if sharedStore != nil {
		sharedStore.Close()
	}
	if sharedPG != nil {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := sharedPG.Terminate(stopCtx); err != nil {
			os.Stderr.WriteString("остановка тестового контейнера: " + err.Error() + "\n")
		}
		cancel()
	}
	os.Exit(code)
}

// newTestUser создаёт пользователя с уникальным username. Хеш пароля —
// дешёвая константа: репозиторий проверяет только хранение, не криптографию.
func newTestUser(t *testing.T) *User {
	t.Helper()
	st := sharedTestStore(t)
	u := &User{
		Username:     "t-" + uuid.NewString()[:12],
		PasswordHash: "$argon2id$test",
		Role:         "user",
		Enabled:      true,
		Email:        "user@example.com",
		Phone:        "+70000000000",
	}
	if err := st.UserCreate(t.Context(), u); err != nil {
		t.Fatalf("создание тестового пользователя: %v", err)
	}
	return u
}
