//go:build integration

// Интеграционный тест миграций: требует Docker (testcontainers-go, postgres:16-alpine).
// Запуск: go test -tags integration ./internal/store/
package store

import (
	"context"
	"io/fs"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/aligorov/twofa/migrations"
)

// schemaTables — таблицы, создаваемые миграцией 0001 (спека §5).
var schemaTables = []string{
	"users",
	"totp_secrets",
	"backup_codes",
	"challenges",
	"sessions",
	"settings",
	"audit_log",
	"trusted_devices",
	"webauthn_credentials",
}

func dockerAvailable() bool {
	return exec.Command("docker", "info").Run() == nil
}

func TestMigrateIntegration(t *testing.T) {
	if !dockerAvailable() {
		t.Skip("docker недоступен (docker info завершается с ошибкой) — интеграционный тест пропущен")
	}

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
		t.Fatalf("запуск testcontainer postgres: %v", err)
	}
	defer func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer stopCancel()
		if err := pg.Terminate(stopCtx); err != nil {
			t.Logf("остановка контейнера: %v", err)
		}
	}()

	dsn, err := pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("получение DSN: %v", err)
	}

	st, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	// Первый прогон: применяет все миграции без ошибок.
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("первый Migrate: %v", err)
	}

	// Таблица учёта миграций существует.
	var exists bool
	err = st.Pool().QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables
		 WHERE table_schema = 'public' AND table_name = 'schema_migrations')`,
	).Scan(&exists)
	if err != nil {
		t.Fatalf("information_schema(schema_migrations): %v", err)
	}
	if !exists {
		t.Fatal("таблица schema_migrations не создана")
	}

	// Все таблицы схемы существуют.
	for _, tbl := range schemaTables {
		err := st.Pool().QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM information_schema.tables
			 WHERE table_schema = 'public' AND table_name = $1)`, tbl,
		).Scan(&exists)
		if err != nil {
			t.Fatalf("information_schema(%s): %v", tbl, err)
		}
		if !exists {
			t.Errorf("таблица %s не создана миграцией", tbl)
		}
	}

	// SELECT из всех таблиц без ошибок.
	allTables := append([]string{"schema_migrations"}, schemaTables...)
	for _, tbl := range allTables {
		var n int64
		if err := st.Pool().QueryRow(ctx, "SELECT count(*) FROM "+tbl).Scan(&n); err != nil {
			t.Errorf("SELECT count(*) FROM %s: %v", tbl, err)
		}
	}

	// webauthn_credentials — плоские колонки (не JSON-столбец), спека §5.
	webauthnColumns := []string{
		"id", "user_id", "credential_id", "rpid", "public_key",
		"sign_count", "clone_warning", "aaguid", "attestation_type",
		"attestation_format", "attachment", "transports", "present",
		"verified", "backup_eligible", "backup_state", "name",
		"created_at", "last_used_at",
	}
	for _, col := range webauthnColumns {
		err := st.Pool().QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM information_schema.columns
			 WHERE table_schema = 'public'
			   AND table_name = 'webauthn_credentials' AND column_name = $1)`, col,
		).Scan(&exists)
		if err != nil {
			t.Fatalf("information_schema.columns(webauthn_credentials.%s): %v", col, err)
		}
		if !exists {
			t.Errorf("webauthn_credentials: нет колонки %s", col)
		}
	}

	// Миграция 0002: users.source ('local' по умолчанию) и display_name.
	for _, col := range []string{"source", "display_name"} {
		err := st.Pool().QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM information_schema.columns
			 WHERE table_schema = 'public'
			   AND table_name = 'users' AND column_name = $1)`, col,
		).Scan(&exists)
		if err != nil {
			t.Fatalf("information_schema.columns(users.%s): %v", col, err)
		}
		if !exists {
			t.Errorf("users: нет колонки %s (миграция 0002)", col)
		}
	}
	var srcDefault string
	if err := st.Pool().QueryRow(ctx,
		`SELECT column_default FROM information_schema.columns
		 WHERE table_schema = 'public' AND table_name = 'users'
		   AND column_name = 'source'`).Scan(&srcDefault); err != nil {
		t.Fatalf("information_schema.columns(users.source default): %v", err)
	}
	if !strings.Contains(srcDefault, "local") {
		t.Errorf("users.source default = %q, ожидался 'local' (существующие строки не меняются)", srcDefault)
	}
	// Строка, созданная без явного source, получает 'local' от БД.
	if _, err := st.Pool().Exec(ctx,
		`INSERT INTO users (id, username, password_hash) VALUES (gen_random_uuid(), 'mig-0002', 'x')`); err != nil {
		t.Fatalf("вставка пользователя без source: %v", err)
	}
	var src string
	if err := st.Pool().QueryRow(ctx,
		`SELECT source FROM users WHERE username = 'mig-0002'`).Scan(&src); err != nil {
		t.Fatalf("чтение source: %v", err)
	}
	if src != "local" {
		t.Errorf("source без явного значения = %q, ожидался local", src)
	}

	// Число применённых версий совпадает с числом встроенных миграций.
	sqlFiles, err := fs.Glob(migrations.FS, "*.sql")
	if err != nil {
		t.Fatalf("glob встроенных миграций: %v", err)
	}
	countApplied := func() int {
		t.Helper()
		var n int
		if err := st.Pool().QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&n); err != nil {
			t.Fatalf("count schema_migrations: %v", err)
		}
		return n
	}
	if got := countApplied(); got != len(sqlFiles) {
		t.Errorf("применено %d миграций, ожидалось %d", got, len(sqlFiles))
	}

	// Повторный Migrate идемпотентен: без ошибок и не применяет ничего нового.
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("повторный Migrate: %v", err)
	}
	if got := countApplied(); got != len(sqlFiles) {
		t.Errorf("после повторного Migrate применено %d миграций, ожидалось прежнее %d", got, len(sqlFiles))
	}
}
