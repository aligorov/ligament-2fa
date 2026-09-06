// Юнит-тесты генератора логического дампа (без БД): экранирование
// SQL-литералов (доллар-кавычки с защитой от коллизии, \n, кириллица,
// байты через decode('...','hex'), NULL), сборка multi-row INSERT,
// порядок таблиц по FK.
package backup

import (
	"strings"
	"testing"
	"time"
)

func TestSQLLiteralNull(t *testing.T) {
	got, err := sqlLiteral(nil)
	if err != nil {
		t.Fatalf("nil: %v", err)
	}
	if got != "NULL" {
		t.Fatalf("nil = %q, want NULL", got)
	}
}

func TestSQLLiteralScalars(t *testing.T) {
	cases := []struct {
		name string
		val  any
		want string
	}{
		{"bool true", true, "TRUE"},
		{"bool false", false, "FALSE"},
		{"int64", int64(-42), "-42"},
		{"int32", int32(7), "7"},
		{"int16", int16(-1), "-1"},
		{"int", int(100), "100"},
		{"float64", float64(1.5), "1.5"},
		{"float32", float32(0.25), "0.25"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := sqlLiteral(c.val)
			if err != nil {
				t.Fatalf("sqlLiteral(%v): %v", c.val, err)
			}
			if got != c.want {
				t.Fatalf("sqlLiteral(%v) = %q, want %q", c.val, got, c.want)
			}
		})
	}
}

func TestSQLLiteralString(t *testing.T) {
	cases := []struct {
		name string
		val  string
		want string
	}{
		{"простая", "hello", "$lig$hello$lig$"},
		{"кириллица", "Пароль №5", "$lig$Пароль №5$lig$"},
		{"переводы строк", "line1\nline2\ttab", "$lig$line1\nline2\ttab$lig$"},
		{"одинарная кавычка", "it's", "$lig$it's$lig$"},
		{"ноль-байты не в тексте", "a\\b'c\"d", `$lig$a\b'c"d$lig$`},
		{"jsonb-строка", `{"host":"smtp.example.com","port":587}`, `$lig${"host":"smtp.example.com","port":587}$lig$`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := sqlLiteral(c.val)
			if err != nil {
				t.Fatalf("sqlLiteral(%q): %v", c.val, err)
			}
			if got != c.want {
				t.Fatalf("sqlLiteral(%q) = %q, want %q", c.val, got, c.want)
			}
		})
	}
}

func TestSQLLiteralBytes(t *testing.T) {
	got, err := sqlLiteral([]byte{0xde, 0xad, 0xbe, 0xef})
	if err != nil {
		t.Fatalf("bytes: %v", err)
	}
	if got != `decode('deadbeef', 'hex')` {
		t.Fatalf("bytes = %q", got)
	}
	// Пустой (но не NULL) bytea — decode('', 'hex') = '\x'.
	got, err = sqlLiteral([]byte{})
	if err != nil {
		t.Fatalf("empty bytes: %v", err)
	}
	if got != `decode('', 'hex')` {
		t.Fatalf("empty bytes = %q", got)
	}
}

func TestSQLLiteralTime(t *testing.T) {
	ts := time.Date(2026, 9, 5, 12, 34, 56, 789000000, time.FixedZone("MSK", 3*3600))
	got, err := sqlLiteral(ts)
	if err != nil {
		t.Fatalf("time: %v", err)
	}
	want := `$lig$2026-09-05T12:34:56.789+03:00$lig$`
	if got != want {
		t.Fatalf("time = %q, want %q", got, want)
	}
}

func TestSQLLiteralUUID(t *testing.T) {
	// pgx v5 отдаёт UUID как [16]uint8.
	id := [16]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	got, err := sqlLiteral(id)
	if err != nil {
		t.Fatalf("uuid: %v", err)
	}
	if got != `$lig$00010203-0405-0607-0809-0a0b0c0d0e0f$lig$` {
		t.Fatalf("uuid = %q", got)
	}
}

func TestSQLLiteralUnknownType(t *testing.T) {
	if _, err := sqlLiteral(struct{ X int }{1}); err == nil {
		t.Fatal("неизвестный тип должен давать ошибку, а не мусор в дампе")
	}
}

// TestQuoteStringDollarCollision: значение, содержащее разделитель $lig$,
// получает другой тег — литерал не «разрывается» посередине данных.
func TestQuoteStringDollarCollision(t *testing.T) {
	for _, val := range []string{
		"до $lig$ после",
		"$lig$$lig$",
		"x$lig0$ и $lig1$ и $lig$",
		"$lig9$$lig8$$lig7$$lig6$$lig5$",
	} {
		got := quoteString(val)
		// Открытие и закрытие — один и тот же тег; внутри данных его нет.
		if !strings.HasPrefix(got, "$") || !strings.HasSuffix(got, "$") {
			t.Fatalf("quoteString(%q) = %q: ожидается доллар-кавычка", val, got)
		}
		open := got[:strings.Index(got[1:], "$")+2]
		close_ := got[len(got)-len(open):]
		if open != close_ {
			t.Fatalf("quoteString(%q) = %q: теги открытия/закрытия различаются", val, got)
		}
		inner := got[len(open) : len(got)-len(open)]
		if strings.Contains(inner, open) {
			t.Fatalf("quoteString(%q) = %q: данные содержат тег %q", val, got, open)
		}
		if inner != val {
			t.Fatalf("quoteString(%q): внутренность %q не равна значению", val, inner)
		}
	}
}

// TestInsertStatements: сборка multi-row INSERT со списком колонок,
// NULL-пропуски и разбиение на пачки фиксированного размера.
func TestInsertStatements(t *testing.T) {
	rows := [][]any{
		{"a", int64(1), nil},
		{"кириллица\nвторая строка", nil, []byte{0x00, 0xff}},
	}
	got, err := insertStatements("demo", []string{"key", "n", "raw"}, rows, 100)
	if err != nil {
		t.Fatalf("insertStatements: %v", err)
	}
	want := `INSERT INTO demo (key, n, raw) VALUES
  ($lig$a$lig$, 1, NULL),
  ($lig$кириллица
вторая строка$lig$, NULL, decode('00ff', 'hex'));
`
	if got != want {
		t.Fatalf("insertStatements =\n%s\nwant\n%s", got, want)
	}
}

// TestInsertStatementsBatching: при maxRows < строк генерируется несколько
// INSERT-операторов по maxRows строк.
func TestInsertStatementsBatching(t *testing.T) {
	rows := [][]any{{"a"}, {"b"}, {"c"}, {"d"}, {"e"}}
	got, err := insertStatements("t", []string{"k"}, rows, 2)
	if err != nil {
		t.Fatalf("insertStatements: %v", err)
	}
	if n := strings.Count(got, "INSERT INTO t"); n != 3 {
		t.Fatalf("ожидались 3 INSERT-пачки, получено %d:\n%s", n, got)
	}
	for _, frag := range []string{"($lig$a$lig$),\n  ($lig$b$lig$);", "($lig$c$lig$),\n  ($lig$d$lig$);", "($lig$e$lig$);"} {
		if !strings.Contains(got, frag) {
			t.Fatalf("пачка %q не найдена в:\n%s", frag, got)
		}
	}
}

// TestInsertStatementsEmpty: без строк INSERT не генерируется вовсе.
func TestInsertStatementsEmpty(t *testing.T) {
	got, err := insertStatements("t", []string{"k"}, nil, 100)
	if err != nil {
		t.Fatalf("insertStatements: %v", err)
	}
	if got != "" {
		t.Fatalf("пустая таблица: %q, want \"\"", got)
	}
}

// TestDumpTableOrderFK: порядок таблиц дампа — родители раньше детей по FK
// (users до всех ссылающихся), settings/audit_log/schema_migrations — без FK.
func TestDumpTableOrderFK(t *testing.T) {
	want := []string{
		"users", "totp_secrets", "backup_codes", "challenges", "sessions",
		"settings", "audit_log", "trusted_devices", "webauthn_credentials",
		"oidc_clients", "schema_migrations",
	}
	if len(tables) != len(want) {
		t.Fatalf("таблиц в дампе %d, ожидалось %d", len(tables), len(want))
	}
	for i, name := range want {
		if tables[i].name != name {
			t.Fatalf("таблица #%d = %q, want %q (порядок по FK)", i, tables[i].name, name)
		}
	}
	// Каждая таблица упорядочена по детерминированному ключу.
	for i := range tables {
		if tables[i].order == "" {
			t.Fatalf("таблица %s без ORDER BY — дамп недетерминирован", tables[i].name)
		}
	}
}

// TestSettingsExcludesMasterKey: из settings исключается master_key.
func TestSettingsExcludesMasterKey(t *testing.T) {
	for _, tb := range tables {
		if tb.name != "settings" {
			continue
		}
		if tb.exclude == nil || !tb.exclude("master_key") {
			t.Fatal("settings: master_key должен исключаться из дампа")
		}
		if tb.exclude("listen.http") {
			t.Fatal("settings: обычные ключи не должны исключаться")
		}
		return
	}
	t.Fatal("таблица settings не найдена в tables")
}
