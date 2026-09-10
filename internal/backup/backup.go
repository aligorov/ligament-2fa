// Package backup — логический дамп базы twofa в SQL без pg_dump (в
// distroless-образе его нет): читает все таблицы через pgx и собирает
// psql-совместимый скрипт (BEGIN; ... COMMIT;) из DELETE FROM и multi-row
// INSERT. Восстановление документируется через psql (автоматическое
// применение дампа сервером намеренно не реализовано — слишком опасно).
//
// master_key в дамп НЕ входит: TOTP-секреты лежат шифротекстом AES-GCM с
// мастер-ключом, поэтому восстановление на другую инсталляцию требует того
// же master_key (первая строка дампа — предупреждение; см. README
// «Бэкап и перенос»).
package backup

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// rowsPerInsert — строк в одном multi-row INSERT: достаточно крупных
// операторов без раздувания размера (audit_log может быть большим).
const rowsPerInsert = 200

// Options — параметры дампа.
type Options struct {
	// IncludeAudit — включать audit_log (по умолчанию дамп его содержит;
	// false — флаг CLI -backup-audit=false: журнал событий не переносится).
	IncludeAudit bool
}

// tableSpec — одна таблица дампа: детерминированный порядок строк и
// опциональное исключение отдельных строк (settings/master_key).
type tableSpec struct {
	name    string                        // имя таблицы
	order   string                        // ORDER BY (стабильный дамп и сравнение)
	exclude func(firstColVal string) bool // фильтр по значению ПЕРВОЙ колонки
}

// tables — порядок таблиц по FK: родители (users) раньше ссылающихся на
// них детей; settings, audit_log и schema_migrations внешних ключей не
// имеют. Порядок проверяется TestDumpTableOrderFK. Одноразовые артефакты
// OIDC-флоу (oidc_codes/oidc_tokens, TTL 60/300 с) не выгружаются —
// конфигурация (oidc_clients) переносится, in-flight входы истекают.
var tables = []tableSpec{
	{name: "users", order: "id"},
	{name: "app_devices", order: "created_at"},
	{name: "groups", order: "id"},
	{name: "user_groups", order: "user_id, group_id"},
	{name: "totp_secrets", order: "user_id"},
	{name: "backup_codes", order: "id"},
	{name: "challenges", order: "id"},
	{name: "sessions", order: "token_hash"},
	{name: "settings", order: "key", exclude: func(key string) bool { return key == "master_key" }},
	{name: "audit_log", order: "id"},
	{name: "trusted_devices", order: "id"},
	{name: "webauthn_credentials", order: "id"},
	{name: "oidc_clients", order: "client_id"},
	{name: "ip_lists", order: "id"},
	{name: "ip_bans", order: "ip"},
	{name: "support_sessions", order: "created_at"},
	{name: "support_messages", order: "created_at"},
	{name: "schema_migrations", order: "version"},
}

// serialTables — таблицы с BIGSERIAL-колонкой id: после вставки явных
// значений последовательность выставляется за максимумом, иначе первые
// вставки после восстановления упрутся в дубликат ключа.
var serialTables = map[string]string{
	"backup_codes":         "id",
	"audit_log":            "id",
	"trusted_devices":      "id",
	"webauthn_credentials": "id",
}

// Dump генерирует полный логический дамп в SQL-скрипт (в памяти). Скрипт
// начинается с BEGIN; и заканчивается COMMIT; — применение атомарно и
// идемпотентно (перед вставками таблицы очищаются DELETE FROM). Схема
// (миграции) в дамп не входит: целевая БД должна быть уже мигрирована.
func Dump(ctx context.Context, pool *pgxpool.Pool, opts Options) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString("-- twofa: логический бэкап базы (twofa -backup / GET /api/v1/admin/backup).\n")
	b.WriteString("-- ВНИМАНИЕ: master_key НЕ входит в дамп. TOTP-секреты зашифрованы master_key:\n")
	b.WriteString("-- восстановление на другую инсталляцию требует ТОГО ЖЕ master_key\n")
	b.WriteString("-- (выгрузите его отдельно: select value from settings where key='master_key').\n")
	b.WriteString("-- Сгенерирован: " + time.Now().UTC().Format(time.RFC3339) + "\n")
	b.WriteString("BEGIN;\n\n")

	for _, tb := range tables {
		if tb.name == "audit_log" && !opts.IncludeAudit {
			continue
		}
		if err := dumpTable(ctx, pool, &b, tb); err != nil {
			return nil, err
		}
	}

	b.WriteString("COMMIT;\n")
	return b.Bytes(), nil
}

// dumpTable выгружает одну таблицу: DELETE FROM + пачки INSERT (+ setval
// для serial-таблиц).
func dumpTable(ctx context.Context, pool *pgxpool.Pool, b *bytes.Buffer, tb tableSpec) error {
	cols, sel, err := tableColumns(ctx, pool, tb.name)
	if err != nil {
		return err
	}

	query := `SELECT ` + strings.Join(sel, ", ") + ` FROM ` + tb.name
	if tb.exclude != nil {
		query += ` WHERE ` + firstColumn(tb.name) + ` <> $1`
	}
	query += ` ORDER BY ` + tb.order

	var args []any
	if tb.exclude != nil {
		args = []any{"master_key"}
	}
	rows, err := pool.Query(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("backup: чтение %s: %w", tb.name, err)
	}
	defer rows.Close()

	var data [][]any
	for rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			return fmt.Errorf("backup: значения строки %s: %w", tb.name, err)
		}
		data = append(data, vals)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("backup: итерация %s: %w", tb.name, err)
	}

	fmt.Fprintf(b, "DELETE FROM %s;\n", tb.name)
	stmts, err := insertStatements(tb.name, cols, data, rowsPerInsert)
	if err != nil {
		return err
	}
	b.WriteString(stmts)
	if col, ok := serialTables[tb.name]; ok {
		fmt.Fprintf(b, "SELECT setval(pg_get_serial_sequence('%s', '%s'), COALESCE((SELECT MAX(%s) FROM %s), 0) + 1, false);\n",
			tb.name, col, col, tb.name)
	}
	b.WriteString("\n")
	return nil
}

// OID json/jsonb (pgconn не экспортирует константы всех типов).
const (
	oidJSON  = 114  // json
	oidJSONB = 3802 // jsonb
)

// tableColumns возвращает имена колонок таблицы и список выражений SELECT:
// jsonb/json приводятся к ::text — pgx иначе декодирует их в map/slice
// (потеря точности больших чисел и исходного текста), а ::text даёт
// канонический jsonb-текст — тот же, что использует pg_dump.
func tableColumns(ctx context.Context, pool *pgxpool.Pool, table string) (cols, sel []string, err error) {
	probe, err := pool.Query(ctx, `SELECT * FROM `+table+` LIMIT 0`)
	if err != nil {
		return nil, nil, fmt.Errorf("backup: колонки %s: %w", table, err)
	}
	defer probe.Close()
	for _, fd := range probe.FieldDescriptions() {
		cols = append(cols, fd.Name)
		switch fd.DataTypeOID {
		case oidJSON, oidJSONB:
			sel = append(sel, fd.Name+"::text")
		default:
			sel = append(sel, fd.Name)
		}
	}
	return cols, sel, nil
}

// firstColumn — имя первой колонки таблицы для фильтра исключения.
// Используется только для settings (первая колонка в схеме — key); список
// короткий, отдельного запроса в catalog не требуется.
func firstColumn(table string) string {
	if table == "settings" {
		return "key"
	}
	return "1"
}

// insertStatements собирает multi-row INSERT-операторы по maxRows строк
// (0 — все строки одним оператором). Пустой набор строк — пустая строка.
func insertStatements(table string, cols []string, rows [][]any, maxRows int) (string, error) {
	if len(rows) == 0 {
		return "", nil
	}
	if maxRows <= 0 {
		maxRows = len(rows)
	}
	var b strings.Builder
	for start := 0; start < len(rows); start += maxRows {
		end := min(start+maxRows, len(rows))
		fmt.Fprintf(&b, "INSERT INTO %s (%s) VALUES\n", table, strings.Join(cols, ", "))
		for i := start; i < end; i++ {
			lits := make([]string, 0, len(rows[i]))
			for _, v := range rows[i] {
				lit, err := sqlLiteral(v)
				if err != nil {
					return "", fmt.Errorf("backup: %s строка %d: %w", table, i, err)
				}
				lits = append(lits, lit)
			}
			b.WriteString("  (")
			b.WriteString(strings.Join(lits, ", "))
			b.WriteString(")")
			if i == end-1 {
				b.WriteString(";\n")
			} else {
				b.WriteString(",\n")
			}
		}
	}
	return b.String(), nil
}

// sqlLiteral представляет значение pgx как SQL-литерал: NULL для nil,
// числа/булевы как есть, строки — доллар-кавычками $tag$...$tag$ с
// защитой от коллизии тега, байты — decode('hex','hex') (переносимо и
// не зависит от bytea_output), время — RFC3339, UUID — канонической
// строкой. Неизвестный тип — ошибка (лучше упасть на дампе, чем молча
// записать мусор).
func sqlLiteral(v any) (string, error) {
	switch x := v.(type) {
	case nil:
		return "NULL", nil
	case bool:
		if x {
			return "TRUE", nil
		}
		return "FALSE", nil
	case int64:
		return strconv.FormatInt(x, 10), nil
	case int32:
		return strconv.FormatInt(int64(x), 10), nil
	case int16:
		return strconv.FormatInt(int64(x), 10), nil
	case int8:
		return strconv.FormatInt(int64(x), 10), nil
	case uint8: // одиночный байт мог проскочить как число
		return strconv.FormatUint(uint64(x), 10), nil
	case int:
		return strconv.Itoa(x), nil
	case uint:
		return strconv.FormatUint(uint64(x), 10), nil
	case float64:
		return strconv.FormatFloat(x, 'g', -1, 64), nil
	case float32:
		return strconv.FormatFloat(float64(x), 'g', -1, 32), nil
	case string:
		return quoteString(x), nil
	case []byte:
		return "decode('" + hexEncode(x) + "', 'hex')", nil
	case time.Time:
		// Смещение оставляется как есть: timestamptz хранит момент времени,
		// а не зону — значение восстанавливается тем же инстантом.
		return quoteString(x.Format(time.RFC3339Nano)), nil
	case [16]byte: // UUID из pgx v5
		return quoteString(uuidString(x)), nil
	case []string: // TEXT[] (ldap_groups, support_roles, …)
		return arrayLiteral(len(x), func(i int) string { return quoteString(x[i]) }), nil
	case []any: // массивы pgx без типизации элемента
		parts := make([]string, len(x))
		for i, el := range x {
			lit, err := sqlLiteral(el)
			if err != nil {
				return "", fmt.Errorf("элемент массива %d: %w", i, err)
			}
			parts[i] = lit
		}
		return arrayLiteral(len(parts), func(i int) string { return parts[i] }), nil
	default:
		return "", fmt.Errorf("неподдерживаемый тип значения %T", v)
	}
}

// arrayLiteral собирает ARRAY[...]::text[]: без ::text[] пустой ARRAY[]
// выводится как unknown и не вставляется в TEXT[]-колонку.
func arrayLiteral(n int, elem func(i int) string) string {
	parts := make([]string, n)
	for i := 0; i < n; i++ {
		parts[i] = elem(i)
	}
	return "ARRAY[" + strings.Join(parts, ", ") + "]::text[]"
}

// uuidString — [16]byte в канонической форме UUID.
func uuidString(x [16]byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uint32(x[0])<<24|uint32(x[1])<<16|uint32(x[2])<<8|uint32(x[3]),
		uint16(x[4])<<8|uint16(x[5]),
		uint16(x[6])<<8|uint16(x[7]),
		uint16(x[8])<<8|uint16(x[9]),
		uint64(x[10])<<40|uint64(x[11])<<32|uint64(x[12])<<24|
			uint64(x[13])<<16|uint64(x[14])<<8|uint64(x[15]))
}

// quoteString — доллар-кавычка $tag$...$tag$. Если данные содержат тег,
// подбирается следующий ($lig$ → $lig0$ → $lig1$ → …), пока не найдётся
// отсутствующий в значении: литерал не может «разорваться» содержимым.
func quoteString(s string) string {
	tag := "lig"
	for i := 0; strings.Contains(s, "$"+tag+"$"); i++ {
		tag = "lig" + strconv.Itoa(i)
	}
	return "$" + tag + "$" + s + "$" + tag + "$"
}

// hexEncode — байты в hex (нижний регистр), encoding/hex без аллокаций
// поверх строкового построения literals.
func hexEncode(b []byte) string {
	const digits = "0123456789abcdef"
	var sb strings.Builder
	sb.Grow(len(b) * 2)
	for _, c := range b {
		sb.WriteByte(digits[c>>4])
		sb.WriteByte(digits[c&0x0f])
	}
	return sb.String()
}
