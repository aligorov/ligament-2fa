// Экспорт/импорт настроек и логический бэкап БД (админ): файл экспорта
// содержит СЕКРЕТЫ (кроме master_key/admin_token) и помечен предупреждением;
// импорт атомарно валидирует все ключи (неизвестный — 400, ничего не
// применяется), применяет значения через m.Put и один финальный Reload.
// GET /backup генерирует тот же SQL-дамп, что и `twofa -backup`; при
// огромном audit_log отвечает 413 с подсказкой использовать CLI.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/aligorov/twofa/internal/backup"
	"github.com/aligorov/twofa/internal/settings"
)

// exportWarning — поле _warning в файле экспорта настроек: файл содержит
// секреты (radius.secret, smtp.password, токен Telegram, креды SMS/LDAP).
const exportWarning = "файл содержит секреты — храните безопасно"

// licenseStatePrefix — ключи состояния лицензии (license.*) не являются
// конфигурацией: это runtime-состояние конкретной инсталляции, экспорт
// их не применяет (считаются пропущенными, а не неизвестными).
const licenseStatePrefix = "license."

// backupAuditRowLimit — потолок строк audit_log для бэкапа через HTTP:
// больше — 413 с подсказкой снять дамп CLI (генерация в память крупного
// журнала подвешивала бы HTTP-воркер).
const backupAuditRowLimit = 500_000

// errBackupTooLarge — audit_log превышает лимит HTTP-бэкапа.
type errBackupTooLarge struct{ rows int64 }

func (e errBackupTooLarge) Error() string {
	return fmt.Sprintf("audit_log слишком велик для бэкапа через HTTP: %d строк", e.rows)
}

// ---- экспорт настроек ----

// settingsExportPayload собирает файл экспорта настроек: все ключи из БД,
// кроме master_key/admin_token (никогда), с предупреждением о секретности.
// Возвращает имя вложения и тело файла.
func (a *AdminAPI) settingsExportPayload(ctx context.Context) (string, []byte, error) {
	raw, err := a.m.Export(ctx)
	if err != nil {
		return "", nil, err
	}
	now := time.Now()
	body, err := json.MarshalIndent(map[string]any{
		"_warning":    exportWarning,
		"exported_at": now.UTC().Format(time.RFC3339),
		"settings":    raw,
	}, "", "  ")
	if err != nil {
		return "", nil, fmt.Errorf("экспорт настроек: маршал: %w", err)
	}
	return "ligament-settings-" + now.Format("20060102") + ".json", body, nil
}

// handleSettingsExport — GET /api/v1/admin/settings/export: вложение JSON
// со всеми настройками, кроме master_key/admin_token. Файл секретен.
func (a *AdminAPI) handleSettingsExport(w http.ResponseWriter, r *http.Request) {
	name, body, err := a.settingsExportPayload(r.Context())
	if err != nil {
		slog.Error("api: admin export настроек", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	a.audit(r.Context(), "settings_export", map[string]any{"via": "api"})
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// ---- импорт настроек ----

type settingsImportReq struct {
	Settings map[string]json.RawMessage `json:"settings"`
}

// handleSettingsImport — PUT /api/v1/admin/settings/import
// {settings:{ключ: значение}}: атомарная валидация всех ключей
// (неизвестный → 400 unknown_key со списком, НЕ применяется ничего),
// затем применение заменой значения каждого ключа через m.Put и один
// финальный Reload. Маски («••••» / {"set":…}) и null пропускаются;
// master_key/admin_token и license.* не применяются никогда; отсутствующие
// в файле ключи не затрагиваются. Ответ {applied, skipped}.
func (a *AdminAPI) handleSettingsImport(w http.ResponseWriter, r *http.Request) {
	var req settingsImportReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Settings == nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	ctx := r.Context()
	applied, skipped, unknown, err := a.applySettingsImport(ctx, req.Settings)
	if len(unknown) > 0 {
		sort.Strings(unknown)
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unknown_key", "keys": unknown})
		return
	}
	if err != nil {
		// Значение не является валидным JSON — ошибка клиента.
		writeError(w, http.StatusBadRequest, "bad_key")
		return
	}
	a.audit(ctx, "settings_import", map[string]any{
		"applied": applied, "skipped": skipped, "via": "api",
	})
	writeJSON(w, http.StatusOK, map[string]any{"applied": applied, "skipped": skipped})
}

// applySettingsImport — общая логика импорта (JSON API и HTML-форма):
// сначала валидация всех ключей, потом применение. Возвращает счётчики
// применённых/пропущенных, список неизвестных ключей (валидация НЕ
// пропустила запрос) и ошибку применения.
func (a *AdminAPI) applySettingsImport(ctx context.Context, in map[string]json.RawMessage) (applied, skipped int, unknown []string, err error) {
	for key := range in {
		if settings.IsKnownKey(key) || strings.HasPrefix(key, licenseStatePrefix) {
			continue
		}
		unknown = append(unknown, key)
	}
	if len(unknown) > 0 {
		return 0, 0, unknown, nil
	}

	keys := make([]string, 0, len(in))
	for key := range in {
		keys = append(keys, key)
	}
	sort.Strings(keys) // стабильный порядок применения и аудита

	for _, key := range keys {
		val := in[key]
		// master_key/admin_token и состояние лицензии не применяются;
		// null и маски («••••» / {"set":…,"value":"••••"}) — «не менять».
		if settings.IsImportExcluded(key) || strings.HasPrefix(key, licenseStatePrefix) ||
			isNullRaw(val) || isNoChangeValue(val) {
			skipped++
			continue
		}
		if err := a.m.Put(ctx, key, val); err != nil {
			return applied, skipped, nil, err
		}
		applied++
	}
	// Финальный перезд снимка: Put перезит и так, но единая точка
	// гарантирует консистентность после всей пачки.
	if err := a.m.Reload(ctx); err != nil {
		return applied, skipped, nil, err
	}
	return applied, skipped, nil, nil
}

// isNullRaw — JSON-литерал null (отсутствующий ключ в файле = «не трогать»).
func isNullRaw(raw json.RawMessage) bool {
	return strings.TrimSpace(string(raw)) == "null"
}

// ---- логический бэкап ----

// dumpBackup генерирует SQL-дамп (как `twofa -backup`, включая audit_log).
// При audit_log больше backupAuditRowLimit возвращает errBackupTooLarge —
// HTTP-ответ 413 с подсказкой CLI. Возвращает имя вложения и дамп.
func (a *AdminAPI) dumpBackup(ctx context.Context) (string, []byte, error) {
	rows, err := a.countAuditRows(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("подсчёт audit_log: %w", err)
	}
	if rows > backupAuditRowLimit {
		return "", nil, errBackupTooLarge{rows: rows}
	}
	dump, err := backup.Dump(ctx, a.st.Pool(), backup.Options{IncludeAudit: true})
	if err != nil {
		return "", nil, err
	}
	return "ligament-backup-" + time.Now().Format("20060102") + ".sql", dump, nil
}

// handleBackup — GET /api/v1/admin/backup: дамп вложением SQL. Аудит
// backup_download пишется ПОСЛЕ генерации (событие не попадает в сам дамп).
func (a *AdminAPI) handleBackup(w http.ResponseWriter, r *http.Request) {
	name, dump, err := a.dumpBackup(r.Context())
	var tooLarge errBackupTooLarge
	if errors.As(err, &tooLarge) {
		hint := "снимите дамп CLI: twofa -dsn ... -backup out.sql " +
			"(-backup-audit=false — без журнала событий)"
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{
			"error":      "backup_too_large",
			"audit_rows": tooLarge.rows,
			"hint":       hint,
		})
		return
	}
	if err != nil {
		slog.Error("api: admin бэкап", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	a.audit(r.Context(), "backup_download", map[string]any{"via": "api"})
	w.Header().Set("Content-Type", "application/sql; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(dump)
}
