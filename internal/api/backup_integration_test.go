//go:build integration

// Интеграционные тесты экспорта/импорта настроек и HTTP-бэкапа: файл
// экспорта содержит секреты, но никогда master_key/admin_token; импорт
// атомарно валидирует ключи, пропускает маски/null/license.*; бэкап —
// SQL-дамп вложением с аудитом; 413 при огромном audit_log (mock счётчика).
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
)

// restoreSettings — восстановление ключей, которые тест портит.
func restoreSettings(t *testing.T, ctx context.Context, set *settings.M, keys map[string]string) {
	t.Helper()
	t.Cleanup(func() {
		for key, val := range keys {
			if err := set.Put(ctx, key, json.RawMessage(val)); err != nil {
				t.Errorf("восстановление %s: %v", key, err)
			}
		}
	})
}

// adminActionCount — число событий admin_action с данным detail.action
// (формат аудита админ-API).
func adminActionCount(t *testing.T, st *store.Store, action string) int {
	t.Helper()
	var n int
	if err := st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_log WHERE event = 'admin_action' AND detail->>'action' = $1`,
		action).Scan(&n); err != nil {
		t.Fatalf("подсчёт аудита %s: %v", action, err)
	}
	return n
}

// TestAdminSettingsExport: 200 + вложение + _warning; master_key/admin_token
// исключены, реальные секреты (radius.secret) включены; ключи license.*
// попадают в файл (состояние инсталляции), аудит settings_export записан.
func TestAdminSettingsExport(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	h, _ := newWebRouter(t, st, set, box, nil)
	tok := set.Get().AdminToken

	// Ключ состояния лицензии — как после первого старта с лицензированием.
	if _, err := st.Pool().Exec(ctx,
		`INSERT INTO settings (key, value) VALUES ('license.trial_started', '"2026-01-01T00:00:00Z"')
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`); err != nil {
		t.Fatalf("license-ключ: %v", err)
	}
	t.Cleanup(func() {
		_, _ = st.Pool().Exec(context.Background(), `DELETE FROM settings WHERE key = 'license.trial_started'`)
	})

	rec := adminReq(t, h, http.MethodGet, "/api/v1/admin/settings/export", nil, "")
	wantStatus(t, rec, http.StatusUnauthorized)

	rec = adminReq(t, h, http.MethodGet, "/api/v1/admin/settings/export", nil, tok)
	wantStatus(t, rec, http.StatusOK)
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") ||
		!strings.Contains(cd, "ligament-settings-"+time.Now().Format("20060102")+".json") {
		t.Fatalf("Content-Disposition = %q", cd)
	}

	var body struct {
		Warning    string                     `json:"_warning"`
		ExportedAt string                     `json:"exported_at"`
		Settings   map[string]json.RawMessage `json:"settings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("разбор экспорта: %v (%s)", err, rec.Body.String())
	}
	if !strings.Contains(body.Warning, "секрет") {
		t.Fatalf("_warning = %q, want упоминание секретов", body.Warning)
	}
	if body.ExportedAt == "" {
		t.Fatal("exported_at пуст")
	}
	if _, ok := body.Settings["master_key"]; ok {
		t.Fatal("master_key в экспорте — секрет утёк")
	}
	if _, ok := body.Settings["admin_token"]; ok {
		t.Fatal("admin_token в экспорте — секрет утёк")
	}
	if rec.Body.String() != "" && strings.Contains(rec.Body.String(), set.Get().AdminToken) {
		t.Fatal("в экспорте встречается значение admin_token")
	}
	// Секреты включены НАСТОЯЩИМИ значениями — файл годится для переноса.
	if string(body.Settings["radius.secret"]) == "" {
		t.Fatal("radius.secret не в экспорте")
	}
	var radiusSecret string
	if err := json.Unmarshal(body.Settings["radius.secret"], &radiusSecret); err != nil || radiusSecret != set.Get().RadiusSecret {
		t.Fatalf("radius.secret в экспорте = %q, want реальное значение", radiusSecret)
	}
	if _, ok := body.Settings["license.trial_started"]; !ok {
		t.Fatal("ключи license.* должны попадать в экспорт")
	}

	// Аудит settings_export.
	if adminActionCount(t, st, "settings_export") == 0 {
		t.Fatal("аудит settings_export не записан")
	}
}

// TestAdminSettingsImport: применение {settings:{...}}; атомарность
// (неизвестный ключ → 400, НИЧЕГО не применяется); маски/null/master_key/
// admin_token/license.* пропускаются; отсутствующие ключи не трогаются.
func TestAdminSettingsImport(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	h, _ := newWebRouter(t, st, set, box, nil)
	tok := set.Get().AdminToken

	restoreSettings(t, ctx, set, map[string]string{
		"totp":        `{"issuer":"twofa","digits":6,"period":30,"skew":1}`,
		"listen.http": `":8080"`,
	})
	beforeSecret := set.Get().RadiusSecret
	beforeMaster := set.Get().MasterKeyB64

	// Успешный импорт двух ключей.
	rec := adminReq(t, h, http.MethodPut, "/api/v1/admin/settings/import", map[string]any{
		"settings": map[string]any{
			"totp":        map[string]any{"issuer": "imported-2fa", "digits": 8, "period": 30, "skew": 1},
			"listen.http": ":9090",
		},
	}, tok)
	wantStatus(t, rec, http.StatusOK)
	body := jsonBody(t, rec)
	if body["applied"] != float64(2) || body["skipped"] != float64(0) {
		t.Fatalf("import: %v, want applied=2 skipped=0", body)
	}
	if set.Get().TOTP.Issuer != "imported-2fa" || set.Get().TOTP.Digits != 8 ||
		set.Get().Listen.HTTP != ":9090" {
		t.Fatalf("импорт не применился: %+v", set.Get().TOTP)
	}

	// Маска, null, master_key, admin_token, license.* — пропуски.
	rec = adminReq(t, h, http.MethodPut, "/api/v1/admin/settings/import", map[string]any{
		"settings": map[string]any{
			"radius.secret":      "••••",
			"totp":               nil,
			"master_key":         "чужой-ключ-атака",
			"admin_token":        "чужой-токен",
			"license.trial_used": true,
		},
	}, tok)
	wantStatus(t, rec, http.StatusOK)
	body = jsonBody(t, rec)
	if body["applied"] != float64(0) || body["skipped"] != float64(5) {
		t.Fatalf("skips: %v, want applied=0 skipped=5", body)
	}
	if set.Get().RadiusSecret != beforeSecret {
		t.Fatal("маска radius.secret не должна менять секрет")
	}
	if set.Get().MasterKeyB64 != beforeMaster {
		t.Fatal("master_key не должен применяться импортом")
	}
	if set.Get().TOTP.Issuer != "imported-2fa" {
		t.Fatal("null должен пропускаться (не сбрасывать ключ)")
	}

	// Объект-маска {"set":...,"value":"••••"} тоже пропускается.
	rec = adminReq(t, h, http.MethodPut, "/api/v1/admin/settings/import", map[string]any{
		"settings": map[string]any{
			"telegram": map[string]any{"set": true, "value": "••••"},
		},
	}, tok)
	wantStatus(t, rec, http.StatusOK)
	if body := jsonBody(t, rec); body["skipped"] != float64(1) {
		t.Fatalf("объект-маска: %v, want skipped=1", body)
	}

	// Неизвестный ключ → 400 со списком, АТОМАРНО: валидный ключ рядом
	// не применяется.
	rec = adminReq(t, h, http.MethodPut, "/api/v1/admin/settings/import", map[string]any{
		"settings": map[string]any{
			"totp":     map[string]any{"issuer": "must-not-apply"},
			"smtp.bad": 1,
			"nope":     true,
		},
	}, tok)
	wantStatus(t, rec, http.StatusBadRequest)
	body = jsonBody(t, rec)
	if body["error"] != "unknown_key" {
		t.Fatalf("error = %v, want unknown_key", body)
	}
	keys, _ := body["keys"].([]any)
	if len(keys) != 2 {
		t.Fatalf("keys = %v, want 2 неизвестных", keys)
	}
	if set.Get().TOTP.Issuer != "imported-2fa" {
		t.Fatal("неизвестный ключ должен отклонять запрос целиком")
	}

	// settings отсутствует → 400.
	rec = adminReq(t, h, http.MethodPut, "/api/v1/admin/settings/import", map[string]any{}, tok)
	wantStatus(t, rec, http.StatusBadRequest)

	// Roundtrip: экспорт → импорт возвращает applied (все ключи валидны).
	rec = adminReq(t, h, http.MethodGet, "/api/v1/admin/settings/export", nil, tok)
	wantStatus(t, rec, http.StatusOK)
	var exp struct {
		Settings map[string]json.RawMessage `json:"settings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &exp); err != nil {
		t.Fatalf("экспорт: %v", err)
	}
	rec = adminReq(t, h, http.MethodPut, "/api/v1/admin/settings/import",
		map[string]any{"settings": exp.Settings}, tok)
	wantStatus(t, rec, http.StatusOK)
	body = jsonBody(t, rec)
	if body["applied"] == float64(0) {
		t.Fatalf("roundtrip export→import ничего не применил: %v", body)
	}
	if _, ok := body["applied"].(float64); !ok {
		t.Fatalf("import roundtrip: %v", body)
	}

	if adminActionCount(t, st, "settings_import") == 0 {
		t.Fatal("аудит settings_import не записан")
	}
}

// TestAdminBackupDownload: 200 + вложение SQL + содержимое дампа без
// master_key + аудит backup_download.
func TestAdminBackupDownload(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	h, _ := newWebRouter(t, st, set, box, nil)
	tok := set.Get().AdminToken
	mkUser(t, ctx, st, "backupuser", nil)

	rec := adminReq(t, h, http.MethodGet, "/api/v1/admin/backup", nil, "")
	wantStatus(t, rec, http.StatusUnauthorized)

	rec = adminReq(t, h, http.MethodGet, "/api/v1/admin/backup", nil, tok)
	wantStatus(t, rec, http.StatusOK)
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") ||
		!strings.Contains(cd, "ligament-backup-"+time.Now().Format("20060102")+".sql") {
		t.Fatalf("Content-Disposition = %q", cd)
	}
	dump := rec.Body.String()
	if !strings.Contains(dump, "master_key НЕ входит в дамп") {
		t.Fatal("дамп без предупреждения о master_key")
	}
	if strings.Contains(dump, set.Get().MasterKeyB64) {
		t.Fatal("дамп раскрывает master_key")
	}
	if !strings.Contains(dump, "BEGIN;") || !strings.Contains(dump, "COMMIT;") {
		t.Fatal("дамп не в транзакции")
	}
	if !strings.Contains(dump, "INSERT INTO users") || !strings.Contains(dump, "backupuser") {
		t.Fatal("дамп не содержит пользователей")
	}
	if !strings.Contains(dump, "INSERT INTO audit_log") {
		t.Fatal("дамп должен включать audit_log по умолчанию")
	}

	if adminActionCount(t, st, "backup_download") == 0 {
		t.Fatal("аудит backup_download не записан")
	}
}

// TestAdminBackupTooLarge: audit_log свыше лимита → 413 backup_too_large
// с подсказкой CLI (счётчик подменяется — 500k строк не вставляем).
func TestAdminBackupTooLarge(t *testing.T) {
	st, set, box := setup(t)
	h, _ := newWebRouter(t, st, set, box, nil)
	tok := set.Get().AdminToken
	_ = h

	// Изолированный AdminAPI с подменённым счётчиком audit_log.
	backupAdmin := NewAdminAPI(st, set, nil)
	backupAdmin.countAuditRows = func(context.Context) (int64, error) {
		return backupAuditRowLimit + 1000, nil
	}
	r := chi.NewRouter()
	backupAdmin.Register(r)

	rec := adminReq(t, r, http.MethodGet, "/api/v1/admin/backup", nil, tok)
	wantStatus(t, rec, http.StatusRequestEntityTooLarge)
	body := jsonBody(t, rec)
	if body["error"] != "backup_too_large" {
		t.Fatalf("error = %v, want backup_too_large", body)
	}
	if rows, _ := body["audit_rows"].(float64); int64(rows) != backupAuditRowLimit+1000 {
		t.Fatalf("audit_rows = %v", body["audit_rows"])
	}
	hint, _ := body["hint"].(string)
	if !strings.Contains(hint, "-backup") {
		t.Fatalf("hint без указания CLI: %q", hint)
	}
}
