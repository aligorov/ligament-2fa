// HTML-обвязка бэкапа/переноса настроек: скачивание экспорта настроек и
// SQL-дампа по сессии админа (те же генераторы, что у JSON API — но по
// cookie-сессии, чтобы работали обычные ссылки/формы браузера; Bearer-токен
// у HTML-страниц нет), импорт настроек файлом или вставкой JSON с
// флеш-результатом.
package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// maxImportFileSize — потолок файла импорта настроек (JSON всех ключей
// умещается в сотни килобайт; мегабайта достаточно с запасом).
const maxImportFileSize = 1 << 20

// handlePageSettingsExport — GET /admin/settings/export (сессия админа):
// вложение ligament-settings-YYYYMMDD.json, как у JSON API. Ссылка-кнопка
// на странице настроек (Bearer-токен у браузера нет — потому страница).
func (p *PagesAPI) handlePageSettingsExport(w http.ResponseWriter, r *http.Request) {
	name, body, err := p.admin.settingsExportPayload(r.Context())
	if err != nil {
		flash500(w, r, "/admin/settings", err)
		return
	}
	p.admin.audit(r.Context(), "settings_export", map[string]any{"via": "html"})
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// handlePageSettingsImport — POST /admin/settings/import: файл (multipart
// поле file) ИЛИ вставленный JSON (поле json; файл приоритетнее). Флеш —
// результат applied/skipped; неизвестные ключи отклоняют импорт целиком
// со списком (ничего не применяется).
func (p *PagesAPI) handlePageSettingsImport(w http.ResponseWriter, r *http.Request) {
	back := "/admin/settings"
	// multipart (файл) или обычная форма — разбор по Content-Type
	// (ParseMultipartForm на urlencoded возвращает ErrNotMultipart).
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		if err := r.ParseMultipartForm(maxImportFileSize); err != nil {
			redirectFlash(w, r, back, "Не удалось разобрать форму импорта.", false)
			return
		}
	} else if err := r.ParseForm(); err != nil {
		redirectFlash(w, r, back, "Не удалось разобрать форму импорта.", false)
		return
	}

	raw := strings.TrimSpace(r.PostFormValue("json"))
	if r.MultipartForm != nil {
		if fhs := r.MultipartForm.File["file"]; len(fhs) > 0 {
			f, err := fhs[0].Open()
			if err != nil {
				redirectFlash(w, r, back, "Не удалось открыть файл импорта.", false)
				return
			}
			b, err := io.ReadAll(io.LimitReader(f, maxImportFileSize))
			f.Close()
			if err != nil {
				redirectFlash(w, r, back, "Не удалось прочитать файл импорта.", false)
				return
			}
			if trimmed := strings.TrimSpace(string(b)); trimmed != "" {
				raw = trimmed
			}
		}
	}
	if raw == "" {
		redirectFlash(w, r, back, "Выберите файл экспорта или вставьте JSON.", false)
		return
	}

	var req settingsImportReq
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		redirectFlash(w, r, back, "Файл не похож на экспорт настроек: неверный JSON.", false)
		return
	}
	if req.Settings == nil {
		redirectFlash(w, r, back, "В файле нет объекта settings.", false)
		return
	}

	ctx := r.Context()
	applied, skipped, unknown, err := p.admin.applySettingsImport(ctx, req.Settings)
	switch {
	case len(unknown) > 0:
		p.admin.audit(ctx, "settings_import", map[string]any{
			"via": "html", "error": "unknown_key", "keys": unknown,
		})
		redirectFlash(w, r, back,
			"Импорт отклонён: неизвестные ключи "+strings.Join(unknown, ", ")+".", false)
	case err != nil:
		// Значение ключа не прошло запись (обычно невалидный JSON) — ошибка
		// данных файла, а не сервера.
		p.admin.audit(ctx, "settings_import", map[string]any{"via": "html", "error": "bad_key"})
		redirectFlash(w, r, back, "Значение одного из ключей не принимается.", false)
	default:
		p.admin.audit(ctx, "settings_import", map[string]any{
			"applied": applied, "skipped": skipped, "via": "html",
		})
		redirectFlash(w, r, back, "Настройки импортированы: применено "+
			strconv.Itoa(applied)+", пропущено "+strconv.Itoa(skipped)+".", true)
	}
}

// handlePageBackup — GET /admin/backup (сессия админа): SQL-дамп вложением,
// как у JSON API /api/v1/admin/backup (включая защиту 413 от гигантского
// audit_log — здесь флешем с подсказкой CLI).
func (p *PagesAPI) handlePageBackup(w http.ResponseWriter, r *http.Request) {
	name, dump, err := p.admin.dumpBackup(r.Context())
	var tooLarge errBackupTooLarge
	if errors.As(err, &tooLarge) {
		redirectFlash(w, r, "/admin/settings",
			"Журнал аудита слишком велик для скачивания через браузер ("+
				strconv.FormatInt(tooLarge.rows, 10)+
				" строк) — снимите дамп CLI: twofa -backup out.sql", false)
		return
	}
	if err != nil {
		flash500(w, r, "/admin/settings", err)
		return
	}
	p.admin.audit(r.Context(), "backup_download", map[string]any{"via": "html"})
	w.Header().Set("Content-Type", "application/sql; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(dump)
}
