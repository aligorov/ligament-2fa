// Админ REST API (спека §7): Bearer admin_token из настроек (сравнение
// хешей в постоянном времени), CRUD пользователей, сбросы второго фактора
// (reset-totp c новой партией резервных кодов, reset-webauthn,
// unlink-telegram, отзыв устройств), аудит с фильтрами, активные
// челленджи (только метаданные, без code_hash) и настройки: GET — маской,
// PUT — точечный мерж (маска/пустое значение = «не менять»), regenerate —
// только для генерируемых секретов. Все действия пишутся в аудит как
// admin_action.
package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/aligorov/twofa/internal/secrets"
	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
)

// settingsMask — маска секретного значения из settings.M.Masked (см.
// settings.maskValue); PUT с таким значением = «не менять секрет».
const settingsMask = "••••"

// regenerableKeys — ключи, допускающие регенерацию случайного значения.
var regenerableKeys = map[string]struct{}{
	"admin_token":   {},
	"radius.secret": {},
}

// AdminAPI — зависимости и маршруты /api/v1/admin/*.
type AdminAPI struct {
	st *store.Store
	m  *settings.M
}

// NewAdminAPI собирает админ API.
func NewAdminAPI(st *store.Store, m *settings.M) *AdminAPI {
	return &AdminAPI{st: st, m: m}
}

// Register монтирует админ маршруты в chi-роутер (все под RequireAdminToken).
func (a *AdminAPI) Register(r chi.Router) {
	r.Route("/api/v1/admin", func(r chi.Router) {
		r.Use(a.RequireAdminToken)
		r.Get("/users", a.handleUsersList)
		r.Post("/users", a.handleUserCreate)
		r.Get("/users/{id}", a.handleUserGet)
		r.Patch("/users/{id}", a.handleUserPatch)
		r.Delete("/users/{id}", a.handleUserDelete)
		r.Post("/users/{id}/reset-totp", a.handleResetTOTP)
		r.Post("/users/{id}/reset-webauthn", a.handleResetWebauthn)
		r.Post("/users/{id}/unlink-telegram", a.handleUnlinkTelegram)
		r.Delete("/users/{id}/devices", a.handleDeleteDevices)
		r.Get("/audit", a.handleAudit)
		r.Get("/challenges", a.handleChallenges)
		r.Get("/settings", a.handleSettingsGet)
		r.Put("/settings", a.handleSettingsPut)
		r.Post("/settings/regenerate", a.handleSettingsRegenerate)
	})
}

// RequireAdminToken пропускает запросы с Authorization: Bearer <admin_token>.
// Сравниваются SHA-256 обоих значений в постоянном времени — длина секрета
// не раскрывается и сравнение не зависит от совпавшего префикса.
func (a *AdminAPI) RequireAdminToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := sha256.Sum256([]byte(a.m.Get().AdminToken))
		got := sha256.Sum256([]byte(bearerToken(r)))
		if subtle.ConstantTimeCompare(want[:], got[:]) != 1 {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// bearerToken извлекает токен из заголовка Authorization: Bearer <token>.
func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, prefix) {
		return strings.TrimPrefix(h, prefix)
	}
	return ""
}

// audit пишет событие admin_action (detail.action — конкретное действие);
// ошибка записи логируется и проглатывается.
func (a *AdminAPI) audit(ctx context.Context, action string, detail map[string]any) {
	d := map[string]any{"action": action}
	for k, v := range detail {
		d[k] = v
	}
	if err := a.st.Audit(ctx, "", "admin_action", d, "", "ok"); err != nil {
		slog.Warn("api: аудит admin_action не записан", "action", action, "error", err)
	}
}

// userByIDParam разбирает {id} из URL; при ошибке сам отвечает и возвращает
// нулевой UUID.
func userByIDParam(w http.ResponseWriter, r *http.Request) uuid.UUID {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return uuid.Nil
	}
	return id
}

// loadUser отвечает 404/500 или возвращает пользователя.
func (a *AdminAPI) loadUser(w http.ResponseWriter, r *http.Request, id uuid.UUID) *store.User {
	u, err := a.st.UserByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found")
		return nil
	}
	if err != nil {
		slog.Error("api: admin чтение пользователя", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return nil
	}
	return u
}

// ---- пользователи ----

// adminUser — пользователь в ответах API: password_hash никогда не покидает БД.
type adminUser struct {
	ID             string            `json:"id"`
	Username       string            `json:"username"`
	Role           string            `json:"role"`
	Enabled        bool              `json:"enabled"`
	Email          string            `json:"email"`
	Phone          string            `json:"phone"`
	TelegramLinked bool              `json:"telegram_linked"`
	PreferChannels []string          `json:"prefer_channels"`
	RadiusPush     bool              `json:"radius_push"`
	RadiusReply    map[string]string `json:"radius_reply"`
}

// toAdminUser переводит store.User в безопасное представление ответа;
// nil prefer_channels становится пустым массивом (стабильный JSON).
func toAdminUser(u *store.User) adminUser {
	chs := make([]string, len(u.PreferChannels))
	for i, c := range u.PreferChannels {
		chs[i] = string(c)
	}
	return adminUser{
		ID:             u.ID.String(),
		Username:       u.Username,
		Role:           u.Role,
		Enabled:        u.Enabled,
		Email:          u.Email,
		Phone:          u.Phone,
		TelegramLinked: u.TelegramChatID != nil,
		PreferChannels: chs,
		RadiusPush:     u.RadiusPush,
		RadiusReply:    u.RadiusReply,
	}
}

// handleUsersList — GET /api/v1/admin/users.
func (a *AdminAPI) handleUsersList(w http.ResponseWriter, r *http.Request) {
	users, err := a.st.UserList(r.Context())
	if err != nil {
		slog.Error("api: admin список пользователей", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	out := make([]adminUser, len(users))
	for i, u := range users {
		out[i] = toAdminUser(u)
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

type adminUserCreateReq struct {
	Username       string   `json:"username"`
	Password       string   `json:"password"`
	Email          string   `json:"email"`
	Phone          string   `json:"phone"`
	Role           string   `json:"role"`
	PreferChannels []string `json:"prefer_channels"`
}

// handleUserCreate — POST /api/v1/admin/users {username,password,...}.
// Пароль хешируется argon2id; занятое имя → 409.
func (a *AdminAPI) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	var req adminUserCreateReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	u := &store.User{
		Username:     req.Username,
		Role:         req.Role,
		Enabled:      true,
		Email:        req.Email,
		Phone:        req.Phone,
		PasswordHash: secrets.HashPassword(req.Password),
	}
	if u.Role == "" {
		u.Role = "user"
	}
	if req.PreferChannels != nil {
		chs, ok := parseChannels(req.PreferChannels)
		if !ok {
			writeError(w, http.StatusBadRequest, "bad_channel")
			return
		}
		u.PreferChannels = chs
	}
	if err := a.st.UserCreate(r.Context(), u); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			writeError(w, http.StatusConflict, "username_taken")
			return
		}
		slog.Error("api: admin создать пользователя", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	a.audit(r.Context(), "user_create", map[string]any{"username": u.Username})
	writeJSON(w, http.StatusCreated, toAdminUser(u))
}

// handleUserGet — GET /api/v1/admin/users/{id}.
func (a *AdminAPI) handleUserGet(w http.ResponseWriter, r *http.Request) {
	id := userByIDParam(w, r)
	if id == uuid.Nil {
		return
	}
	if u := a.loadUser(w, r, id); u != nil {
		writeJSON(w, http.StatusOK, toAdminUser(u))
	}
}

type adminUserPatchReq struct {
	Username       *string           `json:"username"`
	Password       *string           `json:"password"`
	Email          *string           `json:"email"`
	Phone          *string           `json:"phone"`
	Role           *string           `json:"role"`
	Enabled        *bool             `json:"enabled"`
	PreferChannels *[]string         `json:"prefer_channels"`
	RadiusPush     *bool             `json:"radius_push"`
	RadiusReply    map[string]string `json:"radius_reply"`
}

// handleUserPatch — PATCH /api/v1/admin/users/{id}: точечная смена полей
// (nil-поля не трогаются); смена пароля хешируется argon2id.
func (a *AdminAPI) handleUserPatch(w http.ResponseWriter, r *http.Request) {
	id := userByIDParam(w, r)
	if id == uuid.Nil {
		return
	}
	var req adminUserPatchReq
	if !decodeJSON(w, r, &req) {
		return
	}
	u := a.loadUser(w, r, id)
	if u == nil {
		return
	}
	if req.Username != nil {
		if *req.Username == "" {
			writeError(w, http.StatusBadRequest, "bad_request")
			return
		}
		u.Username = *req.Username
	}
	if req.Password != nil {
		if *req.Password == "" {
			writeError(w, http.StatusBadRequest, "bad_request")
			return
		}
		u.PasswordHash = secrets.HashPassword(*req.Password)
	}
	if req.Email != nil {
		u.Email = *req.Email
	}
	if req.Phone != nil {
		u.Phone = *req.Phone
	}
	if req.Role != nil {
		u.Role = *req.Role
	}
	if req.Enabled != nil {
		u.Enabled = *req.Enabled
	}
	if req.PreferChannels != nil {
		chs, ok := parseChannels(*req.PreferChannels)
		if !ok {
			writeError(w, http.StatusBadRequest, "bad_channel")
			return
		}
		u.PreferChannels = chs
	}
	if req.RadiusPush != nil {
		u.RadiusPush = *req.RadiusPush
	}
	if req.RadiusReply != nil {
		u.RadiusReply = req.RadiusReply
	}
	if err := a.st.UserUpdate(r.Context(), u); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			writeError(w, http.StatusConflict, "username_taken")
			return
		}
		slog.Error("api: admin обновить пользователя", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	a.audit(r.Context(), "user_update", map[string]any{"user_id": u.ID.String()})
	writeJSON(w, http.StatusOK, toAdminUser(u))
}

// handleUserDelete — DELETE /api/v1/admin/users/{id} (каскад чистит
// секреты, сессии и устройства).
func (a *AdminAPI) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	id := userByIDParam(w, r)
	if id == uuid.Nil {
		return
	}
	if err := a.st.UserDelete(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found")
			return
		}
		slog.Error("api: admin удалить пользователя", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	a.audit(r.Context(), "user_delete", map[string]any{"user_id": id.String()})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---- сбросы второго фактора ----

// handleResetTOTP — POST .../reset-totp: удаляет TOTP-секрет и выдаёт новую
// партию резервных кодов (старые аннулируются); коды возвращаются один раз —
// админ передаёт их пользователю.
func (a *AdminAPI) handleResetTOTP(w http.ResponseWriter, r *http.Request) {
	id := userByIDParam(w, r)
	if id == uuid.Nil {
		return
	}
	u := a.loadUser(w, r, id)
	if u == nil {
		return
	}
	if err := a.st.TOTPDelete(r.Context(), u.ID); err != nil {
		slog.Error("api: admin reset-totp", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	codes, err := replaceBackupCodes(r.Context(), a.st, u.ID)
	if err != nil {
		slog.Error("api: admin reset-totp коды", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	a.audit(r.Context(), "user_reset_totp", map[string]any{"user_id": u.ID.String()})
	writeJSON(w, http.StatusOK, map[string]any{"backup_codes": codes})
}

// replaceBackupCodes атомарно заменяет резервные коды пользователя и
// возвращает открытые значения (хранятся только SHA-256).
func replaceBackupCodes(ctx context.Context, st *store.Store, userID uuid.UUID) ([]string, error) {
	codes := secrets.GenBackupCodes()
	hashes := make([][]byte, len(codes))
	for i, c := range codes {
		hashes[i] = secrets.SHA256(c)
	}
	if err := st.BackupReplace(ctx, userID, hashes); err != nil {
		return nil, err
	}
	return codes, nil
}

// handleResetWebauthn — POST .../reset-webauthn: удаляет все passkeys.
func (a *AdminAPI) handleResetWebauthn(w http.ResponseWriter, r *http.Request) {
	id := userByIDParam(w, r)
	if id == uuid.Nil {
		return
	}
	u := a.loadUser(w, r, id)
	if u == nil {
		return
	}
	if err := a.st.WACredsDeleteForUser(r.Context(), u.ID); err != nil {
		slog.Error("api: admin reset-webauthn", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	a.audit(r.Context(), "user_reset_webauthn", map[string]any{"user_id": u.ID.String()})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleUnlinkTelegram — POST .../unlink-telegram: отвязывает чат бота.
func (a *AdminAPI) handleUnlinkTelegram(w http.ResponseWriter, r *http.Request) {
	id := userByIDParam(w, r)
	if id == uuid.Nil {
		return
	}
	u := a.loadUser(w, r, id)
	if u == nil {
		return
	}
	u.TelegramChatID = nil
	if err := a.st.UserUpdate(r.Context(), u); err != nil {
		slog.Error("api: admin unlink-telegram", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	a.audit(r.Context(), "user_unlink_telegram", map[string]any{"user_id": u.ID.String()})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleDeleteDevices — DELETE .../devices: отзыв всех доверенных устройств.
func (a *AdminAPI) handleDeleteDevices(w http.ResponseWriter, r *http.Request) {
	id := userByIDParam(w, r)
	if id == uuid.Nil {
		return
	}
	u := a.loadUser(w, r, id)
	if u == nil {
		return
	}
	if err := a.st.DeviceDeleteAllForUser(r.Context(), u.ID); err != nil {
		slog.Error("api: admin devices", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	a.audit(r.Context(), "user_devices_revoke", map[string]any{"user_id": u.ID.String()})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---- аудит и челленджи ----

// handleAudit — GET /api/v1/admin/audit?username=&event=&since=&until=&limit=
// (since/until — RFC3339, новые первыми).
func (a *AdminAPI) handleAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.AuditFilter{Username: q.Get("username"), Event: q.Get("event")}
	if s := q.Get("since"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request")
			return
		}
		f.Since = t
	}
	if s := q.Get("until"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request")
			return
		}
		f.Until = t
	}
	if s := q.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > 1000 {
			writeError(w, http.StatusBadRequest, "bad_request")
			return
		}
		f.Limit = n
	}
	rows, err := a.st.AuditList(r.Context(), f)
	if err != nil {
		slog.Error("api: admin аудит", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	out := make([]map[string]any, len(rows))
	for i, row := range rows {
		out[i] = map[string]any{
			"id": row.ID, "ts": row.Ts, "username": row.Username,
			"event": row.Event, "detail": row.Detail,
			"src_ip": row.SrcIP, "result": row.Result,
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": out})
}

// handleChallenges — GET /api/v1/admin/challenges: активные челленджи
// прямым SQL, ТОЛЬКО метаданные (code_hash не выбирается; push_state —
// только для telegram_push, у webauthn_session в этой колонке лежит
// сессия церемонии, которая не должна покидать сервер).
func (a *AdminAPI) handleChallenges(w http.ResponseWriter, r *http.Request) {
	rows, err := a.st.Pool().Query(r.Context(), `
		SELECT id, user_id, channel, expires_at, attempts_left, purpose, created_at,
		       CASE WHEN channel = 'telegram_push' THEN COALESCE(push_state, '') ELSE '' END
		FROM challenges
		WHERE expires_at > now() AND used_at IS NULL
		ORDER BY created_at DESC
		LIMIT 500`)
	if err != nil {
		slog.Error("api: admin челленджи", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	defer rows.Close()

	out := make([]map[string]any, 0, 16)
	for rows.Next() {
		var (
			id, userID     uuid.UUID
			ch             string
			expiresAt      time.Time
			attempts       int
			purpose, state string
			createdAt      time.Time
		)
		if err := rows.Scan(&id, &userID, &ch, &expiresAt, &attempts, &purpose, &createdAt, &state); err != nil {
			slog.Error("api: admin челленджи scan", "error", err)
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		out = append(out, map[string]any{
			"id": id.String(), "user_id": userID.String(), "channel": ch,
			"purpose": purpose, "push_state": state, "attempts_left": attempts,
			"expires_at": expiresAt, "created_at": createdAt,
		})
	}
	if err := rows.Err(); err != nil {
		slog.Error("api: admin челленджи итерация", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"challenges": out})
}

// ---- настройки ----

// handleSettingsGet — GET /api/v1/admin/settings: дерево Masked — секреты
// только маской {"set":bool,"value":"••••"}.
func (a *AdminAPI) handleSettingsGet(w http.ResponseWriter, r *http.Request) {
	masked, err := a.m.Masked(r.Context())
	if err != nil {
		slog.Error("api: admin settings get", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(w, http.StatusOK, masked)
}

// handleSettingsPut — PUT /api/v1/admin/settings {ключ: значение}: мерж.
// Объекты сливаются с текущим значением рекурсивно; маска ("••••" или
// {"set":...,"value":"••••"}) и пустая строка на любом уровне означают
// «не менять это поле» (спека §7: «пустое/маскированное значение = не
// менять»). Атомарность: СНАЧАЛА валидируются все ключи — неизвестный
// отклоняет запрос целиком (400 unknown_key) БЕЗ применения остальных;
// затем применяются все годные. Маскированные значения пропускаются как
// раньше.
func (a *AdminAPI) handleSettingsPut(w http.ResponseWriter, r *http.Request) {
	var body map[string]json.RawMessage
	if !decodeJSON(w, r, &body) {
		return
	}
	ctx := r.Context()

	// Первый проход — валидация всех ключей ДО записи любого значения:
	// ни один ключ не применяется, пока весь запрос не признан корректным.
	keys := make([]string, 0, len(body))
	for key := range body {
		if !settings.IsKnownKey(key) {
			writeJSON(w, http.StatusBadRequest,
				map[string]string{"error": "unknown_key", "key": key})
			return
		}
		keys = append(keys, key)
	}
	sort.Strings(keys) // стабильный порядок аудита

	// Второй проход — применение (маска/пустое значение = «не менять»).
	changed := make([]string, 0, len(keys))
	for _, key := range keys {
		val := body[key]
		if isNoChangeValue(val) {
			continue
		}
		merged, err := a.mergedValue(ctx, key, val)
		if err != nil {
			// Ошибка чтения текущего значения из БД — не вина клиента.
			slog.Error("api: admin settings мерж", "key", key, "error", err)
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		if err := a.m.Put(ctx, key, merged); err != nil {
			// Невалидный JSON значения — ошибка клиента.
			writeError(w, http.StatusBadRequest, "bad_key")
			return
		}
		changed = append(changed, key)
	}
	a.audit(ctx, "settings_update", map[string]any{"keys": changed})
	a.handleSettingsGet(w, r)
}

// mergedValue сливает входящее значение ключа с текущим из БД (deep merge
// объектов; скаляры и массивы заменяются целиком). Отсутствующий ключ
// (pgx.ErrNoRows) — входящее значение как есть; любая другая ошибка БД
// возвращается наверх (вызывающий отвечает 500, а не молча заменяет значение).
func (a *AdminAPI) mergedValue(ctx context.Context, key string, inc json.RawMessage) (json.RawMessage, error) {
	var cur json.RawMessage
	err := a.st.Pool().QueryRow(ctx,
		`SELECT value FROM settings WHERE key = $1`, key).Scan(&cur)
	if errors.Is(err, pgx.ErrNoRows) {
		return inc, nil // текущего значения нет — просто записать
	}
	if err != nil {
		return nil, fmt.Errorf("чтение текущего значения %s: %w", key, err)
	}
	if len(cur) == 0 {
		return inc, nil
	}
	return mergeSettingValue(cur, inc), nil
}

// mergeSettingValue рекурсивно мержит inc в cur (оба — JSON-объекты;
// не-объекты заменяются). Поля-маски и пустые строки пропускаются —
// текущее значение сохраняется.
func mergeSettingValue(cur, inc json.RawMessage) json.RawMessage {
	var curM, incM map[string]json.RawMessage
	if json.Unmarshal(cur, &curM) != nil || curM == nil ||
		json.Unmarshal(inc, &incM) != nil || incM == nil {
		return inc // хотя бы одно не объект — заменяем целиком
	}
	mergeSettingMap(curM, incM)
	out, err := json.Marshal(curM)
	if err != nil {
		return inc
	}
	return out
}

func mergeSettingMap(dst, inc map[string]json.RawMessage) {
	for k, v := range inc {
		if isNoChangeValue(v) {
			continue // маска/пустое — оставить текущее значение поля
		}
		// Вложенные объекты мержатся так же рекурсивно.
		if merged := mergeSettingValue(dst[k], v); merged != nil {
			dst[k] = merged
		}
	}
}

// isNoChangeValue распознаёт значения «не менять»: строку-маску "••••",
// пустую строку или объект маски {"set":bool,"value":"••••"} (формат
// settings.M.Masked).
func isNoChangeValue(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s == "" || s == settingsMask
	}
	var m struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(raw, &m); err == nil {
		return m.Value == settingsMask
	}
	return false
}

type regenReq struct {
	Key string `json:"key"`
}

// handleSettingsRegenerate — POST /api/v1/admin/settings/regenerate {key}:
// только admin_token / radius.secret; новое значение RandomToken(32)
// возвращается один раз (GET всегда маскирует).
func (a *AdminAPI) handleSettingsRegenerate(w http.ResponseWriter, r *http.Request) {
	var req regenReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if _, ok := regenerableKeys[req.Key]; !ok {
		writeError(w, http.StatusBadRequest, "bad_key")
		return
	}
	val := secrets.RandomToken(tokenBytes)
	b, err := json.Marshal(val)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	if err := a.m.Put(r.Context(), req.Key, b); err != nil {
		slog.Error("api: admin settings regenerate", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	a.audit(r.Context(), "settings_regenerate", map[string]any{"key": req.Key})
	writeJSON(w, http.StatusOK, map[string]any{"key": req.Key, "value": val})
}
