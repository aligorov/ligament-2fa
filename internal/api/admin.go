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
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/aligorov/twofa/internal/acme"
	"github.com/aligorov/twofa/internal/auth"
	"github.com/aligorov/twofa/internal/channel"
	"github.com/aligorov/twofa/internal/license"
	"github.com/aligorov/twofa/internal/oidc"
	"github.com/aligorov/twofa/internal/radiusserver"
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
	fw  firewallInvalidate // nil — мутации списков не сбрасывают кэш guard
	st  *store.Store
	m   *settings.M
	lic *license.Manager // nil — лицензирование не смонтировано (тесты)
	// countAuditRows — подсчёт строк audit_log для лимита HTTP-бэкапа;
	// отдельное поле, чтобы тест 413-ветки подменял счётчик без вставки
	// полумиллиона строк.
	countAuditRows func(ctx context.Context) (int64, error)
	radius         *radiusserver.Server
	acme           *acme.Manager
}

func (a *AdminAPI) SetRadius(srv *radiusserver.Server) { a.radius = srv }
func (a *AdminAPI) SetACME(mgr *acme.Manager)          { a.acme = mgr }

// NewAdminAPI собирает админ API.
func NewAdminAPI(st *store.Store, m *settings.M, lic *license.Manager) *AdminAPI {
	a := &AdminAPI{st: st, m: m, lic: lic}
	a.countAuditRows = func(ctx context.Context) (int64, error) {
		var n int64
		if err := st.Pool().QueryRow(ctx, `SELECT count(*) FROM audit_log`).Scan(&n); err != nil {
			return 0, err
		}
		return n, nil
	}
	return a
}

// box возвращает secrets.Box из настроек master_key (nil если настройки недоступны).
func (a *AdminAPI) box() *secrets.Box {
	if a.m != nil && a.m.Get() != nil && a.m.Get().MasterKeyB64 != "" {
		b, _ := secrets.NewBox(a.m.Get().MasterKeyB64)
		return b
	}
	return nil
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
		r.Get("/settings/export", a.handleSettingsExport)
		r.Put("/settings/import", a.handleSettingsImport)
		r.Get("/backup", a.handleBackup)
		r.Get("/firewall", a.handleFirewallGet)
		r.Post("/firewall/ip", a.handleFirewallIPAdd)
		r.Delete("/firewall/ip/{id}", a.handleFirewallIPDelete)
		r.Delete("/firewall/bans/{ip}", a.handleFirewallUnban)
		r.Get("/groups", a.handleGroupsList)
		r.Post("/groups", a.handleGroupCreate)
		r.Get("/groups/{id}", a.handleGroupGet)
		r.Put("/groups/{id}", a.handleGroupUpdate)
		r.Delete("/groups/{id}", a.handleGroupDelete)
		r.Get("/groups/{id}/members", a.handleGroupMembersGet)
		r.Put("/groups/{id}/members", a.handleGroupMembersSet)
		r.Get("/oidc/clients", a.handleOIDCClientsList)
		r.Post("/oidc/clients", a.handleOIDCClientCreate)
		r.Get("/oidc/clients/{id}", a.handleOIDCClientGet)
		r.Put("/oidc/clients/{id}", a.handleOIDCClientUpdate)
		r.Delete("/oidc/clients/{id}", a.handleOIDCClientDelete)
		r.Get("/radius/cert", a.handleRadiusCertGet)
		r.Post("/radius/acme/renew", a.handleRadiusACMERenew)
		r.Post("/ldap/test", a.handleLdapTest)
		r.Post("/ldap/test-user", a.handleLdapTestUser)
		r.Post("/ldap/sync", a.handleLdapSync)
		a.registerLicenseRoutes(r)
	})
}

// RequireAdminToken пропускает запросы с Authorization: Bearer <admin_token>.
// Сравниваются SHA-256 обоих значений в постоянном времени — длина секрета
// не раскрывается и сравнение не зависит от совпавшего префикса. Неудачная
// попытка пишется в аудит (SEC-010, event admin_auth_fail) — брут токена
// виден в журнале наравне с брутом паролей.
func (a *AdminAPI) RequireAdminToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := sha256.Sum256([]byte(a.m.Get().AdminToken))
		got := sha256.Sum256([]byte(bearerToken(r)))
		if subtle.ConstantTimeCompare(want[:], got[:]) != 1 {
			if err := a.st.Audit(r.Context(), "", "admin_auth_fail",
				map[string]any{"has_token": bearerToken(r) != ""}, clientIP(r), "fail"); err != nil {
				slog.Warn("api: аудит admin_auth_fail не записан", "error", err)
			}
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
	LDAPGroups     []string          `json:"ldap_groups"`
}

// toAdminUser переводит store.User в безопасное представление ответа;
// nil prefer_channels становится пустым массивом (стабильный JSON).
func toAdminUser(u *store.User) adminUser {
	chs := make([]string, len(u.PreferChannels))
	for i, c := range u.PreferChannels {
		chs[i] = string(c)
	}
	ldapGrps := u.LDAPGroups
	if ldapGrps == nil {
		ldapGrps = []string{}
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
		LDAPGroups:     ldapGrps,
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
// Пароль хешируется argon2id; занятое имя → 409. Создание сверх лимита
// лицензии (активные пользователи) → 403 license_limit (report §3.3:
// блокируется только СОЗДАНИЕ, вход существующим — никогда).
func (a *AdminAPI) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	var req adminUserCreateReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	if exceeded, st := a.licenseExceeded(r); exceeded {
		a.denyLicenseLimit(w, r, st)
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
	if b := a.box(); b != nil {
		u.PasswordEnc = b.EncryptAAD(u.Username, []byte(req.Password))
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
// (nil-поля не трогаются); смена пароля хешируется argon2id. Включение
// (enabled=false→true) сверх лимита лицензии → 403 license_limit — это
// «создание» активного пользователя; выключение не ограничивается.
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
	if req.Enabled != nil && *req.Enabled && !u.Enabled {
		if exceeded, st := a.licenseExceeded(r); exceeded {
			a.denyLicenseLimit(w, r, st)
			return
		}
	}
	oldUsername := u.Username
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
		if b := a.box(); b != nil {
			u.PasswordEnc = b.EncryptAAD(u.Username, []byte(*req.Password))
		}
	} else if req.Username != nil && *req.Username != oldUsername && len(u.PasswordEnc) > 0 {
		if b := a.box(); b != nil {
			if raw, err := b.DecryptAAD(oldUsername, u.PasswordEnc); err == nil {
				u.PasswordEnc = b.EncryptAAD(u.Username, raw)
			}
		}
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

// ---- файрвол/fail2ban: чёрные/белые списки и автобаны ----

// firewallIPReq — добавление CIDR в список (kind: allow|deny).
type firewallIPReq struct {
	Kind string `json:"kind"`
	CIDR string `json:"cidr"`
	Note string `json:"note"`
}

// handleFirewallGet — GET /api/v1/admin/firewall: оба списка + активные
// банки + текущие настройки fail2ban.
func (a *AdminAPI) handleFirewallGet(w http.ResponseWriter, r *http.Request) {
	lists, err := a.st.IPLists(r.Context())
	if err != nil {
		slog.Error("api: firewall lists", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	bans, err := a.st.BansActive(r.Context())
	if err != nil {
		slog.Error("api: firewall bans", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	allow := make([]store.IPList, 0)
	deny := make([]store.IPList, 0)
	for _, l := range lists {
		if l.Kind == "allow" {
			allow = append(allow, l)
		} else {
			deny = append(deny, l)
		}
	}
	f := a.m.Get().Fail2ban
	a.audit(r.Context(), "firewall_view", nil)
	writeJSON(w, http.StatusOK, map[string]any{
		"allow": allow, "deny": deny, "bans": bans,
		"settings": map[string]any{
			"enabled": f.Enabled, "max_fail": f.MaxFail,
			"window": f.Window.String(), "ban_time": f.BanTime.String(),
		},
	})
}

// handleFirewallIPAdd — POST /api/v1/admin/firewall/ip {kind, cidr, note}.
func (a *AdminAPI) handleFirewallIPAdd(w http.ResponseWriter, r *http.Request) {
	var req firewallIPReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Kind != "allow" && req.Kind != "deny" {
		writeError(w, http.StatusBadRequest, "bad_kind")
		return
	}
	row, err := a.st.IPListAdd(r.Context(), req.Kind, req.CIDR, req.Note)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_cidr")
		return
	}
	if a.fw != nil {
		a.fw.Invalidate()
	}
	a.audit(r.Context(), "firewall_ip_add", map[string]any{"kind": req.Kind, "cidr": row.CIDR})
	writeJSON(w, http.StatusCreated, row)
}

// handleFirewallIPDelete — DELETE /api/v1/admin/firewall/ip/{id}.
func (a *AdminAPI) handleFirewallIPDelete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	if err := a.st.IPListDelete(r.Context(), id); err != nil {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	if a.fw != nil {
		a.fw.Invalidate()
	}
	a.audit(r.Context(), "firewall_ip_delete", map[string]any{"id": id.String()})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleFirewallUnban — DELETE /api/v1/admin/firewall/bans/{ip}.
func (a *AdminAPI) handleFirewallUnban(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	if net.ParseIP(ip) == nil {
		writeError(w, http.StatusBadRequest, "bad_ip")
		return
	}
	if err := a.st.BanDelete(r.Context(), ip); err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	a.audit(r.Context(), "firewall_unban", map[string]any{"ip": ip})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// firewallInvalidate — узкий интерфейс guard (без цикла импортов).
type firewallInvalidate interface{ Invalidate() }

// SetFirewall подключает guard для сброса кэша списков при мутациях.
func (a *AdminAPI) SetFirewall(f firewallInvalidate) { a.fw = f }

// ---- OpenID Connect: клиентские приложения ----

// adminOIDCClient — клиент OIDC в ответах API: секрет никогда не покидает
// БД (в ответе создания — только что сгенерированный, один раз).
type adminOIDCClient struct {
	ID            string    `json:"id"`
	ClientID      string    `json:"client_id"`
	Name          string    `json:"name"`
	RedirectURIs  []string  `json:"redirect_uris"`
	IsPublic      bool      `json:"is_public"`
	AllowedUsers  []string  `json:"allowed_users"`
	AllowedGroups []string  `json:"allowed_groups"`
	CreatedAt     time.Time `json:"created_at"`
}

// toAdminOIDCClient переводит store.OIDCClient в безопасное представление;
// nil redirect_uris становится пустым массивом (стабильный JSON).
func toAdminOIDCClient(c store.OIDCClient) adminOIDCClient {
	uris := c.RedirectURIs
	if uris == nil {
		uris = []string{}
	}
	allowedUsers := c.AllowedUsers
	if allowedUsers == nil {
		allowedUsers = []string{}
	}
	allowedGroups := c.AllowedGroups
	if allowedGroups == nil {
		allowedGroups = []string{}
	}
	return adminOIDCClient{
		ID:            c.ID.String(),
		ClientID:      c.ClientID,
		Name:          c.Name,
		RedirectURIs:  uris,
		IsPublic:      c.IsPublic,
		AllowedUsers:  allowedUsers,
		AllowedGroups: allowedGroups,
		CreatedAt:     c.CreatedAt,
	}
}

// validateRedirectURIs проверяет список redirect_uri: непустой, каждый —
// абсолютный http(s)-URL. Возвращает нормализованный список или ошибку.
func validateRedirectURIs(uris []string) ([]string, error) {
	if len(uris) == 0 {
		return nil, errors.New("нужен хотя бы один redirect_uri")
	}
	out := make([]string, 0, len(uris))
	for _, raw := range uris {
		u := strings.TrimSpace(raw)
		if u == "" {
			continue
		}
		parsed, err := url.Parse(u)
		if err != nil || parsed.Host == "" ||
			(parsed.Scheme != "http" && parsed.Scheme != "https") {
			return nil, fmt.Errorf("redirect_uri %q не является абсолютным http(s)-URL", u)
		}
		out = append(out, u)
	}
	if len(out) == 0 {
		return nil, errors.New("нужен хотя бы один redirect_uri")
	}
	return out, nil
}

// handleOIDCClientsList — GET /api/v1/admin/oidc/clients.
func (a *AdminAPI) handleOIDCClientsList(w http.ResponseWriter, r *http.Request) {
	clients, err := a.st.OIDCClients(r.Context())
	if err != nil {
		slog.Error("api: admin oidc список клиентов", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	out := make([]adminOIDCClient, len(clients))
	for i, c := range clients {
		out[i] = toAdminOIDCClient(c)
	}
	writeJSON(w, http.StatusOK, map[string]any{"clients": out})
}

type oidcClientCreateReq struct {
	Name          string   `json:"name"`
	ClientID      string   `json:"client_id"`
	ClientSecret  string   `json:"client_secret"`
	RedirectURIs  []string `json:"redirect_uris"`
	IsPublic      bool     `json:"is_public"`
	AllowedUsers  []string `json:"allowed_users"`
	AllowedGroups []string `json:"allowed_groups"`
}

// handleOIDCClientCreate — POST /api/v1/admin/oidc/clients {name,
// redirect_uris, is_public, client_id, client_secret}: генерирует client_id и client_secret (если не заданы);
// секрет возвращается ровно один раз (в БД — только хеш).
func (a *AdminAPI) handleOIDCClientCreate(w http.ResponseWriter, r *http.Request) {
	var req oidcClientCreateReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	uris, err := validateRedirectURIs(req.RedirectURIs)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_redirect_uri")
		return
	}
	cid := strings.TrimSpace(req.ClientID)
	if cid == "" {
		cid = oidc.NewClientID()
	}
	c := &store.OIDCClient{
		ClientID:      cid,
		Name:          strings.TrimSpace(req.Name),
		RedirectURIs:  uris,
		IsPublic:      req.IsPublic,
		AllowedUsers:  cleanStringList(req.AllowedUsers),
		AllowedGroups: cleanStringList(req.AllowedGroups),
	}
	resp := map[string]any{
		"id": "", "client_id": c.ClientID, "name": c.Name,
		"redirect_uris":  uris, "is_public": c.IsPublic,
		"allowed_users":  c.AllowedUsers,
		"allowed_groups": c.AllowedGroups,
	}
	if !c.IsPublic {
		secret := strings.TrimSpace(req.ClientSecret)
		if secret == "" {
			secret = oidc.NewClientSecret()
		}
		c.ClientSecretHash = oidc.HashClientSecret(secret)
		// Секрет показывается один раз — только в ответе создания.
		resp["client_secret"] = secret
	}
	if err := a.st.OIDCClientUpsert(r.Context(), c); err != nil {
		slog.Error("api: admin oidc создать клиента", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	a.audit(r.Context(), "oidc_client_create", map[string]any{
		"client_id": c.ClientID, "is_public": c.IsPublic,
	})
	resp["id"] = c.ID.String()
	resp["created_at"] = c.CreatedAt
	writeJSON(w, http.StatusCreated, resp)
}

// handleOIDCClientGet — GET /api/v1/admin/oidc/clients/{id}.
func (a *AdminAPI) handleOIDCClientGet(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	client, err := a.st.OIDCClientByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found")
			return
		}
		slog.Error("api: admin oidc получить клиента", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(w, http.StatusOK, toAdminOIDCClient(*client))
}

type oidcClientUpdateReq struct {
	Name          string   `json:"name"`
	RedirectURIs  []string `json:"redirect_uris"`
	IsPublic      *bool    `json:"is_public,omitempty"`
	AllowedUsers  []string `json:"allowed_users"`
	AllowedGroups []string `json:"allowed_groups"`
	ClientSecret  string   `json:"client_secret,omitempty"`
}

// handleOIDCClientUpdate — PUT /api/v1/admin/oidc/clients/{id}.
func (a *AdminAPI) handleOIDCClientUpdate(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	client, err := a.st.OIDCClientByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found")
			return
		}
		slog.Error("api: admin oidc клиент не найден", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	var req oidcClientUpdateReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Name) != "" {
		client.Name = strings.TrimSpace(req.Name)
	}
	if len(req.RedirectURIs) > 0 {
		uris, err := validateRedirectURIs(req.RedirectURIs)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_redirect_uri")
			return
		}
		client.RedirectURIs = uris
	}
	if req.IsPublic != nil {
		client.IsPublic = *req.IsPublic
	}
	if req.AllowedUsers != nil {
		client.AllowedUsers = cleanStringList(req.AllowedUsers)
	}
	if req.AllowedGroups != nil {
		client.AllowedGroups = cleanStringList(req.AllowedGroups)
	}
	resp := map[string]any{
		"ok": true,
	}
	if !client.IsPublic && strings.TrimSpace(req.ClientSecret) != "" {
		secret := strings.TrimSpace(req.ClientSecret)
		client.ClientSecretHash = oidc.HashClientSecret(secret)
		resp["client_secret"] = secret
	}
	if err := a.st.OIDCClientUpdate(r.Context(), client); err != nil {
		slog.Error("api: admin oidc обновить клиента", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	a.audit(r.Context(), "oidc_client_update", map[string]any{"id": id.String(), "client_id": client.ClientID})
	resp["client"] = toAdminOIDCClient(*client)
	writeJSON(w, http.StatusOK, resp)
}

// handleOIDCClientDelete — DELETE /api/v1/admin/oidc/clients/{id} (каскад
// чистит коды и токены клиента).
func (a *AdminAPI) handleOIDCClientDelete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	if err := a.st.OIDCClientDelete(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found")
			return
		}
		slog.Error("api: admin oidc удалить клиента", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	a.audit(r.Context(), "oidc_client_delete", map[string]any{"id": id.String()})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---- Groups: локальные группы пользователей ----

type adminGroup struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Description    string            `json:"description"`
	Priority       int               `json:"priority"`
	PreferChannels []string          `json:"prefer_channels"`
	RadiusPush     bool              `json:"radius_push"`
	RadiusReply    map[string]string `json:"radius_reply"`
	MemberCount    int               `json:"member_count"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
}

func toAdminGroup(g store.Group) adminGroup {
	var chs []string
	if g.PreferChannels != nil {
		chs = make([]string, len(g.PreferChannels))
		for i, c := range g.PreferChannels {
			chs[i] = string(c)
		}
	} else {
		chs = []string{}
	}
	reply := g.RadiusReply
	if reply == nil {
		reply = make(map[string]string)
	}
	prio := g.Priority
	if prio <= 0 {
		prio = 50
	}
	return adminGroup{
		ID:             g.ID.String(),
		Name:           g.Name,
		Description:    g.Description,
		Priority:       prio,
		PreferChannels: chs,
		RadiusPush:     g.RadiusPush,
		RadiusReply:    reply,
		MemberCount:    g.MemberCount,
		CreatedAt:      g.CreatedAt,
		UpdatedAt:      g.UpdatedAt,
	}
}

type groupCreateReq struct {
	Name           string            `json:"name"`
	Description    string            `json:"description"`
	Priority       *int              `json:"priority,omitempty"`
	PreferChannels *[]string         `json:"prefer_channels,omitempty"`
	RadiusPush     *bool             `json:"radius_push,omitempty"`
	RadiusReply    map[string]string `json:"radius_reply,omitempty"`
	VLAN           *string           `json:"vlan,omitempty"`
	ApplyToMembers bool              `json:"apply_to_members,omitempty"`
}

func (a *AdminAPI) handleGroupsList(w http.ResponseWriter, r *http.Request) {
	groups, err := a.st.GroupList(r.Context())
	if err != nil {
		slog.Error("api: admin список групп", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	out := make([]adminGroup, len(groups))
	for i, g := range groups {
		out[i] = toAdminGroup(g)
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": out})
}

func (a *AdminAPI) handleGroupCreate(w http.ResponseWriter, r *http.Request) {
	var req groupCreateReq
	if !decodeJSON(w, r, &req) {
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	prio := 50
	if req.Priority != nil && *req.Priority >= 1 && *req.Priority <= 100 {
		prio = *req.Priority
	}
	var prefer []channel.Channel
	if req.PreferChannels != nil {
		chs, ok := parseChannels(*req.PreferChannels)
		if !ok {
			writeError(w, http.StatusBadRequest, "bad_channels")
			return
		}
		prefer = chs
	}
	var radiusPush bool
	if req.RadiusPush != nil {
		radiusPush = *req.RadiusPush
	}
	reply := req.RadiusReply
	if req.VLAN != nil {
		vid := strings.TrimSpace(*req.VLAN)
		if vid != "" {
			if reply == nil {
				reply = make(map[string]string)
			}
			reply["Tunnel-Private-Group-Id"] = vid
		} else if reply != nil {
			delete(reply, "Tunnel-Private-Group-Id")
			delete(reply, "Tunnel-Type")
			delete(reply, "Tunnel-Medium-Type")
			if len(reply) == 0 {
				reply = nil
			}
		}
	}
	g := &store.Group{
		Name:           name,
		Description:    strings.TrimSpace(req.Description),
		Priority:       prio,
		PreferChannels: prefer,
		RadiusPush:     radiusPush,
		RadiusReply:    reply,
	}
	if err := a.st.GroupCreate(r.Context(), g); err != nil {
		slog.Error("api: admin создать группу", "error", err)
		writeError(w, http.StatusBadRequest, "create_failed")
		return
	}
	a.audit(r.Context(), "group_create", map[string]any{"id": g.ID.String(), "name": g.Name})
	writeJSON(w, http.StatusCreated, toAdminGroup(*g))
}

func (a *AdminAPI) handleGroupGet(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	g, err := a.st.GroupByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found")
			return
		}
		slog.Error("api: admin получить группу", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(w, http.StatusOK, toAdminGroup(*g))
}

func (a *AdminAPI) handleGroupUpdate(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	g, err := a.st.GroupByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found")
			return
		}
		slog.Error("api: admin получить группу перед обновлением", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	var req groupCreateReq
	if !decodeJSON(w, r, &req) {
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	g.Name = name
	g.Description = strings.TrimSpace(req.Description)
	if req.Priority != nil {
		prio := *req.Priority
		if prio < 1 || prio > 100 {
			prio = 50
		}
		g.Priority = prio
	}
	if req.PreferChannels != nil {
		chs, ok := parseChannels(*req.PreferChannels)
		if !ok {
			writeError(w, http.StatusBadRequest, "bad_channels")
			return
		}
		g.PreferChannels = chs
	}
	if req.RadiusPush != nil {
		g.RadiusPush = *req.RadiusPush
	}
	if req.RadiusReply != nil {
		g.RadiusReply = req.RadiusReply
	}
	if req.VLAN != nil {
		vid := strings.TrimSpace(*req.VLAN)
		if vid != "" {
			if g.RadiusReply == nil {
				g.RadiusReply = make(map[string]string)
			}
			g.RadiusReply["Tunnel-Private-Group-Id"] = vid
		} else if g.RadiusReply != nil {
			delete(g.RadiusReply, "Tunnel-Private-Group-Id")
			delete(g.RadiusReply, "Tunnel-Type")
			delete(g.RadiusReply, "Tunnel-Medium-Type")
			if len(g.RadiusReply) == 0 {
				g.RadiusReply = nil
			}
		}
	}
	if err := a.st.GroupUpdate(r.Context(), g); err != nil {
		slog.Error("api: admin обновить группу", "error", err)
		writeError(w, http.StatusBadRequest, "update_failed")
		return
	}
	if req.ApplyToMembers {
		if err := a.st.ApplyGroupSettingsToMembers(r.Context(), id); err != nil {
			slog.Warn("api: admin применить настройки к участникам", "group_id", id, "error", err)
		}
	}
	a.audit(r.Context(), "group_update", map[string]any{"id": g.ID.String(), "name": g.Name})
	writeJSON(w, http.StatusOK, toAdminGroup(*g))
}

func (a *AdminAPI) handleGroupDelete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	if err := a.st.GroupDelete(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found")
			return
		}
		slog.Error("api: admin удалить группу", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	a.audit(r.Context(), "group_delete", map[string]any{"id": id.String()})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *AdminAPI) handleGroupMembersGet(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	members, err := a.st.GroupMembers(r.Context(), id)
	if err != nil {
		slog.Error("api: admin участники группы", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	memberIDs := make([]string, len(members))
	for i, m := range members {
		memberIDs[i] = m.ID.String()
	}
	writeJSON(w, http.StatusOK, map[string]any{"members": memberIDs})
}

type groupMembersSetReq struct {
	UserIDs []string `json:"user_ids"`
}

func (a *AdminAPI) handleGroupMembersSet(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	var req groupMembersSetReq
	if !decodeJSON(w, r, &req) {
		return
	}
	var uids []uuid.UUID
	for _, raw := range req.UserIDs {
		uid, err := uuid.Parse(strings.TrimSpace(raw))
		if err == nil {
			uids = append(uids, uid)
		}
	}
	if err := a.st.SetGroupMembers(r.Context(), id, uids); err != nil {
		slog.Error("api: admin обновить участников группы", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	a.audit(r.Context(), "group_members_update", map[string]any{"id": id.String(), "count": len(uids)})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleRadiusCertGet — GET /api/v1/admin/radius/cert.
func (a *AdminAPI) handleRadiusCertGet(w http.ResponseWriter, r *http.Request) {
	var pemBytes []byte
	if a.radius != nil {
		pemBytes = a.radius.CurrentEAPCertPEM()
	}
	if len(pemBytes) == 0 && a.m != nil {
		if raw := a.m.Get().Radius.EAPCert; len(raw) > 0 {
			var pair struct {
				CertPEM string `json:"cert_pem"`
			}
			if json.Unmarshal(raw, &pair) == nil && pair.CertPEM != "" {
				pemBytes = []byte(pair.CertPEM)
			}
		}
	}
	if len(pemBytes) == 0 {
		writeError(w, http.StatusNotFound, "cert_not_found")
		return
	}
	_, info, err := acme.ParseCertPEM(pemBytes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cert_parse_failed")
		return
	}
	acmeConf := a.m.Get().ACME
	resp := map[string]any{
		"cert": info,
		"acme": map[string]any{
			"enabled": acmeConf.Enabled,
			"domain":  acmeConf.Domain,
			"email":   acmeConf.Email,
			"staging": acmeConf.Staging,
		},
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleRadiusACMERenew — POST /api/v1/admin/radius/acme/renew.
func (a *AdminAPI) handleRadiusACMERenew(w http.ResponseWriter, r *http.Request) {
	if a.acme == nil {
		writeError(w, http.StatusServiceUnavailable, "acme_not_configured")
		return
	}
	if err := a.acme.Renew(r.Context()); err != nil {
		slog.Error("api: ошибка ручного обновления сертификата ACME", "error", err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "acme_renew_failed", "details": err.Error()})
		return
	}
	a.audit(r.Context(), "acme_cert_renewed", map[string]any{"domain": a.m.Get().ACME.Domain})
	a.handleRadiusCertGet(w, r)
}

func (a *AdminAPI) ldapVerifier() *auth.LdapVerifier {
	return auth.NewLdapVerifier(a.st, a.m)
}

// handleLdapTest — POST /api/v1/admin/ldap/test: проверка подключения к серверу LDAP.
func (a *AdminAPI) handleLdapTest(w http.ResponseWriter, r *http.Request) {
	res, err := a.ldapVerifier().TestConnection(r.Context())
	if err != nil {
		a.audit(r.Context(), "ldap_test_connection_fail", map[string]any{"error": err.Error(), "via": "api"})
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":    false,
			"error": err.Error(),
		})
		return
	}
	a.audit(r.Context(), "ldap_test_connection_ok", map[string]any{"url": res.URL, "via": "api"})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"result": res,
	})
}

// handleLdapTestUser — POST /api/v1/admin/ldap/test-user: проверка поиска пользователя и прав в LDAP.
func (a *AdminAPI) handleLdapTestUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" {
		writeError(w, http.StatusBadRequest, "username_required")
		return
	}
	res, err := a.ldapVerifier().TestUserLookup(r.Context(), req.Username)
	if err != nil {
		a.audit(r.Context(), "ldap_test_user_fail", map[string]any{"username": req.Username, "error": err.Error(), "via": "api"})
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":    false,
			"error": err.Error(),
		})
		return
	}
	a.audit(r.Context(), "ldap_test_user_ok", map[string]any{"username": req.Username, "allowed": res.Allowed, "role": res.Role, "via": "api"})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"result": res,
	})
}

// handleLdapSync — POST /api/v1/admin/ldap/sync: принудительная синхронизация пользователей из LDAP в БД.
func (a *AdminAPI) handleLdapSync(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MaxCount int `json:"max_count"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.MaxCount <= 0 {
		req.MaxCount = 500
	}
	res, err := a.ldapVerifier().SyncUsers(r.Context(), req.MaxCount)
	if err != nil {
		a.audit(r.Context(), "ldap_sync_users_fail", map[string]any{"error": err.Error(), "via": "api"})
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":    false,
			"error": err.Error(),
		})
		return
	}
	a.audit(r.Context(), "ldap_sync_users_ok", map[string]any{
		"total": res.TotalFound, "created": res.Created, "updated": res.Updated, "skipped": res.Skipped, "via": "api",
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"result": res,
	})
}


