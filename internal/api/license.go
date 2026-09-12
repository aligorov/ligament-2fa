// Лицензирование в админ API (report §4.3): статус (маскированный — без
// блоба), загрузка/удаление лицензии, загрузка CRL-отзыва и enforcement
// лимита активных пользователей на создании/включении (вход существующим
// не блокируется никогда — report §3.3).
package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/aligorov/twofa/internal/license"
)

// registerLicenseRoutes монтирует лицензионные маршруты (вызывается из
// AdminAPI.Register внутри группы /api/v1/admin).
func (a *AdminAPI) registerLicenseRoutes(r chi.Router) {
	r.Get("/license", a.handleLicenseGet)
	r.Put("/license", a.handleLicensePut)
	r.Delete("/license", a.handleLicenseDelete)
	r.Put("/license/crl", a.handleLicenseCRLPut)
}

// licenseStatus вычисляет статус с подсчётом активных (не disabled)
// пользователей из UserList (отдельный метод счёта в store не вводится).
// nil-менеджер (частичные композиции тестов) — минимальный free-статус
// без обращения к БД: роуты остаются зарегистрированными, паники нет.
func (a *AdminAPI) licenseStatus(r *http.Request) (license.Status, error) {
	if a.licEmpty() {
		return license.Status{Mode: license.ModeFree, UserLimit: license.FreeUserLimit}, nil
	}
	st, err := a.lic.Effective(r.Context())
	if err != nil {
		return st, err
	}
	users, err := a.st.UserList(r.Context())
	if err != nil {
		return st, err
	}
	active := 0
	for _, u := range users {
		if u.Enabled {
			active++
		}
	}
	st.UsersActive = active
	st.AtLimit = st.UserLimit > 0 && active >= st.UserLimit
	return st, nil
}

// licenseStatusJSON — маскированный статус для ответа (blob не входит).
type licenseStatusJSON struct {
	Mode          string   `json:"mode"`
	UserLimit     int      `json:"user_limit"` // 0 — не ограничено
	Unlimited     bool     `json:"unlimited"`
	ActiveUsers   int      `json:"active_users"`
	AtLimit       bool     `json:"at_limit"`
	LicID         string   `json:"lic_id,omitempty"`
	Customer      string   `json:"customer,omitempty"`
	Plan          string   `json:"plan,omitempty"`
	Features      []string `json:"features,omitempty"`
	Revoked       bool     `json:"revoked"`
	Expired       bool     `json:"expired"`
	Grace         bool     `json:"grace"`
	DaysLeft      int      `json:"days_left"`
	TrialDaysLeft int      `json:"trial_days_left"`
	UpdatesUntil  string   `json:"updates_until,omitempty"` // RFC3339, только licensed
}

func toLicenseStatusJSON(st license.Status) licenseStatusJSON {
	out := licenseStatusJSON{
		Mode:          string(st.Mode),
		UserLimit:     st.UserLimit,
		Unlimited:     st.UserLimit <= 0,
		ActiveUsers:   st.UsersActive,
		AtLimit:       st.AtLimit,
		LicID:         st.LicID,
		Customer:      st.Customer,
		Plan:          st.Plan,
		Revoked:       st.Revoked,
		Expired:       st.Expired,
		Grace:         st.Grace,
		DaysLeft:      st.DaysLeft,
		TrialDaysLeft: st.TrialDaysLeft,
	}
	if st.UserLimit <= 0 && st.Mode == license.ModeFree {
		out.UserLimit = license.FreeUserLimit // free всегда с конкретным лимитом
		out.Unlimited = false
	}
	if !st.UpdatesUntil.IsZero() {
		out.UpdatesUntil = st.UpdatesUntil.UTC().Format("2006-01-02")
	}
	return out
}

// handleLicenseGet — GET /api/v1/admin/license: статус без блоба.
func (a *AdminAPI) handleLicenseGet(w http.ResponseWriter, r *http.Request) {
	st, err := a.licenseStatus(r)
	if err != nil {
		slog.Error("api: admin license статус", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(w, http.StatusOK, toLicenseStatusJSON(st))
}

type licensePutReq struct {
	Blob string `json:"blob"`
}

// handleLicensePut — PUT /api/v1/admin/license {blob}: parse+verify+check
// CRL → персист (аудит license_upload). Подписанная, но отозванная — 400
// revoked; битый формат/подпись/kid — 400 invalid_format/invalid_signature.
func (a *AdminAPI) handleLicensePut(w http.ResponseWriter, r *http.Request) {
	var req licensePutReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Blob == "" {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	if a.licEmpty() {
		writeError(w, http.StatusServiceUnavailable, "licensing_disabled")
		return
	}
	lic, err := a.lic.Upload(r.Context(), req.Blob)
	switch {
	case err == nil:
	case errors.Is(err, license.ErrMalformed):
		writeError(w, http.StatusBadRequest, "invalid_format")
		return
	case errors.Is(err, license.ErrBadSignature), errors.Is(err, license.ErrUnknownKid):
		writeError(w, http.StatusBadRequest, "invalid_signature")
		return
	case errors.Is(err, license.ErrRevoked):
		writeError(w, http.StatusBadRequest, "revoked")
		return
	default:
		slog.Error("api: admin license загрузка", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	a.audit(r.Context(), "license_upload", map[string]any{
		"lic_id": lic.LicID, "plan": lic.Plan, "customer": lic.Customer,
		"user_limit": lic.UserLimit,
	})
	st, err := a.licenseStatus(r)
	if err != nil {
		slog.Error("api: admin license статус после загрузки", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(w, http.StatusOK, toLicenseStatusJSON(st))
}

// handleLicenseDelete — DELETE /api/v1/admin/license: удаление → free
// (демо не воскрешается: trial_used остаётся).
func (a *AdminAPI) handleLicenseDelete(w http.ResponseWriter, r *http.Request) {
	if a.licEmpty() {
		writeError(w, http.StatusServiceUnavailable, "licensing_disabled")
		return
	}
	if err := a.lic.Remove(r.Context()); err != nil {
		slog.Error("api: admin license удаление", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	a.audit(r.Context(), "license_remove", nil)
	st, err := a.licenseStatus(r)
	if err != nil {
		slog.Error("api: admin license статус после удаления", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(w, http.StatusOK, toLicenseStatusJSON(st))
}

// handleLicenseCRLPut — PUT /api/v1/admin/license/crl {blob}: подписанный
// CRL-отзыв (проверка той же схемой Ed25519).
func (a *AdminAPI) handleLicenseCRLPut(w http.ResponseWriter, r *http.Request) {
	var req licensePutReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Blob == "" {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	if a.licEmpty() {
		writeError(w, http.StatusServiceUnavailable, "licensing_disabled")
		return
	}
	rev, err := a.lic.UploadCRL(r.Context(), req.Blob)
	switch {
	case err == nil:
	case errors.Is(err, license.ErrMalformed):
		writeError(w, http.StatusBadRequest, "invalid_format")
		return
	case errors.Is(err, license.ErrBadSignature), errors.Is(err, license.ErrUnknownKid):
		writeError(w, http.StatusBadRequest, "invalid_signature")
		return
	default:
		slog.Error("api: admin license CRL загрузка", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	a.audit(r.Context(), "license_crl_upload", map[string]any{"lic_id": rev.LicID})
	writeJSON(w, http.StatusOK, map[string]any{
		"lic_id": rev.LicID, "revoked_at": rev.RevokedAt.UTC().Format("2006-01-02T15:04:05Z"),
	})
}

// ---- enforcement лимита активных пользователей ----

// licEmpty — лицензирование не смонтировано (nil-менеджер, частичные
// композиции тестов): баннеры и лимиты не действуют.
func (a *AdminAPI) licEmpty() bool { return a.lic == nil }

// licenseExceeded сообщает, приведёт ли +1 активный пользователь к
// превышению лимита (limit<=0 — не ограничено). nil-менеджер лицензий
// (композиция без лицензирования) ничего не ограничивает.
//
// 30-дневный grace на превышение (report §3.3): первое попадание в лимит
// фиксирует license.over_limit_since, после чего создание/включение сверх
// лимита разрешается (с аудитом-предупреждением license_over_limit_grace);
// спустя 30 дней — блокируется. Возврат активных под лимит сбрасывает
// фиксацию (следующее превышение начнёт grace заново).
func (a *AdminAPI) licenseExceeded(r *http.Request) (bool, license.Status) {
	if a.lic == nil {
		return false, license.Status{}
	}
	st, err := a.licenseStatus(r)
	if err != nil {
		// Ошибка БД не должна блокировать создание: логируем и пропускаем
		// (лицензирование — юридический барьер, не DRM; report §3.8).
		slog.Error("api: license статус для enforcement", "error", err)
		return false, st
	}
	if st.UserLimit <= 0 {
		return false, st
	}
	if st.UsersActive+1 <= st.UserLimit {
		// Активных меньше лимита: фиксация превышения больше не актуальна.
		if err := a.lic.ClearOverLimit(r.Context()); err != nil {
			slog.Warn("api: сброс license.over_limit_since", "error", err)
		}
		return false, st
	}
	dec, err := a.lic.OverLimit(r.Context())
	if err != nil {
		// Ошибка БД не должна блокировать создание (fail open, report §3.8).
		slog.Error("api: license over-limit grace", "error", err)
		return false, st
	}
	if dec.Allowed {
		a.audit(r.Context(), "license_over_limit_grace", map[string]any{
			"limit": st.UserLimit, "active_users": st.UsersActive,
			"over_limit_since": dec.Since.UTC().Format(time.RFC3339),
		})
		return false, st
	}
	return true, st
}

// ldapLicenseGate — колбэк для LdapVerifier.SetLicenseAllowsCreate:
// LDAP-авто-провижининг разрешён только в пределах лимита лицензии
// (семантика licenseExceeded, но без контекста запроса: фоновый контекст
// с потолком 5 c, fail-open при ошибках — лицензирование юридический
// барьер, не DRM). Вход существующим не ограничивается никогда.
func (a *AdminAPI) ldapLicenseGate() func(string) bool {
	return func(username string) bool {
		if a.lic == nil {
			return true // лицензирование не смонтировано (тесты/композиции)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		status, err := a.lic.Effective(ctx)
		if err != nil {
			slog.Error("api: license статус для LDAP-провижининга", "error", err)
			return true
		}
		users, err := a.st.UserList(ctx)
		if err != nil {
			slog.Error("api: список пользователей для LDAP-провижининга", "error", err)
			return true
		}
		active := 0
		for _, u := range users {
			if u.Enabled {
				active++
			}
		}
		if status.UserLimit <= 0 || active+1 <= status.UserLimit {
			if status.UserLimit > 0 {
				if err := a.lic.ClearOverLimit(ctx); err != nil {
					slog.Warn("api: сброс license.over_limit_since", "error", err)
				}
			}
			return true
		}
		dec, err := a.lic.OverLimit(ctx)
		if err != nil {
			slog.Error("api: license over-limit grace (LDAP)", "error", err)
			return true
		}
		if !dec.Allowed {
			slog.Warn("api: LDAP авто-провижининг заблокирован лимитом лицензии",
				"username", username, "limit", status.UserLimit, "active_users", active)
			return false
		}
		return true // в grace-окне создание разрешено
	}
}

// denyLicenseLimit отвечает 403 license_limit и пишет аудит.
func (a *AdminAPI) denyLicenseLimit(w http.ResponseWriter, r *http.Request, st license.Status) {
	a.audit(r.Context(), "license_limit", map[string]any{
		"limit": st.UserLimit, "active_users": st.UsersActive,
	})
	writeJSON(w, http.StatusForbidden, map[string]any{
		"error":        "license_limit",
		"limit":        st.UserLimit,
		"active_users": st.UsersActive,
	})
}
