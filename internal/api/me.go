// Кабинет пользователя (спека §7, session-cookie + CSRF): профиль со
// статусом каналов, смена пароля и контактов (чувствительные операции —
// с кодом второго фактора), prefer-каналы, энроллмент/подтверждение/сброс
// TOTP с резервными кодами (показ один раз), регистрация passkeys,
// привязка Telegram кодом боту и управление доверенными устройствами.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/aligorov/twofa/internal/auth"
	"github.com/aligorov/twofa/internal/channel"
	"github.com/aligorov/twofa/internal/secrets"
	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
	"github.com/aligorov/twofa/internal/telegram"
	"github.com/aligorov/twofa/internal/webauthn"
)

// tgLinkTTL — срок жизни кода привязки Telegram (цель — успеть найти бота
// и отправить код; окно короткое, код одноразовый).
const tgLinkTTL = 10 * time.Minute

// purposeUIConfirm — purpose челленджа подтверждения чувствительной
// операции в кабинете (см. схему challenges).
const purposeUIConfirm = "ui_confirm"

// hasSecondFactor сообщает, есть ли у пользователя хоть один второй фактор:
// подтверждённый TOTP, неиспользованные резервные коды, passkeys или
// привязанный канал доставки кода (email/телефон/Telegram-чат). Выдача кода
// привязки Telegram — чувствительная операция (SEC-002) и требует
// подтверждения кодом, когда подтверждаться есть чем; пользователь вообще
// без факторов (свежая учётка) — редкий случай, ему код не требуется.
func hasSecondFactor(ctx context.Context, st *store.Store, user *store.User) bool {
	if _, _, _, confirmed, _, err := st.TOTPGet(ctx, user.ID); err == nil && confirmed {
		return true
	}
	if n, err := backupRemaining(ctx, st, user.ID); err == nil && n > 0 {
		return true
	}
	if creds, err := st.WACredListForUser(ctx, user.ID); err == nil && len(creds) > 0 {
		return true
	}
	return user.Email != "" || user.Phone != "" || user.TelegramChatID != nil
}

// tgLinkCodeCheck — общий предикат выдачи кода привязки Telegram: если у
// пользователя есть второй фактор, выдача требует код подтверждения
// (VerifyAnyCode с purpose ui_confirm — TOTP/резервный/код доставки со
// старого канала). Возвращает ("", true), когда можно выдавать, и машинную
// причину (code_required/bad_code), когда подтверждение не пройдено.
func tgLinkCodeCheck(ctx context.Context, core *auth.Core, st *store.Store, user *store.User, code string) (string, bool) {
	if !hasSecondFactor(ctx, st, user) {
		return "", true // факторов нет — подтверждаться нечем
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return "code_required", false
	}
	if _, err := core.VerifyAnyCode(ctx, user, code, purposeUIConfirm); err != nil {
		return "bad_code", false
	}
	return "", true
}

// MeAPI — зависимости и маршруты /api/v1/me/* (под RequireSession).
type MeAPI struct {
	core *auth.Core
	wa   *webauthn.Svc // nil — webauthn-роуты отвечают 503
	st   *store.Store
	box  *secrets.Box
	pv   auth.PasswordVerifier
	m    *settings.M
}

// NewMeAPI собирает кабинет; wa может быть nil, pv — проверка первого
// фактора (смена пароля/контактов).
func NewMeAPI(core *auth.Core, wa *webauthn.Svc, st *store.Store, box *secrets.Box, pv auth.PasswordVerifier, m *settings.M) *MeAPI {
	return &MeAPI{core: core, wa: wa, st: st, box: box, pv: pv, m: m}
}

// Register монтирует маршруты кабинета в chi-роутер.
func (p *MeAPI) Register(r chi.Router) {
	r.Route("/api/v1/me", func(r chi.Router) {
		r.Use(RequireSession(p.st))
		r.Get("/", p.handleProfile)
		r.Patch("/password", p.handlePasswordChange)
		r.Put("/contacts", p.handleContactsPut)
		r.Put("/contacts/send-code", p.handleContactsSendCode)
		r.Put("/prefer", p.handlePrefer)
		r.Post("/totp/enroll", p.handleTOTPEnroll)
		r.Post("/totp/confirm", p.handleTOTPConfirm)
		r.Post("/totp/delete", p.handleTOTPDelete)
		r.Post("/backup-codes/regenerate", p.handleBackupCodesRegenerate)
		r.Get("/webauthn/credentials", p.handleWACreds)
		r.Post("/webauthn/register/begin", p.handleWARegisterBegin)
		r.Post("/webauthn/register/finish", p.handleWARegisterFinish)
		r.Delete("/webauthn/credentials/{id}", p.handleWACredDelete)
		r.Post("/telegram/link", p.handleTelegramLink)
		r.Delete("/telegram", p.handleTelegramDelete)
		r.Get("/devices", p.handleDevices)
		r.Delete("/devices/{id}", p.handleDeviceDelete)
	})
}

// audit пишет событие кабинета (result ok/fail), не ломая основной поток.
func (p *MeAPI) audit(ctx context.Context, username, event, ip, result string, detail map[string]any) {
	if err := p.st.Audit(ctx, username, event, detail, ip, result); err != nil {
		slog.Warn("api: аудит не записан", "event", event, "error", err)
	}
}

// parseChannels валидирует имена каналов prefer_channels; false — среди
// имён есть неизвестное или список пуст.
func parseChannels(names []string) ([]channel.Channel, bool) {
	out := make([]channel.Channel, 0, len(names))
	for _, n := range names {
		ch := channel.Channel(n)
		switch ch {
		case channel.TOTP, channel.Email, channel.SMS, channel.Telegram, channel.TelegramPush:
			out = append(out, ch)
		default:
			return nil, false
		}
	}
	return out, len(out) > 0
}

// ---- GET /api/v1/me ----

// handleProfile — профиль + статус каналов + CSRF-токен сессии (cookie
// HttpOnly, поэтому CSRF отдаётся в теле для заголовка X-CSRF-Token).
func (p *MeAPI) handleProfile(w http.ResponseWriter, r *http.Request) {
	user, _ := userFrom(r.Context())
	ctx := r.Context()

	var totpConfirmed bool
	if _, _, _, confirmed, _, err := p.st.TOTPGet(ctx, user.ID); err == nil {
		totpConfirmed = confirmed
	} else if !errors.Is(err, store.ErrNotFound) {
		slog.Error("api: me TOTPGet", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	waCount := 0
	if creds, err := p.st.WACredListForUser(ctx, user.ID); err == nil {
		waCount = len(creds)
	} else {
		slog.Error("api: me WACredListForUser", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}

	chs := make([]string, len(user.PreferChannels))
	for i, c := range user.PreferChannels {
		chs[i] = string(c)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"username": user.Username,
		"role":     user.Role,
		"email":    user.Email,
		"phone":    user.Phone,

		"email_set":        user.Email != "",
		"phone_set":        user.Phone != "",
		"telegram_linked":  user.TelegramChatID != nil,
		"totp_confirmed":   totpConfirmed,
		"webauthn_count":   waCount,
		"prefer_channels":  chs,
		"csrf":             ctx.Value(ctxKeyCSRF),
		"radius_push":      user.RadiusPush,
		"radius_reply_set": user.RadiusReply != nil,
	})
}

// ---- PATCH /api/v1/me/password ----

type passwordChangeReq struct {
	Old string `json:"old"`
	New string `json:"new"`
}

// handlePasswordChange: проверка старого пароля → новый хеш → отзыв ВСЕХ
// сессий и доверенных устройств пользователя (спека §6). Текущая сессия
// тоже отзывается — клиент обязан перелогиниться. LDAP-пользователям
// смена локального пароля запрещена сервером (не только скрытой формой):
// пароль живёт в каталоге, а Verify старого пароля прошёл бы bind-ом —
// замена хеша на неизвестный стала бы lockout-ом.
func (p *MeAPI) handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	user, _ := userFrom(r.Context())
	if user.Source == store.SourceLDAP {
		p.audit(r.Context(), user.Username, "password_change", clientIP(r), "fail",
			map[string]any{"reason": "ldap_managed"})
		writeError(w, http.StatusBadRequest, "ldap_managed")
		return
	}
	var req passwordChangeReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.New == "" {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	ctx := r.Context()
	ip := clientIP(r)
	if _, err := p.pv.Verify(ctx, user.Username, req.Old); err != nil {
		p.audit(ctx, user.Username, "password_change", ip, "fail",
			map[string]any{"reason": "bad_credentials"})
		writeError(w, http.StatusUnauthorized, "bad_credentials")
		return
	}
	user.PasswordHash = secrets.HashPassword(req.New)
	if p.box != nil {
		user.PasswordEnc = p.box.EncryptAAD(user.Username, []byte(req.New))
	}
	if err := p.st.UserUpdate(ctx, user); err != nil {
		slog.Error("api: смена пароля", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	if err := p.st.SessionDeleteAllForUser(ctx, user.ID); err != nil {
		slog.Warn("api: отзыв сессий после смены пароля", "error", err)
	}
	if err := p.st.DeviceDeleteAllForUser(ctx, user.ID); err != nil {
		slog.Warn("api: отзыв устройств после смены пароля", "error", err)
	}
	setCookie(w, cookieSession, "", -1)
	setCookie(w, cookieDevice, "", -1)
	p.audit(ctx, user.Username, "password_change", ip, "ok", nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---- PUT /api/v1/me/contacts ----

type contactsReq struct {
	Email *string `json:"email"`
	Phone *string `json:"phone"`
	Code  string  `json:"code"`
}

// handleContactsPut — смена email/phone: чувствительная операция, код
// проверяется core.VerifyAnyCode (резервный, TOTP или активный кодовый
// челлендж). Поле с nil не меняется; пустая строка очищает контакт.
func (p *MeAPI) handleContactsPut(w http.ResponseWriter, r *http.Request) {
	user, _ := userFrom(r.Context())
	var req contactsReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Email == nil && req.Phone == nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	ctx := r.Context()
	ip := clientIP(r)
	if req.Code == "" {
		writeError(w, http.StatusBadRequest, "code_required")
		return
	}
	if _, err := p.core.VerifyAnyCode(ctx, user, req.Code, purposeUIConfirm); err != nil {
		p.audit(ctx, user.Username, "contacts_change", ip, "fail",
			map[string]any{"reason": "bad_code"})
		writeError(w, http.StatusUnauthorized, "bad_code")
		return
	}
	if req.Email != nil {
		user.Email = *req.Email
	}
	if req.Phone != nil {
		user.Phone = *req.Phone
	}
	if err := p.st.UserUpdate(ctx, user); err != nil {
		slog.Error("api: смена контактов", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	p.audit(ctx, user.Username, "contacts_change", ip, "ok", nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---- PUT /api/v1/me/contacts/send-code ----

// handleContactsSendCode — код подтверждения на СТАРЫЙ канал: из
// prefer_channels берутся email/telegram (первый доступный), TOTP и push
// пропускаются — нужен доставленный код, а не код из приложения.
func (p *MeAPI) handleContactsSendCode(w http.ResponseWriter, r *http.Request) {
	user, _ := userFrom(r.Context())

	var prefer []channel.Channel
	for _, ch := range user.PreferChannels {
		if ch == channel.Email || ch == channel.Telegram {
			prefer = append(prefer, ch)
		}
	}
	if len(prefer) == 0 {
		prefer = []channel.Channel{channel.Email, channel.Telegram}
	}
	slim := *user // копия с ограниченным набором каналов; ядро не мутирует user
	slim.PreferChannels = prefer

	ch, err := p.core.StartWithMeta(r.Context(), &slim, purposeUIConfirm, clientIP(r), r.UserAgent())
	switch {
	case err == nil:
	case errors.Is(err, auth.ErrNoChannel):
		writeError(w, http.StatusConflict, "no_channel")
		return
	case errors.Is(err, auth.ErrCooldown):
		retry := int((p.m.Get().Policy.ResendCooldown + time.Second - 1) / time.Second)
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		writeJSON(w, http.StatusTooManyRequests,
			map[string]any{"error": "cooldown", "retry_after": retry})
		return
	default:
		slog.Error("api: send-code", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"challenge_id": ch.ID.String(),
		"channel":      string(ch.Channel),
		"expires_in":   int(time.Until(ch.ExpiresAt).Seconds()),
	})
}

// ---- PUT /api/v1/me/prefer ----

type preferReq struct {
	Channels []string `json:"channels"`
}

// handlePrefer — порядок prefer_channels (валидные имена каналов).
func (p *MeAPI) handlePrefer(w http.ResponseWriter, r *http.Request) {
	user, _ := userFrom(r.Context())
	var req preferReq
	if !decodeJSON(w, r, &req) {
		return
	}
	chs, ok := parseChannels(req.Channels)
	if !ok {
		writeError(w, http.StatusBadRequest, "bad_channel")
		return
	}
	user.PreferChannels = chs
	if err := p.st.UserUpdate(r.Context(), user); err != nil {
		slog.Error("api: prefer", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	p.audit(r.Context(), user.Username, "prefer_change", clientIP(r), "ok",
		map[string]any{"channels": req.Channels})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---- TOTP ----

// handleTOTPEnroll — POST /api/v1/me/totp/enroll: новый секрет
// (pquerna/otp, issuer/period/digits из настроек), шифрование AES-GCM с
// AAD-привязкой к username, TOTPSave (секрет требует подтверждения).
// Ответ {secret, otpauth_url}: QR по URL рендерит web-UI (T13).
func (p *MeAPI) handleTOTPEnroll(w http.ResponseWriter, r *http.Request) {
	user, _ := userFrom(r.Context())
	t := p.m.Get().TOTP
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      t.Issuer,
		AccountName: user.Username,
		Period:      uint(t.Period),
		Digits:      otp.Digits(t.Digits),
	})
	if err != nil {
		slog.Error("api: totp generate", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	enc := p.box.EncryptAAD(auth.AADTOTP(user.Username), []byte(key.Secret()))
	if err := p.st.TOTPSave(r.Context(), user.ID, enc, t.Digits, t.Period); err != nil {
		slog.Error("api: totp save", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	p.audit(r.Context(), user.Username, "totp_enroll", clientIP(r), "ok", nil)
	writeJSON(w, http.StatusOK, map[string]any{
		"secret":      key.Secret(),
		"otpauth_url": key.URL(),
	})
}

type codeReq struct {
	Code string `json:"code"`
}

// handleTOTPConfirm — POST /api/v1/me/totp/confirm {code}: VerifyAnyCode не
// годится (секрет ещё не подтверждён) — код проверяется по расшифрованному
// секрету через totp.ValidateCustom. Успех: TOTPConfirm + новая партия
// резервных кодов (BackupReplace), коды показываются ОДИН раз. Подтверждённый
// код «сжигается» повторной проверкой ядра — поднимается last_timestep,
// тот же код нельзя переиспользовать для входа.
func (p *MeAPI) handleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	user, _ := userFrom(r.Context())
	var req codeReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Code == "" {
		writeError(w, http.StatusBadRequest, "code_required")
		return
	}
	ctx := r.Context()

	secretEnc, digits, period, _, _, err := p.st.TOTPGet(ctx, user.ID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusBadRequest, "totp_not_enrolled")
		return
	}
	if err != nil {
		slog.Error("api: totp confirm get", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	secret, err := p.box.DecryptAAD(auth.AADTOTP(user.Username), secretEnc)
	if err != nil {
		slog.Error("api: totp confirm decrypt", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	ok, err := totp.ValidateCustom(req.Code, string(secret), time.Now().UTC(), totp.ValidateOpts{
		Period:    uint(period),
		Skew:      p.m.Get().TOTP.Skew,
		Digits:    otp.Digits(digits),
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		slog.Error("api: totp confirm validate", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	if !ok {
		p.audit(ctx, user.Username, "totp_confirm", clientIP(r), "fail",
			map[string]any{"reason": "bad_code"})
		writeError(w, http.StatusUnauthorized, "bad_code")
		return
	}
	if err := p.st.TOTPConfirm(ctx, user.ID); err != nil {
		slog.Error("api: totp confirm", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	// Replay-защита подтверждённого кода (см. auth.Core.verifyTOTP): нужен
	// только подъём last_timestep у TOTP-фактора — доставленные коды
	// (purposes) здесь не расходуются.
	if _, err := p.core.VerifyAnyCode(ctx, user, req.Code); err != nil {
		slog.Warn("api: burn кода после totp confirm", "error", err)
	}
	codes, err := replaceBackupCodes(ctx, p.st, user.ID)
	if err != nil {
		slog.Error("api: totp confirm backup", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	p.audit(ctx, user.Username, "totp_confirm", clientIP(r), "ok", nil)
	writeJSON(w, http.StatusOK, map[string]any{"backup_codes": codes})
}

// handleTOTPDelete — POST /api/v1/me/totp/delete {code}: чувствительная
// операция — код любым способом (резервный/TOTP/активный челлендж).
func (p *MeAPI) handleTOTPDelete(w http.ResponseWriter, r *http.Request) {
	user, _ := userFrom(r.Context())
	var req codeReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Code == "" {
		writeError(w, http.StatusBadRequest, "code_required")
		return
	}
	ctx := r.Context()
	if _, err := p.core.VerifyAnyCode(ctx, user, req.Code, purposeUIConfirm); err != nil {
		p.audit(ctx, user.Username, "totp_delete", clientIP(r), "fail",
			map[string]any{"reason": "bad_code"})
		writeError(w, http.StatusUnauthorized, "bad_code")
		return
	}
	if err := p.st.TOTPDelete(ctx, user.ID); err != nil {
		slog.Error("api: totp delete", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	p.audit(ctx, user.Username, "totp_delete", clientIP(r), "ok", nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleBackupCodesRegenerate — POST /api/v1/me/backup-codes/regenerate
// {code} (спека §7): чувствительная операция — код вторым фактором любым
// способом (VerifyAnyCode); старая партия аннулируется, новая показывается
// ровно один раз в теле ответа (HTML-аналог — /me/backup/regenerate).
func (p *MeAPI) handleBackupCodesRegenerate(w http.ResponseWriter, r *http.Request) {
	user, _ := userFrom(r.Context())
	var req codeReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Code == "" {
		writeError(w, http.StatusBadRequest, "code_required")
		return
	}
	ctx := r.Context()
	if _, err := p.core.VerifyAnyCode(ctx, user, req.Code, purposeUIConfirm); err != nil {
		p.audit(ctx, user.Username, "backup_regen", clientIP(r), "fail",
			map[string]any{"reason": "bad_code"})
		writeError(w, http.StatusUnauthorized, "bad_code")
		return
	}
	codes, err := replaceBackupCodes(ctx, p.st, user.ID)
	if err != nil {
		slog.Error("api: backup regenerate", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	p.audit(ctx, user.Username, "backup_regen", clientIP(r), "ok", nil)
	writeJSON(w, http.StatusOK, map[string]any{"codes": codes})
}

// ---- WebAuthn ----

// handleWACreds — GET /api/v1/me/webauthn/credentials: список ключей
// (метаданные, без public_key).
func (p *MeAPI) handleWACreds(w http.ResponseWriter, r *http.Request) {
	user, _ := userFrom(r.Context())
	creds, err := p.st.WACredListForUser(r.Context(), user.ID)
	if err != nil {
		slog.Error("api: me webauthn list", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	out := make([]map[string]any, len(creds))
	for i, c := range creds {
		var transports []string
		if c.Transports != "" {
			transports = strings.Split(c.Transports, ",")
		} else {
			transports = []string{}
		}
		out[i] = map[string]any{
			"id":              c.ID,
			"name":            c.Name,
			"attachment":      c.Attachment,
			"transports":      transports,
			"aaguid":          c.AAGUID,
			"backup_eligible": c.BackupEligible,
			"backup_state":    c.BackupState,
			"clone_warning":   c.CloneWarning,
			"last_used_at":    c.LastUsedAt,
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"credentials": out})
}

// waRegBeginReq — запрос начала регистрации passkey: метка ключа и код
// второго фактора (чувствительная операция — код обязателен и проверяется).
type waRegBeginReq struct {
	Name string `json:"name"`
	Code string `json:"code"`
}

// handleWARegisterBegin — POST /api/v1/me/webauthn/register/begin {name, code}:
// чувствительная операция — код второго фактора (доставленный/TOTP/резервный)
// проверяется ДО старта церемонии; метка ключа используется на finish;
// здесь — {handle, options}.
func (p *MeAPI) handleWARegisterBegin(w http.ResponseWriter, r *http.Request) {
	if p.wa == nil {
		writeError(w, http.StatusServiceUnavailable, "webauthn_disabled")
		return
	}
	var req waRegBeginReq
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Code = strings.TrimSpace(req.Code)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	if req.Code == "" {
		writeError(w, http.StatusBadRequest, "code_required")
		return
	}
	user, _ := userFrom(r.Context())
	if _, err := p.core.VerifyAnyCode(r.Context(), user, req.Code, purposeUIConfirm); err != nil {
		p.audit(r.Context(), user.Username, "webauthn_register", clientIP(r), "fail",
			map[string]any{"reason": "bad_code"})
		writeError(w, http.StatusUnauthorized, "bad_code")
		return
	}
	opts, handle, err := p.wa.BeginRegister(r.Context(), user)
	if err != nil {
		slog.Error("api: me webauthn begin", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"handle": handle, "options": opts})
}

// handleWARegisterFinish — POST /api/v1/me/webauthn/register/finish
// {handle, name}: тело — сырой PublicKeyCredential (парсит go-webauthn);
// запрос форвардится в Svc.FinishRegister с тем же телом и заголовками
// (паттерн public.go webauthn/finish).
func (p *MeAPI) handleWARegisterFinish(w http.ResponseWriter, r *http.Request) {
	if p.wa == nil {
		writeError(w, http.StatusServiceUnavailable, "webauthn_disabled")
		return
	}
	user, _ := userFrom(r.Context())
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	var probe struct {
		Handle string `json:"handle"`
		Name   string `json:"name"`
	}
	_ = json.Unmarshal(body, &probe)
	handle := r.URL.Query().Get("handle")
	if handle == "" {
		handle = probe.Handle
	}
	if handle == "" {
		writeError(w, http.StatusBadRequest, "handle_required")
		return
	}
	name := r.URL.Query().Get("name")
	if name == "" {
		name = probe.Name
	}

	// go-webauthn разбирает тело из *http.Request — пересобираем запрос
	// с сырым телом, форвардингом Content-Type/User-Agent/RemoteAddr.
	freq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, r.URL.Path, bytes.NewReader(body))
	if err != nil {
		slog.Error("api: me webauthn finish request", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	freq.Header.Set("Content-Type", r.Header.Get("Content-Type"))
	freq.Header.Set("User-Agent", r.UserAgent())
	freq.RemoteAddr = r.RemoteAddr

	if err := p.wa.FinishRegister(r.Context(), user, handle, name, freq); err != nil {
		writeError(w, http.StatusBadRequest, "webauthn_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleWACredDelete — DELETE /api/v1/me/webauthn/credentials/{id}.
func (p *MeAPI) handleWACredDelete(w http.ResponseWriter, r *http.Request) {
	user, _ := userFrom(r.Context())
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id < 1 {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	if err := p.st.WACredDelete(r.Context(), id, user.ID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found")
			return
		}
		slog.Error("api: me webauthn delete", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	p.audit(r.Context(), user.Username, "webauthn_cred_delete", clientIP(r), "ok",
		map[string]any{"credential_row": id})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---- Telegram ----

// handleTelegramLink — POST /api/v1/me/telegram/link {code}: код привязки
// (telegram.GenerateLinkCode, формат XXXX-XXXX) с SHA-256-хешем и TTL
// 10 минут; бот (T8) находит челлендж по purpose=tg_link и хешу
// нормализованного кода и привязывает chat_id. Выдача — чувствительная
// операция (SEC-002): при наличии у пользователя второго фактора требуется
// код подтверждения (ui_confirm).
func (p *MeAPI) handleTelegramLink(w http.ResponseWriter, r *http.Request) {
	user, _ := userFrom(r.Context())
	var req codeReq
	if !decodeJSON(w, r, &req) {
		return
	}
	ctx := r.Context()
	ip := clientIP(r)
	reason, ok := tgLinkCodeCheck(ctx, p.core, p.st, user, req.Code)
	if !ok {
		p.audit(ctx, user.Username, "tg_link_start", ip, "fail",
			map[string]any{"reason": reason})
		if reason == "code_required" {
			writeError(w, http.StatusBadRequest, "code_required")
		} else {
			writeError(w, http.StatusUnauthorized, "bad_code")
		}
		return
	}
	code := telegram.GenerateLinkCode()
	ch := &store.Challenge{
		UserID:       user.ID,
		Channel:      channel.Telegram,
		CodeHash:     secrets.SHA256(code),
		ExpiresAt:    time.Now().Add(tgLinkTTL),
		AttemptsLeft: 1,
		Purpose:      "tg_link",
	}
	if err := p.st.ChallengeCreate(r.Context(), ch); err != nil {
		slog.Error("api: telegram link", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	p.audit(r.Context(), user.Username, "tg_link_start", clientIP(r), "ok", nil)
	writeJSON(w, http.StatusOK, map[string]any{
		"link_code":    code,
		"instructions": "Отправьте код боту Telegram",
		"expires_in":   int(tgLinkTTL.Seconds()),
	})
}

// handleTelegramDelete — DELETE /api/v1/me/telegram: отвязка чата.
func (p *MeAPI) handleTelegramDelete(w http.ResponseWriter, r *http.Request) {
	user, _ := userFrom(r.Context())
	user.TelegramChatID = nil
	if err := p.st.UserUpdate(r.Context(), user); err != nil {
		slog.Error("api: telegram delete", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	p.audit(r.Context(), user.Username, "telegram_unlink", clientIP(r), "ok", nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---- доверенные устройства ----

// handleDevices — GET /api/v1/me/devices: действующие устройства
// (токен-хешы не раскрываются, только метаданные).
func (p *MeAPI) handleDevices(w http.ResponseWriter, r *http.Request) {
	user, _ := userFrom(r.Context())
	list, err := p.st.DeviceListForUser(r.Context(), user.ID)
	if err != nil {
		slog.Error("api: me devices", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	out := make([]map[string]any, len(list))
	for i, d := range list {
		out[i] = map[string]any{
			"id":           d.ID,
			"ua":           d.UA,
			"ip":           d.IP,
			"created_at":   d.CreatedAt,
			"last_seen_at": d.LastSeenAt,
			"expires_at":   d.ExpiresAt,
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": out})
}

// handleDeviceDelete — DELETE /api/v1/me/devices/{id}: отзыв устройства
// (user_id — проверка принадлежности в store).
func (p *MeAPI) handleDeviceDelete(w http.ResponseWriter, r *http.Request) {
	user, _ := userFrom(r.Context())
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id < 1 {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	if err := p.st.DeviceDelete(r.Context(), id, user.ID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found")
			return
		}
		slog.Error("api: me device delete", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	p.audit(r.Context(), user.Username, "device_revoke", clientIP(r), "ok",
		map[string]any{"device_id": id})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
