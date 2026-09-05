// Web-сессии (спека §6/§7): cookie twofa_session (токен — 32 случайных
// байта, в БД только SHA-256), CSRF-защита мутирующих запросов заголовком
// X-CSRF-Token, вход POST /api/v1/login (один шаг без второго фактора /
// на доверенном устройстве, два шага с кодом или passkey), доверенные
// устройства (cookie twofa_device) и выход.
package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aligorov/twofa/internal/auth"
	"github.com/aligorov/twofa/internal/channel"
	"github.com/aligorov/twofa/internal/secrets"
	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
)

const (
	// cookieSession — cookie web-сессии; в БД хранится SHA-256 значения.
	cookieSession = "twofa_session"
	// cookieDevice — cookie доверенного устройства (remember_device).
	cookieDevice = "twofa_device"
	// csrfHeader — заголовок двойной отправки CSRF-токена сессии.
	csrfHeader = "X-CSRF-Token"
	// tokenBytes — энтропия (байт) токенов сессии, CSRF и устройства.
	tokenBytes = 32
)

// ctxKey — тип ключей контекста запроса.
type ctxKey int

const (
	ctxKeyUser ctxKey = iota
	ctxKeyCSRF
	ctxKeySessionHash
)

// userFrom возвращает пользователя из контекста RequireSession.
func userFrom(ctx context.Context) (*store.User, bool) {
	u, ok := ctx.Value(ctxKeyUser).(*store.User)
	return u, ok
}

// mutatingMethod сообщает, меняет ли метод состояние (GET/HEAD/OPTIONS —
// безопасные и CSRF-заголовка не требуют).
func mutatingMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}

// setCookie устанавливает cookie с флагами web-сессий: HttpOnly, Secure,
// SameSite=Lax, Path=/ (спека §6).
func setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}

// RequireSession — middleware загрузки сессии по cookie twofa_session:
// отсутствующая/просроченная сессия и отключённый пользователь → 401;
// мутирующие методы дополнительно требуют заголовок X-CSRF-Token, равный
// CSRF-токену сессии (сравнение в постоянном времени), иначе 403.
// Пользователь, CSRF-токен и хеш токена сессии кладутся в контекст
// (ctxKeyUser/ctxKeyCSRF/ctxKeySessionHash).
func RequireSession(st *store.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := r.Cookie(cookieSession)
			if err != nil || c.Value == "" {
				writeError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			tokenHash := secrets.SHA256(c.Value)
			userID, csrf, err := st.SessionGet(r.Context(), tokenHash)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			user, err := st.UserByID(r.Context(), userID)
			if err != nil || !user.Enabled {
				// Отключённый админом пользователь теряет сессию сразу.
				writeError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			if mutatingMethod(r.Method) &&
				subtle.ConstantTimeCompare([]byte(r.Header.Get(csrfHeader)), []byte(csrf)) != 1 {
				writeError(w, http.StatusForbidden, "csrf")
				return
			}
			ctx := context.WithValue(r.Context(), ctxKeyUser, user)
			ctx = context.WithValue(ctx, ctxKeyCSRF, csrf)
			ctx = context.WithValue(ctx, ctxKeySessionHash, tokenHash)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// SessionAPI — зависимости и маршруты входа web: /api/v1/login,
// /api/v1/login/2fa, /api/v1/logout.
type SessionAPI struct {
	core *auth.Core
	st   *store.Store
	pv   auth.PasswordVerifier
	m    *settings.M
	rl   *limiterMap
}

// NewSessionAPI собирает API сессий; pv — проверка первого фактора (тот же
// верификатор, что в ядре). Ресурсы освобождаются Stop.
func NewSessionAPI(core *auth.Core, st *store.Store, pv auth.PasswordVerifier, m *settings.M) *SessionAPI {
	return &SessionAPI{core: core, st: st, pv: pv, m: m, rl: newLimiterMap()}
}

// Stop останавливает фоновую очистку rate-limiter.
func (s *SessionAPI) Stop() { s.rl.Stop() }

// Register монтирует маршруты входа web в chi-роутер.
func (s *SessionAPI) Register(r chi.Router) {
	r.Post("/api/v1/login", s.handleLogin)
	r.Post("/api/v1/login/2fa", s.handleLogin2FA)
	r.With(RequireSession(s.st)).Post("/api/v1/logout", s.handleLogout)
}

// audit пишет событие, не ломая основной поток (как в PublicAPI).
func (s *SessionAPI) audit(ctx context.Context, username, event, ip, result string, detail map[string]any) {
	if err := s.st.Audit(ctx, username, event, detail, ip, result); err != nil {
		slog.Warn("api: аудит не записан", "event", event, "error", err)
	}
}

// allowReq проверяет rate-limit корзины username и IP без записи ответа —
// общий предикат для JSON- и HTML-входа.
func (s *SessionAPI) allowReq(r *http.Request, username string) bool {
	return s.rl.Allow("u:"+username) && s.rl.Allow("ip:"+clientIP(r))
}

// allow проверяет rate-limit корзины username и IP (как /auth/start);
// при исчерпании сам отвечает 429.
func (s *SessionAPI) allow(w http.ResponseWriter, r *http.Request, username string) bool {
	if !s.allowReq(r, username) {
		w.Header().Set("Retry-After", strconv.Itoa(rlRetryAfterSec))
		writeJSON(w, http.StatusTooManyRequests,
			map[string]any{"error": "rate_limited", "retry_after": rlRetryAfterSec})
		return false
	}
	return true
}

// loginStep1 — первый фактор web-входа (общий код JSON- и HTML-обвязки):
// проверка пароля и fail-блокировки; аудит пишется здесь же. flow — метка
// аудита (web / web_html). Возвращает (user, 0, "") при успехе либо код
// ответа и машинный код ошибки (status != 0).
func (s *SessionAPI) loginStep1(ctx context.Context, ip, username, password, flow string) (*store.User, int, string) {
	user, err := s.pv.Verify(ctx, username, password)
	if errors.Is(err, auth.ErrBadCredentials) || errors.Is(err, store.ErrNotFound) {
		// Единый ответ против перечисления пользователей.
		s.audit(ctx, username, "login_fail", ip, "fail",
			map[string]any{"reason": "bad_credentials", "flow": flow})
		return nil, http.StatusUnauthorized, "bad_credentials"
	}
	if err != nil {
		slog.Error("api: login verify", "error", err)
		return nil, http.StatusInternalServerError, "internal"
	}
	if s.core.FailLocked(ctx, user.ID) {
		s.audit(ctx, user.Username, "login_fail", ip, "fail",
			map[string]any{"reason": "locked", "flow": flow})
		return nil, http.StatusLocked, "locked"
	}
	return user, 0, ""
}

// loginStep2 — второй шаг web-входа «пароль + код» одним запросом (общий
// код JSON- и HTML-обвязки): lookup пользователя → enabled → FailLocked →
// код (VerifyAnyCode либо одноразовое passkey-окно consumeWebauthnPending)
// → пароль РОВНО один раз и только после кода (инвариант «один argon2 на
// запрос»). Возвращает (user, 0, "") при успехе либо код ответа и ошибку.
func (s *SessionAPI) loginStep2(ctx context.Context, r *http.Request, username, password, code, flow string) (*store.User, int, string) {
	ip := clientIP(r)
	user, err := s.st.UserByUsername(ctx, username)
	if errors.Is(err, store.ErrNotFound) {
		s.audit(ctx, username, "login_fail", ip, "fail",
			map[string]any{"reason": "no_user", "flow": flow})
		return nil, http.StatusUnauthorized, "bad_credentials"
	}
	if err != nil {
		slog.Error("api: login/2fa lookup", "error", err)
		return nil, http.StatusInternalServerError, "internal"
	}
	if !user.Enabled {
		// Единый 401, как в первом шаге (анти-перечисление).
		s.audit(ctx, user.Username, "login_fail", ip, "fail",
			map[string]any{"reason": "bad_credentials", "flow": flow})
		return nil, http.StatusUnauthorized, "bad_credentials"
	}
	if s.core.FailLocked(ctx, user.ID) {
		s.audit(ctx, user.Username, "login_fail", ip, "fail",
			map[string]any{"reason": "locked", "flow": flow})
		return nil, http.StatusLocked, "locked"
	}

	if code != "" {
		if _, err := s.core.VerifyAnyCode(ctx, user, code); err != nil {
			if !errors.Is(err, auth.ErrBadCode) {
				slog.Error("api: login/2fa код", "error", err)
				return nil, http.StatusInternalServerError, "internal"
			}
			s.audit(ctx, user.Username, "login_fail", ip, "fail",
				map[string]any{"reason": "bad_code", "flow": flow})
			return nil, http.StatusUnauthorized, "bad_code"
		}
	} else if !s.consumeWebauthnPending(ctx, user) {
		s.audit(ctx, user.Username, "login_fail", ip, "fail",
			map[string]any{"reason": "bad_code", "flow": flow})
		return nil, http.StatusUnauthorized, "bad_code"
	}

	if _, err := s.pv.Verify(ctx, username, password); err != nil {
		if errors.Is(err, auth.ErrBadCredentials) || errors.Is(err, store.ErrNotFound) {
			s.audit(ctx, user.Username, "login_fail", ip, "fail",
				map[string]any{"reason": "bad_credentials", "flow": flow})
			return nil, http.StatusUnauthorized, "bad_credentials"
		}
		slog.Error("api: login/2fa verify", "error", err)
		return nil, http.StatusInternalServerError, "internal"
	}
	return user, 0, ""
}

// ---- POST /api/v1/login ----

type loginReq struct {
	Username       string `json:"username"`
	Password       string `json:"password"`
	RememberDevice bool   `json:"remember_device"`
}

// handleLogin — первый шаг входа web: проверка пароля (+FailLocked → 423);
// доверенное устройство с верным паролем и пользователь без второго фактора
// получают сессию сразу; иначе 200 {two_factor:"required", methods:[...]}
// без создания сессии-кандидата.
func (s *SessionAPI) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if !decodeJSON(w, r, &req) {
		return
	}
	ctx := r.Context()
	ip := clientIP(r)
	if !s.allow(w, r, req.Username) {
		return
	}

	user, status, errCode := s.loginStep1(ctx, ip, req.Username, req.Password, "web")
	if status != 0 {
		writeError(w, status, errCode)
		return
	}

	// Доверенное устройство + верный пароль → сессия без второго фактора.
	if s.trustedDevice(r, user) {
		s.finishLogin(w, r, user, req.RememberDevice, "trusted_device")
		return
	}

	methods := s.twoFactorMethods(ctx, user)
	if len(methods) == 0 {
		// Второй фактор не настроен — пароль достаточен.
		s.finishLogin(w, r, user, false, "password_only")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"two_factor": "required", "methods": methods})
}

// ---- POST /api/v1/login/2fa ----

type login2FAReq struct {
	Username       string `json:"username"`
	Password       string `json:"password"`
	Code           string `json:"code"`
	RememberDevice bool   `json:"remember_device"`
}

// handleLogin2FA — второй шаг: «пароль + код» одним запросом. Код проверяется
// core.VerifyAnyCode (резервный / TOTP / активный код доставки); passkey-ветка
// — пустой код при активном «webauthn_web_pending»-окне: его создаёт
// публичный /api/v1/auth/webauthn/finish ПОСЛЕ проверки подписи passkey, и
// оно атомарно погашается этим входом (consumeWebauthnPending — одноразовое
// окно вместо прежнего скана аудита). Решение принимает loginStep2.
func (s *SessionAPI) handleLogin2FA(w http.ResponseWriter, r *http.Request) {
	var req login2FAReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if !s.allow(w, r, req.Username) {
		return
	}
	user, status, errCode := s.loginStep2(r.Context(), r, req.Username, req.Password, req.Code, "web_2fa")
	if status != 0 {
		writeError(w, status, errCode)
		return
	}
	s.finishLogin(w, r, user, req.RememberDevice, "password+code")
}

// finishLogin выпускает сессию (startSession) и отвечает {ok, username, csrf}.
func (s *SessionAPI) finishLogin(w http.ResponseWriter, r *http.Request, user *store.User, rememberDevice bool, mode string) {
	csrf, err := s.startSession(w, r, user, rememberDevice, mode)
	if err != nil {
		slog.Error("api: создать сессию", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "username": user.Username, "csrf": csrf})
}

// startSession выпускает сессию (и, при remember_device, доверяет
// устройству) и пишет login_ok — общий хвост JSON- и HTML-входа.
// Возвращает CSRF для ответа клиенту (cookie HttpOnly — скрипт токен
// не прочитает).
func (s *SessionAPI) startSession(w http.ResponseWriter, r *http.Request, user *store.User, rememberDevice bool, mode string) (string, error) {
	csrf, err := s.createSession(w, r, user)
	if err != nil {
		return "", err
	}
	if rememberDevice {
		s.trustDevice(w, r, user)
	}
	s.audit(r.Context(), user.Username, "login_ok", clientIP(r), "ok", map[string]any{"mode": mode})
	return csrf, nil
}

// createSession выпускает сессию: случайный токен — в cookie, в БД — только
// его SHA-256 и CSRF-токен. Возвращает CSRF для ответа клиенту (cookie
// HttpOnly — скрипт токен не прочитает).
func (s *SessionAPI) createSession(w http.ResponseWriter, r *http.Request, user *store.User) (string, error) {
	token := secrets.RandomToken(tokenBytes)
	csrf := secrets.RandomToken(tokenBytes)
	ttl := s.m.Get().Policy.SessionTTL
	if err := s.st.SessionCreate(r.Context(), secrets.SHA256(token), user.ID, csrf, ttl); err != nil {
		return "", err
	}
	setCookie(w, cookieSession, token, int(ttl.Seconds()))
	return csrf, nil
}

// trustDevice регистрирует доверенное устройство (remember_device): токен —
// в cookie, SHA-256 и метаданные — в БД, срок policy.trusted_device_ttl.
// Отказ записи не ломает вход — сессия уже создана.
func (s *SessionAPI) trustDevice(w http.ResponseWriter, r *http.Request, user *store.User) {
	token := secrets.RandomToken(tokenBytes)
	ttl := s.m.Get().Policy.TrustedDeviceTTL
	d := &store.Device{
		UserID:    user.ID,
		TokenHash: secrets.SHA256(token),
		UA:        r.UserAgent(),
		IP:        clientIP(r),
		ExpiresAt: time.Now().Add(ttl),
	}
	if err := s.st.DeviceCreate(r.Context(), d); err != nil {
		slog.Warn("api: создать доверенное устройство", "error", err)
		return
	}
	setCookie(w, cookieDevice, token, int(ttl.Seconds()))
}

// trustedDevice проверяет cookie twofa_device: устройство действует
// (DeviceGet отсекает просроченные) и принадлежит этому пользователю;
// попутно обновляется last_seen_at.
func (s *SessionAPI) trustedDevice(r *http.Request, user *store.User) bool {
	c, err := r.Cookie(cookieDevice)
	if err != nil || c.Value == "" {
		return false
	}
	hash := secrets.SHA256(c.Value)
	d, err := s.st.DeviceGet(r.Context(), hash)
	if err != nil || d.UserID != user.ID {
		return false
	}
	_ = s.st.DeviceTouch(r.Context(), hash)
	return true
}

// twoFactorMethods перечисляет доступные пользователю способы второго
// фактора: подтверждённый TOTP, зарегистрированные passkeys и привязанные
// кодовые каналы из prefer_channels (email/sms/telegram).
func (s *SessionAPI) twoFactorMethods(ctx context.Context, user *store.User) []string {
	var methods []string
	seen := make(map[string]struct{}, 4)
	add := func(m string) {
		if _, dup := seen[m]; !dup {
			seen[m] = struct{}{}
			methods = append(methods, m)
		}
	}
	if _, _, _, confirmed, _, err := s.st.TOTPGet(ctx, user.ID); err == nil && confirmed {
		add(string(channel.TOTP))
	}
	if creds, err := s.st.WACredListForUser(ctx, user.ID); err == nil && len(creds) > 0 {
		add("webauthn")
	}
	for _, ch := range user.PreferChannels {
		switch ch {
		case channel.Email:
			if user.Email != "" {
				add(string(ch))
			}
		case channel.SMS:
			if user.Phone != "" {
				add(string(ch))
			}
		case channel.Telegram:
			if user.TelegramChatID != nil {
				add(string(ch))
			}
		}
	}
	return methods
}

// consumeWebauthnPending атомарно погашает свежее «webauthn_web_pending»-
// окно пользователя — доказательство только что завершённой успешной
// WebAuthn-церемонии входа (строку создаёт handleWAFinish после проверки
// подписи, TTL waPendingTTL). Поиск берёт самое свежее активное окно;
// ChallengeMarkUsed — одноразовый claim: повторный вход и гонка двух
// параллельных login/2fa получают ErrNotFound → false, replay окна
// невозможен. Аудит webauthn_login остаётся только для наблюдаемости.
func (s *SessionAPI) consumeWebauthnPending(ctx context.Context, user *store.User) bool {
	var id uuid.UUID
	err := s.st.Pool().QueryRow(ctx, `
		SELECT id FROM challenges
		WHERE user_id = $1 AND purpose = $2 AND used_at IS NULL AND expires_at > now()
		ORDER BY created_at DESC
		LIMIT 1`, user.ID, purposeWAPending).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false // активного окна нет — passkey-вход не доказан
	}
	if err != nil {
		slog.Warn("api: поиск webauthn_web_pending", "error", err)
		return false // fail closed
	}
	if err := s.st.ChallengeMarkUsed(ctx, id); err != nil {
		// ErrNotFound — окно только что погасил конкурентный claim; прочее —
		// ошибка БД, вход без доказательства не выпускаем.
		if !errors.Is(err, store.ErrNotFound) {
			slog.Warn("api: погашение webauthn_web_pending", "error", err)
		}
		return false
	}
	return true
}

// ---- POST /api/v1/logout ----

// handleLogout удаляет текущую сессию и чистит cookie (требует сессию и
// CSRF-заголовок — мутирующий запрос).
func (s *SessionAPI) handleLogout(w http.ResponseWriter, r *http.Request) {
	hash, _ := r.Context().Value(ctxKeySessionHash).([]byte)
	if len(hash) > 0 {
		if err := s.st.SessionDelete(r.Context(), hash); err != nil && !errors.Is(err, store.ErrNotFound) {
			slog.Warn("api: удалить сессию", "error", err)
		}
	}
	setCookie(w, cookieSession, "", -1)
	if u, ok := userFrom(r.Context()); ok {
		s.audit(r.Context(), u.Username, "logout", clientIP(r), "ok", nil)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
