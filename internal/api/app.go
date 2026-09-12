// Package api: REST API, WebSocket и SSE для мобильных и десктопных приложений (Windows, Android, iOS).
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"github.com/aligorov/twofa/internal/auth"
	"github.com/aligorov/twofa/internal/channel"
	"github.com/aligorov/twofa/internal/delivery"
	"github.com/aligorov/twofa/internal/oidc"
	"github.com/aligorov/twofa/internal/secrets"
	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
)

type appContextKey int

const (
	appKeyUser appContextKey = iota
	appKeyDevice
)

// appFirewall — узкое окно в firewall.Guard (подача неудач входа в fail2ban,
// без импорта пакета firewall и цикла зависимостей).
type appFirewall interface {
	Fail(ctx context.Context, ip, reason string)
}

// AppAPI предоставляет API для клиентских приложений Ligament Authenticator.
type AppAPI struct {
	core     *auth.Core
	st       *store.Store
	pv       auth.PasswordVerifier
	set      *settings.M
	hub      *delivery.AppHub
	oidc     *oidc.Manager
	notifier *delivery.SupportNotifier
	rl       *limiterMap // корзины username+IP для /app/login
	fw       appFirewall // nil — неудачи входа не кормят fail2ban

	// Ленивая автоматика TTL support-сессий (system-актёр таблицы
	// переходов): троттлинг раз в минуту на часто опрашиваемых ручках.
	supportSweepAt atomic.Int64 // unix-нanos последнего sweep
}

// SetSupportNotifier подключает диспетчер оповещений поддержки.
func (a *AppAPI) SetSupportNotifier(n *delivery.SupportNotifier) {
	a.notifier = n
}

// SetFirewall подключает fail2ban-guard: неудачные app-логины считаются
// по IP наравне с web-входом (аудит раунд-2: app-путь был невидим fail2ban).
func (a *AppAPI) SetFirewall(f appFirewall) { a.fw = f }

// Stop освобождает фоновую очистку rate-limiter.
func (a *AppAPI) Stop() {
	if a.rl != nil {
		a.rl.Stop()
	}
}

// NewAppAPI создает обработчик клиентского API.
func NewAppAPI(core *auth.Core, st *store.Store, pv auth.PasswordVerifier, set *settings.M, hub *delivery.AppHub, oidcMgr *oidc.Manager) *AppAPI {
	return &AppAPI{
		core: core,
		st:   st,
		pv:   pv,
		set:  set,
		hub:  hub,
		oidc: oidcMgr,
		rl:   newLimiterMap(),
	}
}

// rateLimitByUser — rate-limit корзин username+IP (a.allow) для
// аутентифицированных ручек с перебираемым секретом. Ставится на decision
// (P1 аудита 2026-09-11: перебор number_match не ограничивался).
// authMiddleware гарантирует пользователя в контексте; на всякий случай
// при его отсутствии ограничивается хотя бы IP-корзина.
func (a *AppAPI) rateLimitByUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username := ""
		if user, _ := appUserFromCtx(r.Context()); user != nil {
			username = user.Username
		}
		if !a.allow(w, r, username) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Register монтирует маршруты приложения.
func (a *AppAPI) Register(r chi.Router) {
	r.Route("/api/v1/app", func(r chi.Router) {
		r.Post("/login", a.handleLogin)
		r.Get("/config", a.handleConfig)

		r.Group(func(r chi.Router) {
			r.Use(a.authMiddleware)

			r.Post("/logout", a.handleLogout)
			r.Post("/device/push-token", a.handleUpdatePushToken)
			r.Post("/telemetry", a.handleTelemetry)

			r.Get("/challenges/pending", a.handlePendingChallenges)
			// Decision — перебор number_match: rate-limit как у /app/login.
			r.With(a.rateLimitByUser).Post("/challenges/{id}/decision", a.handleChallengeDecision)

			// Удаленная поддержка (SOS / Quick Assist)
			r.Post("/support/request", a.handleSupportRequest)
			r.Get("/support/current", a.handleSupportCurrent)
			r.Get("/support/categories", a.handleSupportCategories)
			r.Get("/support/queue", a.handleSupportQueue)
			r.Post("/support/{id}/connect", a.handleSupportConnect)
			r.Post("/support/{id}/decision", a.handleSupportDecision)
			r.Post("/support/{id}/signal", a.handleSupportSignal)
			r.Get("/support/{id}/messages", a.handleSupportMessagesGet)
			r.Post("/support/{id}/messages", a.handleSupportMessageSend)
			r.Post("/support/{id}/end", a.handleSupportEnd)

			r.Get("/me/profile", a.handleProfile)
			r.Get("/me/apps", a.handleAllowedApps)
			r.Get("/me/history", a.handleHistory)

			r.Get("/ws", a.handleWS)
			r.Get("/sse", a.handleSSE)
		})
	})
}

// audit записывает аудит-событие для приложения.
func (a *AppAPI) audit(ctx context.Context, username, event string, detail map[string]any, ip, result string) {
	if a.st == nil {
		return
	}
	if err := a.st.Audit(ctx, username, event, detail, ip, result); err != nil {
		slog.Warn("app_api: аудит не записан", "event", event, "error", err)
	}
}

// sweepStaleSupport лениво применяет TTL-автоматику машины состояний
// (pending > 15м → expired, active > 4ч → completed) не чаще раза в минуту.
func (a *AppAPI) sweepStaleSupport(ctx context.Context) {
	nowNs := time.Now().UnixNano()
	last := a.supportSweepAt.Load()
	if nowNs-last < int64(time.Minute) {
		return
	}
	if !a.supportSweepAt.CompareAndSwap(last, nowNs) {
		return
	}
	if err := a.st.SupportSessionSweepStale(ctx); err != nil {
		slog.Warn("app_api: sweep просроченных support-сессий", "error", err)
	}
}

type appLoginRequest struct {
	Username        string         `json:"username"`
	Password        string         `json:"password"`
	Code            string         `json:"code"` // код второго фактора (TOTP/резервный/доставленный), когда фактор настроен
	DeviceName      string         `json:"device_name"`
	Platform        string         `json:"platform"` // windows | android | ios
	OSVersion       string         `json:"os_version"`
	AppVersion      string         `json:"app_version"`
	PushToken       string         `json:"push_token"`
	SecurityPosture map[string]any `json:"security_posture"`
}

type appLoginResponse struct {
	Token    string          `json:"token"`
	DeviceID uuid.UUID       `json:"device_id"`
	User     appUserResponse `json:"user"`
	Posture  map[string]any  `json:"security_posture"`
}

type appUserResponse struct {
	ID           uuid.UUID `json:"id"`
	Username     string    `json:"username"`
	DisplayName  string    `json:"display_name"`
	Role         string    `json:"role"`
	SupportRoles []string  `json:"support_roles"`
}

// allow проверяет rate-limit корзины username и IP /app/login (как
// /auth/start и web-вход); при исчерпании сам отвечает 429.
func (a *AppAPI) allow(w http.ResponseWriter, r *http.Request, username string) bool {
	if !a.rl.Allow("u:"+username) || !a.rl.Allow("ip:"+clientIP(r)) {
		w.Header().Set("Retry-After", strconv.Itoa(rlRetryAfterSec))
		writeJSON(w, http.StatusTooManyRequests,
			map[string]any{"error": "rate_limited", "retry_after": rlRetryAfterSec})
		return false
	}
	return true
}

// failLogin фиксирует неудачный app-вход: событие login_fail (flow=app)
// кормит per-user fail-счётчик (core.FailLocked считает login_fail) и
// fail2ban (Guard.Fail по IP).
func (a *AppAPI) failLogin(ctx context.Context, username, ip, reason string, detail map[string]any) {
	if detail == nil {
		detail = map[string]any{}
	}
	detail["reason"] = reason
	detail["flow"] = "app"
	a.audit(ctx, username, "login_fail", detail, ip, "fail")
	if a.fw != nil {
		a.fw.Fail(ctx, ip, "login_fail")
	}
}

// handleLogin — авторизация устройства в приложении. Защищён как web-вход
// (аудит раунд-2): rate-limit username+IP, per-user fail-блокировка до
// проверки пароля, единый 401 против перечисления, кормление fail2ban;
// при настроенном втором факторе требуется код (P0 аудита 2026-09-11 —
// раньше токен с правом approve выдавался по одному паролю).
func (a *AppAPI) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req appLoginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "empty_credentials")
		return
	}
	if !a.allow(w, r, req.Username) {
		return
	}
	ctx := r.Context()
	ip := clientIP(r)

	// Пользователь нужен для fail-блокировки; отсутствие не раскрывается
	// (ответ проходит через ту же argon2-проверку, что и существующий).
	user, lookupErr := a.st.UserByUsername(ctx, req.Username)
	if lookupErr != nil && !errors.Is(lookupErr, store.ErrNotFound) {
		slog.Error("app_api: поиск пользователя при входе", "error", lookupErr)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	if lookupErr == nil && a.core != nil && a.core.FailLocked(ctx, user.ID) {
		a.failLogin(ctx, user.Username, ip, "locked", nil)
		writeError(w, http.StatusLocked, "locked")
		return
	}

	// Проверка первого фактора (пароля) через PasswordVerifier.
	if _, err := a.pv.Verify(ctx, req.Username, req.Password); err != nil {
		a.failLogin(ctx, req.Username, ip, "bad_credentials",
			map[string]any{"platform": req.Platform, "device": req.DeviceName})
		writeError(w, http.StatusUnauthorized, "invalid_credentials")
		return
	}
	if lookupErr != nil {
		// Несуществующий пользователь: argon2 уже сожжён Verify — отвечаем
		// тем же кодом, что и неверный пароль.
		a.failLogin(ctx, req.Username, ip, "no_user", nil)
		writeError(w, http.StatusUnauthorized, "invalid_credentials")
		return
	}

	if !user.Enabled {
		writeError(w, http.StatusForbidden, "user_disabled")
		return
	}

	// Второй фактор (P0 аудита 2026-09-11): токен устройства даёт право
	// approve push-челленджей, поэтому выдача по одному паролю вырождала
	// 2FA в пароль (полная цепочка logins→approve одним фактором). При
	// наличии у пользователя хоть одного настроенного фактора требуется
	// валидный код — тот же верификатор и login-набор purposes, что у
	// web-входа (TOTP/резервные — факторы пользователя, доставленные
	// коды — только своего назначения). Учётка вообще без факторов
	// (bootstrap) пускается как раньше — подтверждаться нечем.
	if hasSecondFactor(ctx, a.st, user) {
		if a.core == nil || strings.TrimSpace(req.Code) == "" {
			a.failLogin(ctx, user.Username, ip, "bad_code", nil)
			writeError(w, http.StatusUnauthorized, "second_factor_required")
			return
		}
		if _, err := a.core.VerifyAnyCode(ctx, user, strings.TrimSpace(req.Code), auth.LoginCodePurposes...); err != nil {
			a.failLogin(ctx, user.Username, ip, "bad_code", nil)
			writeError(w, http.StatusUnauthorized, "second_factor_required")
			return
		}
	}

	// Генерация 32-байтного Bearer-токена
	rawBytes := make([]byte, 32)
	if _, err := rand.Read(rawBytes); err != nil {
		writeError(w, http.StatusInternalServerError, "rand_error")
		return
	}
	tokenStr := hex.EncodeToString(rawBytes)
	tokenHash := secrets.SHA256(tokenStr)

	platform := strings.ToLower(strings.TrimSpace(req.Platform))
	if platform == "" {
		platform = "windows"
	}
	deviceName := strings.TrimSpace(req.DeviceName)
	if deviceName == "" {
		deviceName = platform + " device"
	}

	if req.SecurityPosture == nil {
		req.SecurityPosture = make(map[string]any)
	}
	// Базовая оценка безопасности: если root/jailbreak, помечаем несовместимым
	isCompliant := true
	if rooted, ok := req.SecurityPosture["rooted"].(bool); ok && rooted {
		isCompliant = false
	}
	if jailbroken, ok := req.SecurityPosture["jailbroken"].(bool); ok && jailbroken {
		isCompliant = false
	}
	req.SecurityPosture["is_compliant"] = isCompliant
	req.SecurityPosture["evaluated_at"] = time.Now().Format(time.RFC3339)

	device := &store.AppDevice{
		UserID:          user.ID,
		DeviceName:      deviceName,
		Platform:        platform,
		PushToken:       strings.TrimSpace(req.PushToken),
		TokenHash:       tokenHash,
		Active:          true,
		OSVersion:       strings.TrimSpace(req.OSVersion),
		AppVersion:      strings.TrimSpace(req.AppVersion),
		SecurityPosture: req.SecurityPosture,
		LastIP:          ip,
	}

	if err := a.st.AppDeviceCreate(r.Context(), device); err != nil {
		slog.Error("app_api: ошибка регистрации устройства", "user", user.Username, "error", err)
		writeError(w, http.StatusInternalServerError, "db_error")
		return
	}

	a.audit(r.Context(), user.Username, "app_login",
		map[string]any{
			"device_id":    device.ID.String(),
			"platform":     platform,
			"device_name":  deviceName,
			"is_compliant": isCompliant,
		}, ip, "ok")

	writeJSON(w, http.StatusOK, appLoginResponse{
		Token:    tokenStr,
		DeviceID: device.ID,
		User: appUserResponse{
			ID:           user.ID,
			Username:     user.Username,
			DisplayName:  user.DisplayName,
			Role:         user.Role,
			SupportRoles: user.SupportRoles,
		},
		Posture: req.SecurityPosture,
	})
}

// authMiddleware проверяет Bearer токен клиентского приложения. Токен в
// ?token= принимается только для WS/SSE-запросов (браузерные EventSource и
// WebSocket не умеют заголовок Authorization; для обычных JSON-запросов
// query-строка оседает в логах прокси и истории — только заголовок).
// Токен бессрочным не является: истёкший (expires_at) отклоняется, при
// использовании лениво продлевается sliding-окном (store.AppDeviceTouch).
func (a *AppAPI) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		var tokenStr string
		if strings.HasPrefix(authHeader, "Bearer ") {
			tokenStr = strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		} else if qToken := r.URL.Query().Get("token"); qToken != "" && isStreamRequest(r) {
			tokenStr = strings.TrimSpace(qToken)
		}

		if tokenStr == "" {
			writeError(w, http.StatusUnauthorized, "missing_token")
			return
		}

		tokenHash := secrets.SHA256(tokenStr)
		device, err := a.st.AppDeviceGetByTokenHash(r.Context(), tokenHash)
		if err != nil || !device.Active {
			writeError(w, http.StatusUnauthorized, "invalid_token")
			return
		}

		user, err := a.st.UserByID(r.Context(), device.UserID)
		if err != nil || !user.Enabled {
			writeError(w, http.StatusForbidden, "user_disabled")
			return
		}

		// Обновляем активность устройства
		_ = a.st.AppDeviceUpdateSeen(r.Context(), device.ID, clientIP(r), device.SecurityPosture)

		// Sliding-продление токена: UPDATE только когда до истечения
		// осталось меньше окна продления — регулярный запрос не пишет в БД.
		if device.ExpiresAt.Before(time.Now().Add(store.AppDeviceRenewWindow)) {
			_ = a.st.AppDeviceTouch(r.Context(), device.ID)
		}

		ctx := context.WithValue(r.Context(), appKeyDevice, device)
		ctx = context.WithValue(ctx, appKeyUser, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func appDeviceFromCtx(ctx context.Context) (*store.AppDevice, bool) {
	d, ok := ctx.Value(appKeyDevice).(*store.AppDevice)
	return d, ok
}

func appUserFromCtx(ctx context.Context) (*store.User, bool) {
	u, ok := ctx.Value(appKeyUser).(*store.User)
	return u, ok
}

// handleLogout отзывает сессию устройства.
func (a *AppAPI) handleLogout(w http.ResponseWriter, r *http.Request) {
	device, _ := appDeviceFromCtx(r.Context())
	user, _ := appUserFromCtx(r.Context())

	if err := a.st.AppDeviceSetActive(r.Context(), device.ID, user.ID, false); err != nil {
		writeError(w, http.StatusInternalServerError, "db_error")
		return
	}

	a.audit(r.Context(), user.Username, "app_logout",
		map[string]any{"device_id": device.ID.String(), "device_name": device.DeviceName}, clientIP(r), "ok")

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleUpdatePushToken обновляет push-токен устройства (APNs/FCM).
func (a *AppAPI) handleUpdatePushToken(w http.ResponseWriter, r *http.Request) {
	device, _ := appDeviceFromCtx(r.Context())
	var req struct {
		PushToken string `json:"push_token"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	if err := a.st.AppDeviceUpdatePushToken(r.Context(), device.ID, strings.TrimSpace(req.PushToken)); err != nil {
		writeError(w, http.StatusInternalServerError, "db_error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleTelemetry принимает снимок телеметрии с проверками безопасности (GPO / EDR / BitLocker).
func (a *AppAPI) handleTelemetry(w http.ResponseWriter, r *http.Request) {
	device, _ := appDeviceFromCtx(r.Context())
	user, _ := appUserFromCtx(r.Context())

	var req struct {
		SecurityPosture map[string]any `json:"security_posture"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.SecurityPosture == nil {
		req.SecurityPosture = make(map[string]any)
	}

	// Расчет статуса соответствия корпоративным политикам безопасности (GPO compliance)
	isCompliant := true

	// Проверка Windows BitLocker
	if device.Platform == "windows" {
		if bitlocker, ok := req.SecurityPosture["bitlocker"].(string); ok {
			if strings.EqualFold(bitlocker, "off") || strings.EqualFold(bitlocker, "disabled") {
				// Если GPO требует BitLocker
				if req.SecurityPosture["policy_require_bitlocker"] == true {
					isCompliant = false
				}
			}
		}
	}

	// Проверка Jailbreak / Rooting
	if rooted, ok := req.SecurityPosture["rooted"].(bool); ok && rooted {
		isCompliant = false
	}
	if jb, ok := req.SecurityPosture["jailbroken"].(bool); ok && jb {
		isCompliant = false
	}

	req.SecurityPosture["is_compliant"] = isCompliant
	req.SecurityPosture["evaluated_at"] = time.Now().Format(time.RFC3339)

	if err := a.st.AppDeviceUpdatePosture(r.Context(), device.ID, req.SecurityPosture); err != nil {
		writeError(w, http.StatusInternalServerError, "db_error")
		return
	}

	device.SecurityPosture = req.SecurityPosture

	a.audit(r.Context(), user.Username, "app_telemetry",
		map[string]any{
			"device_id":    device.ID.String(),
			"is_compliant": isCompliant,
			"platform":     device.Platform,
		}, clientIP(r), "ok")

	writeJSON(w, http.StatusOK, map[string]any{
		"status":       "ok",
		"is_compliant": isCompliant,
	})
}

// handlePendingChallenges возвращает список ожидающих подтверждения push-челленджей для приложения.
func (a *AppAPI) handlePendingChallenges(w http.ResponseWriter, r *http.Request) {
	user, _ := appUserFromCtx(r.Context())

	list, err := a.st.ActiveAppPushChallenges(r.Context(), user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db_error")
		return
	}

	type challengeItem struct {
		ID               uuid.UUID      `json:"id"`
		Channel          string         `json:"channel"`
		Purpose          string         `json:"purpose"`
		ExpiresAt        time.Time      `json:"expires_at"`
		ExpiresInSeconds int            `json:"expires_in_seconds"`
		Metadata         map[string]any `json:"metadata"`
		CreatedAt        time.Time      `json:"created_at"`
	}

	out := make([]challengeItem, 0, len(list))
	now := time.Now()
	for _, ch := range list {
		secs := int(ch.ExpiresAt.Sub(now).Seconds())
		if secs < 0 {
			secs = 0
		}
		out = append(out, challengeItem{
			ID:               ch.ID,
			Channel:          string(ch.Channel),
			Purpose:          ch.Purpose,
			ExpiresAt:        ch.ExpiresAt,
			ExpiresInSeconds: secs,
			Metadata:         ch.Metadata,
			CreatedAt:        ch.CreatedAt,
		})
	}

	writeJSON(w, http.StatusOK, out)
}

// handleChallengeDecision принимает решение пользователя: approve или deny.
func (a *AppAPI) handleChallengeDecision(w http.ResponseWriter, r *http.Request) {
	device, _ := appDeviceFromCtx(r.Context())
	user, _ := appUserFromCtx(r.Context())

	idStr := chi.URLParam(r, "id")
	chID, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_id")
		return
	}

	var req struct {
		Decision    string `json:"decision"` // approve | deny
		NumberMatch string `json:"number_match,omitempty"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Decision = strings.ToLower(strings.TrimSpace(req.Decision))
	if req.Decision != "approve" && req.Decision != "deny" {
		writeError(w, http.StatusBadRequest, "invalid_decision")
		return
	}

	ch, err := a.st.ChallengeGet(r.Context(), chID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "challenge_not_found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db_error")
		return
	}

	// Проверка владельца и канала челленджа
	if ch.UserID != user.ID || ch.Channel != channel.AppPush {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if ch.UsedAt != nil || !time.Now().Before(ch.ExpiresAt) {
		writeError(w, http.StatusGone, "challenge_expired")
		return
	}

	ip := clientIP(r)

	if req.Decision == "approve" {
		// 1. Проверка соответствия корпоративным политикам безопасности устройства
		if compliant, ok := device.SecurityPosture["is_compliant"].(bool); ok && !compliant {
			a.audit(r.Context(), user.Username, "app_push_blocked_compliance",
				map[string]any{"challenge_id": ch.ID.String(), "device_id": device.ID.String()}, ip, "fail")
			writeError(w, http.StatusForbidden, "device_non_compliant")
			return
		}

		// 2. Проверка Number Matching (защита от push-fatigue и случайных нажатий)
		if expectedMatch, ok := ch.Metadata["number_match"].(string); ok && expectedMatch != "" {
			if strings.TrimSpace(req.NumberMatch) != expectedMatch {
				// Промах расходует попытку челленджа (как Core.failAttempt:
				// атомарный декремент, при исчерпании — погашение). Без
				// этого 2-значный код перебирается за TTL (P1 аудита
				// 2026-09-11); погашенный челлендж в RADIUS/pollStatus
				// ведёт себя как отклонённый.
				left, derr := a.st.ChallengeDecrAttempt(r.Context(), ch.ID)
				if derr == nil && left == 0 {
					_ = a.st.ChallengeMarkUsed(r.Context(), ch.ID)
				}
				a.audit(r.Context(), user.Username, "app_push_number_mismatch",
					map[string]any{"challenge_id": ch.ID.String(), "entered": req.NumberMatch}, ip, "fail")
				writeError(w, http.StatusBadRequest, "number_match_mismatch")
				return
			}
		}

		buildDetail := func(decision string) map[string]any {
			m := map[string]any{
				"challenge_id": ch.ID.String(),
				"decision":     decision,
				"device_id":    device.ID.String(),
				"device_name":  device.DeviceName,
				"method":       "app_push",
			}
			if ch.Metadata != nil {
				if s, _ := ch.Metadata["service"].(string); s != "" {
					m["service"] = s
				} else if ch.Purpose != "" {
					m["service"] = ch.Purpose
				}
				if cip, _ := ch.Metadata["client_ip"].(string); cip != "" {
					m["client_ip"] = cip
				}
				if hip, _ := ch.Metadata["host_ip"].(string); hip != "" {
					m["host_ip"] = hip
				}
				if tip, _ := ch.Metadata["ip"].(string); tip != "" {
					m["target_ip"] = tip
				}
				if tua, _ := ch.Metadata["ua"].(string); tua != "" {
					m["target_ua"] = tua
				}
				if host, _ := ch.Metadata["host"].(string); host != "" {
					m["host"] = host
				}
				if cl, _ := ch.Metadata["client"].(string); cl != "" {
					m["client"] = cl
				}
			}
			return m
		}

		if err := a.st.ChallengeSetPush(r.Context(), ch.ID, "approved"); err != nil {
			writeError(w, http.StatusInternalServerError, "db_error")
			return
		}

		a.audit(r.Context(), user.Username, "app_push_decision", buildDetail("approve"), ip, "ok")
	} else {
		// Отклонение запроса: фиксируем статус "denied" в push_state,
		// не вызывая ChallengeMarkUsed, чтобы RADIUS и pollStatus зафиксировали отказ.
		_ = a.st.ChallengeSetPush(r.Context(), ch.ID, "denied")

		buildDetail := func(decision string) map[string]any {
			m := map[string]any{
				"challenge_id": ch.ID.String(),
				"decision":     decision,
				"device_id":    device.ID.String(),
				"device_name":  device.DeviceName,
				"method":       "app_push",
			}
			if ch.Metadata != nil {
				if s, _ := ch.Metadata["service"].(string); s != "" {
					m["service"] = s
				} else if ch.Purpose != "" {
					m["service"] = ch.Purpose
				}
				if cip, _ := ch.Metadata["client_ip"].(string); cip != "" {
					m["client_ip"] = cip
				}
				if hip, _ := ch.Metadata["host_ip"].(string); hip != "" {
					m["host_ip"] = hip
				}
				if tip, _ := ch.Metadata["ip"].(string); tip != "" {
					m["target_ip"] = tip
				}
				if tua, _ := ch.Metadata["ua"].(string); tua != "" {
					m["target_ua"] = tua
				}
				if host, _ := ch.Metadata["host"].(string); host != "" {
					m["host"] = host
				}
				if cl, _ := ch.Metadata["client"].(string); cl != "" {
					m["client"] = cl
				}
			}
			return m
		}

		a.audit(r.Context(), user.Username, "app_push_decision", buildDetail("deny"), ip, "ok")
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleProfile возвращает информацию о текущем пользователе.
func (a *AppAPI) handleProfile(w http.ResponseWriter, r *http.Request) {
	user, _ := appUserFromCtx(r.Context())

	groups, _ := a.st.UserGroupNames(r.Context(), user.ID)
	allGroups := append(groups, user.LDAPGroups...)

	devices, _ := a.st.AppDeviceActiveListByUser(r.Context(), user.ID)

	writeJSON(w, http.StatusOK, map[string]any{
		"id":             user.ID,
		"username":       user.Username,
		"display_name":   user.DisplayName,
		"email":          user.Email,
		"phone":          user.Phone,
		"role":           user.Role,
		"support_roles":  user.SupportRoles,
		"groups":         allGroups,
		"active_devices": len(devices),
		"telegram_bound": user.TelegramChatID != nil,
	})
}

// handleAllowedApps возвращает OIDC-приложения (Launchpad/SSO), разрешенные данному пользователю.
func (a *AppAPI) handleAllowedApps(w http.ResponseWriter, r *http.Request) {
	user, _ := appUserFromCtx(r.Context())

	clients, err := a.st.OIDCClients(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db_error")
		return
	}

	type appItem struct {
		ID           uuid.UUID `json:"id"`
		ClientID     string    `json:"client_id"`
		Name         string    `json:"name"`
		RedirectURIs []string  `json:"redirect_uris"`
		LaunchURL    string    `json:"launch_url,omitempty"`
	}

	out := make([]appItem, 0)
	for _, cl := range clients {
		// Проверяем доступ через OIDC менеджер
		if a.oidc != nil && !a.oidc.IsUserAllowed(r.Context(), user, &cl) {
			continue
		}
		launchURL := ""
		if len(cl.RedirectURIs) > 0 {
			launchURL = cl.RedirectURIs[0]
		}
		out = append(out, appItem{
			ID:           cl.ID,
			ClientID:     cl.ClientID,
			Name:         cl.Name,
			RedirectURIs: cl.RedirectURIs,
			LaunchURL:    launchURL,
		})
	}

	writeJSON(w, http.StatusOK, out)
}

func effectiveIP(cip, src string) string {
	if cip != "" {
		return cip
	}
	return src
}

// handleHistory возвращает недавний аудит-лог входов пользователя с детальной информацией («Куда, Где, Чем»).
func (a *AppAPI) handleHistory(w http.ResponseWriter, r *http.Request) {
	user, _ := appUserFromCtx(r.Context())

	// Исключаем фоновую телеметрию устройств app_telemetry, чтобы не вытеснять реальные входы
	list, err := a.st.AuditList(r.Context(), store.AuditFilter{
		Username:      user.Username,
		ExcludeEvents: []string{"app_telemetry"},
		Limit:         50,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db_error")
		return
	}

	type historyItem struct {
		ID          int64          `json:"id"`
		Timestamp   time.Time      `json:"timestamp"`
		Event       string         `json:"event"`
		EventTitle  string         `json:"event_title"`
		Result      string         `json:"result"`
		ResultTitle string         `json:"result_title"`
		IP          string         `json:"ip"`
		ClientIP    string         `json:"client_ip,omitempty"`
		HostIP      string         `json:"host_ip,omitempty"`
		Location    string         `json:"location"`
		Service     string         `json:"service"`
		Device      string         `json:"device"`
		Browser     string         `json:"browser,omitempty"`
		Method      string         `json:"method"`
		Description string         `json:"description"`
		Detail      map[string]any `json:"detail"`
	}

	out := make([]historyItem, 0, len(list))
	for _, it := range list {
		det := it.Detail
		if det == nil {
			det = make(map[string]any)
		}

		// 1. Определение сервиса («Куда»)
		service := ""
		if s, ok := det["service"].(string); ok && s != "" {
			service = s
		} else if s, ok := det["client_name"].(string); ok && s != "" {
			service = s
		} else if s, ok := det["client_id"].(string); ok && s != "" {
			service = s
		} else if s, ok := det["target"].(string); ok && s != "" {
			service = s
		} else if it.Event == "radius_auth" {
			service = "Корпоративный Wi-Fi / Сеть"
		} else if it.Event == "app_login" {
			service = "Приложение Ligament 2FA"
		} else if strings.HasPrefix(it.Event, "oidc_") {
			service = "Единый вход (SSO)"
		} else if host, ok := det["host"].(string); ok && host != "" {
			service = "Windows RDP (" + host + ")"
		} else {
			service = "Корпоративный доступ"
		}

		// 2. Внутренние и внешние IP-адреса («Где / Откуда»)
		clientIP := it.SrcIP
		if cip, ok := det["client_ip"].(string); ok && cip != "" {
			clientIP = cip
		} else if tip, ok := det["target_ip"].(string); ok && tip != "" {
			clientIP = tip
		}
		hostIP := ""
		if hip, ok := det["host_ip"].(string); ok && hip != "" {
			hostIP = hip
		} else if nip, ok := det["nas_ip"].(string); ok && nip != "" {
			hostIP = nip
		}

		location := ""
		if clientIP != "" && hostIP != "" && clientIP != hostIP {
			location = "Клиент: " + auth.FormatIPDescription(clientIP) + " • Сервер: " + auth.FormatIPDescription(hostIP)
		} else if clientIP != "" {
			location = auth.FormatIPDescription(clientIP)
		} else if it.SrcIP != "" {
			location = auth.FormatIPDescription(it.SrcIP)
		}

		// 3. Устройство и клиент
		ua := ""
		if tua, ok := det["target_ua"].(string); ok && tua != "" {
			ua = tua
		} else if u, ok := det["ua"].(string); ok && u != "" {
			ua = u
		}
		devStr, brStr := auth.FormatDeviceAndBrowser(ua)
		if devStr == "" || devStr == "Неизвестное устройство" {
			if dn, ok := det["device_name"].(string); ok && dn != "" {
				devStr = dn
			} else if cl, ok := det["client"].(string); ok && cl != "" {
				devStr = cl
			} else if it.Event == "radius_auth" {
				devStr = "Сетевое устройство"
			} else {
				devStr = "Устройство пользователя"
			}
		}

		// 4. Способ («Чем»)
		method := ""
		if m, ok := det["method"].(string); ok && m != "" {
			method = m
		} else if ch, ok := det["channel"].(string); ok && ch != "" {
			method = ch
		} else if md, ok := det["mode"].(string); ok && md != "" {
			method = md
		}
		switch method {
		case "app_push", "push":
			method = "Push в приложении"
		case "telegram_push", "telegram":
			method = "Telegram"
		case "totp":
			method = "TOTP-код"
		case "sms":
			method = "SMS-код"
		case "email":
			method = "Email-код"
		case "fido2", "webauthn":
			method = "Ключ FIDO2"
		case "backup":
			method = "Резервный код"
		case "password+code":
			method = "Пароль + 2FA"
		case "password":
			method = "Пароль"
		default:
			if it.Event == "app_push_decision" {
				method = "Push в приложении"
			} else if it.Event == "tg_push" {
				method = "Telegram"
			} else if it.Event == "radius_auth" {
				method = "802.1X / RADIUS"
			} else if method == "" {
				method = "Пароль / 2FA"
			}
		}

		// 5. Заголовок события (event_title)
		eventTitle := ""
		decision, _ := det["decision"].(string)
		action, _ := det["action"].(string)
		switch it.Event {
		case "app_push_decision":
			if decision == "approve" {
				eventTitle = "Подтверждение входа (Push)"
			} else if decision == "deny" {
				eventTitle = "Вход отклонён (Push)"
			} else {
				eventTitle = "Запрос 2FA подтверждения"
			}
		case "tg_push":
			if action == "approve" {
				eventTitle = "Подтверждение входа (Telegram)"
			} else if action == "deny" {
				eventTitle = "Вход отклонён (Telegram)"
			} else {
				eventTitle = "Запрос 2FA (Telegram)"
			}
		case "login_ok":
			if strings.Contains(service, "RDP") {
				eventTitle = "Вход через Windows RDP"
			} else if strings.Contains(service, "Wi-Fi") {
				eventTitle = "Подключение к Wi-Fi"
			} else {
				eventTitle = "Успешный вход в систему"
			}
		case "login_fail":
			reason, _ := det["reason"].(string)
			if reason == "bad_credentials" {
				eventTitle = "Неверный логин или пароль"
			} else if reason == "bad_code" {
				eventTitle = "Неверный 2FA код"
			} else if reason == "locked" {
				eventTitle = "Учётная запись заблокирована"
			} else {
				eventTitle = "Неудачная попытка входа"
			}
		case "app_login":
			eventTitle = "Вход в приложение Ligament"
		case "code_sent":
			eventTitle = "Отправлен код подтверждения"
		case "code_fail":
			eventTitle = "Неверный проверочный код"
		case "radius_auth":
			eventTitle = "Авторизация в сети Wi-Fi/VPN"
		case "oidc_consent":
			eventTitle = "Предоставление доступа SSO"
		case "oidc_token":
			eventTitle = "Вход через SSO (OpenID)"
		case "api_start":
			if it.Result == "fail" {
				eventTitle = "Неудачная проверка пароля"
			} else {
				eventTitle = "Запрос 2FA входа"
			}
		case "api_verify_ok":
			eventTitle = "Успешная 2FA авторизация"
		case "api_verify_fail":
			eventTitle = "Ошибка 2FA авторизации"
		case "app_device_register":
			eventTitle = "Привязка устройства"
		case "app_device_revoke":
			eventTitle = "Отзыв устройства"
		case "password_change":
			eventTitle = "Смена пароля"
		default:
			eventTitle = it.Event
		}

		// 6. Статус и описание
		resultTitle := "Успешно"
		if decision == "deny" || action == "deny" {
			resultTitle = "Отклонено пользователем"
		} else if it.Result == "fail" {
			resultTitle = "Ошибка"
		}

		desc := fmt.Sprintf("%s: сервис %s, способ %s (%s)", eventTitle, service, method, resultTitle)

		out = append(out, historyItem{
			ID:          it.ID,
			Timestamp:   it.Ts,
			Event:       it.Event,
			EventTitle:  eventTitle,
			Result:      it.Result,
			ResultTitle: resultTitle,
			IP:          effectiveIP(clientIP, it.SrcIP),
			ClientIP:    clientIP,
			HostIP:      hostIP,
			Location:    location,
			Service:     service,
			Device:      devStr,
			Browser:     brStr,
			Method:      method,
			Description: desc,
			Detail:      det,
		})
	}

	writeJSON(w, http.StatusOK, out)
}

// handleConfig возвращает публичные параметры сервера для настройки клиента.
func (a *AppAPI) handleConfig(w http.ResponseWriter, r *http.Request) {
	brandName := "Ligament 2FA"
	if a.set != nil {
		if snap := a.set.Get(); snap != nil && snap.Branding.Name != "" {
			brandName = snap.Branding.Name
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"server_name":    brandName,
		"version":        "1.0.0",
		"supported_auth": []string{"password", "totp", "app_push", "telegram_push"},
	})
}

// handleWS обслуживает постоянное WebSocket соединение с приложением.
func (a *AppAPI) handleWS(w http.ResponseWriter, r *http.Request) {
	if a.hub == nil {
		writeError(w, http.StatusServiceUnavailable, "hub_unavailable")
		return
	}

	user, _ := appUserFromCtx(r.Context())

	conn, err := a.hub.Upgrader().Upgrade(w, r, nil)
	if err != nil {
		slog.Warn("app_api: ошибка апгрейда websocket", "error", err)
		return
	}

	a.hub.RegisterWS(user.ID, conn)
	defer a.hub.UnregisterWS(user.ID, conn)

	// Цикл поддержания соединения и чтения клиентских ping/pong сообщений
	for {
		messageType, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
		if messageType == websocket.PingMessage {
			// Контрольный кадр пишем напрямую через WriteControl: это единственный
			// write-метод gorilla/websocket, разрешённый ДОКУМЕНТАЦИЕЙ для
			// конкурентного вызова параллельно с WriteMessage writer-горутины хаба
			// ("The Close and WriteControl methods can be called concurrently with
			// all other methods", gorilla/websocket@v1.5.3 doc.go, Concurrency).
			// WriteMessage здесь гонялся бы с рассылкой хаба и детонировал панику
			// "concurrent write to websocket connection" (conn.go).
			_ = conn.WriteControl(websocket.PongMessage, nil, time.Now().Add(3*time.Second))
		}
	}
}

// handleSSE организует поток Server-Sent Events для легких клиентов без WebSocket.
func (a *AppAPI) handleSSE(w http.ResponseWriter, r *http.Request) {
	if a.hub == nil {
		writeError(w, http.StatusServiceUnavailable, "hub_unavailable")
		return
	}

	user, _ := appUserFromCtx(r.Context())

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming_unsupported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// Access-Control-Allow-Origin намеренно не ставится (аудит 2026-09-11):
	// поток аутентифицирован Bearer-токеном устройства и доставляет
	// push-челленджи — открытый CORS позволял бы чужим origin'ам
	// подключаться с токеном, выуженным из логов/истории (запросы из
	// браузера и так ходят с того же origin или нативных клиентов).

	ch := a.hub.RegisterSSE(user.ID)
	defer a.hub.UnregisterSSE(user.ID, ch)

	// Отправляем начальное подтверждение
	fmt.Fprintf(w, "event: connected\ndata: {\"status\":\"connected\"}\n\n")
	flusher.Flush()

	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case data, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "event: prompt\ndata: %s\n\n", string(data))
			flusher.Flush()
		case <-ticker.C:
			// Heartbeat
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		}
	}
}

type supportRequestPayload struct {
	Category       string `json:"category"`        // "it" | "1c"
	ProblemSummary string `json:"problem_summary"` // обязательное описание проблемы
	AccessMode     string `json:"access_mode"`     // "full_control" | "view_only"
}

// handleSupportRequest обрабатывает отправку экстренного SOS-запроса от пользователя.
func (a *AppAPI) handleSupportRequest(w http.ResponseWriter, r *http.Request) {
	device, _ := appDeviceFromCtx(r.Context())
	user, _ := appUserFromCtx(r.Context())

	var req supportRequestPayload
	if !decodeJSON(w, r, &req) {
		return
	}

	req.ProblemSummary = strings.TrimSpace(req.ProblemSummary)
	if req.ProblemSummary == "" || len([]rune(req.ProblemSummary)) < 3 {
		writeError(w, http.StatusBadRequest, "empty_problem_summary")
		return
	}

	req.Category = strings.ToLower(strings.TrimSpace(req.Category))
	if req.Category != "1c" {
		req.Category = "it"
	}

	req.AccessMode = strings.ToLower(strings.TrimSpace(req.AccessMode))
	if req.AccessMode != "view_only" {
		req.AccessMode = "full_control"
	}

	// Одна живая сессия на пользователя (жёсткая последовательность
	// обращений): идёт активный сеанс (уже подтверждён пользователем) —
	// новое обращение не создаётся; «висящее» обращение (никто не
	// подключился) — заменяется, старое отменяется владельцем.
	if old, err := a.st.SupportSessionActiveByUser(r.Context(), user.ID); err == nil && old != nil {
		switch old.Status {
		case "approved", "active", "transferred":
			writeError(w, http.StatusConflict, "session_already_active")
			return
		default:
			// Юзер перезаписывает собственное незакрытое обращение.
			if err := a.st.SupportSessionEnd(r.Context(), old.ID, "cancelled", store.SupportActorUser); err != nil && !errors.Is(err, store.ErrInvalidTransition) {
				slog.Error("app_api: отмена предыдущей support_session", "error", err)
			}
		}
	}

	ss := &store.SupportSession{
		UserID:         user.ID,
		DeviceID:       device.ID,
		Category:       req.Category,
		Status:         "requested",
		ProblemSummary: req.ProblemSummary,
		AccessMode:     req.AccessMode,
		Metadata: map[string]any{
			"ip":               clientIP(r),
			"platform":         device.Platform,
			"os_version":       device.OSVersion,
			"device_name":      device.DeviceName,
			"security_posture": device.SecurityPosture,
		},
	}

	if err := a.st.SupportSessionCreate(r.Context(), ss); err != nil {
		if errors.Is(err, store.ErrDuplicateSession) {
			// Гонка двух обращений: параллельный запрос уже открыл сессию.
			writeError(w, http.StatusConflict, "session_already_active")
			return
		}
		slog.Error("app_api: ошибка создания support_session", "error", err)
		writeError(w, http.StatusInternalServerError, "db_error")
		return
	}

	ss.Username = user.Username
	ss.DisplayName = user.DisplayName
	ss.DeviceName = device.DeviceName
	ss.Platform = device.Platform
	ss.LastIP = clientIP(r)

	// Многоканальное оповещение инженеров (Email / Telegram / Web / WebSocket)
	if a.notifier != nil {
		a.notifier.NotifyNewSession(r.Context(), ss, user, device)
	}
	if a.hub != nil {
		if engineers, err := a.st.UserIDsBySupportRole(r.Context(), ss.Category); err == nil && len(engineers) > 0 {
			a.hub.BroadcastSupportRequest(engineers, ss)
		}
	}

	a.audit(r.Context(), user.Username, "support_requested", map[string]any{
		"session_id": ss.ID.String(),
		"category":   ss.Category,
		"summary":    ss.ProblemSummary,
	}, clientIP(r), "ok")

	writeJSON(w, http.StatusOK, ss)
}

// handleSupportCurrent возвращает текущую активную сессию пользователя.
func (a *AppAPI) handleSupportCurrent(w http.ResponseWriter, r *http.Request) {
	user, _ := appUserFromCtx(r.Context())

	// Ленивая автоматика TTL: «вечных» сессий не бывает.
	a.sweepStaleSupport(r.Context())

	ss, err := a.st.SupportSessionActiveByUser(r.Context(), user.ID)
	if errors.Is(err, store.ErrNotFound) || ss == nil {
		writeJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db_error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"active":  true,
		"session": ss,
	})
}

// handleSupportDecision принимает решение пользователя (approve / deny) по запросу на подключение.
func (a *AppAPI) handleSupportDecision(w http.ResponseWriter, r *http.Request) {
	user, _ := appUserFromCtx(r.Context())

	idStr := chi.URLParam(r, "id")
	sessID, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_id")
		return
	}

	var req struct {
		Decision    string `json:"decision"` // approve | deny
		NumberMatch string `json:"number_match,omitempty"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Decision = strings.ToLower(strings.TrimSpace(req.Decision))

	ss, err := a.st.SupportSessionGet(r.Context(), sessID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "session_not_found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db_error")
		return
	}

	if ss.UserID != user.ID {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	ip := clientIP(r)

	if req.Decision == "approve" {
		// ГЛАВНЫЙ ИНВАРИАНТ: active возможен только решением владельца с
		// совпавшим number-match. Подключение оператора (connect) уже
		// произошло: код сгенерирован; пустой код = аномалия = approve
		// запрещён (обход number-match исключён на корню).
		switch ss.Status {
		case "requested", "connecting":
		default:
			writeError(w, http.StatusConflict, "invalid_transition")
			return
		}
		if ss.NumberMatch == "" {
			// Оператор не подключался (код не сгенерирован) — подтверждать
			// нечего: и запрошенный, и «пустой» код отвергаются.
			a.audit(r.Context(), user.Username, "support_decision_no_operator", map[string]any{
				"session_id": ss.ID.String(),
				"status":     ss.Status,
			}, ip, "fail")
			writeError(w, http.StatusConflict, "no_operator_connected")
			return
		}

		// Проверка 2FA Number Matching: код обязателен и одноразов;
		// после supportMaxNMAttempts несовпадений сессия гасится.
		if strings.TrimSpace(req.NumberMatch) != ss.NumberMatch {
			attempts, _ := a.st.SupportSessionFailNumberMatch(r.Context(), ss.ID)
			a.audit(r.Context(), user.Username, "support_decision_mismatch", map[string]any{
				"session_id": ss.ID.String(),
				"attempts":   attempts,
			}, ip, "fail")
			if attempts >= store.SupportMaxNMAttempts {
				writeError(w, http.StatusConflict, "invalid_transition")
				return
			}
			writeError(w, http.StatusBadRequest, "number_match_mismatch")
			return
		}

		if err := a.st.SupportSessionApprove(r.Context(), ss.ID); err != nil {
			// Гонка статусов (сессия уже завершена/истекла) или повторный
			// approve — нарушение последовательности.
			a.audit(r.Context(), user.Username, "support_decision_approve_failed", map[string]any{
				"session_id": ss.ID.String(),
				"error":      err.Error(),
			}, ip, "fail")
			writeError(w, http.StatusConflict, "invalid_transition")
			return
		}
		if a.hub != nil {
			a.hub.SendEventToAdmin(ss.ID, "session_approved", map[string]any{"user": user.Username})
		}

		a.audit(r.Context(), user.Username, "support_decision_approved", map[string]any{
			"session_id": ss.ID.String(),
		}, ip, "ok")
	} else {
		// Отклонение/прерывание владельцем: только живая сессия; после
		// терминального статуса действие невозможно (409).
		if err := a.st.SupportSessionEnd(r.Context(), ss.ID, "rejected", store.SupportActorUser); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeError(w, http.StatusNotFound, "session_not_found")
				return
			}
			writeError(w, http.StatusConflict, "invalid_transition")
			return
		}
		if a.hub != nil {
			a.hub.SendEventToAdmin(ss.ID, "session_rejected", map[string]any{"user": user.Username})
		}

		a.audit(r.Context(), user.Username, "support_decision_denied", map[string]any{
			"session_id": ss.ID.String(),
		}, ip, "ok")
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleSupportSignal транслирует сигнальные сообщения WebRTC от клиента в браузер оператора.
// Проверяется владение сессией и живое состояние (аудит раунд-2, IDOR:
// раньше сигнал/чат можно было слать в ЛЮБУЮ сессию по UUID).
func (a *AppAPI) handleSupportSignal(w http.ResponseWriter, r *http.Request) {
	user, _ := appUserFromCtx(r.Context())

	idStr := chi.URLParam(r, "id")
	sessID, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_id")
		return
	}

	ss, err := a.st.SupportSessionGet(r.Context(), sessID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "session_not_found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db_error")
		return
	}
	if user == nil || ss.UserID != user.ID {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	switch ss.Status {
	case "requested", "connecting", "active", "transferred":
	default:
		writeError(w, http.StatusConflict, "invalid_session_state")
		return
	}

	var signal map[string]any
	if !decodeJSON(w, r, &signal) {
		return
	}

	// Если это сообщение чата, сохраняем в БД и рассылаем через хаб
	if signal["type"] == "chat_message" {
		text, _ := signal["text"].(string)
		senderName, _ := signal["sender_name"].(string)
		if strings.TrimSpace(text) != "" {
			if senderName == "" && user != nil {
				senderName = user.DisplayName
				if senderName == "" {
					senderName = user.Username
				}
			}
			msg := &store.SupportMessage{
				SessionID:  sessID,
				Sender:     "user",
				SenderName: senderName,
				Text:       strings.TrimSpace(text),
			}
			_ = a.st.SupportMessageCreate(r.Context(), msg)
			if a.hub != nil {
				a.hub.SendSupportChatMessage(sessID, user.ID, msg)
			}
			writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "message": msg})
			return
		}
	}

	if a.hub != nil {
		a.hub.SendSignalToAdmin(sessID, signal)
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleSupportMessagesGet возвращает историю сообщений чата сессии поддержки.
func (a *AppAPI) handleSupportMessagesGet(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	sessID, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_id")
		return
	}

	user, _ := appUserFromCtx(r.Context())
	ss, err := a.st.SupportSessionGet(r.Context(), sessID)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	if user == nil || (ss.UserID != user.ID && !user.IsSupportAny()) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	msgs, err := a.st.SupportMessagesList(r.Context(), sessID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db_error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"messages": msgs,
	})
}

// handleSupportMessageSend отправляет новое сообщение в чат сессии.
func (a *AppAPI) handleSupportMessageSend(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	sessID, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_id")
		return
	}

	user, _ := appUserFromCtx(r.Context())
	ss, err := a.st.SupportSessionGet(r.Context(), sessID)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	if user == nil || (ss.UserID != user.ID && !user.IsSupportAny()) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	var req struct {
		Text       string `json:"text"`
		SenderName string `json:"sender_name"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	req.Text = strings.TrimSpace(req.Text)
	if req.Text == "" {
		writeError(w, http.StatusBadRequest, "empty_text")
		return
	}

	sender := "user"
	if ss.UserID != user.ID && user.IsSupportAny() {
		sender = "operator"
	}
	senderName := strings.TrimSpace(req.SenderName)
	if senderName == "" {
		senderName = user.DisplayName
		if senderName == "" {
			senderName = user.Username
		}
	}

	msg := &store.SupportMessage{
		SessionID:  sessID,
		Sender:     sender,
		SenderName: senderName,
		Text:       req.Text,
	}

	if err := a.st.SupportMessageCreate(r.Context(), msg); err != nil {
		slog.Error("app_api: ошибка сохранения сообщения чата", "error", err)
		writeError(w, http.StatusInternalServerError, "db_error")
		return
	}

	if a.hub != nil {
		a.hub.SendSupportChatMessage(sessID, ss.UserID, msg)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"message": msg,
	})
}

// handleSupportEnd завершает активный сеанс удаленного доступа по инициативе пользователя.
// Владение сессией проверяется как в decision (аудит раунд-2, IDOR).
func (a *AppAPI) handleSupportEnd(w http.ResponseWriter, r *http.Request) {
	user, _ := appUserFromCtx(r.Context())

	idStr := chi.URLParam(r, "id")
	sessID, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_id")
		return
	}

	ss, err := a.st.SupportSessionGet(r.Context(), sessID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "session_not_found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db_error")
		return
	}
	if user == nil || ss.UserID != user.ID {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	if err := a.st.SupportSessionEnd(r.Context(), sessID, "completed", store.SupportActorUser); err != nil {
		// Повторное завершение терминальной сессии невозможно —
		// последовательность действий на обращение строго одна.
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "session_not_found")
			return
		}
		writeError(w, http.StatusConflict, "invalid_transition")
		return
	}
	if a.hub != nil {
		a.hub.SendEventToAdmin(sessID, "session_ended", map[string]any{"by": "user"})
	}

	a.audit(r.Context(), user.Username, "support_session_ended_by_user", map[string]any{
		"session_id": sessID.String(),
	}, clientIP(r), "ok")

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleSupportCategories возвращает список активных категорий SOS-поддержки.
func (a *AppAPI) handleSupportCategories(w http.ResponseWriter, r *http.Request) {
	snap := a.set.Get()
	if snap == nil || !snap.Support.Enabled {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	writeJSON(w, http.StatusOK, snap.Support.Categories)
}

// handleSupportQueue возвращает очередь вызовов SOS для инженеров поддержки.
func (a *AppAPI) handleSupportQueue(w http.ResponseWriter, r *http.Request) {
	user, _ := appUserFromCtx(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	isAdmin := strings.EqualFold(user.Role, "admin")
	if !isAdmin && len(user.SupportRoles) == 0 {
		writeError(w, http.StatusForbidden, "not_support_engineer")
		return
	}

	// Ленивая автоматика TTL: просроченные сессии уходят из очереди.
	a.sweepStaleSupport(r.Context())

	var sessions []store.SupportSession
	var err error
	if isAdmin {
		sessions, err = a.st.SupportSessionList(r.Context(), store.SupportFilter{
			ActiveOnly: true,
			Limit:      50,
		})
	} else {
		sessions, err = a.st.SupportSessionList(r.Context(), store.SupportFilter{
			Categories: user.SupportRoles,
			ActiveOnly: true,
			Limit:      50,
		})
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db_error")
		return
	}
	if sessions == nil {
		sessions = []store.SupportSession{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"queue":    sessions,
		"sessions": sessions,
	})
}

// handleSupportConnect инициирует подключение инженера к сессии из приложения.
func (a *AppAPI) handleSupportConnect(w http.ResponseWriter, r *http.Request) {
	user, _ := appUserFromCtx(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	isAdmin := strings.EqualFold(user.Role, "admin")
	if !isAdmin && len(user.SupportRoles) == 0 {
		writeError(w, http.StatusForbidden, "not_support_engineer")
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_id")
		return
	}

	session, err := a.st.SupportSessionGet(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db_error")
		return
	}

	// Проверяем соответствие категории
	if !isAdmin {
		matched := false
		for _, r := range user.SupportRoles {
			if strings.EqualFold(r, session.Category) {
				matched = true
				break
			}
		}
		if !matched {
			writeError(w, http.StatusForbidden, "category_forbidden")
			return
		}
	}

	adminName := user.DisplayName
	if adminName == "" {
		adminName = user.Username
	}

	// Number Matching: код генерируется ЗАНОВО на каждый connect (аудит
	// раунд-2, находка A): переиспользование подсмотренного кода и
	// «вечная» пара цифр исключены.
	nBig, err := rand.Int(rand.Reader, big.NewInt(90))
	num := 42
	if err == nil {
		num = int(nBig.Int64()) + 10
	}
	numberMatch := fmt.Sprintf("%02d", num)
	session.NumberMatch = numberMatch

	// Переход через серверную таблицу состояний: подключение возможно
	// только к живой requested/connecting-сессии; чужую (уже занятую
	// другим оператором), завершённую или просроченную подключить нельзя.
	actor := store.SupportActorOperator
	if isAdmin {
		actor = store.SupportActorAdmin
	}
	if err := a.st.SupportSessionConnect(r.Context(), session.ID, actor, &user.ID, numberMatch); err != nil {
		switch {
		case errors.Is(err, store.ErrSessionTaken):
			writeError(w, http.StatusConflict, "session_taken")
		case errors.Is(err, store.ErrInvalidTransition):
			writeError(w, http.StatusConflict, "invalid_transition")
		case errors.Is(err, store.ErrNotFound):
			writeError(w, http.StatusNotFound, "not_found")
		default:
			slog.Error("app_api: ошибка обновления статуса сессии", "error", err)
			writeError(w, http.StatusInternalServerError, "db_error")
		}
		return
	}

	// Отправляем push-запрос на экран пользователя
	if a.hub != nil {
		a.hub.SendSupportPrompt(session.UserID, &delivery.SupportPushPrompt{
			Type:           "support_prompt",
			SessionID:      session.ID,
			AdminName:      adminName,
			Category:       session.Category,
			NumberMatch:    numberMatch,
			AccessMode:     session.AccessMode,
			ProblemSummary: session.ProblemSummary,
			Timestamp:      time.Now(),
		})
	}

	a.audit(r.Context(), user.Username, "support_app_connect", map[string]any{
		"session_id":   session.ID.String(),
		"user_id":      session.UserID.String(),
		"number_match": numberMatch,
	}, clientIP(r), "ok")

	writeJSON(w, http.StatusOK, map[string]any{
		"status":       "prompt_sent",
		"session_id":   session.ID,
		"number_match": numberMatch,
		"session":      session,
	})
}
