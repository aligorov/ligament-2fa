// Package api: REST API, WebSocket и SSE для мобильных и десктопных приложений (Windows, Android, iOS).
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
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

// AppAPI предоставляет API для клиентских приложений Ligament Authenticator.
type AppAPI struct {
	core *auth.Core
	st   *store.Store
	pv   auth.PasswordVerifier
	set  *settings.M
	hub  *delivery.AppHub
	oidc *oidc.Manager
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
	}
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
			r.Post("/challenges/{id}/decision", a.handleChallengeDecision)

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

type appLoginRequest struct {
	Username        string         `json:"username"`
	Password        string         `json:"password"`
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
	ID          uuid.UUID `json:"id"`
	Username    string    `json:"username"`
	DisplayName string    `json:"display_name"`
	Role        string    `json:"role"`
}

// handleLogin — авторизация устройства в приложении.
func (a *AppAPI) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req appLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "empty_credentials")
		return
	}
	ip := clientIP(r)

	// Проверка первого фактора (пароля) через PasswordVerifier
	if _, err := a.pv.Verify(r.Context(), req.Username, req.Password); err != nil {
		a.audit(r.Context(), req.Username, "app_login_fail",
			map[string]any{"reason": "bad_credentials", "platform": req.Platform, "device": req.DeviceName}, ip, "fail")
		writeError(w, http.StatusUnauthorized, "invalid_credentials")
		return
	}

	user, err := a.st.UserByUsername(r.Context(), req.Username)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_credentials")
		return
	}
	if !user.Enabled {
		writeError(w, http.StatusForbidden, "user_disabled")
		return
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
			ID:          user.ID,
			Username:    user.Username,
			DisplayName: user.DisplayName,
			Role:        user.Role,
		},
		Posture: req.SecurityPosture,
	})
}

// authMiddleware проверяет Bearer токен клиентского приложения.
func (a *AppAPI) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		var tokenStr string
		if strings.HasPrefix(authHeader, "Bearer ") {
			tokenStr = strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		} else if qToken := r.URL.Query().Get("token"); qToken != "" {
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json")
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json")
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json")
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
				a.audit(r.Context(), user.Username, "app_push_number_mismatch",
					map[string]any{"challenge_id": ch.ID.String(), "entered": req.NumberMatch}, ip, "fail")
				writeError(w, http.StatusBadRequest, "number_match_mismatch")
				return
			}
		}

		if err := a.st.ChallengeSetPush(r.Context(), ch.ID, "approved"); err != nil {
			writeError(w, http.StatusInternalServerError, "db_error")
			return
		}

		a.audit(r.Context(), user.Username, "app_push_decision",
			map[string]any{
				"challenge_id": ch.ID.String(),
				"decision":     "approve",
				"device_id":    device.ID.String(),
				"device_name":  device.DeviceName,
			}, ip, "ok")
	} else {
		// Отклонение запроса
		_ = a.st.ChallengeSetPush(r.Context(), ch.ID, "denied")
		_ = a.st.ChallengeMarkUsed(r.Context(), ch.ID)

		a.audit(r.Context(), user.Username, "app_push_decision",
			map[string]any{
				"challenge_id": ch.ID.String(),
				"decision":     "deny",
				"device_id":    device.ID.String(),
			}, ip, "ok")
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

// handleHistory возвращает недавний аудит-лог входов пользователя.
func (a *AppAPI) handleHistory(w http.ResponseWriter, r *http.Request) {
	user, _ := appUserFromCtx(r.Context())

	list, err := a.st.AuditList(r.Context(), store.AuditFilter{
		Username: user.Username,
		Limit:    50,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db_error")
		return
	}

	type historyItem struct {
		ID        int64          `json:"id"`
		Timestamp time.Time      `json:"timestamp"`
		Event     string         `json:"event"`
		Result    string         `json:"result"`
		IP        string         `json:"ip"`
		Detail    map[string]any `json:"detail"`
	}

	out := make([]historyItem, 0, len(list))
	for _, it := range list {
		out = append(out, historyItem{
			ID:        it.ID,
			Timestamp: it.Ts,
			Event:     it.Event,
			Result:    it.Result,
			IP:        it.SrcIP,
			Detail:    it.Detail,
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
			_ = conn.WriteMessage(websocket.PongMessage, nil)
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
	w.Header().Set("Access-Control-Allow-Origin", "*")

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
