// Публичный REST API (спека §3.2/§7): двухшаговый флоу start/verify,
// комбинированный вход «пароль+код», poll статуса push-челленджей и
// WebAuthn-церемония входа. Все ответы — JSON с Content-Type; коды и
// секреты в ответах не раскрываются (username/challenge_id/channel только).
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/aligorov/twofa/internal/auth"
	"github.com/aligorov/twofa/internal/channel"
	"github.com/aligorov/twofa/internal/firewall"
	"github.com/aligorov/twofa/internal/secrets"
	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
	"github.com/aligorov/twofa/internal/webauthn"
)

// purposeAPI — purpose челленджей, выданных публичным API (см. схему
// challenges: api|radius_prefetch|ui_confirm|webauthn_session|tg_link).
const purposeAPI = "api"

// maxBodyBytes — потолок тела запроса публичного API.
const maxBodyBytes = 1 << 20

// PublicAPI — зависимости и маршруты /api/v1/auth/*.
type PublicAPI struct {
	core *auth.Core
	wa   *webauthn.Svc // nil — webauthn не сконфигурирован (503)
	st   *store.Store
	pv   auth.PasswordVerifier
	m    *settings.M
	rl   *limiterMap
}

// NewPublicAPI собирает публичный API. wa может быть nil — webauthn-роуты
// тогда отвечают 503; pv — проверка первого фактора (тот же верификатор,
// что в ядре). Ресурсы освобождаются Stop.
func NewPublicAPI(core *auth.Core, wa *webauthn.Svc, st *store.Store, pv auth.PasswordVerifier, m *settings.M) *PublicAPI {
	return &PublicAPI{core: core, wa: wa, st: st, pv: pv, m: m, rl: newLimiterMap()}
}

// Stop останавливает фоновую очистку rate-limiter.
func (p *PublicAPI) Stop() { p.rl.Stop() }

// Register монтирует маршруты публичного API в chi-роутер.
func (p *PublicAPI) Register(r chi.Router) {
	r.Route("/api/v1/auth", func(r chi.Router) {
		r.Post("/start", p.handleStart)
		r.Post("/verify", p.handleVerify)
		r.Post("/combined", p.handleCombined)
		r.Post("/poll", p.handlePoll)
		r.Post("/webauthn/begin", p.handleWABegin)
		r.Post("/webauthn/finish", p.handleWAFinish)
	})
}

// ---- общие помощники ----

// writeJSON — JSON-ответ с корректным Content-Type.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError — JSON-ответ-ошибка {"error": code} без внутренних деталей.
func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

// clientIP — хост RemoteAddr. Заголовки прокси (X-Forwarded-For)
// сознательно не учитываются: подделка заголовка обходила бы ip-корзину
// rate-limiter; доверенный прокси появится вместе с его конфигурацией.
func clientIP(r *http.Request) string {
	// Middleware файрвола кладёт сюда реальный IP (RemoteAddr или
	// X-Forwarded-For за доверенным прокси) — он приоритетнее сокета.
	if ip := firewall.IPFrom(r.Context()); ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// decodeJSON разбирает JSON-тело с потолком размера; при ошибке сам
// отвечает 400 и возвращает false.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return false
	}
	if err := json.Unmarshal(body, v); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return false
	}
	return true
}

// audit пишет событие публичного API (result ok/fail, src_ip); ошибка
// записи логируется и проглатывается — аудит не ломает ответ клиенту.
func (p *PublicAPI) audit(ctx context.Context, username, event, ip, result string, detail map[string]any) {
	if err := p.st.Audit(ctx, username, event, detail, ip, result); err != nil {
		slog.Warn("api: аудит не записан", "event", event, "error", err)
	}
}

// ---- POST /api/v1/auth/start ----

type startReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// handleStart — первый шаг: проверка пароля и выдача челленджа по
// предпочтительному каналу. Rate-limit по двум независимым корзинам
// (username и IP); ErrCooldown → 429 с retry_after из policy.
func (p *PublicAPI) handleStart(w http.ResponseWriter, r *http.Request) {
	var req startReq
	if !decodeJSON(w, r, &req) {
		return
	}
	ctx := r.Context()
	ip := clientIP(r)

	if !p.rl.Allow("u:"+req.Username) || !p.rl.Allow("ip:"+ip) {
		w.Header().Set("Retry-After", strconv.Itoa(rlRetryAfterSec))
		writeJSON(w, http.StatusTooManyRequests,
			map[string]any{"error": "rate_limited", "retry_after": rlRetryAfterSec})
		return
	}

	user, err := p.pv.Verify(ctx, req.Username, req.Password)
	if errors.Is(err, auth.ErrBadCredentials) || errors.Is(err, store.ErrNotFound) {
		// Единый 401: «нет пользователя» и «неверный пароль» неотличимы.
		p.audit(ctx, req.Username, "api_start", ip, "fail",
			map[string]any{"reason": "bad_credentials"})
		// login_fail кормит единый fail-счётчик (FailLocked): без него
		// брут по /auth/start обходил бы блокировку (api_start не считается).
		p.audit(ctx, req.Username, "login_fail", ip, "fail",
			map[string]any{"reason": "bad_credentials", "via": "api_start"})
		writeError(w, http.StatusUnauthorized, "bad_credentials")
		return
	}
	if err != nil {
		slog.Error("api: start verify", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	if p.core.FailLocked(ctx, user.ID) {
		p.audit(ctx, user.Username, "api_start", ip, "fail",
			map[string]any{"reason": "locked"})
		writeError(w, http.StatusLocked, "locked")
		return
	}

	ch, err := p.core.StartWithMeta(ctx, user, purposeAPI, ip, r.UserAgent())
	switch {
	case err == nil:
	case errors.Is(err, auth.ErrNoChannel):
		p.audit(ctx, user.Username, "api_start", ip, "fail",
			map[string]any{"reason": "no_channel"})
		writeError(w, http.StatusConflict, "no_channel")
		return
	case errors.Is(err, auth.ErrCooldown):
		// retry_after — округлённый вверх policy.resend_cooldown в секундах.
		retry := int((p.m.Get().Policy.ResendCooldown + time.Second - 1) / time.Second)
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		writeJSON(w, http.StatusTooManyRequests,
			map[string]any{"error": "cooldown", "retry_after": retry})
		return
	default:
		slog.Error("api: start", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}

	p.audit(ctx, user.Username, "api_start", ip, "ok",
		map[string]any{"channel": string(ch.Channel), "challenge_id": ch.ID.String()})
	writeJSON(w, http.StatusOK, map[string]any{
		"challenge_id": ch.ID.String(),
		"channel":      string(ch.Channel),
		"expires_in":   int(time.Until(ch.ExpiresAt).Seconds()),
	})
}

// ---- POST /api/v1/auth/verify ----

type verifyReq struct {
	ChallengeID string `json:"challenge_id"`
	Code        string `json:"code"`
}

// handleVerify — второй шаг: код конкретного челленджа. Неверный код →
// 401 с остатком попыток; закрытый (использован/просрочен/попытки
// исчерпаны) → 410.
func (p *PublicAPI) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req verifyReq
	if !decodeJSON(w, r, &req) {
		return
	}
	id, err := uuid.Parse(req.ChallengeID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	ctx := r.Context()
	ip := clientIP(r)

	ch, err := p.st.ChallengeGet(ctx, id)
	if err != nil {
		// Неизвестный ID неотличим от удалённого janitor'ом просроченного
		// челленджа — единый 410 без раскрытия причин.
		writeError(w, http.StatusGone, "expired")
		return
	}
	user, err := p.st.UserByID(ctx, ch.UserID)
	if err != nil {
		slog.Error("api: verify user", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}

	// Закрытый челлендж отсеиваем до ядра: VerifyChallengeCode вернул бы
	// тот же ErrChallengeClosed, но без расхода попыток и аудита.
	if ch.UsedAt != nil || !time.Now().Before(ch.ExpiresAt) || ch.AttemptsLeft <= 0 {
		p.audit(ctx, user.Username, "api_verify_fail", ip, "fail",
			map[string]any{"reason": "expired", "challenge_id": ch.ID.String()})
		writeError(w, http.StatusGone, "expired")
		return
	}

	ok, err := p.core.VerifyChallengeCode(ctx, ch, req.Code)
	detail := map[string]any{"channel": string(ch.Channel), "challenge_id": ch.ID.String()}
	switch {
	case err == nil && ok:
		p.audit(ctx, user.Username, "api_verify_ok", ip, "ok", detail)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "username": user.Username})
	case errors.Is(err, auth.ErrChallengeClosed):
		p.audit(ctx, user.Username, "api_verify_fail", ip, "fail",
			map[string]any{"reason": "expired", "challenge_id": ch.ID.String()})
		writeError(w, http.StatusGone, "expired")
	case errors.Is(err, auth.ErrBadCode):
		// attempts_left после атомарного декремента — перечитываем строку.
		left := 0
		if fresh, gerr := p.st.ChallengeGet(ctx, ch.ID); gerr == nil {
			left = fresh.AttemptsLeft
		}
		p.audit(ctx, user.Username, "api_verify_fail", ip, "fail", detail)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "attempts_left": left})
	default:
		slog.Error("api: verify", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
	}
}

// ---- POST /api/v1/auth/combined ----

type combinedReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Code     string `json:"code"`
}

// handleCombined — вход одним вызовом «пароль + код» (код любой:
// доставленный, TOTP или резервный). Аудит login_ok/login_fail пишет
// ядро (VerifyPasswordAndCode) — по одной записи на попытку.
func (p *PublicAPI) handleCombined(w http.ResponseWriter, r *http.Request) {
	var req combinedReq
	if !decodeJSON(w, r, &req) {
		return
	}
	user, ok, err := p.core.VerifyPasswordAndCode(r.Context(), req.Username, req.Password, req.Code, auth.LoginCodePurposes...)
	switch {
	case err == nil && ok && user != nil:
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "username": user.Username})
	case errors.Is(err, auth.ErrLocked):
		writeError(w, http.StatusLocked, "locked")
	case err == nil:
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false})
	default:
		slog.Error("api: combined", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
	}
}

// ---- POST /api/v1/auth/poll ----

type pollReq struct {
	ChallengeID string `json:"challenge_id"`
}

// handlePoll — статус push-челленджа (клиент опрашивает, пока пользователь
// решает: «Подтвердить»/«Это не я» в Telegram).
func (p *PublicAPI) handlePoll(w http.ResponseWriter, r *http.Request) {
	var req pollReq
	if !decodeJSON(w, r, &req) {
		return
	}
	id, err := uuid.Parse(req.ChallengeID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	ch, err := p.st.ChallengeGet(r.Context(), id)
	if err != nil {
		// Удалённый janitor'ом просроченный челлендж — терминальный
		// «expired», а не 404: poll-циклу нужен статус, а не ошибка.
		writeJSON(w, http.StatusOK, map[string]string{"status": "expired"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": pollStatus(ch, time.Now())})
}

// pollStatus выводит статус челленджа: expired — просрочен, попытки
// исчерпаны либо код уже погашен (одноразовый claim); approved/denied —
// решение по push-кнопкам (использованный push остаётся «approved»:
// claim забрал успешный вход); остальное — pending.
func pollStatus(ch *store.Challenge, now time.Time) string {
	if !now.Before(ch.ExpiresAt) || ch.AttemptsLeft <= 0 {
		return "expired"
	}
	// Для push-каналов (telegram_push, app_push) решение пользователя
	// (approved/denied) имеет наивысший приоритет над флагом used_at.
	if (ch.Channel == channel.TelegramPush || ch.Channel == channel.AppPush) && ch.PushState != nil {
		switch *ch.PushState {
		case "approved", "denied":
			return *ch.PushState
		}
	}
	if ch.UsedAt != nil {
		return "expired"
	}
	return "pending"
}

// ---- POST /api/v1/auth/webauthn/begin ----

type waBeginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// handleWABegin — вход WebAuthn: проверка пароля (+FailLocked) и выдача
// PublicKeyCredentialRequestOptions с одноразовым handle сессии церемонии.
func (p *PublicAPI) handleWABegin(w http.ResponseWriter, r *http.Request) {
	if p.wa == nil {
		writeError(w, http.StatusServiceUnavailable, "webauthn_disabled")
		return
	}
	var req waBeginReq
	if !decodeJSON(w, r, &req) {
		return
	}
	ctx := r.Context()

	user, err := p.pv.Verify(ctx, req.Username, req.Password)
	if errors.Is(err, auth.ErrBadCredentials) || errors.Is(err, store.ErrNotFound) {
		// Путь раньше был тихим — теперь неудачный пароль кормит единый
		// fail-счётчик (login_fail), как и /auth/start.
		p.audit(ctx, req.Username, "login_fail", clientIP(r), "fail",
			map[string]any{"reason": "bad_credentials", "via": "webauthn_begin"})
		writeError(w, http.StatusUnauthorized, "bad_credentials")
		return
	}
	if err != nil {
		slog.Error("api: webauthn begin verify", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	if p.core.FailLocked(ctx, user.ID) {
		writeError(w, http.StatusLocked, "locked")
		return
	}

	opts, handle, err := p.wa.BeginLogin(ctx, user)
	if err != nil {
		// 409 — у пользователя нет зарегистрированных ключей (конфликт
		// состояния клиента и аккаунта); сверяемся с хранилищем, а не
		// строкой ошибки. Аудит церемоний пишет сам Svc.
		if creds, cerr := p.st.WACredListForUser(ctx, user.ID); cerr == nil && len(creds) == 0 {
			writeError(w, http.StatusConflict, "no_credentials")
			return
		}
		slog.Error("api: webauthn begin", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"handle": handle, "options": opts})
}

// ---- POST /api/v1/auth/webauthn/finish ----

// handleWAFinish — завершение WebAuthn-входа. Тело запроса — сырой
// PublicKeyCredential (его парсит go-webauthn по *http.Request), handle
// сессии — query-параметр ?handle= или поле "handle" того же JSON.
func (p *PublicAPI) handleWAFinish(w http.ResponseWriter, r *http.Request) {
	if p.wa == nil {
		writeError(w, http.StatusServiceUnavailable, "webauthn_disabled")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	handle := r.URL.Query().Get("handle")
	if handle == "" {
		var probe struct {
			Handle string `json:"handle"`
		}
		_ = json.Unmarshal(body, &probe)
		handle = probe.Handle
	}
	if handle == "" {
		writeError(w, http.StatusBadRequest, "handle_required")
		return
	}
	ctx := r.Context()

	user, err := p.waSessionUser(ctx, handle)
	if err != nil {
		// Сессия неизвестна/истекла/погашена — единый 401.
		writeError(w, http.StatusUnauthorized, "bad_credentials")
		return
	}

	// go-webauthn разбирает тело из *http.Request: пересобираем запрос с
	// тем же сырым телом, форвардинг Content-Type и User-Agent;
	// RemoteAddr — источник для аудита webauthn_login в Svc.
	freq, err := http.NewRequestWithContext(ctx, http.MethodPost, r.URL.Path, bytes.NewReader(body))
	if err != nil {
		slog.Error("api: webauthn finish request", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	freq.Header.Set("Content-Type", r.Header.Get("Content-Type"))
	freq.Header.Set("User-Agent", r.UserAgent())
	freq.RemoteAddr = r.RemoteAddr

	if err := p.wa.FinishLogin(ctx, user, handle, freq); err != nil {
		writeError(w, http.StatusUnauthorized, "bad_credentials")
		return
	}

	// Подпись проверена — церемония доказала второй фактор. Создаём
	// одноразовое «webauthn_web_pending»-окно: web-логин (login/2fa с
	// пустым кодом) погасит его атомарно ровно один раз. Отказ создания —
	// fail-closed 500: без окна пустой код не пройдёт, клиент повторит
	// вход обычным кодом.
	if err := createWebPendingChallenge(ctx, p.st, user.ID); err != nil {
		slog.Error("api: webauthn finish — pending-окно web-логина", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

// purposeWAPending — purpose challenges-строки, доказывающей «только что
// завершилась успешная WebAuthn-церемония входа»: создаётся handleWAFinish
// ПОСЛЕ проверки подписи passkey, атомарно погашается одним login/2fa
// (SessionAPI.consumeWebauthnPending). Заменяет прежний скан аудита
// webauthn_login (replay-окно без расхода).
const purposeWAPending = "webauthn_web_pending"

// waPendingTTL — срок жизни одноразового passkey-окна web-логина: у
// пользователя есть столько времени, чтобы обменять успешную церемонию
// на web-сессию.
const waPendingTTL = 5 * time.Minute

// createWebPendingChallenge отмечает успешную WebAuthn-церемонию входа:
// challenges-строка без кода (code_hash=nil, AttemptsLeft=1), живёт
// waPendingTTL и расходуется атомарным ChallengeMarkUsed — повторный
// claim и гонка двух параллельных login/2fa исключены.
func createWebPendingChallenge(ctx context.Context, st *store.Store, userID uuid.UUID) error {
	return st.ChallengeCreate(ctx, &store.Challenge{
		UserID:       userID,
		Channel:      channel.WebAuthn,
		ExpiresAt:    time.Now().Add(waPendingTTL),
		AttemptsLeft: 1,
		Purpose:      purposeWAPending,
	})
}

// waSessionUser резолвит владельца по handle сессии церемонии: сессия —
// challenges-строка purpose=webauthn_session с code_hash = SHA256(handle)
// (см. internal/webauthn saveSession). Одноразовый claim остаётся за
// Svc.FinishLogin — здесь только поиск пользователя.
func (p *PublicAPI) waSessionUser(ctx context.Context, handle string) (*store.User, error) {
	var userID uuid.UUID
	err := p.st.Pool().QueryRow(ctx,
		`SELECT user_id FROM challenges
		 WHERE purpose = 'webauthn_session' AND code_hash = $1 AND used_at IS NULL`,
		secrets.SHA256(handle)).Scan(&userID)
	if err != nil {
		return nil, err
	}
	return p.st.UserByID(ctx, userID)
}
