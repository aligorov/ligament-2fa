package auth

import (
	"context"
	"crypto/hmac"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/aligorov/twofa/internal/channel"
	"github.com/aligorov/twofa/internal/delivery"
	"github.com/aligorov/twofa/internal/firewall"
	"github.com/aligorov/twofa/internal/secrets"
	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
)

// pushTick — интервал опроса push-челленджа в удержании RADIUS-запроса.
const pushTick = time.Second

// pushGetRetries — допуск подряд ошибок чтения состояния push-челленджа
// в удержании (БД моргнула): после третьей ошибки подряд — Reject
// push_timeout.
const pushGetRetries = 3

// Core — ядро аутентификации: выдча челленджей по предпочтительным
// каналам, проверка кодов всех типов, fail-счётчик и RADIUS-флоу
// (сплиты «пароль+код», push_wait).
type Core struct {
	st  *store.Store
	set *settings.M
	box *secrets.Box
	fw  Firewall // nil — fail2ban выключен

	// senders/push меняются на лету (SetSenders после SIGHUP-перезагрузки
	// настроек доставки) под RWMutex — HTTP-хендлеры и RADIUS-цикл читают
	// их конкурентно.
	mu      sync.RWMutex
	senders map[channel.Channel]delivery.Sender
	pv      PasswordVerifier
	push    PushNotifier    // nil → канал telegram_push недоступен
	appPush AppPushNotifier // nil → канал app_push недоступен

	notifyMu   sync.Mutex
	lastNotify map[string]time.Time
}

// NewCore собирает ядро. senders — доставка кодов по каналам (email/sms/
// telegram; регистрация telegram-отправителя — T8); отсутствующий или
// непривязанный канал просто пропускается при выборе. pv — проверка
// первого фактора; push — Telegram-бот (может быть nil).
func NewCore(
	st *store.Store,
	set *settings.M,
	box *secrets.Box,
	senders map[channel.Channel]delivery.Sender,
	pv PasswordVerifier,
	push PushNotifier,
) *Core {
	c := &Core{
		st:         st,
		set:        set,
		box:        box,
		pv:         pv,
		lastNotify: make(map[string]time.Time),
	}
	c.SetSenders(senders, push)
	return c
}

// SetSenders атомарно подменяет карту отправителей и push-нотификатор
// (горячая перезагрузка настроек доставки — SIGHUP в main). Карта
// копируется: последующие мутации карты вызывающего не видны ядру.
func (c *Core) SetSenders(senders map[channel.Channel]delivery.Sender, push PushNotifier) {
	m := make(map[channel.Channel]delivery.Sender, len(senders))
	for k, v := range senders {
		m[k] = v
	}
	c.mu.Lock()
	c.senders = m
	c.push = push
	c.mu.Unlock()
}

// senderFor возвращает зарегистрированного отправителя канала (nil — нет).
func (c *Core) senderFor(ch channel.Channel) delivery.Sender {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.senders[ch]
}

// HasSender сообщает, зарегистрирован ли отправитель для данного канала.
func (c *Core) HasSender(ch channel.Channel) bool {
	return c.senderFor(ch) != nil
}

// pushNotifier возвращает текущий push-нотификатор (nil — недоступен).
func (c *Core) pushNotifier() PushNotifier {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.push
}

// SetAppPush регистрирует диспетчер мобильных и десктопных push-уведомлений.
func (c *Core) SetAppPush(ap AppPushNotifier) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.appPush = ap
}

// appPushNotifier возвращает диспетчер мобильных и десктопных push-уведомлений (nil — недоступен).
func (c *Core) appPushNotifier() AppPushNotifier {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.appPush
}

// audit записывает событие аудита, не ломая основной поток: ошибка записи
// логируется и проглатывается (аудит не должен блокировать аутентификацию).
func (c *Core) audit(ctx context.Context, username, event string, detail map[string]any, ip, result string) {
	if ip == "" {
		ip = firewall.IPFrom(ctx)
	}
	if cip, ok := ctx.Value(CtxKeyClientIP).(string); ok && cip != "" && (ip == "" || ip == "127.0.0.1") {
		ip = cip
	}
	if err := c.st.Audit(ctx, username, event, detail, ip, result); err != nil {
		slog.Warn("auth: аудит не записан", "event", event, "error", err)
	}
	// fail2ban: каждая неудача входа/кода (HTTP) считается по IP.
	// radius_fail сознательно НЕ кормит IP-счётчик: IP источника RADIUS —
	// адрес маршрутизатора (NAS), за NAT неуспехи всех пользователей
	// вылились бы в самобан NAS и 30-минутный отказ Wi-Fi/VPN всем
	// сразу (аудит 2026-09-11). Брут по RADIUS ограничивает per-user
	// fail-счётчик (FailLocked + radius.max_fail_per_user по audit_log);
	// событие radius_fail продолжает писаться в аудит.
	if result == "fail" && c.fw != nil {
		switch event {
		case "login_fail", "code_fail":
			if ip != "" {
				c.fw.Fail(ctx, ip, event)
			}
		}
	}
}

// Firewall — узкое окно в firewall.Guard (интерфейс — без цикла импортов).
type Firewall interface {
	Fail(ctx context.Context, ip, reason string)
}

// SetFirewall подключает fail2ban-guard (вызов из main; nil — выключено).
func (c *Core) SetFirewall(f Firewall) { c.fw = f }

func ptrString(s string) *string { return &s }

// urlInErrorRE — http(s)-URL в тексте ошибки доставки (токен бота, креды
// SMS-шлюза и текст сообщения не должны попадать в audit_log).
var urlInErrorRE = regexp.MustCompile(`https?://[^\s"']+`)

// redactErrText вырезает http(s)-URL'ы из текста ошибки для деталей аудита
// (SEC-003): отправители уже санитизируют свои транспортные ошибки, здесь —
// эшелонированная защита от любых вложенных ошибок с адресом.
func redactErrText(err error) string {
	if err == nil {
		return ""
	}
	return urlInErrorRE.ReplaceAllString(err.Error(), "[url]")
}

// binding возвращает отправителя и адрес получателя для кодового канала,
// если канал привязан у пользователя и отправитель зарегистрирован.
func (c *Core) binding(ch channel.Channel, user *store.User) (delivery.Sender, string, bool) {
	var to string
	switch ch {
	case channel.Email:
		to = user.Email
	case channel.SMS:
		to = user.Phone
	case channel.Telegram:
		if user.TelegramChatID == nil {
			return nil, "", false
		}
		to = fmt.Sprintf("%d", *user.TelegramChatID)
	default:
		return nil, "", false
	}
	if to == "" {
		return nil, "", false
	}
	sender := c.senderFor(ch)
	if sender == nil {
		return nil, "", false
	}
	return sender, to, true
}

// Start выдаёт челлендж по первому доступному каналу из prefer_channels
// пользователя (fallback — policy.default_prefer): TOTP (без кода, метка
// сессии-челленджа), email/sms/telegram (генерация кода, отправка,
// SHA-256-хеш в БД) или telegram_push (pending + SendPush). Каналы без
// привязки/отправителя пропускаются; ни одного → ErrNoChannel. Канал в
// состоянии cooldown (resend_cooldown у кодового, push_cooldown /
// push_per_hour у push) → ErrCooldown.
func (c *Core) Start(ctx context.Context, user *store.User, purpose string) (*store.Challenge, error) {
	return c.StartWithMeta(ctx, user, purpose, "", "")
}

// StartWithMeta — Start с метаданными запроса (IP, User-Agent): они
// передаются в push-сообщение для режима approve.
func (c *Core) StartWithMeta(ctx context.Context, user *store.User, purpose, ip, ua string) (*store.Challenge, error) {
	return c.StartWithService(ctx, user, purpose, ip, ua, "", "", "", "", "")
}

// StartWithService — Start с расширенными метаданными контекста (сервис, хост, клиент, внутренние IP).
func (c *Core) StartWithService(ctx context.Context, user *store.User, purpose, ip, ua, service, host, client, clientIP, hostIP string) (*store.Challenge, error) {
	pol := c.set.Get().Policy
	prefer := user.PreferChannels
	if len(prefer) == 0 {
		if grpPrefer, err := c.st.UserEffectivePreferChannels(ctx, user); err == nil && len(grpPrefer) > 0 {
			prefer = grpPrefer
		} else {
			prefer = pol.DefaultPrefer
		}
	}

	// Динамическая маршрутизация: если у пользователя есть активные клиентские приложения,
	// приоритетно направляем push-запрос в приложение.
	if hasApp, err := c.st.AppDeviceHasActive(ctx, user.ID); err == nil && hasApp && c.appPushNotifier() != nil {
		hasCh := false
		for _, ch := range prefer {
			if ch == channel.AppPush {
				hasCh = true
				break
			}
		}
		if !hasCh {
			prefer = append([]channel.Channel{channel.AppPush}, prefer...)
		}
	}
	now := time.Now()

	if service == "" {
		if s, ok := ctx.Value(CtxKeyService).(string); ok && s != "" {
			service = s
		} else if strings.Contains(ua, "CredentialProvider") {
			if host != "" {
				service = "Windows RDP (" + host + ")"
			} else {
				service = "Windows Вход / RDP"
			}
		} else if purpose == PurposeUIConfirm {
			service = "Личный кабинет (Подтверждение)"
		} else {
			service = "Корпоративный доступ"
		}
	}
	if host == "" {
		if h, ok := ctx.Value(CtxKeyHost).(string); ok && h != "" {
			host = h
		}
	}
	if client == "" {
		if cl, ok := ctx.Value(CtxKeyDevice).(string); ok && cl != "" {
			client = cl
		}
	}
	if clientIP == "" {
		if cip, ok := ctx.Value(CtxKeyClientIP).(string); ok && cip != "" {
			clientIP = cip
		}
	}
	if hostIP == "" {
		if hip, ok := ctx.Value(CtxKeyHostIP).(string); ok && hip != "" {
			hostIP = hip
		}
	}
	effectiveIP := ip
	if clientIP != "" && (ip == "" || ip == "127.0.0.1" || strings.HasPrefix(ip, "172.")) {
		effectiveIP = clientIP
	}

	for _, ch := range prefer {
		switch ch {
		case channel.TOTP:
			// TOTP-код генерируется приложением — челлендж без кода.
			_, _, _, confirmed, _, err := c.st.TOTPGet(ctx, user.ID)
			if err != nil || !confirmed {
				continue
			}
			c2 := &store.Challenge{
				UserID:       user.ID,
				Channel:      channel.TOTP,
				ExpiresAt:    now.Add(pol.CodeTTL),
				AttemptsLeft: pol.MaxAttempts,
				Purpose:      purpose,
			}
			if err := c.st.ChallengeCreate(ctx, c2); err != nil {
				return nil, err
			}
			return c2, nil

		case channel.Email, channel.SMS, channel.Telegram:
			sender, to, ok := c.binding(ch, user)
			if !ok {
				continue
			}
			// Cooldown: последний челлендж этого канала моложе ResendCooldown.
			var recent bool
			err := c.st.Pool().QueryRow(ctx,
				`SELECT EXISTS (SELECT 1 FROM challenges
				 WHERE user_id = $1 AND channel = $2 AND created_at > $3)`,
				user.ID, ch, now.Add(-pol.ResendCooldown)).Scan(&recent)
			if err != nil {
				return nil, fmt.Errorf("auth: cooldown-проверка %s: %w", ch, err)
			}
			if recent {
				return nil, ErrCooldown
			}
			code := secrets.GenDigits(pol.CodeLength)
			if err := sender.Send(ctx, to, code); err != nil {
				c.audit(ctx, user.Username, "code_sent",
					map[string]any{"channel": string(ch), "purpose": purpose, "service": service, "error": redactErrText(err)},
					effectiveIP, "fail")
				continue // канал недоступен — следующий в списке
			}
			c2 := &store.Challenge{
				UserID:       user.ID,
				Channel:      ch,
				CodeHash:     secrets.SHA256(code),
				ExpiresAt:    now.Add(pol.CodeTTL),
				AttemptsLeft: pol.MaxAttempts,
				Purpose:      purpose,
			}
			if err := c.st.ChallengeCreate(ctx, c2); err != nil {
				return nil, err
			}
			c.audit(ctx, user.Username, "code_sent",
				map[string]any{"channel": string(ch), "purpose": purpose, "service": service}, effectiveIP, "ok")
			return c2, nil

		case channel.TelegramPush:
			push := c.pushNotifier()
			if user.TelegramChatID == nil || push == nil {
				continue
			}
			// Push-fatigue: те же границы, что в RADIUSAuth — не чаще
			// push_cooldown и не более push_per_hour в час.
			if last, err := c.st.LastPushAt(ctx, user.ID); err != nil {
				return nil, fmt.Errorf("auth: push-cooldown проверка %s: %w", user.Username, err)
			} else if !last.IsZero() && time.Since(last) < pol.PushCooldown {
				return nil, ErrCooldown
			}
			if n, err := c.st.PushCountSince(ctx, user.ID, now.Add(-time.Hour)); err != nil {
				return nil, fmt.Errorf("auth: push-лимит проверка %s: %w", user.Username, err)
			} else if n >= pol.PushPerHour {
				return nil, ErrCooldown
			}
			meta := map[string]any{
				"ip":        effectiveIP,
				"client_ip": clientIP,
				"host_ip":   hostIP,
				"ua":        ua,
				"service":   service,
				"host":      host,
				"client":    client,
				"purpose":   purpose,
				"username":  user.Username,
			}
			c2 := &store.Challenge{
				UserID:       user.ID,
				Channel:      channel.TelegramPush,
				PushState:    ptrString("pending"),
				ExpiresAt:    now.Add(pol.CodeTTL),
				AttemptsLeft: 1,
				Purpose:      purpose,
				Metadata:     meta,
			}
			if err := c.st.ChallengeCreate(ctx, c2); err != nil {
				return nil, err
			}
			var pushErr error
			if pushSvc, ok := push.(PushNotifierWithService); ok {
				pushErr = pushSvc.SendPushWithService(ctx, *user.TelegramChatID, user.Username, effectiveIP, ua, service, hostIP, c2.ID)
			} else {
				pushErr = push.SendPush(ctx, *user.TelegramChatID, user.Username, effectiveIP, ua, c2.ID)
			}
			if pushErr != nil {
				// Осиротевший челлендж держал бы cooldown следующего
				// push — удаляем (WithoutCancel: доставка могла упасть
				// из-за отмены ctx).
				if _, derr := c.st.Pool().Exec(context.WithoutCancel(ctx),
					`DELETE FROM challenges WHERE id = $1`, c2.ID); derr != nil {
					slog.Warn("auth: удаление push-челленджа после ошибки доставки",
						"id", c2.ID, "error", derr)
				}
				c.audit(ctx, user.Username, "push_sent",
					map[string]any{"purpose": purpose, "service": service, "error": redactErrText(pushErr)}, effectiveIP, "fail")
				continue
			}
			c.audit(ctx, user.Username, "push_sent",
				map[string]any{"purpose": purpose, "service": service, "challenge_id": c2.ID.String()}, effectiveIP, "ok")
			return c2, nil

		case channel.AppPush:
			appPush := c.appPushNotifier()
			if appPush == nil {
				continue
			}
			hasApp, err := c.st.AppDeviceHasActive(ctx, user.ID)
			if err != nil || !hasApp {
				continue
			}
			if last, err := c.st.LastPushAt(ctx, user.ID); err != nil {
				return nil, fmt.Errorf("auth: app_push cooldown проверка %s: %w", user.Username, err)
			} else if !last.IsZero() && time.Since(last) < pol.PushCooldown {
				return nil, ErrCooldown
			}
			if n, err := c.st.PushCountSince(ctx, user.ID, now.Add(-time.Hour)); err != nil {
				return nil, fmt.Errorf("auth: app_push лимит проверка %s: %w", user.Username, err)
			} else if n >= pol.PushPerHour {
				return nil, ErrCooldown
			}

			numMatch := secrets.GenDigits(2)
			meta := map[string]any{
				"ip":           effectiveIP,
				"client_ip":    clientIP,
				"host_ip":      hostIP,
				"ua":           ua,
				"purpose":      purpose,
				"service":      service,
				"host":         host,
				"client":       client,
				"number_match": numMatch,
				"username":     user.Username,
			}
			c2 := &store.Challenge{
				UserID:       user.ID,
				Channel:      channel.AppPush,
				PushState:    ptrString("pending"),
				ExpiresAt:    now.Add(pol.CodeTTL),
				AttemptsLeft: 1,
				Purpose:      purpose,
				Metadata:     meta,
			}
			if err := c.st.ChallengeCreate(ctx, c2); err != nil {
				return nil, err
			}
			expiresSecs := int(time.Until(c2.ExpiresAt).Seconds())
			displayService := service
			if hostIP != "" && !strings.Contains(displayService, hostIP) {
				displayService = service + " [" + hostIP + "]"
			}
			var pushErr error
			if apm, ok := appPush.(AppPushNotifierWithMeta); ok {
				_, pushErr = apm.SendAppPushWithMeta(ctx, user.ID, user.Username, effectiveIP, clientIP, hostIP, host, ua, client, displayService, numMatch, c2.ID, expiresSecs)
			} else {
				pushErr = appPush.SendAppPush(ctx, user.ID, user.Username, effectiveIP, ua, displayService, numMatch, c2.ID, expiresSecs)
			}
			if pushErr != nil {
				if _, derr := c.st.Pool().Exec(context.WithoutCancel(ctx),
					`DELETE FROM challenges WHERE id = $1`, c2.ID); derr != nil {
					slog.Warn("auth: удаление app_push челленджа после ошибки доставки",
						"id", c2.ID, "error", derr)
				}
				c.audit(ctx, user.Username, "app_push_sent",
					map[string]any{"purpose": purpose, "service": service, "error": redactErrText(pushErr)}, effectiveIP, "fail")
				continue
			}
			c.audit(ctx, user.Username, "app_push_sent",
				map[string]any{"purpose": purpose, "service": service, "challenge_id": c2.ID.String(), "number_match": numMatch}, effectiveIP, "ok")
			return c2, nil
		}
	}
	return nil, ErrNoChannel
}

// failAttempt расходует одну попытку челленджа: атомарный декремент
// attempts_left, при исчерпании челлендж помечается использованным
// (код больше не принимается). Попутно пишется code_fail — источник
// единого fail-счётчика (FailLocked).
func (c *Core) failAttempt(ctx context.Context, ch *store.Challenge, username string) {
	left, err := c.st.ChallengeDecrAttempt(ctx, ch.ID)
	if err != nil {
		return
	}
	if left == 0 {
		_ = c.st.ChallengeMarkUsed(ctx, ch.ID)
	}
	c.audit(ctx, username, "code_fail",
		map[string]any{"channel": string(ch.Channel), "challenge_id": ch.ID.String()}, "", "fail")
}

// VerifyChallengeCode проверяет код конкретного челленджа. Закрытый
// (использованный/просроченный) челлендж → ErrChallengeClosed; неверный
// код → ErrBadCode и расход попытки (при исчерпании челлендж закрывается);
// успех → single-use claim (ChallengeMarkUsed). Для channel=totp код
// проверяется по секрету пользователя (см. verifyTOTP).
func (c *Core) VerifyChallengeCode(ctx context.Context, ch *store.Challenge, code string) (bool, error) {
	if ch.UsedAt != nil || !time.Now().Before(ch.ExpiresAt) {
		return false, ErrChallengeClosed
	}
	user, err := c.st.UserByID(ctx, ch.UserID)
	if err != nil {
		return false, err
	}

	if ch.Channel == channel.TOTP {
		if err := c.verifyTOTP(ctx, user, code); err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				c.failAttempt(ctx, ch, user.Username)
				return false, ErrBadCode
			}
			return false, fmt.Errorf("auth: TOTP-секрет %s: %w", user.Username, err)
		}
		// Одноразовое использование челленджа; гонку двойной подачи
		// закрывает условный UPDATE в ChallengeMarkUsed — ErrNotFound
		// значит, что claim уже забрал конкурентный запрос (как в
		// кодовом канале: челлендж закрыт, а не второй успех).
		if err := c.st.ChallengeMarkUsed(ctx, ch.ID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return false, ErrChallengeClosed
			}
			return false, err
		}
		c.audit(ctx, user.Username, "code_ok",
			map[string]any{"channel": string(ch.Channel), "challenge_id": ch.ID.String()}, "", "ok")
		return true, nil
	}

	// Кодовые каналы (email/sms/telegram): точное сравнение хеша
	// (constant-time — hmac.Equal, чтобы тайминг не подсказывал длину
	// совпавшего префикса; унифицировано с остальной криптопроверкой).
	if hmac.Equal(ch.CodeHash, secrets.SHA256(code)) {
		if err := c.st.ChallengeMarkUsed(ctx, ch.ID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				// Одноразовый claim уже забрал конкурентный запрос.
				return false, ErrChallengeClosed
			}
			return false, err
		}
		c.audit(ctx, user.Username, "code_ok",
			map[string]any{"channel": string(ch.Channel), "challenge_id": ch.ID.String()}, "", "ok")
		return true, nil
	}
	c.failAttempt(ctx, ch, user.Username)
	return false, ErrBadCode
}

// LoginCodePurposes — purpose челленджей, пригодных в качестве второго
// фактора ВХОДА (web login/2fa, combined, RADIUS): api (публичный /auth/start)
// и radius_prefetch (предварительный запрос кода для VPN). Экранные коды
// tg_link (привязка Telegram) и ui_confirm (подтверждение операций кабинета)
// входом не считаются (SEC-001).
var LoginCodePurposes = []string{"api", "radius_prefetch"}

// VerifyAnyCode опознаёт код любым способом, в порядке: резервные коды
// (одноразовое потребление по SHA-256) → TOTP (с replay-защитой) →
// активные кодовые челленджи пользователя с purpose из purposes (первый
// точный хеш, mark used). Резервные коды и TOTP — факторы пользователя и
// purposes не фильтруются; доставленные коды — только своего назначения:
// пустой список purposes означает «доставленные коды не принимаются».
// Возвращает канал, по которому код опознан (BackupChannel — резервный
// код). Никто не подошёл → ErrBadCode. Аудит пишет вызывающий
// (VerifyPasswordAndCode / RADIUSAuth) — одна запись на попытку входа.
func (c *Core) VerifyAnyCode(ctx context.Context, user *store.User, code string, purposes ...string) (channel.Channel, error) {
	// 1. Резервные коды.
	if ok, err := c.st.BackupConsume(ctx, user.ID, secrets.SHA256(code)); err == nil && ok {
		return BackupChannel, nil
	}
	// 2. TOTP: не настроен или не подошёл — пробуем дальше.
	if err := c.verifyTOTP(ctx, user, code); err == nil {
		return channel.TOTP, nil
	}
	// 3. Активные кодовые челленджи перечисленных назначений.
	if len(purposes) > 0 {
		list, err := c.st.ActiveCodeChallenges(ctx, user.ID, purposes...)
		if err != nil {
			return "", err
		}
		sum := secrets.SHA256(code)
		for _, ch := range list {
			if hmac.Equal(ch.CodeHash, sum) {
				if err := c.st.ChallengeMarkUsed(ctx, ch.ID); err != nil {
					if errors.Is(err, store.ErrNotFound) {
						// Челлендж уже использован конкурентным запросом.
						return "", ErrBadCode
					}
					return "", err
				}
				return ch.Channel, nil
			}
		}
	}
	return "", ErrBadCode
}

// VerifyPasswordAndCode проверяет вход «пароль + второй фактор».
// Отдельный код (UI-флоу) или сплиты «код приклеен к паролю»
// (RADIUS-флоу, code == ""). Инвариант «один argon2 на запрос»:
// фаза 1 — код дёшево проверяется по кандидатам (VerifyAnyCode);
// у ПЕРВОГО кандидата с подошедшим кодом пароль проверяется ровно
// один раз, неудача → неверные учётные данные без перебора остальных
// кандидатов. Фаза 2 (код не опознан нигде) — ровно одна проверка
// полной строки (push-режим «пароль без кода»). Возвращает
// (user, true) при полном успехе; (user, false) — пароль верен, но
// код не опознан; (nil, false) — неверный логин или пароль.
// Блокировка fail-счётчика → ErrLocked. purposes — назначения кодовых
// челленджей, принимаемые как второй фактор (см. LoginCodePurposes).
func (c *Core) VerifyPasswordAndCode(ctx context.Context, username, password, code string, purposes ...string) (*store.User, bool, error) {
	user, err := c.st.UserByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Тайминг-оракул (SEC-005): отсутствие пользователя отвечает
			// argon2-ценой неверного пароля, как LocalVerifier.Verify.
			BurnDummyVerify(password)
			c.audit(ctx, username, "login_fail", map[string]any{"reason": "no_user"}, "", "fail")
			return nil, false, nil
		}
		return nil, false, err
	}
	if c.FailLocked(ctx, user.ID) {
		return nil, false, ErrLocked
	}

	auditDetail := func(base map[string]any) map[string]any {
		if s, ok := ctx.Value(CtxKeyService).(string); ok && s != "" {
			base["service"] = s
		}
		if h, ok := ctx.Value(CtxKeyHost).(string); ok && h != "" {
			base["host"] = h
		}
		if hip, ok := ctx.Value(CtxKeyHostIP).(string); ok && hip != "" {
			base["host_ip"] = hip
		}
		if cip, ok := ctx.Value(CtxKeyClientIP).(string); ok && cip != "" {
			base["client_ip"] = cip
		}
		if cl, ok := ctx.Value(CtxKeyDevice).(string); ok && cl != "" {
			base["client"] = cl
		}
		return base
	}

	// Кандидаты «пароль+код»: явный код или сплиты строки пароля.
	cands := []Split{{Password: password, Code: code}}
	if code == "" {
		cands = SplitCandidates(password, c.set.Get().Radius.CodeLengths)
	}

	// Фаза 1: код дёшево по всем кандидатам; пароль — одна проверка у
	// первого подошедшего (ONE password verify per request).
	for i := range cands {
		if _, err := c.VerifyAnyCode(ctx, user, cands[i].Code, purposes...); err != nil {
			continue
		}
		if _, err := c.pv.Verify(ctx, username, cands[i].Password); err == nil {
			c.audit(ctx, username, "login_ok", auditDetail(map[string]any{"mode": "password+code"}), "", "ok")
			return user, true, nil
		}
		c.audit(ctx, username, "login_fail", auditDetail(map[string]any{"reason": "bad_credentials"}), "", "fail")
		return nil, false, nil
	}

	// Фаза 2: код не опознан ни в одном кандидате — верен ли сам пароль
	// (полная строка, ровно одна проверка)?
	if _, err := c.pv.Verify(ctx, username, password); err == nil {
		c.audit(ctx, username, "login_fail", auditDetail(map[string]any{"reason": "bad_code"}), "", "fail")
		return user, false, nil
	}
	c.audit(ctx, username, "login_fail", auditDetail(map[string]any{"reason": "bad_credentials"}), "", "fail")
	return nil, false, nil
}

// FailLocked — единый per-user fail-счётчик по audit_log (спека §6,
// паттерн «аудит как источник rate-limit»): число неуспехов
// (login_fail / code_fail / radius_fail, result = fail) за
// policy.fail_window ≥ policy.max_fail И последний неуспех моложе
// policy.ban_time. Ошибки чтения трактуются как «не заблокирован».
func (c *Core) FailLocked(ctx context.Context, userID uuid.UUID) bool {
	pol := c.set.Get().Policy
	user, err := c.st.UserByID(ctx, userID)
	if err != nil {
		return false
	}
	var (
		count  int
		latest *time.Time
	)
	err = c.st.Pool().QueryRow(ctx, `
		SELECT count(*), MAX(ts) FROM audit_log
		WHERE username = $1
		  AND event IN ('login_fail', 'code_fail', 'radius_fail')
		  AND result = 'fail'
		  AND ts > $2`,
		user.Username, time.Now().Add(-pol.FailWindow)).Scan(&count, &latest)
	if err != nil || latest == nil {
		return false
	}
	return count >= pol.MaxFail && time.Since(*latest) < pol.BanTime
}

// countedAppPush — необязательная способность диспетчера app-push
// (реализация — (*delivery.AppHub).SendAppPushCounted): вернуть число живых
// соединений, принявших prompt в очередь. Диспетчер без этой способности
// (тестовые фейки) считается доставившим: количество неизвестно.
type countedAppPush interface {
	SendAppPushCounted(ctx context.Context, userID uuid.UUID, who, ip, ua, service, numberMatch string, challengeID uuid.UUID, expiresInSeconds int) (int, error)
}

// RADIUSAuth — полный алгоритм Access-Request (спека §3.1 + §3.6):
// lookup → enabled → FailLocked → сплиты «пароль+код» (код дёшево по
// всем, пароль — ровно один argon2: у первого split с подошедшим кодом,
// иначе полная строка) → при верном пароле без кода и флаге radius_push
// — push с cooldown/лимитом и удержанием запроса (опрос 1 с до
// radius.push_wait). Любой исход пишется в аудит (event radius_auth,
// detail.reason, src_ip, result). Вторая строка radius_fail на плохие
// учётные данные кормит fail-счётчик (FailLocked).
func (c *Core) RADIUSAuth(ctx context.Context, username, papString, srcIP string) (bool, string) {
	audit := func(reason string, accept bool) {
		result := "fail"
		if accept {
			result = "ok"
		}
		c.audit(ctx, username, "radius_auth", map[string]any{"reason": reason}, srcIP, result)
	}
	badCredentials := func() (bool, string) {
		audit("bad_credentials", false)
		c.audit(ctx, username, "radius_fail",
			map[string]any{"reason": "bad_credentials"}, srcIP, "fail")
		return false, "bad_credentials"
	}

	user, err := c.st.UserByUsername(ctx, username)
	if err != nil {
		// Тайминг-оракул (SEC-005): RADIUS-ветка «нет пользователя» тоже
		// платит полную argon2-цену — как VPN-клиент с неверным паролем.
		BurnDummyVerify(papString)
		audit("no_user", false)
		// Брут несуществующих имён должен кормить fail2ban (Guard.Fail) и
		// fail-счётчик — как bad_credentials; раньше radius_auth/no_user
		// не входил в фильтр событий (см. audit → switch event).
		c.audit(ctx, username, "radius_fail",
			map[string]any{"reason": "no_user"}, srcIP, "fail")
		return false, "no_user"
	}
	if !user.Enabled {
		audit("disabled", false)
		return false, "disabled"
	}
	// RADIUS-специфичный per-user fail-счётчик (radius.max_fail_per_user за
	// radius.fail_window, источник — аудит radius_fail) — в дополнение к
	// общему FailLocked: окно и порог настраиваются отдельно для VPN-потока.
	// Ошибка чтения трактуется как «не заблокирован» (как в FailLocked).
	if rad := c.set.Get().Radius; rad.MaxFailPerUser > 0 {
		var n int
		if err := c.st.Pool().QueryRow(ctx, `
			SELECT count(*) FROM audit_log
			WHERE username = $1 AND event = 'radius_fail' AND result = 'fail'
			  AND ts > $2`,
			user.Username, time.Now().Add(-rad.FailWindow)).Scan(&n); err == nil && n >= rad.MaxFailPerUser {
			audit("locked", false)
			return false, "locked"
		}
	}
	if c.FailLocked(ctx, user.ID) {
		audit("locked", false)
		return false, "locked"
	}

	// 1. Сплиты «пароль+код»: код дёшево по всем кандидатам; пароль —
	// ровно одна argon2-проверка у ПЕРВОГО split с подошедшим кодом;
	// неудача пароля → bad_credentials без перебора остальных.
	splits := SplitCandidates(papString, c.set.Get().Radius.CodeLengths)
	for i := range splits {
		if _, err := c.VerifyAnyCode(ctx, user, splits[i].Code, LoginCodePurposes...); err != nil {
			continue
		}
		if _, err := c.pv.Verify(ctx, username, splits[i].Password); err == nil {
			audit("code_ok", true)
			return true, "code_ok"
		}
		return badCredentials()
	}

	// 2. Пароль без кода: ровно одна проверка полной строки
	// (push-режим «пароль без кода»).
	if _, err := c.pv.Verify(ctx, username, papString); err != nil {
		return badCredentials()
	}

	pol := c.set.Get().Policy
	push := c.pushNotifier()
	appPush := c.appPushNotifier()
	radiusPush := c.st.UserEffectiveRadiusPush(ctx, user)

	// Фан-аут каналов доставки RADIUS-push: приложение (WS/SSE-рассылка +
	// pending-список для polling-фолбэка) — всегда, когда зарегистрирован
	// диспетчер; Telegram — при привязке. Раньше выбирался ОДИН канал
	// (app при активной регистрации устройства, иначе Telegram): при
	// отсутствии/истечении регистрации приложения пуш уходил только в
	// Telegram, и приложение не показывало подтверждение — челлендж
	// channel=telegram_push не попадает ни в BroadcastPrompt, ни в
	// pending-список приложения (ActiveAppPushChallenges фильтрует по
	// channel=app_push). Теперь оба канала доставляют ОДИН и тот же
	// челлендж: подтвердить можно из любого.
	sendApp := radiusPush && appPush != nil
	sendTg := radiusPush && user.TelegramChatID != nil && push != nil

	if !sendApp && !sendTg {
		// Пароль верен, но кода нет и push недоступен — Reject.
		if radiusPush {
			slog.Warn("radius: для пользователя включен RADIUS Push, но диспетчер app-push и Telegram не привязаны — отказ", "user", username)
		}
		audit("bad_credentials", false)
		return false, "bad_credentials"
	}

	// Push-fatigue: не чаще push_cooldown и не более push_per_hour в час.
	// Исключение: повторный Access-Request в cooldown при ЖИВОМ pending
	// push-челлендже (ретрансмит NAS после завершения первого хендлера,
	// повтор клиента после короткого push_wait — UniFi ~5с) — возобновляем
	// ожидание ЕГО вместо мгновенного Reject push_cooldown: пользователь
	// мог уже нажать «одобрить», а первый ответ ушёл до нажатия.
	var pushCh *store.Challenge
	resumed := false
	if last, err := c.st.LastPushAt(ctx, user.ID); err != nil {
		audit("push_send_fail", false)
		return false, "push_send_fail"
	} else if !last.IsZero() && time.Since(last) < pol.PushCooldown {
		if live := c.livePendingPush(ctx, user.ID); live != nil {
			pushCh, resumed = live, true
			slog.Info("auth: push в cooldown — возобновлено ожидание живого челленджа",
				"user", username, "challenge_id", live.ID.String())
		} else {
			audit("push_cooldown", false)
			return false, "push_cooldown"
		}
	}
	if !resumed {
		if n, err := c.st.PushCountSince(ctx, user.ID, time.Now().Add(-time.Hour)); err != nil {
			audit("push_send_fail", false)
			return false, "push_send_fail"
		} else if n >= pol.PushPerHour {
			audit("push_limit", false)
			return false, "push_limit"
		}
	}

	svc := "Корпоративный Wi-Fi / Сеть"
	if s, ok := ctx.Value(CtxKeyService).(string); ok && s != "" {
		svc = s
	}
	clientDesc := ""
	if d, ok := ctx.Value(CtxKeyDevice).(string); ok && d != "" {
		clientDesc = d
	}

	clientIP := srcIP
	if cip, ok := ctx.Value(CtxKeyClientIP).(string); ok && cip != "" {
		clientIP = cip
	}
	nasIP := srcIP
	if nip, ok := ctx.Value(CtxKeyHostIP).(string); ok && nip != "" {
		nasIP = nip
	}

	// Push-челлендж (pending) и фан-аут доставки: приложение (WS/SSE)
	// всегда + Telegram при привязке — один челлендж, оба канала. Для
	// RADIUS (Wi-Fi 802.1X / VPN) клиент подключается через сетевой стек
	// ОС, где невозможно показать проверочный номер на экране, поэтому
	// подтверждение в один клик (Принять / Отклонить) без Number Match.
	// При возобновлении живого челленджа — не создаём и не шлём заново.
	if !resumed {
		meta := map[string]any{
			"ip":        clientIP,
			"client_ip": clientIP,
			"host_ip":   nasIP,
			"service":   svc,
			"purpose":   svc,
			"device":    clientDesc,
			"username":  username,
		}
		chChannel := channel.TelegramPush
		if sendApp {
			chChannel = channel.AppPush
		}
		pushCh = &store.Challenge{
			UserID:       user.ID,
			Channel:      chChannel,
			PushState:    ptrString("pending"),
			ExpiresAt:    time.Now().Add(pol.CodeTTL),
			AttemptsLeft: 1,
			Purpose:      svc,
			Metadata:     meta,
		}
		if err := c.st.ChallengeCreate(ctx, pushCh); err != nil {
			audit("push_send_fail", false)
			return false, "push_send_fail"
		}
		expiresSecs := int(time.Until(pushCh.ExpiresAt).Seconds())

		// Канал 1: приложение — WS/SSE-рассылка + запись в pending-список
		// (само создание челленджа channel=app_push). 0 живых клиентов не
		// ошибка: polling-фолбэк клиента подхватит челлендж из pending.
		delivered := 0
		var appErr error
		if sendApp {
			if counted, ok := appPush.(countedAppPush); ok {
				delivered, appErr = counted.SendAppPushCounted(ctx, user.ID, username, clientIP, clientDesc, svc, "", pushCh.ID, expiresSecs)
			} else {
				appErr = appPush.SendAppPush(ctx, user.ID, username, clientIP, clientDesc, svc, "", pushCh.ID, expiresSecs)
				delivered = 1 // количество неизвестно — считаем доставленным
			}
			if appErr != nil {
				c.audit(ctx, username, "app_push_sent",
					map[string]any{"purpose": svc, "service": svc, "error": redactErrText(appErr)}, clientIP, "fail")
			} else {
				c.audit(ctx, username, "app_push_sent",
					map[string]any{"purpose": svc, "service": svc, "challenge_id": pushCh.ID.String(), "online_clients": delivered}, clientIP, "ok")
			}
		}

		// Канал 2: Telegram-бот (как и раньше: inline-кнопки, тот же
		// challenge ID — кнопка бота аппрувит тот же челлендж).
		tgOK := false
		if sendTg {
			var tgErr error
			if pushSvc, ok := push.(PushNotifierWithService); ok {
				tgErr = pushSvc.SendPushWithService(ctx, *user.TelegramChatID, username, clientIP, clientDesc, svc, nasIP, pushCh.ID)
			} else {
				tgErr = push.SendPush(ctx, *user.TelegramChatID, username, clientIP, clientDesc, pushCh.ID)
			}
			if tgErr != nil {
				c.audit(ctx, username, "push_sent",
					map[string]any{"purpose": svc, "service": svc, "error": redactErrText(tgErr)}, clientIP, "fail")
				slog.Warn("radius: доставка telegram-push не удалась (канал приложения продолжает работать)",
					"user", username, "error", tgErr)
			} else {
				tgOK = true
				c.audit(ctx, username, "push_sent",
					map[string]any{"purpose": svc, "service": svc, "challenge_id": pushCh.ID.String()}, clientIP, "ok")
			}
		}

		// Ни один канал не доставлен: рассылка в приложение упала И
		// Telegram не отправлен — челлендж удаляем (осиротевший держал бы
		// cooldown следующего push) и Reject.
		if appErr != nil && delivered == 0 && !tgOK {
			if _, derr := c.st.Pool().Exec(context.WithoutCancel(ctx),
				`DELETE FROM challenges WHERE id = $1`, pushCh.ID); derr != nil {
				slog.Warn("auth: удаление push-челленджа после ошибки доставки",
					"id", pushCh.ID, "error", derr)
			}
			audit("push_send_fail", false)
			return false, "push_send_fail"
		}
	}

	// Удержание Access-Request: опрос состояния 1 раз в секунду до
	// radius.push_wait («Один запрос клиента — один ответ», §3.1).
	// Разовая ошибка чтения состояния (БД моргнула) НЕ завершает
	// удержание: допускается до pushGetRetries подряд ошибок (следующий
	// тик — повтор), после — Reject push_timeout. consumed/expired
	// обрабатываются как раньше — немедленный push_timeout.
	deadline := time.Now().Add(c.set.Get().Radius.PushWait)
	ticker := time.NewTicker(pushTick)
	defer ticker.Stop()
	var getFails int
	for {
		select {
		case <-ctx.Done():
			// Терминальный аудит — в контексте без отмены: событие не
			// должно теряться вместе с отменённым ctx (Go 1.21+).
			c.audit(context.WithoutCancel(ctx), username, "radius_auth",
				map[string]any{"reason": "push_timeout"}, srcIP, "fail")
			return false, "push_timeout"
		case <-ticker.C:
			if time.Now().After(deadline) {
				audit("push_timeout", false)
				return false, "push_timeout"
			}
			cur, err := c.st.ChallengeGet(ctx, pushCh.ID)
			if err != nil {
				getFails++
				if getFails >= pushGetRetries {
					slog.Warn("radius: push-удержание — ошибки опроса состояния",
						"user", username, "challenge_id", pushCh.ID.String(),
						"errors", getFails, "error", err)
					audit("push_timeout", false)
					return false, "push_timeout"
				}
				slog.Warn("radius: push-удержание — повтор после ошибки опроса состояния",
					"user", username, "error", err)
				continue
			}
			getFails = 0
			if cur.UsedAt != nil || !time.Now().Before(cur.ExpiresAt) {
				audit("push_timeout", false)
				return false, "push_timeout"
			}
			switch {
			case cur.PushState != nil && *cur.PushState == "approved":
				_ = c.st.ChallengeMarkUsed(ctx, pushCh.ID)
				audit("push_ok", true)
				return true, "push_ok"
			case cur.PushState != nil && *cur.PushState == "denied":
				audit("push_denied", false)
				return false, "push_denied"
			}
		}
	}
}

// livePendingPush возвращает живой push-челлендж пользователя (не истёк,
// не использован, push_state=pending; каналы telegram_push/app_push) —
// кандидат на возобновление ожидания при повторном RADIUS-запросе в
// push_cooldown. Чужие purposes исключены (аудит 2026-09-11): RADIUS не
// должен возобновлять и поглощать approval web-челленджа (web-логин —
// purpose 'api', подтверждение операции кабинета — 'ui_confirm',
// код привязки Telegram — 'tg_link'); RADIUS-push создаётся с purpose =
// строке сервиса, поэтому фильтр — чёрный список. nil — живого
// челленджа нет.
func (c *Core) livePendingPush(ctx context.Context, userID uuid.UUID) *store.Challenge {
	var id uuid.UUID
	err := c.st.Pool().QueryRow(ctx, `
		SELECT id FROM challenges
		WHERE user_id = $1
		  AND channel IN ('telegram_push','app_push')
		  AND push_state = 'pending'
		  AND used_at IS NULL
		  AND expires_at > now()
		  AND purpose NOT IN ('api', 'ui_confirm', 'tg_link')
		ORDER BY created_at DESC
		LIMIT 1`, userID).Scan(&id)
	if err != nil {
		return nil
	}
	ch, err := c.st.ChallengeGet(ctx, id)
	if err != nil {
		return nil
	}
	return ch
}

// NotifyLoginSuccess асинхронно отправляет пользователю уведомление о входе
// во все доступные каналы (Telegram, если привязан, и Email, если настроен).
// 2-минутный антиспам-кулдаун на связку user:method:ip предотвращает спам
// при быстром роуминге Wi-Fi 802.1X между точками доступа.
func (c *Core) NotifyLoginSuccess(ctx context.Context, username, method, ip, ua string) {
	if username == "" {
		return
	}

	key := username + ":" + method + ":" + ip
	c.notifyMu.Lock()
	if c.lastNotify == nil {
		c.lastNotify = make(map[string]time.Time)
	}
	last, ok := c.lastNotify[key]
	now := time.Now()
	if ok && now.Sub(last) < 2*time.Minute {
		c.notifyMu.Unlock()
		return
	}
	c.lastNotify[key] = now
	// Очистка устаревших записей (> 10 минут)
	if len(c.lastNotify) > 1000 {
		for k, t := range c.lastNotify {
			if now.Sub(t) > 10*time.Minute {
				delete(c.lastNotify, k)
			}
		}
	}
	c.notifyMu.Unlock()

	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()

		user, err := c.st.UserByUsername(bgCtx, username)
		if err != nil || user == nil {
			return
		}

		loc := time.UTC
		domain := ""
		if c.set != nil && c.set.Get() != nil {
			t := c.set.Get()
			loc = t.Location()
			if t.Server.Domain != "" {
				domain = t.Server.Domain
			} else if t.ACME.Domain != "" {
				domain = t.ACME.Domain
			}
		}

		timeStr := now.In(loc).Format("02.01.2006 15:04:05")

		var sb strings.Builder
		sb.WriteString("🔔 Вход в учётную запись\n\n")

		userTitle := username
		if user.DisplayName != "" && user.DisplayName != username {
			userTitle = fmt.Sprintf("%s (%s)", username, user.DisplayName)
		}
		sb.WriteString("👤 Пользователь: " + userTitle + "\n")

		if method != "" {
			sb.WriteString("🌐 Способ: " + method + "\n")
		}
		if ip != "" {
			label := "📍 IP-адрес"
			ipVal := ip
			if strings.HasPrefix(method, "Wi-Fi") {
				label = "📡 Точка доступа (NAS)"
			} else {
				ipVal = FormatIPDescription(ip)
			}
			sb.WriteString(label + ": " + ipVal + "\n")
		}
		if ua != "" {
			devStr, browserStr := FormatDeviceAndBrowser(ua)
			devIcon := "💻"
			if strings.Contains(devStr, "iPhone") || strings.Contains(devStr, "Android") || strings.Contains(devStr, "iPad") {
				devIcon = "📱"
			} else if strings.HasPrefix(method, "Wi-Fi") {
				devIcon = "📱"
			}
			if devStr != "" {
				sb.WriteString(devIcon + " Устройство: " + devStr + "\n")
			}
			if browserStr != "" {
				sb.WriteString("🌐 Браузер: " + browserStr + "\n")
			}
		}
		sb.WriteString("⏰ Время: " + timeStr + "\n")
		if domain != "" {
			sb.WriteString("🏢 Сервер: " + domain + "\n")
		}
		sb.WriteString("\nЕсли это были не вы, немедленно обратитесь к администратору или смените пароль.")
		text := sb.String()

		subject := "Вход в учётную запись " + username
		if domain != "" {
			subject = "[" + domain + "] " + subject
		}

		// 1. Telegram
		if user.TelegramChatID != nil {
			if push := c.pushNotifier(); push != nil {
				if err := push.SendNotification(bgCtx, *user.TelegramChatID, text); err != nil {
					slog.Warn("auth: ошибка отправки уведомления в Telegram", "user", username, "error", err)
				} else {
					slog.Info("auth: отправлено уведомление о входе в Telegram", "user", username)
				}
			}
		}

		// 2. Email
		if user.Email != "" {
			if s := c.senderFor(channel.Email); s != nil {
				if as, ok := s.(delivery.AlertSender); ok {
					if err := as.SendAlert(bgCtx, user.Email, subject, text); err != nil {
						slog.Warn("auth: ошибка отправки уведомления на Email", "user", username, "error", err)
					} else {
						slog.Info("auth: отправлено уведомление о входе на Email", "user", username)
					}
				}
			}
		}
	}()
}
