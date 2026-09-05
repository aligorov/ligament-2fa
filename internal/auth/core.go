package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/aligorov/twofa/internal/channel"
	"github.com/aligorov/twofa/internal/delivery"
	"github.com/aligorov/twofa/internal/secrets"
	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
)

// pushTick — интервал опроса push-челленджа в удержании RADIUS-запроса.
const pushTick = time.Second

// Core — ядро аутентификации: выдча челленджей по предпочтительным
// каналам, проверка кодов всех типов, fail-счётчик и RADIUS-флоу
// (сплиты «пароль+код», push_wait).
type Core struct {
	st      *store.Store
	set     *settings.M
	box     *secrets.Box
	senders map[channel.Channel]delivery.Sender
	pv      PasswordVerifier
	push    PushNotifier // nil → канал telegram_push недоступен
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
	m := make(map[channel.Channel]delivery.Sender, len(senders))
	for k, v := range senders {
		m[k] = v
	}
	return &Core{st: st, set: set, box: box, senders: m, pv: pv, push: push}
}

// audit записывает событие аудита, не ломая основной поток: ошибка записи
// логируется и проглатывается (аудит не должен блокировать аутентификацию).
func (c *Core) audit(ctx context.Context, username, event string, detail map[string]any, ip, result string) {
	if err := c.st.Audit(ctx, username, event, detail, ip, result); err != nil {
		slog.Warn("auth: аудит не записан", "event", event, "error", err)
	}
}

func ptrString(s string) *string { return &s }

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
	sender, ok := c.senders[ch]
	if !ok || sender == nil {
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
	pol := c.set.Get().Policy
	prefer := user.PreferChannels
	if len(prefer) == 0 {
		prefer = pol.DefaultPrefer
	}
	now := time.Now()

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
					map[string]any{"channel": string(ch), "purpose": purpose, "error": err.Error()},
					ip, "fail")
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
				map[string]any{"channel": string(ch), "purpose": purpose}, ip, "ok")
			return c2, nil

		case channel.TelegramPush:
			if user.TelegramChatID == nil || c.push == nil {
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
			c2 := &store.Challenge{
				UserID:       user.ID,
				Channel:      channel.TelegramPush,
				PushState:    ptrString("pending"),
				ExpiresAt:    now.Add(pol.CodeTTL),
				AttemptsLeft: 1,
				Purpose:      purpose,
			}
			if err := c.st.ChallengeCreate(ctx, c2); err != nil {
				return nil, err
			}
			if err := c.push.SendPush(ctx, *user.TelegramChatID, user.Username, ip, ua, c2.ID); err != nil {
				// Осиротевший челлендж держал бы cooldown следующего
				// push — удаляем (WithoutCancel: доставка могла упасть
				// из-за отмены ctx).
				if _, derr := c.st.Pool().Exec(context.WithoutCancel(ctx),
					`DELETE FROM challenges WHERE id = $1`, c2.ID); derr != nil {
					slog.Warn("auth: удаление push-челленджа после ошибки доставки",
						"id", c2.ID, "error", derr)
				}
				c.audit(ctx, user.Username, "push_sent",
					map[string]any{"purpose": purpose, "error": err.Error()}, ip, "fail")
				continue
			}
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

	// Кодовые каналы (email/sms/telegram): точное сравнение хеша.
	if bytes.Equal(ch.CodeHash, secrets.SHA256(code)) {
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

// VerifyAnyCode опознаёт код любым способом, в порядке: резервные коды
// (одноразовое потребление по SHA-256) → TOTP (с replay-защитой) →
// активные кодовые челленджи пользователя (первый точный хеш, mark used).
// Возвращает канал, по которому код опознан (BackupChannel — резервный
// код). Никто не подошёл → ErrBadCode. Аудит пишет вызывающий
// (VerifyPasswordAndCode / RADIUSAuth) — одна запись на попытку входа.
func (c *Core) VerifyAnyCode(ctx context.Context, user *store.User, code string) (channel.Channel, error) {
	// 1. Резервные коды.
	if ok, err := c.st.BackupConsume(ctx, user.ID, secrets.SHA256(code)); err == nil && ok {
		return BackupChannel, nil
	}
	// 2. TOTP: не настроен или не подошёл — пробуем дальше.
	if err := c.verifyTOTP(ctx, user, code); err == nil {
		return channel.TOTP, nil
	}
	// 3. Активные кодовые челленджи.
	list, err := c.st.ActiveCodeChallenges(ctx, user.ID)
	if err != nil {
		return "", err
	}
	sum := secrets.SHA256(code)
	for _, ch := range list {
		if bytes.Equal(ch.CodeHash, sum) {
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
// Блокировка fail-счётчика → ErrLocked.
func (c *Core) VerifyPasswordAndCode(ctx context.Context, username, password, code string) (*store.User, bool, error) {
	user, err := c.st.UserByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			c.audit(ctx, username, "login_fail", map[string]any{"reason": "no_user"}, "", "fail")
			return nil, false, nil
		}
		return nil, false, err
	}
	if c.FailLocked(ctx, user.ID) {
		return nil, false, ErrLocked
	}

	// Кандидаты «пароль+код»: явный код или сплиты строки пароля.
	cands := []Split{{Password: password, Code: code}}
	if code == "" {
		cands = SplitCandidates(password, c.set.Get().Radius.CodeLengths)
	}

	// Фаза 1: код дёшево по всем кандидатам; пароль — одна проверка у
	// первого подошедшего (ONE password verify per request).
	for i := range cands {
		if _, err := c.VerifyAnyCode(ctx, user, cands[i].Code); err != nil {
			continue
		}
		if _, err := c.pv.Verify(ctx, username, cands[i].Password); err == nil {
			c.audit(ctx, username, "login_ok", map[string]any{"mode": "password+code"}, "", "ok")
			return user, true, nil
		}
		c.audit(ctx, username, "login_fail", map[string]any{"reason": "bad_credentials"}, "", "fail")
		return nil, false, nil
	}

	// Фаза 2: код не опознан ни в одном кандидате — верен ли сам пароль
	// (полная строка, ровно одна проверка)?
	if _, err := c.pv.Verify(ctx, username, password); err == nil {
		c.audit(ctx, username, "login_fail", map[string]any{"reason": "bad_code"}, "", "fail")
		return user, false, nil
	}
	c.audit(ctx, username, "login_fail", map[string]any{"reason": "bad_credentials"}, "", "fail")
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
		audit("no_user", false)
		return false, "no_user"
	}
	if !user.Enabled {
		audit("disabled", false)
		return false, "disabled"
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
		if _, err := c.VerifyAnyCode(ctx, user, splits[i].Code); err != nil {
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
	if !user.RadiusPush || user.TelegramChatID == nil || c.push == nil {
		// Пароль верен, но кода нет и push недоступен — Reject.
		audit("bad_credentials", false)
		return false, "bad_credentials"
	}

	// Push-fatigue: не чаще push_cooldown и не более push_per_hour в час.
	if last, err := c.st.LastPushAt(ctx, user.ID); err != nil {
		audit("push_send_fail", false)
		return false, "push_send_fail"
	} else if !last.IsZero() && time.Since(last) < pol.PushCooldown {
		audit("push_cooldown", false)
		return false, "push_cooldown"
	}
	if n, err := c.st.PushCountSince(ctx, user.ID, time.Now().Add(-time.Hour)); err != nil {
		audit("push_send_fail", false)
		return false, "push_send_fail"
	} else if n >= pol.PushPerHour {
		audit("push_limit", false)
		return false, "push_limit"
	}

	// Push-челлендж (pending) и сообщение боту.
	pushCh := &store.Challenge{
		UserID:       user.ID,
		Channel:      channel.TelegramPush,
		PushState:    ptrString("pending"),
		ExpiresAt:    time.Now().Add(pol.CodeTTL),
		AttemptsLeft: 1,
		Purpose:      "radius",
	}
	if err := c.st.ChallengeCreate(ctx, pushCh); err != nil {
		audit("push_send_fail", false)
		return false, "push_send_fail"
	}
	if err := c.push.SendPush(ctx, *user.TelegramChatID, username, srcIP, "", pushCh.ID); err != nil {
		// Осиротевший челлендж держал бы cooldown следующего push —
		// удаляем (WithoutCancel: доставка могла упасть из-за отмены ctx).
		if _, derr := c.st.Pool().Exec(context.WithoutCancel(ctx),
			`DELETE FROM challenges WHERE id = $1`, pushCh.ID); derr != nil {
			slog.Warn("auth: удаление push-челленджа после ошибки доставки",
				"id", pushCh.ID, "error", derr)
		}
		audit("push_send_fail", false)
		return false, "push_send_fail"
	}

	// Удержание Access-Request: опрос состояния 1 раз в секунду до
	// radius.push_wait («Один запрос клиента — один ответ», §3.1).
	deadline := time.Now().Add(c.set.Get().Radius.PushWait)
	ticker := time.NewTicker(pushTick)
	defer ticker.Stop()
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
			if err != nil || cur.UsedAt != nil || !time.Now().Before(cur.ExpiresAt) {
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
