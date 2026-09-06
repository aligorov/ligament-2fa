// Бот Telegram: long polling обновлений Bot API, привязка аккаунта по коду
// и push-подтверждение входа inline-кнопками.
package telegram

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aligorov/twofa/internal/channel"
	"github.com/aligorov/twofa/internal/delivery"
	"github.com/aligorov/twofa/internal/secrets"
	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
)

// runHTTPTimeout — таймаут HTTP-клиента бота: больше long-poll timeout (50 с)
// с запасом на сеть.
const runHTTPTimeout = 60 * time.Second

// perChatInterval — лимит Telegram ~1 сообщение/с на чат.
const perChatInterval = time.Second

// storeDeps — используемая ботом часть store.Store; интерфейс вынесен,
// чтобы юнит-тесты подменяли хранилище фейком (store требует PostgreSQL).
type storeDeps interface {
	ChallengeGet(ctx context.Context, id uuid.UUID) (*store.Challenge, error)
	ChallengeMarkUsed(ctx context.Context, id uuid.UUID) error
	ChallengeSetPush(ctx context.Context, id uuid.UUID, state string) error
	UserByID(ctx context.Context, id uuid.UUID) (*store.User, error)
	UserUpdate(ctx context.Context, u *store.User) error
	Audit(ctx context.Context, username, event string, detail map[string]any, ip, result string) error
}

// settingsDeps — используемая ботом часть settings.M.
type settingsDeps interface {
	Get() *settings.T
}

// Bot — долго живущий воркер Bot API. После New запускается методом Run;
// Send/SendPush можно вызывать из других горутин (доставка кода и пушей).
type Bot struct {
	cl  *Client
	st  storeDeps
	set settingsDeps

	// adLine — рекламная подпись бесплатной лицензии ("" — нет);
	// сеттер SetAdLine, вычисляется на каждую отправку.
	adLine func() string

	// findLink ищет активный tg_link-челлендж по SHA-256 нормализованного
	// кода. По умолчанию — прямой SQL через пул store (без user_id: код
	// вводит пользователь в чат, сервер не знает, чей он). Отдельное поле —
	// чтобы тесты подменяли поиск без PostgreSQL.
	findLink func(ctx context.Context, codeHash []byte) (*store.Challenge, error)

	mu       sync.Mutex
	lastSent map[int64]time.Time // per-chat троттлинг 1 сообщение/с
}

var _ delivery.Sender = (*Bot)(nil)

// New создаёт бота. Клиент берёт bot_token из текущего снимка настроек;
// пустой токен — канал выключен, Run сразу вернёт nil. Смена токена
// применяется после пересоздания бота (рестарта процесса).
func New(st *store.Store, set *settings.M) *Bot {
	token := ""
	if set != nil && set.Get() != nil {
		token = set.Get().TG.BotToken
	}
	b := &Bot{
		cl:       NewClient("", token, &http.Client{Timeout: runHTTPTimeout}),
		st:       st,
		set:      set,
		lastSent: make(map[int64]time.Time),
	}
	b.findLink = linkByCodeHash(st)
	return b
}

// linkByCodeHash возвращает поиск активного tg_link-челленджа по хешу кода
// прямым SQL: среди непросроченных и неиспользованных, свежий первый.
func linkByCodeHash(st *store.Store) func(ctx context.Context, codeHash []byte) (*store.Challenge, error) {
	return func(ctx context.Context, codeHash []byte) (*store.Challenge, error) {
		var ch store.Challenge
		err := st.Pool().QueryRow(ctx, `SELECT id, user_id FROM challenges
			WHERE purpose = 'tg_link' AND expires_at > now() AND used_at IS NULL
			  AND code_hash = $1
			ORDER BY created_at DESC
			LIMIT 1`, codeHash).Scan(&ch.ID, &ch.UserID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		if err != nil {
			return nil, fmt.Errorf("telegram: tg_link по хешу: %w", err)
		}
		return &ch, nil
	}
}

// Run — цикл long polling'а до отмены ctx. Пустой токен — канал выключен.
// 429 → пауза retry_after+1 с; 403 (бот заблокирован) — пауза 60 с и повтор;
// прочие ошибки — пауза 5 с. Остановка по ctx возвращает nil.
func (b *Bot) Run(ctx context.Context) error {
	if b.cl == nil || b.cl.token == "" {
		slog.Info("telegram: канал выключен (bot_token пуст)")
		return nil
	}
	slog.Info("telegram: бот запущен (long polling)")
	defer slog.Info("telegram: бот остановлен")

	offset := int64(0)
	for {
		if ctx.Err() != nil {
			return nil
		}
		ups, err := b.cl.getUpdates(ctx, offset)
		if err == nil {
			for _, u := range ups {
				offset = u.UpdateID + 1
				b.handleUpdate(ctx, u)
			}
			continue
		}
		if ctx.Err() != nil {
			return nil
		}
		var apiErr *APIError
		if errors.As(err, &apiErr) {
			switch apiErr.Code {
			case http.StatusTooManyRequests: // 429
				wait := time.Duration(apiErr.RetryAfter+1) * time.Second
				slog.Warn("telegram: 429 от Bot API, пауза", "wait", wait.String())
				b.cl.sleep(wait)
				continue
			case http.StatusForbidden: // 403 — бот заблокирован пользователем
				slog.Error("telegram: 403 от Bot API (заблокирован?), повтор через 60с",
					"desc", apiErr.Description)
				b.cl.sleep(60 * time.Second)
				continue
			}
		}
		slog.Error("telegram: getUpdates, повтор через 5с", "err", err)
		b.cl.sleep(5 * time.Second)
	}
}

// handleUpdate маршрутизирует одно обновление.
func (b *Bot) handleUpdate(ctx context.Context, u Update) {
	switch {
	case u.Message != nil:
		b.handleMessage(ctx, u.Message.Chat.ID, u.Message.Text)
	case u.CallbackQuery != nil:
		cq := u.CallbackQuery
		if cq.Message == nil { // сообщение слишком старое для редактирования
			_ = b.cl.answerCallbackQuery(ctx, cq.ID, "Не удалось обновить сообщение", false)
			return
		}
		b.handleCallback(ctx, cq.ID, cq.Message.Chat.ID, cq.Message.MessageID, cq.Data)
	}
}

// handleMessage обрабатывает текст: "/start <код>" или сам код — привязка
// чата к аккаунту по активному tg_link-челленджу.
func (b *Bot) handleMessage(ctx context.Context, chatID int64, text string) {
	code := extractLinkCode(text)
	if code == "" {
		b.reply(ctx, chatID, "Отправьте код привязки вида XXXX-XXXX")
		return
	}
	b.linkChat(ctx, chatID, code)
}

// extractLinkCode достаёт код привязки из текста сообщения: снимает команду
// /start (deep-link), обрезает пробелы и приводит к верхнему регистру —
// хеш считается от нормализованной формы. Команда без аргумента и пустой
// текст дают "" (бот ответит подсказкой).
func extractLinkCode(text string) string {
	text = strings.TrimSpace(text)
	if head, rest, found := strings.Cut(text, " "); found && strings.HasPrefix(head, "/") {
		text = strings.TrimSpace(rest)
	}
	if strings.HasPrefix(text, "/") { // команда без кода
		return ""
	}
	return strings.ToUpper(strings.TrimSpace(text))
}

// linkChat привязывает чат к пользователю по коду. Челлендж сначала
// помечается использованным (одноразовый claim — закрывает гонку двух
// чатов с одним кодом), затем сохраняется telegram_chat_id.
func (b *Bot) linkChat(ctx context.Context, chatID int64, code string) {
	ch, err := b.findLink(ctx, secrets.SHA256(code))
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			slog.Error("telegram: поиск tg_link", "err", err)
		}
		b.reply(ctx, chatID, "❌ Код не найден или истёк")
		return
	}
	if err := b.st.ChallengeMarkUsed(ctx, ch.ID); err != nil {
		slog.Error("telegram: claim tg_link", "challenge", ch.ID, "err", err)
		b.reply(ctx, chatID, "❌ Код не найден или истёк")
		return
	}
	u, err := b.st.UserByID(ctx, ch.UserID)
	if err != nil {
		slog.Error("telegram: пользователь tg_link", "user", ch.UserID, "err", err)
		b.reply(ctx, chatID, "❌ Ошибка привязки, попробуйте позже")
		return
	}
	// Перепривязка (SEC-002): у аккаунта уже был ДРУГОЙ чат — до перезаписи
	// уведомляем старый чат best-effort: если код привязки утёк или аккаунт
	// захватывают, у владельца есть сигнал сменить пароль. Ошибка отправки
	// не мешает привязке.
	if u.TelegramChatID != nil && *u.TelegramChatID != chatID {
		old := *u.TelegramChatID
		b.reply(context.WithoutCancel(ctx), old, fmt.Sprintf(
			"Ваш Telegram отвязан от аккаунта %s. Если это не вы — смените пароль.", u.Username))
	}
	chat := chatID
	u.TelegramChatID = &chat
	if err := b.st.UserUpdate(ctx, u); err != nil {
		slog.Error("telegram: сохранение telegram_chat_id", "user", u.ID, "err", err)
		b.reply(ctx, chatID, "❌ Ошибка привязки, попробуйте позже")
		return
	}
	b.reply(ctx, chatID, "✅ Telegram привязан")
	if err := b.st.Audit(ctx, u.Username, "tg_link", nil, "", "ok"); err != nil {
		slog.Error("telegram: аудит tg_link", "user", u.Username, "err", err)
	}
}

// handleCallback обрабатывает нажатие кнопки push-подтверждения:
// "approve:<uuid>" / "deny:<uuid>". answerCallbackQuery вызывается всегда
// (иначе у пользователя крутится спиннер).
func (b *Bot) handleCallback(ctx context.Context, queryID string, chatID, msgID int64, data string) {
	answer := func() { _ = b.cl.answerCallbackQuery(ctx, queryID, "", false) }

	action, idStr, found := strings.Cut(data, ":")
	if !found || (action != "approve" && action != "deny") {
		slog.Warn("telegram: неизвестный callback", "data", data)
		answer()
		return
	}
	id, err := uuid.Parse(idStr)
	if err != nil {
		slog.Warn("telegram: некорректный uuid в callback", "data", data)
		answer()
		return
	}
	ch, err := b.st.ChallengeGet(ctx, id)
	if err != nil {
		// челлендж удалён/истёрт — для пользователя это "уже обработано"
		_ = b.cl.editMessageText(ctx, chatID, msgID, "⏳ Уже обработано")
		answer()
		return
	}
	if ch.PushState == nil || *ch.PushState != "pending" {
		_ = b.cl.editMessageText(ctx, chatID, msgID, "⏳ Уже обработано")
		answer()
		return
	}
	state, text := "approved", "✅ Вход подтверждён"
	if action == "deny" {
		state, text = "denied", "🚫 Вход отклонён"
	}
	if err := b.st.ChallengeSetPush(ctx, id, state); err != nil {
		slog.Error("telegram: push_state", "challenge", id, "err", err)
		_ = b.cl.editMessageText(ctx, chatID, msgID, "❌ Ошибка, попробуйте позже")
		answer()
		return
	}
	_ = b.cl.editMessageText(ctx, chatID, msgID, text)
	username := ""
	if u, err := b.st.UserByID(ctx, ch.UserID); err == nil {
		username = u.Username
	}
	if err := b.st.Audit(ctx, username, "tg_push",
		map[string]any{"action": action, "challenge": id.String()}, "", state); err != nil {
		slog.Error("telegram: аудит tg_push", "challenge", id, "err", err)
	}
	answer()
}

// SendPush отправляет в чат запрос push-подтверждения входа с кнопками
// "✅ Подтвердить" / "❌ Это не я"; callback_data — approve:<id> / deny:<id>.
func (b *Bot) SendPush(ctx context.Context, chatID int64, who, ip, ua string, challengeID uuid.UUID) error {
	pushTpl := snap0(b.set).Messages.TelegramPush
	if strings.TrimSpace(pushTpl) == "" {
		pushTpl = settings.DefaultTelegramPush // тесты без менеджера настроек
	}
	vars := map[string]string{
		"username": who, "ip": ip, "ua": ua,
		"time": time.Now().Format("15:04:05"),
	}
	text := delivery.RenderTemplate(pushTpl, "", vars)
	kb := &InlineKeyboard{InlineKeyboard: [][]InlineButton{
		{{Text: "✅ Подтвердить", CallbackData: "approve:" + challengeID.String()}},
		{{Text: "❌ Это не я", CallbackData: "deny:" + challengeID.String()}},
	}}
	return b.send(ctx, chatID, text, kb)
}

// Name реализует delivery.Sender.
func (b *Bot) Name() channel.Channel { return channel.Telegram }

// Send реализует delivery.Sender: to — chat id строкой; текст —
// messages.telegram_code_text (пусто — встроенный дефолт), рендер с
// общими переменными шаблона ({ttl}, {domain}).
func (b *Bot) Send(ctx context.Context, to, code string) error {
	chatID, err := strconv.ParseInt(strings.TrimSpace(to), 10, 64)
	if err != nil {
		return fmt.Errorf("telegram: chat id %q: %w", to, err)
	}
	snap := snap0(b.set)
	codeTpl := snap.Messages.TelegramCode
	if strings.TrimSpace(codeTpl) == "" {
		codeTpl = settings.DefaultTelegramCode // тесты без менеджера настроек
	}
	text := delivery.RenderTemplate(codeTpl, code, snap.MessageVars())
	if b.adLine != nil {
		if ad := b.adLine(); ad != "" {
			text += "\n\n" + ad
		}
	}
	return b.send(ctx, chatID, text, nil)
}

// snap0 — снимок настроек или пустой (нет менеджера — тесты бота).
func snap0(m settingsDeps) *settings.T {
	if m == nil {
		return &settings.T{}
	}
	if t := m.Get(); t != nil {
		return t
	}
	return &settings.T{}
}

// send троттлит чат (≤1 сообщение/с) и отправляет сообщение. Пауза троттлинга
// идёт через тот же injectable sleep, что и 429, — тесты не ждут реально.
func (b *Bot) send(ctx context.Context, chatID int64, text string, kb *InlineKeyboard) error {
	b.throttle(chatID)
	return b.cl.sendMessage(ctx, chatID, text, kb)
}

// reply — обёртка send для ответов бота: ошибки отправки логируются,
// а не прерывают цикл обновлений.
func (b *Bot) reply(ctx context.Context, chatID int64, text string) {
	if err := b.send(ctx, chatID, text, nil); err != nil {
		slog.Error("telegram: sendMessage", "chat", chatID, "err", err)
	}
}

// throttle выдерживает интервал perChatInterval между сообщениями в один чат.
func (b *Bot) throttle(chatID int64) {
	b.mu.Lock()
	now := time.Now()
	last, ok := b.lastSent[chatID]
	if !ok || now.Sub(last) >= perChatInterval {
		b.lastSent[chatID] = now
		b.mu.Unlock()
		return
	}
	wait := perChatInterval - now.Sub(last)
	b.lastSent[chatID] = now.Add(wait) // бронь слота на момент конца паузы
	b.mu.Unlock()
	b.cl.sleep(wait)
}

// linkAlphabet — алфавит кода привязки без похожих символов (0/O, 1/I);
// ровно 32 символа, поэтому b%32 по байту crypto/rand без смещения.
const linkAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// GenerateLinkCode возвращает код привязки формата XXXX-XXXX (8 символов
// из linkAlphabet, crypto/rand).
func GenerateLinkCode() string {
	buf := make([]byte, 12)
	out := make([]byte, 0, 8)
	for len(out) < 8 {
		if _, err := rand.Read(buf); err != nil {
			panic(fmt.Sprintf("telegram: rand.Read: %v", err))
		}
		for _, b := range buf {
			out = append(out, linkAlphabet[int(b)%len(linkAlphabet)])
			if len(out) == 8 {
				break
			}
		}
	}
	return string(out[:4]) + "-" + string(out[4:])
}

// SetAdLine подключает рекламную подпись сообщений (nil — без подписи).
func (b *Bot) SetAdLine(f func() string) { b.adLine = f }
