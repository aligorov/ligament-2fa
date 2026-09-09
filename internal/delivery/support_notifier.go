package delivery

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
)

// TelegramSender — интерфейс для отправки сообщений в Telegram бот.
type TelegramSender interface {
	SendMessage(ctx context.Context, chatID int64, text string) error
}

// SupportNotifier рассылает многоканальные уведомления о новых SOS-обращениях.
type SupportNotifier struct {
	emailSender AlertSender
	tgSender    TelegramSender
	set         *settings.M
	hub         *AppHub
}

// NewSupportNotifier создает новый диспетчер оповещений поддержки.
func NewSupportNotifier(emailSender AlertSender, tgSender TelegramSender, set *settings.M, hub *AppHub) *SupportNotifier {
	return &SupportNotifier{
		emailSender: emailSender,
		tgSender:    tgSender,
		set:         set,
		hub:         hub,
	}
}

// NotifyNewSession рассылает оповещения на email, в Telegram и в веб-консоль при создании запроса помощи.
func (n *SupportNotifier) NotifyNewSession(ctx context.Context, ss *store.SupportSession, user *store.User, device *store.AppDevice) {
	if n.set == nil {
		return
	}
	snap := n.set.Get()
	if snap == nil || !snap.Support.Enabled {
		return
	}

	categoryLabel := "🖥 IT-поддержка"
	if strings.EqualFold(ss.Category, "1c") {
		categoryLabel = "📊 Помощь по 1С"
	}

	domain := snap.Server.Domain
	if domain == "" {
		domain = "http://localhost:8080"
	}
	viewerURL := fmt.Sprintf("%s/admin/support/%s/viewer", domain, ss.ID)

	userName := user.DisplayName
	if userName == "" {
		userName = user.Username
	}

	deviceName := device.DeviceName
	if deviceName == "" {
		deviceName = device.Platform
	}

	// 1. Email-оповещения на адреса из настроек
	var emails []string
	if strings.EqualFold(ss.Category, "1c") {
		emails = snap.Support.Emails1C
		if len(emails) == 0 {
			emails = snap.Support.EmailsIT
		}
	} else {
		emails = snap.Support.EmailsIT
		if len(emails) == 0 {
			emails = snap.Support.Emails1C
		}
	}

	if n.emailSender != nil && len(emails) > 0 {
		subject := fmt.Sprintf("[SOS-%s] %s: %s", strings.ToUpper(ss.Category), userName, truncateText(ss.ProblemSummary, 60))
		body := fmt.Sprintf(
			"🚨 Поступил новый экстренный запрос удаленной помощи!\n\n"+
				"Категория: %s\n"+
				"Сотрудник: %s (%s)\n"+
				"Устройство: %s (ОС: %s, платформа: %s)\n"+
				"IP-адрес: %s\n\n"+
				"СУТЬ ПРОБЛЕМЫ:\n\"%s\"\n\n"+
				"Ссылка для подключения в веб-консоли:\n%s\n",
			categoryLabel, userName, user.Username, deviceName, device.OSVersion, device.Platform, ss.LastIP,
			ss.ProblemSummary, viewerURL,
		)

		for _, emailAddr := range emails {
			emailAddr = strings.TrimSpace(emailAddr)
			if emailAddr == "" {
				continue
			}
			go func(addr string) {
				if err := n.emailSender.SendAlert(context.Background(), addr, subject, body); err != nil {
					slog.Warn("support_notifier: ошибка отправки email", "to", addr, "error", err)
				} else {
					slog.Info("support_notifier: email успешно отправлен", "to", addr, "session_id", ss.ID)
				}
			}(emailAddr)
		}
	}

	// 2. Telegram-оповещения в чат дежурной группы
	var tgChatID int64
	if strings.EqualFold(ss.Category, "1c") {
		tgChatID = snap.Support.TelegramChat1C
		if tgChatID == 0 {
			tgChatID = snap.Support.TelegramChatIT
		}
	} else {
		tgChatID = snap.Support.TelegramChatIT
		if tgChatID == 0 {
			tgChatID = snap.Support.TelegramChat1C
		}
	}

	if n.tgSender != nil && tgChatID != 0 {
		tgMsg := fmt.Sprintf(
			"🚨 *SOS: Новый запрос помощи (%s)*\n\n"+
				"👤 *Сотрудник:* %s (`%s`)\n"+
				"💻 *ПК:* %s (`%s`)\n"+
				"🌐 *IP:* `%s`\n\n"+
				"📝 *Суть проблемы:*\n_%s_\n\n"+
				"🔗 [Открыть веб-консоль подключения](%s)",
			escapeMD(categoryLabel),
			escapeMD(userName), escapeMD(user.Username),
			escapeMD(deviceName), escapeMD(device.Platform),
			escapeMD(ss.LastIP),
			escapeMD(ss.ProblemSummary),
			viewerURL,
		)

		go func(chatID int64, text string) {
			if err := n.tgSender.SendMessage(context.Background(), chatID, text); err != nil {
				slog.Warn("support_notifier: ошибка отправки telegram", "chat_id", chatID, "error", err)
			} else {
				slog.Info("support_notifier: telegram успешно отправлен", "chat_id", chatID, "session_id", ss.ID)
			}
		}(tgChatID, tgMsg)
	}
}

func truncateText(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxLen {
		return s
	}
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "..."
}

func escapeMD(s string) string {
	rep := strings.NewReplacer(
		"_", "\\_",
		"*", "\\*",
		"[", "\\[",
		"]", "\\]",
		"(", "\\(",
		")", "\\)",
		"~", "\\~",
		"`", "\\`",
		">", "\\>",
		"#", "\\#",
		"+", "\\+",
		"-", "\\-",
		"=", "\\=",
		"|", "\\|",
		"{", "\\{",
		"}", "\\}",
		".", "\\.",
		"!", "\\!",
	)
	return rep.Replace(s)
}
