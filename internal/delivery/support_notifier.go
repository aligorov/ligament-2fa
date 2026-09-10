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
	SendNotification(ctx context.Context, chatID int64, text string) error
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
	if catObj := snap.Support.CategoryByID(ss.Category); catObj != nil {
		categoryLabel = catObj.Icon + " " + catObj.Name
	} else if strings.EqualFold(ss.Category, "1c") {
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

	// Сводка телеметрии устройства (диски, CPU)
	telemetrySummary := "Телеметрия: в норме"
	if device != nil && device.SecurityPosture != nil {
		var parts []string
		if diskAlert, ok := device.SecurityPosture["disk_alert"].(bool); ok && diskAlert {
			parts = append(parts, "⚠️ ВНИМАНИЕ: Заполнен диск!")
		}
		if cpuAlert, ok := device.SecurityPosture["cpu_alert"].(bool); ok && cpuAlert {
			parts = append(parts, "🚨 ВНИМАНИЕ: Пиковая 100% нагрузка CPU!")
		} else if cpuLoad, ok := device.SecurityPosture["cpu_load_percent"]; ok {
			parts = append(parts, fmt.Sprintf("Нагрузка CPU: %v%%", cpuLoad))
		}
		if len(parts) > 0 {
			telemetrySummary = strings.Join(parts, "\n")
		}
	}

	// 1. Email-оповещения на адреса из настроек категории
	emails := snap.Support.EmailsForCategory(ss.Category)

	if n.emailSender != nil && len(emails) > 0 {
		subject := fmt.Sprintf("[SOS] %s | %s (%s): %s", categoryLabel, userName, deviceName, truncateText(ss.ProblemSummary, 60))
		body := fmt.Sprintf(
			"🚨 Поступил новый экстренный запрос удаленной помощи!\n\n"+
				"Категория: %s\n"+
				"Сотрудник: %s (логин: @%s, email: %s, телефон: %s)\n"+
				"Компьютер: %s (ОС: %s, платформа: %s)\n"+
				"IP-адрес: %s\n\n"+
				"ДИАГНОСТИКА СИСТЕМЫ:\n%s\n\n"+
				"СУТЬ ПРОБЛЕМЫ:\n\"%s\"\n\n"+
				"Ссылка для подключения в веб-консоли:\n%s\n",
			categoryLabel, userName, user.Username, user.Email, user.Phone,
			deviceName, device.OSVersion, device.Platform, ss.LastIP,
			telemetrySummary,
			ss.ProblemSummary, viewerURL,
		)

		for _, emailAddr := range emails {
			emailAddr = strings.TrimSpace(emailAddr)
			if emailAddr == "" {
				continue
			}
			go func(addr string) {
				var err error
				if replySender, ok := n.emailSender.(AlertSenderReplyTo); ok && user.Email != "" {
					err = replySender.SendAlertWithReplyTo(context.Background(), addr, user.Email, subject, body)
				} else {
					err = n.emailSender.SendAlert(context.Background(), addr, subject, body)
				}
				if err != nil {
					slog.Warn("support_notifier: ошибка отправки email", "to", addr, "error", err)
				} else {
					slog.Info("support_notifier: email успешно отправлен", "to", addr, "session_id", ss.ID)
				}
			}(emailAddr)
		}
	}

	// 2. Telegram-оповещения в чат дежурной группы
	tgChatID := snap.Support.TelegramChatForCategory(ss.Category)

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
			if err := n.tgSender.SendNotification(context.Background(), chatID, text); err != nil {
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
