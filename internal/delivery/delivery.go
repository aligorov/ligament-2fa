// Package delivery отправляет одноразовые коды по каналам доставки:
// email (SMTP), SMS (произвольный HTTP-шлюз или пресеты smsc/twilio)
// и лог (тесты/отладка).
package delivery

import (
	"context"
	"strings"

	"github.com/aligorov/twofa/internal/channel"
)

// Sender — канал доставки одноразового кода.
type Sender interface {
	// Name возвращает канал: channel.Email, channel.SMS и т.д.
	Name() channel.Channel
	// Send доставляет код получателю to (email-адрес или номер телефона).
	Send(ctx context.Context, to, code string) error
}

// AlertSender — канал отправки произвольных текстовых уведомлений (тема + тело).
type AlertSender interface {
	SendAlert(ctx context.Context, to, subject, body string) error
}

// BodyTemplate — встроенный дефолт текста сообщения, если настройка
// messages.* пуста: плейсхолдер {code} заменяется на одноразовый код.
const BodyTemplate = "Ваш код подтверждения: {code}"

// RenderTemplate рендерит шаблон сообщения: сперва переменные vars
// ({ttl}, {domain}, …), затем {code} — код не может подменить переменную.
// Пустой шаблон заменяется дефолтом BodyTemplate.
func RenderTemplate(tpl string, code string, vars map[string]string) string {
	if strings.TrimSpace(tpl) == "" {
		tpl = BodyTemplate
	}
	for k, v := range vars {
		tpl = strings.ReplaceAll(tpl, "{"+k+"}", v)
	}
	return strings.ReplaceAll(tpl, "{code}", code)
}
