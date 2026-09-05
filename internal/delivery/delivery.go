// Package delivery отправляет одноразовые коды по каналам доставки:
// email (SMTP), SMS (произвольный HTTP-шлюз или пресеты smsc/twilio)
// и лог (тесты/отладка).
package delivery

import (
	"context"

	"github.com/aligorov/twofa/internal/channel"
)

// Sender — канал доставки одноразового кода.
type Sender interface {
	// Name возвращает канал: channel.Email, channel.SMS и т.д.
	Name() channel.Channel
	// Send доставляет код получателю to (email-адрес или номер телефона).
	Send(ctx context.Context, to, code string) error
}

// BodyTemplate — шаблон текста сообщения: плейсхолдер {code} заменяется
// на одноразовый код. Общий для email и SMS; настройки могут ссылаться
// на эту константу.
const BodyTemplate = "Ваш код подтверждения: {code}"
