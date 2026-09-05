package delivery

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/aligorov/twofa/internal/channel"
)

// LogSender пишет код в лог (slog) вместо реальной отправки — для
// тестов и отладки. Канал — псевдоимя "log".
type LogSender struct{}

var _ Sender = LogSender{}

// NewLog возвращает отправитель, пишущий коды в лог.
func NewLog() Sender { return LogSender{} }

// Name реализует Sender; у лог-отправителя нет реального канала.
func (LogSender) Name() channel.Channel { return channel.Channel("log") }

// Send пишет строку "code to <to>: <code>" в стандартный slog-лог.
func (LogSender) Send(_ context.Context, to, code string) error {
	slog.Info(fmt.Sprintf("code to %s: %s", to, code))
	return nil
}
