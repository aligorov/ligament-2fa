package delivery

import (
	"context"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/aligorov/twofa/internal/channel"
)

// EmailSender отправляет код письмом по SMTP (net/smtp).
type EmailSender struct {
	host     string
	port     int
	startTLS bool
	user     string
	pass     string
	from     string
	subject  string
	timeout  time.Duration

	// sendFn выполняет SMTP-транзакцию; по умолчанию smtp.SendMail.
	// Отдельное поле — чтобы тесты подменяли его рекордером.
	sendFn func(addr string, a smtp.Auth, from string, to []string, msg []byte) error
}

var _ Sender = (*EmailSender)(nil)

// NewEmail создаёт SMTP-отправитель. Аутентификация PLAIN, только при
// непустом user. STARTTLS: smtp.SendMail обновляет соединение до TLS,
// как только сервер анонсирует STARTTLS (штатный режим порта 587;
// флаг startTLS отмечает такие конфигурации), а smtp.PlainAuth
// отказывается передавать учётные данные без TLS.
// timeout ограничивает отправку (0 — по умолчанию 10 с).
func NewEmail(host string, port int, startTLS bool, user, pass, from, subject string, timeout time.Duration) Sender {
	return &EmailSender{
		host:     host,
		port:     port,
		startTLS: startTLS,
		user:     user,
		pass:     pass,
		from:     from,
		subject:  subject,
		timeout:  timeout,
		sendFn:   smtp.SendMail,
	}
}

// Name реализует Sender.
func (e *EmailSender) Name() channel.Channel { return channel.Email }

// Send отправляет письмо с кодом получателю to. Отправка выполняется
// в фоне и прерывается по timeout или отмене контекста.
func (e *EmailSender) Send(ctx context.Context, to, code string) error {
	addr := net.JoinHostPort(e.host, strconv.Itoa(e.port))
	var auth smtp.Auth
	if e.user != "" {
		auth = smtp.PlainAuth("", e.user, e.pass, e.host)
	}

	timeout := e.timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	done := make(chan error, 1)
	go func() {
		done <- e.sendFn(addr, auth, e.from, []string{to}, e.buildMessage(to, code))
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("delivery: email: отправка через %s: %w", addr, err)
		}
		return nil
	case <-timer.C:
		return fmt.Errorf("delivery: email: таймаут отправки через %s после %s", addr, timeout)
	case <-ctx.Done():
		return fmt.Errorf("delivery: email: отменено: %w", ctx.Err())
	}
}

// buildMessage собирает MIME-письмо (RFC 5322, CRLF): заголовки
// From/To/Subject/Date/MIME-Version/Content-Type/Content-Transfer-Encoding.
// В теме плейсхолдер {code} заменяется на код, после чего тема
// кодируется кодированным словом RFC 2047 (Q-encoding) — код оказывается
// внутри закодированного слова; тело — по BodyTemplate.
func (e *EmailSender) buildMessage(to, code string) []byte {
	// Кодирование ПОСЛЕ подстановки {code}: цифры кода попадают внутрь
	// закодированного слова.
	subject := mime.QEncoding.Encode("UTF-8", sanitizeHeader(strings.ReplaceAll(e.subject, "{code}", code)))
	body := strings.ReplaceAll(BodyTemplate, "{code}", code)
	var b strings.Builder
	b.WriteString("From: " + sanitizeHeader(e.from) + "\r\n")
	b.WriteString("To: " + sanitizeHeader(to) + "\r\n")
	b.WriteString("Subject: " + subject + "\r\n")
	b.WriteString("Date: " + time.Now().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=\"UTF-8\"\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	b.WriteString("\r\n")
	return []byte(b.String())
}

// sanitizeHeader запрещает вставку CRLF в заголовки письма.
func sanitizeHeader(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}
