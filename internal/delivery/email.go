package delivery

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/aligorov/twofa/internal/channel"
)

// SMTP-дедлайны: dial ограничен 10 с, весь диалог (greeting + STARTTLS +
// AUTH + MAIL/RCPT/DATA + QUIT) — 30 с на уровне соединения. smtp.SendMail
// не ставит дедлайнов: зависший сервер оставлял вечную горутину и открытый
// коннект на каждую попытку отправки. Переменные (а не константы) — для
// подмены в тестах.
var (
	smtpDialTimeout   = 10 * time.Second
	smtpDialogTimeout = 30 * time.Second
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
	// bodyTpl — шаблон тела письма (messages.email_body; пусто =
	// BodyTemplate); vars — общие переменные шаблона ({ttl}, {domain}).
	bodyTpl string
	vars    map[string]string
	timeout time.Duration

	// adLine возвращает рекламную подпись бесплатной лицензии (""
	// — платная/выключено); вычисляется на КАЖДУЮ отправку — смена
	// лицензии применяется без пересборки.
	adLine func() string

	// sendFn выполняет SMTP-транзакцию; по умолчанию sendSMTP —
	// собственный диалог с дедлайнами (dial 10 с, диалог 30 с).
	// Отдельное поле — чтобы тесты подменяли его рекордером.
	sendFn func(addr string, a smtp.Auth, from string, to []string, msg []byte) error
}

var _ Sender = (*EmailSender)(nil)
var _ AlertSender = (*EmailSender)(nil)

// NewEmail создаёт SMTP-отправитель. Аутентификация PLAIN, только при
// непустом user. STARTTLS: соединение обновляется до TLS, как только
// сервер анонсирует STARTTLS (штатный режим порта 587; флаг startTLS
// отмечает такие конфигурации), а smtp.PlainAuth отказывается передавать
// учётные данные без TLS.
// timeout ограничивает отправку (0 — по умолчанию 10 с).
func NewEmail(host string, port int, startTLS bool, user, pass, from, subject, bodyTpl string, vars map[string]string, adLine func() string, timeout time.Duration) Sender {
	e := &EmailSender{
		adLine:   adLine,
		host:     host,
		port:     port,
		startTLS: startTLS,
		user:     user,
		pass:     pass,
		from:     from,
		subject:  subject,
		bodyTpl:  bodyTpl,
		vars:     vars,
		timeout:  timeout,
	}
	// По умолчанию — собственный SMTP-диалог с дедлайнами (sendSMTP);
	// тесты подменяют sendFn рекордером.
	e.sendFn = e.sendSMTP
	return e
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

// sendSMTP выполняет SMTP-транзакцию с жёсткими дедлайнами — замена
// smtp.SendMail, который не ограничивает ни dial, ни диалог: зависший
// сервер оставлял вечную горутину и открытый коннект. Собственный dial
// через net.Dialer (10 с), затем общий дедлайн всего диалога (30 с)
// ставится на соединение — любой шаг SMTP (greeting, STARTTLS, AUTH,
// MAIL/RCPT/DATA, QUIT) упирается в него. Поведение совпадает с
// smtp.SendMail: STARTTLS при анонсе сервера, PLAIN-аутентификация при
// заданном auth. Сигнатура — как у sendFn (подмена в тестах).
func (e *EmailSender) sendSMTP(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
	// Dial с ограничением по времени (smtp.Dial — без дедлайна).
	conn, err := (&net.Dialer{Timeout: smtpDialTimeout}).Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.Close()
	// Общий потолок диалога от текущего момента (включая уже прошедший dial).
	if err := conn.SetDeadline(time.Now().Add(smtpDialogTimeout)); err != nil {
		return fmt.Errorf("deadline %s: %w", addr, err)
	}
	c, err := smtp.NewClient(conn, e.host)
	if err != nil {
		return err
	}
	defer c.Close()
	// EHLO/HELO — как в smtp.SendMail.
	if err := c.Hello("localhost"); err != nil {
		return err
	}
	// STARTTLS при анонсе сервера (семантика smtp.SendMail): SNI — хост без порта.
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: e.host}); err != nil {
			return err
		}
	}
	if a != nil {
		if ok, _ := c.Extension("AUTH"); !ok {
			return errors.New("smtp: server doesn't support AUTH")
		}
		if err := c.Auth(a); err != nil {
			return err
		}
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// buildMessage собирает MIME-письмо (RFC 5322, CRLF): заголовки
// From/To/Subject/Date/MIME-Version/Content-Type/Content-Transfer-Encoding.
// В теме и теле плейсхолдеры заменяются рендером шаблона ({code} и общие
// переменные), после чего тема кодируется кодированным словом RFC 2047
// (Q-encoding) — код оказывается внутри закодированного слова.
func (e *EmailSender) buildMessage(to, code string) []byte {
	subject := mime.QEncoding.Encode("UTF-8", sanitizeHeader(RenderTemplate(e.subject, code, e.vars)))
	body := RenderTemplate(e.bodyTpl, code, e.vars)
	if e.adLine != nil {
		if ad := e.adLine(); ad != "" {
			body += "\r\n--\r\n" + ad
		}
	}
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

// SendAlert реализует AlertSender: отправляет произвольное текстовое письмо.
func (e *EmailSender) SendAlert(ctx context.Context, to, subject, body string) error {
	return e.SendAlertWithReplyTo(ctx, to, "", subject, body)
}

// SendAlertWithReplyTo реализует AlertSenderReplyTo: отправляет произвольное текстовое письмо с Reply-To.
func (e *EmailSender) SendAlertWithReplyTo(ctx context.Context, to, replyTo, subject, body string) error {
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
		done <- e.sendFn(addr, auth, e.from, []string{to}, e.buildRawMessage(to, replyTo, subject, body))
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("delivery: email alert: отправка через %s: %w", addr, err)
		}
		return nil
	case <-timer.C:
		return fmt.Errorf("delivery: email alert: таймаут отправки через %s после %s", addr, timeout)
	case <-ctx.Done():
		return fmt.Errorf("delivery: email alert: отменено: %w", ctx.Err())
	}
}

func (e *EmailSender) buildRawMessage(to, replyTo, subject, body string) []byte {
	subj := mime.QEncoding.Encode("UTF-8", sanitizeHeader(subject))
	if e.adLine != nil {
		if ad := e.adLine(); ad != "" {
			body += "\r\n--\r\n" + ad
		}
	}
	var b strings.Builder
	b.WriteString("From: " + sanitizeHeader(e.from) + "\r\n")
	b.WriteString("To: " + sanitizeHeader(to) + "\r\n")
	if replyTo != "" {
		b.WriteString("Reply-To: " + sanitizeHeader(replyTo) + "\r\n")
	}
	b.WriteString("Subject: " + subj + "\r\n")
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
