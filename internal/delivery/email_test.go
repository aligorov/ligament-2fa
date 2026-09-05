package delivery

import (
	"context"
	"errors"
	"net/smtp"
	"strings"
	"testing"
	"time"

	"github.com/aligorov/twofa/internal/channel"
)

// mailRecord — аргументы, переданные в sendFn (рекордер SMTP-транзакции).
type mailRecord struct {
	addr string
	auth smtp.Auth
	from string
	to   []string
	msg  []byte
}

// newTestEmail создаёт EmailSender с рекордером вместо smtp.SendMail.
func newTestEmail(subject string, timeout time.Duration) (*EmailSender, *mailRecord) {
	s := NewEmail("smtp.example.com", 587, true, "user", "pass",
		"noreply@example.com", subject, timeout).(*EmailSender)
	rec := &mailRecord{}
	s.sendFn = func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
		*rec = mailRecord{addr: addr, auth: a, from: from, to: to, msg: msg}
		return nil
	}
	return s, rec
}

func TestEmailMessage(t *testing.T) {
	cases := []struct {
		name    string
		subject string
		code    string
	}{
		{"код в теме", "Ваш код: {code}", "555111"},
		{"тема без плейсхолдера", "Подтверждение входа", "090807"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, rec := newTestEmail(tc.subject, time.Minute)
			if err := s.Send(context.Background(), "user@example.com", tc.code); err != nil {
				t.Fatalf("Send: %v", err)
			}
			if rec.addr != "smtp.example.com:587" {
				t.Errorf("addr = %q, want smtp.example.com:587", rec.addr)
			}
			if rec.from != "noreply@example.com" {
				t.Errorf("from = %q, want noreply@example.com", rec.from)
			}
			if len(rec.to) != 1 || rec.to[0] != "user@example.com" {
				t.Errorf("to = %v, want [user@example.com]", rec.to)
			}
			if rec.auth == nil {
				t.Error("auth = nil, want PLAIN-аутентификация (user задан)")
			}

			msg := string(rec.msg)
			wantSubject := strings.ReplaceAll(tc.subject, "{code}", tc.code)
			for _, want := range []string{
				"From: noreply@example.com\r\n",
				"To: user@example.com\r\n",
				"Subject: " + wantSubject + "\r\n",
				"MIME-Version: 1.0\r\n",
				"Content-Type: text/plain; charset=\"UTF-8\"\r\n",
				"\r\n\r\n" + "Ваш код подтверждения: " + tc.code,
			} {
				if !strings.Contains(msg, want) {
					t.Errorf("сообщение не содержит %q:\n%s", want, msg)
				}
			}
			if strings.Contains(msg, "{code}") {
				t.Errorf("в сообщении остался незамещённый {code}:\n%s", msg)
			}
		})
	}
}

func TestEmailName(t *testing.T) {
	s, _ := newTestEmail("s", time.Minute)
	if got := s.Name(); got != channel.Email {
		t.Fatalf("Name() = %q, want %q", got, channel.Email)
	}
}

func TestEmailNoAuthWithoutUser(t *testing.T) {
	s := NewEmail("smtp.example.com", 25, false, "", "",
		"noreply@example.com", "Код", time.Minute).(*EmailSender)
	rec := &mailRecord{}
	s.sendFn = func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
		*rec = mailRecord{addr: addr, auth: a, from: from, to: to, msg: msg}
		return nil
	}
	if err := s.Send(context.Background(), "user@example.com", "1"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if rec.auth != nil {
		t.Errorf("auth = %v, want nil без учётных данных", rec.auth)
	}
}

func TestEmailSendError(t *testing.T) {
	s, _ := newTestEmail("s", time.Minute)
	s.sendFn = func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
		return errors.New("connection refused")
	}
	err := s.Send(context.Background(), "user@example.com", "1")
	if err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("Send err = %v, want ошибка проброса smtp", err)
	}
}

func TestEmailTimeout(t *testing.T) {
	s, _ := newTestEmail("s", 20*time.Millisecond)
	s.sendFn = func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
		time.Sleep(200 * time.Millisecond)
		return nil
	}
	start := time.Now()
	err := s.Send(context.Background(), "user@example.com", "1")
	if err == nil {
		t.Fatal("ожидали ошибку таймаута")
	}
	if !strings.Contains(err.Error(), "таймаут") {
		t.Errorf("ошибка %q не про таймаут", err)
	}
	if elapsed := time.Since(start); elapsed > 150*time.Millisecond {
		t.Errorf("Send ждал %s, а таймаут 20ms", elapsed)
	}
}

func TestEmailCtxCanceled(t *testing.T) {
	s, _ := newTestEmail("s", time.Minute)
	s.sendFn = func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
		time.Sleep(100 * time.Millisecond)
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := s.Send(ctx, "user@example.com", "1")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Send err = %v, want context.Canceled", err)
	}
}
