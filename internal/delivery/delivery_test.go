package delivery

import (
	"context"
	"net/smtp"
	"strings"
	"testing"
	"time"
)

// TestRenderTemplate: переменные подставляются до кода (код не может
// подменить {ttl}/{domain}), пустой шаблон = BodyTemplate, неизвестные
// плейсхолдеры остаются как есть.
func TestRenderTemplate(t *testing.T) {
	vars := map[string]string{"ttl": "5 мин", "domain": "https://2fa.example.com"}
	if got := RenderTemplate("Код {code} на {domain}, действует {ttl}", "123456", vars); got != "Код 123456 на https://2fa.example.com, действует 5 мин" {
		t.Errorf("RenderTemplate = %q", got)
	}
	// Код подставляется последним: значение переменной вида {code} не
	// исполняется.
	if got := RenderTemplate("{code}", "{ttl}", nil); got != "{ttl}" {
		t.Errorf("код раньше переменных: %q", got)
	}
	if got := RenderTemplate("", "42", nil); got != "Ваш код подтверждения: 42" {
		t.Errorf("пустой шаблон = %q, want BodyTemplate", got)
	}
	if got := RenderTemplate("{unknown}", "1", vars); got != "{unknown}" {
		t.Errorf("неизвестный плейсхолдер = %q, want как есть", got)
	}
}

// TestEmailAdFooter: рекламная подпись (бесплатная лицензия) дописывается
// в тело письма отделённой строкой; nil-хук ничего не добавляет.
func TestEmailAdFooter(t *testing.T) {
	rec := &mailRecord{}
	mk := func(ad func() string) Sender {
		s := NewEmail("smtp.example.com", 25, false, "", "",
			"noreply@example.com", "Код", "Код: {code}", nil, ad, time.Minute).(*EmailSender)
		s.sendFn = func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
			*rec = mailRecord{msg: msg}
			return nil
		}
		return s
	}
	if err := mk(func() string { return "Реклама: https://omg10.com/4/1" }).
		Send(context.Background(), "u@example.com", "123456"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !strings.Contains(string(rec.msg), "\r\n--\r\nРеклама: https://omg10.com/4/1") {
		t.Errorf("подпись не дописана:\n%s", rec.msg)
	}
	if err := mk(nil).Send(context.Background(), "u@example.com", "123456"); err != nil {
		t.Fatalf("Send(nil): %v", err)
	}
	if strings.Contains(string(rec.msg), "--\r\nРеклама") {
		t.Error("nil-хук не должен добавлять подпись")
	}
}
