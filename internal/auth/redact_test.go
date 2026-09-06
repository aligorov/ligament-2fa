package auth

// Юнит-тесты санитизации текста ошибок для audit-деталей (SEC-003).

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)

func TestRedactErrText(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{
			"nil-ошибка",
			"",
			"",
		},
		{
			"токен бота в URL",
			`telegram: sendMessage api.telegram.org: Post "https://api.telegram.org/bot123:AASecret/sendMessage": dial tcp: lookup`,
			`telegram: sendMessage api.telegram.org: Post "[url]": dial tcp: lookup`,
		},
		{
			"креды шлюза в query",
			`delivery: sms: GET sms.example.com: Get "https://sms.example.com/send?login=SECRET&psw=PASS&mes=654321": context deadline exceeded`,
			`delivery: sms: GET sms.example.com: Get "[url]": context deadline exceeded`,
		},
		{
			"без URL — как есть",
			"connection refused by peer",
			"connection refused by peer",
		},
	}
	for _, tc := range cases {
		if tc.in == "" {
			if got := redactErrText(nil); got != "" {
				t.Fatalf("redactErrText(nil) = %q, want пусто", got)
			}
			continue
		}
		if got := redactErrText(errors.New(tc.in)); got != tc.want {
			t.Fatalf("%s: redactErrText = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// Двойная страховка: хелпер санитизации не зависит от конкретной формы
// ошибки отправителя — прямой вызов с сырым *url.Error.
func TestRedactErrTextURLerror(t *testing.T) {
	ue := &url.Error{
		Op:  "Post",
		URL: "https://api.telegram.org/botSECRETTOKEN/sendMessage",
		Err: errors.New("dial tcp 1.2.3.4:443: connect: connection refused"),
	}
	got := redactErrText(ue)
	if strings.Contains(got, "SECRETTOKEN") {
		t.Fatalf("redactErrText пропустил токен: %q", got)
	}
	if !strings.Contains(got, "connection refused") {
		t.Fatalf("redactErrText съел класс причины: %q", got)
	}
}
