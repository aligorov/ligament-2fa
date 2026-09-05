package delivery

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/aligorov/twofa/internal/channel"
)

func TestLogSender(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(prev)

	s := NewLog()
	if got := s.Name(); got != channel.Channel("log") {
		t.Fatalf("Name() = %q, want \"log\"", got)
	}
	if err := s.Send(context.Background(), "alice@example.com", "123456"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !strings.Contains(buf.String(), "code to alice@example.com: 123456") {
		t.Fatalf("в логе нет ожидаемой строки, got %q", buf.String())
	}
}
