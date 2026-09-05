package telegram

// client_test.go — юнит-тесты Client против fakeAPI: формат запросов,
// разбор ответов и ошибок (429 с retry_after, 403, битое тело).

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewClientDefaults(t *testing.T) {
	c := NewClient("", "tok", nil)
	if c.base != defaultBase {
		t.Errorf("base = %q, want %q", c.base, defaultBase)
	}
	if c.hc.Timeout != 15*time.Second {
		t.Errorf("hc.Timeout = %s, want 15s", c.hc.Timeout)
	}
	if c.sleep == nil {
		t.Error("sleep = nil, want time.Sleep")
	}
	c2 := NewClient("http://example.com", "tok", &http.Client{Timeout: time.Second})
	if c2.base != "http://example.com" || c2.hc.Timeout != time.Second {
		t.Errorf("явные base/hc проигнорированы: %+v", c2)
	}
}

func TestClientSendMessage(t *testing.T) {
	api := newFakeAPI(t, "TOK")
	c := NewClient(api.srv.URL, "TOK", nil)
	ctx := context.Background()

	kb := &InlineKeyboard{InlineKeyboard: [][]InlineButton{
		{{Text: "✅ Подтвердить", CallbackData: "approve:abc"}},
		{{Text: "❌ Это не я", CallbackData: "deny:abc"}},
	}}
	if err := c.sendMessage(ctx, 42, "привет", kb); err != nil {
		t.Fatalf("sendMessage: %v", err)
	}
	_, sent, _, _ := api.snapshot()
	if len(sent) != 1 {
		t.Fatalf("sent = %d записей, want 1", len(sent))
	}
	m := sent[0]
	if m["chat_id"] != float64(42) || m["text"] != "привет" {
		t.Errorf("sendMessage тело = %v", m)
	}
	kbm, ok := m["reply_markup"].(map[string]any)
	if !ok {
		t.Fatalf("reply_markup отсутствует: %v", m)
	}
	rows := kbm["inline_keyboard"].([]any)
	if len(rows) != 2 {
		t.Fatalf("inline_keyboard строк = %d, want 2", len(rows))
	}
	btn := rows[0].([]any)[0].(map[string]any)
	if btn["text"] != "✅ Подтвердить" || btn["callback_data"] != "approve:abc" {
		t.Errorf("кнопка = %v", btn)
	}

	// Без клавиатуры reply_markup не отправляется вовсе.
	if err := c.sendMessage(ctx, 42, "ещё", nil); err != nil {
		t.Fatalf("sendMessage: %v", err)
	}
	_, sent, _, _ = api.snapshot()
	if _, has := sent[1]["reply_markup"]; has {
		t.Errorf("reply_markup должен отсутствовать при nil: %v", sent[1])
	}
}

func TestClientAnswerAndEdit(t *testing.T) {
	api := newFakeAPI(t, "TOK")
	c := NewClient(api.srv.URL, "TOK", nil)
	ctx := context.Background()

	if err := c.answerCallbackQuery(ctx, "cb1", "готово", true); err != nil {
		t.Fatalf("answerCallbackQuery: %v", err)
	}
	if err := c.editMessageText(ctx, 42, 7, "итог"); err != nil {
		t.Fatalf("editMessageText: %v", err)
	}
	_, _, answers, edits := api.snapshot()
	if len(answers) != 1 || answers[0]["callback_query_id"] != "cb1" ||
		answers[0]["text"] != "готово" || answers[0]["show_alert"] != true {
		t.Errorf("answerCallbackQuery тело = %v", answers[0])
	}
	if len(edits) != 1 || edits[0]["chat_id"] != float64(42) ||
		edits[0]["message_id"] != float64(7) || edits[0]["text"] != "итог" {
		t.Errorf("editMessageText тело = %v", edits[0])
	}
}

func TestClientGetUpdatesParses(t *testing.T) {
	api := newFakeAPI(t, "TOK")
	api.pushUpdate(`{"update_id":11,"message":{"chat":{"id":42},"text":"ab12-cd34"}}`)
	api.pushUpdate(`{"update_id":12,"callback_query":{"id":"cb9","from":{"id":42},` +
		`"message":{"message_id":7,"chat":{"id":42}},"data":"approve:uuid-1"}}`)

	c := NewClient(api.srv.URL, "TOK", nil)
	ups, err := c.getUpdates(context.Background(), 11)
	if err != nil {
		t.Fatalf("getUpdates: %v", err)
	}
	if len(ups) != 2 {
		t.Fatalf("updates = %d, want 2", len(ups))
	}
	if ups[0].UpdateID != 11 || ups[0].Message == nil ||
		ups[0].Message.Chat.ID != 42 || ups[0].Message.Text != "ab12-cd34" {
		t.Errorf("update[0] = %+v", ups[0])
	}
	cq := ups[1].CallbackQuery
	if cq == nil || cq.ID != "cb9" || cq.From.ID != 42 ||
		cq.Message == nil || cq.Message.MessageID != 7 ||
		cq.Message.Chat.ID != 42 || cq.Data != "approve:uuid-1" {
		t.Errorf("update[1].callback_query = %+v", cq)
	}

	getReqs, _, _, _ := api.snapshot()
	if len(getReqs) != 1 {
		t.Fatalf("getUpdates запросов = %d, want 1", len(getReqs))
	}
	r := getReqs[0]
	if r.Offset != 11 || r.Timeout != pollTimeout {
		t.Errorf("getUpdates req = %+v, want offset 11 timeout %d", r, pollTimeout)
	}
	if len(r.AllowedUpdates) != 2 || r.AllowedUpdates[0] != "message" || r.AllowedUpdates[1] != "callback_query" {
		t.Errorf("allowed_updates = %v", r.AllowedUpdates)
	}
}

func TestClient429(t *testing.T) {
	api := newFakeAPI(t, "TOK")
	api.setFail(429, 7, false)
	c := NewClient(api.srv.URL, "TOK", nil)

	_, err := c.getUpdates(context.Background(), 0)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want *APIError", err)
	}
	if apiErr.Code != 429 || apiErr.RetryAfter != 7 {
		t.Errorf("APIError = %+v, want code 429 retry_after 7", apiErr)
	}
}

func TestClient403(t *testing.T) {
	api := newFakeAPI(t, "TOK")
	api.setFail(403, 0, false)
	c := NewClient(api.srv.URL, "TOK", nil)

	_, err := c.getUpdates(context.Background(), 0)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != 403 || apiErr.RetryAfter != 0 {
		t.Fatalf("err = %v (%+v), want 403 без retry_after", err, apiErr)
	}
}

func TestClientBrokenBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("gateway garbage"))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "TOK", nil)
	_, err := c.getUpdates(context.Background(), 0)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want *APIError", err)
	}
	if apiErr.Code != http.StatusInternalServerError {
		t.Errorf("code = %d, want 500", apiErr.Code)
	}
}
