// Package telegram — бот Telegram: приём кодов привязки и push-подтверждений
// входа (Bot API 10.3 поверх net/http, без внешних библиотек).
package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// defaultBase — адрес Bot API по умолчанию.
const defaultBase = "https://api.telegram.org"

// maxResponseBytes — предел чтения тела ответа Bot API (1 МиБ).
const maxResponseBytes = 1 << 20

// pollTimeout — таймаут long polling getUpdates (секунды). HTTP-клиент бота
// создаётся с таймаутом больше этого значения (60 с).
const pollTimeout = 50

// Client — минимальный клиент Bot API: getUpdates/sendMessage/
// answerCallbackQuery/editMessageText.
type Client struct {
	base  string
	token string
	hc    *http.Client
	// sleep — пауза (429/троттлинг); поле вынесено, чтобы тесты подменяли
	// его рекордером вместо реального ожидания.
	sleep func(time.Duration)
}

// NewClient создаёт клиент. base "" → https://api.telegram.org; hc nil →
// клиент с таймаутом 15 с (для long polling передайте клиент с таймаутом
// больше pollTimeout — Bot.New делает это сам).
func NewClient(base, token string, hc *http.Client) *Client {
	if base == "" {
		base = defaultBase
	}
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	return &Client{base: base, token: token, hc: hc, sleep: time.Sleep}
}

// APIError — ответ Bot API с ok=false (429, 403 и т.п.).
type APIError struct {
	Code        int // error_code (совпадает с HTTP-статусом)
	Description string
	RetryAfter  int // секунды из parameters.retry_after (только для 429)
}

func (e *APIError) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("telegram: api error %d: %s (retry_after=%ds)", e.Code, e.Description, e.RetryAfter)
	}
	return fmt.Sprintf("telegram: api error %d: %s", e.Code, e.Description)
}

// apiResponse — конверт ответа Bot API.
type apiResponse struct {
	OK          bool            `json:"ok"`
	Result      json.RawMessage `json:"result"`
	ErrorCode   int             `json:"error_code"`
	Description string          `json:"description"`
	Parameters  *struct {
		RetryAfter int `json:"retry_after"`
	} `json:"parameters"`
}

// call выполняет POST <base>/bot<token>/<method> с JSON-телом req и
// разбирает конверт; при успехе result декодируется в out (если не nil).
func (c *Client) call(ctx context.Context, method string, req any, out any) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("telegram: кодирование %s: %w", method, err)
	}
	url := fmt.Sprintf("%s/bot%s/%s", c.base, c.token, method)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("telegram: запрос %s: %w", method, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(httpReq)
	if err != nil {
		return fmt.Errorf("telegram: вызов %s: %w", method, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("telegram: чтение ответа %s: %w", method, err)
	}
	var env apiResponse
	if jerr := json.Unmarshal(raw, &env); jerr != nil || !env.OK {
		apiErr := &APIError{Code: env.ErrorCode, Description: env.Description}
		if apiErr.Code == 0 {
			apiErr.Code = resp.StatusCode
			apiErr.Description = string(bytes.TrimSpace(raw))
		}
		if env.Parameters != nil {
			apiErr.RetryAfter = env.Parameters.RetryAfter
		}
		return apiErr
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(env.Result, out); err != nil {
		return fmt.Errorf("telegram: разбор result %s: %w", method, err)
	}
	return nil
}

// Update — обновление long polling'а: только поля, используемые ботом
// (текст сообщения и нажатия inline-кнопок).
type Update struct {
	UpdateID int64 `json:"update_id"`
	Message  *struct {
		Chat struct {
			ID int64 `json:"id"`
		} `json:"chat"`
		Text string `json:"text"`
	} `json:"message"`
	CallbackQuery *struct {
		ID   string `json:"id"`
		From struct {
			ID int64 `json:"id"`
		} `json:"from"`
		Message *struct {
			MessageID int64 `json:"message_id"`
			Chat      struct {
				ID int64 `json:"id"`
			} `json:"chat"`
		} `json:"message"`
		Data string `json:"data"`
	} `json:"callback_query"`
}

// getUpdates — одна итерация long polling: offset = last update_id+1,
// timeout 50 с, только message и callback_query.
func (c *Client) getUpdates(ctx context.Context, offset int64) ([]Update, error) {
	req := map[string]any{
		"offset":          offset,
		"timeout":         pollTimeout,
		"allowed_updates": []string{"message", "callback_query"},
	}
	var ups []Update
	if err := c.call(ctx, "getUpdates", req, &ups); err != nil {
		return nil, err
	}
	return ups, nil
}

// InlineButton — кнопка inline-клавиатуры; callback_data ≤ 64 байт.
type InlineButton struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data"`
}

// InlineKeyboard — inline-клавиатура сообщения.
type InlineKeyboard struct {
	InlineKeyboard [][]InlineButton `json:"inline_keyboard"`
}

// sendMessage отправляет текст (с необязательной клавиатурой) в чат.
func (c *Client) sendMessage(ctx context.Context, chatID int64, text string, kb *InlineKeyboard) error {
	req := struct {
		ChatID      int64           `json:"chat_id"`
		Text        string          `json:"text"`
		ReplyMarkup *InlineKeyboard `json:"reply_markup,omitempty"`
	}{ChatID: chatID, Text: text, ReplyMarkup: kb}
	return c.call(ctx, "sendMessage", req, nil)
}

// answerCallbackQuery закрывает спиннер нажатой кнопки (вызывать всегда).
func (c *Client) answerCallbackQuery(ctx context.Context, id, text string, alert bool) error {
	req := struct {
		CallbackQueryID string `json:"callback_query_id"`
		Text            string `json:"text,omitempty"`
		ShowAlert       bool   `json:"show_alert,omitempty"`
	}{CallbackQueryID: id, Text: text, ShowAlert: alert}
	return c.call(ctx, "answerCallbackQuery", req, nil)
}

// editMessageText заменяет текст уже отправленного сообщения (итог нажатия).
func (c *Client) editMessageText(ctx context.Context, chatID, msgID int64, text string) error {
	req := struct {
		ChatID    int64  `json:"chat_id"`
		MessageID int64  `json:"message_id"`
		Text      string `json:"text"`
	}{ChatID: chatID, MessageID: msgID, Text: text}
	return c.call(ctx, "editMessageText", req, nil)
}
