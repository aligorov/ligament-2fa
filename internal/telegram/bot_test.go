package telegram

// bot_test.go — юнит-тесты Bot: привязка по коду, approve/deny, двойное
// нажатие, SendPush/Send, 429 с паузой, пустой токен, смещение offset.
// Хранилище и настройки подменяются фейками (store требует PostgreSQL).

import (
	"bytes"
	"context"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/aligorov/twofa/internal/channel"
	"github.com/aligorov/twofa/internal/secrets"
	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
)

// ---- фейковое хранилище (реализует storeDeps) ----

type auditRec struct {
	username, event, result string
	detail                  map[string]any
}

type fakeStore struct {
	mu         sync.Mutex
	challenges map[uuid.UUID]*store.Challenge
	users      map[uuid.UUID]*store.User
	audits     []auditRec
	setPushN   int // вызовы ChallengeSetPush
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		challenges: make(map[uuid.UUID]*store.Challenge),
		users:      make(map[uuid.UUID]*store.User),
	}
}

func (f *fakeStore) ChallengeGet(_ context.Context, id uuid.UUID) (*store.Challenge, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ch, ok := f.challenges[id]; ok {
		cp := *ch
		return &cp, nil
	}
	return nil, store.ErrNotFound
}

func (f *fakeStore) ChallengeMarkUsed(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	ch, ok := f.challenges[id]
	if !ok || ch.UsedAt != nil {
		return store.ErrNotFound
	}
	now := time.Now()
	ch.UsedAt = &now
	return nil
}

func (f *fakeStore) ChallengeSetPush(_ context.Context, id uuid.UUID, state string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	ch, ok := f.challenges[id]
	if !ok {
		return store.ErrNotFound
	}
	f.setPushN++
	ch.PushState = &state
	return nil
}

func (f *fakeStore) UserByID(_ context.Context, id uuid.UUID) (*store.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if u, ok := f.users[id]; ok {
		cp := *u
		if cp.TelegramChatID != nil {
			cid := *cp.TelegramChatID
			cp.TelegramChatID = &cid
		}
		return &cp, nil
	}
	return nil, store.ErrNotFound
}

func (f *fakeStore) UserUpdate(_ context.Context, u *store.User) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := *u
	if cp.TelegramChatID != nil {
		cid := *cp.TelegramChatID
		cp.TelegramChatID = &cid
	}
	f.users[u.ID] = &cp
	return nil
}

func (f *fakeStore) Audit(_ context.Context, username, event string, detail map[string]any, _, result string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.audits = append(f.audits, auditRec{username, event, result, detail})
	return nil
}

// findLink — подмена прямого SQL: активный tg_link-челлендж по хешу кода.
func (f *fakeStore) findLink(_ context.Context, codeHash []byte) (*store.Challenge, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, ch := range f.challenges {
		if ch.Purpose == "tg_link" && ch.UsedAt == nil &&
			ch.ExpiresAt.After(time.Now()) && bytes.Equal(ch.CodeHash, codeHash) {
			cp := *ch
			return &cp, nil
		}
	}
	return nil, store.ErrNotFound
}

// snapshot возвращает копии состояния для проверок.
func (f *fakeStore) snapshot() (users map[uuid.UUID]*store.User, challenges map[uuid.UUID]*store.Challenge, audits []auditRec, setPushN int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	users = make(map[uuid.UUID]*store.User, len(f.users))
	for k, v := range f.users {
		cp := *v
		users[k] = &cp
	}
	challenges = make(map[uuid.UUID]*store.Challenge, len(f.challenges))
	for k, v := range f.challenges {
		cp := *v
		challenges[k] = &cp
	}
	return users, challenges, append([]auditRec{}, f.audits...), f.setPushN
}

// ---- фейковые настройки (реализуют settingsDeps) ----

type fakeSettings struct{ t *settings.T }

func (f fakeSettings) Get() *settings.T { return f.t }

// ---- сборка тестового бота ----

// newTestBot создаёт бота на fakeAPI с фейковым хранилищем; sleep подменён
// на мгновенный (отдельные тесты ставят рекордер).
func newTestBot(t *testing.T, token string, fs *fakeStore) (*Bot, *fakeAPI) {
	t.Helper()
	api := newFakeAPI(t, token)
	cl := NewClient(api.srv.URL, token, nil)
	cl.sleep = func(time.Duration) {}
	b := &Bot{
		cl:       cl,
		st:       fs,
		set:      fakeSettings{&settings.T{}},
		findLink: fs.findLink,
		lastSent: make(map[int64]time.Time),
	}
	return b, api
}

// runBot запускает Run в горутине; возвращённая stop отменяет контекст и
// ждёт nil-возврата. Отмена также зарегистрирована в Cleanup — упавший
// тест не оставляет крутиться цикл бота.
func runBot(t *testing.T, b *Bot) (stop func() error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	once := sync.Once{}
	go func() { done <- b.Run(ctx) }()
	return func() error {
		var err error
		once.Do(func() {
			cancel()
			select {
			case err = <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("Run не завершился за 2с после отмены ctx")
			}
		})
		return err
	}
}

// sentTexts собирает тексты всех sendMessage.
func sentTexts(sent []map[string]any) []string {
	out := make([]string, 0, len(sent))
	for _, m := range sent {
		out = append(out, m["text"].(string))
	}
	return out
}

// addLinkUser кладёт пользователя и активный tg_link-челлендж с данным кодом.
func addLinkUser(fs *fakeStore, username, code string) (uuid.UUID, uuid.UUID) {
	uid, cid := uuid.New(), uuid.New()
	fs.users[uid] = &store.User{ID: uid, Username: username, Enabled: true}
	fs.challenges[cid] = &store.Challenge{
		ID: cid, UserID: uid, Channel: channel.Telegram,
		CodeHash: secrets.SHA256(code), ExpiresAt: time.Now().Add(10 * time.Minute),
		AttemptsLeft: 3, Purpose: "tg_link",
	}
	return uid, cid
}

// ---- привязка по коду ----

func TestLinkFlow(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{"код с пробелами и нижним регистром", "  ab12-cd34  "},
		{"/start deep-link", "/start AB12-CD34"},
		{"просто код", "AB12-CD34"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := newFakeStore()
			uid, cid := addLinkUser(fs, "alice", "AB12-CD34")
			b, api := newTestBot(t, "TOK", fs)
			api.pushUpdate(`{"update_id":1,"message":{"chat":{"id":42},"text":"` + tc.text + `"}}`)

			stop := runBot(t, b)
			waitFor(t, "ответ '✅ Telegram привязан'", func() bool {
				_, sent, _, _ := api.snapshot()
				for _, txt := range sentTexts(sent) {
					if txt == "✅ Telegram привязан" {
						return true
					}
				}
				return false
			})
			if err := stop(); err != nil {
				t.Fatalf("Run: %v", err)
			}

			users, challenges, audits, _ := fs.snapshot()
			if got := users[uid].TelegramChatID; got == nil || *got != 42 {
				t.Errorf("telegram_chat_id = %v, want 42", got)
			}
			if ch := challenges[cid]; ch.UsedAt == nil {
				t.Error("челлендж не помечен использованным")
			}
			if len(audits) != 1 || audits[0].username != "alice" ||
				audits[0].event != "tg_link" || audits[0].result != "ok" {
				t.Errorf("аудит = %+v, want один tg_link ok для alice", audits)
			}
		})
	}
}

func TestLinkWrongCode(t *testing.T) {
	fs := newFakeStore()
	uid, _ := addLinkUser(fs, "alice", "AB12-CD34")
	b, api := newTestBot(t, "TOK", fs)
	api.pushUpdate(`{"update_id":1,"message":{"chat":{"id":42},"text":"ZZZZ-ZZZZ"}}`)

	stop := runBot(t, b)
	waitFor(t, "ответ 'код не найден'", func() bool {
		_, sent, _, _ := api.snapshot()
		for _, txt := range sentTexts(sent) {
			if txt == "❌ Код не найден или истёк" {
				return true
			}
		}
		return false
	})
	if err := stop(); err != nil {
		t.Fatalf("Run: %v", err)
	}

	users, _, audits, _ := fs.snapshot()
	if users[uid].TelegramChatID != nil {
		t.Error("чат привязан по неверному коду")
	}
	if len(audits) != 0 {
		t.Errorf("аудит не пуст: %+v", audits)
	}
}

func TestLinkReplay(t *testing.T) {
	fs := newFakeStore()
	addLinkUser(fs, "alice", "AB12-CD34")
	b, api := newTestBot(t, "TOK", fs)
	api.pushUpdate(`{"update_id":1,"message":{"chat":{"id":42},"text":"AB12-CD34"}}`)
	api.pushUpdate(`{"update_id":2,"message":{"chat":{"id":99},"text":"AB12-CD34"}}`)

	stop := runBot(t, b)
	waitFor(t, "два ответа на повторный код", func() bool {
		_, sent, _, _ := api.snapshot()
		ok, fail := 0, 0
		for _, txt := range sentTexts(sent) {
			switch txt {
			case "✅ Telegram привязан":
				ok++
			case "❌ Код не найден или истёк":
				fail++
			}
		}
		return ok == 1 && fail == 1
	})
	if err := stop(); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestLinkEmptyCodeHint(t *testing.T) {
	fs := newFakeStore()
	b, api := newTestBot(t, "TOK", fs)
	api.pushUpdate(`{"update_id":1,"message":{"chat":{"id":42},"text":"/start"}}`)

	stop := runBot(t, b)
	waitFor(t, "подсказка о формате кода", func() bool {
		_, sent, _, _ := api.snapshot()
		for _, txt := range sentTexts(sent) {
			if txt == "Отправьте код привязки вида XXXX-XXXX" {
				return true
			}
		}
		return false
	})
	if err := stop(); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

// ---- push-подтверждения ----

// addPushUser кладёт пользователя и pending push-челлендж; возвращает id.
func addPushUser(fs *fakeStore, username string) (uid, cid uuid.UUID) {
	uid, cid = uuid.New(), uuid.New()
	fs.users[uid] = &store.User{ID: uid, Username: username, Enabled: true}
	pending := "pending"
	fs.challenges[cid] = &store.Challenge{
		ID: cid, UserID: uid, Channel: channel.TelegramPush,
		PushState: &pending, ExpiresAt: time.Now().Add(time.Minute), Purpose: "api",
	}
	return uid, cid
}

func pushCallback(id int64, cid uuid.UUID, action string) string {
	return `{"update_id":` + strconv.FormatInt(id, 10) + `,"callback_query":{"id":"cb1","from":{"id":42},` +
		`"message":{"message_id":7,"chat":{"id":42}},"data":"` + action + `:` + cid.String() + `"}}`
}

func TestCallbackApproveDeny(t *testing.T) {
	for _, tc := range []struct {
		action, wantState, wantText, wantResult string
	}{
		{"approve", "approved", "✅ Вход подтверждён", "approved"},
		{"deny", "denied", "🚫 Вход отклонён", "denied"},
	} {
		t.Run(tc.action, func(t *testing.T) {
			fs := newFakeStore()
			_, cid := addPushUser(fs, "bob")
			b, api := newTestBot(t, "TOK", fs)
			api.pushUpdate(pushCallback(1, cid, tc.action))

			stop := runBot(t, b)
			waitFor(t, "edit с итогом", func() bool {
				_, _, _, edits := api.snapshot()
				for _, m := range edits {
					if m["text"] == tc.wantText {
						return true
					}
				}
				return false
			})
			if err := stop(); err != nil {
				t.Fatalf("Run: %v", err)
			}

			_, challenges, audits, setPushN := fs.snapshot()
			if got := challenges[cid].PushState; got == nil || *got != tc.wantState {
				t.Errorf("push_state = %v, want %s", got, tc.wantState)
			}
			if setPushN != 1 {
				t.Errorf("ChallengeSetPush вызовов = %d, want 1", setPushN)
			}
			if len(audits) != 1 || audits[0].event != "tg_push" ||
				audits[0].result != tc.wantResult || audits[0].username != "bob" {
				t.Errorf("аудит = %+v", audits)
			}
			// answerCallbackQuery отправляется ПОСЛЕ editMessageText и
			// аудита — ждём сам вызов, а не предшествующий ему edit
			// (фикс гонки ожидания).
			waitFor(t, "answerCallbackQuery", func() bool {
				_, _, answers, _ := api.snapshot()
				return len(answers) == 1
			})
			_, _, answers, _ := api.snapshot()
			if len(answers) != 1 || answers[0]["callback_query_id"] != "cb1" {
				t.Errorf("answerCallbackQuery = %v, want всегда cb1", answers)
			}
		})
	}
}

func TestCallbackDoublePress(t *testing.T) {
	fs := newFakeStore()
	_, cid := addPushUser(fs, "bob")
	approved := "approved" // первый ответ уже обработал вход
	fs.challenges[cid].PushState = &approved
	b, api := newTestBot(t, "TOK", fs)
	api.pushUpdate(pushCallback(1, cid, "approve"))

	stop := runBot(t, b)
	waitFor(t, "edit 'уже обработано'", func() bool {
		_, _, _, edits := api.snapshot()
		for _, m := range edits {
			if m["text"] == "⏳ Уже обработано" {
				return true
			}
		}
		return false
	})
	if err := stop(); err != nil {
		t.Fatalf("Run: %v", err)
	}

	_, _, _, setPushN := fs.snapshot()
	if setPushN != 0 {
		t.Errorf("ChallengeSetPush вызовов = %d, want 0 (повторное нажатие)", setPushN)
	}
	// Ответ кнопке приходит после edit — ждём его, а не edit (фикс гонки).
	waitFor(t, "answerCallbackQuery на повторное нажатие", func() bool {
		_, _, answers, _ := api.snapshot()
		return len(answers) == 1
	})
	_, _, answers, _ := api.snapshot()
	if len(answers) != 1 {
		t.Errorf("answerCallbackQuery вызовов = %d, want 1 (всегда)", len(answers))
	}
}

func TestCallbackUnknownData(t *testing.T) {
	fs := newFakeStore()
	b, api := newTestBot(t, "TOK", fs)
	api.pushUpdate(`{"update_id":1,"callback_query":{"id":"cb2","from":{"id":42},` +
		`"message":{"message_id":7,"chat":{"id":42}},"data":"мусор"}}`)

	stop := runBot(t, b)
	waitFor(t, "answerCallbackQuery на мусорный data", func() bool {
		_, _, answers, _ := api.snapshot()
		return len(answers) == 1
	})
	if err := stop(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	_, _, _, edits := api.snapshot()
	if len(edits) != 0 {
		t.Errorf("editMessageText не должно быть: %v", edits)
	}
}

// ---- доставка кода и push-сообщения ----

func TestSendPushKeyboard(t *testing.T) {
	fs := newFakeStore()
	b, api := newTestBot(t, "TOK", fs)
	cid := uuid.New()

	err := b.SendPush(context.Background(), 42, "alice", "1.2.3.4", "Mozilla/5.0", cid)
	if err != nil {
		t.Fatalf("SendPush: %v", err)
	}
	_, sent, _, _ := api.snapshot()
	if len(sent) != 1 {
		t.Fatalf("sent = %d, want 1", len(sent))
	}
	m := sent[0]
	if m["chat_id"] != float64(42) {
		t.Errorf("chat_id = %v, want 42", m["chat_id"])
	}
	text := m["text"].(string)
	for _, want := range []string{"🔑 Подтверждение входа", "alice", "1.2.3.4", "Mozilla/5.0", "Время:"} {
		if !contains(text, want) {
			t.Errorf("текст %q не содержит %q", text, want)
		}
	}
	kb := m["reply_markup"].(map[string]any)
	rows := kb["inline_keyboard"].([]any)
	if len(rows) != 2 {
		t.Fatalf("строк клавиатуры = %d, want 2", len(rows))
	}
	approve := rows[0].([]any)[0].(map[string]any)
	deny := rows[1].([]any)[0].(map[string]any)
	if approve["callback_data"] != "approve:"+cid.String() ||
		deny["callback_data"] != "deny:"+cid.String() {
		t.Errorf("callback_data = %v / %v, want approve/deny:%s",
			approve["callback_data"], deny["callback_data"], cid)
	}
	if len(approve["callback_data"].(string)) > 64 {
		t.Errorf("callback_data длиннее 64 байт: %v", approve["callback_data"])
	}
}

func TestSendDeliversCode(t *testing.T) {
	fs := newFakeStore()
	b, api := newTestBot(t, "TOK", fs)

	if err := b.Send(context.Background(), " 42 ", "654321"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	_, sent, _, _ := api.snapshot()
	if len(sent) != 1 {
		t.Fatalf("sent = %d, want 1", len(sent))
	}
	// Текст — дефолтный шаблон messages.telegram_code_text (тест-бот без
	// менеджера настроек → fallback-константа), код подставлен.
	wantText := "🔑 Код подтверждения: 654321\nДействителен ?. Никому не сообщайте код."
	if sent[0]["chat_id"] != float64(42) || sent[0]["text"] != wantText {
		t.Errorf("sendMessage = %v", sent[0])
	}
	if b.Name() != channel.Telegram {
		t.Errorf("Name = %s, want telegram", b.Name())
	}

	if err := b.Send(context.Background(), "не-число", "1"); err == nil {
		t.Error("Send с нечисловым chat id должен вернуть ошибку")
	}
}

// ---- устойчивость цикла и offset ----

func TestRun429SleepsAndRetries(t *testing.T) {
	fs := newFakeStore()
	b, api := newTestBot(t, "TOK", fs)

	var mu sync.Mutex
	var sleeps []time.Duration
	b.cl.sleep = func(d time.Duration) {
		mu.Lock()
		sleeps = append(sleeps, d)
		mu.Unlock()
	}

	api.setFail(429, 2, true) // первый getUpdates → 429, дальше ок
	api.pushUpdate(`{"update_id":1,"message":{"chat":{"id":42},"text":"/start"}}`)

	stop := runBot(t, b)
	waitFor(t, "бот продолжил после 429", func() bool {
		_, sent, _, _ := api.snapshot()
		return len(sent) == 1
	})
	if err := stop(); err != nil {
		t.Fatalf("Run: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	found := false
	for _, d := range sleeps {
		if d == 3*time.Second { // retry_after 2 + 1
			found = true
		}
	}
	if !found {
		t.Errorf("пауза 3с (retry_after 2 + 1) не зафиксирована: %v", sleeps)
	}
}

func TestRun403Pause(t *testing.T) {
	fs := newFakeStore()
	b, api := newTestBot(t, "TOK", fs)

	var mu sync.Mutex
	var sleeps []time.Duration
	b.cl.sleep = func(d time.Duration) {
		mu.Lock()
		sleeps = append(sleeps, d)
		mu.Unlock()
	}
	api.setFail(403, 0, true)
	api.pushUpdate(`{"update_id":1,"message":{"chat":{"id":42},"text":"/start"}}`)

	stop := runBot(t, b)
	waitFor(t, "бот продолжил после 403", func() bool {
		_, sent, _, _ := api.snapshot()
		return len(sent) == 1
	})
	if err := stop(); err != nil {
		t.Fatalf("Run: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	found := false
	for _, d := range sleeps {
		if d == 60*time.Second {
			found = true
		}
	}
	if !found {
		t.Errorf("пауза 60с после 403 не зафиксирована: %v", sleeps)
	}
}

func TestRunTokenEmpty(t *testing.T) {
	// Через New(nil, nil): пустой токен из отсутствующих настроек.
	b := New(nil, nil)
	if err := b.Run(context.Background()); err != nil {
		t.Fatalf("Run с пустым токеном: %v, want nil", err)
	}

	// Напрямую: бот с пустым токеном не делает ни одного запроса.
	fs := newFakeStore()
	b2, api := newTestBot(t, "", fs)
	if err := b2.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v, want nil", err)
	}
	getReqs, sent, answers, edits := api.snapshot()
	if len(getReqs)+len(sent)+len(answers)+len(edits) != 0 {
		t.Errorf("выключенный бот сделал запросы: %d/%d/%d/%d",
			len(getReqs), len(sent), len(answers), len(edits))
	}
}

func TestRunOffsetAdvances(t *testing.T) {
	fs := newFakeStore()
	b, api := newTestBot(t, "TOK", fs)
	api.pushUpdate(`{"update_id":1,"message":{"chat":{"id":42},"text":"/start"}}`)
	api.pushUpdate(`{"update_id":2,"message":{"chat":{"id":43},"text":"/start"}}`)

	stop := runBot(t, b)
	waitFor(t, "оба сообщения обработаны по одному разу", func() bool {
		_, sent, _, _ := api.snapshot()
		return len(sent) == 2
	})
	// Дождаться следующего getUpdates с новым offset.
	waitFor(t, "offset дошёл до 3", func() bool {
		getReqs, _, _, _ := api.snapshot()
		return len(getReqs) >= 2 && getReqs[len(getReqs)-1].Offset == 3
	})
	if err := stop(); err != nil {
		t.Fatalf("Run: %v", err)
	}

	getReqs, sent, _, _ := api.snapshot()
	if len(getReqs) == 0 || getReqs[0].Offset != 0 {
		t.Errorf("первый offset = %v, want 0", getReqs)
	}
	if last := getReqs[len(getReqs)-1].Offset; last != 3 {
		t.Errorf("последний offset = %d, want 3 (нет дублей обработки)", last)
	}
	if len(sent) != 2 {
		t.Errorf("ответов = %d, want 2 (каждое обновление один раз)", len(sent))
	}
}

// ---- генерация кода привязки ----

func TestGenerateLinkCode(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 200; i++ {
		c := GenerateLinkCode()
		if len(c) != 9 || c[4] != '-' {
			t.Fatalf("код %q не в формате XXXX-XXXX", c)
		}
		for _, r := range c {
			if r == '-' {
				continue
			}
			if !bytes.ContainsRune([]byte("ABCDEFGHJKLMNPQRSTUVWXYZ23456789"), r) {
				t.Fatalf("код %q содержит недопустимый символ %q (0/O/1/I запрещены)", c, r)
			}
		}
		if seen[c] {
			t.Fatalf("повтор кода %q — генератор не случайный", c)
		}
		seen[c] = true
	}
}

func contains(s, sub string) bool {
	return bytes.Contains([]byte(s), []byte(sub))
}

// TestLinkRelinkNotifiesOldChat (SEC-002): перепривязка аккаунта на новый
// чат отправляет старому чату уведомление «Telegram отвязан…» ДО
// перезаписи telegram_chat_id.
func TestLinkRelinkNotifiesOldChat(t *testing.T) {
	fs := newFakeStore()
	uid, _ := addLinkUser(fs, "carol", "AB12-CD34")
	old := int64(100)
	fs.users[uid].TelegramChatID = &old
	b, api := newTestBot(t, "TOK", fs)
	api.pushUpdate(`{"update_id":1,"message":{"chat":{"id":12345},"text":"AB12-CD34"}}`)

	stop := runBot(t, b)
	waitFor(t, "уведомление старому чату + подтверждение новому", func() bool {
		_, sent, _, _ := api.snapshot()
		notified, linked := false, false
		for _, m := range sent {
			switch m["chat_id"] {
			case float64(100):
				if txt, _ := m["text"].(string); strings.Contains(txt, "отвязан от аккаунта carol") &&
					strings.Contains(txt, "смените пароль") {
					notified = true
				}
			case float64(12345):
				if m["text"] == "✅ Telegram привязан" {
					linked = true
				}
			}
		}
		return notified && linked
	})
	if err := stop(); err != nil {
		t.Fatalf("Run: %v", err)
	}

	users, _, _, _ := fs.snapshot()
	if got := users[uid].TelegramChatID; got == nil || *got != 12345 {
		t.Errorf("telegram_chat_id = %v, want 12345", got)
	}
}

// TestLinkSameChatNoNotification: повторная привязка ТОГО ЖЕ чата не
// рассылает «отвязан» (это просто обновление кода).
func TestLinkSameChatNoNotification(t *testing.T) {
	fs := newFakeStore()
	uid, _ := addLinkUser(fs, "dave", "AB12-CD34")
	same := int64(42)
	fs.users[uid].TelegramChatID = &same
	b, api := newTestBot(t, "TOK", fs)
	api.pushUpdate(`{"update_id":1,"message":{"chat":{"id":42},"text":"AB12-CD34"}}`)

	stop := runBot(t, b)
	waitFor(t, "подтверждение привязки", func() bool {
		_, sent, _, _ := api.snapshot()
		for _, txt := range sentTexts(sent) {
			if txt == "✅ Telegram привязан" {
				return true
			}
		}
		return false
	})
	if err := stop(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	_, sent, _, _ := api.snapshot()
	for _, txt := range sentTexts(sent) {
		if strings.Contains(txt, "отвязан") {
			t.Errorf("уведомление об отвязке при привязке того же чата: %q", txt)
		}
	}
}

// ---- аудит раунд-2, N8: закрытые челленджи не аппрувятся ----

// TestCallbackExpiredPush: просроченный push-челлендж не аппрувится —
// бот редактирует сообщение («истёк») и не трогает push_state/аудит.
func TestCallbackExpiredPush(t *testing.T) {
	fs := newFakeStore()
	_, cid := addPushUser(fs, "bob")
	fs.mu.Lock()
	fs.challenges[cid].ExpiresAt = time.Now().Add(-time.Minute)
	fs.mu.Unlock()

	b, api := newTestBot(t, "TOK", fs)
	api.pushUpdate(pushCallback(1, cid, "approve"))
	stop := runBot(t, b)
	waitFor(t, "edit 'истёк'", func() bool {
		_, _, _, edits := api.snapshot()
		for _, m := range edits {
			if m["text"] == "⏳ Запрос истёк" {
				return true
			}
		}
		return false
	})
	if err := stop(); err != nil {
		t.Fatalf("Run: %v", err)
	}

	_, challenges, audits, setPushN := fs.snapshot()
	if got := challenges[cid].PushState; got == nil || *got != "pending" {
		t.Errorf("push_state просроченного = %v, want pending (не трогаем)", got)
	}
	if setPushN != 0 {
		t.Errorf("ChallengeSetPush вызовов = %d, want 0", setPushN)
	}
	if len(audits) != 0 {
		t.Errorf("аудит = %+v, want пусто", audits)
	}
}

// TestCallbackUsedPush: уже погашенный (used_at) push-челлендж не
// аппрувится — «уже обработано», состояние и аудит не меняются.
func TestCallbackUsedPush(t *testing.T) {
	fs := newFakeStore()
	_, cid := addPushUser(fs, "bob")
	used := time.Now().Add(-time.Second)
	fs.mu.Lock()
	fs.challenges[cid].UsedAt = &used
	fs.mu.Unlock()

	b, api := newTestBot(t, "TOK", fs)
	api.pushUpdate(pushCallback(1, cid, "approve"))
	stop := runBot(t, b)
	waitFor(t, "edit 'уже обработано'", func() bool {
		_, _, _, edits := api.snapshot()
		for _, m := range edits {
			if m["text"] == "⏳ Уже обработано" {
				return true
			}
		}
		return false
	})
	if err := stop(); err != nil {
		t.Fatalf("Run: %v", err)
	}

	_, _, audits, setPushN := fs.snapshot()
	if setPushN != 0 {
		t.Errorf("ChallengeSetPush вызовов = %d, want 0", setPushN)
	}
	if len(audits) != 0 {
		t.Errorf("аудит = %+v, want пусто", audits)
	}
}
