//go:build integration

// Интеграционные тесты ядра аутентификации: требуют Docker
// (testcontainers-go, postgres:16-alpine). Паттерн подключения —
// internal/store/migrate_test.go. Запуск:
//
//	go test -tags integration ./internal/auth/
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/aligorov/twofa/internal/channel"
	"github.com/aligorov/twofa/internal/delivery"
	"github.com/aligorov/twofa/internal/secrets"
	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
)

const testPassword = "hunter2pass"

// ---- тестовое окружение: один контейнер на пакет ----

var (
	initOnce sync.Once
	testSt   *store.Store
	testSet  *settings.M
	testBox  *secrets.Box
	initErr  error
)

func dockerAvailable() bool {
	return exec.Command("docker", "info").Run() == nil
}

// setup лениво поднимает postgres-контейнер, применяет миграции, создаёт
// менеджер настроек (дефолты записываются в БД) и Box на master_key.
func setup(t *testing.T) (*store.Store, *settings.M, *secrets.Box) {
	t.Helper()
	if !dockerAvailable() {
		t.Skip("docker недоступен (docker info завершается с ошибкой) — интеграционный тест пропущен")
	}
	initOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		pg, err := tcpostgres.RunContainer(ctx,
			testcontainers.WithImage("postgres:16-alpine"),
			tcpostgres.WithDatabase("twofa"),
			tcpostgres.WithUsername("twofa"),
			tcpostgres.WithPassword("twofa"),
			// postgres:*-alpine при initdb поднимает временный сервер, печатает
			// ready-сообщение и перезапускается — ждём второе вхождение.
			testcontainers.WithWaitStrategy(
				wait.ForLog("database system is ready to accept connections").
					WithOccurrence(2).
					WithStartupTimeout(60*time.Second),
			),
		)
		if err != nil {
			initErr = err
			return
		}
		dsn, err := pg.ConnectionString(ctx, "sslmode=disable")
		if err != nil {
			initErr = err
			return
		}
		if testSt, err = store.Open(ctx, dsn); err != nil {
			initErr = err
			return
		}
		if err = testSt.Migrate(ctx); err != nil {
			initErr = err
			return
		}
		if testSet, err = settings.NewManager(ctx, testSt); err != nil {
			initErr = err
			return
		}
		testBox, err = secrets.NewBox(testSet.Get().MasterKeyB64)
		if err != nil {
			initErr = err
			return
		}
	})
	if initErr != nil {
		t.Fatalf("инициализация тестового окружения: %v", initErr)
	}
	return testSt, testSet, testBox
}

func mustPut(t *testing.T, ctx context.Context, m *settings.M, key, val string) {
	t.Helper()
	if err := m.Put(ctx, key, json.RawMessage(val)); err != nil {
		t.Fatalf("settings.Put(%s=%s): %v", key, val, err)
	}
}

// ---- фейки ----

// fakeSender — захват кодов вместо реальной доставки (delivery.NewLog
// пишет в slog; для тестов нужен детерминированный захват).
type fakeSender struct {
	ch    channel.Channel
	mu    sync.Mutex
	codes []string
	tos   []string
	err   error
}

func (f *fakeSender) Name() channel.Channel { return f.ch }

func (f *fakeSender) Send(_ context.Context, to, code string) error {
	if f.err != nil {
		return f.err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tos = append(f.tos, to)
	f.codes = append(f.codes, code)
	return nil
}

func (f *fakeSender) lastCode() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.codes) == 0 {
		return ""
	}
	return f.codes[len(f.codes)-1]
}

// fakePush — PushNotifier: через after переключает состояние челленджа
// (имитация нажатия кнопки ботом T8).
type fakePush struct {
	st       *store.Store
	setState string // "" — не трогать (таймаут), "approved", "denied"
	after    time.Duration
	err      error

	mu         sync.Mutex
	calls      int
	seenChatID int64
	seenWho    string
	seenIP     string
	seenChalID uuid.UUID

	notifCalls  int
	notifChatID int64
	notifText   string
}

func (f *fakePush) SendPush(_ context.Context, chatID int64, who, ip, ua string, chID uuid.UUID) error {
	f.mu.Lock()
	f.calls++
	f.seenChatID, f.seenWho, f.seenIP, f.seenChalID = chatID, who, ip, chID
	f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	if f.setState != "" {
		state := f.setState
		go func() {
			time.Sleep(f.after)
			_ = f.st.ChallengeSetPush(context.Background(), chID, state)
		}()
	}
	return nil
}

func (f *fakePush) SendNotification(_ context.Context, chatID int64, text string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.notifCalls++
	f.notifChatID = chatID
	f.notifText = text
	return nil
}

func (f *fakePush) snapshot() (calls int, chatID int64, who, ip string, chID uuid.UUID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls, f.seenChatID, f.seenWho, f.seenIP, f.seenChalID
}

// fakeAppPush — AppPushNotifier с подсчётом доставки (как *delivery.AppHub):
// записывает вызовы, отвечает online живых клиентов, опционально «нажимает»
// подтверждение через after; err имитирует отказ рассылки.
type fakeAppPush struct {
	st       *store.Store
	setState string
	after    time.Duration
	err      error
	online   int // ответ SendAppPushCounted

	mu      sync.Mutex
	calls   int
	seenID  uuid.UUID
	seenWho string
	seenIP  string
	seenSvc string
}

func (f *fakeAppPush) SendAppPush(ctx context.Context, userID uuid.UUID, who, ip, ua, service, numberMatch string, challengeID uuid.UUID, expiresInSeconds int) error {
	_, err := f.SendAppPushCounted(ctx, userID, who, ip, ua, service, numberMatch, challengeID, expiresInSeconds)
	return err
}

func (f *fakeAppPush) SendAppPushCounted(_ context.Context, _ uuid.UUID, who, ip, _, service, _ string, chID uuid.UUID, _ int) (int, error) {
	f.mu.Lock()
	f.calls++
	f.seenID, f.seenWho, f.seenIP, f.seenSvc = chID, who, ip, service
	online, err := f.online, f.err
	f.mu.Unlock()
	if err != nil {
		return 0, err
	}
	if f.setState != "" {
		state := f.setState
		go func() {
			time.Sleep(f.after)
			_ = f.st.ChallengeSetPush(context.Background(), chID, state)
		}()
	}
	return online, nil
}

func (f *fakeAppPush) snapshot() (calls int, chID uuid.UUID, who, ip, svc string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls, f.seenID, f.seenWho, f.seenIP, f.seenSvc
}

// ---- утилиты ----

func mkUser(t *testing.T, ctx context.Context, st *store.Store, name string, mutate func(*store.User)) *store.User {
	t.Helper()
	u := &store.User{
		Username:     name,
		Role:         "user",
		Enabled:      true,
		PasswordHash: secrets.HashPassword(testPassword),
	}
	if mutate != nil {
		mutate(u)
	}
	if err := st.UserCreate(ctx, u); err != nil {
		t.Fatalf("создать пользователя %s: %v", name, err)
	}
	return u
}

// enrollTOTP выдаёт секрет как энроллмент T11: шифрование с AAD по
// username, сохранение и (опционально) подтверждение.
func enrollTOTP(t *testing.T, ctx context.Context, st *store.Store, box *secrets.Box, u *store.User, confirm bool) string {
	t.Helper()
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer: "twofa", AccountName: u.Username,
		Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("totp.Generate: %v", err)
	}
	enc := box.EncryptAAD(AADTOTP(u.Username), []byte(key.Secret()))
	if err := st.TOTPSave(ctx, u.ID, enc, 6, 30); err != nil {
		t.Fatalf("TOTPSave: %v", err)
	}
	if confirm {
		if err := st.TOTPConfirm(ctx, u.ID); err != nil {
			t.Fatalf("TOTPConfirm: %v", err)
		}
	}
	return key.Secret()
}

func codeAt(t *testing.T, secret string, counter int64) string {
	t.Helper()
	c, err := hotp.GenerateCode(secret, uint64(counter))
	if err != nil {
		t.Fatalf("hotp.GenerateCode(%d): %v", counter, err)
	}
	return c
}

func newCore(st *store.Store, set *settings.M, box *secrets.Box, senders map[channel.Channel]delivery.Sender, push PushNotifier) *Core {
	return NewCore(st, set, box, senders, NewLocalVerifier(st), push)
}

// ---- тесты ----

func TestStartVerifyEmailFlow(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	email := &fakeSender{ch: channel.Email}
	core := newCore(st, set, box, map[channel.Channel]delivery.Sender{channel.Email: email}, nil)

	user := mkUser(t, ctx, st, "emailuser", func(u *store.User) {
		u.Email = "emailuser@example.com"
		u.PreferChannels = []channel.Channel{channel.Email}
	})

	ch, err := core.Start(ctx, user, "api")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if ch.Channel != channel.Email || ch.CodeHash == nil || ch.AttemptsLeft != set.Get().Policy.MaxAttempts {
		t.Fatalf("Start вернул некорректный челлендж: %+v", ch)
	}
	code := email.lastCode()
	if code == "" || len(code) != set.Get().Policy.CodeLength {
		t.Fatalf("отправитель не получил код нужной длины: %q", code)
	}

	// Неверный код: расход попытки, ErrBadCode.
	if ok, err := core.VerifyChallengeCode(ctx, ch, "000000"); ok || !errors.Is(err, ErrBadCode) {
		t.Fatalf("неверный код: ok=%v err=%v, хочу (false, ErrBadCode)", ok, err)
	}
	fresh, err := st.ChallengeGet(ctx, ch.ID)
	if err != nil {
		t.Fatalf("ChallengeGet: %v", err)
	}
	if fresh.AttemptsLeft != ch.AttemptsLeft-1 {
		t.Fatalf("попытка не списана: %d, хочу %d", fresh.AttemptsLeft, ch.AttemptsLeft-1)
	}

	// Верный код: single-use.
	if ok, err := core.VerifyChallengeCode(ctx, fresh, code); !ok || err != nil {
		t.Fatalf("верный код: ok=%v err=%v", ok, err)
	}
	if ok, err := core.VerifyChallengeCode(ctx, fresh, code); ok || !errors.Is(err, ErrChallengeClosed) {
		t.Fatalf("повторное использование: ok=%v err=%v, хочу ErrChallengeClosed", ok, err)
	}

	// Просроченный челлендж закрыт.
	expired := &store.Challenge{
		UserID: user.ID, Channel: channel.Email,
		CodeHash: secrets.SHA256("999999"), ExpiresAt: time.Now().Add(-time.Second),
	}
	if err := st.ChallengeCreate(ctx, expired); err != nil {
		t.Fatalf("создать просроченный челлендж: %v", err)
	}
	if ok, err := core.VerifyChallengeCode(ctx, expired, "999999"); ok || !errors.Is(err, ErrChallengeClosed) {
		t.Fatalf("просроченный челлендж: ok=%v err=%v, хочу ErrChallengeClosed", ok, err)
	}
}

func TestStartResendCooldown(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	email := &fakeSender{ch: channel.Email}
	core := newCore(st, set, box, map[channel.Channel]delivery.Sender{channel.Email: email}, nil)

	user := mkUser(t, ctx, st, "cooldownuser", func(u *store.User) {
		u.Email = "cooldown@example.com"
		u.PreferChannels = []channel.Channel{channel.Email}
	})
	if _, err := core.Start(ctx, user, "api"); err != nil {
		t.Fatalf("первый Start: %v", err)
	}
	if _, err := core.Start(ctx, user, "api"); !errors.Is(err, ErrCooldown) {
		t.Fatalf("повторный Start: err=%v, хочу ErrCooldown", err)
	}
}

func TestStartChannelFallthroughAndNoChannel(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	email := &fakeSender{ch: channel.Email}
	core := newCore(st, set, box, map[channel.Channel]delivery.Sender{channel.Email: email}, nil)

	// sms первый в списке, но не привязан и отправителя нет → email.
	user := mkUser(t, ctx, st, "falluser", func(u *store.User) {
		u.Email = "fall@example.com"
		u.PreferChannels = []channel.Channel{channel.SMS, channel.Email}
	})
	ch, err := core.Start(ctx, user, "api")
	if err != nil || ch.Channel != channel.Email {
		t.Fatalf("fallback на email: ch=%+v err=%v", ch, err)
	}

	// Ни один канал не привязан/не зарегистрирован.
	bare := mkUser(t, ctx, st, "bareuser", nil) // prefer по умолчанию: totp/telegram/email/sms
	if _, err := core.Start(ctx, bare, "api"); !errors.Is(err, ErrNoChannel) {
		t.Fatalf("Start без привязок: err=%v, хочу ErrNoChannel", err)
	}
}

func TestTOTPFlow(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	core := newCore(st, set, box, nil, nil)

	user := mkUser(t, ctx, st, "totpuser", func(u *store.User) {
		u.PreferChannels = []channel.Channel{channel.TOTP}
	})
	secret := enrollTOTP(t, ctx, st, box, user, true)

	// Start по totp: челлендж-метка без кода.
	ch, err := core.Start(ctx, user, "api")
	if err != nil || ch.Channel != channel.TOTP || ch.CodeHash != nil {
		t.Fatalf("Start(totp): ch=%+v err=%v", ch, err)
	}

	cur := time.Now().Unix() / 30
	// Неверный код списывает попытку.
	if ok, err := core.VerifyChallengeCode(ctx, ch, "000000"); ok || !errors.Is(err, ErrBadCode) {
		t.Fatalf("неверный TOTP: ok=%v err=%v", ok, err)
	}
	// Код текущего окна принимается один раз.
	codeC := codeAt(t, secret, cur)
	if ok, err := core.VerifyChallengeCode(ctx, ch, codeC); !ok || err != nil {
		t.Fatalf("верный TOTP: ok=%v err=%v", ok, err)
	}
	// Replay: тот же код вторично (даже через VerifyAnyCode) — отказ.
	if _, err := core.VerifyAnyCode(ctx, user, codeC); !errors.Is(err, ErrBadCode) {
		t.Fatalf("replay того же кода: err=%v, хочу ErrBadCode", err)
	}
	// Код более старого счётчика — отказ (counter ≤ last_timestep).
	if _, err := core.VerifyAnyCode(ctx, user, codeAt(t, secret, cur-1)); !errors.Is(err, ErrBadCode) {
		t.Fatalf("код прошлого окна: err=%v, хочу ErrBadCode", err)
	}
	// Код следующего счётчика — принят (в окне skew), last_timestep растёт.
	gotCh, err := core.VerifyAnyCode(ctx, user, codeAt(t, secret, cur+1))
	if err != nil || gotCh != channel.TOTP {
		t.Fatalf("код следующего окна: ch=%v err=%v, хочу totp", gotCh, err)
	}

	// Неподтверждённый секрет не принимается.
	u2 := mkUser(t, ctx, st, "totpunconfirmed", nil)
	enrollTOTP(t, ctx, st, box, u2, false)
	if _, err := core.VerifyAnyCode(ctx, u2, codeAt(t, secret, cur)); !errors.Is(err, ErrBadCode) {
		t.Fatalf("неподтверждённый TOTP: err=%v, хочу ErrBadCode", err)
	}
	// AAD: секрет u2 зашифрован на его username — коды его секрета валидны
	// только для него, для user они не подходят (расшифровка чужого не нужна).
	if _, err := core.VerifyAnyCode(ctx, user, codeAt(t, secret, cur+1)); !errors.Is(err, ErrBadCode) {
		t.Fatalf("чужой следующий код после принятия: err=%v, хочу ErrBadCode", err)
	}
}

func TestVerifyAnyCodeBackupOnce(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	core := newCore(st, set, box, nil, nil)

	user := mkUser(t, ctx, st, "backupuser", nil)
	codes := secrets.GenBackupCodes()
	hashes := make([][]byte, len(codes))
	for i, c := range codes {
		hashes[i] = secrets.SHA256(c)
	}
	if err := st.BackupReplace(ctx, user.ID, hashes); err != nil {
		t.Fatalf("BackupReplace: %v", err)
	}

	got, err := core.VerifyAnyCode(ctx, user, codes[0])
	if err != nil || got != BackupChannel {
		t.Fatalf("backup-код: ch=%v err=%v, хочу backup", got, err)
	}
	// Одноразовость: повторное потребление невозможно.
	if _, err := core.VerifyAnyCode(ctx, user, codes[0]); !errors.Is(err, ErrBadCode) {
		t.Fatalf("повторный backup-код: err=%v, хочу ErrBadCode", err)
	}
	// Второй код из набора работает.
	if _, err := core.VerifyAnyCode(ctx, user, codes[1]); err != nil {
		t.Fatalf("второй backup-код: %v", err)
	}
}

func TestVerifyPasswordAndCode(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	email := &fakeSender{ch: channel.Email}
	core := newCore(st, set, box, map[channel.Channel]delivery.Sender{channel.Email: email}, nil)

	user := mkUser(t, ctx, st, "vpacuser", func(u *store.User) {
		u.Email = "vpac@example.com"
		u.PreferChannels = []channel.Channel{channel.Email}
	})

	// Отдельный код (UI-флоу).
	if _, err := core.Start(ctx, user, "api"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	got, ok, err := core.VerifyPasswordAndCode(ctx, user.Username, testPassword, email.lastCode(), LoginCodePurposes...)
	if err != nil || !ok || got == nil || got.ID != user.ID {
		t.Fatalf("пароль+код: user=%v ok=%v err=%v", got, ok, err)
	}

	// Пароль верен, код нет → (user, false).
	got, ok, err = core.VerifyPasswordAndCode(ctx, user.Username, testPassword, "000000")
	if err != nil || ok || got == nil || got.ID != user.ID {
		t.Fatalf("верный пароль без кода: user=%v ok=%v err=%v, хочу (user,false)", got, ok, err)
	}

	// Пароль неверен → (nil, false).
	got, ok, err = core.VerifyPasswordAndCode(ctx, user.Username, "wrongpassword", "000000")
	if err != nil || ok || got != nil {
		t.Fatalf("неверный пароль: user=%v ok=%v err=%v, хочу (nil,false)", got, ok, err)
	}

	// RADIUS-флоу: код приклеен к паролю, code == "".
	combined := mkUser(t, ctx, st, "vpaccombined", func(u *store.User) {
		u.Email = "combined@example.com"
		u.PreferChannels = []channel.Channel{channel.Email}
	})
	if _, err := core.Start(ctx, combined, "api"); err != nil {
		t.Fatalf("Start(combined): %v", err)
	}
	pap := testPassword + email.lastCode()
	got, ok, err = core.VerifyPasswordAndCode(ctx, combined.Username, pap, "", LoginCodePurposes...)
	if err != nil || !ok || got == nil || got.ID != combined.ID {
		t.Fatalf("комбинированная строка: user=%v ok=%v err=%v", got, ok, err)
	}
}

func TestRADIUSAuth(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	mustPut(t, ctx, set, "radius.push_wait", `"4s"`)

	email := &fakeSender{ch: channel.Email}
	push := &fakePush{st: st, setState: "approved", after: 2 * time.Second}
	core := newCore(st, set, box, map[channel.Channel]delivery.Sender{channel.Email: email}, push)

	// 1) push_ok: верный пароль без кода → удержание до approved.
	rad := mkUser(t, ctx, st, "radpush", func(u *store.User) {
		chat := int64(4242)
		u.TelegramChatID = &chat
		u.RadiusPush = true
	})
	start := time.Now()
	accept, reason := core.RADIUSAuth(ctx, rad.Username, testPassword, "10.1.2.3")
	if !accept || reason != "push_ok" {
		t.Fatalf("push_ok: accept=%v reason=%q", accept, reason)
	}
	if wait := time.Since(start); wait < 2*time.Second || wait > 8*time.Second {
		t.Fatalf("push_ok удержание %s — вне диапазона 2..8с", wait)
	}
	calls, chatID, who, ip, chID := push.snapshot()
	if calls != 1 || chatID != 4242 || who != rad.Username || ip != "10.1.2.3" || chID == uuid.Nil {
		t.Fatalf("SendPush получил некорректные аргументы: calls=%d chat=%d who=%q ip=%q ch=%s",
			calls, chatID, who, ip, chID)
	}

	// 2) push_cooldown: повторный push в пределах cooldown отклонён.
	accept, reason = core.RADIUSAuth(ctx, rad.Username, testPassword, "10.1.2.3")
	if accept || reason != "push_cooldown" {
		t.Fatalf("push_cooldown: accept=%v reason=%q", accept, reason)
	}

	// 3) code_ok: код приклеен к паролю (сплит).
	rad2 := mkUser(t, ctx, st, "radcode", func(u *store.User) {
		u.Email = "radcode@example.com"
		u.PreferChannels = []channel.Channel{channel.Email}
	})
	if _, err := core.Start(ctx, rad2, "api"); err != nil {
		t.Fatalf("Start(radcode): %v", err)
	}
	accept, reason = core.RADIUSAuth(ctx, rad2.Username, testPassword+email.lastCode(), "10.0.0.9")
	if !accept || reason != "code_ok" {
		t.Fatalf("code_ok: accept=%v reason=%q", accept, reason)
	}

	// 4) push_denied: «Это не я».
	deniedPush := &fakePush{st: st, setState: "denied", after: time.Second}
	coreDenied := newCore(st, set, box, map[channel.Channel]delivery.Sender{channel.Email: email}, deniedPush)
	radDeny := mkUser(t, ctx, st, "raddeny", func(u *store.User) {
		chat := int64(1)
		u.TelegramChatID = &chat
		u.RadiusPush = true
	})
	if accept, reason = coreDenied.RADIUSAuth(ctx, radDeny.Username, testPassword, "10.0.0.9"); accept || reason != "push_denied" {
		t.Fatalf("push_denied: accept=%v reason=%q", accept, reason)
	}

	// 5) push_timeout: подтверждения нет — отказ после push_wait.
	coreTimeout := newCore(st, set, box, nil, &fakePush{st: st})
	radSlow := mkUser(t, ctx, st, "radtimeout", func(u *store.User) {
		chat := int64(2)
		u.TelegramChatID = &chat
		u.RadiusPush = true
	})
	start = time.Now()
	if accept, reason = coreTimeout.RADIUSAuth(ctx, radSlow.Username, testPassword, "10.0.0.9"); accept || reason != "push_timeout" {
		t.Fatalf("push_timeout: accept=%v reason=%q", accept, reason)
	}
	if wait := time.Since(start); wait < 3*time.Second || wait > 8*time.Second {
		t.Fatalf("push_timeout удержание %s — вне диапазона 3..8с", wait)
	}

	// 6) bad_credentials + radius_fail в аудите (питает FailLocked).
	rad3 := mkUser(t, ctx, st, "radbad", nil)
	if accept, reason = core.RADIUSAuth(ctx, rad3.Username, "completelywrong", "10.0.0.9"); accept || reason != "bad_credentials" {
		t.Fatalf("bad_credentials: accept=%v reason=%q", accept, reason)
	}
	fails, err := st.AuditList(ctx, store.AuditFilter{Username: rad3.Username, Event: "radius_fail"})
	if err != nil || len(fails) == 0 {
		t.Fatalf("radius_fail в аудите: rows=%d err=%v", len(fails), err)
	}
	radiusEvents, err := st.AuditList(ctx, store.AuditFilter{Username: rad3.Username, Event: "radius_auth"})
	if err != nil || len(radiusEvents) == 0 {
		t.Fatalf("radius_auth в аудите: rows=%d err=%v", len(radiusEvents), err)
	}

	// 7) no_user и disabled.
	if accept, reason = core.RADIUSAuth(ctx, "ghost-user", "whatever", "10.0.0.9"); accept || reason != "no_user" {
		t.Fatalf("no_user: accept=%v reason=%q", accept, reason)
	}
	rad4 := mkUser(t, ctx, st, "raddisabled", func(u *store.User) { u.Enabled = false })
	if accept, reason = core.RADIUSAuth(ctx, rad4.Username, testPassword, "10.0.0.9"); accept || reason != "disabled" {
		t.Fatalf("disabled: accept=%v reason=%q", accept, reason)
	}
}

// TestRADIUSAuthPushFanout — фан-аут доставки RADIUS-push: при привязанном
// Telegram И зарегистрированном app-диспетчере ОДИН челлендж доставляется в
// ОБА канала (WS/SSE-рассылка + pending-список приложения, SendPush боту);
// подтвердить можно из любого канала. Отказ одного канала не рвёт другой;
// отказ обоих — push_send_fail с удалением челленджа (cooldown не отравлен).
func TestRADIUSAuthPushFanout(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	mustPut(t, ctx, set, "radius.push_wait", `"6s"`)

	waitFor := func(cond func() bool) bool {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if cond() {
				return true
			}
			time.Sleep(10 * time.Millisecond)
		}
		return cond()
	}

	// 1) Оба канала: один и тот же challenge_id в SendAppPush и SendPush;
	// челлендж channel=app_push виден приложению в pending-списке;
	// подтверждение со стороны Telegram закрывает тот же челлендж.
	tg := &fakePush{st: st}
	app := &fakeAppPush{st: st, online: 2}
	core := newCore(st, set, box, nil, tg)
	core.SetAppPush(app)

	u1 := mkUser(t, ctx, st, "fanout-both", func(u *store.User) {
		chat := int64(5001)
		u.TelegramChatID = &chat
		u.RadiusPush = true
	})
	var accept1 bool
	var reason1 string
	done1 := make(chan struct{})
	go func() {
		accept1, reason1 = core.RADIUSAuth(ctx, u1.Username, testPassword, "10.5.5.5")
		close(done1)
	}()
	if !waitFor(func() bool {
		c, _, _, _, _ := app.snapshot()
		tc, _, _, _, _ := tg.snapshot()
		return c >= 1 && tc >= 1
	}) {
		t.Fatal("фан-аут: SendAppPush/SendPush не вызваны")
	}
	appCalls, appID, appWho, appIP, appSvc := app.snapshot()
	tgCalls, tgChat, tgWho, tgIP, tgID := tg.snapshot()
	if appCalls != 1 || tgCalls != 1 {
		t.Fatalf("фан-аут: app=%d tg=%d вызовов, want 1/1", appCalls, tgCalls)
	}
	if appID != tgID || appID == uuid.Nil {
		t.Fatalf("фан-аут: разные challenge_id: app=%s tg=%s", appID, tgID)
	}
	if tgChat != 5001 || tgWho != u1.Username || tgIP != "10.5.5.5" ||
		appWho != u1.Username || appIP != "10.5.5.5" || appSvc == "" {
		t.Fatalf("фан-аут: аргументы доставки app=(who=%q ip=%q svc=%q) tg=(chat=%d who=%q ip=%q)",
			appWho, appIP, appSvc, tgChat, tgWho, tgIP)
	}
	chal, err := st.ChallengeGet(ctx, appID)
	if err != nil || chal.Channel != channel.AppPush {
		t.Fatalf("челлендж фан-аута: channel=%v err=%v (want app_push)", chal.Channel, err)
	}
	pending, err := st.ActiveAppPushChallenges(ctx, u1.ID)
	if err != nil || len(pending) != 1 || pending[0].ID != appID {
		t.Fatalf("pending-список приложения не видит RADIUS-push: n=%d err=%v", len(pending), err)
	}
	if err := st.ChallengeSetPush(ctx, tgID, "approved"); err != nil {
		t.Fatalf("approve из Telegram: %v", err)
	}
	<-done1
	if !accept1 || reason1 != "push_ok" {
		t.Fatalf("фан-аут: accept=%v reason=%q (want push_ok)", accept1, reason1)
	}
	evs, err := st.AuditList(ctx, store.AuditFilter{Username: u1.Username, Event: "app_push_sent"})
	if err != nil || len(evs) == 0 {
		t.Fatalf("аудит app_push_sent: n=%d err=%v", len(evs), err)
	}

	// 2) Telegram недоступен — канал приложения продолжает работать.
	tgDown := &fakePush{st: st, err: errors.New("telegram down")}
	appOK := &fakeAppPush{st: st, setState: "approved", after: time.Second, online: 0}
	core2 := newCore(st, set, box, nil, tgDown)
	core2.SetAppPush(appOK)
	u2 := mkUser(t, ctx, st, "fanout-tgdown", func(u *store.User) {
		chat := int64(5002)
		u.TelegramChatID = &chat
		u.RadiusPush = true
	})
	if accept, reason := core2.RADIUSAuth(ctx, u2.Username, testPassword, "10.5.5.6"); !accept || reason != "push_ok" {
		t.Fatalf("tg-down: accept=%v reason=%q (want push_ok)", accept, reason)
	}

	// 3) Только приложение (Telegram не привязан).
	appOnly := &fakeAppPush{st: st, setState: "approved", after: time.Second, online: 1}
	core3 := newCore(st, set, box, nil, nil)
	core3.SetAppPush(appOnly)
	u3 := mkUser(t, ctx, st, "fanout-apponly", func(u *store.User) { u.RadiusPush = true })
	if accept, reason := core3.RADIUSAuth(ctx, u3.Username, testPassword, "10.5.5.7"); !accept || reason != "push_ok" {
		t.Fatalf("app-only: accept=%v reason=%q (want push_ok)", accept, reason)
	}

	// 4) Оба канала упали — push_send_fail, челлендж удалён.
	tgDead := &fakePush{st: st, err: errors.New("telegram down")}
	appDead := &fakeAppPush{st: st, err: errors.New("hub down")}
	core4 := newCore(st, set, box, nil, tgDead)
	core4.SetAppPush(appDead)
	u4 := mkUser(t, ctx, st, "fanout-dead", func(u *store.User) {
		chat := int64(5003)
		u.TelegramChatID = &chat
		u.RadiusPush = true
	})
	if accept, reason := core4.RADIUSAuth(ctx, u4.Username, testPassword, "10.5.5.8"); accept || reason != "push_send_fail" {
		t.Fatalf("all-dead: accept=%v reason=%q (want push_send_fail)", accept, reason)
	}
	_, deadID, _, _, _ := appDead.snapshot()
	if _, err := st.ChallengeGet(ctx, deadID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("челлендж после отказа всех каналов должен быть удалён: err=%v", err)
	}
}

// TestCoreSetSendersHotSwap: подмена отправителей через SetSenders применяется
// к последующим Start'ам без пересоздания ядра — так main перестраивает слой
// доставки после SIGHUP (SMTP/SMS/Telegram).
func TestCoreSetSendersHotSwap(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	core := newCore(st, set, box, nil, nil)
	user := mkUser(t, ctx, st, "hotsender", func(u *store.User) {
		u.Email = "hot@example.com"
		u.PreferChannels = []channel.Channel{channel.Email}
	})

	// До подмены: канал email не зарегистрирован → ErrNoChannel.
	if _, err := core.Start(ctx, user, "api"); !errors.Is(err, ErrNoChannel) {
		t.Fatalf("Start без отправителя: err = %v, want ErrNoChannel", err)
	}

	// Подмена на лету (как SIGHUP): доставка идёт через нового отправителя.
	email := &fakeSender{ch: channel.Email}
	core.SetSenders(map[channel.Channel]delivery.Sender{channel.Email: email}, nil)
	if _, err := core.Start(ctx, user, "api"); err != nil {
		t.Fatalf("Start после SetSenders: %v", err)
	}
	if got := email.lastCode(); got == "" {
		t.Fatal("код не доставлен через подменённого отправителя")
	}
}

// TestRADIUSAuthPerUserFailWindow: radius.max_fail_per_user/radius.fail_window
// — RADIUS-специфичный per-user fail-счётчик по аудиту radius_fail. Окно (1h)
// и порог (2) отличны от policy.fail_window (5m) и policy.max_fail (5):
// срабатывает именно RADIUS-окно, третий запрос отбивается «locked» даже с
// верным паролем.
func TestRADIUSAuthPerUserFailWindow(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	mustPut(t, ctx, set, "radius.max_fail_per_user", `2`)
	mustPut(t, ctx, set, "radius.fail_window", `"1h"`)
	t.Cleanup(func() {
		mustPut(t, ctx, set, "radius.max_fail_per_user", `10`)
		mustPut(t, ctx, set, "radius.fail_window", `"5m"`)
	})

	core := newCore(st, set, box, nil, nil)
	u := mkUser(t, ctx, st, "radwindow", nil)

	for i := 0; i < 2; i++ {
		if accept, reason := core.RADIUSAuth(ctx, u.Username, "wrong-password", "10.7.7.7"); accept || reason != "bad_credentials" {
			t.Fatalf("попытка %d: accept=%v reason=%q, want bad_credentials", i+1, accept, reason)
		}
	}
	// Порог radius.max_fail_per_user=2 достигнут; policy.max_fail=5 ещё нет —
	// верный пароль отклонён именно RADIUS-окном.
	if accept, reason := core.RADIUSAuth(ctx, u.Username, testPassword, "10.7.7.7"); accept || reason != "locked" {
		t.Fatalf("после %d неудач: accept=%v reason=%q, want locked", 2, accept, reason)
	}

	// Аудит отражает причину (radius_auth reason=locked, result=fail).
	events, err := st.AuditList(ctx, store.AuditFilter{Username: u.Username, Event: "radius_auth"})
	if err != nil {
		t.Fatalf("AuditList: %v", err)
	}
	var sawLocked bool
	for _, e := range events {
		if e.Result == "fail" && e.Detail != nil && e.Detail["reason"] == "locked" {
			sawLocked = true
		}
	}
	if !sawLocked {
		t.Fatalf("аудит radius_auth не содержит reason=locked: %+v", events)
	}
}

func TestVerifyPasswordAndCodeLocked(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	mustPut(t, ctx, set, "policy", `{"max_fail":2}`)

	core := newCore(st, set, box, nil, nil)
	user := mkUser(t, ctx, st, "lockuser", nil)

	for i := 0; i < 2; i++ {
		got, ok, err := core.VerifyPasswordAndCode(ctx, user.Username, "wrongpassword", "000000")
		if err != nil || ok || got != nil {
			t.Fatalf("неудача #%d: user=%v ok=%v err=%v, хочу (nil,false,nil)", i+1, got, ok, err)
		}
	}
	// Счётчик достиг max_fail → ErrLocked до какой-либо проверки кода.
	_, _, err := core.VerifyPasswordAndCode(ctx, user.Username, testPassword, "000000")
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("после серии неудач: err=%v, хочу ErrLocked", err)
	}
}

func TestFailLockedBanTime(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	mustPut(t, ctx, set, "policy", `{"max_fail":2,"ban_time":"1s"}`)

	core := newCore(st, set, box, nil, nil)
	user := mkUser(t, ctx, st, "banuser", nil)
	for i := 0; i < 2; i++ {
		if err := st.Audit(ctx, user.Username, "login_fail", nil, "", "fail"); err != nil {
			t.Fatalf("seed audit: %v", err)
		}
	}
	if !core.FailLocked(ctx, user.ID) {
		t.Fatal("FailLocked=false при свежих max_fail неудачах")
	}
	time.Sleep(1200 * time.Millisecond) // последний неуспех старше ban_time
	if core.FailLocked(ctx, user.ID) {
		t.Fatal("FailLocked=true после истечения ban_time")
	}

	// Ниже порога — не заблокирован.
	other := mkUser(t, ctx, st, "almostuser", nil)
	if err := st.Audit(ctx, other.Username, "login_fail", nil, "", "fail"); err != nil {
		t.Fatalf("seed audit: %v", err)
	}
	if core.FailLocked(ctx, other.ID) {
		t.Fatal("FailLocked=true ниже порога max_fail")
	}
}

// ---- регрессии ревью (fix round 1) ----

// countingPV — PasswordVerifier-декоратор над локальной проверкой:
// считает вызовы Verify (инвариант «один argon2 на запрос»).
type countingPV struct {
	inner PasswordVerifier
	mu    sync.Mutex
	calls []string
}

func (p *countingPV) Verify(ctx context.Context, username, password string) (*store.User, error) {
	p.mu.Lock()
	p.calls = append(p.calls, password)
	p.mu.Unlock()
	return p.inner.Verify(ctx, username, password)
}

func (p *countingPV) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.calls)
}

func (p *countingPV) requested() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.calls...)
}

func newCountingCore(st *store.Store, set *settings.M, box *secrets.Box, senders map[channel.Channel]delivery.Sender, push PushNotifier) (*Core, *countingPV) {
	pv := &countingPV{inner: NewLocalVerifier(st)}
	return NewCore(st, set, box, senders, pv, push), pv
}

// TestSinglePasswordVerifyPerRequest — регрессия «ONE password verify
// per request»: argon2-проверка выполняется ровно один раз на запрос
// при любом числе кандидатов-сплитов «пароль+код».
func TestSinglePasswordVerifyPerRequest(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	mustPut(t, ctx, set, "radius.push_wait", `"1s"`)

	// (a) верный код приклеен к неверному паролю: пароль первого
	// подошедшего сплита проверяется ровно один раз; отказ.
	ua := mkUser(t, ctx, st, "single-a", func(u *store.User) {
		u.Email = "single-a@example.com"
		u.PreferChannels = []channel.Channel{channel.Email}
	})
	email := &fakeSender{ch: channel.Email}
	coreA, pvA := newCountingCore(st, set, box, map[channel.Channel]delivery.Sender{channel.Email: email}, nil)
	if _, err := coreA.Start(ctx, ua, "api"); err != nil {
		t.Fatalf("Start(single-a): %v", err)
	}
	got, ok, err := coreA.VerifyPasswordAndCode(ctx, ua.Username, "wrongpassword"+email.lastCode(), "")
	if err != nil || ok || got != nil {
		t.Fatalf("(a) код верен, пароль нет: user=%v ok=%v err=%v, хочу (nil,false,nil)", got, ok, err)
	}
	if n := pvA.count(); n != 1 {
		t.Fatalf("(a) проверок пароля %d (%q), хочу ровно 1", n, pvA.requested())
	}

	// (b) неверный код и неверный пароль: код не опознан ни в одном
	// сплите — ровно одна проверка полной строки.
	ub := mkUser(t, ctx, st, "single-b", func(u *store.User) {
		u.Email = "single-b@example.com"
		u.PreferChannels = []channel.Channel{channel.Email}
	})
	coreB, pvB := newCountingCore(st, set, box, map[channel.Channel]delivery.Sender{channel.Email: email}, nil)
	if _, err := coreB.Start(ctx, ub, "api"); err != nil {
		t.Fatalf("Start(single-b): %v", err)
	}
	got, ok, err = coreB.VerifyPasswordAndCode(ctx, ub.Username, "wrongpassword000000", "")
	if err != nil || ok || got != nil {
		t.Fatalf("(b) неверный код и пароль: user=%v ok=%v err=%v, хочу (nil,false,nil)", got, ok, err)
	}
	if n := pvB.count(); n != 1 {
		t.Fatalf("(b) проверок пароля %d (%q), хочу ровно 1", n, pvB.requested())
	}

	// (c) push-режим RADIUS: пароль без кода — ровно одна проверка
	// полной строки, затем push-флоу (здесь — до таймаута).
	uc := mkUser(t, ctx, st, "single-c", func(u *store.User) {
		chat := int64(99)
		u.TelegramChatID = &chat
		u.RadiusPush = true
	})
	coreC, pvC := newCountingCore(st, set, box, nil, &fakePush{st: st})
	accept, reason := coreC.RADIUSAuth(ctx, uc.Username, testPassword, "10.9.9.9")
	if accept || reason != "push_timeout" {
		t.Fatalf("(c) push-режим: accept=%v reason=%q, хочу push_timeout", accept, reason)
	}
	if n := pvC.count(); n != 1 {
		t.Fatalf("(c) проверок пароля %d (%q), хочу ровно 1", n, pvC.requested())
	}

	// (d) RADIUS, верный код приклеен к неверному паролю: один argon2,
	// bad_credentials без перебора остальных кандидатов.
	ud := mkUser(t, ctx, st, "single-d", func(u *store.User) {
		u.Email = "single-d@example.com"
		u.PreferChannels = []channel.Channel{channel.Email}
	})
	coreD, pvD := newCountingCore(st, set, box, map[channel.Channel]delivery.Sender{channel.Email: email}, nil)
	if _, err := coreD.Start(ctx, ud, "api"); err != nil {
		t.Fatalf("Start(single-d): %v", err)
	}
	accept, reason = coreD.RADIUSAuth(ctx, ud.Username, "wrongpassword"+email.lastCode(), "10.9.9.9")
	if accept || reason != "bad_credentials" {
		t.Fatalf("(d) RADIUS код верен, пароль нет: accept=%v reason=%q, хочу bad_credentials", accept, reason)
	}
	if n := pvD.count(); n != 1 {
		t.Fatalf("(d) проверок пароля %d (%q), хочу ровно 1", n, pvD.requested())
	}
}

// TestVerifyChallengeCodeTOTPConcurrentSingleUse — гонка одноразовости
// totp-челленджа: две конкурентные подачи кодов двух разных валидных
// окон (C и C+1) по одному челленджу — ровно один успех.
func TestVerifyChallengeCodeTOTPConcurrentSingleUse(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	core := newCore(st, set, box, nil, nil)

	user := mkUser(t, ctx, st, "totprace", func(u *store.User) {
		u.PreferChannels = []channel.Channel{channel.TOTP}
	})
	secret := enrollTOTP(t, ctx, st, box, user, true)
	ch, err := core.Start(ctx, user, "api")
	if err != nil || ch.Channel != channel.TOTP {
		t.Fatalf("Start(totp): ch=%+v err=%v", ch, err)
	}

	cur := time.Now().Unix() / 30
	codes := []string{codeAt(t, secret, cur), codeAt(t, secret, cur+1)}

	start := make(chan struct{})
	oks := make([]bool, len(codes))
	errs := make([]error, len(codes))
	var wg sync.WaitGroup
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			oks[i], errs[i] = core.VerifyChallengeCode(ctx, ch, codes[i])
		}(i)
	}
	close(start)
	wg.Wait()

	successes := 0
	for i := range codes {
		if oks[i] && errs[i] == nil {
			successes++
			continue
		}
		if oks[i] || errs[i] == nil {
			t.Fatalf("подача #%d: ok=%v err=%v — неконсистентный итог", i+1, oks[i], errs[i])
		}
	}
	if successes != 1 {
		t.Fatalf("успехов %d из двух конкурентных подач, хочу ровно 1 (err: %v / %v)",
			successes, errs[0], errs[1])
	}

	// Детерминированная половина той же гонки: «конкурентный победитель»
	// уже забрал одноразовый claim челленджа (fresh-пользователь, окно C).
	u2 := mkUser(t, ctx, st, "totprace2", func(u *store.User) {
		u.PreferChannels = []channel.Channel{channel.TOTP}
	})
	secret2 := enrollTOTP(t, ctx, st, box, u2, true)
	ch2, err := core.Start(ctx, u2, "api")
	if err != nil || ch2.Channel != channel.TOTP {
		t.Fatalf("Start(totp, u2): ch=%+v err=%v", ch2, err)
	}
	cur2 := time.Now().Unix() / 30
	if ok, err := core.VerifyChallengeCode(ctx, ch2, codeAt(t, secret2, cur2)); !ok || err != nil {
		t.Fatalf("первая подача окна C: ok=%v err=%v, хочу успех", ok, err)
	}
	// Вторая подача кодом следующего валидного окна проходит TOTP
	// (C+1 > last_timestep=C), но claim челленджа уже занят →
	// ErrChallengeClosed, а не второй успех.
	if ok, err := core.VerifyChallengeCode(ctx, ch2, codeAt(t, secret2, cur2+1)); ok || !errors.Is(err, ErrChallengeClosed) {
		t.Fatalf("повторная подача после claim: ok=%v err=%v, хочу (false, ErrChallengeClosed)", ok, err)
	}
}

// TestStartPushCooldownAndOrphanCleanup — Start по telegram_push
// соблюдает push_cooldown/push_per_hour (как RADIUSAuth), а челлендж,
// чей push не доставился, удаляется и не держит cooldown.
func TestStartPushCooldownAndOrphanCleanup(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	mustPut(t, ctx, set, "policy", `{"push_per_hour":1}`)

	user := mkUser(t, ctx, st, "pushstart", func(u *store.User) {
		chat := int64(77)
		u.TelegramChatID = &chat
		u.PreferChannels = []channel.Channel{channel.TelegramPush}
	})

	// Доставка падает: осиротевший челлендж удаляется — cooldown и
	// счётчик push_per_hour не растут.
	broken := &fakePush{st: st, err: errors.New("telegram down")}
	coreBroken := newCore(st, set, box, nil, broken)
	if _, err := coreBroken.Start(ctx, user, "api"); !errors.Is(err, ErrNoChannel) {
		t.Fatalf("Start при ошибке доставки: err=%v, хочу ErrNoChannel", err)
	}
	if _, err := coreBroken.Start(ctx, user, "api"); !errors.Is(err, ErrNoChannel) {
		t.Fatalf("повторный Start: err=%v — осиротевший челлендж держит cooldown", err)
	}
	if n, err := st.PushCountSince(ctx, user.ID, time.Now().Add(-time.Hour)); err != nil || n != 0 {
		t.Fatalf("push-челленджей после ошибки доставки: %d (err=%v), хочу 0", n, err)
	}

	// Успешная доставка → второй Start в пределах push_cooldown (или
	// лимита push_per_hour=1) отклоняется ErrCooldown.
	coreOK := newCore(st, set, box, nil, &fakePush{st: st})
	if _, err := coreOK.Start(ctx, user, "api"); err != nil {
		t.Fatalf("Start с доставкой: %v", err)
	}
	if _, err := coreOK.Start(ctx, user, "api"); !errors.Is(err, ErrCooldown) {
		t.Fatalf("Start в cooldown: err=%v, хочу ErrCooldown", err)
	}
}

// withBurnSpy подменяет пакетовую burn-функцию счётчиком вызовов; возвращает
// восстановление и число вызовов на момент чтения.
func withBurnSpy() (restore func(), count func() int) {
	var mu sync.Mutex
	n := 0
	old := burnDummyVerify
	burnDummyVerify = func(string) {
		mu.Lock()
		n++
		mu.Unlock()
	}
	return func() { burnDummyVerify = old },
		func() int {
			mu.Lock()
			defer mu.Unlock()
			return n
		}
}

// TestVerifyPasswordAndCodeBurnsOnNoUser (SEC-005/F2): ветка «пользователь
// не найден» в VerifyPasswordAndCode обязана выполнять полный argon2-цикл
// по хешу-приманке — иначе время ответа выдаёт существование учётной записи.
func TestVerifyPasswordAndCodeBurnsOnNoUser(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	core := newCore(st, set, box, nil, nil)

	restore, count := withBurnSpy()
	defer restore()

	if _, ok, err := core.VerifyPasswordAndCode(ctx, "no-such-user-xyz", "whatever", "123456"); err != nil || ok {
		t.Fatalf("no_user: ok=%v err=%v, хочу (nil,false,nil)", ok, err)
	}
	if n := count(); n != 1 {
		t.Fatalf("argon2-burn на отсутствующего пользователя: вызовов %d, хочу 1", n)
	}
}

// TestRADIUSAuthBurnsOnNoUser (SEC-005/F2): тот же инвариант для RADIUS-ветки.
func TestRADIUSAuthBurnsOnNoUser(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	core := newCore(st, set, box, nil, nil)

	restore, count := withBurnSpy()
	defer restore()

	core.RADIUSAuth(ctx, "no-such-radius-user", "whatever", "127.0.0.1")
	if n := count(); n != 1 {
		t.Fatalf("argon2-burn на отсутствующего пользователя (RADIUS): вызовов %d, хочу 1", n)
	}
}

// TestVerifyAnyCodeTOTPConcurrentSingleSuccess (SEC-006/B1): два конкурентных
// предъявления ОДНОГО TOTP-кода окна C — ровно один успех: CAS в
// TOTPSetTimestep оставляет второй попытке advanced=false → ErrBadCode.
func TestVerifyAnyCodeTOTPConcurrentSingleSuccess(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	// Skew 3: код окна C+2 остаётся валидным ~90 с — тест не гоняется с
	// тиком реального времени. Восстановление — дефолтный skew 1.
	mustPut(t, ctx, set, "totp", `{"issuer":"twofa","digits":6,"period":30,"skew":3}`)
	t.Cleanup(func() { mustPut(t, ctx, set, "totp", `{"issuer":"twofa","digits":6,"period":30,"skew":1}`) })
	core := newCore(st, set, box, nil, nil)

	user := mkUser(t, ctx, st, "totpcas", func(u *store.User) {
		u.PreferChannels = []channel.Channel{channel.TOTP}
	})
	secret := enrollTOTP(t, ctx, st, box, user, true)

	cur := time.Now().Unix()/30 + 2 // будущее окно в пределах skew
	code := codeAt(t, secret, cur)

	const n = 4
	res := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() { _, err := core.VerifyAnyCode(ctx, user, code); res <- err }()
	}
	okCnt := 0
	for i := 0; i < n; i++ {
		if err := <-res; err == nil {
			okCnt++
		} else if !errors.Is(err, ErrBadCode) {
			t.Fatalf("неожиданная ошибка конкурентной проверки: %v", err)
		}
	}
	if okCnt != 1 {
		t.Fatalf("успешных предъявлений одного кода: %d, хочу ровно 1", okCnt)
	}
	_, _, _, _, last, err := st.TOTPGet(ctx, user.ID)
	if err != nil || last != cur {
		t.Fatalf("last_timestep=%d (err %v), хочу %d", last, err, cur)
	}
}

// TestVerifyAnyCodePurposeScoping (SEC-001): доставленные коди расходуются
// только своим назначением — код входа (api) не подтверждает операцию
// кабинета (ui_confirm), экранный код привязки (tg_link) не работает как
// второй фактор входа.
func TestVerifyAnyCodePurposeScoping(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	core := newCore(st, set, box, nil, nil)

	user := mkUser(t, ctx, st, "purposeuser", nil)
	mkCode := func(purpose, code string) {
		t.Helper()
		if err := st.ChallengeCreate(ctx, &store.Challenge{
			UserID: user.ID, Channel: channel.Email,
			CodeHash: secrets.SHA256(code), ExpiresAt: time.Now().Add(5 * time.Minute),
			AttemptsLeft: 3, Purpose: purpose,
		}); err != nil {
			t.Fatalf("создание челленджа %s: %v", purpose, err)
		}
	}
	mkCode("api", "111111")
	mkCode("ui_confirm", "222222")
	mkCode("tg_link", "333333")

	// Код входа (api) принимается на вход, но не для ui_confirm.
	if _, err := core.VerifyAnyCode(ctx, user, "111111", LoginCodePurposes...); err != nil {
		t.Fatalf("api-код на входе: %v", err)
	}
	if _, err := core.VerifyAnyCode(ctx, user, "222222", purposeUIConfirmForTest); err != nil {
		t.Fatalf("ui_confirm-код для кабинета: %v", err)
	}
	// Экранный код привязки не работает ни входом, ни подтверждением кабинета.
	if _, err := core.VerifyAnyCode(ctx, user, "333333", LoginCodePurposes...); !errors.Is(err, ErrBadCode) {
		t.Fatalf("tg_link-код на входе: err=%v, хочу ErrBadCode", err)
	}
	if _, err := core.VerifyAnyCode(ctx, user, "333333", "ui_confirm"); !errors.Is(err, ErrBadCode) {
		t.Fatalf("tg_link-код в кабинете: err=%v, хочу ErrBadCode", err)
	}
	// Код входа не подтверждает операцию кабинета.
	if _, err := core.VerifyAnyCode(ctx, user, "111111", "ui_confirm"); err == nil {
		t.Fatal("api-код подтверждает ui_confirm — purpose-изоляция нарушена")
	} else if !errors.Is(err, ErrBadCode) {
		t.Fatalf("api-код для ui_confirm: err=%v, хочу ErrBadCode", err)
	}

	// VerifyPasswordAndCode: tg_link-код не даёт вход (пароль верен, код не
	// опознан → (user,false)).
	got, ok, err := core.VerifyPasswordAndCode(ctx, user.Username, testPassword, "333333", LoginCodePurposes...)
	if err != nil || ok || got == nil || got.ID != user.ID {
		t.Fatalf("tg_link в VerifyPasswordAndCode: user=%v ok=%v err=%v, хочу (user,false)", got, ok, err)
	}
}

// purposeUIConfirmForTest — purpose подтверждения операций кабинета в тестах
// ядра (в api-пакете это константа purposeUIConfirm).
const purposeUIConfirmForTest = "ui_confirm"

type fakeAlertEmailSender struct {
	mu      sync.Mutex
	calls   int
	to      string
	subject string
	body    string
}

func (s *fakeAlertEmailSender) Name() channel.Channel                     { return channel.Email }
func (s *fakeAlertEmailSender) Send(_ context.Context, _, _ string) error { return nil }
func (s *fakeAlertEmailSender) SendAlert(_ context.Context, to, subject, body string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.to = to
	s.subject = subject
	s.body = body
	return nil
}

func TestNotifyLoginSuccess(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	push := &fakePush{st: st}
	emailSender := &fakeAlertEmailSender{}
	senders := map[channel.Channel]delivery.Sender{
		channel.Email: emailSender,
	}
	core := newCore(st, set, box, senders, push)

	chatID := int64(123456789)
	user := mkUser(t, ctx, st, "notifyuser", func(u *store.User) {
		u.Email = "notify@example.com"
		u.TelegramChatID = &chatID
	})

	// Первый вход: отправляются уведомления и в TG, и на почту
	core.NotifyLoginSuccess(ctx, user.Username, "Wi-Fi (PEAP)", "192.168.1.50", "")

	// Ожидаем завершения фоновой горутины
	time.Sleep(100 * time.Millisecond)

	push.mu.Lock()
	pCalls := push.notifCalls
	pChatID := push.notifChatID
	pText := push.notifText
	push.mu.Unlock()

	emailSender.mu.Lock()
	eCalls := emailSender.calls
	eTo := emailSender.to
	eSubject := emailSender.subject
	eBody := emailSender.body
	emailSender.mu.Unlock()

	if pCalls != 1 || pChatID != chatID {
		t.Fatalf("Telegram notif: calls=%d chatID=%d, want 1 and %d", pCalls, pChatID, chatID)
	}
	if !strings.Contains(pText, "Wi-Fi (PEAP)") || !strings.Contains(pText, "192.168.1.50") {
		t.Fatalf("Telegram notif text missing info: %s", pText)
	}

	if eCalls != 1 || eTo != "notify@example.com" {
		t.Fatalf("Email alert: calls=%d to=%s, want 1 and notify@example.com", eCalls, eTo)
	}
	if !strings.Contains(eSubject, "notifyuser") || !strings.Contains(eBody, "Wi-Fi (PEAP)") {
		t.Fatalf("Email alert body/subject missing info: subj=%s body=%s", eSubject, eBody)
	}

	// Второй вход с тем же методом и IP в пределах кулдауна (2 мин) — уведомление НЕ отправляется
	core.NotifyLoginSuccess(ctx, user.Username, "Wi-Fi (PEAP)", "192.168.1.50", "")
	time.Sleep(50 * time.Millisecond)

	push.mu.Lock()
	pCalls2 := push.notifCalls
	push.mu.Unlock()
	if pCalls2 != 1 {
		t.Fatalf("Expected cooldown to prevent second notif, but got calls=%d", pCalls2)
	}
}

// TestLivePendingPushPurposeScoping — RADIUS-resume не подхватывает чужие
// web-челленджи: purpose api (web-логин), ui_confirm (кабинет) и tg_link
// исключены из livePendingPush; RADIUS-push (purpose = строка сервиса)
// резюмируется (аудит 2026-09-11).
func TestLivePendingPushPurposeScoping(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	core := newCore(st, set, box, nil, nil)
	user := mkUser(t, ctx, st, "lvpp", nil)

	mkPending := func(purpose string) *store.Challenge {
		ch := &store.Challenge{
			UserID:       user.ID,
			Channel:      channel.AppPush,
			PushState:    ptrString("pending"),
			ExpiresAt:    time.Now().Add(5 * time.Minute),
			AttemptsLeft: 1,
			Purpose:      purpose,
		}
		if err := st.ChallengeCreate(ctx, ch); err != nil {
			t.Fatalf("ChallengeCreate(%s): %v", purpose, err)
		}
		return ch
	}

	// Чужие web-purpose не резюмируются и не поглощаются RADIUS'ом.
	for _, p := range []string{"api", "ui_confirm", "tg_link"} {
		mkPending(p)
		if got := core.livePendingPush(ctx, user.ID); got != nil {
			t.Fatalf("purpose %q: livePendingPush вернул челлендж, want nil", p)
		}
	}

	// RADIUS-push (purpose — строка сервиса) резюмируется.
	ch := mkPending("Корпоративный Wi-Fi / Сеть")
	got := core.livePendingPush(ctx, user.ID)
	if got == nil || got.ID != ch.ID {
		t.Fatalf("RADIUS-purpose: got=%v, want челлендж %s", got, ch.ID)
	}
}
