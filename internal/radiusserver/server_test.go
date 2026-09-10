//go:build integration

// Интеграционные тесты RADIUS-сервера: требуют Docker (testcontainers-go,
// postgres:16-alpine) — паттерн подключения internal/auth/core_test.go.
// Слушатели поднимаются на 127.0.0.1:0 (ServeAuth/ServeAcct на готовом
// conn), клиент — radius.Exchange. Запуск:
//
//	go test -tags integration ./internal/radiusserver/
package radiusserver

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
	mt "layeh.com/radius/vendors/mikrotik"

	"github.com/aligorov/twofa/internal/auth"
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
			// postgres:*-alpine печатает ready-сообщение дважды (initdb).
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

// ---- фейки (паттерн internal/auth/core_test.go) ----

type fakeSender struct {
	ch    channel.Channel
	mu    sync.Mutex
	codes []string
}

func (f *fakeSender) Name() channel.Channel { return f.ch }

func (f *fakeSender) Send(_ context.Context, _, code string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
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

// probePush — PushNotifier, который НЕ меняет состояние челленджа сам, а
// сообщает тесту ID созданного челленджа: утверждение выставляется тестовой
// горутиной через store.ChallengeSetPush (имитация нажатия кнопки в боте).
type probePush struct {
	seen chan uuid.UUID
}

func newProbePush() *probePush { return &probePush{seen: make(chan uuid.UUID, 1)} }

func (p *probePush) SendPush(_ context.Context, _ int64, _, _, _ string, chID uuid.UUID) error {
	select {
	case p.seen <- chID:
	default:
	}
	return nil
}

func (p *probePush) SendNotification(_ context.Context, _ int64, _ string) error {
	return nil
}

// approveAfter ждёт челлендж от probePush и спустя d подтверждает его.
func approveAfter(st *store.Store, p *probePush, d time.Duration, state string) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		chID := <-p.seen
		time.Sleep(d)
		_ = st.ChallengeSetPush(context.Background(), chID, state)
	}()
	return done
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

func newCore(st *store.Store, set *settings.M, box *secrets.Box, senders map[channel.Channel]delivery.Sender, push auth.PushNotifier) *auth.Core {
	return auth.NewCore(st, set, box, senders, auth.NewLocalVerifier(st), push)
}

// startServers поднимает auth+acct слушатели на эфемерных портах и возвращает
// их адреса; остановка — отменой ctx.
func startServers(t *testing.T, ctx context.Context, srv *Server) (authAddr, acctAddr string) {
	t.Helper()
	lc := net.ListenConfig{}
	authConn, err := lc.ListenPacket(ctx, "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen auth: %v", err)
	}
	acctConn, err := lc.ListenPacket(ctx, "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen acct: %v", err)
	}
	authAddr, acctAddr = authConn.LocalAddr().String(), acctConn.LocalAddr().String()

	serveDone := make(chan error, 2)
	go func() { serveDone <- srv.ServeAuth(ctx, authConn) }()
	go func() { serveDone <- srv.ServeAcct(ctx, acctConn) }()
	t.Cleanup(func() {
		for i := 0; i < 2; i++ {
			select {
			case err := <-serveDone:
				if err != nil {
					t.Logf("listener: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Error("слушатель не остановился за 10с")
				return
			}
		}
	})
	return authAddr, acctAddr
}

// accessRequest — клиентский пакет Access-Request (PAP). Message-
// Authenticator подписывается всегда: radius.require_message_authenticator
// по умолчанию true — сервер отбрасывает Access-Request без валидного M-A
// (RFC 3579 / BlastRADIUS); реальный патченый NAS подписывает так же.
func accessRequest(secret []byte, username, password string) *radius.Packet {
	p := radius.New(radius.CodeAccessRequest, secret)
	rfc2865.UserName_SetString(p, username)
	rfc2865.UserPassword_SetString(p, password)
	signRequestMA(p)
	return p
}

// exchangeWrap — Exchange с таймаутом; возвращает ответ или ошибку.
func exchangeWrap(ctx context.Context, pkt *radius.Packet, addr string) (*radius.Packet, error) {
	return radius.Exchange(ctx, pkt, addr)
}

// ---- тесты ----

func TestRadiusAcceptWithReplyAttrs(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	mustPut(t, ctx, set, "radius.reply_attributes",
		`{"Mikrotik-Group":"wifi-users","Reply-Message":"ok"}`)

	email := &fakeSender{ch: channel.Email}
	srv := New(newCore(st, set, box, map[channel.Channel]delivery.Sender{channel.Email: email}, nil), st, set)
	srvCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	authAddr, _ := startServers(t, srvCtx, srv)
	secret := []byte(set.Get().RadiusSecret)

	// Глобальные reply-атрибуты: Accept с Mikrotik-Group.
	user := mkUser(t, ctx, st, "radattr", func(u *store.User) {
		u.Email = "radattr@example.com"
		u.PreferChannels = []channel.Channel{channel.Email}
	})
	core := newCore(st, set, box, map[channel.Channel]delivery.Sender{channel.Email: email}, nil)
	if _, err := core.Start(ctx, user, "api"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	cctx, ccancel := context.WithTimeout(ctx, 5*time.Second)
	defer ccancel()
	resp, err := exchangeWrap(cctx, accessRequest(secret, user.Username, testPassword+email.lastCode()), authAddr)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if resp.Code != radius.CodeAccessAccept {
		t.Fatalf("код ответа %v, хочу Access-Accept", resp.Code)
	}
	if got := mt.MikrotikGroup_GetString(resp); got != "wifi-users" {
		t.Fatalf("Mikrotik-Group = %q, хочу wifi-users", got)
	}
	if got := rfc2865.ReplyMessage_GetString(resp); got != "ok" {
		t.Fatalf("Reply-Message = %q, хочу ok", got)
	}

	// Per-user radius_reply переопределяет глобальные.
	vip := mkUser(t, ctx, st, "radvip", func(u *store.User) {
		u.Email = "radvip@example.com"
		u.PreferChannels = []channel.Channel{channel.Email}
		u.RadiusReply = map[string]string{"Mikrotik-Address-List": "vip-list"}
	})
	if _, err := core.Start(ctx, vip, "api"); err != nil {
		t.Fatalf("Start(vip): %v", err)
	}
	cctx2, ccancel2 := context.WithTimeout(ctx, 5*time.Second)
	defer ccancel2()
	resp, err = exchangeWrap(cctx2, accessRequest(secret, vip.Username, testPassword+email.lastCode()), authAddr)
	if err != nil {
		t.Fatalf("Exchange(vip): %v", err)
	}
	if resp.Code != radius.CodeAccessAccept {
		t.Fatalf("vip: код ответа %v, хочу Access-Accept", resp.Code)
	}
	if got := mt.MikrotikAddressList_GetString(resp); got != "vip-list" {
		t.Fatalf("Mikrotik-Address-List = %q, хочу vip-list", got)
	}
	if got := mt.MikrotikGroup_GetString(resp); got != "" {
		t.Fatalf("глобальный Mikrotik-Group не должен пробиваться при per-user карте: %q", got)
	}
}

func TestRadiusWrongCodeReject(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	mustPut(t, ctx, set, "radius.reply_attributes", `{}`)

	email := &fakeSender{ch: channel.Email}
	core := newCore(st, set, box, map[channel.Channel]delivery.Sender{channel.Email: email}, nil)
	srv := New(core, st, set)
	srvCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	authAddr, _ := startServers(t, srvCtx, srv)
	secret := []byte(set.Get().RadiusSecret)

	user := mkUser(t, ctx, st, "radwrong", func(u *store.User) {
		u.Email = "radwrong@example.com"
		u.PreferChannels = []channel.Channel{channel.Email}
	})
	if _, err := core.Start(ctx, user, "api"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	cctx, ccancel := context.WithTimeout(ctx, 5*time.Second)
	defer ccancel()
	resp, err := exchangeWrap(cctx, accessRequest(secret, user.Username, testPassword+"000000"), authAddr)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if resp.Code != radius.CodeAccessReject {
		t.Fatalf("код ответа %v, хочу Access-Reject", resp.Code)
	}
	if got := rfc2865.ReplyMessage_GetString(resp); got != "rejected" {
		t.Fatalf("Reply-Message = %q, хочу rejected (без внутренних деталей)", got)
	}
}

func TestRadiusPushWaitHold(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	mustPut(t, ctx, set, "radius.push_wait", `"4s"`)

	push := newProbePush()
	core := newCore(st, set, box, nil, push)
	srv := New(core, st, set)
	srvCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	authAddr, _ := startServers(t, srvCtx, srv)
	secret := []byte(set.Get().RadiusSecret)

	// Подтверждение выставляется тестовой горутиной через
	// store.ChallengeSetPush спустя 1.5с после создания челленджа.
	done := approveAfter(st, push, 1500*time.Millisecond, "approved")

	user := mkUser(t, ctx, st, "radhold", func(u *store.User) {
		chat := int64(4242)
		u.TelegramChatID = &chat
		u.RadiusPush = true
	})
	cctx, ccancel := context.WithTimeout(ctx, 15*time.Second)
	defer ccancel()
	start := time.Now()
	resp, err := exchangeWrap(cctx, accessRequest(secret, user.Username, testPassword), authAddr)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if resp.Code != radius.CodeAccessAccept {
		t.Fatalf("код ответа %v, хочу Access-Accept (push подтверждён во время удержания)", resp.Code)
	}
	if waited := time.Since(start); waited < time.Second {
		t.Fatalf("ответ пришёл через %s — удержание push_wait не сработало", waited)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("тестовая горутина подтверждения не завершилась")
	}
	events, err := st.AuditList(ctx, store.AuditFilter{Username: user.Username, Event: "radius_auth"})
	if err != nil || len(events) == 0 {
		t.Fatalf("radius_auth в аудите: rows=%d err=%v", len(events), err)
	}
	if events[0].Detail["reason"] != "push_ok" {
		t.Fatalf("reason последнего radius_auth = %v, хочу push_ok", events[0].Detail["reason"])
	}
}

func TestRadiusPushDeniedAndTimeout(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	mustPut(t, ctx, set, "radius.push_wait", `"3s"`)

	// Denied: «Это не я» во время удержания.
	push := newProbePush()
	core := newCore(st, set, box, nil, push)
	srv := New(core, st, set)
	srvCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	authAddr, _ := startServers(t, srvCtx, srv)
	secret := []byte(set.Get().RadiusSecret)

	done := approveAfter(st, push, time.Second, "denied")
	denied := mkUser(t, ctx, st, "raddenied", func(u *store.User) {
		chat := int64(1)
		u.TelegramChatID = &chat
		u.RadiusPush = true
	})
	cctx, ccancel := context.WithTimeout(ctx, 15*time.Second)
	defer ccancel()
	resp, err := exchangeWrap(cctx, accessRequest(secret, denied.Username, testPassword), authAddr)
	if err != nil {
		t.Fatalf("Exchange(denied): %v", err)
	}
	if resp.Code != radius.CodeAccessReject {
		t.Fatalf("denied: код ответа %v, хочу Access-Reject", resp.Code)
	}
	<-done

	// Timeout: подтверждения нет — Reject после push_wait.
	slow := mkUser(t, ctx, st, "radslow", func(u *store.User) {
		chat := int64(2)
		u.TelegramChatID = &chat
		u.RadiusPush = true
	})
	cctx2, ccancel2 := context.WithTimeout(ctx, 15*time.Second)
	defer ccancel2()
	start := time.Now()
	resp, err = exchangeWrap(cctx2, accessRequest(secret, slow.Username, testPassword), authAddr)
	if err != nil {
		t.Fatalf("Exchange(slow): %v", err)
	}
	if resp.Code != radius.CodeAccessReject {
		t.Fatalf("slow: код ответа %v, хочу Access-Reject по таймауту push_wait", resp.Code)
	}
	if waited := time.Since(start); waited < 2*time.Second {
		t.Fatalf("reject пришёл через %s — удержание push_wait не сработало", waited)
	}
	events, err := st.AuditList(ctx, store.AuditFilter{Username: slow.Username, Event: "radius_auth"})
	if err != nil || len(events) == 0 {
		t.Fatalf("radius_auth в аудите: rows=%d err=%v", len(events), err)
	}
	if events[0].Detail["reason"] != "push_timeout" {
		t.Fatalf("reason = %v, хочу push_timeout", events[0].Detail["reason"])
	}
}

func TestRadiusWrongSecretDropped(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	srv := New(newCore(st, set, box, nil, nil), st, set)
	srvCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	authAddr, _ := startServers(t, srvCtx, srv)
	serverSecret := set.Get().RadiusSecret
	wrong := "definitely-not-" + serverSecret

	mkUser(t, ctx, st, "radsecret", nil)
	// Короткий ctx: неверный секрет → пакет молча дропается, Exchange
	// ретранслирует до отмены контекста.
	cctx, ccancel := context.WithTimeout(ctx, 900*time.Millisecond)
	defer ccancel()
	_, err := exchangeWrap(cctx, accessRequest([]byte(wrong), "radsecret", testPassword), authAddr)
	if err == nil {
		t.Fatal("неверный секрет: Exchange не вернул ошибку (пакет не должен был получить ответ)")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ошибка Exchange = %v, хочу context.DeadlineExceeded", err)
	}
}

func TestRadiusAccounting(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	srv := New(newCore(st, set, box, nil, nil), st, set)
	srvCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	_, acctAddr := startServers(t, srvCtx, srv)
	secret := []byte(set.Get().RadiusSecret)

	pkt := radius.New(radius.CodeAccountingRequest, secret)
	rfc2865.UserName_SetString(pkt, "acctuser")
	rfc2866.AcctSessionID_SetString(pkt, "81a0b7c9")
	rfc2866.AcctStatusType_Set(pkt, rfc2866.AcctStatusType_Value_Start)

	cctx, ccancel := context.WithTimeout(ctx, 5*time.Second)
	defer ccancel()
	resp, err := exchangeWrap(cctx, pkt, acctAddr)
	if err != nil {
		t.Fatalf("Exchange(acct): %v", err)
	}
	if resp.Code != radius.CodeAccountingResponse {
		t.Fatalf("код ответа %v, хочу Accounting-Response", resp.Code)
	}

	// Событие продублировано в audit_log.
	deadline := time.Now().Add(3 * time.Second)
	for {
		rows, err := st.AuditList(ctx, store.AuditFilter{Username: "acctuser", Event: "radius_acct"})
		if err != nil {
			t.Fatalf("AuditList: %v", err)
		}
		if len(rows) > 0 {
			if rows[0].Detail["session_id"] != "81a0b7c9" || rows[0].Detail["status"] != "Start" {
				t.Fatalf("detail radius_acct = %v, хочу session_id=81a0b7c9 status=Start", rows[0].Detail)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("radius_acct не появился в audit_log за 3с")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestRadiusFailLockedThrottle(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	mustPut(t, ctx, set, "policy", `{"max_fail":2}`)

	core := newCore(st, set, box, nil, nil)
	srv := New(core, st, set)
	srvCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	authAddr, _ := startServers(t, srvCtx, srv)
	secret := []byte(set.Get().RadiusSecret)

	user := mkUser(t, ctx, st, "radthrottle", nil)
	send := func() radius.Code {
		cctx, ccancel := context.WithTimeout(ctx, 5*time.Second)
		defer ccancel()
		resp, err := exchangeWrap(cctx, accessRequest(secret, user.Username, "wrongpassword"), authAddr)
		if err != nil {
			t.Fatalf("Exchange: %v", err)
		}
		return resp.Code
	}

	// Две неудачи наполняют fail-счётчик (radius_fail в audit_log)…
	for i := 0; i < 2; i++ {
		if code := send(); code != radius.CodeAccessReject {
			t.Fatalf("неудача #%d: код %v, хочу Reject", i+1, code)
		}
	}
	// …третий запрос отвергается по FailLocked БЕЗ проверки учётных данных.
	if code := send(); code != radius.CodeAccessReject {
		t.Fatalf("заблокированный: код %v, хочу Reject", code)
	}
	events, err := st.AuditList(ctx, store.AuditFilter{Username: user.Username, Event: "radius_auth"})
	if err != nil || len(events) < 3 {
		t.Fatalf("radius_auth в аудите: rows=%d err=%v", len(events), err)
	}
	if reason := events[0].Detail["reason"]; reason != "locked" {
		t.Fatalf("reason последнего radius_auth = %v, хочу locked (отказ без проверки)", reason)
	}
}

func TestRadiusMessageAuthenticatorRequest(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	mustPut(t, ctx, set, "radius.reply_attributes", `{}`)

	email := &fakeSender{ch: channel.Email}
	core := newCore(st, set, box, map[channel.Channel]delivery.Sender{channel.Email: email}, nil)
	srv := New(core, st, set)
	srvCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	authAddr, _ := startServers(t, srvCtx, srv)
	secret := []byte(set.Get().RadiusSecret)

	user := mkUser(t, ctx, st, "radma", func(u *store.User) {
		u.Email = "radma@example.com"
		u.PreferChannels = []channel.Channel{channel.Email}
	})
	if _, err := core.Start(ctx, user, "api"); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Валидный Message-Authenticator: Accept, ответ содержит корректный M-A.
	pkt := accessRequest(secret, user.Username, testPassword+email.lastCode())
	signRequestMA(pkt)
	cctx, ccancel := context.WithTimeout(ctx, 5*time.Second)
	defer ccancel()
	resp, err := exchangeWrap(cctx, pkt, authAddr)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if resp.Code != radius.CodeAccessAccept {
		t.Fatalf("код ответа %v, хочу Access-Accept", resp.Code)
	}
	if !hasMessageAuthenticator(resp) {
		t.Fatal("ответ не содержит Message-Authenticator (требование RFC 3579)")
	}
	if !verifyResponseMA(pkt, resp) {
		t.Fatal("Message-Authenticator ответа не проходит проверку")
	}

	// Подделанный M-A: пакет молча дропается → таймаут клиента.
	bad := accessRequest(secret, user.Username, testPassword+email.lastCode())
	signRequestMA(bad)
	attr, _ := bad.Attributes.Lookup(messageAuthenticatorType)
	attr[0] ^= 0xFF
	cctx2, ccancel2 := context.WithTimeout(ctx, 900*time.Millisecond)
	defer ccancel2()
	if _, err := exchangeWrap(cctx2, bad, authAddr); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("подделанный M-A: err=%v, хочу context.DeadlineExceeded", err)
	}
}

func TestRadiusEmptySecretSkipsListeners(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	realSecret := set.Get().RadiusSecret
	mustPut(t, ctx, set, "radius.secret", `""`)
	t.Cleanup(func() { mustPut(t, ctx, set, "radius.secret", `"`+realSecret+`"`) })

	srv := New(newCore(st, set, box, nil, nil), st, set)
	srvCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := srv.ListenAndServe(srvCtx); err != nil {
		t.Fatalf("ListenAndServe с пустым секретом: err=%v, хочу nil", err)
	}
	if waited := time.Since(start); waited > 2*time.Second {
		t.Fatalf("ListenAndServe держал соединение %s при пустом секрете — слушатели не должны стартовать", waited)
	}

	// ServeAuth при пустом секрете возвращает ошибку немедленно.
	lc := net.ListenConfig{}
	conn, err := lc.ListenPacket(ctx, "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	if err := srv.ServeAuth(srvCtx, conn); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("ServeAuth: err=%v, хочу ErrNoSecret", err)
	}
}

// TestRadiusSecretHotRotation (F1): секрет читается из текущего снимка
// настроек НА КАЖДЫЙ пакет — смена radius.secret применяется к работающему
// серверу без рестарта: exchange с новым секретом проходит, со старым —
// молча дропается. Accounting-запросы отвечают независимо от пользователей,
// поэтому ротация проверяется детерминированно.
func TestRadiusSecretHotRotation(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	secretA := set.Get().RadiusSecret

	srv := New(newCore(st, set, box, nil, nil), st, set)
	srvCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	_, acctAddr := startServers(t, srvCtx, srv)

	acct := func(secret string) radius.Code {
		pkt := radius.New(radius.CodeAccountingRequest, []byte(secret))
		rfc2865.UserName_SetString(pkt, "rotate-user")
		rfc2866.AcctStatusType_Set(pkt, rfc2866.AcctStatusType_Value_Start)
		cctx, ccancel := context.WithTimeout(ctx, 3*time.Second)
		defer ccancel()
		resp, err := exchangeWrap(cctx, pkt, acctAddr)
		if err != nil {
			t.Fatalf("Exchange(secret=%q…): %v", secret[:4], err)
		}
		return resp.Code
	}

	// Секрет A (стартовый): обмен работает.
	if code := acct(secretA); code != radius.CodeAccountingResponse {
		t.Fatalf("до ротации: код %v, хочу Accounting-Response", code)
	}

	// Ротация: radius.secret = B — новый секрет работает сразу.
	secretB := "rotated-hot-" + secrets.RandomToken(16)
	mustPut(t, ctx, set, "radius.secret", `"`+secretB+`"`)
	t.Cleanup(func() { mustPut(t, ctx, set, "radius.secret", `"`+secretA+`"`) })
	if code := acct(secretB); code != radius.CodeAccountingResponse {
		t.Fatalf("после ротации (новый секрет): код %v, хочу Accounting-Response", code)
	}

	// Старый секрет больше не аутентичен: пакет дропается, клиент
	// ретранслирует до отмены контекста.
	pkt := radius.New(radius.CodeAccountingRequest, []byte(secretA))
	rfc2865.UserName_SetString(pkt, "rotate-user")
	rfc2866.AcctStatusType_Set(pkt, rfc2866.AcctStatusType_Value_Start)
	cctx, ccancel := context.WithTimeout(ctx, 900*time.Millisecond)
	defer ccancel()
	if _, err := exchangeWrap(cctx, pkt, acctAddr); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("старый секрет после ротации: err=%v, хочу context.DeadlineExceeded (drop)", err)
	}
}
