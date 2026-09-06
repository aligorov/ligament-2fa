//go:build integration

// Интеграционные тесты EAP-TTLS/PAP (RFC 5281): ПОЛНЫЙ обмен через
// handleAuth с настоящим crypto/tls.Client — тест-суппликант реализует
// зеркальный мост (тот же адаптер eapConn, сторона клиента): ClientHello →
// handshake → phase-2 AVP (User-Name + User-Password = пароль+TOTP-код) →
// Access-Accept с EAP-Success и MS-MPPE 32+32. Негативные: неверный
// внутренний пароль → Reject; повторное использование State после Success →
// Reject; ретранзмит NAS идемпотентен. Запуск:
//
//	go test -tags integration ./internal/radiusserver/
package radiusserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
	mt "layeh.com/radius/vendors/mikrotik"

	"github.com/aligorov/twofa/internal/auth"
	"github.com/aligorov/twofa/internal/channel"
	"github.com/aligorov/twofa/internal/delivery"
	"github.com/aligorov/twofa/internal/radiusserver/eap"
	"github.com/aligorov/twofa/internal/secrets"
	"github.com/aligorov/twofa/internal/store"
)

// ---- тест-суппликант: зеркальный мост + RADIUS-клиент ----

// ttlsSupplicant — клиент EAP-TTLS/PAP поверх UDP-RADIUS: tls.Client на
// собственном eapConn (Write клиента — исходящие записи, Read — доставленные
// записи сервера), handshake гонится горутиной между запросами.
type ttlsSupplicant struct {
	t       *testing.T
	conn    *eapConn
	tlsConn *tls.Conn
	hsCh    chan error // результат handshake клиента

	pc     net.PacketConn
	addr   net.Addr
	secret []byte

	state       []byte         // RADIUS State из последнего Challenge
	ident       int            // RADIUS Identifier
	lastReqPkt  *radius.Packet // последний Access-Request (для проверки M-A)
	lastRawReq  []byte         // сырой последний запрос (ретрансмиты NAS)
	lastRespEAP []byte         // наш последний EAP-Response (проверка id Success)
	eapReqID    byte           // id последнего EAP-Request сервера

	handshakeDone bool
	sentInner     bool
	firstFlight   bool
}

func newSupplicant(t *testing.T, addr string, secret []byte) *ttlsSupplicant {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	udp, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatalf("resolve %s: %v", addr, err)
	}
	s := &ttlsSupplicant{
		t:           t,
		conn:        newEAPConn(),
		hsCh:        make(chan error, 1),
		pc:          pc,
		addr:        udp,
		secret:      secret,
		firstFlight: true,
	}
	s.tlsConn = tls.Client(s.conn, &tls.Config{
		InsecureSkipVerify: true, // self-signed сертификат сервера
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
	})
	go func() { s.hsCh <- s.tlsConn.Handshake() }()
	return s
}

// exchange отправляет Access-Request и ждёт ответ (без ретрансмитов —
// сервер отвечает мгновенно, push_wait в этих тестах не используется).
func (s *ttlsSupplicant) exchange(pkt *radius.Packet) *radius.Packet {
	s.t.Helper()
	pkt.Identifier = byte(s.ident)
	s.ident++
	rfc2865.UserName_SetString(pkt, "anonymous") // внешний identity
	signRequestMA(pkt)
	raw, err := pkt.Encode()
	if err != nil {
		s.t.Fatalf("Encode: %v", err)
	}
	s.lastReqPkt = pkt
	s.lastRawReq = raw
	if _, err := s.pc.WriteTo(raw, s.addr); err != nil {
		s.t.Fatalf("WriteTo: %v", err)
	}
	return s.readResp()
}

// readResp читает один ответ сервера.
func (s *ttlsSupplicant) readResp() *radius.Packet {
	s.t.Helper()
	buf := make([]byte, 4096)
	if err := s.pc.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		s.t.Fatalf("SetReadDeadline: %v", err)
	}
	n, _, err := s.pc.ReadFrom(buf)
	if err != nil {
		s.t.Fatalf("ReadFrom: %v", err)
	}
	resp, err := radius.Parse(buf[:n], s.secret)
	if err != nil {
		s.t.Fatalf("Parse ответа: %v", err)
	}
	if st := rfc2865.State_Get(resp); len(st) > 0 {
		s.state = st
	}
	return resp
}

// retransmit дублирует последний запрос байт-в-байт (поведение NAS).
func (s *ttlsSupplicant) retransmit() *radius.Packet {
	s.t.Helper()
	if _, err := s.pc.WriteTo(s.lastRawReq, s.addr); err != nil {
		s.t.Fatalf("retransmit WriteTo: %v", err)
	}
	return s.readResp()
}

// request шлёт EAP-Response (с текущим State) и возвращает ответ сервера.
func (s *ttlsSupplicant) request(eapPkt []byte) *radius.Packet {
	pkt := radius.New(radius.CodeAccessRequest, s.secret)
	if len(s.state) > 0 {
		rfc2865.State_Add(pkt, s.state)
	}
	rfc2869.EAPMessage_Set(pkt, eapPkt)
	return s.exchange(pkt)
}

// waitStep — зеркальный waitHandshakeStep сервера: собирает записи
// TLS-клиента до точки покоя («TLS ждёт ввода», handshake завершён или
// таймаут — не ошибка, вернём что накопили).
func (s *ttlsSupplicant) waitStep() (out []byte, err error) {
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for {
		if b := s.conn.takeOutput(); len(b) > 0 {
			out = append(out, b...)
			continue
		}
		select {
		case <-s.conn.outReady:
			continue
		case <-s.conn.wantIn:
			if b := s.conn.takeOutput(); len(b) > 0 {
				out = append(out, b...)
				continue
			}
			// Короткая пауза: TLS мог ещё не дописать ответ (гонка
			// сигналов), прежде чем признаться в ожидании ввода.
			time.Sleep(20 * time.Millisecond)
			if b := s.conn.takeOutput(); len(b) > 0 {
				out = append(out, b...)
				continue
			}
			return out, nil
		case hsErr := <-s.hsCh:
			if hsErr != nil {
				return nil, hsErr
			}
			s.handshakeDone = true
			if b := s.conn.takeOutput(); len(b) > 0 {
				out = append(out, b...)
			}
			return out, nil
		case <-timer.C:
			return out, nil
		}
	}
}

// runExchange — цикл TTLS от полученного Challenge до терминального
// ответа (Accept/Reject): доставляет записи сервера в мост, забирает
// записи клиента, после handshake шлёт AVP внутреннего PAP.
func (s *ttlsSupplicant) runExchange(resp *radius.Packet, username, password string) *radius.Packet {
	s.t.Helper()
	for {
		if resp.Code == radius.CodeAccessAccept || resp.Code == radius.CodeAccessReject {
			return resp
		}
		if resp.Code != radius.CodeAccessChallenge {
			s.t.Fatalf("неожиданный код ответа %v", resp.Code)
		}
		raw, err := rfc2869.EAPMessage_Lookup(resp)
		if err != nil {
			s.t.Fatalf("Challenge без EAP-Message: %v", err)
		}
		p, err := eap.Parse(raw)
		if err != nil {
			s.t.Fatalf("Parse challenge: %v", err)
		}
		if p.Code != eap.CodeRequest || p.Type() != eap.TypeTTLS {
			s.t.Fatalf("ожидался EAP-Request/TTLS, получен code=%d type=%d", p.Code, p.Type())
		}
		s.eapReqID = p.ID
		ttlsMsg, err := eap.ParseTTLS(p.Data)
		if err != nil {
			s.t.Fatalf("ParseTTLS challenge: %v", err)
		}
		if len(ttlsMsg.Payload) > 0 {
			s.conn.deliver(ttlsMsg.Payload)
		}

		out, err := s.waitStep()
		if err != nil {
			s.t.Fatalf("TLS-клиент: %v", err)
		}
		if s.handshakeDone && !s.sentInner {
			// Туннель поднят: phase-2 AVP внутреннего PAP.
			s.sentInner = true
			if _, werr := s.tlsConn.Write(eap.BuildInnerPAP(username, password)); werr != nil {
				s.t.Fatalf("запись AVP: %v", werr)
			}
			out = append(out, s.conn.takeOutput()...)
		}
		if len(out) > eap.MaxFragment {
			s.t.Fatalf("вылет клиента %d байт — зеркальная фрагментация в тесте не реализована", len(out))
		}
		var flags byte
		if s.firstFlight && len(out) > 0 {
			flags = eap.TTLSFlagStart
			s.firstFlight = false
		}
		pkt := eap.BuildTTLS(eap.CodeResponse, s.eapReqID, flags, len(out), out)
		s.lastRespEAP = pkt
		resp = s.request(pkt)
	}
}

// authenticate — полный обмен с нуля (Identity → …).
func (s *ttlsSupplicant) authenticate(username, password string) *radius.Packet {
	return s.runExchange(s.request(eap.BuildIdentity(eap.CodeResponse, 0, "anonymous")),
		username, password)
}

// enrollEAPTOTP выдаёт и подтверждает TOTP-секрет (паттерн auth-тестов).
func enrollEAPTOTP(t *testing.T, ctx context.Context, st *store.Store, box *secrets.Box, u *store.User) string {
	t.Helper()
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer: "twofa", AccountName: u.Username,
		Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("totp.Generate: %v", err)
	}
	enc := box.EncryptAAD(auth.AADTOTP(u.Username), []byte(key.Secret()))
	if err := st.TOTPSave(ctx, u.ID, enc, 6, 30); err != nil {
		t.Fatalf("TOTPSave: %v", err)
	}
	if err := st.TOTPConfirm(ctx, u.ID); err != nil {
		t.Fatalf("TOTPConfirm: %v", err)
	}
	return key.Secret()
}

// ---- тесты ----

// TestEAPTTLSFullExchange: полный TTLS-обмен с TOTP «пароль+код» —
// Accept, EAP-Success с id последнего ответа, MS-MPPE 32+32, корректный
// Message-Authenticator, аудит radius_eap ok, State после Success мёртв.
func TestEAPTTLSFullExchange(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	mustPut(t, ctx, set, "radius.reply_attributes",
		`{"Mikrotik-Group":"wifi-users","Session-Timeout":"3600"}`)

	email := &fakeSender{ch: channel.Email}
	core := newCore(st, set, box, map[channel.Channel]delivery.Sender{channel.Email: email}, nil)
	srv := New(core, st, set)
	srvCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	authAddr, _ := startServers(t, srvCtx, srv)
	secret := []byte(set.Get().RadiusSecret)

	if err := srv.EnsureEAPCert(ctx); err != nil {
		t.Fatalf("EnsureEAPCert: %v", err)
	}

	user := mkUser(t, ctx, st, "eapwifi", func(u *store.User) {
		u.PreferChannels = []channel.Channel{channel.TOTP}
	})
	totpSecret := enrollEAPTOTP(t, ctx, st, box, user)
	code, err := totp.GenerateCode(totpSecret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	supp := newSupplicant(t, authAddr, secret)
	resp := supp.authenticate(user.Username, testPassword+code)
	if resp.Code != radius.CodeAccessAccept {
		t.Fatalf("код ответа %v, хочу Access-Accept", resp.Code)
	}

	// EAP-Success с id последнего EAP-Response (RFC 3748 §4.2).
	raw, err := rfc2869.EAPMessage_Lookup(resp)
	if err != nil {
		t.Fatalf("Accept без EAP-Message: %v", err)
	}
	p, err := eap.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Code != eap.CodeSuccess {
		t.Fatalf("EAP-код %d, хочу Success", p.Code)
	}
	lastResp, err := eap.Parse(supp.lastRespEAP)
	if err != nil {
		t.Fatalf("Parse lastResp: %v", err)
	}
	if p.ID != lastResp.ID {
		t.Fatalf("id EAP-Success = %d, хочу %d (id последнего Response)", p.ID, lastResp.ID)
	}

	// MS-MPPE-ключи: расшифровываются в 32+32 несовпадающих байта.
	recvKey := decryptMSMPPE(t, resp, supp.lastReqPkt, 17)
	sendKey := decryptMSMPPE(t, resp, supp.lastReqPkt, 16)
	if len(recvKey) != 32 || len(sendKey) != 32 {
		t.Fatalf("MS-MPPE: Recv=%d Send=%d байт, хочу 32+32", len(recvKey), len(sendKey))
	}
	if bytes.Equal(recvKey, sendKey) {
		t.Fatal("Recv и Send ключи совпадают")
	}

	// Reply-атрибуты как в PAP-пути.
	if got := mt.MikrotikGroup_GetString(resp); got != "wifi-users" {
		t.Fatalf("Mikrotik-Group = %q, хочу wifi-users", got)
	}

	// Message-Authenticator ответа корректен (проверка клиентской стороной).
	if !hasMessageAuthenticator(resp) || !verifyResponseMA(supp.lastReqPkt, resp) {
		t.Fatal("Message-Authenticator Accept-а отсутствует или неверен")
	}

	// Аудит radius_eap записан с ok.
	waitAudit(t, ctx, st, user.Username, "radius_eap", "ok")

	// Повторное использование State после Success: сессии нет — Reject.
	stale := supp.request(eap.BuildTTLS(eap.CodeResponse, p.ID, 0, -1, []byte{1, 2, 3}))
	if stale.Code != radius.CodeAccessReject {
		t.Fatalf("State после Success: код %v, хочу Reject", stale.Code)
	}
}

// TestEAPTTLSWrongPassword: неверный внутренний пароль — Reject с
// EAP-Failure, аудит radius_eap с fail.
func TestEAPTTLSWrongPassword(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()

	core := newCore(st, set, box, nil, nil)
	srv := New(core, st, set)
	srvCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	authAddr, _ := startServers(t, srvCtx, srv)
	secret := []byte(set.Get().RadiusSecret)

	if err := srv.EnsureEAPCert(ctx); err != nil {
		t.Fatalf("EnsureEAPCert: %v", err)
	}

	user := mkUser(t, ctx, st, "eapwrongpass", func(u *store.User) {
		u.PreferChannels = []channel.Channel{channel.TOTP}
	})
	totpSecret := enrollEAPTOTP(t, ctx, st, box, user)
	code, err := totp.GenerateCode(totpSecret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	supp := newSupplicant(t, authAddr, secret)
	resp := supp.authenticate(user.Username, "completely-wrong"+code)
	if resp.Code != radius.CodeAccessReject {
		t.Fatalf("код ответа %v, хочу Access-Reject", resp.Code)
	}
	raw, err := rfc2869.EAPMessage_Lookup(resp)
	if err != nil {
		t.Fatalf("Reject без EAP-Message: %v", err)
	}
	p, err := eap.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Code != eap.CodeFailure {
		t.Fatalf("EAP-код %d, хочу Failure", p.Code)
	}
	waitAudit(t, ctx, st, user.Username, "radius_eap", "fail")
}

// TestEAPTTLSRetransmitIdentity: дубликат Identity-запроса от NAS — сервер
// повторяет последний Challenge байт-в-байт (идемпотентность), обмен после
// дубликата доходит до Accept.
func TestEAPTTLSRetransmitIdentity(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()

	core := newCore(st, set, box, nil, nil)
	srv := New(core, st, set)
	srvCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	authAddr, _ := startServers(t, srvCtx, srv)
	secret := []byte(set.Get().RadiusSecret)

	if err := srv.EnsureEAPCert(ctx); err != nil {
		t.Fatalf("EnsureEAPCert: %v", err)
	}

	user := mkUser(t, ctx, st, "eapretrans", func(u *store.User) {
		u.PreferChannels = []channel.Channel{channel.TOTP}
	})
	totpSecret := enrollEAPTOTP(t, ctx, st, box, user)
	code, err := totp.GenerateCode(totpSecret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	supp := newSupplicant(t, authAddr, secret)
	resp := supp.request(eap.BuildIdentity(eap.CodeResponse, 0, "anonymous"))
	if resp.Code != radius.CodeAccessChallenge {
		t.Fatalf("код %v, хочу Challenge", resp.Code)
	}
	first := mustEAPMessage(resp)

	// Дубликат того же запроса — тот же самый EAP-пакет в ответе.
	dup := supp.retransmit()
	if dup.Code != radius.CodeAccessChallenge {
		t.Fatalf("дубликат: код %v, хочу Challenge", dup.Code)
	}
	if !bytes.Equal(mustEAPMessage(dup), first) {
		t.Fatal("ретранзмит Identity не повторил последний Challenge байт-в-байт")
	}

	// Обмен продолжается и доходит до Accept.
	final := supp.runExchange(resp, user.Username, testPassword+code)
	if final.Code != radius.CodeAccessAccept {
		t.Fatalf("код ответа %v, хочу Access-Accept после ретрансмита", final.Code)
	}
}

// waitAudit ждёт появления события в audit_log с нужным результатом.
func waitAudit(t *testing.T, ctx context.Context, st *store.Store, username, event, result string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		events, err := st.AuditList(ctx, store.AuditFilter{Username: username, Event: event})
		if err == nil && len(events) > 0 {
			if events[0].Result != result {
				t.Fatalf("%s result = %s, хочу %s", event, events[0].Result, result)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s (result=%s) не появился в audit_log за 3с", event, result)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
