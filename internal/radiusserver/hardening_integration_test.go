//go:build integration

// Интеграционные тесты hardening-правок Фазы 1 (аудит АГЕНТ 5):
// Message-Authenticator (RFC 3579 / BlastRADIUS), per-NAS rate limit,
// accounting-фильтрация Interim-Update, возобновление живого push-челленджа
// в cooldown. Запуск:
//
//	go test -tags integration ./internal/radiusserver/
package radiusserver

import (
	"context"
	"net"
	"testing"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
	"layeh.com/radius/rfc2869"

	"github.com/aligorov/twofa/internal/radiusserver/eap"
	"github.com/aligorov/twofa/internal/store"
)

// rawSendNoMA отправляет пакет БЕЗ Message-Authenticator и ждёт ответ до
// таймаута ctx (nil — ответа не было: сервер молча отбросил пакет).
func rawSendNoMA(ctx context.Context, pkt *radius.Packet, addr string) *radius.Packet {
	raw, err := pkt.Encode()
	if err != nil {
		return nil
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil
	}
	defer pc.Close()
	udp, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil
	}
	if _, err := pc.WriteTo(raw, udp); err != nil {
		return nil
	}
	if err := pc.SetReadDeadline(time.Now().Add(900 * time.Millisecond)); err != nil {
		return nil
	}
	buf := make([]byte, 4096)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		return nil // таймаут — ответа нет
	}
	resp, err := radius.Parse(buf[:n], pkt.Secret)
	if err != nil {
		return nil
	}
	return resp
}

// TestRadiusRequireMessageAuthenticator: Access-Request без валидного
// Message-Authenticator отбрасывается — и EAP (RFC 3579 §3.2 MUST, всегда),
// и PAP (при radius.require_message_authenticator=true, дефолт). Ответ на
// подписанный запрос всегда несёт MA. Отключение настройки возвращает
// совместимость для легаси-PAP, но EAP без MA не обслуживается никогда.
func TestRadiusRequireMessageAuthenticator(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()

	core := newCore(st, set, box, nil, nil)
	srv := New(core, st, set)
	srvCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	authAddr, _ := startServers(t, srvCtx, srv)
	secret := []byte(set.Get().RadiusSecret)

	user := mkUser(t, ctx, st, "radmareq", nil)

	// PAP без MA (настройка по умолчанию true) — молчаливый discard.
	pap := radius.New(radius.CodeAccessRequest, secret)
	rfc2865.UserName_SetString(pap, user.Username)
	rfc2865.UserPassword_SetString(pap, "wrongpassword")
	cctx, ccancel := context.WithTimeout(ctx, time.Second)
	defer ccancel()
	if resp := rawSendNoMA(cctx, pap, authAddr); resp != nil {
		t.Fatalf("PAP без MA обслужен (код %v) — обязан отбрасываться", resp.Code)
	}

	// EAP-Message без MA — discard ВСЕГДА (RFC 3579 §3.2 MUST).
	eapPkt := radius.New(radius.CodeAccessRequest, secret)
	rfc2865.UserName_SetString(eapPkt, "anonymous")
	if err := rfc2869.EAPMessage_Set(eapPkt, eap.BuildIdentity(eap.CodeResponse, 0, "anonymous")); err != nil {
		t.Fatalf("EAPMessage_Set: %v", err)
	}
	cctx2, ccancel2 := context.WithTimeout(ctx, time.Second)
	defer ccancel2()
	if resp := rawSendNoMA(cctx2, eapPkt, authAddr); resp != nil {
		t.Fatalf("EAP без MA обслужен (код %v) — обязан отбрасываться всегда", resp.Code)
	}

	// Оба discard-а зафиксированы в аудите radius_ma_missing.
	deadline := time.Now().Add(3 * time.Second)
	for {
		events, err := st.AuditList(ctx, store.AuditFilter{Event: "radius_ma_missing"})
		if err == nil && len(events) >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("radius_ma_missing: rows=%d err=%v, хочу >= 2", len(events), err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Подписанный PAP — Reject (не тот пароль), ответ ВСЕГДА подписан MA.
	signed := radius.New(radius.CodeAccessRequest, secret)
	rfc2865.UserName_SetString(signed, user.Username)
	rfc2865.UserPassword_SetString(signed, "wrongpassword")
	signRequestMA(signed)
	cctx3, ccancel3 := context.WithTimeout(ctx, 5*time.Second)
	defer ccancel3()
	resp, err := exchangeWrap(cctx3, signed, authAddr)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if resp.Code != radius.CodeAccessReject {
		t.Fatalf("код ответа %v, хочу Access-Reject", resp.Code)
	}
	if !hasMessageAuthenticator(resp) || !verifyResponseMA(signed, resp) {
		t.Fatal("ответ не подписан Message-Authenticator (требуется всегда)")
	}

	// Легаси-режим: require=false — PAP без MA получает ответ…
	mustPut(t, ctx, set, "radius.require_message_authenticator", `false`)
	t.Cleanup(func() { mustPut(t, ctx, set, "radius.require_message_authenticator", `true`) })
	cctx4, ccancel4 := context.WithTimeout(ctx, 5*time.Second)
	defer ccancel4()
	if resp := rawSendNoMA(cctx4, pap, authAddr); resp == nil || resp.Code != radius.CodeAccessReject {
		t.Fatalf("require=false: PAP без MA должен обслуживаться, resp=%v", resp)
	}
	// …а EAP без MA — по-прежнему discard.
	cctx5, ccancel5 := context.WithTimeout(ctx, time.Second)
	defer ccancel5()
	if resp := rawSendNoMA(cctx5, eapPkt, authAddr); resp != nil {
		t.Fatalf("require=false: EAP без MA обслужен (%v) — MUST отбрасываться всегда", resp.Code)
	}
}

// TestRadiusAcctInterimSkipped: Interim-Update получает Accounting-Response,
// но НЕ пишется в audit_log (шум retention); Stop — пишется.
func TestRadiusAcctInterimSkipped(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	srv := New(newCore(st, set, box, nil, nil), st, set)
	srvCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	_, acctAddr := startServers(t, srvCtx, srv)
	secret := []byte(set.Get().RadiusSecret)

	acct := func(status rfc2866.AcctStatusType) *radius.Packet {
		pkt := radius.New(radius.CodeAccountingRequest, secret)
		rfc2865.UserName_SetString(pkt, "interimuser")
		rfc2866.AcctSessionID_SetString(pkt, "sess-interim-1")
		rfc2866.AcctStatusType_Set(pkt, status)
		return pkt
	}

	// Interim-Update: ответ есть, аудита нет.
	cctx, ccancel := context.WithTimeout(ctx, 5*time.Second)
	defer ccancel()
	resp, err := exchangeWrap(cctx, acct(rfc2866.AcctStatusType_Value_InterimUpdate), acctAddr)
	if err != nil {
		t.Fatalf("Exchange(interim): %v", err)
	}
	if resp.Code != radius.CodeAccountingResponse {
		t.Fatalf("interim: код %v, хочу Accounting-Response", resp.Code)
	}
	time.Sleep(500 * time.Millisecond)
	if rows, err := st.AuditList(ctx, store.AuditFilter{Username: "interimuser", Event: "radius_acct"}); err != nil || len(rows) != 0 {
		t.Fatalf("Interim-Update не должен писать radius_acct: rows=%d err=%v", len(rows), err)
	}

	// Stop: ответ + аудит.
	cctx2, ccancel2 := context.WithTimeout(ctx, 5*time.Second)
	defer ccancel2()
	if _, err := exchangeWrap(cctx2, acct(rfc2866.AcctStatusType_Value_Stop), acctAddr); err != nil {
		t.Fatalf("Exchange(stop): %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		rows, err := st.AuditList(ctx, store.AuditFilter{Username: "interimuser", Event: "radius_acct"})
		if err == nil && len(rows) > 0 {
			if rows[0].Detail["status"] != "Stop" {
				t.Fatalf("detail radius_acct = %v, хочу status=Stop", rows[0].Detail)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("radius_acct(Stop) не появился в audit_log за 3с")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestRadiusRateLimitBurst: пачка пакетов с одного IP сверх burst+rate
// молча отбрасывается (гейт перед БД/argon2), счётчик дропов растёт.
func TestRadiusRateLimitBurst(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	// 5 pps → burst 10: заведомо меньше пачки, но с запасом для служебных
	// пакетов теста (обмен ниже укладывается в ~12 пакетов).
	mustPut(t, ctx, set, "radius.rate_limit_pps", `5`)
	t.Cleanup(func() { mustPut(t, ctx, set, "radius.rate_limit_pps", `20`) })

	srv := New(newCore(st, set, box, nil, nil), st, set)
	srvCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	_, acctAddr := startServers(t, srvCtx, srv)
	secret := []byte(set.Get().RadiusSecret)

	// Пачка 40 Accounting-запросов подряд (без чтения ответов) — в один
	// момент времени проходят не больше burst+немного пополнения.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()
	udp, err := net.ResolveUDPAddr("udp", acctAddr)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	const total = 40
	for i := 0; i < total; i++ {
		pkt := radius.New(radius.CodeAccountingRequest, secret)
		pkt.Identifier = byte(i)
		rfc2865.UserName_SetString(pkt, "burst-user")
		rfc2866.AcctStatusType_Set(pkt, rfc2866.AcctStatusType_Value_InterimUpdate)
		raw, err := pkt.Encode()
		if err != nil {
			t.Fatalf("Encode #%d: %v", i, err)
		}
		if _, err := pc.WriteTo(raw, udp); err != nil {
			t.Fatalf("WriteTo #%d: %v", i, err)
		}
	}

	// Ответы: только пакеты, влезшие в bucket.
	responses := 0
	if err := pc.SetReadDeadline(time.Now().Add(1500 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 4096)
	for {
		if _, _, err := pc.ReadFrom(buf); err != nil {
			break // таймаут — больше ответов нет
		}
		responses++
	}
	if responses < 5 || responses > 20 {
		t.Fatalf("ответов %d из %d — bucket не работает (жду 5..20)", responses, total)
	}
	if dropped := srv.limiter.droppedCount(); dropped < 15 {
		t.Fatalf("dropped = %d, хочу >= 15 (пачка 40 при burst 10)", dropped)
	}
}

// TestRadiusPushCooldownPendingResume: повторный Access-Request в
// push_cooldown при живом pending-челлендже возобновляет ожидание ЕГО
// вместо мгновенного Reject — подтверждение, пришедшее после первого
// push_timeout, достаётся второму запросу.
func TestRadiusPushCooldownPendingResume(t *testing.T) {
	st, set, box := setup(t)
	ctx := context.Background()
	mustPut(t, ctx, set, "radius.push_wait", `"3s"`)

	push := newProbePush()
	core := newCore(st, set, box, nil, push)
	srv := New(core, st, set)
	srvCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	authAddr, _ := startServers(t, srvCtx, srv)
	secret := []byte(set.Get().RadiusSecret)

	// Подтверждение через 4с — ПОСЛЕ первого удержания (3с): первый запрос
	// ответит push_timeout, челлендж останется живым (pending, TTL 5м);
	// второе удержание (3с, до 6.1с) успевает поймать approved в 4с.
	done := approveAfter(st, push, 4*time.Second, "approved")

	user := mkUser(t, ctx, st, "radresume", func(u *store.User) {
		chat := int64(7)
		u.TelegramChatID = &chat
		u.RadiusPush = true
	})

	cctx, ccancel := context.WithTimeout(ctx, 15*time.Second)
	defer ccancel()
	resp, err := exchangeWrap(cctx, accessRequest(secret, user.Username, testPassword), authAddr)
	if err != nil {
		t.Fatalf("Exchange #1: %v", err)
	}
	if resp.Code != radius.CodeAccessReject {
		t.Fatalf("запрос #1: код %v, хочу Access-Reject (push_timeout до подтверждения)", resp.Code)
	}

	// Повтор немедленно: cooldown активен (последний push < 30с назад), но
	// челлендж жив — ожидание возобновляется и ловит approved (~4с).
	start := time.Now()
	cctx2, ccancel2 := context.WithTimeout(ctx, 15*time.Second)
	defer ccancel2()
	resp, err = exchangeWrap(cctx2, accessRequest(secret, user.Username, testPassword), authAddr)
	if err != nil {
		t.Fatalf("Exchange #2: %v", err)
	}
	if resp.Code != radius.CodeAccessAccept {
		t.Fatalf("запрос #2: код %v, хочу Access-Accept (возобновление живого push-челленджа)", resp.Code)
	}
	if waited := time.Since(start); waited < 500*time.Millisecond {
		t.Fatalf("ответ #2 пришёл через %s — мгновенный Reject вместо возобновления удержания", waited)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("тестовая горутина подтверждения не завершилась")
	}
	events, err := st.AuditList(ctx, store.AuditFilter{Username: user.Username, Event: "radius_auth"})
	if err != nil || len(events) == 0 {
		t.Fatalf("radius_auth: rows=%d err=%v", len(events), err)
	}
	if events[0].Detail["reason"] != "push_ok" {
		t.Fatalf("reason последнего radius_auth = %v, хочу push_ok", events[0].Detail["reason"])
	}
}
