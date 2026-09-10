// Package radiusserver — RADIUS-интерфейс 2FA-сервера: Access-Request (PAP)
// через auth.Core (сплиты «пароль+код», push_wait-удержание, fail-счётчик)
// и accounting-лог. EAP-TTLS/PAP (RFC 3579/5281) для WPA2/WPA3-Enterprise:
// внутренний PAP идёт через тот же Core.RADIUSAuth (eapauth.go), сессии
// держатся по RADIUS State (eapsession.go), серверный сертификат
// self-signed (cert.go). Reply-атрибуты Access-Accept: сначала per-user
// users.radius_reply, иначе глобальные radius.reply_attributes (MikroTik VSA
// и стандартные атрибуты, см. attrs.go). Message-Authenticator (RFC 3579,
// митигация BlastRADIUS, см. messageauth.go): неверный MA — discard;
// EAP-Message без MA — discard (§3.2 MUST); PAP без MA — discard при
// radius.require_message_authenticator (дефолт); ВСЕ ответы auth-порта
// подписываются MA всегда. Неизвестные коды пакетов игнорируются без
// ответа. Первый гейт — per-NAS token bucket (ratelimit.go, анти-DoS).
package radiusserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"sync"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
	"layeh.com/radius/rfc2869"

	"github.com/aligorov/twofa/internal/auth"
	"github.com/aligorov/twofa/internal/firewall"
	"github.com/aligorov/twofa/internal/secrets"
	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
)

// shutdownGrace — сколько ждать завершения in-flight хендлеров (включая
// удержания push_wait) при остановке.
const shutdownGrace = 30 * time.Second

// authTimeoutMargin — запас сверх radius.push_wait на контексте обработки:
// удержание Core опрашивает состояние с шагом 1 с, ответ должен успеть
// уйти до отмены контекста.
const authTimeoutMargin = 5 * time.Second

// ErrNoSecret — radius.secret не задан: серверы не стартуют.
var ErrNoSecret = errors.New("radiusserver: radius.secret не задан")

// Server — RADIUS auth (:1812) и acct (:1813) серверы поверх одного ядра
// аутентификации.
type Server struct {
	core *auth.Core
	st   *store.Store
	m    *settings.M
	fw   *firewall.Guard // nil — фильтрации по IP нет

	// limiter — per-NAS token bucket: первый гейт auth/acct-пакетов до
	// любой тяжёлой работы (анти-DoS перед argon2, см. ratelimit.go).
	limiter *rateLimiter

	// EAP-TTLS (802.1X): сессии по RADIUS State и серверный сертификат
	// (self-signed, см. cert.go; nil при его отсутствии — EAP отключён).
	eapSessions *eapSessionStore
	certMu      sync.RWMutex
	eapTLSCert  *tls.Certificate
	eapCertPEM  []byte
}

// New собирает RADIUS-сервер. Секрет и адреса читаются из настроек при
// каждом запуске слушателей (ListenAndServe/ServeAuth/ServeAcct);
// сертификат EAP-TTLS — EnsureEAPCert (main) или лениво при первом
// EAP-запросе.
func New(core *auth.Core, st *store.Store, m *settings.M) *Server {
	return &Server{
		core:        core,
		st:          st,
		m:           m,
		limiter:     newRateLimiter(),
		eapSessions: newEAPSessionStore(),
	}
}

// SetFirewall подключает fail2ban-guard: Access-Request с чёрного/
// забаненного IP получает Access-Reject без обращения к паролям;
// accounting с такого IP отбрасывается. nil — фильтрации нет.
func (s *Server) SetFirewall(g *firewall.Guard) { s.fw = g }

// box создаёт экземпляр шифровальщика secrets.Box из настроек master_key.
func (s *Server) box() (*secrets.Box, error) {
	if s.m == nil || s.m.Get() == nil || s.m.Get().MasterKeyB64 == "" {
		return nil, errors.New("master_key не настроен")
	}
	return secrets.NewBox(s.m.Get().MasterKeyB64)
}

// slogBridge — маршрутизация внутренних ошибок layeh/radius в slog
// (PacketServer.ErrorLog принимает *log.Logger).
func slogBridge() *log.Logger {
	return slog.NewLogLogger(slog.Default().Handler(), slog.LevelWarn)
}

// settingsSecretSource — секрет из ТЕКУЩЕГО снимка настроек на каждый
// пакет: смена radius.secret применяется к новым пакетам без рестарта
// слушателей (горячая ротация, F1). Пустой секрет — ошибка: библиотека
// отбрасывает пакет (живой аналог «не стартовать без секрета»).
type settingsSecretSource struct{ m *settings.M }

// RADIUSSecret реализует radius.SecretSource.
func (src settingsSecretSource) RADIUSSecret(_ context.Context, _ net.Addr) ([]byte, error) {
	secret := src.m.Get().RadiusSecret
	if secret == "" {
		return nil, ErrNoSecret
	}
	return []byte(secret), nil
}

// buildAuth/buildAcct собирают PacketServer-ы; стартовый секрет проверяется
// сразу (пустой — ErrNoSecret), дальше каждый пакет подписывается текущим
// значением из настроек.
func (s *Server) buildAuth() (*radius.PacketServer, error) {
	if s.m.Get().RadiusSecret == "" {
		return nil, ErrNoSecret
	}
	return &radius.PacketServer{
		Handler:      radius.HandlerFunc(s.safeHandleAuth),
		SecretSource: settingsSecretSource{m: s.m},
		ErrorLog:     slogBridge(),
	}, nil
}

func (s *Server) buildAcct() (*radius.PacketServer, error) {
	if s.m.Get().RadiusSecret == "" {
		return nil, ErrNoSecret
	}
	return &radius.PacketServer{
		Handler:      radius.HandlerFunc(s.safeHandleAcct),
		SecretSource: settingsSecretSource{m: s.m},
		ErrorLog:     slogBridge(),
	}, nil
}

// safeHandleAuth/safeHandleAcct — recover-обёртки: layeh/radius исполняет
// хендлер в горутине на пакет БЕЗ recover, поэтому любая паника роняла бы
// весь процесс (HTTP-стек net/http паники изолирует сам). Паника логируется,
// клиенту — Access-Reject (auth) / тишина (acct).
func (s *Server) safeHandleAuth(w radius.ResponseWriter, r *radius.Request) {
	defer func() {
		if rec := recover(); rec != nil {
			slog.Error("radius: panic в handleAuth (recover)", "panic", rec, "remote", r.RemoteAddr)
			_ = w.Write(r.Response(radius.CodeAccessReject))
		}
	}()
	s.handleAuth(w, r)
}

func (s *Server) safeHandleAcct(w radius.ResponseWriter, r *radius.Request) {
	defer func() {
		if rec := recover(); rec != nil {
			slog.Error("radius: panic в handleAcct (recover)", "panic", rec, "remote", r.RemoteAddr)
		}
	}()
	s.handleAcct(w, r)
}

// ListenAndServe поднимает оба сервера на listen.radius_auth /
// listen.radius_acct и блокирует до отмены ctx (затем Shutdown обоих;
// ошибки слушателей логируются, не прерывая второй сервер). При пустом
// radius.secret серверы не запускаются (одна запись в лог), метод ждёт
// отмены ctx и возвращает nil.
func (s *Server) ListenAndServe(ctx context.Context) error {
	authSrv, err := s.buildAuth()
	if err != nil {
		slog.Error("radius: серверы не запущены — radius.secret не задан")
		<-ctx.Done()
		return nil
	}
	acctSrv, err := s.buildAcct()
	if err != nil { // тот же секрет — практически недостижимо, но не паникуем
		slog.Error("radius: acct-сервер не запущен", "error", err)
	}

	run := func(name, addr string, srv *radius.PacketServer) {
		if srv == nil {
			return
		}
		srv.Addr = addr
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, radius.ErrServerShutdown) {
			slog.Error("radius: слушатель остановлен с ошибкой", "server", name, "error", err)
		}
	}
	go run("auth", s.m.Get().Listen.RadiusAuth, authSrv)
	go run("acct", s.m.Get().Listen.RadiusAcct, acctSrv)

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
	defer cancel()
	for _, srv := range []*radius.PacketServer{authSrv, acctSrv} {
		if srv == nil {
			continue
		}
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Warn("radius: не удалось корректно остановить сервер", "error", err)
		}
	}
	return nil
}

// ServeAuth обслуживает auth-запросы на готовом соединении (тесты слушают
// на 127.0.0.1:0). Блокирует до отмены ctx; сервер останавливается
// Shutdown-ом при отмене.
func (s *Server) ServeAuth(ctx context.Context, conn net.PacketConn) error {
	srv, err := s.buildAuth()
	if err != nil {
		conn.Close()
		return err
	}
	go shutdownOnDone(ctx, srv, conn)
	err = srv.Serve(conn)
	if errors.Is(err, radius.ErrServerShutdown) {
		return nil
	}
	return err
}

// ServeAcct — аналог ServeAuth для accounting-сервера.
func (s *Server) ServeAcct(ctx context.Context, conn net.PacketConn) error {
	srv, err := s.buildAcct()
	if err != nil {
		conn.Close()
		return err
	}
	go shutdownOnDone(ctx, srv, conn)
	err = srv.Serve(conn)
	if errors.Is(err, radius.ErrServerShutdown) {
		return nil
	}
	return err
}

// shutdownOnDone закрывает слушатель и ждёт хендлеры при отмене ctx.
func shutdownOnDone(ctx context.Context, srv *radius.PacketServer, conn net.PacketConn) {
	<-ctx.Done()
	conn.Close()
	shctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
	defer cancel()
	if err := srv.Shutdown(shctx); err != nil {
		slog.Warn("radius: shutdown завершился с ошибкой", "error", err)
	}
}

// handleAuth — Access-Request: EAP-Message (RFC 3579) уходит в EAP-TTLS/
// PAP-поток (handleEAPAuth), иначе — PAP: UserName + User-Password
// (библиотека расшифровывает PAP сама) → Core.RADIUSAuth с таймаутом
// push_wait+5s → Accept с reply-атрибутами (per-user radius_reply, иначе
// глобальные) или Reject с Reply-Message "rejected" без внутренних деталей.
func (s *Server) handleAuth(w radius.ResponseWriter, r *radius.Request) {
	if r.Code != radius.CodeAccessRequest {
		return // неизвестные коды игнорируются без ответа
	}
	// DoS-гейт ПЕРВЫМ — до MA-проверки, файрвола, БД и argon2: флуд с
	// одного источника молчаливо дропается (rate.limit_pps, см. ratelimit.go).
	if !s.limiter.allow(hostOnly(r.RemoteAddr), s.m.Get().Radius.RateLimitPPS, time.Now()) {
		return
	}
	if !s.checkRequestMessageAuthenticator(r) {
		return
	}

	// Файрвол: чёрный список/автобан фильтруют и RADIUS-запросы.
	if s.fw != nil {
		switch s.fw.Check(r.Context(), hostOnly(r.RemoteAddr)) {
		case firewall.Denied, firewall.Banned:
			slog.Warn("radius: Access-Request отброшен файрволом",
				"remote", hostOnly(r.RemoteAddr))
			resp := r.Response(radius.CodeAccessReject)
			rfc2865.ReplyMessage_SetString(resp, "rejected")
			signResponseMessageAuthenticator(r.Packet, resp)
			_ = w.Write(resp)
			return
		}
	}

	// EAP-обмен (WPA2/WPA3-Enterprise): все EAP-Message атрибуты запроса
	// библиотека уже склеила в один EAP-пакет.
	if eapRaw, err := rfc2869.EAPMessage_Lookup(r.Packet); err == nil {
		s.handleEAPAuth(w, r, eapRaw)
		return
	}

	username, _ := rfc2865.UserName_LookupString(r.Packet)
	password, _ := rfc2865.UserPassword_LookupString(r.Packet)

	portType, _ := rfc2865.NASPortType_Lookup(r.Packet)
	clientMAC, _ := rfc2865.CallingStationID_LookupString(r.Packet)
	calledStation, _ := rfc2865.CalledStationID_LookupString(r.Packet)
	nasID, _ := rfc2865.NASIdentifier_LookupString(r.Packet)
	nasIP := hostOnly(r.RemoteAddr)
	if nip, err := rfc2865.NASIPAddress_Lookup(r.Packet); err == nil && len(nip) > 0 {
		nasIP = nip.String()
	}
	nasDesc := ResolveNASDescription(nasIP, nasID, calledStation, s.m.Get().Radius.NASInventory)
	deviceDesc := FormatDeviceDescription(clientMAC)

	svc := "Корпоративная сеть (RADIUS)"
	if portType == 19 {
		svc = "Подключение к Wi-Fi"
		if nasDesc != "" {
			svc = "Wi-Fi: " + nasDesc
		}
	} else if portType == 5 {
		svc = "VPN доступ (RADIUS)"
	} else if nasDesc != "" {
		svc = nasDesc
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.m.Get().Radius.PushWait+authTimeoutMargin)
	defer cancel()
	ctx = context.WithValue(ctx, auth.CtxKeyService, svc)
	ctx = context.WithValue(ctx, auth.CtxKeyDevice, deviceDesc)

	accept, reason := s.core.RADIUSAuth(ctx, username, password, hostOnly(r.RemoteAddr))
	var resp *radius.Packet
	if accept {
		resp = r.Response(radius.CodeAccessAccept)
		attrs := s.m.Get().Radius.ReplyAttributes
		if user, err := s.st.UserByUsername(ctx, username); err == nil {
			eff, errEff := s.st.UserEffectiveRadiusReply(ctx, user)
			if errEff == nil && len(eff) > 0 {
				attrs = eff
			}
		}
		applyReplyAttrs(resp, attrs)

		clientMAC, _ := rfc2865.CallingStationID_LookupString(r.Packet)
		calledStation, _ := rfc2865.CalledStationID_LookupString(r.Packet)
		nasID, _ := rfc2865.NASIdentifier_LookupString(r.Packet)
		nasIP := hostOnly(r.RemoteAddr)
		if nip, err := rfc2865.NASIPAddress_Lookup(r.Packet); err == nil && len(nip) > 0 {
			nasIP = nip.String()
		}

		vlan := ExtractVLAN(attrs)
		method := "Wi-Fi (PAP)"
		if vlan != "" {
			method = fmt.Sprintf("Wi-Fi (PAP), VLAN %s", vlan)
		}
		nasDesc := ResolveNASDescription(nasIP, nasID, calledStation, s.m.Get().Radius.NASInventory)
		deviceDesc := FormatDeviceDescription(clientMAC)

		slog.Info("radius: Access-Accept", "user", username, "reason", reason,
			"remote", hostOnly(r.RemoteAddr), "vlan", vlan, "nas", nasDesc, "device", deviceDesc)
		s.core.NotifyLoginSuccess(context.WithoutCancel(r.Context()), username, method, nasDesc, deviceDesc)
	} else {
		resp = r.Response(radius.CodeAccessReject)
		if err := rfc2865.ReplyMessage_SetString(resp, "rejected"); err != nil {
			slog.Warn("radius: Reply-Message не установлен", "error", err)
		}
		slog.Info("radius: Access-Reject", "user", username, "reason", reason,
			"remote", hostOnly(r.RemoteAddr))
	}
	signResponseMessageAuthenticator(r.Packet, resp)
	if err := w.Write(resp); err != nil {
		slog.Warn("radius: ответ не отправлен", "user", username, "error", err)
	}
}

// checkRequestMessageAuthenticator — политика Message-Authenticator для
// Access-Request (RFC 3579 §3.2, митигация BlastRADIUS/downgrade):
//  1. неверный MA — discard всегда (подделка/несовпадение секрета);
//  2. запрос с EAP-Message БЕЗ MA — discard всегда (RFC 3579 §3.2 MUST:
//     внешний EAP-обмен без MA тамперится MITM-ом);
//  3. прочие Access-Request (PAP) без MA — discard при включённом
//     radius.require_message_authenticator (дефолт true).
//
// Каждый discard пишется в аудит radius_ma_missing (fail) — событие НЕ
// входит в fail-фильтр Guard, чтобы отброшенный флуд не крутил автобан.
func (s *Server) checkRequestMessageAuthenticator(r *radius.Request) bool {
	srcIP := hostOnly(r.RemoteAddr)
	if hasMessageAuthenticator(r.Packet) {
		if verifyMessageAuthenticator(r.Packet) {
			return true
		}
		slog.Warn("radius: неверный Message-Authenticator (проверьте совпадение RADIUS Secret на NAS и в настройках сервера) — пакет отброшен",
			"remote", srcIP)
		s.auditMAMissing(r, "invalid")
		return false
	}
	_, errEAP := rfc2869.EAPMessage_Lookup(r.Packet)
	reason := ""
	switch {
	case errEAP == nil: // EAP-Message присутствует
		reason = "missing_eap"
	case s.m.Get().Radius.RequireMessageAuthenticator:
		reason = "missing"
	default:
		return true // MA нет, но политика разрешает (легаси-NAS)
	}
	slog.Warn("radius: Access-Request без Message-Authenticator — пакет отброшен (RFC 3579 §3.2)",
		"remote", srcIP, "reason", reason)
	s.auditMAMissing(r, reason)
	return false
}

// auditMAMissing фиксирует discard по Message-Authenticator в audit_log
// (контекст без отмены — аудит переживает обработку пакета).
func (s *Server) auditMAMissing(r *radius.Request, reason string) {
	username, _ := rfc2865.UserName_LookupString(r.Packet)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 3*time.Second)
	defer cancel()
	if err := s.st.Audit(ctx, username, "radius_ma_missing",
		map[string]any{"reason": reason}, hostOnly(r.RemoteAddr), "fail"); err != nil {
		slog.Warn("radius: radius_ma_missing не записан в аудит", "error", err)
	}
}

// handleAcct — Accounting-Request: файрвол-гейт, событие в лог и аудит
// (только Start/Stop — Interim-Update не шумит в audit_log), ВСЕГДА
// Accounting-Response (иначе NAS ретрансмитит).
func (s *Server) handleAcct(w radius.ResponseWriter, r *radius.Request) {
	if r.Code != radius.CodeAccountingRequest {
		return
	}
	// DoS-гейт тем же bucket-ом, что и auth-порт (acct тоже бьётся флудом).
	if !s.limiter.allow(hostOnly(r.RemoteAddr), s.m.Get().Radius.RateLimitPPS, time.Now()) {
		return
	}
	// Файрвол (документация SetFirewall): accounting с чёрного/
	// забаненного IP отбрасывается молча (SetFirewall: «accounting с
	// такого IP отбрасывается»).
	if s.fw != nil {
		switch s.fw.Check(r.Context(), hostOnly(r.RemoteAddr)) {
		case firewall.Denied, firewall.Banned:
			slog.Warn("radius: Accounting-Request отброшен файрволом",
				"remote", hostOnly(r.RemoteAddr))
			return
		}
	}
	username, _ := rfc2865.UserName_LookupString(r.Packet)
	session, _ := rfc2866.AcctSessionID_LookupString(r.Packet)
	status := rfc2866.AcctStatusType_Get(r.Packet)
	srcIP := hostOnly(r.RemoteAddr)

	slog.Info("radius: accounting", "user", username, "session_id", session,
		"status", status.String(), "src_ip", srcIP)

	// В audit_log — только начало/конец сессии: Interim-Update ходит
	// каждые пару минут на каждую сессию и без фильтра забивает аудит
	// (retention-шум, АГЕНТ 5). Ошибки записи не ломают ответ NAS.
	switch status {
	case rfc2866.AcctStatusType_Value_Start, rfc2866.AcctStatusType_Value_Stop:
		auditCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
		defer cancel()
		if err := s.st.Audit(auditCtx, username, "radius_acct",
			map[string]any{"session_id": session, "status": status.String()}, srcIP, "ok"); err != nil {
			slog.Warn("radius: accounting не записан в аудит", "user", username, "error", err)
		}
	}

	if err := w.Write(r.Response(radius.CodeAccountingResponse)); err != nil {
		slog.Warn("radius: accounting-ответ не отправлен", "user", username, "error", err)
	}
}

// hostOnly выдает IP из net.Addr ("1.2.3.4:5678" → "1.2.3.4").
func hostOnly(addr net.Addr) string {
	if host, _, err := net.SplitHostPort(addr.String()); err == nil {
		return host
	}
	return addr.String()
}
