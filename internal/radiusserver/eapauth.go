// Поток EAP-TTLS/PAP в Access-Request (RFC 3579 + RFC 5281): Identity →
// сессия по RADIUS State → пошаговый TLS-handshake через мост (eapsession)
// → phase-2 AVP (User-Name + User-Password) → внутренний PAP через общий
// конвейер Core.RADIUSAuth (сплиты «пароль+код», push_wait) → Accept с
// EAP-Success и MS-MPPE-ключами WPA2 либо Reject с EAP-Failure.
package radiusserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
	msm "layeh.com/radius/vendors/microsoft"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"

	"github.com/aligorov/twofa/internal/auth"
	"github.com/aligorov/twofa/internal/radiusserver/eap"
)

// handleEAPAuth — Access-Request с EAP-Message. PAP-путь (без EAP-Message)
// остаётся в handleAuth нетронутым. Все ответы несут корректный
// Message-Authenticator (RFC 3579 §3.2 — обязателен для ответов на запросы
// с EAP-Message), см. signEAPResponseMessageAuthenticator.
func (s *Server) handleEAPAuth(w radius.ResponseWriter, r *radius.Request, eapRaw []byte) {
	srcIP := hostOnly(r.RemoteAddr)

	pkt, err := eap.Parse(eapRaw)
	if err != nil {
		slog.Warn("radius: битый EAP-пакет — Reject", "remote", srcIP, "error", err)
		s.rejectEAP(w, r, 0)
		return
	}
	slog.Debug("radius: handleEAPAuth enter", "pkt_id", pkt.ID, "pkt_type", pkt.Type(), "raw_len", len(eapRaw))
	if pkt.Code != eap.CodeResponse {
		// Request/Success/Failure от клиента — протокольная ошибка.
		slog.Warn("radius: EAP-пакет не Response — Reject", "remote", srcIP, "code", int(pkt.Code))
		s.rejectEAP(w, r, pkt.ID)
		return
	}

	state := hexState(rfc2865.State_Get(r.Packet))
	sess := s.eapSessions.get(state)
	if sess != nil {
		if mtu, err := rfc2865.FramedMTU_Lookup(r.Packet); err == nil && mtu > 0 {
			maxFrag := int(mtu) - 100
			if maxFrag > eap.MaxFragment {
				maxFrag = eap.MaxFragment
			}
			if maxFrag < 256 {
				maxFrag = 256
			}
			sess.fragSize = maxFrag
		}
	}

	// Ретрансмит NAS (тот же State + тот же EAP-пакет): повторяем последний
	// ответ идентично — дубли запросов от AP нормальны и идемпотентны.
	if sess != nil && bytes.Equal(sess.lastReqEAP, eapRaw) {
		slog.Debug("radius: NAS EAP retransmit", "remote", srcIP, "state", state)
		s.sendEAP(w, r, sess, sess.lastRespEAP)
		return
	}

	switch pkt.Type() {
	case eap.TypeIdentity:
		// Внешний identity может быть anonymous@… — реальное имя придёт
		// внутри туннеля (phase-2 AVP User-Name или MS-CHAPv2).
		cert := s.eapCertificate()
		if cert == nil {
			if cerr := s.EnsureEAPCert(r.Context()); cerr != nil {
				slog.Error("radius: EAP недоступен — сертификат не создан",
					"error", cerr, "remote", srcIP)
				s.rejectEAP(w, r, pkt.ID)
				return
			}
			cert = s.eapCertificate()
		}
		if sess != nil {
			s.eapSessions.delete(sess) // повторный Identity с тем же State
		}
		// Дефолт для нативного входа iOS, Windows, macOS, Android без профилей: PEAPv0 (Type 25).
		// Клиенты, явно сконфигурированные под EAP-TTLS, ответят Nak, и мы переключимся.
		sess = s.eapSessions.create(cert, eapProtoPEAP)
		sess.reqID = pkt.ID + 1
		sess.outerIdentity = string(pkt.IdentityData())
		sess.lastReqEAP = append([]byte(nil), eapRaw...)
		if mtu, err := rfc2865.FramedMTU_Lookup(r.Packet); err == nil && mtu > 0 {
			maxFrag := int(mtu) - 100
			if maxFrag > eap.MaxFragment {
				maxFrag = eap.MaxFragment
			}
			if maxFrag < 256 {
				maxFrag = 256
			}
			sess.fragSize = maxFrag
		}
		slog.Info("radius: EAP-PEAP начат", "identity", sess.outerIdentity, "remote", srcIP)
		// Старт PEAP: пустой EAP-Request/PEAP с флагом S.
		// Идентификатор инкрементируется (sess.nextReqID()), чтобы следующий Request
		// (TLS ServerHello) имел отличный ID (RFC 3748 §4.1).
		s.sendEAP(w, r, sess,
			eap.BuildPEAP(eap.CodeRequest, sess.nextReqID(), eap.PEAPFlagStart, -1, nil))

	case eap.TypePEAP:
		if sess == nil {
			slog.Warn("radius: PEAP-данные без сессии — Reject", "remote", srcIP)
			s.rejectEAP(w, r, pkt.ID)
			return
		}
		s.handlePEAP(w, r, sess, pkt, eapRaw)

	case eap.TypeTTLS:
		if sess == nil {
			// Чужой/просроченный/пустой State — новой сессии по данным без
			// Identity не создаём (защита от подмены).
			slog.Warn("radius: TTLS-данные без сессии — Reject", "remote", srcIP)
			s.rejectEAP(w, r, pkt.ID)
			return
		}
		s.handleTTLS(w, r, sess, pkt, eapRaw)

	case eap.TypeNak:
		// Если клиент отверг PEAP, проверяем, не предлагает ли он TTLS:
		if sess != nil && sess.proto == eapProtoPEAP {
			hasTTLS := false
			for _, p := range pkt.Data[1:] {
				if eap.Type(p) == eap.TypeTTLS {
					hasTTLS = true
					break
				}
			}
			if hasTTLS {
				slog.Info("radius: клиент запросил EAP-TTLS через Nak — переключаемся", "remote", srcIP)
				sess.proto = eapProtoTTLS
				sess.reqID = pkt.ID + 1
				sess.lastReqEAP = append([]byte(nil), eapRaw...)
				s.sendEAP(w, r, sess,
					eap.BuildTTLS(eap.CodeRequest, sess.nextReqID(), eap.TTLSFlagStart, -1, nil))
				return
			}
		}
		slog.Info("radius: клиент отверг предложенный EAP-метод (Nak) — Reject", "remote", srcIP)
		s.rejectEAP(w, r, pkt.ID)

	default:
		slog.Warn("radius: неподдерживаемый EAP-тип — Reject",
			"type", int(pkt.Type()), "remote", srcIP)
		s.rejectEAP(w, r, pkt.ID)
	}
}

// handleTTLS — шаг EAP-TTLS в существующей сессии: сборка входящих
// фрагментов, продолжение очереди исходящих, движение TLS-handshake или
// расшифровка phase-2 AVP и внутренний PAP.
func (s *Server) handleTTLS(w radius.ResponseWriter, r *radius.Request,
	sess *eapSession, pkt *eap.Packet, eapRaw []byte) {
	srcIP := hostOnly(r.RemoteAddr)
	sess.lastReqEAP = append([]byte(nil), eapRaw...)
	sess.id = pkt.ID

	t, err := eap.ParseTTLS(pkt.Data)
	if err != nil {
		s.failEAP(w, r, sess, "битые TTLS-данные: "+err.Error())
		return
	}
	payload, complete, err := sess.frag.Add(t)
	if err != nil {
		s.failEAP(w, r, sess, "сборка фрагментов: "+err.Error())
		return
	}
	if !complete && sess.frag.InFlight() {
		// Входящее сообщение ещё не собрано (ждём фрагменты); застрявший
		// исходящий поток (воркер мог дописать между шагами — гонка
		// сигналов wantIn) прокачиваем.
		s.pumpTTLS(w, r, sess, nil)
		return
	}
	// Здесь payload либо полный, либо пустой ACK клиента (InFlight=false):
	// в inner-фазе пустой ACK всё равно обязан попробовать расшифровать
	// накопленные phase-2 данные — воркер мог расшифровать AVP ещё до
	// перехода фазы (handshake завершился на предыдущем шаге).

	switch sess.phase {
	case eapPhaseHandshake:
		if len(payload) == 0 {
			// Пустой ACK клиента (подтверждение нашего фрагмента/запроса):
			// продолжаем очередь исходящих, handshake не двигаем — новых
			// данных нет, ждать нечего.
			s.pumpTTLS(w, r, sess, nil)
			return
		}
		sess.conn.deliver(payload)
		out, finished, err := sess.waitHandshakeStep()
		if err != nil {
			s.failEAP(w, r, sess, "TLS handshake: "+err.Error())
			return
		}
		if finished {
			sess.phase = eapPhaseInner
		}
		s.pumpTTLS(w, r, sess, out)

	case eapPhaseInner:
		var app []byte
		if len(payload) > 0 {
			sess.conn.deliver(payload)
			app, err = sess.waitAppData()
			if err != nil {
				s.failEAP(w, r, sess, "чтение phase-2: "+err.Error())
				return
			}
		} else {
			// Пустой ACK: расшифрованные AVP могли накопиться в канале
			// раньше (handshake завершился на прошлом шаге — гонка фаз).
			app = sess.takeAppData()
			if len(app) == 0 && len(sess.pendingInner) == 0 {
				s.pumpTTLS(w, r, sess, nil)
				return
			}
		}
		if extra := sess.takeAppData(); len(extra) > 0 {
			app = append(app, extra...)
		}
		app = append(sess.pendingInner, app...)
		sess.pendingInner = nil

		inner, perr := eap.ParseAVPs(app)
		switch {
		case perr != nil:
			s.failEAP(w, r, sess, "AVP phase-2: "+perr.Error())
			return
		case !inner.Complete():
			// AVP пришли частично — ждём продолжения; пустой ACK-запрос —
			// приглашение клиенту слать данные (RFC 5281 §9.1).
			sess.pendingInner = app
			s.pumpTTLS(w, r, sess, nil)
			return
		}
		s.finishInnerPAP(w, r, sess, pkt.ID, inner, srcIP)
	}
}

// pumpTTLS кладёт out (и застрявший в мосту исходящий поток — воркер мог
// дописать записи между шагами, гонка сигналов wantIn) в очередь фрагментов
// и отправляет следующий фрагмент либо пустой ACK-запрос. Гарантирует
// продвижение обмена: данные никогда не застревают в мосту.
func (s *Server) pumpTTLS(w radius.ResponseWriter, r *radius.Request, sess *eapSession, out []byte) {
	if stuck := sess.conn.takeOutput(); len(stuck) > 0 {
		out = append(stuck, out...)
	}
	sess.pushOutQueue(out)
	s.sendEAP(w, r, sess, sess.popOrAck())
}

// finishInnerPAP — внутренний PAP через общий конвейер RADIUSAuth (сплиты
// «пароль+код», TOTP, push_wait-удержание) + отдельный аудит-ивент
// radius_eap; успех — Accept с EAP-Success, MS-MPPE-ключами WPA2 (RFC 5281
// §10) и обычными reply-атрибутами; неудача — Reject + EAP-Failure.
func (s *Server) finishInnerPAP(w radius.ResponseWriter, r *radius.Request,
	sess *eapSession, eapID byte, inner *eap.InnerPAP, srcIP string) {
	ctx, cancel := context.WithTimeout(r.Context(), s.m.Get().Radius.PushWait+authTimeoutMargin)
	defer cancel()

	accept, reason := s.core.RADIUSAuth(ctx, inner.UserName, inner.UserPassword, srcIP)

	// Аудит EAP-обмена (в дополнение к radius_auth из ядра): контекст без
	// отмены — событие переживает отработанный push_wait.
	auditCtx, acancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer acancel()
	result := "fail"
	if accept {
		result = "ok"
	}
	if err := s.st.Audit(auditCtx, inner.UserName, "radius_eap",
		map[string]any{"reason": reason}, srcIP, result); err != nil {
		slog.Warn("radius: radius_eap не записан в аудит",
			"user", inner.UserName, "error", err)
	}

	if !accept {
		slog.Info("radius: EAP-TTLS Reject", "user", inner.UserName,
			"reason", reason, "remote", srcIP)
		s.failEAP(w, r, sess, "внутренний PAP: "+reason)
		return
	}

	resp := r.Response(radius.CodeAccessAccept)
	if err := rfc2869.EAPMessage_Set(resp, eap.BuildResult(eap.CodeSuccess, eapID)); err != nil {
		slog.Warn("radius: EAP-Success не установлен", "error", err)
	}
	// MS-MPPE-ключи WPA2/802.1X (RFC 5281 §10 + RFC 2548): Recv = первые
	// 32 байта keying material, Send = вторые 32 (направление относительно
	// NAS: Recv расшифровывает трафик ОТ клиента). Шифрование
	// salt+Tunnel-Password делает vendors/microsoft.
	if len(sess.keyBlock) == eapKeyBlockLen {
		if err := msm.MSMPPERecvKey_Add(resp, sess.keyBlock[:32]); err != nil {
			slog.Warn("radius: MS-MPPE-Recv-Key не установлен", "error", err)
		}
		if err := msm.MSMPPESendKey_Add(resp, sess.keyBlock[32:]); err != nil {
			slog.Warn("radius: MS-MPPE-Send-Key не установлен", "error", err)
		}
	} else {
		slog.Warn("radius: MS-MPPE-ключи не выданы — keying material отсутствует",
			"user", inner.UserName)
	}
	// Обычные reply-атрибуты — как в PAP-пути.
	attrs := s.m.Get().Radius.ReplyAttributes
	if user, err := s.st.UserByUsername(ctx, inner.UserName); err == nil && len(user.RadiusReply) > 0 {
		attrs = user.RadiusReply
	}
	applyReplyAttrs(resp, attrs)

	signEAPResponseMessageAuthenticator(r.Packet, resp)
	if err := w.Write(resp); err != nil {
		slog.Warn("radius: ответ не отправлен", "user", inner.UserName, "error", err)
	}
	s.eapSessions.delete(sess)
	slog.Info("radius: EAP-TTLS Accept", "user", inner.UserName, "remote", srcIP)
}

// handlePEAP — шаг PEAPv0 в существующей сессии: сборка входящих
// фрагментов, продвижение TLS handshake, либо приём и обработка
// внутренних EAP-сообщений (MS-CHAPv2 / Result TLV).
func (s *Server) handlePEAP(w radius.ResponseWriter, r *radius.Request,
	sess *eapSession, pkt *eap.Packet, eapRaw []byte) {
	srcIP := hostOnly(r.RemoteAddr)
	sess.lastReqEAP = append([]byte(nil), eapRaw...)
	sess.id = pkt.ID

	p, err := eap.ParsePEAP(pkt.Data)
	if err != nil {
		s.failEAP(w, r, sess, "битые PEAP-данные: "+err.Error())
		return
	}
	payload, complete, err := sess.frag.AddPEAP(p)
	if err != nil {
		s.failEAP(w, r, sess, "сборка фрагментов PEAP: "+err.Error())
		return
	}
	if !complete && sess.frag.InFlight() {
		s.pumpPEAP(w, r, sess, nil)
		return
	}

	switch sess.phase {
	case eapPhaseHandshake:
		if len(payload) == 0 {
			// Пустой ACK клиента
			s.pumpPEAP(w, r, sess, nil)
			return
		}
		sess.conn.deliver(payload)
		out, finished, err := sess.waitHandshakeStep()
		if err != nil {
			s.failEAP(w, r, sess, "PEAP TLS handshake: "+err.Error())
			return
		}
		if finished {
			sess.phase = eapPhaseHandshakeDone
			slog.Info("radius: PEAP TLS handshake завершён сервером, отправка Server Finished", "identity", sess.outerIdentity, "remote", srcIP)
		}
		s.pumpPEAP(w, r, sess, out)

	case eapPhaseHandshakeDone:
		if len(payload) > 0 {
			sess.conn.deliver(payload)
		}
		sess.phase = eapPhaseInner
		slog.Info("radius: PEAP TLS handshake подтверждён клиентом, запуск inner MS-CHAPv2", "identity", sess.outerIdentity, "remote", srcIP)

		// TLS-handshake завершён и подтверждён клиентом! В PEAPv0 сервер первым инициирует
		// внутреннюю аутентификацию, отправляя EAP-Request/MS-CHAPv2 Challenge.
		if _, err := rand.Read(sess.authChallenge[:]); err != nil {
			binary.BigEndian.PutUint64(sess.authChallenge[:8], uint64(time.Now().UnixNano()))
		}
		sess.innerReqID = 1
		sess.innerMSCHAPID = 1
		sess.innerState = peapStateChallenge

		chal := eap.BuildMSCHAPv2Challenge(sess.innerReqID, sess.innerMSCHAPID, sess.authChallenge, "ligament")
		// В PEAPv0 внутренние пакеты MS-CHAPv2 передаются без 4-байтового EAP-заголовка (draft-kamath-pppext-peapv0-00 §2.1)
		chalPayload := chal[4:]
		if err := sess.writeInner(chalPayload); err != nil {
			s.failEAP(w, r, sess, "отправка inner MS-CHAPv2 Challenge: "+err.Error())
			return
		}
		slog.Info("radius: inner MS-CHAPv2 Challenge отправлен", "identity", sess.outerIdentity, "remote", srcIP)
		s.pumpPEAP(w, r, sess, nil)

	case eapPhaseInner:
		var app []byte
		if len(payload) > 0 {
			sess.conn.deliver(payload)
			app, err = sess.waitAppData()
			if err != nil {
				s.failEAP(w, r, sess, "чтение PEAP phase-2: "+err.Error())
				return
			}
		} else {
			app = sess.takeAppData()
			if len(app) == 0 && len(sess.pendingInner) == 0 {
				s.pumpPEAP(w, r, sess, nil)
				return
			}
		}
		if extra := sess.takeAppData(); len(extra) > 0 {
			app = append(app, extra...)
		}
		app = append(sess.pendingInner, app...)
		sess.pendingInner = nil

		if len(app) == 0 {
			slog.Info("radius: inner PEAP данные пусты, pumping", "innerState", sess.innerState, "user", sess.outerIdentity)
			s.pumpPEAP(w, r, sess, nil)
			return
		}
		slog.Info("radius: получен inner PEAP пакет", "len", len(app), "app0", app[0], "innerState", sess.innerState, "user", sess.outerIdentity)

		var innerPkt *eap.Packet
		// В PEAPv0 внутренние пакеты MS-CHAPv2 (26) и Identity (1) передаются без
		// 4-байтового EAP-заголовка Code/ID/Length (draft-kamath-pppext-peapv0-00 §2.1,
		// hostapd eap_server_peap.c). Result TLV (33) передаётся с полным EAP-заголовком.
		if len(app) >= 1 && (eap.Type(app[0]) == eap.TypeMSCHAPv2 || eap.Type(app[0]) == eap.TypeIdentity || eap.Type(app[0]) == eap.TypeTLV) {
			synthesized := make([]byte, 4+len(app))
			synthesized[0] = byte(eap.CodeResponse)
			synthesized[1] = sess.innerReqID
			binary.BigEndian.PutUint16(synthesized[2:4], uint16(len(synthesized)))
			copy(synthesized[4:], app)
			var err error
			innerPkt, err = eap.Parse(synthesized)
			if err != nil {
				s.failEAP(w, r, sess, "битый inner PEAP: "+err.Error())
				return
			}
		} else if len(app) >= 4 {
			eapLen := int(binary.BigEndian.Uint16(app[2:4]))
			if eapLen > len(app) {
				sess.pendingInner = app
				s.pumpPEAP(w, r, sess, nil)
				return
			}
			var err error
			innerPkt, err = eap.Parse(app[:eapLen])
			if err != nil {
				s.failEAP(w, r, sess, "битый внутренний EAP: "+err.Error())
				return
			}
			if len(app) > eapLen {
				sess.pendingInner = app[eapLen:]
			}
		} else {
			sess.pendingInner = app
			s.pumpPEAP(w, r, sess, nil)
			return
		}

		s.handlePEAPInner(w, r, sess, pkt.ID, innerPkt, srcIP)
	}
}

// pumpPEAP складывает out и застрявший в мосту исходящий поток в очередь
// фрагментов и отправляет следующий EAP-Request/PEAP либо ACK-запрос.
func (s *Server) pumpPEAP(w radius.ResponseWriter, r *radius.Request, sess *eapSession, out []byte) {
	if extra := sess.conn.takeOutput(); len(extra) > 0 {
		out = append(out, extra...)
	}
	sess.pushOutQueue(out)
	s.sendEAP(w, r, sess, sess.popOrAck())
}

// handlePEAPInner обрабатывает расшифрованные внутренние EAP-пакеты (MS-CHAPv2, Result TLV).
func (s *Server) handlePEAPInner(w radius.ResponseWriter, r *radius.Request,
	sess *eapSession, outerEAPID byte, innerPkt *eap.Packet, srcIP string) {

	switch sess.innerState {
	case peapStateChallenge:
		// Если клиент прислал EAP-Identity внутри туннеля (Windows/Android):
		if innerPkt.Type() == eap.TypeIdentity {
			sess.outerIdentity = string(innerPkt.IdentityData())
			sess.innerReqID++
			chal := eap.BuildMSCHAPv2Challenge(sess.innerReqID, sess.innerMSCHAPID, sess.authChallenge, "ligament")
			_ = sess.writeInner(chal[4:])
			s.pumpPEAP(w, r, sess, nil)
			return
		}

		if innerPkt.Type() != eap.TypeMSCHAPv2 {
			s.failEAP(w, r, sess, fmt.Sprintf("ожидался MS-CHAPv2 (26), получен тип %d", innerPkt.Type()))
			return
		}

		resp, err := eap.ParseMSCHAPv2Response(innerPkt.Data)
		if err != nil {
			s.failEAP(w, r, sess, "разбор MS-CHAPv2 Response: "+err.Error())
			return
		}

		username := resp.UserName
		if username == "" {
			username = sess.outerIdentity
		}
		// Нормализация username (вырезаем домен/realm: domain\user или user@realm)
		if idx := strings.LastIndex(username, "\\"); idx >= 0 {
			username = username[idx+1:]
		}
		if idx := strings.Index(username, "@"); idx >= 0 {
			username = username[:idx]
		}
		sess.outerIdentity = username

		ctx, cancel := context.WithTimeout(r.Context(), s.m.Get().Radius.PushWait+authTimeoutMargin)
		defer cancel()

		user, err := s.st.UserByUsername(ctx, username)
		if err != nil {
			auth.BurnDummyVerify(username)
			slog.Warn("radius: пользователь не найден", "user", username, "remote", srcIP)
			_ = s.st.Audit(ctx, username, "radius_auth", map[string]any{"reason": "no_user"}, srcIP, "fail")
			s.failMSCHAPv2(w, r, sess, resp.ID, "no_user")
			return
		}
		if !user.Enabled {
			slog.Warn("radius: пользователь отключён", "user", username, "remote", srcIP)
			_ = s.st.Audit(ctx, username, "radius_auth", map[string]any{"reason": "disabled"}, srcIP, "fail")
			s.failMSCHAPv2(w, r, sess, resp.ID, "disabled")
			return
		}

		// Проверка per-user fail window и FailLocked
		if rad := s.m.Get().Radius; rad.MaxFailPerUser > 0 {
			var n int
			if err := s.st.Pool().QueryRow(ctx, `
				SELECT count(*) FROM audit_log
				WHERE username = $1 AND event = 'radius_fail' AND result = 'fail'
				  AND ts > $2`,
				user.Username, time.Now().Add(-rad.FailWindow)).Scan(&n); err == nil && n >= rad.MaxFailPerUser {
				_ = s.st.Audit(ctx, username, "radius_auth", map[string]any{"reason": "locked"}, srcIP, "fail")
				s.failMSCHAPv2(w, r, sess, resp.ID, "locked")
				return
			}
		}
		if s.core.FailLocked(ctx, user.ID) {
			_ = s.st.Audit(ctx, username, "radius_auth", map[string]any{"reason": "locked"}, srcIP, "fail")
			s.failMSCHAPv2(w, r, sess, resp.ID, "locked")
			return
		}

		box, err := s.box()
		if err != nil {
			s.failEAP(w, r, sess, "мастер-ключ: "+err.Error())
			return
		}

		if len(user.PasswordEnc) == 0 {
			slog.Error("radius: пользователь не имеет password_enc (нужно пересохранить пароль)", "user", username)
			_ = s.st.Audit(ctx, username, "radius_auth", map[string]any{"reason": "password_enc_missing"}, srcIP, "fail")
			s.failMSCHAPv2(w, r, sess, resp.ID, "bad_credentials")
			return
		}

		rawPwd, err := box.DecryptAAD(user.Username, user.PasswordEnc)
		if err != nil {
			slog.Error("radius: расшифровка password_enc не удалась", "user", username, "error", err)
			_ = s.st.Audit(ctx, username, "radius_auth", map[string]any{"reason": "bad_credentials"}, srcIP, "fail")
			s.failMSCHAPv2(w, r, sess, resp.ID, "bad_credentials")
			return
		}

		type candidate struct {
			pwdString string
			authResp  string
			isClean   bool
		}
		var matched *candidate

		testCandidate := func(pwd string, isClean bool) bool {
			ntHash := eap.NTHash(pwd)
			if authResp, ok := eap.VerifyMSCHAPv2(resp, sess.authChallenge[:], ntHash); ok {
				matched = &candidate{pwdString: pwd, authResp: authResp, isClean: isClean}
				return true
			}
			return false
		}

		// 1. Проверяем чистый пароль
		if !testCandidate(string(rawPwd), true) {
			// 2. Проверяем кандидаты с TOTP-кодом (если TOTP подтверждён)
			if secretEnc, digits, period, confirmed, _, terr := s.st.TOTPGet(ctx, user.ID); terr == nil && confirmed && len(secretEnc) > 0 {
				secret, derr := box.DecryptAAD(auth.AADTOTP(user.Username), secretEnc)
				if derr == nil {
					totpCfg := s.m.Get().TOTP
					skew := int(totpCfg.Skew)
					if skew <= 0 {
						skew = 1
					}
					per := int64(period)
					if per <= 0 {
						per = int64(totpCfg.Period)
					}
					if per <= 0 {
						per = 30
					}
					now := time.Now().UTC()
					cur := now.Unix() / per
					hotpOpts := hotp.ValidateOpts{Digits: otp.Digits(digits), Algorithm: otp.AlgorithmSHA1}
					for cnt := cur - int64(skew); cnt <= cur+int64(skew); cnt++ {
						if cnt < 0 {
							continue
						}
						if code, err := hotp.GenerateCodeCustom(string(secret), uint64(cnt), hotpOpts); err == nil {
							if testCandidate(string(rawPwd)+code, false) {
								break
							}
						}
					}
				}
			}
		}

		if matched == nil {
			slog.Info("radius: MS-CHAPv2 неверный пароль", "user", username, "remote", srcIP)
			_ = s.st.Audit(ctx, username, "radius_auth", map[string]any{"reason": "bad_credentials"}, srcIP, "fail")
			_ = s.st.Audit(ctx, username, "radius_fail", map[string]any{"reason": "bad_credentials"}, srcIP, "fail")
			s.failMSCHAPv2(w, r, sess, resp.ID, "bad_credentials")
			return
		}

		// Пароль сошёлся!
		// Если это чистый пароль без 2FA-кода:
		// - при user.RadiusPush && Telegram: запускаем Telegram push-удержание через RADIUSAuth.
		// - при !user.RadiusPush: пользователь аутентифицируется по чистому паролю (нативный вход Wi-Fi).
		if matched.isClean && !user.RadiusPush {
			// Прямой вход по логину/паролю без 2FA-кода
			_ = s.st.Audit(ctx, username, "radius_auth", map[string]any{"reason": "password_ok"}, srcIP, "ok")
		} else {
			// Пропускаем через конвейер s.core.RADIUSAuth (проверка TOTP-кода или Telegram push-удержание)
			accept, reason := s.core.RADIUSAuth(ctx, username, matched.pwdString, srcIP)
			if !accept {
				slog.Info("radius: RADIUSAuth отклонил запрос", "user", username, "reason", reason, "remote", srcIP)
				s.failMSCHAPv2(w, r, sess, resp.ID, reason)
				return
			}
		}

		// Аутентификация успешна!
		// Вычисляем ISK, CMK, IPMK и CSK для Cryptobinding и MPPE ([MS-PEAP] §3.1.5.5):
		if len(sess.keyBlock) >= 40 {
			sess.peapRawTLSKey = make([]byte, len(sess.keyBlock))
			copy(sess.peapRawTLSKey, sess.keyBlock)

			isk := eap.DerivePEAPISK(eap.NTHash(matched.pwdString), resp.NTResponse[:])
			ipmk, cmk := eap.DerivePEAPCMK(sess.keyBlock[:40], isk)
			sess.peapCMK = cmk
			csk := eap.DerivePEAPCSK(ipmk)
			sess.peapCSK = csk[:64]
			sess.keyBlock = csk[:64] // по умолчанию CSK[:64]
			slog.Info("radius: PEAP Cryptobinding и CSK ключи сформированы", "user", username)
		}

		// Отправляем inner MS-CHAPv2 Success с эталонным AuthenticatorResponse
		sess.innerReqID++
		sess.innerState = peapStateSuccess
		succPkt := eap.BuildMSCHAPv2Success(sess.innerReqID, resp.ID, matched.authResp)
		if err := sess.writeInner(succPkt[4:]); err != nil {
			s.failEAP(w, r, sess, "отправка MS-CHAPv2 Success: "+err.Error())
			return
		}
		slog.Info("radius: MS-CHAPv2 пароль верен, отправка inner Success", "user", username, "remote", srcIP)
		s.pumpPEAP(w, r, sess, nil)

	case peapStateSuccess:
		// Проверяем, прислал ли клиент сразу Result TLV (Type 33)
		if innerPkt.Type() == eap.TypeTLV {
			if ok, _ := eap.ParseResultTLV(innerPkt.Data); ok {
				slog.Info("radius: клиент сразу прислал Result TLV Success", "user", sess.outerIdentity)
				if !eap.HasCryptobindingTLV(innerPkt.Data) && len(sess.peapRawTLSKey) >= 64 {
					sess.keyBlock = sess.peapRawTLSKey[:64]
				}
				s.finishPEAP(w, r, sess, outerEAPID, sess.outerIdentity, srcIP)
				return
			}
		}

		// Клиент прислал Success ACK (Type 26).
		// Отправляем EAP-Request/TLV с Result TLV (Success) и Cryptobinding TLV Request!
		sess.innerReqID++
		sess.innerState = peapStateTLV
		var nonce [32]byte
		_, _ = rand.Read(nonce[:])
		tlvReq := eap.BuildPEAPResultAndCryptoRequest(sess.innerReqID, nonce[:], sess.peapCMK)
		if err := sess.writeInner(tlvReq); err != nil {
			s.failEAP(w, r, sess, "отправка Result+Crypto TLV: "+err.Error())
			return
		}
		slog.Info("radius: получен MS-CHAPv2 Success ACK, отправка Result+Cryptobinding TLV", "user", sess.outerIdentity)
		s.pumpPEAP(w, r, sess, nil)

	case peapStateTLV:
		// Завершающий шаг: клиент прислал Result TLV Response
		cryptoUsed := false
		if innerPkt.Type() == eap.TypeTLV {
			if ok, err := eap.ParseResultTLV(innerPkt.Data); err == nil && !ok {
				s.failEAP(w, r, sess, "клиент отклонил Result TLV")
				return
			}
			cryptoUsed = eap.HasCryptobindingTLV(innerPkt.Data)
		}
		if cryptoUsed && len(sess.peapCSK) >= 64 {
			sess.keyBlock = sess.peapCSK[:64]
			slog.Info("radius: Cryptobinding TLV подтверждён клиентом, использован CSK", "user", sess.outerIdentity)
		} else if len(sess.peapRawTLSKey) >= 64 {
			sess.keyBlock = sess.peapRawTLSKey[:64]
			slog.Info("radius: Cryptobinding TLV не использован клиентом, применён TLS keying material", "user", sess.outerIdentity)
		}
		slog.Info("radius: получен Result TLV Response, завершение PEAP", "user", sess.outerIdentity)
		s.finishPEAP(w, r, sess, outerEAPID, sess.outerIdentity, srcIP)

	case peapStateFailed:
		s.failEAP(w, r, sess, "mschapv2 failure")
	}
}

// failMSCHAPv2 отправляет inner EAP-Request/MS-CHAPv2 Failure (OpCode 4)
// и переводит сессию в peapStateFailed для последующего отлупа.
func (s *Server) failMSCHAPv2(w radius.ResponseWriter, r *radius.Request, sess *eapSession, mschapID byte, reason string) {
	sess.innerReqID++
	sess.innerState = peapStateFailed
	failPkt := eap.BuildMSCHAPv2Failure(sess.innerReqID, mschapID, "E=691 R=0 M="+reason)
	if err := sess.writeInner(failPkt[4:]); err == nil {
		s.pumpPEAP(w, r, sess, nil)
	} else {
		s.failEAP(w, r, sess, reason)
	}
}

// finishPEAP выдаёт Access-Accept с EAP-Success, ключами MS-MPPE-Recv-Key
// и MS-MPPE-Send-Key для WPA2 PMK-деривации и стандартными reply-атрибутами.
func (s *Server) finishPEAP(w radius.ResponseWriter, r *radius.Request,
	sess *eapSession, eapID byte, username string, srcIP string) {
	auditCtx, acancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer acancel()
	if err := s.st.Audit(auditCtx, username, "radius_eap",
		map[string]any{"proto": "peap"}, srcIP, "ok"); err != nil {
		slog.Warn("radius: radius_eap не записан в аудит", "user", username, "error", err)
	}

	resp := r.Response(radius.CodeAccessAccept)
	if err := rfc2869.EAPMessage_Set(resp, eap.BuildResult(eap.CodeSuccess, eapID)); err != nil {
		slog.Warn("radius: EAP-Success не установлен", "error", err)
	}
	if len(sess.keyBlock) == eapKeyBlockLen {
		if err := msm.MSMPPERecvKey_Add(resp, sess.keyBlock[:32]); err != nil {
			slog.Warn("radius: MS-MPPE-Recv-Key не установлен", "error", err)
		}
		if err := msm.MSMPPESendKey_Add(resp, sess.keyBlock[32:]); err != nil {
			slog.Warn("radius: MS-MPPE-Send-Key не установлен", "error", err)
		}
	} else {
		slog.Warn("radius: MS-MPPE-ключи не выданы — keying material отсутствует", "user", username)
	}

	attrs := s.m.Get().Radius.ReplyAttributes
	if user, err := s.st.UserByUsername(r.Context(), username); err == nil && len(user.RadiusReply) > 0 {
		attrs = user.RadiusReply
	}
	applyReplyAttrs(resp, attrs)

	signEAPResponseMessageAuthenticator(r.Packet, resp)
	if err := w.Write(resp); err != nil {
		slog.Warn("radius: ответ не отправлен", "user", username, "error", err)
	}
	s.eapSessions.delete(sess)
	slog.Info("radius: EAP-PEAP Accept", "user", username, "remote", srcIP)
}

// sendEAP отправляет Access-Challenge с EAP-пакетом и State сессии,
// запоминая его для идемпотентных ретрансмитов NAS.
func (s *Server) sendEAP(w radius.ResponseWriter, r *radius.Request, sess *eapSession, pkt []byte) {
	resp := r.Response(radius.CodeAccessChallenge)
	if err := rfc2865.State_Add(resp, sess.state); err != nil {
		slog.Warn("radius: State не установлен", "error", err)
	}
	if err := rfc2869.EAPMessage_Set(resp, pkt); err != nil {
		slog.Warn("radius: EAP-Message не установлен", "error", err)
	}
	signEAPResponseMessageAuthenticator(r.Packet, resp)
	if err := w.Write(resp); err != nil {
		slog.Warn("radius: challenge не отправлен", "error", err)
	}
	sess.lastRespEAP = pkt
}

// popOrAck — следующий фрагмент исходящей очереди либо пустой
// EAP-Request/PEAP или EAP-Request/TTLS (ACK-запрос: «продолжай»).
func (sess *eapSession) popOrAck() []byte {
	if pkt := sess.popOutFragment(); pkt != nil {
		return pkt
	}
	id := sess.nextReqID()
	if sess.proto == eapProtoPEAP {
		return eap.BuildPEAP(eap.CodeRequest, id, 0, -1, nil)
	}
	return eap.BuildTTLS(eap.CodeRequest, id, 0, -1, nil)
}

// rejectEAP — Access-Reject с EAP-Failure (сессии может не быть).
func (s *Server) rejectEAP(w radius.ResponseWriter, r *radius.Request, id byte) {
	resp := r.Response(radius.CodeAccessReject)
	if err := rfc2869.EAPMessage_Set(resp, eap.BuildResult(eap.CodeFailure, id)); err != nil {
		slog.Warn("radius: EAP-Failure не установлен", "error", err)
	}
	if err := rfc2865.ReplyMessage_SetString(resp, "rejected"); err != nil {
		slog.Warn("radius: Reply-Message не установлен", "error", err)
	}
	signEAPResponseMessageAuthenticator(r.Packet, resp)
	if err := w.Write(resp); err != nil {
		slog.Warn("radius: ответ не отправлен", "error", err)
	}
}

// failEAP — терминальная ошибка обмена: Reject + EAP-Failure, сессия
// удаляется (bridge закрывается, воркер завершается).
func (s *Server) failEAP(w radius.ResponseWriter, r *radius.Request, sess *eapSession, why string) {
	slog.Warn("radius: EAP-TTLS обмен прерван", "reason", why, "remote", hostOnly(r.RemoteAddr))
	id := sess.id
	s.eapSessions.delete(sess)
	s.rejectEAP(w, r, id)
}

// hexState кодирует State-байты в ключ сессии.
func hexState(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hexDigits[c>>4], hexDigits[c&0x0F])
	}
	return string(out)
}
