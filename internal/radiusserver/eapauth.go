// Поток EAP-TTLS/PAP в Access-Request (RFC 3579 + RFC 5281): Identity →
// сессия по RADIUS State → пошаговый TLS-handshake через мост (eapsession)
// → phase-2 AVP (User-Name + User-Password) → внутренний PAP через общий
// конвейер Core.RADIUSAuth (сплиты «пароль+код», push_wait) → Accept с
// EAP-Success и MS-MPPE-ключами WPA2 либо Reject с EAP-Failure.
package radiusserver

import (
	"bytes"
	"context"
	"log/slog"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
	msm "layeh.com/radius/vendors/microsoft"

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
	if pkt.Code != eap.CodeResponse {
		// Request/Success/Failure от клиента — протокольная ошибка.
		slog.Warn("radius: EAP-пакет не Response — Reject", "remote", srcIP, "code", int(pkt.Code))
		s.rejectEAP(w, r, pkt.ID)
		return
	}

	state := hexState(rfc2865.State_Get(r.Packet))
	sess := s.eapSessions.get(state)

	// Ретрансмит NAS (тот же State + тот же EAP-пакет): повторяем последний
	// ответ идентично — дубли запросов от AP нормальны и идемпотентны.
	if sess != nil && bytes.Equal(sess.lastReqEAP, eapRaw) {
		s.sendEAP(w, r, sess, sess.lastRespEAP)
		return
	}

	switch pkt.Type() {
	case eap.TypeIdentity:
		// Внешний identity может быть anonymous@… — реальное имя придёт
		// внутри туннеля (phase-2 AVP User-Name).
		cert := s.eapCertificate()
		if cert == nil {
			if cerr := s.EnsureEAPCert(r.Context()); cerr != nil {
				slog.Error("radius: EAP-TTLS недоступен — сертификат не создан",
					"error", cerr, "remote", srcIP)
				s.rejectEAP(w, r, pkt.ID)
				return
			}
			cert = s.eapCertificate()
		}
		if sess != nil {
			s.eapSessions.delete(sess) // повторный Identity с тем же State
		}
		sess = s.eapSessions.create(cert)
		sess.reqID = pkt.ID + 1
		sess.lastReqEAP = append([]byte(nil), eapRaw...)
		slog.Info("radius: EAP-TTLS начат", "identity", string(pkt.IdentityData()),
			"remote", srcIP)
		// Старт: пустой EAP-Request/TTLS с флагом S.
		s.sendEAP(w, r, sess,
			eap.BuildTTLS(eap.CodeRequest, sess.reqID, eap.TTLSFlagStart, -1, nil))

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
		// Клиент не поддерживает TTLS; других методов нет.
		slog.Info("radius: клиент отверг TTLS (Nak) — Reject", "remote", srcIP)
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
		sess.pushOutQueue(stuck)
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
	if user, err := s.st.UserByUsername(ctx, inner.UserName); err == nil && user.RadiusReply != nil {
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
// EAP-Request/TTLS (ACK-запрос: «продолжай»).
func (sess *eapSession) popOrAck() []byte {
	if pkt := sess.popOutFragment(); pkt != nil {
		return pkt
	}
	id := sess.reqID
	sess.reqID++
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
