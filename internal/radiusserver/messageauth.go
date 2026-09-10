// Message-Authenticator (RFC 3579, тип 80) — механизм против BlastRADIUS
// (CVE-2024-3596). layeh.com/radius заморожен без поддержки rfc3579
// (пакета rfc3579 и константы MessageAuthenticator_Type нет — проверено по
// исходникам), поэтому проверка запроса и подпись ответа реализованы вручную
// поверх экспортируемых MarshalBinary/AVP: HMAC-MD5 считается по байтам
// пакета с обнулённым значением Message-Authenticator и (для ответа)
// Request Authenticator в поле Authenticator.
package radiusserver

import (
	"crypto/hmac"
	"crypto/md5"
	"layeh.com/radius"
)

// messageAuthenticatorType — атрибут Message-Authenticator (RFC 3579 §3.2,
// он же RFC 2869 §5.14); в layeh/radius константа не сгенерирована.
const messageAuthenticatorType radius.Type = 80

// macSize — длина HMAC-MD5 (16 байт).
const macSize = 16

// hasMessageAuthenticator сообщает, содержал ли запрос Message-Authenticator.
func hasMessageAuthenticator(p *radius.Packet) bool {
	_, ok := p.Attributes.Lookup(messageAuthenticatorType)
	return ok
}

// verifyMessageAuthenticator проверяет Message-Authenticator запроса
// (RFC 3579 §3.2): HMAC-MD5 секрета по всему пакету с обнулённым значением
// атрибута. Сам факт «запрос без Message-Authenticator» этой функцией НЕ
// карается (она отвечает только за корректность присутствующего атрибута);
// обязанность запроса нести MA — политика вызывающего кода (см.
// Server.checkRequestMessageAuthenticator: RFC 3579 §3.2 MUST для
// EAP-Message и radius.require_message_authenticator для остальных).
func verifyMessageAuthenticator(p *radius.Packet) bool {
	attr, ok := p.Attributes.Lookup(messageAuthenticatorType)
	if !ok {
		return true
	}
	if len(attr) != macSize {
		return false
	}
	for _, avp := range p.Attributes {
		if avp.Type != messageAuthenticatorType {
			continue
		}
		orig := avp.Attribute
		avp.Attribute = make(radius.Attribute, macSize)
		b, err := p.MarshalBinary()
		avp.Attribute = orig
		if err != nil {
			return false
		}
		mac := hmac.New(md5.New, p.Secret)
		mac.Write(b)
		return hmac.Equal(mac.Sum(nil), orig)
	}
	return false
}

// signResponseMessageAuthenticator добавляет в ответ вычисленный
// Message-Authenticator ВСЕГДА, независимо от наличия атрибута в запросе:
// это митигация downgrade BlastRADIUS (CVE-2024-3596) — даже если запрос
// MITM подменил и убрал Message-Authenticator, ответ, подписанный MA,
// строгими NAS принимается, а нестификованный перехваченный ответ (без MA)
// патченые NAS отбрасывают. Значение — HMAC-MD5 секрета по ответу с нулевым
// атрибутом и Request Authenticator в поле Authenticator (r.Response копирует
// его из запроса, MarshalBinary записывает как есть). Вызывается последним,
// после всех reply-атрибутов.
func signResponseMessageAuthenticator(req, resp *radius.Packet) {
	_ = req
	forceResponseMessageAuthenticator(resp)
}

// signEAPResponseMessageAuthenticator подписывает ответ EAP-обмена:
// RFC 3579 §3.2 требует Message-Authenticator в ЛЮБОМ ответе на запрос
// с EAP-Message (Access-Challenge/Accept/Reject), даже если сам запрос
// атрибута не содержал. Алгоритм общий с обычной подписью (RFC 2869 §5.14).
func signEAPResponseMessageAuthenticator(req, resp *radius.Packet) {
	_ = req
	forceResponseMessageAuthenticator(resp)
}

// forceResponseMessageAuthenticator вписывает в ответ корректный
// Message-Authenticator (RFC 2869 §5.14 / RFC 3579 §3.2): HMAC-MD5 секрета по
// пакету с нулевым атрибутом MA и Request Authenticator в поле Authenticator
// (r.Response копирует его из запроса, MarshalBinary записывает как есть).
// Повторная подпись заменяет атрибут, а не дублирует.
// Нарушение (вычисление MA с нулями в Authenticator или поверх финального Response
// Authenticator) заставляет строгие NAS (UniFi, Keenetic, MikroTik, hostapd)
// молча отбрасывать Access-Challenge.
func forceResponseMessageAuthenticator(resp *radius.Packet) {
	resp.Attributes.Del(messageAuthenticatorType)
	resp.Add(messageAuthenticatorType, make(radius.Attribute, macSize))
	b, err := resp.MarshalBinary()
	if err != nil {
		resp.Attributes.Del(messageAuthenticatorType)
		return
	}

	mac := hmac.New(md5.New, resp.Secret)
	mac.Write(b)
	sum := mac.Sum(nil)
	for i := len(resp.Attributes) - 1; i >= 0; i-- {
		if resp.Attributes[i].Type == messageAuthenticatorType {
			copy(resp.Attributes[i].Attribute, sum)
			return
		}
	}
}
