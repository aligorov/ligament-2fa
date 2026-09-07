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
	"encoding/binary"
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
// атрибута. Запрос без Message-Authenticator считается корректным — обычная
// Библиотека MD5-проверку Access-Request не делает; реальный fallback:
// неверный секрет даёт мусор при расшифровке PAP и пароль не сойдётся.
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
// Message-Authenticator, если запрос его содержал (RFC 3579: ответ на пакет
// с Message-Authenticator обязан включать корректный Message-Authenticator,
// иначе строгие NAS, патченые от BlastRADIUS, отбросят ответ). Значение —
// HMAC-MD5 секрета по ответу с нулевым атрибутом и Request Authenticator в
// поле Authenticator (r.Response копирует его из запроса, MarshalBinary
// записывает как есть). Вызывается последним, после всех reply-атрибутов.
func signResponseMessageAuthenticator(req, resp *radius.Packet) {
	if !hasMessageAuthenticator(req) {
		return
	}
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
// Message-Authenticator (RFC 2869 §5.14 / RFC 3579 §3.2): HMAC-MD5 по
// пакету, в котором ПОЛЕ Authenticator (16 байт) и сам атрибут MA
// обнулены — независимо от того, какой Response Authenticator будет
// вычислен при финальном кодировании (layeh считает его ПОСЛЕ, с уже
// готовой MA). Повторная подпись заменяет атрибут, а не дублирует.
// Нарушение порядка (MA поверх ненулевого Authenticator) заставляет
// строгие NAS (UniFi/hostapd) молча отбрасывать Challenge.
func forceResponseMessageAuthenticator(resp *radius.Packet) {
	resp.Attributes.Del(messageAuthenticatorType)
	resp.Add(messageAuthenticatorType, make(radius.Attribute, macSize))

	buf := make([]byte, 0, 64)
	buf = append(buf, byte(resp.Code), byte(resp.Identifier), 0, 0)
	buf = append(buf, make([]byte, 16)...) // Authenticator = нули
	for _, a := range resp.Attributes {
		buf = append(buf, byte(a.Type), byte(len(a.Attribute)+2))
		buf = append(buf, a.Attribute...)
	}
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(buf)))

	mac := hmac.New(md5.New, resp.Secret)
	mac.Write(buf)
	sum := mac.Sum(nil)
	for i := len(resp.Attributes) - 1; i >= 0; i-- {
		if resp.Attributes[i].Type == messageAuthenticatorType {
			copy(resp.Attributes[i].Attribute, sum)
			return
		}
	}
}
