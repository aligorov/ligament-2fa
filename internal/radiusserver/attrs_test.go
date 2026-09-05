// Юнит-тесты таблицы reply-атрибутов и Message-Authenticator (RFC 3579)
// — без БД и сети.
package radiusserver

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"testing"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	mt "layeh.com/radius/vendors/mikrotik"
)

func TestApplyReplyAttrsMikrotikAndStandard(t *testing.T) {
	resp := radius.New(radius.CodeAccessAccept, []byte("s3cret"))
	applyReplyAttrs(resp, map[string]string{
		"Mikrotik-Group":        "wifi-users",
		"Mikrotik-Rate-Limit":   "5M/5M",
		"Mikrotik-Address-List": "allowed",
		"Reply-Message":         "welcome",
		"Session-Timeout":       "3600",
		"Framed-IP-Address":     "10.7.0.9",
		"Filter-Id":             "filt-1",
	})

	if got := mt.MikrotikGroup_GetString(resp); got != "wifi-users" {
		t.Fatalf("Mikrotik-Group = %q", got)
	}
	if got := mt.MikrotikRateLimit_GetString(resp); got != "5M/5M" {
		t.Fatalf("Mikrotik-Rate-Limit = %q", got)
	}
	if got := mt.MikrotikAddressList_GetString(resp); got != "allowed" {
		t.Fatalf("Mikrotik-Address-List = %q", got)
	}
	if got := rfc2865.ReplyMessage_GetString(resp); got != "welcome" {
		t.Fatalf("Reply-Message = %q", got)
	}
	n, err := radius.Integer(resp.Attributes.Get(rfc2865.SessionTimeout_Type))
	if err != nil || n != 3600 {
		t.Fatalf("Session-Timeout = %d err=%v, хочу 3600", n, err)
	}
	ip, err := radius.IPAddr(resp.Attributes.Get(rfc2865.FramedIPAddress_Type))
	if err != nil || ip.String() != "10.7.0.9" {
		t.Fatalf("Framed-IP-Address = %v err=%v, хочу 10.7.0.9", ip, err)
	}
	if got := rfc2865.FilterID_GetString(resp); got != "filt-1" {
		t.Fatalf("Filter-Id = %q", got)
	}
}

func TestApplyReplyAttrsSkipsUnknown(t *testing.T) {
	resp := radius.New(radius.CodeAccessAccept, []byte("s3cret"))
	applyReplyAttrs(resp, map[string]string{
		"Mikrotik-Wireless-Unknown": "x", // Mikrotik-*, не входит в белый список
		"Frobnicate-Attr":           "y", // нестандартный
		"Session-Timeout":           "not-a-number",
		"Framed-IP-Address":         "not-an-ip",
	})
	if got := len(resp.Attributes); got != 0 {
		t.Fatalf("все неизвестные/битые атрибуты должны быть пропущены, добавлено %d", got)
	}
}

// ---- Message-Authenticator (RFC 3579) ----

// signRequestMA — тестовый клиентский хелпер: считает и проставляет
// Message-Authenticator запроса (алгоритм RFC 3579 §3.2, сторона клиента).
func signRequestMA(p *radius.Packet) {
	p.Add(messageAuthenticatorType, make(radius.Attribute, macSize))
	for _, avp := range p.Attributes {
		if avp.Type != messageAuthenticatorType {
			continue
		}
		orig := avp.Attribute
		avp.Attribute = make(radius.Attribute, macSize)
		b, _ := p.MarshalBinary()
		avp.Attribute = orig
		mac := hmac.New(md5.New, p.Secret)
		mac.Write(b)
		copy(orig, mac.Sum(nil))
		return
	}
}

func TestMessageAuthenticatorVerify(t *testing.T) {
	secret := []byte("topsecret")
	p := radius.New(radius.CodeAccessRequest, secret)
	rfc2865.UserName_SetString(p, "alice")
	rfc2865.UserPassword_SetString(p, "hunter2")
	signRequestMA(p)

	if !verifyMessageAuthenticator(p) {
		t.Fatal("корректный Message-Authenticator отвергнут")
	}

	// Подделка: меняем один байт атрибута.
	tampered := radius.New(radius.CodeAccessRequest, secret)
	rfc2865.UserName_SetString(tampered, "alice")
	signRequestMA(tampered)
	attr, _ := tampered.Attributes.Lookup(messageAuthenticatorType)
	attr[0] ^= 0xFF
	if verifyMessageAuthenticator(tampered) {
		t.Fatal("подделанный Message-Authenticator принят")
	}

	// Атрибут неверной длины.
	bad := radius.New(radius.CodeAccessRequest, secret)
	bad.Add(messageAuthenticatorType, radius.Attribute("short"))
	if verifyMessageAuthenticator(bad) {
		t.Fatal("Message-Authenticator неверной длины принят")
	}

	// Без атрибута — проверка не требуется (MD5 уже сделала библиотека).
	plain := radius.New(radius.CodeAccessRequest, secret)
	if !verifyMessageAuthenticator(plain) {
		t.Fatal("запрос без Message-Authenticator не должен проваливать проверку")
	}
}

// verifyResponseMA — тестовый клиентский хелпер: проверяет Message-
// Authenticator ответа по RFC 3579: HMAC по ответу с нулевым атрибутом и
// Request Authenticator в поле Authenticator (при проверке клиент подстав-
// ляет Request Authenticator — поле ответа уже занято response-hash).
func verifyResponseMA(req, resp *radius.Packet) bool {
	attr, ok := resp.Attributes.Lookup(messageAuthenticatorType)
	if !ok || len(attr) != macSize {
		return false
	}
	saved := resp.Authenticator
	resp.Authenticator = req.Authenticator
	defer func() { resp.Authenticator = saved }()
	for _, avp := range resp.Attributes {
		if avp.Type != messageAuthenticatorType {
			continue
		}
		orig := avp.Attribute
		avp.Attribute = make(radius.Attribute, macSize)
		b, err := resp.MarshalBinary()
		avp.Attribute = orig
		if err != nil {
			return false
		}
		mac := hmac.New(md5.New, resp.Secret)
		mac.Write(b)
		return hmac.Equal(mac.Sum(nil), orig)
	}
	return false
}

func TestMessageAuthenticatorResponseSignature(t *testing.T) {
	req := radius.New(radius.CodeAccessRequest, []byte("topsecret"))
	rfc2865.UserName_SetString(req, "alice")
	signRequestMA(req)

	resp := req.Response(radius.CodeAccessAccept)
	rfc2865.ReplyMessage_SetString(resp, "welcome")
	mt.MikrotikGroup_SetString(resp, "wifi-users")
	signResponseMessageAuthenticator(req, resp)

	if !verifyResponseMA(req, resp) {
		t.Fatal("Message-Authenticator ответа не проходит проверку RFC 3579")
	}
	if !bytes.Equal(resp.Authenticator[:], req.Authenticator[:]) {
		t.Fatal("поле Authenticator ответа должно остаться Request Authenticator до Encode")
	}

	// Запрос без M-A → ответ без M-A.
	plainReq := radius.New(radius.CodeAccessRequest, []byte("topsecret"))
	plainResp := plainReq.Response(radius.CodeAccessReject)
	signResponseMessageAuthenticator(plainReq, plainResp)
	if hasMessageAuthenticator(plainResp) {
		t.Fatal("ответ на запрос без Message-Authenticator не должен содержать атрибут")
	}
}
