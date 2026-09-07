// Юнит-тесты таблицы reply-атрибутов, Message-Authenticator (RFC 3579)
// и MS-MPPE-ключей (RFC 2548) — без БД и сети.
package radiusserver

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"testing"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
	msm "layeh.com/radius/vendors/microsoft"
	mt "layeh.com/radius/vendors/mikrotik"

	"github.com/aligorov/twofa/internal/radiusserver/eap"
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
// Authenticator ответа по RFC 3579 §3.2 / RFC 2869 §5.14: HMAC по ответу с
// нулевым атрибутом MA и Request Authenticator в поле Authenticator (при
// проверке клиент/NAS подставляет Request Authenticator).
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

// TestEAPResponseMessageAuthenticator: ответы EAP-обмена (RFC 3579 §3.2)
// подписываются ВСЕГДА — даже на запрос без Message-Authenticator — и
// проходят клиентскую проверку (пара подпись+проверка).
func TestEAPResponseMessageAuthenticator(t *testing.T) {
	// EAP-запрос без Message-Authenticator (пустой State, Identity).
	req := radius.New(radius.CodeAccessRequest, []byte("topsecret"))
	rfc2865.UserName_SetString(req, "anonymous")
	rfc2869.EAPMessage_Set(req, eap.BuildIdentity(eap.CodeResponse, 0, "anonymous"))

	resp := req.Response(radius.CodeAccessChallenge)
	rfc2865.State_Add(resp, []byte("0123456789abcdef"))
	rfc2869.EAPMessage_Set(resp,
		eap.BuildTTLS(eap.CodeRequest, 1, eap.TTLSFlagStart, -1, nil))
	signEAPResponseMessageAuthenticator(req, resp)

	if !hasMessageAuthenticator(resp) {
		t.Fatal("ответ EAP-обмена обязан содержать Message-Authenticator (RFC 3579 §3.2)")
	}
	if !verifyResponseMA(req, resp) {
		t.Fatal("Message-Authenticator EAP-ответа не проходит проверку RFC 3579")
	}

	// Подпись чувствительна к изменению содержимого: меняем EAP-пакет —
	// старая подпись больше не сходится (перестановка атрибутов тоже
	// меняет кодировку пакета), повторная подпись восстанавливает парность.
	saved := append([]byte(nil), mustEAPMessage(resp)...)
	mustEAPMessageSet(resp, eap.BuildTTLS(eap.CodeRequest, 2, 0, -1, nil))
	if verifyResponseMA(req, resp) {
		t.Fatal("подпись совпала после подмены EAP-Message")
	}
	mustEAPMessageSet(resp, saved)
	signEAPResponseMessageAuthenticator(req, resp)
	if !verifyResponseMA(req, resp) {
		t.Fatal("переподписанный EAP-ответ не прошёл проверку")
	}
}

// mustEAPMessage достаёт собранный EAP-пакет ответа (тестовый хелпер).
func mustEAPMessage(p *radius.Packet) []byte {
	b, err := rfc2869.EAPMessage_Lookup(p)
	if err != nil {
		panic(err)
	}
	return b
}

func mustEAPMessageSet(p *radius.Packet, pkt []byte) {
	p.Attributes.Del(rfc2869.EAPMessage_Type)
	if err := rfc2869.EAPMessage_Set(p, pkt); err != nil {
		panic(err)
	}
}

// TestMSMPPEKeyAttributes: формат MS-MPPE-Send/Recv-Key (RFC 2548 §3.5/
// §3.6): vendor 311, типы 16/17, значение Salt(2, старший бит 1)+
// length(1)+ключ с паддингом, зашифрованное цепочкой MD5 по секрету и
// Request Authenticator. Расшифровка зеркалом NewTunnelPassword должна
// вернуть исходные 32 байта.
func TestMSMPPEKeyAttributes(t *testing.T) {
	secret := []byte("topsecret")
	req := radius.New(radius.CodeAccessRequest, secret)
	rfc2865.UserName_SetString(req, "alice")

	recvKey := make([]byte, 32)
	sendKey := make([]byte, 32)
	for i := range recvKey {
		recvKey[i] = byte(i)
		sendKey[i] = byte(255 - i)
	}

	resp := req.Response(radius.CodeAccessAccept)
	if err := msm.MSMPPERecvKey_Add(resp, recvKey); err != nil {
		t.Fatalf("MSMPPERecvKey_Add: %v", err)
	}
	if err := msm.MSMPPESendKey_Add(resp, sendKey); err != nil {
		t.Fatalf("MSMPPESendKey_Add: %v", err)
	}

	gotRecv := decryptMSMPPE(t, resp, req, 17)
	gotSend := decryptMSMPPE(t, resp, req, 16)
	if !bytes.Equal(gotRecv, recvKey) {
		t.Fatalf("Recv-Key не расшифровался: %x", gotRecv)
	}
	if !bytes.Equal(gotSend, sendKey) {
		t.Fatalf("Send-Key не расшифровался: %x", gotSend)
	}
}

// decryptMSMPPE достаёт VSA Microsoft(311)/type и расшифровывает
// Tunnel-Password-подобное значение (зеркало layeh/radius NewTunnelPassword).
func decryptMSMPPE(t *testing.T, resp, req *radius.Packet, vendorType byte) []byte {
	t.Helper()
	for _, avp := range resp.Attributes {
		if avp.Type != rfc2865.VendorSpecific_Type {
			continue
		}
		vendorID, vsa, err := radius.VendorSpecific(avp.Attribute)
		if err != nil || vendorID != 311 || len(vsa) < 2 || vsa[0] != vendorType {
			continue
		}
		attr := vsa[2:] // за байтом типа лежит длина VSA (учтена выше)
		if len(attr) < 18 {
			t.Fatalf("MPPE-атрибут подозрительно короткий: %d", len(attr))
		}
		salt := attr[:2]
		if salt[0]&0x80 == 0 {
			t.Fatal("старший бит Salt не установлен (RFC 2548)")
		}
		enc := attr[2:]
		plain := make([]byte, len(enc))
		hash := md5.New()
		var b [md5.Size]byte
		for chunk := 0; chunk*16 < len(enc); chunk++ {
			hash.Reset()
			hash.Write(resp.Secret)
			if chunk == 0 {
				hash.Write(req.Authenticator[:])
				hash.Write(salt)
			} else {
				hash.Write(enc[(chunk-1)*16 : chunk*16])
			}
			hash.Sum(b[:0])
			for i := 0; i < 16 && chunk*16+i < len(enc); i++ {
				plain[chunk*16+i] = enc[chunk*16+i] ^ b[i]
			}
		}
		keyLen := int(plain[0])
		if keyLen != 32 {
			t.Fatalf("длина ключа внутри атрибута = %d, хочу 32", keyLen)
		}
		return plain[1 : 1+keyLen]
	}
	t.Fatalf("VSA Microsoft c типом %d не найден", vendorType)
	return nil
}

// TestResponseMAVerifiedByNAS: Message-Authenticator ответа обязан
// сходиться при пересчёте клиентом/NAS (UniFi/hostapd): по RFC 2869 §5.14
// HMAC считается по пакету с Request Authenticator в заголовке и обнулённым MA.
// Регрессия на баг: вычисление с нулями в заголовке или поверх финального
// Response Authenticator заставляло NAS молча ронять Challenge.
func TestResponseMAVerifiedByNAS(t *testing.T) {
	secret := []byte("s3cret")
	req := radius.New(radius.CodeAccessRequest, secret)
	resp := req.Response(radius.CodeAccessChallenge)
	resp.Attributes.Add(radius.Type(24), testAttr(t, 24, []byte("state-abc")))
	resp.Attributes.Add(radius.Type(79), testAttr(t, 79, []byte{2, 1, 0, 6, 21, 0x20}))
	forceResponseMessageAuthenticator(resp)

	// Симуляция проверки на стороне NAS после получения пакета:
	// Ответ кодируется в wire-формат (layeh вычисляет Response Authenticator в 4..20)
	encoded, err := resp.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// NAS проверяет Message-Authenticator по RFC 2869 §5.14:
	// 1. Копирует пакет
	verifyBuf := make([]byte, len(encoded))
	copy(verifyBuf, encoded)
	// 2. Подставляет исходный Request Authenticator в заголовок (байты 4..20)
	copy(verifyBuf[4:20], req.Authenticator[:])
	// 3. Находит Message-Authenticator, запоминает и обнуляет его значение
	var receivedMA []byte
	pos := 20
	for pos+2 <= len(verifyBuf) {
		aType := verifyBuf[pos]
		aLen := int(verifyBuf[pos+1])
		if aLen < 2 || pos+aLen > len(verifyBuf) {
			break
		}
		if aType == byte(messageAuthenticatorType) {
			receivedMA = append([]byte(nil), verifyBuf[pos+2:pos+aLen]...)
			for i := pos + 2; i < pos+aLen; i++ {
				verifyBuf[i] = 0
			}
			break
		}
		pos += aLen
	}
	if len(receivedMA) != 16 {
		t.Fatalf("MA не найден в пакете: %d", len(receivedMA))
	}

	// 4. Считает HMAC-MD5 по verifyBuf с секретом
	mac := hmac.New(md5.New, secret)
	mac.Write(verifyBuf)
	expectedMA := mac.Sum(nil)

	if !hmac.Equal(expectedMA, receivedMA) {
		t.Fatal("MA ответа не сходится при пересчёте по RFC 2869 на стороне NAS")
	}
}

// testAttr — radius.Attribute по типу и данным (в тестах layeh конструктора нет).
func testAttr(t *testing.T, typ radius.Type, data []byte) radius.Attribute {
	t.Helper()
	a := make(radius.Attribute, len(data)+2)
	a[0] = byte(typ)
	a[1] = byte(len(a))
	copy(a[2:], data)
	return a
}
