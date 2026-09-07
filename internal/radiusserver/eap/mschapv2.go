// MS-CHAPv2 (RFC 2759) и Result TLV ([MS-PEAP]): структуры пакетов,
// проверка NT-Response и генерация AuthenticatorResponse для PEAPv0.
package eap

import (
	"bytes"
	"crypto/des"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

// OpCode MS-CHAPv2 (RFC 2759 §3).
const (
	MSCHAPv2OpChallenge byte = 1
	MSCHAPv2OpResponse  byte = 2
	MSCHAPv2OpSuccess   byte = 3
	MSCHAPv2OpFailure   byte = 4
)

// MSCHAPv2Challenge — серверный вызов (OpCode 1).
type MSCHAPv2Challenge struct {
	ID        byte
	Challenge [16]byte
	Name      string
}

// BuildMSCHAPv2Challenge собирает EAP-пакет Request типа 26 с вызовом.
func BuildMSCHAPv2Challenge(eapID byte, mschapID byte, challenge [16]byte, name string) []byte {
	// Длина данных MS-CHAPv2: OpCode(1) + ID(1) + Len(2) + ValSize(1) + Chal(16) + Name(N)
	msLen := 5 + 16 + len(name)
	data := make([]byte, 1+msLen)
	data[0] = byte(TypeMSCHAPv2)
	data[1] = MSCHAPv2OpChallenge
	data[2] = mschapID
	binary.BigEndian.PutUint16(data[3:5], uint16(msLen))
	data[5] = 16 // Value-Size
	copy(data[6:22], challenge[:])
	copy(data[22:], name)
	return Build(CodeRequest, eapID, data)
}

// MSCHAPv2Response — ответ клиента (OpCode 2).
type MSCHAPv2Response struct {
	ID            byte
	PeerChallenge [16]byte
	NTResponse    [24]byte
	Flags         byte
	UserName      string
}

// ParseMSCHAPv2Response разбирает ответ клиента из EAP-пакета (Type 26).
func ParseMSCHAPv2Response(data []byte) (*MSCHAPv2Response, error) {
	if len(data) < 1+5+49 { // Type(1) + OpCode(1) + ID(1) + Len(2) + ValSize(1) + Val(49)
		return nil, errors.New("mschapv2: пакет короче заголовка Response")
	}
	if Type(data[0]) != TypeMSCHAPv2 {
		return nil, fmt.Errorf("mschapv2: тип %d не MS-CHAPv2", data[0])
	}
	if data[1] != MSCHAPv2OpResponse {
		return nil, fmt.Errorf("mschapv2: ожидался OpCode Response (2), получено %d", data[1])
	}
	valSize := int(data[5])
	if valSize != 49 {
		return nil, fmt.Errorf("mschapv2: неверный Value-Size %d (ожидалось 49)", valSize)
	}
	resp := &MSCHAPv2Response{
		ID: data[2],
	}
	copy(resp.PeerChallenge[:], data[6:22])
	// data[22:30] — 8 байт reserved (нули)
	copy(resp.NTResponse[:], data[30:54])
	resp.Flags = data[54]
	if len(data) > 55 {
		resp.UserName = string(data[55:])
	}
	return resp, nil
}

// BuildMSCHAPv2Success собирает EAP-Request/MS-CHAPv2 Success (OpCode 3)
// со строкой AuthenticatorResponse ("S=<40_hex> M=...").
func BuildMSCHAPv2Success(eapID byte, mschapID byte, authResponse string) []byte {
	msg := []byte(authResponse)
	msLen := 4 + len(msg)
	data := make([]byte, 1+msLen)
	data[0] = byte(TypeMSCHAPv2)
	data[1] = MSCHAPv2OpSuccess
	data[2] = mschapID
	binary.BigEndian.PutUint16(data[3:5], uint16(msLen))
	copy(data[5:], msg)
	return Build(CodeRequest, eapID, data)
}

// BuildMSCHAPv2Failure собирает EAP-Request/MS-CHAPv2 Failure (OpCode 4).
func BuildMSCHAPv2Failure(eapID byte, mschapID byte, message string) []byte {
	msg := []byte(message)
	msLen := 4 + len(msg)
	data := make([]byte, 1+msLen)
	data[0] = byte(TypeMSCHAPv2)
	data[1] = MSCHAPv2OpFailure
	data[2] = mschapID
	binary.BigEndian.PutUint16(data[3:5], uint16(msLen))
	copy(data[5:], msg)
	return Build(CodeRequest, eapID, data)
}

// BuildResultTLV собирает EAP-пакет Type 33 (Result TLV, [MS-PEAP] §2.2.8.1).
// success=true -> Value 1 (Success); success=false -> Value 2 (Failure).
func BuildResultTLV(code Code, id byte, success bool) []byte {
	data := make([]byte, 7)
	data[0] = byte(TypeTLV)
	binary.BigEndian.PutUint16(data[1:3], 0x8003) // TLV Type: 0x8003 (Result TLV = 3, mandatory = 0x8000)
	binary.BigEndian.PutUint16(data[3:5], 2)      // TLV Length: 2
	val := uint16(1)
	if !success {
		val = 2
	}
	binary.BigEndian.PutUint16(data[5:7], val)
	return Build(code, id, data)
}

// BuildCryptobindingTLV создаёт 60-байтный Cryptobinding TLV (Type 12) для PEAPv0 ([MS-PEAP] §2.2.8.2).
// nonce — 32 случайных байта. cmk — 20-байтный Compound MAC Key.
func BuildCryptobindingTLV(nonce []byte, cmk []byte) []byte {
	tlv := make([]byte, 60)
	binary.BigEndian.PutUint16(tlv[0:2], 12) // Type 12 = Cryptobinding TLV
	binary.BigEndian.PutUint16(tlv[2:4], 56) // Length = 56
	tlv[4] = 0                              // Reserved
	tlv[5] = 0                              // Version = 0 (PEAPv0)
	tlv[6] = 0                              // RecvVersion = 0
	tlv[7] = 0                              // SubType = 0 (Request)
	copy(tlv[8:40], nonce)                  // 32-byte Nonce
	// tlv[40:60] — Compound_MAC, инициализированный нулями

	// Compound_MAC: HMAC-SHA1-160(CMK, cryptobinding TLV (60 байт с нулями в MAC) | EAP_TYPE_PEAP (0x19))
	h := hmac.New(sha1.New, cmk)
	h.Write(tlv)
	h.Write([]byte{byte(TypePEAP)}) // TypePEAP = 25 (0x19)
	mac := h.Sum(nil)
	copy(tlv[40:60], mac)
	return tlv
}

// BuildPEAPResultAndCryptoRequest собирает внутренний EAP-пакет с Result TLV (Success)
// и Cryptobinding TLV Request ([MS-PEAP] §3.1.5.5).
func BuildPEAPResultAndCryptoRequest(innerReqID byte, nonce []byte, cmk []byte) []byte {
	if len(cmk) == 0 {
		return BuildResultTLV(CodeRequest, innerReqID, true)
	}
	resTLV := make([]byte, 6)
	binary.BigEndian.PutUint16(resTLV[0:2], 0x8003) // Result TLV (3), mandatory (0x8000)
	binary.BigEndian.PutUint16(resTLV[2:4], 2)      // Length 2
	binary.BigEndian.PutUint16(resTLV[4:6], 1)      // Status 1 (Success)

	cryptoTLV := BuildCryptobindingTLV(nonce, cmk)
	data := make([]byte, 1+len(resTLV)+len(cryptoTLV))
	data[0] = byte(TypeTLV)
	copy(data[1:], resTLV)
	copy(data[1+len(resTLV):], cryptoTLV)
	return Build(CodeRequest, innerReqID, data)
}

// ParseResultTLV сканирует все TLV внутри пакета TypeTLV и проверяет,
// присутствует ли Result TLV со статусом Success (1).
func ParseResultTLV(data []byte) (bool, error) {
	if len(data) < 1 {
		return false, errors.New("eap: пустые TLV-данные")
	}
	if Type(data[0]) != TypeTLV {
		return false, fmt.Errorf("eap: тип %d не TLV", data[0])
	}
	pos := data[1:]
	for len(pos) >= 4 {
		tlvType := binary.BigEndian.Uint16(pos[0:2]) & 0x3fff // маскируем mandatory-бит 0x8000
		tlvLen := int(binary.BigEndian.Uint16(pos[2:4]))
		pos = pos[4:]
		if len(pos) < tlvLen {
			break
		}
		if tlvType == 3 { // Result TLV (EAP_TLV_RESULT_TLV = 3)
			if tlvLen >= 2 {
				status := binary.BigEndian.Uint16(pos[:2])
				return status == 1, nil
			}
		}
		pos = pos[tlvLen:]
	}
	return false, errors.New("eap: Result TLV не найден")
}

// HasCryptobindingTLV возвращает true, если внутри пакета TypeTLV присутствует Cryptobinding TLV (тип 12).
func HasCryptobindingTLV(data []byte) bool {
	if len(data) < 1 || Type(data[0]) != TypeTLV {
		return false
	}
	pos := data[1:]
	for len(pos) >= 4 {
		tlvType := binary.BigEndian.Uint16(pos[0:2]) & 0x3fff
		tlvLen := int(binary.BigEndian.Uint16(pos[2:4]))
		pos = pos[4:]
		if len(pos) < tlvLen {
			break
		}
		if tlvType == 12 { // Cryptobinding TLV
			return true
		}
		pos = pos[tlvLen:]
	}
	return false
}

// GetMasterKey (RFC 3079 §3.4): вычисляет 16-байтный MasterKey из PasswordHashHash и NTResponse.
// PasswordHashHash = MD4(ntHash).
func GetMasterKey(ntHash []byte, ntResponse []byte) []byte {
	hMD4 := md4.New()
	hMD4.Write(ntHash)
	passwordHashHash := hMD4.Sum(nil)

	magic1 := []byte("This is the MPPE Master Key")
	h := sha1.New()
	h.Write(passwordHashHash)
	h.Write(ntResponse)
	h.Write(magic1)
	digest := h.Sum(nil)
	res := make([]byte, 16)
	copy(res, digest[:16])
	return res
}

// GetAsymmetricStartKey (RFC 3079 §3.4): вычисляет 16-байтный SessionKey (Send или Recv)
// из MasterKey.
func GetAsymmetricStartKey(masterKey []byte, isSend bool, isServer bool) []byte {
	magic2 := []byte("On the client side, this is the send key; on the server side, it is the receive key.")
	magic3 := []byte("On the client side, this is the receive key; on the server side, it is the send key.")
	pad1 := make([]byte, 40)
	pad2 := bytes.Repeat([]byte{0xf2}, 40)

	var magic []byte
	if isSend {
		if isServer {
			magic = magic3
		} else {
			magic = magic2
		}
	} else {
		if isServer {
			magic = magic2
		} else {
			magic = magic3
		}
	}

	h := sha1.New()
	h.Write(masterKey)
	h.Write(pad1)
	h.Write(magic)
	h.Write(pad2)
	digest := h.Sum(nil)
	res := make([]byte, 16)
	copy(res, digest[:16])
	return res
}

// DerivePEAPISK (hostapd eap_mschapv2_getKey / [MS-PEAP]): вычисляет 32-байтный ISK
// (Inner Session Key): Server RecvKey (16 байт) || Server SendKey (16 байт).
func DerivePEAPISK(ntHash []byte, ntResponse []byte) []byte {
	masterKey := GetMasterKey(ntHash, ntResponse)
	recvKey := GetAsymmetricStartKey(masterKey, false, true)
	sendKey := GetAsymmetricStartKey(masterKey, true, true)
	isk := make([]byte, 32)
	copy(isk[:16], recvKey)
	copy(isk[16:], sendKey)
	return isk
}

// PEAPPRFPlus реализует PRF+ для PEAPv0 (hostapd peap_prfplus / [MS-PEAP]).
// PRF+(K, S, LEN) = T1 | T2 | ... | Tn
// T1 = HMAC-SHA1(K, S | 0x01 | 0x00 | 0x00)
// T2 = HMAC-SHA1(K, T1 | S | 0x02 | 0x00 | 0x00)
// ...
// Tn = HMAC-SHA1(K, Tn-1 | S | n | 0x00 | 0x00)
func PEAPPRFPlus(key []byte, label string, seed []byte, outLen int) []byte {
	out := make([]byte, 0, outLen)
	var counter byte
	var prevHash []byte
	for len(out) < outLen {
		counter++
		h := hmac.New(sha1.New, key)
		if len(prevHash) > 0 {
			h.Write(prevHash)
		}
		h.Write([]byte(label))
		h.Write(seed)
		h.Write([]byte{counter, 0x00, 0x00})
		prevHash = h.Sum(nil)
		out = append(out, prevHash...)
	}
	return out[:outLen]
}

// DerivePEAPCMK вычисляет IPMK (40 байт) и CMK (20 байт) из Tunnel Key (TK) и ISK.
// TK — первые 40 октетов TLS keying material (экспортированных с "client EAP encryption").
func DerivePEAPCMK(tk []byte, isk []byte) (ipmk []byte, cmk []byte) {
	imck := PEAPPRFPlus(tk[:40], "Inner Methods Compound Keys", isk, 60)
	return imck[:40], imck[40:60]
}

// DerivePEAPCSK вычисляет 128-байтный Compound Session Key (CSK) из IPMK ([MS-PEAP] §3.1.5.5):
// CSK = PRF+(IPMK, "Session Key Generating Function", "\x00", 128).
// Первые 64 байта используются для MS-MPPE: Recv-Key (32 байта) и Send-Key (32 байта).
func DerivePEAPCSK(ipmk []byte) []byte {
	return PEAPPRFPlus(ipmk, "Session Key Generating Function", []byte{0x00}, 128)
}

// ---- Криптография RFC 2759 ----

// NTHash вычисляет MD4(UTF-16LE(password)) — 16 байт NT-Hash.
func NTHash(password string) []byte {
	u := utf16.Encode([]rune(password))
	b := make([]byte, len(u)*2)
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[i*2:], v)
	}
	h := md4.New()
	h.Write(b)
	return h.Sum(nil)
}

// ChallengeHash (RFC 2759 §8.2): SHA-1(PeerChallenge || AuthChallenge || UserName)[:8].
func ChallengeHash(peerChallenge, authChallenge []byte, userName string) []byte {
	// По RFC 2759 из имени пользователя вырезается имя домена/realm, если оно есть
	idx := strings.LastIndex(userName, "\\")
	if idx >= 0 {
		userName = userName[idx+1:]
	}
	idx = strings.Index(userName, "@")
	if idx >= 0 {
		userName = userName[:idx]
	}

	h := sha1.New()
	h.Write(peerChallenge)
	h.Write(authChallenge)
	h.Write([]byte(userName))
	sum := h.Sum(nil)
	return sum[:8]
}

// ChallengeResponse (RFC 2759 §8.5): шифрование 8-байтного challenge
// тремя DES-ключами, полученными из дополненного 21-байтного NT-Hash.
func ChallengeResponse(challenge []byte, ntHash []byte) [24]byte {
	var zHash [21]byte
	copy(zHash[:], ntHash)

	k1 := makeDESKey(zHash[0:7])
	k2 := makeDESKey(zHash[7:14])
	k3 := makeDESKey(zHash[14:21])

	var resp [24]byte
	c1, _ := des.NewCipher(k1)
	c1.Encrypt(resp[0:8], challenge)

	c2, _ := des.NewCipher(k2)
	c2.Encrypt(resp[8:16], challenge)

	c3, _ := des.NewCipher(k3)
	c3.Encrypt(resp[16:24], challenge)

	return resp
}

// GenerateAuthenticatorResponse (RFC 2759 §8.7): вычисление 20-байтного
// ответа сервера для взаимной аутентификации. Возвращает "S=" + 40 hex символов.
func GenerateAuthenticatorResponse(ntHash []byte, ntResponse []byte, peerChallenge, authChallenge []byte, userName string) string {
	magic1 := []byte("Magic server to client signing constant")
	magic2 := []byte("Pad to make it do more than one iteration")

	// HashHash = MD4(ntHash)
	hMD4 := md4.New()
	hMD4.Write(ntHash)
	hashHash := hMD4.Sum(nil)

	// SHA-1(HashHash || ntResponse || magic1)
	h1 := sha1.New()
	h1.Write(hashHash)
	h1.Write(ntResponse)
	h1.Write(magic1)
	digest := h1.Sum(nil)

	// Challenge = ChallengeHash(peerChallenge, authChallenge, userName)
	chal := ChallengeHash(peerChallenge, authChallenge, userName)

	// SHA-1(digest || chal || magic2)
	h2 := sha1.New()
	h2.Write(digest)
	h2.Write(chal)
	h2.Write(magic2)
	authResp := h2.Sum(nil)

	return "S=" + strings.ToUpper(hex.EncodeToString(authResp))
}

// makeDESKey преобразует 7 байт в 8 байт DES-ключа с нечётной чётностью (RFC 2759 §8.8).
func makeDESKey(k []byte) []byte {
	key := make([]byte, 8)
	key[0] = k[0] >> 1
	key[1] = ((k[0] & 0x01) << 6) | (k[1] >> 2)
	key[2] = ((k[1] & 0x03) << 5) | (k[2] >> 3)
	key[3] = ((k[2] & 0x07) << 4) | (k[3] >> 4)
	key[4] = ((k[3] & 0x0F) << 3) | (k[4] >> 5)
	key[5] = ((k[4] & 0x1F) << 2) | (k[5] >> 6)
	key[6] = ((k[5] & 0x3F) << 1) | (k[6] >> 7)
	key[7] = k[6] & 0x7F
	for i := 0; i < 8; i++ {
		key[i] = key[i] << 1
		var count int
		for b := key[i]; b > 0; b >>= 1 {
			count += int(b & 1)
		}
		if count%2 == 0 {
			key[i] ^= 1
		}
	}
	return key
}

// VerifyMSCHAPv2 проверяет соответствие полученного NT-Response вычисленному
// эталону и возвращает строку AuthenticatorResponse для успеха.
func VerifyMSCHAPv2(resp *MSCHAPv2Response, authChallenge []byte, ntHash []byte) (string, bool) {
	chal := ChallengeHash(resp.PeerChallenge[:], authChallenge, resp.UserName)
	expected := ChallengeResponse(chal, ntHash)

	for i := 0; i < 24; i++ {
		if resp.NTResponse[i] != expected[i] {
			return "", false
		}
	}
	authResp := GenerateAuthenticatorResponse(ntHash, resp.NTResponse[:], resp.PeerChallenge[:], authChallenge, resp.UserName)
	return authResp, true
}
