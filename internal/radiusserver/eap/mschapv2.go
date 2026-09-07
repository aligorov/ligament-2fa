// MS-CHAPv2 (RFC 2759) и Result TLV ([MS-PEAP]): структуры пакетов,
// проверка NT-Response и генерация AuthenticatorResponse для PEAPv0.
package eap

import (
	"crypto/des"
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
	binary.BigEndian.PutUint16(data[1:3], 0x8001) // TLV Type: 0x8001 (Result TLV, mandatory)
	binary.BigEndian.PutUint16(data[3:5], 2)      // TLV Length: 2
	val := uint16(1)
	if !success {
		val = 2
	}
	binary.BigEndian.PutUint16(data[5:7], val)
	return Build(code, id, data)
}

// ParseResultTLV проверяет, является ли EAP-пакет успешным Result TLV.
func ParseResultTLV(data []byte) (bool, error) {
	if len(data) < 7 {
		return false, errors.New("eap: Result TLV короче 7 байт")
	}
	if Type(data[0]) != TypeTLV {
		return false, fmt.Errorf("eap: тип %d не TLV", data[0])
	}
	tlvType := binary.BigEndian.Uint16(data[1:3])
	if tlvType != 0x8001 && tlvType != 0x0001 {
		return false, fmt.Errorf("eap: неверный TLV Type 0x%04X", tlvType)
	}
	tlvLen := binary.BigEndian.Uint16(data[3:5])
	if tlvLen != 2 {
		return false, fmt.Errorf("eap: неверная TLV Length %d", tlvLen)
	}
	val := binary.BigEndian.Uint16(data[5:7])
	return val == 1, nil
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
