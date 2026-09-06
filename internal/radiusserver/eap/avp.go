// Phase-2 AVP EAP-TTLS (RFC 5281 §10.2): внутри TLS-туннеля клиент
// присылает AVP-блок с учётными данными. Поддержан внутренний PAP:
// User-Name(1) + User-Password(2) открытым текстом внутри туннеля.
package eap

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Коды phase-2 AVP (RADIUS-атрибуты в туннеле).
const (
	AVPUserName     uint32 = 1 // User-Name (строка)
	AVPUserPassword uint32 = 2 // User-Password (plaintext внутри туннеля)
)

// AVP: code u32 + flags u32 + length u32 (включая заголовок) + данные.
// Флаг Mandatory (M=0x40) обязателен для понимаемых AVP; неизвестные AVP
// парсер пропускает (либерально: строгий reject по M-неизвестным оставляем
// на будущее — реальные supplicant'ы шлют только понятный набор).
const (
	avpHeaderLen     = 12
	avpFlagMandatory = 0x40
)

// InnerPAP — учётные данные внутреннего PAP из phase-2 AVP.
type InnerPAP struct {
	UserName     string
	UserPassword string
}

// Complete — оба поля на месте (внутренний PAP возможен только целиком).
func (p *InnerPAP) Complete() bool { return p.UserName != "" && p.UserPassword != "" }

// BuildAVP кодирует один AVP с флагом Mandatory.
func BuildAVP(code uint32, data []byte) []byte {
	b := make([]byte, avpHeaderLen+len(data))
	binary.BigEndian.PutUint32(b[0:4], code)
	binary.BigEndian.PutUint32(b[4:8], avpFlagMandatory)
	binary.BigEndian.PutUint32(b[8:12], uint32(avpHeaderLen+len(data)))
	copy(b[avpHeaderLen:], data)
	return b
}

// BuildInnerPAP — AVP-блок phase-2 для внутреннего PAP (клиентская и
// тестовая сторона; сервер только разбирает).
func BuildInnerPAP(username, password string) []byte {
	out := BuildAVP(AVPUserName, []byte(username))
	return append(out, BuildAVP(AVPUserPassword, []byte(password))...)
}

// ParseAVPs разбирает AVP-блок: неизвестные AVP пропускаются, User-Name(1)
// и User-Password(2) извлекаются (при повторах побеждает последнее).
func ParseAVPs(b []byte) (*InnerPAP, error) {
	p := &InnerPAP{}
	for len(b) > 0 {
		if len(b) < avpHeaderLen {
			return nil, errors.New("eap: AVP-заголовок обрезан")
		}
		code := binary.BigEndian.Uint32(b[0:4])
		length := int(binary.BigEndian.Uint32(b[8:12]))
		if length < avpHeaderLen || length > len(b) {
			return nil, fmt.Errorf("eap: некорректная длина AVP %d (в блоке %d)", length, len(b))
		}
		switch code {
		case AVPUserName:
			p.UserName = string(b[avpHeaderLen:length])
		case AVPUserPassword:
			p.UserPassword = string(b[avpHeaderLen:length])
		}
		b = b[length:]
	}
	return p, nil
}
