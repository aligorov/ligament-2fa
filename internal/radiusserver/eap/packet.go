// Package eap — кодеки EAP (RFC 3748) и EAP-TTLS (RFC 5281): разбор и
// сборка пакетов, флаги/фрагментация TTLS и phase-2 AVP внутреннего PAP.
// Чистые функции без состояния: сессии и TLS-мост живут в пакете
// radiusserver (eapsession.go), сюда не тянутся ни БД, ни сеть.
package eap

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Code — коды EAP-пакетов (RFC 3748 §4.1).
type Code byte

const (
	CodeRequest  Code = 1 // Request (сервер → клиент)
	CodeResponse Code = 2 // Response (клиент → сервер)
	CodeSuccess  Code = 3 // Success
	CodeFailure  Code = 4 // Failure
)

// Type — тип данных Request/Response (первый байт Data, RFC 3748 §5).
type Type byte

const (
	TypeIdentity     Type = 1  // Identity
	TypeNotification Type = 2  // Notification (в обмене не участвует)
	TypeNak          Type = 3  // Nak: клиент не поддерживает предложенный метод
	TypeTTLS         Type = 21 // EAP-TTLS (RFC 5281)
	TypePEAP         Type = 25 // PEAPv0 (Protected EAP, [MS-PEAP])
	TypeMSCHAPv2     Type = 26 // EAP-MSCHAPv2 (RFC 2759)
	TypeTLV          Type = 33 // EAP-TLV / Result TLV ([MS-PEAP])
)

// headerLen — размер заголовка EAP: Code(1) + Identifier(1) + Length(2).
const headerLen = 4

// Packet — разобранный EAP-пакет. Data — тип-специфичные данные; для
// Request/Response первый байт Data — Type; Success/Failure идут без Data.
type Packet struct {
	Code Code
	ID   byte
	Data []byte
}

// Type возвращает тип Request/Response-данных (0, если данных нет).
func (p *Packet) Type() Type {
	if len(p.Data) == 0 {
		return 0
	}
	return Type(p.Data[0])
}

// IdentityData возвращает payload Identity (без байта типа); имеет смысл
// только при Type == TypeIdentity.
func (p *Packet) IdentityData() []byte {
	if len(p.Data) < 2 {
		return nil
	}
	return p.Data[1:]
}

// Parse разбирает EAP-пакет из собранных EAP-Message атрибутов запроса.
// Поле Length — источник правды: хвост сверх него отбрасывается.
func Parse(b []byte) (*Packet, error) {
	if len(b) < headerLen {
		return nil, errors.New("eap: пакет короче заголовка")
	}
	length := int(binary.BigEndian.Uint16(b[2:4]))
	if length < headerLen {
		return nil, fmt.Errorf("eap: некорректная длина пакета %d", length)
	}
	if length > len(b) {
		return nil, fmt.Errorf("eap: заявлено %d байт, получено %d", length, len(b))
	}
	data := make([]byte, length-headerLen)
	copy(data, b[headerLen:length])
	return &Packet{Code: Code(b[0]), ID: b[1], Data: data}, nil
}

// Build собирает EAP-пакет в wire-формат.
func Build(code Code, id byte, data []byte) []byte {
	b := make([]byte, headerLen+len(data))
	b[0] = byte(code)
	b[1] = id
	binary.BigEndian.PutUint16(b[2:4], uint16(headerLen+len(data)))
	copy(b[headerLen:], data)
	return b
}

// BuildIdentity — Request/Response с типом Identity.
func BuildIdentity(code Code, id byte, identity string) []byte {
	data := make([]byte, 1+len(identity))
	data[0] = byte(TypeIdentity)
	copy(data[1:], identity)
	return Build(code, id, data)
}

// BuildResult — Success/Failure (без данных).
func BuildResult(code Code, id byte) []byte { return Build(code, id, nil) }
