// PEAPv0 ([MS-PEAP]): флаги, фрагментация отправки и разбор сообщений.
// Внешняя оболочка TLS аналогична EAP-TTLS, но тип EAP равен 25 (TypePEAP),
// а младшие 3 бита флагов содержат версию (для PEAPv0 — 0).
package eap

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Флаги PEAP ([MS-PEAP] §2.2.1.1).
const (
	PEAPFlagLength byte = 0x80 // L — присутствует 4-байтовое поле полной длины
	PEAPFlagMore   byte = 0x40 // M — будет продолжение (фрагмент)
	PEAPFlagStart  byte = 0x20 // S — начало TLS-обмена
	PEAPVersion0   byte = 0x00 // версия 0
)

// PEAP — разобранные PEAP-данные EAP-пакета: [25, flags, (len4)?, payload].
type PEAP struct {
	Flags       byte
	Version     byte
	DeclaredLen int // полная длина сообщения, если задан флаг L; иначе -1
	Payload     []byte
}

// Start — флаг S (начало обмена).
func (p *PEAP) Start() bool { return p.Flags&PEAPFlagStart != 0 }

// More — флаг M (фрагмент, будет продолжение).
func (p *PEAP) More() bool { return p.Flags&PEAPFlagMore != 0 }

// LengthPresent — флаг L (заявлена полная длина).
func (p *PEAP) LengthPresent() bool { return p.Flags&PEAPFlagLength != 0 }

// ParsePEAP разбирает Data EAP-пакета типа PEAP (25).
func ParsePEAP(data []byte) (*PEAP, error) {
	if len(data) < 2 {
		return nil, errors.New("eap: PEAP-данные короче заголовка")
	}
	if Type(data[0]) != TypePEAP {
		return nil, fmt.Errorf("eap: тип данных %d не PEAP", data[0])
	}
	flags := data[1]
	p := &PEAP{
		Flags:       flags & 0xF8,
		Version:     flags & 0x07,
		DeclaredLen: -1,
	}
	off := 2
	if p.LengthPresent() {
		if len(data) < off+4 {
			return nil, errors.New("eap: PEAP: обрезано поле длины L")
		}
		p.DeclaredLen = int(binary.BigEndian.Uint32(data[off : off+4]))
		off += 4
	}
	p.Payload = data[off:]
	return p, nil
}

// BuildPEAP — EAP-пакет Request/Response PEAP с флагами и payload;
// declared >= 0 автоматически добавляет флаг L и поле полной длины.
func BuildPEAP(code Code, id byte, flags byte, declared int, payload []byte) []byte {
	size := 2 + len(payload)
	if declared >= 0 {
		flags |= PEAPFlagLength
		size += 4
	}
	data := make([]byte, size)
	data[0] = byte(TypePEAP)
	data[1] = flags | PEAPVersion0
	off := 2
	if declared >= 0 {
		binary.BigEndian.PutUint32(data[off:off+4], uint32(declared))
		off += 4
	}
	copy(data[off:], payload)
	return Build(code, id, data)
}

// FragmentPEAP режет payload на цепочку PEAP-сообщений: первый фрагмент
// несёт L с полной длиной, все кроме последнего — флаг M.
func FragmentPEAP(code Code, id byte, payload []byte) [][]byte {
	if len(payload) == 0 {
		return [][]byte{BuildPEAP(code, id, 0, -1, nil)}
	}
	var frags [][]byte
	for off := 0; off < len(payload); {
		end := off + MaxFragment
		if end > len(payload) {
			end = len(payload)
		}
		var flags byte
		if off == 0 {
			flags |= PEAPFlagLength
		}
		if end < len(payload) {
			flags |= PEAPFlagMore
		}
		frags = append(frags, BuildPEAP(code, id, flags, len(payload), payload[off:end]))
		off = end
	}
	return frags
}

// AddPEAP добавляет сообщение PEAP в Assembler (поведение аналогично TTLS).
func (a *Assembler) AddPEAP(p *PEAP) ([]byte, bool, error) {
	return a.Add(&TTLS{
		Flags:       p.Flags,
		DeclaredLen: p.DeclaredLen,
		Payload:     p.Payload,
	})
}
