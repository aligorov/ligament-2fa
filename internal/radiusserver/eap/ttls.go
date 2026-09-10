// EAP-TTLS (RFC 5281): флаги, фрагментация отправки и сборка входящих
// фрагментов. Один TTLS-фрагмент переносится одним EAP-пакетом и одним
// Access-Challenge; поток байтов TLS режется/склеивается прозрачно для
// crypto/tls.
package eap

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Флаги EAP-TTLS (RFC 5281 §9.2).
const (
	TTLSFlagLength byte = 0x80 // L — присутствует 4-байтовое поле полной длины
	TTLSFlagMore   byte = 0x40 // M — будет продолжение (фрагмент)
	TTLSFlagStart  byte = 0x20 // S — начало TLS-обмена
)

// MaxFragment — максимальный payload одного TTLS-сообщения при
// фрагментации отправки: ServerHello+Certificate не влезают в один
// EAP-пакет, поток режется по этому размеру; каждый фрагмент — отдельный
// Access-Challenge, клиент подтверждает пустым EAP-Response/TTLS.
const MaxFragment = 1000

// MaxReassembly — потолок буфера сборки ВХОДЯЩИХ фрагментов (анти-DoS,
// АГЕНТ 5 аудита): цепочка с флагом M и без конца не должна копить память
// бесконечно (1024 сессии × неограниченный буфер = memory exhaustion).
// Легитимному TLS-handshake и phase-2 AVP 64 KiB хватает с запасом.
const MaxReassembly = 64 * 1024

// TTLS — разобранные TTLS-данные EAP-пакета: [21, flags, (len4)?, payload].
type TTLS struct {
	Flags       byte
	DeclaredLen int // полная длина сообщения, если задан флаг L; иначе -1
	Payload     []byte
}

// Start — флаг S (начало обмена).
func (t *TTLS) Start() bool { return t.Flags&TTLSFlagStart != 0 }

// More — флаг M (фрагмент, будет продолжение).
func (t *TTLS) More() bool { return t.Flags&TTLSFlagMore != 0 }

// LengthPresent — флаг L (заявлена полная длина).
func (t *TTLS) LengthPresent() bool { return t.Flags&TTLSFlagLength != 0 }

// ParseTTLS разбирает Data EAP-пакета типа TTLS.
func ParseTTLS(data []byte) (*TTLS, error) {
	if len(data) < 2 {
		return nil, errors.New("eap: TTLS-данные короче заголовка")
	}
	if Type(data[0]) != TypeTTLS {
		return nil, fmt.Errorf("eap: тип данных %d не TTLS", data[0])
	}
	t := &TTLS{Flags: data[1], DeclaredLen: -1}
	off := 2
	if t.LengthPresent() {
		if len(data) < off+4 {
			return nil, errors.New("eap: TTLS: обрезано поле длины L")
		}
		t.DeclaredLen = int(binary.BigEndian.Uint32(data[off : off+4]))
		off += 4
	}
	t.Payload = data[off:]
	return t, nil
}

// BuildTTLS — EAP-пакет Request/Response TTLS с флагами и payload;
// declared >= 0 автоматически добавляет флаг L и поле полной длины.
func BuildTTLS(code Code, id byte, flags byte, declared int, payload []byte) []byte {
	size := 2 + len(payload)
	if declared >= 0 {
		flags |= TTLSFlagLength
		size += 4
	}
	data := make([]byte, size)
	data[0] = byte(TypeTTLS)
	data[1] = flags
	off := 2
	if declared >= 0 {
		binary.BigEndian.PutUint32(data[off:off+4], uint32(declared))
		off += 4
	}
	copy(data[off:], payload)
	return Build(code, id, data)
}

// FragmentTTLS режет payload на цепочку TTLS-сообщений (полные EAP-пакеты
// заданного кода/идентификатора): первый фрагмент несёт L с полной длиной,
// все кроме последнего — флаг M; получатель подтверждает каждый фрагмент
// пустым ответом. Пустой payload даёт одно пустое сообщение без флагов.
func FragmentTTLS(code Code, id byte, payload []byte) [][]byte {
	if len(payload) == 0 {
		return [][]byte{BuildTTLS(code, id, 0, -1, nil)}
	}
	var frags [][]byte
	for off := 0; off < len(payload); {
		end := off + MaxFragment
		if end > len(payload) {
			end = len(payload)
		}
		var flags byte
		if off == 0 {
			flags |= TTLSFlagLength
		}
		if end < len(payload) {
			flags |= TTLSFlagMore
		}
		frags = append(frags, BuildTTLS(code, id, flags, len(payload), payload[off:end]))
		off = end
	}
	return frags
}

// Assembler — сборка входящих TTLS-фрагментов (M-цепочек) в один payload.
type Assembler struct {
	buf      []byte
	declared int
	inFlight bool
}

// Add добавляет сообщение TTLS и возвращает собранный payload с done=true,
// когда цепочка завершена (фрагмент без M). Флаг S начинает новую цепочку
// (незавершённая теряется — ретрансмит старта или resumption); phase-2
// данные приходят БЕЗ S и тоже начинают цепочку (RFC 5281: S только в
// первом сообщении handshake-фазы). Ошибки: порванная заявленная длина и
// превышение MaxReassembly (буфер сбрасывается, сессию пусть прибьёт
// вызывающий код по ошибке).
func (a *Assembler) Add(t *TTLS) ([]byte, bool, error) {
	// Заявленная длина сверх капа — отказ сразу, не копим заведомый мусор.
	if t.DeclaredLen > MaxReassembly {
		return nil, false, fmt.Errorf("eap: TTLS: заявленная длина %d превышает лимит сборки %d",
			t.DeclaredLen, MaxReassembly)
	}
	if t.Start() {
		a.buf = nil
		a.declared = t.DeclaredLen
		a.inFlight = true
	}
	if !a.inFlight {
		if len(t.Payload) == 0 {
			// Пустой ACK клиента — не фрагмент, вызывающий код решает сам.
			return nil, false, nil
		}
		a.inFlight = true
		// Начало цепочки без S (phase-2 данные): длина — из L, иначе не
		// проверяется (нулевое значение поля не должно выглядеть как L=0).
		a.declared = t.DeclaredLen
	}
	a.buf = append(a.buf, t.Payload...)
	if len(a.buf) > MaxReassembly {
		// DoS-гейт: бесконечная цепочка M-фрагментов — сброс сборщика.
		a.buf, a.declared, a.inFlight = nil, -1, false
		return nil, false, fmt.Errorf("eap: TTLS: буфер сборки превысил %d байт", MaxReassembly)
	}
	if t.More() {
		return nil, false, nil
	}
	full, decl := a.buf, a.declared
	a.buf, a.declared, a.inFlight = nil, -1, false
	if decl >= 0 && len(full) != decl {
		return nil, false, fmt.Errorf("eap: TTLS: собрано %d байт, заявлено %d", len(full), decl)
	}
	return full, true, nil
}

// InFlight — собирается ли сейчас фрагментированное сообщение.
func (a *Assembler) InFlight() bool { return a.inFlight }
