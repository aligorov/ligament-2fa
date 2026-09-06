// Юнит-тесты кодеков EAP/EAP-TTLS/AVP: без БД и сети, только байты.
package eap

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestPacketRoundtrip(t *testing.T) {
	b := BuildIdentity(CodeResponse, 7, "anonymous@example.com")
	p, err := Parse(b)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Code != CodeResponse || p.ID != 7 || p.Type() != TypeIdentity {
		t.Fatalf("разбор: code=%d id=%d type=%d", p.Code, p.ID, p.Type())
	}
	if string(p.IdentityData()) != "anonymous@example.com" {
		t.Fatalf("identity = %q", p.IdentityData())
	}
	if !bytes.Equal(Build(p.Code, p.ID, p.Data), b) {
		t.Fatal("повторная сборка не совпала с исходным пакетом")
	}
}

func TestParseValidatesLength(t *testing.T) {
	if _, err := Parse([]byte{1, 2, 3}); err == nil {
		t.Fatal("короче заголовка: ошибки нет")
	}
	// Length меньше заголовка.
	if _, err := Parse([]byte{2, 0, 0, 2, 0}); err == nil {
		t.Fatal("Length=2 не отвергнут")
	}
	// Length больше реальных данных.
	if _, err := Parse([]byte{2, 0, 0, 9, 1, 1}); err == nil {
		t.Fatal("Length=9 при 6 байтах не отвергнут")
	}
	// Хвост сверх Length отбрасывается.
	p, err := Parse([]byte{2, 0, 0, 6, 1, 'a', 0xFF, 0xFF})
	if err != nil {
		t.Fatalf("Parse с хвостом: %v", err)
	}
	if !bytes.Equal(p.Data, []byte{1, 'a'}) {
		t.Fatalf("Data = %v, хочу [1 a]", p.Data)
	}
}

func TestTTLSRoundtrip(t *testing.T) {
	payload := make([]byte, 40)
	rand.Read(payload)
	b := BuildTTLS(CodeRequest, 3, TTLSFlagStart, 12345, payload)
	p, err := Parse(b)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	tt, err := ParseTTLS(p.Data)
	if err != nil {
		t.Fatalf("ParseTTLS: %v", err)
	}
	if !tt.Start() || tt.DeclaredLen != 12345 || !bytes.Equal(tt.Payload, payload) {
		t.Fatalf("start=%v declared=%d payloadEqual=%v", tt.Start(), tt.DeclaredLen, bytes.Equal(tt.Payload, payload))
	}

	// Без L: declared не задаётся.
	b2 := BuildTTLS(CodeResponse, 4, TTLSFlagMore, -1, payload[:5])
	p2, err := Parse(b2)
	if err != nil {
		t.Fatalf("Parse(no-L): %v", err)
	}
	tt2, err := ParseTTLS(p2.Data)
	if err != nil {
		t.Fatalf("ParseTTLS(no-L): %v", err)
	}
	if tt2.LengthPresent() || tt2.DeclaredLen != -1 || !tt2.More() {
		t.Fatalf("lengthPresent=%v declared=%d more=%v", tt2.LengthPresent(), tt2.DeclaredLen, tt2.More())
	}
}

func TestParseTTLSErrors(t *testing.T) {
	if _, err := ParseTTLS([]byte{21}); err == nil {
		t.Fatal("TTLS короче заголовка принят")
	}
	if _, err := ParseTTLS([]byte{1, 0}); err == nil {
		t.Fatal("не-TTLS тип принят")
	}
	// L заявлен, но поле обрезано.
	if _, err := ParseTTLS([]byte{21, TTLSFlagLength, 0}); err == nil {
		t.Fatal("обрезанное поле L принято")
	}
}

func TestFragmentationRoundtrip(t *testing.T) {
	payload := make([]byte, 3*MaxFragment+137) // 3 полных фрагмента + хвост
	rand.Read(payload)

	frags := FragmentTTLS(CodeRequest, 9, payload)
	if len(frags) != 4 {
		t.Fatalf("фрагментов %d, хочу 4", len(frags))
	}

	// Сборка туда-обратно через Assembler.
	var asm Assembler
	var got []byte
	for i, raw := range frags {
		p, err := Parse(raw)
		if err != nil {
			t.Fatalf("Parse фрагмента %d: %v", i, err)
		}
		if p.Code != CodeRequest || p.ID != 9 || p.Type() != TypeTTLS {
			t.Fatalf("фрагмент %d: code=%d id=%d type=%d", i, p.Code, p.ID, p.Type())
		}
		tt, err := ParseTTLS(p.Data)
		if err != nil {
			t.Fatalf("ParseTTLS фрагмента %d: %v", i, err)
		}
		if i < len(frags)-1 && !tt.More() {
			t.Fatalf("фрагмент %d без M (не последний)", i)
		}
		if i == len(frags)-1 && tt.More() {
			t.Fatal("последний фрагмент с M")
		}
		full, done, err := asm.Add(tt)
		if err != nil {
			t.Fatalf("Add фрагмента %d: %v", i, err)
		}
		if i < len(frags)-1 {
			if done || full != nil {
				t.Fatalf("фрагмент %d: цепочка закрылась раньше времени", i)
			}
			continue
		}
		if !done {
			t.Fatal("последний фрагмент не завершил цепочку")
		}
		got = full
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("сборка не совпала: %d байт вместо %d", len(got), len(payload))
	}
}

func TestAssemblerErrors(t *testing.T) {
	// Пустой ACK вне цепочки — не фрагмент и не ошибка.
	var asm Assembler
	full, done, err := asm.Add(&TTLS{Flags: 0})
	if full != nil || done || err != nil {
		t.Fatalf("пустой ACK: full=%v done=%v err=%v", full, done, err)
	}

	// Порванная заявленная длина: первый фрагмент с L+M, завершение
	// с меньшим числом байт.
	var asm2 Assembler
	if _, _, err := asm2.Add(&TTLS{Flags: TTLSFlagStart | TTLSFlagLength | TTLSFlagMore, DeclaredLen: 10, Payload: make([]byte, 4)}); err != nil {
		t.Fatalf("S-фрагмент: %v", err)
	}
	_, _, err = asm2.Add(&TTLS{Flags: 0, Payload: make([]byte, 4)})
	if err == nil || asm2.InFlight() {
		t.Fatalf("несовпадение длины не поймано: err=%v", err)
	}

	// S посреди цепочки начинает новую (старая теряется).
	var asm3 Assembler
	if _, _, err := asm3.Add(&TTLS{Flags: TTLSFlagStart | TTLSFlagLength | TTLSFlagMore, DeclaredLen: 100, Payload: make([]byte, 4)}); err != nil {
		t.Fatalf("первый фрагмент: %v", err)
	}
	full, done, err = asm3.Add(&TTLS{Flags: TTLSFlagStart, DeclaredLen: -1, Payload: []byte{1, 2, 3}})
	if err != nil || !done || !bytes.Equal(full, []byte{1, 2, 3}) {
		t.Fatalf("S-перезапуск: full=%v done=%v err=%v", full, done, err)
	}
}

func TestAVPRoundtrip(t *testing.T) {
	// Чужие AVP вперемешку с User-Name/User-Password.
	block := BuildAVP(79, []byte("charge-uri\x00http://x")) // EAP-URI-Id? нет — просто неизвестный
	block = append(block, BuildAVP(AVPUserName, []byte("wifi-user"))...)
	block = append(block, BuildAVP(31, []byte("call-station-id 00:11:22"))...) // неизвестный
	block = append(block, BuildAVP(AVPUserPassword, []byte("hunter2pass043211"))...)

	p, err := ParseAVPs(block)
	if err != nil {
		t.Fatalf("ParseAVPs: %v", err)
	}
	if p.UserName != "wifi-user" || p.UserPassword != "hunter2pass043211" {
		t.Fatalf("user=%q pass=%q", p.UserName, p.UserPassword)
	}
	if !p.Complete() {
		t.Fatal("Complete() = false при обоих полях")
	}

	// BuildInnerPAP — обратим: разбор даёт те же учётные данные.
	built, err := ParseAVPs(BuildInnerPAP("wifi-user", "hunter2pass043211"))
	if err != nil {
		t.Fatalf("ParseAVPs(BuildInnerPAP): %v", err)
	}
	if built.UserName != "wifi-user" || built.UserPassword != "hunter2pass043211" {
		t.Fatalf("BuildInnerPAP обратим: user=%q pass=%q", built.UserName, built.UserPassword)
	}
}

func TestParseAVPsErrors(t *testing.T) {
	if _, err := ParseAVPs([]byte{0, 0}); err == nil {
		t.Fatal("обрезанный заголовок принят")
	}
	bad := BuildAVP(AVPUserName, []byte("x"))
	bad[11] = 200 // длина за пределами блока
	if _, err := ParseAVPs(bad); err == nil {
		t.Fatal("длина AVP за пределами блока принята")
	}
}
