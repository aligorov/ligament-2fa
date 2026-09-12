package eap

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// TestMSCHAPv2RFC2759Vector проверяет эталонные векторы из RFC 2759 Section 9:
// User: "User"
// Password: "clientPass"
// AuthChallenge: 5B 5D 7C 6E 67 58 62 73 76 7A 79 78 7C 7A 6E 76
// PeerChallenge: 64 50 75 75 62 64 64 63 75 6F 65 66 74 67 6C 75
// Expected NT-Response: 82 30 9E CD 8D 70 8B 5E BF A5 02 97 B6 12 36 37 62 80 62 EC 00 66 2F F8
// Expected AuthenticatorResponse: S=407A5589115FD0D6209F510FE9C0496667704280
func TestMSCHAPv2RFC2759Vector(t *testing.T) {
	userName := "User"
	password := "clientPass"

	authChal, _ := hex.DecodeString("5B5D7C7D7B3F2F3E3C2C602132262628")
	peerChal, _ := hex.DecodeString("21402324255E262A28295F2B3A337C7E")
	expectedChal, _ := hex.DecodeString("D02E4386BCE91226")
	expectedNTHash, _ := hex.DecodeString("44EBBA8D5312B8D611474411F56989AE")
	expectedNTResp, _ := hex.DecodeString("82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF")
	expectedAuthResp := "S=407A5589115FD0D6209F510FE9C04566932CDA56"

	ntHash := NTHash(password)
	if !bytes.Equal(ntHash, expectedNTHash) {
		t.Fatalf("NTHash: got %X, want %X", ntHash, expectedNTHash)
	}

	chal := ChallengeHash(peerChal, authChal, userName)
	if !bytes.Equal(chal, expectedChal) {
		t.Fatalf("ChallengeHash: got %X, want %X", chal, expectedChal)
	}

	resp := ChallengeResponse(chal, ntHash)
	if !bytes.Equal(resp[:], expectedNTResp) {
		t.Fatalf("ChallengeResponse: got %X, want %X", resp[:], expectedNTResp)
	}

	authResp := GenerateAuthenticatorResponse(ntHash, resp[:], peerChal, authChal, userName)
	if authResp != expectedAuthResp {
		t.Fatalf("AuthenticatorResponse: got %q, want %q", authResp, expectedAuthResp)
	}

	// Проверка через VerifyMSCHAPv2
	var mschapResp MSCHAPv2Response
	mschapResp.UserName = userName
	copy(mschapResp.PeerChallenge[:], peerChal)
	copy(mschapResp.NTResponse[:], resp[:])

	verifiedAuthResp, ok := VerifyMSCHAPv2(&mschapResp, authChal, ntHash)
	if !ok {
		t.Fatal("VerifyMSCHAPv2 вернул false для корректного ответа")
	}
	if verifiedAuthResp != expectedAuthResp {
		t.Fatalf("VerifyMSCHAPv2: got %q, want %q", verifiedAuthResp, expectedAuthResp)
	}
}

func TestResultTLV(t *testing.T) {
	req := BuildResultTLV(CodeRequest, 5, true)
	p, err := Parse(req)
	if err != nil {
		t.Fatalf("Parse Result TLV: %v", err)
	}
	if p.Type() != TypeTLV {
		t.Fatalf("Type = %d, want TypeTLV", p.Type())
	}
	ok, err := ParseResultTLV(p.Data)
	if err != nil || !ok {
		t.Fatalf("ParseResultTLV: ok=%v, err=%v", ok, err)
	}

	failReq := BuildResultTLV(CodeRequest, 6, false)
	pFail, err := Parse(failReq)
	if err != nil {
		t.Fatalf("Parse Result TLV: %v", err)
	}
	okFail, err := ParseResultTLV(pFail.Data)
	if err != nil || okFail {
		t.Fatalf("ParseResultTLV (fail): ok=%v, err=%v", okFail, err)
	}
}

func TestPEAPRoundtrip(t *testing.T) {
	payload := []byte("hello-peap-tls")
	pkt := BuildPEAP(CodeRequest, 10, PEAPFlagStart, len(payload), payload)
	p, err := Parse(pkt)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Type() != TypePEAP {
		t.Fatalf("Type = %d, want TypePEAP", p.Type())
	}
	peapPkt, err := ParsePEAP(p.Data)
	if err != nil {
		t.Fatalf("ParsePEAP: %v", err)
	}
	if !peapPkt.Start() {
		t.Fatal("PEAP flag Start не установлен")
	}
	if peapPkt.DeclaredLen != len(payload) {
		t.Fatalf("DeclaredLen = %d, want %d", peapPkt.DeclaredLen, len(payload))
	}
	if !bytes.Equal(peapPkt.Payload, payload) {
		t.Fatalf("Payload = %s, want %s", peapPkt.Payload, payload)
	}
}

// TestRFC3079KeyDerivation проверяет деривацию ключей по RFC 3079 Section 3.5.3.
func TestRFC3079KeyDerivation(t *testing.T) {
	ntHash, _ := hex.DecodeString("44EBBA8D5312B8D611474411F56989AE")
	ntResp, _ := hex.DecodeString("82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF")
	expectedMasterKey, _ := hex.DecodeString("FDECE3717A8C838CB388E527AE3CDD31")
	// SendStartKey128 (Client Send / Server Recv): magic3
	expectedSendStartKey, _ := hex.DecodeString("8B7CDC149B993A1BA118CB153F56DCCB")

	masterKey := GetMasterKey(ntHash, ntResp)
	if !bytes.Equal(masterKey, expectedMasterKey) {
		t.Fatalf("MasterKey = %X, want %X", masterKey, expectedMasterKey)
	}

	sendStartKey := GetAsymmetricStartKey(masterKey, true, true)
	if !bytes.Equal(sendStartKey, expectedSendStartKey) {
		t.Fatalf("SendStartKey = %X, want %X", sendStartKey, expectedSendStartKey)
	}

	isk := DerivePEAPISK(ntHash, ntResp)
	if len(isk) != 32 {
		t.Fatalf("ISK len = %d, want 32", len(isk))
	}

	tk := bytes.Repeat([]byte{0x42}, 40)
	ipmk, cmk := DerivePEAPCMK(tk, isk)
	if len(ipmk) != 40 || len(cmk) != 20 {
		t.Fatalf("DerivePEAPCMK: ipmk=%d, cmk=%d", len(ipmk), len(cmk))
	}

	csk := DerivePEAPCSK(ipmk)
	if len(csk) != 128 {
		t.Fatalf("DerivePEAPCSK: csk len = %d, want 128", len(csk))
	}
}

// TestCryptobindingTLV проверяет сборку и разбор Result TLV + Cryptobinding TLV.
func TestCryptobindingTLV(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x01}, 32)
	cmk := bytes.Repeat([]byte{0x02}, 20)

	pkt := BuildPEAPResultAndCryptoRequest(1, nonce, cmk)
	p, err := Parse(pkt)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Type() != TypeTLV {
		t.Fatalf("Type = %d, want TypeTLV", p.Type())
	}

	ok, err := ParseResultTLV(p.Data)
	if err != nil || !ok {
		t.Fatalf("ParseResultTLV: ok=%v, err=%v", ok, err)
	}

	// Проверяем, что Cryptobinding TLV имеет правильную структуру:
	// p.Data[0] = TypeTLV (33)
	// p.Data[1..6] = Result TLV (6 байт)
	// p.Data[7..66] = Cryptobinding TLV (60 байт)
	if len(p.Data) != 1+6+60 {
		t.Fatalf("len(p.Data) = %d, want %d", len(p.Data), 1+6+60)
	}
	cryptoTLV := p.Data[7:]
	tlvType := binary.BigEndian.Uint16(cryptoTLV[0:2])
	if tlvType != 12 {
		t.Fatalf("Cryptobinding TLV Type = %d, want 12", tlvType)
	}
	tlvLen := binary.BigEndian.Uint16(cryptoTLV[2:4])
	if tlvLen != 56 {
		t.Fatalf("Cryptobinding TLV Len = %d, want 56", tlvLen)
	}
}
