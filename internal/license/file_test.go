// Юнит-тесты формата license-файла: PEM-подобная обёртка, base64(payload)+
// "."+base64(sig), Ed25519-подпись по каноническим байtam payload, отказ на
// подделку/неизвестный kid, CRL-отзыв тем же форматом.
package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

// signTestKey — тестовая пара ключей, подменяющая trustedKeys.
func signTestKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

// withTestKeys подменяет доверенные ключи на свежесгенерированные и
// возвращает функцию восстановления.
func withTestKeys(t *testing.T, kid string) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv := signTestKey(t)
	SetTrustedKeys(map[string]ed25519.PublicKey{kid: pub})
	t.Cleanup(func() { resetTrustedKeys() })
	return pub, priv
}

// TestSignVerifyRoundtrip: подпись приватным ключом → ParseLicense тем же
// kid проверяется и возвращает payload.
func TestSignVerifyRoundtrip(t *testing.T) {
	_, priv := withTestKeys(t, "test-key-1")
	p := testPayload()
	blob, err := Sign(priv, p)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !strings.HasPrefix(blob, LicenseHeader) || !strings.HasSuffix(strings.TrimSpace(blob), LicenseFooter) {
		t.Fatalf("blob без PEM-обёртки: %q", blob)
	}
	got, err := ParseLicense(blob)
	if err != nil {
		t.Fatalf("ParseLicense: %v", err)
	}
	if got.LicID != p.LicID || got.Customer != p.Customer || got.Plan != p.Plan ||
		got.UserLimit != p.UserLimit || got.Kid != p.Kid {
		t.Fatalf("payload разошёлся: %+v", got)
	}
	if got.ExpiresAt == nil || !got.ExpiresAt.Equal(*p.ExpiresAt) {
		t.Fatalf("expires_at потерян: %+v", got.ExpiresAt)
	}
}

// TestParseLicensePerpetual: perpetual-лицензия без expires_at — nil.
func TestParseLicensePerpetual(t *testing.T) {
	_, priv := withTestKeys(t, "test-key-1")
	p := testPayload()
	p.Plan = PlanPerpetual
	p.ExpiresAt = nil
	blob, err := Sign(priv, p)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	got, err := ParseLicense(blob)
	if err != nil {
		t.Fatalf("ParseLicense: %v", err)
	}
	if got.ExpiresAt != nil {
		t.Fatalf("perpetual: expires_at должен быть nil, есть %v", got.ExpiresAt)
	}
}

// TestParseLicenseTampered: подделка payload или подписи → ErrBadSignature.
func TestParseLicenseTampered(t *testing.T) {
	_, priv := withTestKeys(t, "test-key-1")
	blob, err := Sign(priv, testPayload())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Подмена поля customer в payload.
	i := strings.Index(blob, ".")
	tampered := blob[:i]                                            // base64(payload)
	tampered = strings.Replace(tampered, "Um9tYXNo", "Um9tYXNr", 1) // битые байты
	if tampered == blob[:i] {
		// Кодировка не совпала — просто перевыпустим blob с другим customer.
		p := testPayload()
		p.Customer = "ООО Хакер"
		other, err := Sign(priv, p)
		if err != nil {
			t.Fatalf("Sign other: %v", err)
		}
		// payload от other + sig от blob.
		j := strings.Index(other, ".")
		tampered = other[:j] + blob[i:]
	} else {
		tampered += blob[i:]
	}
	if _, err := ParseLicense(tampered); err == nil {
		t.Fatal("подделанный payload принялcя")
	} else if err != ErrBadSignature {
		t.Fatalf("ошибка подделки = %v, хочу ErrBadSignature", err)
	}

	// Подмена подписи (регистр первого символа base64-sig).
	j := strings.LastIndex(blob, ".")
	sigB64 := blob[j+1 : len(blob)-len(footerLine)]
	first := sigB64[0]
	var flipped byte
	if first >= 'a' && first <= 'z' {
		flipped = first - ('a' - 'A')
	} else {
		flipped = first + ('a' - 'A')
	}
	bad := blob[:j+1] + string(flipped) + sigB64[1:] + footerLine
	if _, err := ParseLicense(bad); err != ErrBadSignature {
		t.Fatalf("ошибка подмены sig = %v, хочу ErrBadSignature", err)
	}
}

// TestParseLicenseUnknownKid: подпись валидна, но kid не зашит → ErrUnknownKid.
func TestParseLicenseUnknownKid(t *testing.T) {
	_, priv := withTestKeys(t, "test-key-1")
	p := testPayload()
	p.Kid = "unknown-kid"
	blob, err := Sign(priv, p)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := ParseLicense(blob); err != ErrUnknownKid {
		t.Fatalf("ошибка unknown kid = %v, хочу ErrUnknownKid", err)
	}
}

// TestParseLicenseMalformed: мусор вместо PEM → ErrMalformed.
func TestParseLicenseMalformed(t *testing.T) {
	for _, bad := range []string{
		"",
		"garbage",
		LicenseHeader + "\nAAAA\n" + LicenseFooter,
		LicenseHeader + "\n" + LicenseFooter,
		"-----BEGIN OTHER-----\nAAA.BBB\n-----END OTHER-----",
	} {
		if _, err := ParseLicense(bad); err != ErrMalformed {
			t.Errorf("ParseLicense(%q) ошибка = %v, хочу ErrMalformed", bad, err)
		}
	}
}

// TestParseLicenseWhitespace: обёртка с \r\n и пустыми строками вокруг —
// tolerated (вставка из буфера).
func TestParseLicenseWhitespace(t *testing.T) {
	_, priv := withTestKeys(t, "test-key-1")
	blob, err := Sign(priv, testPayload())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	padded := "\n  " + strings.ReplaceAll(blob, "\n", "\r\n") + "  \n\n"
	if _, err := ParseLicense(padded); err != nil {
		t.Fatalf("ParseLicense с CRLF/пробелами: %v", err)
	}
}

// TestRevocationRoundtrip: CRL-блоб подписывается и разбирается тем же
// форматом; отзыв чужой подписью не проходит.
func TestRevocationRoundtrip(t *testing.T) {
	_, priv := withTestKeys(t, "test-key-1")
	rev := Revocation{
		LicID:     "11111111-2222-3333-4444-555555555555",
		RevokedAt: time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC),
		Kid:       "test-key-1",
	}
	blob, err := SignRevocation(priv, rev)
	if err != nil {
		t.Fatalf("SignRevocation: %v", err)
	}
	if !strings.HasPrefix(blob, RevocationHeader) {
		t.Fatalf("CRL без обёртки: %q", blob)
	}
	got, err := ParseRevocation(blob)
	if err != nil {
		t.Fatalf("ParseRevocation: %v", err)
	}
	if got.LicID != rev.LicID || !got.RevokedAt.Equal(rev.RevokedAt) {
		t.Fatalf("revocation разошёлся: %+v", got)
	}

	// Подпись другим ключом → bad signature.
	_, other := signTestKey(t)
	bad, err := SignRevocation(other, rev)
	if err != nil {
		t.Fatalf("SignRevocation other: %v", err)
	}
	if _, err := ParseRevocation(bad); err != ErrBadSignature {
		t.Fatalf("CRL чужой подписью: %v, хочу ErrBadSignature", err)
	}

	// Мусор → malformed.
	if _, err := ParseRevocation("nope"); err != ErrMalformed {
		t.Fatalf("CRL мусор: %v, хочу ErrMalformed", err)
	}
}
