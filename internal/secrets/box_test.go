package secrets

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func mustKeyB64(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func TestNewBox(t *testing.T) {
	if _, err := NewBox(mustKeyB64(t)); err != nil {
		t.Fatalf("NewBox(valid key) error: %v", err)
	}
}

func TestNewBoxBadKey(t *testing.T) {
	short := base64.StdEncoding.EncodeToString(make([]byte, 31))
	long := base64.StdEncoding.EncodeToString(make([]byte, 33))
	cases := []string{
		"",
		short,
		long,
		"not base64 !!!",
	}
	for _, c := range cases {
		if _, err := NewBox(c); err == nil {
			t.Errorf("NewBox(%q) = nil error, want error", c)
		}
	}
}

func TestBoxRoundtrip(t *testing.T) {
	box, err := NewBox(mustKeyB64(t))
	if err != nil {
		t.Fatalf("NewBox: %v", err)
	}
	plaintexts := [][]byte{
		{},
		[]byte("x"),
		[]byte("correct horse battery staple"),
		bytes.Repeat([]byte{0xAB}, 4096),
	}
	for _, p := range plaintexts {
		c := box.Encrypt(p)
		got, err := box.Decrypt(c)
		if err != nil {
			t.Fatalf("Decrypt(len %d) error: %v", len(p), err)
		}
		if !bytes.Equal(got, p) {
			t.Fatalf("roundtrip mismatch: got %q, want %q", got, p)
		}
	}
}

func TestBoxTamper(t *testing.T) {
	box, err := NewBox(mustKeyB64(t))
	if err != nil {
		t.Fatalf("NewBox: %v", err)
	}
	c := box.Encrypt([]byte("secret payload"))

	for _, i := range []int{0, 12, len(c) - 1} { // nonce, body, tag
		tampered := bytes.Clone(c)
		tampered[i] ^= 0xFF
		if _, err := box.Decrypt(tampered); err == nil {
			t.Errorf("Decrypt(tampered byte %d) = nil error, want error", i)
		}
	}
}

func TestBoxWrongKey(t *testing.T) {
	box1, err := NewBox(mustKeyB64(t))
	if err != nil {
		t.Fatalf("NewBox: %v", err)
	}
	box2, err := NewBox(mustKeyB64(t))
	if err != nil {
		t.Fatalf("NewBox: %v", err)
	}
	c := box1.Encrypt([]byte("secret payload"))
	if _, err := box2.Decrypt(c); err == nil {
		t.Error("Decrypt with wrong key = nil error, want error")
	}
}

func TestBoxEncryptNonDeterministic(t *testing.T) {
	box, err := NewBox(mustKeyB64(t))
	if err != nil {
		t.Fatalf("NewBox: %v", err)
	}
	p := []byte("same plaintext")
	c1 := box.Encrypt(p)
	c2 := box.Encrypt(p)
	if bytes.Equal(c1, c2) {
		t.Error("two encryptions of the same plaintext are identical, want different nonces")
	}
	for _, c := range [][]byte{c1, c2} {
		got, err := box.Decrypt(c)
		if err != nil || !bytes.Equal(got, p) {
			t.Errorf("Decrypt = (%q, %v), want (%q, nil)", got, err, p)
		}
	}
}

func TestBoxDecryptShortInput(t *testing.T) {
	box, err := NewBox(mustKeyB64(t))
	if err != nil {
		t.Fatalf("NewBox: %v", err)
	}
	cases := [][]byte{
		nil,
		{},
		{1, 2, 3},
		bytes.Repeat([]byte{0x00}, 11),
	}
	for _, c := range cases {
		if _, err := box.Decrypt(c); err == nil {
			t.Errorf("Decrypt(len %d) = nil error, want error", len(c))
		}
	}
}

func TestBoxAADRoundtrip(t *testing.T) {
	box, err := NewBox(mustKeyB64(t))
	if err != nil {
		t.Fatalf("NewBox: %v", err)
	}
	aad := "users:42"
	p := []byte("totp secret")
	c := box.EncryptAAD(aad, p)

	got, err := box.DecryptAAD(aad, c)
	if err != nil {
		t.Fatalf("DecryptAAD(correct aad) error: %v", err)
	}
	if !bytes.Equal(got, p) {
		t.Fatalf("DecryptAAD = %q, want %q", got, p)
	}
}

func TestBoxAADMismatch(t *testing.T) {
	box, err := NewBox(mustKeyB64(t))
	if err != nil {
		t.Fatalf("NewBox: %v", err)
	}
	c := box.EncryptAAD("users:42", []byte("totp secret"))

	for _, wrong := range []string{"", "users:43", "USERS:42", "users:42 "} {
		if _, err := box.DecryptAAD(wrong, c); err == nil {
			t.Errorf("DecryptAAD(%q) = nil error, want error", wrong)
		}
	}
	// Данные, зашифрованные с AAD, не расшифровываются без AAD, и наоборот.
	if _, err := box.Decrypt(c); err == nil {
		t.Error("Decrypt(data sealed with AAD) = nil error, want error")
	}
	plain := box.Encrypt([]byte("totp secret"))
	if _, err := box.DecryptAAD("users:42", plain); err == nil {
		t.Error("DecryptAAD(data sealed without AAD) = nil error, want error")
	}
	if _, err := box.DecryptAAD("users:42", []byte{1}); err == nil {
		t.Error("DecryptAAD(short input) = nil error, want error")
	}
}

func TestNewMasterKeyB64(t *testing.T) {
	k1 := NewMasterKeyB64()
	k2 := NewMasterKeyB64()

	raw, err := base64.StdEncoding.Strict().DecodeString(k1)
	if err != nil {
		t.Fatalf("NewMasterKeyB64() not valid std base64: %v", err)
	}
	if len(raw) != 32 {
		t.Errorf("decoded master key len = %d, want 32", len(raw))
	}
	if k1 == k2 {
		t.Error("two master keys are identical, want different")
	}

	if _, err := NewBox(k1); err != nil {
		t.Errorf("NewBox(NewMasterKeyB64()) error: %v", err)
	}
}
