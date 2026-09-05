package secrets

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestHashPasswordFormat(t *testing.T) {
	h := HashPassword("hunter2")

	parts := strings.Split(h, "$")
	// "" "argon2id" "v=19" "m=65536,t=1,p=4" "<salt>" "<hash>"
	if len(parts) != 6 {
		t.Fatalf("expected 6 $-separated parts, got %d: %q", len(parts), h)
	}
	if parts[1] != "argon2id" {
		t.Errorf("algo = %q, want argon2id", parts[1])
	}
	if parts[2] != "v=19" {
		t.Errorf("version = %q, want v=19", parts[2])
	}
	if parts[3] != "m=65536,t=1,p=4" {
		t.Errorf("params = %q, want m=65536,t=1,p=4", parts[3])
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		t.Fatalf("salt not valid RawStdEncoding base64: %v", err)
	}
	if len(salt) != 16 {
		t.Errorf("salt len = %d, want 16", len(salt))
	}

	digest, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		t.Fatalf("hash not valid RawStdEncoding base64: %v", err)
	}
	if len(digest) != 32 {
		t.Errorf("hash len = %d, want 32", len(digest))
	}
}

func TestHashPasswordRandomSalt(t *testing.T) {
	h1 := HashPassword("same-password")
	h2 := HashPassword("same-password")
	if h1 == h2 {
		t.Error("two hashes of the same password must differ (random salt)")
	}
}

func TestVerifyPasswordOK(t *testing.T) {
	h := HashPassword("correct horse battery staple")
	if !VerifyPassword(h, "correct horse battery staple") {
		t.Error("VerifyPassword(correct) = false, want true")
	}
}

func TestVerifyPasswordWrong(t *testing.T) {
	h := HashPassword("right")
	if VerifyPassword(h, "wrong") {
		t.Error("VerifyPassword(wrong) = true, want false")
	}
	if VerifyPassword(h, "") {
		t.Error("VerifyPassword(empty) = true, want false")
	}
}

func TestVerifyPasswordMalformed(t *testing.T) {
	cases := []string{
		"",
		"garbage",
		"not-a-hash-at-all",
		"$argon2id$v=19$m=65536,t=1,p=4$too$few$parts",
		"$argon2id$v=19$m=65536,t=1,p=4$",
		"$argon2id$v=19$m=65536,t=1,p=4$onlysalt",
		// валидный b64, но неверные длины: AAAA = 3 байта
		"$argon2id$v=19$m=65536,t=1,p=4$AAAA$AAAA",
		// сломанный base64
		"$argon2id$v=19$m=65536,t=1,p=4$****$AAAA",
		"$argon2id$v=19$m=65536,t=1,p=4$AAAA$****",
		// неверная версия
		"$argon2id$v=18$m=65536,t=1,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		// неверные параметры
		"$argon2id$v=19$m=1024,t=1,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
	for _, c := range cases {
		if VerifyPassword(c, "whatever") {
			t.Errorf("VerifyPassword(%q) = true, want false", c)
		}
	}
}
