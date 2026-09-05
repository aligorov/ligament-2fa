package secrets

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"testing"
)

func TestGenDigits(t *testing.T) {
	for _, n := range []int{1, 4, 6, 8} {
		for range 50 {
			s := GenDigits(n)
			if len(s) != n {
				t.Fatalf("GenDigits(%d) len = %d (%q), want %d", n, len(s), s, n)
			}
			for _, r := range s {
				if r < '0' || r > '9' {
					t.Fatalf("GenDigits(%d) = %q, символ %q не цифра", n, s, r)
				}
			}
		}
	}
}

func TestSHA256(t *testing.T) {
	const wantHex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" // SHA256("abc")
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatalf("hex.DecodeString: %v", err)
	}
	if got := SHA256("abc"); !bytes.Equal(got, want) {
		t.Errorf("SHA256(\"abc\") = %x, want %s", got, wantHex)
	}
	if SHA256("") == nil {
		t.Error("SHA256(\"\") = nil, want non-nil")
	}
}

var backupCodeRe = regexp.MustCompile(`^[A-Z2-9]{5}-[A-Z2-9]{5}$`)

func TestGenBackupCodes(t *testing.T) {
	for range 10 {
		codes := GenBackupCodes()
		if len(codes) != 10 {
			t.Fatalf("GenBackupCodes() len = %d, want 10", len(codes))
		}
		seen := make(map[string]struct{}, 10)
		for _, c := range codes {
			if !backupCodeRe.MatchString(c) {
				t.Fatalf("код %q не matches %s", c, backupCodeRe)
			}
			if _, dup := seen[c]; dup {
				t.Fatalf("дубликат кода %q в наборе", c)
			}
			seen[c] = struct{}{}
		}
	}
}

func TestRandomToken(t *testing.T) {
	for _, n := range []int{1, 16, 32} {
		tok := RandomToken(n)
		raw, err := base64.RawURLEncoding.Strict().DecodeString(tok)
		if err != nil {
			t.Fatalf("RandomToken(%d) = %q не base64url: %v", n, tok, err)
		}
		if len(raw) != n {
			t.Errorf("RandomToken(%d) декодируется в %d байт, want %d", n, len(raw), n)
		}
	}
	if RandomToken(32) == RandomToken(32) {
		t.Error("два вызова RandomToken дали одинаковый токен")
	}
}
