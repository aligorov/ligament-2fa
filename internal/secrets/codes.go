package secrets

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// backupAlphabet — алфавит резервных кодов без похожих символов
// (нет 0/O и 1/I): 31 символ.
const backupAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// backupCodesCount — число резервных кодов в наборе.
const backupCodesCount = 10

// GenDigits возвращает строку ровно из n случайных цифр (crypto/rand),
// ведущие нули разрешены. Байты 250..255 отбрасываются, чтобы исключить
// modulo-смещение при отображении 256 значений на 10 цифр.
func GenDigits(n int) string {
	buf := make([]byte, n+10)
	out := make([]byte, 0, n)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			panic(fmt.Sprintf("secrets: rand.Read: %v", err))
		}
		for _, b := range buf {
			if b >= 250 {
				continue
			}
			out = append(out, '0'+b%10)
			if len(out) == n {
				break
			}
		}
	}
	return string(out)
}

// SHA256 возвращает SHA-256 от строки.
func SHA256(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

// GenBackupCodes возвращает 10 уникальных кодов формата XXXXX-XXXXX
// из алфавита без 0/O/1/I.
func GenBackupCodes() []string {
	codes := make([]string, 0, backupCodesCount)
	seen := make(map[string]struct{}, backupCodesCount)
	for len(codes) < backupCodesCount {
		c := randomBackupCode()
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		codes = append(codes, c)
	}
	return codes
}

// randomBackupCode выбирает 10 символов алфавита rejection sampling'ом
// (256 % 31 != 0, поэтому байты 248..255 отбрасываются).
func randomBackupCode() string {
	buf := make([]byte, 16)
	chars := make([]byte, 0, 10)
	for len(chars) < 10 {
		if _, err := rand.Read(buf); err != nil {
			panic(fmt.Sprintf("secrets: rand.Read: %v", err))
		}
		for _, b := range buf {
			if b >= 248 {
				continue
			}
			chars = append(chars, backupAlphabet[int(b)%len(backupAlphabet)])
			if len(chars) == 10 {
				break
			}
		}
	}
	return string(chars[:5]) + "-" + string(chars[5:])
}

// RandomToken возвращает n случайных байт в base64url (без паддинга).
func RandomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("secrets: rand.Read: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
