// Package secrets содержит криптографические примитивы приложения:
// хеширование паролей (argon2id), симметричное шифрование (AES-256-GCM)
// и генерацию случайных кодов и токенов.
package secrets

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Параметры argon2id (согласованы со спецификацией, RFC 9106 вторая
// рекомендованная конфигурация с уменьшенным числом итераций):
// 64 MiB памяти, 1 итерация, 4 потока.
const (
	argonTime    = 1
	argonMemory  = 1 << 26 // 64 MiB
	argonThreads = 4
	argonSaltLen = 16
	argonKeyLen  = 32
)

// HashPassword возвращает хеш пароля в стандартном формате argon2id:
//
//	$argon2id$v=19$m=65536,t=1,p=4$<b64salt>$<b64hash>
//
// Соль (16 байт) и ключ (32 байта) кодируются base64.RawStdEncoding,
// как в других реализациях argon2 (например alexedwards/argon2id).
func HashPassword(pw string) string {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		panic(fmt.Sprintf("secrets: rand.Read: %v", err))
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
}

// VerifyPassword сверяет пароль с хешем в формате HashPassword.
// Сравнение ключей выполняется за постоянное время; любой
// некорректный формат хеша даёт false без паники.
func VerifyPassword(hash, pw string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	if parts[2] != fmt.Sprintf("v=%d", argon2.Version) {
		return false
	}

	var m, tc, p uint32
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &tc, &p); err != nil {
		return false
	}
	if m != argonMemory || tc != argonTime || p != argonThreads {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) != argonSaltLen {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) != argonKeyLen {
		return false
	}

	got := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return subtle.ConstantTimeCompare(got, want) == 1
}
