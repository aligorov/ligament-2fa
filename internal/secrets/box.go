package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// keyLen — размер ключа AES-256; nonceLen — стандартный размер nonce GCM.
const (
	keyLen   = 32
	nonceLen = 12
)

// Box — симметричный шифровальщик AES-256-GCM с фиксированным ключом.
// Шифротекст имеет вид: nonce (12 байт) || ciphertext || tag (16 байт).
type Box struct {
	gcm cipher.AEAD
}

// NewMasterKeyB64 возвращает свежий 32-байтовый ключ в base64 (std).
// Используется как мастер-ключ шифрования секретов; принимается NewBox.
func NewMasterKeyB64() string {
	key := make([]byte, keyLen)
	if _, err := rand.Read(key); err != nil {
		panic(fmt.Sprintf("secrets: rand.Read: %v", err))
	}
	return base64.StdEncoding.EncodeToString(key)
}

// NewBox создаёт Box из ключа в base64; ключ должен раскодироваться
// ровно в 32 байта (AES-256), иначе возвращается ошибка.
func NewBox(keyB64 string) (*Box, error) {
	key, err := base64.StdEncoding.Strict().DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf("secrets: ключ не является base64: %w", err)
	}
	if len(key) != keyLen {
		return nil, fmt.Errorf("secrets: ключ %d байт, нужно %d", len(key), keyLen)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secrets: aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secrets: cipher.NewGCM: %w", err)
	}
	return &Box{gcm: gcm}, nil
}

// Encrypt шифрует p: 12 случайных байт nonce || AES-256-GCM (без AAD).
func (b *Box) Encrypt(p []byte) []byte {
	return b.seal(nil, p)
}

// Decrypt расшифровывает данные из Encrypt; повреждённый шифротекст,
// данные под другим ключом или короче nonce дают ошибку.
func (b *Box) Decrypt(c []byte) ([]byte, error) {
	return b.open(nil, c)
}

// EncryptAAD шифрует p с additional data aad — привязкой к контексту
// (например, "таблица:пользователь"). Изменение aad делает расшифровку
// невозможной, сам aad в шифротекст не входит.
func (b *Box) EncryptAAD(aad string, p []byte) []byte {
	return b.seal([]byte(aad), p)
}

// DecryptAAD расшифровывает данные из EncryptAAD; ошибочный aad
// (как и повреждённый шифротекст) даёт ошибку.
func (b *Box) DecryptAAD(aad string, c []byte) ([]byte, error) {
	return b.open([]byte(aad), c)
}

func (b *Box) seal(aad, p []byte) []byte {
	out := make([]byte, nonceLen, nonceLen+len(p)+b.gcm.Overhead())
	if _, err := rand.Read(out); err != nil {
		panic(fmt.Sprintf("secrets: rand.Read: %v", err))
	}
	return b.gcm.Seal(out, out[:nonceLen], p, aad)
}

func (b *Box) open(aad, c []byte) ([]byte, error) {
	if len(c) < nonceLen {
		return nil, fmt.Errorf("secrets: шифротекст короче nonce (%d байт)", len(c))
	}
	p, err := b.gcm.Open(nil, c[:nonceLen], c[nonceLen:], aad)
	if err != nil {
		return nil, fmt.Errorf("secrets: расшифровка не удалась: %w", err)
	}
	return p, nil
}
