// Package license — подсистема лицензирования Ligament: оффлайн
// подписанный license-файл (Ed25519, PEM-подобная обёртка), модель
// free/trial/licensed, CRL-отзыв и гейт обновлений по build-date.
// Модель утверждена в docs/reports/2026-09-06-licensing.md (§3-4).
package license

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// Тарифы (report §3.2).
const (
	PlanSubscription = "subscription" // X ₽/пользователь/год, expires_at ≤ 13 мес
	PlanPerpetual    = "perpetual"    // бессрочная, обновления до maintenance_expires
)

// Payload — содержимое лицензии. Подпись считается по каноническому JSON
// (см. Canonical): отсортированные ключи, без пробелов — стабильные байты
// независимо от порядка полей в исходном JSON.
type Payload struct {
	LicID    string `json:"lic_id"` // UUID — идентификатор для отзыва/реестра
	Customer string `json:"customer"`
	Plan     string `json:"plan"` // subscription | perpetual
	// UserLimit — лимит активных пользователей (0 — не ограничено).
	UserLimit int       `json:"user_limit"`
	IssuedAt  time.Time `json:"issued_at"`
	// ExpiresAt — только subscription; perpetual → null.
	ExpiresAt          *time.Time `json:"expires_at,omitempty"`
	MaintenanceExpires time.Time  `json:"maintenance_expires"`
	Features           []string   `json:"features,omitempty"`
	Kid                string     `json:"kid"` // ID ключа подписи (ротация)
	Notes              string     `json:"notes,omitempty"`
}

// Revocation — содержимое CRL-блоба: досрочный отзыв подписки (report §3.5).
type Revocation struct {
	LicID     string    `json:"lic_id"`
	RevokedAt time.Time `json:"revoked_at"`
	Kid       string    `json:"kid"`
}

// Canonical возвращает каноническое JSON-представление значения для подписи:
// маршал через map[string]any (encoding/json сортирует ключи карт) с
// json.Number — целые числа не искажаются форматом float. Пробелов нет.
func Canonical(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("license: маршал payload: %w", err)
	}
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("license: разбор payload для канонизации: %w", err)
	}
	out, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("license: канонический маршал: %w", err)
	}
	return out, nil
}

// Canonical — канонические байты лицензии (для подписи/проверки).
func (p Payload) Canonical() ([]byte, error) { return Canonical(p) }

// Canonical — канонические байты отзыва (для подписи/проверки).
func (r Revocation) Canonical() ([]byte, error) { return Canonical(r) }
