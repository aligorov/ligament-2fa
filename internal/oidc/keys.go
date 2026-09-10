// Package oidc — OpenID Connect Provider: внешние приложения (relying
// party) направляют пользователей на вход в Ligament (первый фактор +
// второй фактор web-сессии) и получают подписанный ID-токен (RS256).
// Поддержана authorization code flow с PKCE (S256/plain), discovery и
// JWKS; refresh-токенов и implicit-флоу нет (v1).
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"sync"

	"github.com/aligorov/twofa/internal/secrets"
	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
	"github.com/aligorov/twofa/internal/web"
)

// rsaKeyBits — размер ключа подписи ID-токенов.
const rsaKeyBits = 2048

// keyPair — одна пара ключей подписи OIDC: идентификатор kid и приватный
// ключ в PEM. Приватный ключ — секрет: хранится только в settings.
type keyPair struct {
	KID        string `json:"kid"`
	PrivatePEM string `json:"private_pem"`
}

// keySet — значение настройки oidc.keys. Previous зарезервировано под
// ротацию (v1 всегда null: ключ не меняется, JWKS отдаёт один ключ).
type keySet struct {
	Current  *keyPair `json:"current"`
	Previous *keyPair `json:"previous"`
}

// jwk — один ключ формата JWKS (RFC 7517); n и e — base64url без паддинга.
type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// Manager — провайдер OIDC: ключ подписи (создаётся при первом старте и
// сохраняется в настройках), зависимости store/settings/renderer. После
// сборки иммутабелен — ключ не мутируется, снимок настроек читается на
// каждый запрос (дёшево). Исключение — лимитер /oidc/token: создаётся
// лениво (sync.Once), чтобы Manager, собранный литералом в тестах, работал
// без него.
type Manager struct {
	st   *store.Store
	m    *settings.M
	rend *web.Renderer

	notifier LoginNotifier

	ads   func(*http.Request) web.AdsData
	brand func(*http.Request) web.BrandData

	key *rsa.PrivateKey
	kid string

	rlOnce sync.Once
	rl     *tokenLimiter
}

// LoginNotifier интерфейс отправки уведомлений о входе.
type LoginNotifier interface {
	NotifyLoginSuccess(ctx context.Context, username, method, ip, ua string)
}

// SetNotifier подключает обработчик уведомлений о входе.
func (mgr *Manager) SetNotifier(n LoginNotifier) { mgr.notifier = n }

// SetAds подключает решатель показа рекламы РСЯ / direct.
func (mgr *Manager) SetAds(f func(*http.Request) web.AdsData) { mgr.ads = f }

// SetBrand подключает решатель белого лейбла.
func (mgr *Manager) SetBrand(f func(*http.Request) web.BrandData) { mgr.brand = f }

// NewManager собирает провайдер OIDC: читает ключ подписи из настройки
// oidc.keys, при её отсутствии (или битом значении) генерирует новую пару
// RSA-2048 и записывает через settings.Put (идемпотентно: при
// конкурентном старте двух процессов ключ уже в БД — перечитывается
// снимком внутри Put).
func NewManager(ctx context.Context, st *store.Store, m *settings.M, rend *web.Renderer) (*Manager, error) {
	mgr := &Manager{st: st, m: m, rend: rend}
	ks, perr := parseKeySet(m.Get().OIDCKeys)
	if perr != nil {
		// Битое значение не должно хоронить сервер: перегенерируем.
		slog.Error("oidc: ключ oidc.keys не разбирается — генерирую новый", "error", perr)
	}
	if ks != nil {
		if lerr := mgr.loadKey(ks.Current); lerr == nil {
			return mgr, nil
		} else {
			slog.Error("oidc: приватный ключ oidc.keys не читается — генерирую новый", "error", lerr)
		}
	}
	if err := mgr.generateAndStore(ctx); err != nil {
		return nil, err
	}
	return mgr, nil
}

// loadKey разбирает PEM приватного ключа и вычисляет kid.
func (mgr *Manager) loadKey(p *keyPair) error {
	if p == nil || p.PrivatePEM == "" {
		return errors.New("пустая пара ключей")
	}
	block, _ := pem.Decode([]byte(p.PrivatePEM))
	if block == nil {
		return errors.New("PEM-блок не найден")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("разбор приватного ключа: %w", err)
	}
	mgr.key = key
	mgr.kid = KeyID(&key.PublicKey)
	if p.KID != "" && p.KID != mgr.kid {
		slog.Warn("oidc: kid в настройках не совпадает с вычисленным — использую вычисленный",
			"stored", p.KID, "computed", mgr.kid)
	}
	return nil
}

// generateAndStore создаёт пару RSA-2048, вычисляет kid и сохраняет
// keyset в настройку oidc.keys.
func (mgr *Manager) generateAndStore(ctx context.Context) error {
	key, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return fmt.Errorf("oidc: генерация RSA-%d: %w", rsaKeyBits, err)
	}
	pemB := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	ks := keySet{Current: &keyPair{KID: KeyID(&key.PublicKey), PrivatePEM: string(pemB)}}
	raw, err := json.Marshal(ks)
	if err != nil {
		return fmt.Errorf("oidc: маршал oidc.keys: %w", err)
	}
	if err := mgr.m.Put(ctx, "oidc.keys", raw); err != nil {
		return fmt.Errorf("oidc: запись oidc.keys: %w", err)
	}
	mgr.key = key
	mgr.kid = ks.Current.KID
	slog.Info("oidc: сгенерирован ключ подписи ID-токенов", "kid", mgr.kid)
	return nil
}

// parseKeySet разбирает сырое значение oidc.keys; nil/пустое значение —
// ключ ещё не создан (nil, nil).
func parseKeySet(raw json.RawMessage) (*keySet, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var ks keySet
	if err := json.Unmarshal(raw, &ks); err != nil {
		return nil, fmt.Errorf("разбор oidc.keys: %w", err)
	}
	if ks.Current == nil {
		return nil, errors.New("oidc.keys без current")
	}
	return &ks, nil
}

// KeyID — идентификатор ключа: hex(SHA-256 публичного DER)[:16].
func KeyID(pub *rsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		// Невозможно для rsa.PublicKey — защитная ветка.
		panic(fmt.Sprintf("oidc: MarshalPKIXPublicKey: %v", err))
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])[:16]
}

// JWKS — публичные ключи проверки подписи (стандартный формат RFC 7517;
// base64url без паддинга, big-endian модуль и экспонента).
func (mgr *Manager) JWKS() map[string]any {
	return map[string]any{
		"keys": []jwk{{
			Kty: "RSA",
			Use: "sig",
			Kid: mgr.kid,
			Alg: "RS256",
			N:   b64url(mgr.key.N.Bytes()),
			E:   b64url(big.NewInt(int64(mgr.key.E)).Bytes()),
		}},
	}
}

// ---- секреты клиентских приложений ----

// secretSaltLen — энтропия соли хеша client_secret (байт до base64url).
const secretSaltLen = 16

// NewClientID генерирует публичный идентификатор клиента (не секрет).
func NewClientID() string { return "mfa_" + secrets.RandomToken(8) }

// NewClientSecret генерирует секрет конфиденциального клиента; показывается
// админу ровно один раз, в БД хранится только хеш.
func NewClientSecret() string { return secrets.RandomToken(32) }

// HashClientSecret хеширует секрет клиента форматом «salt$hash»:
// salt — base64url(16 байт), hash — base64url(SHA-256(salt||secret)).
// Перебор по словарю неактуален (секреты случайные 32 байта), соль
// защищает от радужных таблиц при утечке БД.
func HashClientSecret(secret string) string {
	salt := secrets.RandomToken(secretSaltLen)
	return salt + "$" + b64url(secrets.SHA256(salt+secret))
}

// VerifyClientSecret сверяет секрет с хранимым «salt$hash» в постоянном
// времени (crypto/subtle): сравниваются хеши — время не зависит от длины
// совпавшего префикса секрета.
func VerifyClientSecret(stored, secret string) bool {
	for i := 0; i < len(stored); i++ {
		if stored[i] != '$' {
			continue
		}
		salt, want := stored[:i], stored[i+1:]
		got := b64url(secrets.SHA256(salt + secret))
		return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
	}
	return false
}

// b64url — base64url без паддинга (формат JWT/JWKS).
func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
