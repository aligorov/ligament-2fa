// ID-токены OIDC (JWT, RS256) и проверка PKCE. Подпись собирается вручную:
// header {alg,typ,kid} и клеймы — JSON в base64url, подпись — RSA
// PKCS#1 v1.5 по SHA-256 (стандартный RS256, внешний jwt-пакет не нужен).
package oidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aligorov/twofa/internal/store"
)

// idTokenTTL — срок жизни ID-токена (короткий: токен только для обмена,
// не для долгих сессий клиента).
const idTokenTTL = 5 * time.Minute

// defaultAMR — методы аутентификации по умолчанию: web-сессия Ligament
// всегда получена паролем + вторым фактором (или доверенным устройством);
// granular-метод сессия не хранит (см. internal/api startSession).
const defaultAMR = "pwd,mfa"

// SignIDToken подписывает клеймы ключом менеджера (RS256) и возвращает
// компактный JWT «header.payload.signature».
func (mgr *Manager) SignIDToken(claims map[string]any) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": mgr.kid})
	if err != nil {
		return "", fmt.Errorf("oidc: маршал заголовка JWT: %w", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("oidc: маршал клеймов JWT: %w", err)
	}
	signingInput := b64url(header) + "." + b64url(payload)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, mgr.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("oidc: подпись RS256: %w", err)
	}
	return signingInput + "." + b64url(sig), nil
}

// IDTokenClaims собирает клеймы ID-токена: обязательные (iss, sub, aud,
// exp, iat, auth_time, amr) и необязательные — nonce и профильные,
// ограниченные scope (profile → preferred_username/name/groups,
// email → email/email_verified).
func (mgr *Manager) IDTokenClaims(iss string, u *store.User, clientID, scope, nonce, amr string, authTime, now time.Time) map[string]any {
	claims := map[string]any{
		"iss":       iss,
		"sub":       u.ID.String(),
		"aud":       clientID,
		"exp":       now.Add(idTokenTTL).Unix(),
		"iat":       now.Unix(),
		"auth_time": authTime.Unix(),
		"amr":       SplitAMR(amr),
		"groups":    []string{u.Role},
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if HasScope(scope, "profile") {
		claims["preferred_username"] = u.Username
		claims["name"] = u.DisplayName
		if u.DisplayName == "" {
			claims["name"] = u.Username
		}
	}
	if HasScope(scope, "email") && u.Email != "" {
		// Контакты в Ligament подтверждаются кодом доставки — считаем
		// проверенными.
		claims["email"] = u.Email
		claims["email_verified"] = true
	}
	return claims
}

// SplitAMR разбирает хранимую строку методов («pwd,mfa») в массив клейма
// amr; пустая строка даёт стандартный набор [pwd, mfa].
func SplitAMR(amr string) []string {
	parts := strings.Split(amr, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return []string{"pwd", "mfa"}
	}
	return out
}

// HasScope сообщает, входит ли scope в запрошенную строку (через пробел).
func HasScope(scope, want string) bool {
	for _, s := range strings.Fields(scope) {
		if s == want {
			return true
		}
	}
	return false
}

// FilterScopes оставляет из запрошенной строки только поддерживаемые
// scope (openid, profile, email) — грант никогда не шире возможного.
func FilterScopes(scope string) string {
	supported := []string{"openid", "profile", "email"}
	var out []string
	for _, s := range strings.Fields(scope) {
		for _, sup := range supported {
			if s == sup {
				out = append(out, s)
				break
			}
		}
	}
	return strings.Join(out, " ")
}

// VerifyPKCE сверяет code_verifier с challenge кода. Метод S256:
// base64url(SHA-256(verifier)) == challenge; plain: точное совпадение.
// Код без challenge (PKCE не применялся) требует отсутствия verifier —
// лишний verifier так же ломает обмен, как и отсутствующий.
func VerifyPKCE(challenge, method, verifier string) bool {
	if challenge == "" {
		return verifier == ""
	}
	if verifier == "" {
		return false
	}
	switch method {
	case "S256":
		sum := sha256.Sum256([]byte(verifier))
		return subtle.ConstantTimeCompare([]byte(b64url(sum[:])), []byte(challenge)) == 1
	case "plain":
		return subtle.ConstantTimeCompare([]byte(verifier), []byte(challenge)) == 1
	}
	return false
}
