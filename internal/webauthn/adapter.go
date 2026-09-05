// Адаптер store.User к интерфейсу go-webauthn.User.
package webauthn

import (
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/aligorov/twofa/internal/store"
)

// waUser адаптирует store.User к gowebauthn.User. WebAuthnID (user handle)
// — стабильный случайный users.webauthn_id, гарантируемый ceremonyUser;
// имя и отображаемое имя — username.
type waUser struct {
	u     *store.User
	creds []gowebauthn.Credential
}

// WebAuthnID возвращает user handle (≤64 байт по спеке, см. ceremonyUser).
func (a *waUser) WebAuthnID() []byte { return a.u.WebAuthnID }

// WebAuthnName — имя учётной записи (username).
func (a *waUser) WebAuthnName() string { return a.u.Username }

// WebAuthnDisplayName — отображаемое имя (username).
func (a *waUser) WebAuthnDisplayName() string { return a.u.Username }

// WebAuthnCredentials возвращает копию ключей пользователя, чтобы
// библиотека не могла мутировать внутренний срез адаптера.
func (a *waUser) WebAuthnCredentials() []gowebauthn.Credential {
	out := make([]gowebauthn.Credential, len(a.creds))
	copy(out, a.creds)
	return out
}
