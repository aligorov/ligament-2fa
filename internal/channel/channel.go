// Package channel описывает каналы второго фактора. Leaf-пакет без
// зависимостей — на него ссылаются store, settings, delivery и auth.
package channel

type Channel string

const (
	TOTP         Channel = "totp"
	Email        Channel = "email"
	SMS          Channel = "sms"
	Telegram     Channel = "telegram"
	TelegramPush Channel = "telegram_push"
	WebAuthn     Channel = "webauthn"
)

// IsCodeChannel — каналы доставки кодов/подтверждений (webauthn — церемония, не канал кода).
func (c Channel) IsCodeChannel() bool {
	switch c {
	case Email, SMS, Telegram, TOTP:
		return true
	}
	return false
}
