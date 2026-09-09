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
	AppPush      Channel = "app_push"
	WebAuthn     Channel = "webauthn"
)
