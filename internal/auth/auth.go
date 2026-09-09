// Package auth — ядро аутентификации 2FA-сервера: lifecycle челленджей
// (выдача кодов по предпочтительным каналам, cooldown, single-use),
// проверка кодов (TOTP с replay-защитой, резервные коды, коды доставки),
// разбиение «пароль+код» для RADIUS и push-подтверждение с удержанием
// запроса (push_wait, паттерн privacyIDEA).
package auth

import (
	"context"
	"errors"
	"sync"

	"github.com/google/uuid"

	"github.com/aligorov/twofa/internal/channel"
	"github.com/aligorov/twofa/internal/secrets"
	"github.com/aligorov/twofa/internal/store"
)

// Ошибки ядра аутентификации — точечные sentinel-значения: API-слой (T9/T10)
// отображает их в 4xx-ответы (ErrCooldown → 429, ErrLocked → 423 и т.п.).
var (
	// ErrNoChannel — ни один канал из prefer_channels не привязан/не зарегистрирован.
	ErrNoChannel = errors.New("auth: нет доступного канала доставки")
	// ErrCooldown — повторная отправка кода раньше policy.resend_cooldown.
	ErrCooldown = errors.New("auth: повторная отправка раньше cooldown")
	// ErrChallengeClosed — челлендж просрочен, использован или попытки исчерпаны.
	ErrChallengeClosed = errors.New("auth: челлендж просрочен или уже использован")
	// ErrLocked — вход заблокирован после серии неудач (fail-счётчик).
	ErrLocked = errors.New("auth: вход заблокирован после серии неудач")
	// ErrBadCode — код не опознан (неверен или переиспользован).
	ErrBadCode = errors.New("auth: неверный код")
	// ErrBadCredentials — неверный логин или пароль (единый ответ,
	// против перечисления пользователей).
	ErrBadCredentials = errors.New("auth: неверный логин или пароль")
)

// AADTOTP — additional authenticated data для шифрования TOTP-секрета:
// шифротекст привязан к таблице и имени пользователя, поэтому секрет
// невозможно расшифровать в контексте другой учётной записи. Экспортируется
// для повторного использования энроллментом TOTP (T11).
func AADTOTP(username string) string { return "twofa:storage:totp_secrets:" + username }

// PasswordVerifier — проверка первого фактора. Абстракция над локальной
// argon2id-проверкой (NewLocalVerifier); при необходимости (WebAuthn-first
// вход и т.п.) подставляется другая реализация.
type PasswordVerifier interface {
	Verify(ctx context.Context, username, password string) (*store.User, error)
}

// LocalVerifier — проверка пароля по локальной БД (argon2id, secrets).
type LocalVerifier struct {
	st *store.Store
}

// NewLocalVerifier возвращает PasswordVerifier поверх store.
func NewLocalVerifier(st *store.Store) *LocalVerifier { return &LocalVerifier{st: st} }

var _ PasswordVerifier = (*LocalVerifier)(nil)

// dummyHashStore — фиксированный argon2id-хеш для ветки «пользователь не
// найден»: Verify обязан тратить на отсутствующего пользователя ту же
// работу argon2, что и на неверный пароль существующего, иначе время ответа
// служит оракулом перечисления учётных записей. Генерируется один раз на
// процесс (sync.Once).
var dummyHashStore struct {
	once sync.Once
	val  string
}

// dummyArgon2Hash лениво создаёт и возвращает хеш-приманку (формат
// secrets.HashPassword; пароль-источник фиксирован и публично безопасен).
func dummyArgon2Hash() string {
	dummyHashStore.once.Do(func() {
		dummyHashStore.val = secrets.HashPassword("twofa-dummy-password")
	})
	return dummyHashStore.val
}

// burnDummyVerify выполняет полный argon2-цикл по хешу-приманке — та же
// цена, что у secrets.VerifyPassword для реального хеша. Результат
// заведомо ложен и отбрасывается. Пакетная переменная (а не функция) —
// тест подменяет её счётчиком, проверяя вызов в ветке «нет пользователя».
var burnDummyVerify = func(password string) {
	_ = secrets.VerifyPassword(dummyArgon2Hash(), password)
}

// BurnDummyVerify — экспортированная обёртка burnDummyVerify: единый argon2-
// burn для веток «пользователь не найден» за пределами LocalVerifier
// (Core.VerifyPasswordAndCode / Core.RADIUSAuth), чтобы все пути входа
// отвечали одинаковой ценой и тайминг не раскрывал существование учётной
// записи.
func BurnDummyVerify(password string) { burnDummyVerify(password) }

// Verify возвращает пользователя при верном пароле. Отсутствующий
// пользователь → store.ErrNotFound (после полного argon2 по хешу-приманке —
// обе ветки стоят одинаково, тайминг не различим); неверный пароль или
// отключённый (enabled = false) пользователь → ErrBadCredentials — единый
// ответ, не раскрывающий причину.
func (v *LocalVerifier) Verify(ctx context.Context, username, password string) (*store.User, error) {
	u, err := v.st.UserByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Тайминг-оракул: отсутствующий пользователь отвечает argon2-ценой
			// неверного пароля, а не мгновенно.
			burnDummyVerify(password)
		}
		return nil, err
	}
	if !u.Enabled || !secrets.VerifyPassword(u.PasswordHash, password) {
		return nil, ErrBadCredentials
	}
	return u, nil
}

// PushNotifier — отправка Telegram push-подтверждения: сообщение с
// inline-кнопками «Подтвердить / Это не я» и деталями запроса (кто, IP,
// User-Agent). Реализация появится вместе с ботом (T8); nil в NewCore
// означает, что канал telegram_push недоступен и пропускается.
type PushNotifier interface {
	SendPush(ctx context.Context, chatID int64, who, ip, ua string, challengeID uuid.UUID) error
	SendNotification(ctx context.Context, chatID int64, text string) error
}

// AppPushNotifier — отправка push-подтверждения на мобильные и десктопные приложения пользователя.
type AppPushNotifier interface {
	SendAppPush(ctx context.Context, userID uuid.UUID, who, ip, ua, service, numberMatch string, challengeID uuid.UUID) error
}

// BackupChannel — псевдоканал в возвращаемом значении VerifyAnyCode:
// код опознан как резервный (backup-коды не входят в channel.Channel).
const BackupChannel channel.Channel = "backup"
