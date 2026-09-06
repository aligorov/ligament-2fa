// Данные страниц web-UI: типизированные структуры для каждого шаблона.
// Все структуры встраивают BaseData (макет: заголовок, пользователь,
// флеш-сообщения, CSRF). Заполнением занимается HTTP-слой (T14).
package web

import (
	"github.com/google/uuid"

	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
)

// BaseData — общие данные макета base.gohtml. Username пуст на /login —
// тогда приложение не показывает боковое меню и кнопку выхода.
type BaseData struct {
	Title    string
	Username string // текущий пользователь (пусто до входа)
	IsAdmin  bool
	// Nav — идентификатор активного пункта бокового меню: "me", "totp",
	// "backup", "telegram", "passkeys", "devices", "admin-users",
	// "admin-audit", "admin-challenges", "admin-settings"; пусто для
	// страниц без меню (login, error).
	Nav      string
	CSRF     string // CSRF-токен сессии; пусто для анонимных форм
	Flash    string // флеш-успех (после редиректа)
	FlashErr string // флеш-ошибка (после редиректа)
}

// LoginData — страница /login: одна форма имя+пароль+код (решение о шаге
// 2FA принимает сервер), чекбокс доверия устройству.
type LoginData struct {
	BaseData
	Err      string // ошибка прошлого входа (не флеш — рендерится в 200/401)
	Prefill  string // подстановка username после неудачной попытки
	NeedCode bool   // подсказка: сервер ждёт именно код 2FA
}

// MeProfileData — /me: контакты, prefer_channels, смена пароля + сводка
// статусов каналов со ссылками на их страницы.
type MeProfileData struct {
	BaseData
	User            store.User
	TOTPConfirmed   bool
	TelegramLinked  bool
	BackupRemaining int // неиспользованные резервные коды
	PasskeyCount    int
}

// MeTOTPData — /me/totp. Три состояния: не привязан (кнопка enroll),
// выдан и ждёт подтверждения (QR + otpauth + форма confirm), подтверждён
// (кнопка отвязки с кодом).
type MeTOTPData struct {
	BaseData
	Confirmed  bool
	OtpauthURL string // непусто, когда секрет выдан, но не подтверждён
}

// MeBackupData — /me/backup: регенерация с кодом; новые коды показываются
// ровно один раз.
type MeBackupData struct {
	BaseData
	Generated bool
	Codes     []string // показ один раз после регенерации
	Remaining int      // неиспользованных кодов осталось
}

// MeTelegramData — /me/telegram: link_code для отправки боту либо
// статус привязки и отвязка.
type MeTelegramData struct {
	BaseData
	Linked   bool
	ChatID   *int64
	LinkCode string // непусто после POST /me/telegram/link
	// NeedCode — у пользователя есть второй фактор: выдача кода привязки
	// требует кода подтверждения (SEC-002).
	NeedCode bool
}

// MePasskeysData — /me/passkeys: список credential и форма добавления
// (WebAuthn-церемония — webauthn.js, форма — graceful fallback).
type MePasskeysData struct {
	BaseData
	Creds []store.WACred
	// Handle/RegName/OptionsJSON — непусты, когда сервер начал регистрацию
	// (POST /me/webauthn/credentials): страница несёт их в data-атрибутах
	// #passkey-pending, webauthn.js проводит церемонию и завершает её через
	// JSON API (T14).
	Handle      string
	RegName     string
	OptionsJSON string
}

// MeDevicesData — /me/devices: доверенные устройства, отзыв по одному.
type MeDevicesData struct {
	BaseData
	Devices []store.Device
}

// AdminUsersData — /admin/users: таблица всех пользователей; Edit != nil —
// под таблицей форма редактирования конкретного пользователя, иначе форма
// создания. EditReplyJSON — radius_reply для textarea. BackupCodes непуст
// после сброса TOTP: новые резервные коды показываются один раз в теле
// ответа (nil — блок не рендерится).
type AdminUsersData struct {
	BaseData
	Users         []store.User
	Edit          *store.User
	EditReplyJSON string
	BackupCodes   []string // новые резервные коды (показ один раз)
}

// AdminAuditData — /admin/audit: последние записи журнала.
type AdminAuditData struct {
	BaseData
	Rows []store.AuditRow
}

// AdminChallengesData — /admin/challenges: активные challenge;
// Usernames превращает UserID в имя для отображения.
type AdminChallengesData struct {
	BaseData
	Challenges []store.Challenge
	Usernames  map[uuid.UUID]string
}

// SMSPresetChoice — пункт выбора пресета SMS-шлюза на странице настроек
// (select в карточке SMS). web не зависит от delivery: HTTP-слой
// собирает пункты из delivery.Presets(). ConfigJSON — конфиг пресета с
// пустыми кредами-заглушками в форме настроек sms.gateway; выбор пункта
// подставляет этот JSON в textarea sms.gateway (app.js).
type SMSPresetChoice struct {
	Name        string
	Title       string
	Description string // русское описание: креды, телефон, тест-режим, цена
	ConfigJSON  string // JSON GatewayConfig (snake_case, как sms.gateway)
}

// AdminSettingsData — /admin/settings: снимок настроек по секциям.
// Секретные значения НЕ входят: только *Set-флаги («•••• (задано)»);
// изменение — ввод нового значения в поле с placeholder.
// OneTimeValue непусто после регенерации секрета: новое значение
// показывается один раз в теле ответа (пусто — блок не рендерится).
type AdminSettingsData struct {
	BaseData
	S                *settings.T
	RadiusSecretSet  bool
	SMTPPasswordSet  bool
	TGBotTokenSet    bool
	LDAPPasswordSet  bool // задан ли ldap.bind_password
	SMSGatewayJSON   string            // сырой JSON sms.gateway для textarea
	SMSPresetsJSON   string            // сырой JSON sms.presets для textarea
	SMSPresetChoices []SMSPresetChoice // пресеты шлюзов для select (заполняют textarea через JS)
	ReplyAttrsJSON   string            // radius.reply_attributes для textarea
	LDAPAllowGroups  string            // ldap.allow_groups (JSON) для textarea
	LDAPRoleMap      string            // ldap.role_map (JSON) для textarea
	OneTimeValue     string            // новое значение секрета (показ один раз)
	OneTimeLabel     string            // ключ секрета (admin_token / radius.secret)
}

// ErrorData — страница ошибки (код + сообщение по-русски).
type ErrorData struct {
	BaseData
	Code    int
	Message string
}
