// Данные страниц web-UI: типизированные структуры для каждого шаблона.
// Все структуры встраивают BaseData (макет: заголовок, пользователь,
// флеш-сообщения, CSRF). Заполнением занимается HTTP-слой (T14).
package web

import (
	"github.com/google/uuid"

	"github.com/aligorov/twofa/internal/license"
	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
)

// BaseData — общие данные макета base.gohtml. Username пуст на /login —
// тогда приложение не показывает боковое меню и кнопку выхода.
// AdsData — параметры рекламы РСЯ: Show ненулевой только когда лицензия
// не платная и админ включил блоки; каждое поле — ID блока из
// partner.yandex.ru (пусто → место не рендерится).
type AdsData struct {
	Show       bool
	Provider   string // rsya | direct
	LoginLeft  string // rsya: ID блоков
	LoginRight string
	Sidebar    string
	// direct: одна ссылка на все слоты (Monetag/Adsterra/PropellerAds —
	// работает на любом домене клиента без модерации площадки).
	DirectURL   string
	DirectLabel string
	DirectImage string
}

// BrandData — белый лейбл (только платная лицензия): пустые поля =
// стандартный бренд Ligament.
type BrandData struct {
	Name        string
	Mark        string
	Logo        string
	Description string
}

type BaseData struct {
	Ads      AdsData
	Brand    BrandData
	Title    string
	Username string // текущий пользователь (пусто до входа)
	IsAdmin  bool
	// Nav — идентификатор активного пункта бокового меню: "me", "totp",
	// "backup", "telegram", "passkeys", "devices", "admin-users",
	// "admin-audit", "admin-challenges", "admin-settings",
	// "admin-license"; пусто для страниц без меню (login, error).
	Nav      string
	CSRF     string // CSRF-токен сессии; пусто для анонимных форм
	Flash    string // флеш-успех (после редиректа)
	FlashErr string // флеш-ошибка (после редиректа)
	// LicenseWarnings — баннер лицензии для админа (лимит, истечение
	// подписки/демо, окно обновлений); пуст для не-админа.
	LicenseWarnings []string
}

// LoginData — страница /login: одна форма имя+пароль+код (решение о шаге
// 2FA принимает сервер), чекбокс доверия устройству. Next — адрес
// возврата после входа (hidden-поле; например, /oidc/authorize?...).
type LoginData struct {
	BaseData
	Err      string // ошибка прошлого входа (не флеш — рендерится в 200/401)
	Prefill  string // подстановка username после неудачной попытки
	NeedCode bool   // подсказка: сервер ждёт именно код 2FA
	Next     string // куда вернуться после успешного входа (только локальные пути)
	Info     string // пояснение о доставке кода (email/sms/telegram/cooldown)
	CanEmail   bool   // доступна ли отправка на Email
	CanSMS     bool   // доступна ли отправка по SMS по подтверждению пользователя
	CanPasskey bool   // привязаны ли у пользователя passkeys (Touch ID, Windows Hello, YubiKey)
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

// AdminFirewallData — /admin/firewall: списки allow/deny, активные банки
// и настройки fail2ban.
type AdminFirewallData struct {
	BaseData
	Allow []store.IPList
	Deny  []store.IPList
	Bans  []store.IPBan
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
	LDAPPasswordSet  bool              // задан ли ldap.bind_password
	SMSGatewayJSON   string            // сырой JSON sms.gateway для textarea
	SMSPresetsJSON   string            // сырой JSON sms.presets для textarea
	SMSPresetChoices []SMSPresetChoice // пресеты шлюзов для select (заполняют textarea через JS)
	ReplyAttrsJSON     string            // radius.reply_attributes для textarea
	LDAPAllowGroups    string            // ldap.allow_groups (JSON) для textarea
	LDAPRoleMap        string            // ldap.role_map (JSON) для textarea
	LDAPGroupRadiusMap string            // ldap.group_radius_map (JSON) для textarea
	OneTimeValue       string            // новое значение секрета (показ один раз)
	OneTimeLabel       string            // ключ секрета (admin_token / radius.secret)
	CertCN             string
	CertIssuer         string
	CertNotAfter       string
	CertDaysLeft       int
	CertIsSelfSigned   bool
	CertIsACME         bool
	HasCert            bool
}

// ErrorData — страница ошибки (код + сообщение по-русски).
type ErrorData struct {
	BaseData
	Code    int
	Message string
}

// FormField — скрытое поле формы (проксирование параметров OIDC authorize
// через POST-подтверждение согласия).
type FormField struct {
	Key string
	Val string
}

// OIDCScopeInfo — структурированное описание одного scope OIDC для страницы согласия.
type OIDCScopeInfo struct {
	Scope       string
	Title       string
	Description string
	Icon        string
}

// OIDCConsentData — страница согласия /oidc/authorize: «Приложение X
// запрашивает вход». Форма POST /oidc/authorize/confirm несёт CSRF и все
// параметры authorize скрытыми полями.
type OIDCConsentData struct {
	BaseData
	ClientName      string
	ClientID        string
	ClientInitial   string
	RedirectURI     string
	RedirectHost    string
	UserDisplayName string
	UserEmail       string
	UserInitial     string
	Scopes          []string        // человекочитаемые описания запрошенных scope
	ScopeDetails    []OIDCScopeInfo // расширенные описания с иконками
	Fields          []FormField     // параметры authorize для скрытых полей формы
}

// AdminOIDCClientsData — /admin/oidc: клиентские приложения OIDC и форма
// создания. OneTimeClientID/OneTimeSecret непусты после создания: секрет
// показывается ровно один раз (хранится только хеш).
type AdminOIDCClientsData struct {
	BaseData
	Clients         []store.OIDCClient
	OneTimeClientID string // созданный client_id (показ один раз)
	OneTimeSecret   string // созданный client_secret (показ один раз)
}

// AdminLicenseData — /admin/license: статус-карточка лицензии и формы
// загрузки лицензии/CRL (report §3.7). Status — готовый к отображению
// перевод (LimitText/UpdatesUntil/ModeText), чтобы шаблон не считал дни.
type AdminLicenseData struct {
	BaseData
	Status       license.Status
	ModeText     string // человекочитаемый режим
	LimitText    string // "3/25" или "не ограничено"
	UpdatesUntil string // "01.09.2027" (пусто — не применимо)
}
