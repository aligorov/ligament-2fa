// Package settings — настройки 2FA-сервера в БД (таблица settings):
// дефолты, снапшоты для конкурентного чтения, точечная запись и
// маскировка секретов. delivery не импортируется: SMS-шлюз хранится
// как json.RawMessage и декодируется методом SMSGateway (зеркальный
// локальный тип), чтобы избежать цикла delivery -> settings.
package settings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aligorov/twofa/internal/channel"
	"github.com/aligorov/twofa/internal/store"
)

// maskValue — универсальная маска вместо значений секретов в Masked.
const maskValue = "••••"

// T — снимок настроек. Читается конкурентно HTTP-хендлерами и RADIUS-циклом,
// поэтому после создания трактуется как иммутабельный: обновление снимка
// всегда строит новый T (Manager.Reload), старый не мутируется.
// Default-шаблоны сообщений — один источник для дефолтов настроек
// (ключ messages), fallback-ов сендеров и тестов.
const (
	DefaultEmailBody    = "Ваш код подтверждения: {code}\n\nКод действителен {ttl}.\nЗапросили не вы — смените пароль: {domain}/me/password"
	DefaultSMSText      = "Код подтверждения: {code} (действ. {ttl})"
	DefaultTelegramCode = "🔑 Код подтверждения: {code}\nДействителен {ttl}. Никому не сообщайте код."
	DefaultTelegramPush = "🔑 Подтверждение входа\nПользователь: {username}\nIP: {ip}\nУстройство: {ua}\nВремя: {time}"
)

type T struct {
	Listen struct {
		HTTP       string
		RadiusAuth string
		RadiusAcct string
	}
	MasterKeyB64, AdminToken, RadiusSecret string

	// Server — публичные параметры инсталляции.
	Server struct {
		// Domain — базовый URL сервера (https://2fa.example.com, без
		// слэша на конце): подставляется в шаблоны сообщений {domain}.
		Domain string
	}

	// Branding — белый лейбл (ключ branding): применяется ТОЛЬКО при
	// активной платной лицензии (Licensed); free/trial видят Ligament.
	Branding struct {
		Name        string `json:"name"`        // название продукта
		Mark        string `json:"mark"`        // буква маркера (вместо «L»)
		Logo        string `json:"logo"`        // URL или data:URI логотипа
		Description string `json:"description"` // подпись на странице входа
	}

	// Ads — блоки рекламы РСЯ (ключ ads): показываются ТОЛЬКО когда
	// лицензия не платная (free/trial); ID блоков выдаёт partner.yandex.ru.
	Ads struct {
		Enabled bool
		// Provider: "rsya" — RTB-блоки РСЯ (площадка/домен модеруется),
		// "direct" — direct-link сеть (Monetag/Adsterra/PropellerAds):
		// одна ссылка работает на ЛЮБОМ домене без модерации площадки.
		Provider string
		Blocks   struct {
			LoginLeft  string `json:"login_left"`
			LoginRight string `json:"login_right"`
			Sidebar    string `json:"sidebar"`
		} `json:"blocks"`
		// MessageFooter — рекламная подпись email/Telegram-сообщений
		// ({url} — случайная ссылка пула); только free/trial.
		MessageFooter string `json:"message_footer"`
		Direct        struct {
			URL   string   `json:"url"`   // direct-ссылка (одна)
			URLs  []string `json:"urls"`  // пул ссылок: слот берёт случайную
			Label string   `json:"label"` // текст слота (пусто = «Реклама»)
			Image string   `json:"image"` // опц. картинка баннера (https URL)
		} `json:"direct"`
	}

	// Proxy — доверенные сети обратного прокси (ключ proxy): только с
	// этих адресов принимается X-Forwarded-For (реальные IP клиентов в
	// аудите/fail2ban); пусто = всегда RemoteAddr (заголовок игнорируется).
	Proxy struct {
		TrustedNetworks []string `json:"trusted_networks"`
	}

	// Fail2ban — автоблокировка IP по неудачам (ключ fail2ban);
	// чёрный список отклоняет всегда, белый не банится.
	Fail2ban struct {
		Enabled bool
		MaxFail int
		Window  time.Duration
		BanTime time.Duration
	}

	// Messages — шаблоны текстов сообщений (ключ messages):
	// плейсхолдеры {code} {ttl} {domain} {username} {ip} {ua} {time};
	// пустой шаблон = встроенный дефолт. Тема письма — smtp.subject.
	Messages struct {
		EmailBody    string `json:"email_body"`
		SMSText      string `json:"sms_text"`
		TelegramCode string `json:"telegram_code_text"`
		TelegramPush string `json:"telegram_push_text"`
	}

	Radius struct {
		CodeLengths     []int
		MaxFailPerUser  int
		FailWindow      time.Duration
		PushWait        time.Duration
		ReplyAttributes map[string]string
	}

	SMTP struct {
		Host     string
		Port     int
		StartTLS bool
		User     string
		Password string
		From     string
		Subject  string
		Timeout  time.Duration
	}

	// SMS — сырое JSON-значение ключа sms.gateway (delivery.GatewayConfig
	// из Task 6); декодируется методом SMSGateway.
	SMS json.RawMessage
	// SMSPresets — сырое JSON-значение ключа sms.presets.
	SMSPresets json.RawMessage

	TOTP struct {
		Issuer string
		Digits int
		Period int
		Skew   uint
	}

	// LDAP — конфигурация внешнего каталога LDAP/Active Directory
	// (ключ ldap): первый фактор проверяется bind-ом в каталоге,
	// атрибуты и группы синхронизируются в локального пользователя.
	LDAP LDAPSettings

	TG struct {
		BotToken string
	}

	// OIDCKeys — сырой JSON ключа подписи ID-токенов (ключ oidc.keys):
	// {"current":{"kid","private_pem"},"previous":{...}|null}. Генерируется
	// менеджером OIDC при первом старте; nil — ключ ещё не создан.
	OIDCKeys json.RawMessage

	WebAuthn struct {
		RPID   string
		RPName string
		// Origins — явный список origin (scheme://host[:port]); пусто =
		// выводить из RPID оба варианта схемы на стандартных портах.
		Origins []string
	}

	Policy struct {
		CodeTTL          time.Duration
		ResendCooldown   time.Duration
		PushCooldown     time.Duration
		TrustedDeviceTTL time.Duration
		SessionTTL       time.Duration
		FailWindow       time.Duration
		BanTime          time.Duration
		CodeLength       int
		MaxAttempts      int
		PushPerHour      int
		MaxFail          int
		DefaultPrefer    []channel.Channel
	}
}

// LDAPSettings — конфигурация внешнего каталога LDAP/Active Directory
// (ключ ldap): первый фактор проверяется bind-ом в каталоге, атрибуты и
// группы синхронизируются в локального пользователя. Именованный тип
// нужен пакету auth (LdapVerifier принимает значение снимка без доступа к T).
type LDAPSettings struct {
	Enabled      bool
	URL          string // ldap://host:389 или ldaps://host:636
	StartTLS     bool   // STARTTLS поверх ldap://
	BindDN       string // сервисная учётка для поиска (пустая — анонимный поиск)
	BindPassword string
	BaseDN       string
	UserFilter   string // {login} заменяется на экранированный логин
	GroupBaseDN  string // пусто — base_dn
	GroupFilter  string // {dn} заменяется на DN пользователя
	Attrs        LDAPAttrs
	AllowGroups  []string          // пусто — все найденные в каталоге
	RoleMap      map[string]string // DN или CN группы → роль (admin/user)
}

// LDAPAttrs — имена LDAP-атрибутов, из которых берутся контакты
// пользователя при синхронизации (ключ ldap.attrs).
type LDAPAttrs struct {
	Email       string
	Phone       string
	DisplayName string
}

// SMSGatewayConfig — локальное зеркало delivery.GatewayConfig (Task 6):
// settings не импортирует delivery (обратная зависимость).
type SMSGatewayConfig struct {
	Preset      string            `json:"preset"`
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
	ContentType string            `json:"content_type"`
	Success     SMSSuccessRule    `json:"success"`
}

// SMSSuccessRule — критерий успеха HTTP-запроса к шлюзу: выполнены все
// непустые условия (спека §8).
type SMSSuccessRule struct {
	HTTPStatus   int    `json:"http_status"`
	BodyContains string `json:"body_contains"`
	JSONPath     string `json:"json_path"`
	Equals       string `json:"equals"`
}

// SMSGateway декодирует T.SMS в типизированный конфиг шлюза; пустое
// значение даёт нулевой конфиг без ошибки.
func (t *T) SMSGateway() (SMSGatewayConfig, error) {
	var gw SMSGatewayConfig
	if len(t.SMS) == 0 {
		return gw, nil
	}
	if err := json.Unmarshal(t.SMS, &gw); err != nil {
		return gw, fmt.Errorf("settings: разбор sms.gateway: %w", err)
	}
	return gw, nil
}

// defaultT — дефолтный снимок; значения согласованы с defaults.go
// (проверяется тестом TestDefaultsConsistent).
func defaultT() *T {
	t := &T{}
	t.Listen.HTTP = ":8080"
	t.Listen.RadiusAuth = ":1812"
	t.Listen.RadiusAcct = ":1813"
	t.Ads.Enabled = false
	t.Ads.Direct.URLs = []string{}
	t.Proxy.TrustedNetworks = []string{}
	t.Fail2ban.Enabled = true
	t.Fail2ban.MaxFail = 10
	t.Fail2ban.Window = 5 * time.Minute
	t.Fail2ban.BanTime = 30 * time.Minute
	t.Messages.EmailBody = DefaultEmailBody
	t.Messages.SMSText = DefaultSMSText
	t.Messages.TelegramCode = DefaultTelegramCode
	t.Messages.TelegramPush = DefaultTelegramPush
	t.Radius.CodeLengths = []int{6, 8}
	t.Radius.MaxFailPerUser = 10
	t.Radius.FailWindow = 5 * time.Minute
	t.Radius.PushWait = 20 * time.Second
	t.Radius.ReplyAttributes = map[string]string{}
	t.TOTP.Issuer = "twofa"
	t.TOTP.Digits = 6
	t.TOTP.Period = 30
	t.TOTP.Skew = 1
	t.WebAuthn.RPName = "twofa"
	t.WebAuthn.Origins = []string{}
	t.LDAP.UserFilter = `(&(objectClass=user)(sAMAccountName={login}))`
	t.LDAP.GroupFilter = `(&(objectClass=group)(member={dn}))`
	t.LDAP.Attrs.Email = "mail"
	t.LDAP.Attrs.Phone = "telephoneNumber"
	t.LDAP.Attrs.DisplayName = "displayName"
	t.LDAP.AllowGroups = []string{}
	t.LDAP.RoleMap = map[string]string{}
	t.Policy.CodeTTL = 5 * time.Minute
	t.Policy.ResendCooldown = 60 * time.Second
	t.Policy.PushCooldown = 30 * time.Second
	t.Policy.TrustedDeviceTTL = 720 * time.Hour
	t.Policy.SessionTTL = 12 * time.Hour
	t.Policy.FailWindow = 5 * time.Minute
	t.Policy.BanTime = 15 * time.Minute
	t.Policy.CodeLength = 6
	t.Policy.MaxAttempts = 5
	t.Policy.PushPerHour = 10
	t.Policy.MaxFail = 5
	t.Policy.DefaultPrefer = []channel.Channel{channel.TOTP, channel.Telegram, channel.Email, channel.SMS}
	t.SMS = json.RawMessage(`{}`)
	t.SMSPresets = json.RawMessage(`{}`)
	return t
}

// ---- парсеры значений: отсутствующее/битое -> дефолт + лог ----

// isNullJSON — отсутствующее значение или JSON-литерал null. Оба случая
// трактуются как «ключ не задан»: json.Unmarshal("null", &v) — no-op
// без ошибки, поэтому без явной проверки null проскакивал как нулевое
// значение вместо дефолта.
func isNullJSON(raw json.RawMessage) bool {
	return len(raw) == 0 || string(raw) == "null"
}

func parseString(raw json.RawMessage, def string) string {
	if isNullJSON(raw) {
		return def
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		log.Printf("settings: значение %s не строка — использую дефолт %q", raw, def)
		return def
	}
	return s
}

func parseInt(raw json.RawMessage, def int) int {
	if isNullJSON(raw) {
		return def
	}
	var n int
	if err := json.Unmarshal(raw, &n); err != nil {
		log.Printf("settings: значение %s не целое — использую дефолт %d", raw, def)
		return def
	}
	return n
}

func parseUint(raw json.RawMessage, def uint) uint {
	if isNullJSON(raw) {
		return def
	}
	var n uint
	if err := json.Unmarshal(raw, &n); err != nil {
		log.Printf("settings: значение %s не целое без знака — использую дефолт %d", raw, def)
		return def
	}
	return n
}

func parseBool(raw json.RawMessage, def bool) bool {
	if isNullJSON(raw) {
		return def
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err != nil {
		log.Printf("settings: значение %s не bool — использую дефолт %v", raw, def)
		return def
	}
	return b
}

// parseDur разбирает duration в виде JSON-строки ("5m", "720h").
func parseDur(raw json.RawMessage, def time.Duration) time.Duration {
	if isNullJSON(raw) {
		return def
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		log.Printf("settings: длительность %s не строка — использую дефолт %s", raw, def)
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		log.Printf("settings: длительность %q не разбирается — использую дефолт %s", s, def)
		return def
	}
	return d
}

func parseInts(raw json.RawMessage, def []int) []int {
	if isNullJSON(raw) {
		return def
	}
	var v []int
	if err := json.Unmarshal(raw, &v); err != nil {
		log.Printf("settings: значение %s не массив целых — использую дефолт %v", raw, def)
		return def
	}
	return v
}

// parseStrings разбирает JSON-массив строк. Пустой массив значим
// (в отличие от parseChannels) и возвращается как есть.
// parseStringsFlex — список строк из JSON-массива ИЛИ сырой строки
// (ссылки через перевод строки / запятую / пробел — форма админки).
func parseStringsFlex(raw json.RawMessage, def []string) []string {
	if isNullJSON(raw) {
		return def
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return list
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil && strings.TrimSpace(one) != "" {
		out := strings.FieldsFunc(one, func(r rune) bool {
			return r == '\n' || r == '\r' || r == ',' || r == ' ' || r == '\t'
		})
		if len(out) > 0 {
			return out
		}
	}
	return def
}

func parseStrings(raw json.RawMessage, def []string) []string {
	if isNullJSON(raw) {
		return def
	}
	var v []string
	if err := json.Unmarshal(raw, &v); err != nil {
		log.Printf("settings: значение %s не массив строк — использую дефолт %v", raw, def)
		return def
	}
	return v
}

func parseStringMap(raw json.RawMessage, def map[string]string) map[string]string {
	if isNullJSON(raw) {
		return def
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		log.Printf("settings: значение %s не объект строк — использую дефолт %v", raw, def)
		return def
	}
	return m
}

func parseChannels(raw json.RawMessage, def []channel.Channel) []channel.Channel {
	if isNullJSON(raw) {
		return def
	}
	var names []string
	if err := json.Unmarshal(raw, &names); err != nil {
		log.Printf("settings: значение %s не массив строк — использую дефолт %v", raw, def)
		return def
	}
	// Пустой список — как отсутствующее значение: дефолтный набор каналов.
	if len(names) == 0 {
		return def
	}
	ch := make([]channel.Channel, len(names))
	for i, n := range names {
		ch[i] = channel.Channel(n)
	}
	return ch
}

// warnShortSecret логирует предупреждение о пустом/коротком генерируемом
// секрете: такие ключи создаются длинными (см. generatedKeys), поэтому
// пустое или короткое значение в БД — почти всегда ручная правка или
// ошибка конфигурации. Поведение не меняет — только диагностика в лог.
func warnShortSecret(key, val string) {
	if len(val) < 16 {
		log.Printf("settings: предупреждение: секрет %s пустой или подозрительно короткий (%d символов)", key, len(val))
	}
}

// fields разбирает JSON-объект настройки в карту полей; битое/не-объект
// значение даёт пустую карту (все поля откатятся к дефолтам).
func fields(raw json.RawMessage) map[string]json.RawMessage {
	m := make(map[string]json.RawMessage)
	if isNullJSON(raw) {
		return m
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		log.Printf("settings: значение %s не JSON-объект — использую дефолты группы", raw)
		return make(map[string]json.RawMessage)
	}
	return m
}

// rawJSON возвращает сырое JSON-значение как есть; отсутствующий ключ -> def.
func rawJSON(raw, def json.RawMessage) json.RawMessage {
	if isNullJSON(raw) {
		return def
	}
	return raw
}

// buildT собирает снимок из raw-значений ключей настроек; отсутствующие
// и битые значения откатываются к дефолтам defaultT (с записью в лог).
// MessageVars — общие переменные шаблонов сообщений (кроме {code} и
// контекстных {username}/{ip}/{ua}/{time}): срок жизни кода человекочитаемо
// и домен сервера без хвостового слэша.
func (t *T) MessageVars() map[string]string {
	return map[string]string{
		"ttl":    humanTTL(t.Policy.CodeTTL),
		"domain": strings.TrimRight(t.Server.Domain, "/"),
	}
}

// humanTTL — длительность жизни кода для текста сообщения: «5 мин»,
// «1 ч», «90 мин».
func humanTTL(d time.Duration) string {
	switch {
	case d <= 0:
		return "?"
	case d%time.Hour == 0:
		return fmt.Sprintf("%d ч", int(d.Hours()))
	default:
		return fmt.Sprintf("%d мин", int(d.Minutes()))
	}
}

func buildT(raw map[string]json.RawMessage) *T {
	def := defaultT()
	t := &T{}

	t.Listen.HTTP = parseString(raw["listen.http"], def.Listen.HTTP)
	t.Listen.RadiusAuth = parseString(raw["listen.radius_auth"], def.Listen.RadiusAuth)
	t.Listen.RadiusAcct = parseString(raw["listen.radius_acct"], def.Listen.RadiusAcct)

	t.Server.Domain = strings.TrimRight(parseString(raw["server.domain"], def.Server.Domain), "/")
	br := fields(raw["branding"])
	t.Branding.Name = parseString(br["name"], def.Branding.Name)
	t.Branding.Mark = parseString(br["mark"], def.Branding.Mark)
	t.Branding.Logo = parseString(br["logo"], def.Branding.Logo)
	t.Branding.Description = parseString(br["description"], def.Branding.Description)
	ads := fields(raw["ads"])
	t.Ads.Enabled = parseBool(ads["enabled"], def.Ads.Enabled)
	t.Ads.Provider = parseString(ads["provider"], def.Ads.Provider)
	if t.Ads.Provider != "direct" {
		t.Ads.Provider = "rsya"
	}
	t.Ads.MessageFooter = parseString(ads["message_footer"], def.Ads.MessageFooter)
	adsd := fields(ads["direct"])
	t.Ads.Direct.URL = parseString(adsd["url"], def.Ads.Direct.URL)
	t.Ads.Direct.URLs = parseStringsFlex(adsd["urls"], def.Ads.Direct.URLs)
	t.Ads.Direct.Label = parseString(adsd["label"], def.Ads.Direct.Label)
	t.Ads.Direct.Image = parseString(adsd["image"], def.Ads.Direct.Image)
	adsb := fields(ads["blocks"])
	t.Ads.Blocks.LoginLeft = parseString(adsb["login_left"], def.Ads.Blocks.LoginLeft)
	t.Ads.Blocks.LoginRight = parseString(adsb["login_right"], def.Ads.Blocks.LoginRight)
	t.Ads.Blocks.Sidebar = parseString(adsb["sidebar"], def.Ads.Blocks.Sidebar)
	px := fields(raw["proxy"])
	t.Proxy.TrustedNetworks = parseStringsFlex(px["trusted_networks"], def.Proxy.TrustedNetworks)
	f2b := fields(raw["fail2ban"])
	t.Fail2ban.Enabled = parseBool(f2b["enabled"], def.Fail2ban.Enabled)
	t.Fail2ban.MaxFail = parseInt(f2b["max_fail"], def.Fail2ban.MaxFail)
	t.Fail2ban.Window = parseDur(f2b["window"], def.Fail2ban.Window)
	t.Fail2ban.BanTime = parseDur(f2b["ban_time"], def.Fail2ban.BanTime)
	msg := fields(raw["messages"])
	t.Messages.EmailBody = parseString(msg["email_body"], def.Messages.EmailBody)
	t.Messages.SMSText = parseString(msg["sms_text"], def.Messages.SMSText)
	t.Messages.TelegramCode = parseString(msg["telegram_code_text"], def.Messages.TelegramCode)
	t.Messages.TelegramPush = parseString(msg["telegram_push_text"], def.Messages.TelegramPush)

	t.MasterKeyB64 = parseString(raw["master_key"], def.MasterKeyB64)
	t.AdminToken = parseString(raw["admin_token"], def.AdminToken)
	t.RadiusSecret = parseString(raw["radius.secret"], def.RadiusSecret)
	warnShortSecret("master_key", t.MasterKeyB64)
	warnShortSecret("admin_token", t.AdminToken)
	warnShortSecret("radius.secret", t.RadiusSecret)

	t.Radius.CodeLengths = parseInts(raw["radius.code_lengths"], def.Radius.CodeLengths)
	t.Radius.MaxFailPerUser = parseInt(raw["radius.max_fail_per_user"], def.Radius.MaxFailPerUser)
	t.Radius.FailWindow = parseDur(raw["radius.fail_window"], def.Radius.FailWindow)
	t.Radius.PushWait = parseDur(raw["radius.push_wait"], def.Radius.PushWait)
	t.Radius.ReplyAttributes = parseStringMap(raw["radius.reply_attributes"], def.Radius.ReplyAttributes)

	smtp := fields(raw["smtp"])
	t.SMTP.Host = parseString(smtp["host"], def.SMTP.Host)
	t.SMTP.Port = parseInt(smtp["port"], def.SMTP.Port)
	t.SMTP.StartTLS = parseBool(smtp["starttls"], def.SMTP.StartTLS)
	t.SMTP.User = parseString(smtp["user"], def.SMTP.User)
	t.SMTP.Password = parseString(smtp["password"], def.SMTP.Password)
	t.SMTP.From = parseString(smtp["from"], def.SMTP.From)
	t.SMTP.Subject = parseString(smtp["subject"], def.SMTP.Subject)
	t.SMTP.Timeout = parseDur(smtp["timeout"], def.SMTP.Timeout)

	t.SMS = rawJSON(raw["sms.gateway"], def.SMS)
	t.SMSPresets = rawJSON(raw["sms.presets"], def.SMSPresets)

	totp := fields(raw["totp"])
	t.TOTP.Issuer = parseString(totp["issuer"], def.TOTP.Issuer)
	t.TOTP.Digits = parseInt(totp["digits"], def.TOTP.Digits)
	t.TOTP.Period = parseInt(totp["period"], def.TOTP.Period)
	t.TOTP.Skew = parseUint(totp["skew"], def.TOTP.Skew)

	tg := fields(raw["telegram"])
	t.TG.BotToken = parseString(tg["bot_token"], def.TG.BotToken)

	// oidc.keys: null/отсутствие = ключ не создан (nil), иначе — сырой JSON.
	if v := rawJSON(raw["oidc.keys"], def.OIDCKeys); !isNullJSON(v) {
		t.OIDCKeys = v
	}

	wa := fields(raw["webauthn"])
	t.WebAuthn.RPID = parseString(wa["rp_id"], def.WebAuthn.RPID)
	t.WebAuthn.RPName = parseString(wa["rp_name"], def.WebAuthn.RPName)
	t.WebAuthn.Origins = parseStrings(wa["origins"], def.WebAuthn.Origins)

	ld := fields(raw["ldap"])
	t.LDAP.Enabled = parseBool(ld["enabled"], def.LDAP.Enabled)
	t.LDAP.URL = parseString(ld["url"], def.LDAP.URL)
	t.LDAP.StartTLS = parseBool(ld["starttls"], def.LDAP.StartTLS)
	t.LDAP.BindDN = parseString(ld["bind_dn"], def.LDAP.BindDN)
	t.LDAP.BindPassword = parseString(ld["bind_password"], def.LDAP.BindPassword)
	t.LDAP.BaseDN = parseString(ld["base_dn"], def.LDAP.BaseDN)
	t.LDAP.UserFilter = parseString(ld["user_filter"], def.LDAP.UserFilter)
	t.LDAP.GroupBaseDN = parseString(ld["group_base_dn"], def.LDAP.GroupBaseDN)
	t.LDAP.GroupFilter = parseString(ld["group_filter"], def.LDAP.GroupFilter)
	ldAttrs := fields(ld["attrs"])
	t.LDAP.Attrs.Email = parseString(ldAttrs["email"], def.LDAP.Attrs.Email)
	t.LDAP.Attrs.Phone = parseString(ldAttrs["phone"], def.LDAP.Attrs.Phone)
	t.LDAP.Attrs.DisplayName = parseString(ldAttrs["display_name"], def.LDAP.Attrs.DisplayName)
	t.LDAP.AllowGroups = parseStrings(ld["allow_groups"], def.LDAP.AllowGroups)
	t.LDAP.RoleMap = parseStringMap(ld["role_map"], def.LDAP.RoleMap)

	pol := fields(raw["policy"])
	t.Policy.CodeTTL = parseDur(pol["code_ttl"], def.Policy.CodeTTL)
	t.Policy.ResendCooldown = parseDur(pol["resend_cooldown"], def.Policy.ResendCooldown)
	t.Policy.PushCooldown = parseDur(pol["push_cooldown"], def.Policy.PushCooldown)
	t.Policy.TrustedDeviceTTL = parseDur(pol["trusted_device_ttl"], def.Policy.TrustedDeviceTTL)
	t.Policy.MaxFail = parseInt(pol["max_fail"], def.Policy.MaxFail)
	t.Policy.FailWindow = parseDur(pol["fail_window"], def.Policy.FailWindow)
	t.Policy.BanTime = parseDur(pol["ban_time"], def.Policy.BanTime)
	t.Policy.CodeLength = parseInt(pol["code_length"], def.Policy.CodeLength)
	t.Policy.MaxAttempts = parseInt(pol["max_attempts"], def.Policy.MaxAttempts)
	t.Policy.PushPerHour = parseInt(pol["push_per_hour"], def.Policy.PushPerHour)
	t.Policy.DefaultPrefer = parseChannels(pol["default_prefer_channels"], def.Policy.DefaultPrefer)
	t.Policy.SessionTTL = parseDur(raw["web.session_ttl"], def.Policy.SessionTTL)

	return t
}

// ---- чтение из БД ----

// Load читает все настройки из таблицы settings. Каждый отсутствующий
// известный ключ записывается в БД: статический дефолт из defaults.go,
// а для master_key/admin_token/radius.secret — свежесгенерированное
// значение (secrets.NewMasterKeyB64 / RandomToken(32)); на первом старте
// с пустой таблицей именно так создаётся вся конфигурация. Битые
// длительности и числа откатываются к дефолтам (см. buildT).
func Load(ctx context.Context, st *store.Store) (*T, error) {
	raw, err := readAll(ctx, st)
	if err != nil {
		return nil, err
	}

	for _, key := range sortedKnownKeys() {
		if _, ok := raw[key]; ok {
			continue
		}
		var val json.RawMessage
		if gen, isGen := generatedKeys[key]; isGen {
			b, err := json.Marshal(gen())
			if err != nil {
				return nil, fmt.Errorf("settings: маршал генерируемого ключа %s: %w", key, err)
			}
			val = b
		} else {
			val = defaults[key]
		}
		// ON CONFLICT DO NOTHING + RETURNING: если конкурентный процесс уже
		// записал ключ, берём его значение (иначе снапшот разойдётся с БД).
		var stored json.RawMessage
		err := st.Pool().QueryRow(ctx,
			`INSERT INTO settings (key, value) VALUES ($1, $2)
			 ON CONFLICT (key) DO NOTHING RETURNING value`, key, val).Scan(&stored)
		if errors.Is(err, pgx.ErrNoRows) {
			if selErr := st.Pool().QueryRow(ctx,
				`SELECT value FROM settings WHERE key = $1`, key).Scan(&stored); selErr != nil {
				return nil, fmt.Errorf("settings: чтение ключа %s после конфликта: %w", key, selErr)
			}
			raw[key] = stored
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("settings: запись дефолта %s: %w", key, err)
		}
		raw[key] = stored
	}

	return buildT(raw), nil
}

// readAll читает все строки settings в карту raw-значений.
func readAll(ctx context.Context, st *store.Store) (map[string]json.RawMessage, error) {
	rows, err := st.Pool().Query(ctx, `SELECT key, value FROM settings`)
	if err != nil {
		return nil, fmt.Errorf("settings: чтение таблицы settings: %w", err)
	}
	defer rows.Close()
	raw := make(map[string]json.RawMessage)
	for rows.Next() {
		var k string
		var v json.RawMessage
		if err := rows.Scan(&k, &v); err != nil {
			return nil, fmt.Errorf("settings: разбор строки settings: %w", err)
		}
		raw[k] = v
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("settings: итерация по settings: %w", err)
	}
	return raw, nil
}

// ---- менеджер ----

// M — менеджер настроек: атомарно заменяемый снимок T поверх Store.
type M struct {
	st  *store.Store
	cur atomic.Pointer[T]
}

// NewManager выполняет первичный Load и возвращает готовый менеджер.
func NewManager(ctx context.Context, st *store.Store) (*M, error) {
	m := &M{st: st}
	t, err := Load(ctx, st)
	if err != nil {
		return nil, err
	}
	m.cur.Store(t)
	return m, nil
}

// Get возвращает текущий снимок. Возвращённый T иммутабелен — только
// читать; обновление всегда даёт новый снимок через Reload/Put.
func (m *M) Get() *T { return m.cur.Load() }

// Reload перечитывает настройки из БД, атомарно подменяя снимок.
// Изменения listen.* применяются фактически после рестарта процесса
// (порты слушателей); остальное подхватывается на лету.
func (m *M) Reload(ctx context.Context) error {
	t, err := Load(ctx, m.st)
	if err != nil {
		return err
	}
	m.cur.Store(t)
	return nil
}

// Put точечно перезаписывает один известный ключ и перечитывает снимок.
// Значение должно быть валидным JSON.
func (m *M) Put(ctx context.Context, key string, val json.RawMessage) error {
	if !isKnownKey(key) {
		return fmt.Errorf("settings: неизвестный ключ %q", key)
	}
	if !json.Valid(val) {
		return fmt.Errorf("settings: значение ключа %s не является валидным JSON", key)
	}
	if _, err := m.st.Pool().Exec(ctx,
		`INSERT INTO settings (key, value) VALUES ($1, $2)
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, key, val); err != nil {
		return fmt.Errorf("settings: запись ключа %s: %w", key, err)
	}
	return m.Reload(ctx)
}

// Masked возвращает все настройки одним деревом; секретные значения
// (master_key, admin_token, radius.secret, smtp.password,
// telegram.bot_token, токены внутри sms.*) по key path заменены маской
// {"set":bool,"value":"••••"} и никогда не возвращаются реальным значением.
func (m *M) Masked(ctx context.Context) (map[string]any, error) {
	t := m.Get()
	if t == nil {
		return nil, fmt.Errorf("settings: снимок ещё не загружен")
	}
	return t.masked(), nil
}

// IsKnownKey — экспортированная обёртка isKnownKey: API-слою нужно
// провалидировать ВСЕ ключи PUT /settings до применения любого из них
// (атомарность запроса), не выходя за границы пакета.
func IsKnownKey(key string) bool { return isKnownKey(key) }

// exportExcluded — ключи, НИКОГДА не покидающие сервер в экспорте
// настроек: master_key расшифровывает TOTP-секреты (перенос равен
// компрометации всех факторов), admin_token — полный доступ к админ-API,
// oidc.keys подписывает ID-токены (перенос позволяет подделывать вход).
var exportExcluded = map[string]struct{}{
	"master_key":  {},
	"admin_token": {},
	"oidc.keys":   {},
}

// IsImportExcluded — ключ, который нельзя применить импортом настроек
// (симметрия экспорта): master_key/admin_token задаются только генерацией
// сервера или regenerate-эндпоинтом.
func IsImportExcluded(key string) bool {
	_, ok := exportExcluded[key]
	return ok
}

// Export возвращает СЫРЫЕ значения всех ключей настроек из БД, кроме
// master_key и admin_token (никогда не экспортируются). Файл экспорта
// содержит секреты (radius.secret, smtp.password, telegram-токен, креды
// SMS/LDAP) — он предназначен для переноса между инсталляциями и должен
// храниться как секрет.
func (m *M) Export(ctx context.Context) (map[string]json.RawMessage, error) {
	raw, err := readAll(ctx, m.st)
	if err != nil {
		return nil, err
	}
	for key := range exportExcluded {
		delete(raw, key)
	}
	return raw, nil
}

// ---- маскировка ----

// sensitiveKeys — имена JSON-полей внутри sms.*: значения маскируются по
// key path (последний сегмент, без учёта регистра). Соответствуют кредам
// пресетов шлюзов (smsc login/psw, smsaero auth_base64, bytehand id/key,
// mainsms project/api_key, twilio sid/token, smsgateway24 device_id) и
// типовым именам ключей custom-шлюзов. Сопоставление ТОЧНОЕ по имени поля —
// «id» маскирует только поле с этим именем внутри sms.*, значения других
// секций настроек не задевает (maskValueTree применяется только к sms.*).
var sensitiveKeys = map[string]struct{}{
	"authorization":       {},
	"proxy-authorization": {},
	"token":               {},
	"api_key":             {},
	"apikey":              {},
	"api-key":             {},
	"access_token":        {},
	"access_key":          {},
	"secret":              {},
	"password":            {},
	"psw":                 {},
	"bearer":              {},
	"key":                 {},
	"api_id":              {},
	"auth_base64":         {},
	"sid":                 {},
	"login":               {},
	"id":                  {},
	"project":             {},
	"device_id":           {},
}

func isSensitiveKey(k string) bool {
	_, ok := sensitiveKeys[strings.ToLower(k)]
	return ok
}

// secretMask — маска строкового секрета: set = значение задано.
func secretMask(s string) map[string]any {
	return map[string]any{"set": s != "", "value": maskValue}
}

// maskForValue — маска для секретного поля произвольного JSON-типа.
func maskForValue(v any) map[string]any {
	if s, ok := v.(string); ok {
		return map[string]any{"set": s != "", "value": maskValue}
	}
	return map[string]any{"set": v != nil, "value": maskValue}
}

// maskedJSON разбирает сырое SMS-JSON и обходит дерево, маскируя
// чувствительные поля по имени ключа. Значение из jsonb всегда валидно;
// ветка ошибки — защитная.
func maskedJSON(raw json.RawMessage) any {
	if len(raw) == 0 {
		return map[string]any{}
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return string(raw)
	}
	return maskValueTree(v)
}

func maskValueTree(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			if isSensitiveKey(k) {
				out[k] = maskForValue(val)
				continue
			}
			out[k] = maskValueTree(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = maskValueTree(val)
		}
		return out
	default:
		return v
	}
}

// MaskedJSONTree возвращает pretty-JSON дерева raw с маскированными
// чувствительными полями (те же правила, что в Masked). Для HTML-форм
// настроек: маски-объекты {"set":…,"value":"••••"} распознаются мержем
// (isNoChangeValue/mergeSettingMap) как «не менять поле» — отправка формы
// с замаскированным JSON сохраняет текущие креды, новые значения их
// заменяют.
func MaskedJSONTree(raw json.RawMessage) string {
	b, err := json.MarshalIndent(maskedJSON(raw), "", "  ")
	if err != nil {
		return "{}"
	}
	return string(b)
}

// channelsToAny — []Channel -> []any для map-вывода.
func channelsToAny(ch []channel.Channel) []any {
	out := make([]any, len(ch))
	for i, c := range ch {
		out[i] = string(c)
	}
	return out
}

// masked строит дерево всех настроек с маскировкой секретов по key path.
func (t *T) masked() map[string]any {
	return map[string]any{
		"listen": map[string]any{
			"http":        t.Listen.HTTP,
			"radius_auth": t.Listen.RadiusAuth,
			"radius_acct": t.Listen.RadiusAcct,
		},
		"server": map[string]any{
			"domain": t.Server.Domain,
		},
		"branding": map[string]any{
			"name":        t.Branding.Name,
			"mark":        t.Branding.Mark,
			"logo":        t.Branding.Logo,
			"description": t.Branding.Description,
		},
		"ads": map[string]any{
			"enabled":        t.Ads.Enabled,
			"provider":       t.Ads.Provider,
			"message_footer": t.Ads.MessageFooter,
			"direct": map[string]any{
				"url": t.Ads.Direct.URL, "urls": t.Ads.Direct.URLs,
				"label": t.Ads.Direct.Label, "image": t.Ads.Direct.Image,
			},
			"blocks": map[string]any{
				"login_left":  t.Ads.Blocks.LoginLeft,
				"login_right": t.Ads.Blocks.LoginRight,
				"sidebar":     t.Ads.Blocks.Sidebar,
			},
		},
		"proxy": map[string]any{
			"trusted_networks": t.Proxy.TrustedNetworks,
		},
		"fail2ban": map[string]any{
			"enabled":  t.Fail2ban.Enabled,
			"max_fail": t.Fail2ban.MaxFail,
			"window":   t.Fail2ban.Window.String(),
			"ban_time": t.Fail2ban.BanTime.String(),
		},
		"messages": map[string]any{
			"email_body":         t.Messages.EmailBody,
			"sms_text":           t.Messages.SMSText,
			"telegram_code_text": t.Messages.TelegramCode,
			"telegram_push_text": t.Messages.TelegramPush,
		},
		"master_key":  secretMask(t.MasterKeyB64),
		"admin_token": secretMask(t.AdminToken),
		"radius": map[string]any{
			"secret":            secretMask(t.RadiusSecret),
			"code_lengths":      t.Radius.CodeLengths,
			"max_fail_per_user": t.Radius.MaxFailPerUser,
			"fail_window":       t.Radius.FailWindow.String(),
			"push_wait":         t.Radius.PushWait.String(),
			"reply_attributes":  t.Radius.ReplyAttributes,
		},
		"smtp": map[string]any{
			"host":     t.SMTP.Host,
			"port":     t.SMTP.Port,
			"starttls": t.SMTP.StartTLS,
			"user":     t.SMTP.User,
			"password": secretMask(t.SMTP.Password),
			"from":     t.SMTP.From,
			"subject":  t.SMTP.Subject,
			"timeout":  t.SMTP.Timeout.String(),
		},
		"sms": map[string]any{
			"gateway": maskedJSON(t.SMS),
			"presets": maskedJSON(t.SMSPresets),
		},
		"totp": map[string]any{
			"issuer": t.TOTP.Issuer,
			"digits": t.TOTP.Digits,
			"period": t.TOTP.Period,
			"skew":   t.TOTP.Skew,
		},
		"telegram": map[string]any{
			"bot_token": secretMask(t.TG.BotToken),
		},
		"oidc": map[string]any{
			"keys": maskForValue(t.OIDCKeys), // секрет: приватный ключ подписи
		},
		"webauthn": map[string]any{
			"rp_id":   t.WebAuthn.RPID,
			"rp_name": t.WebAuthn.RPName,
			"origins": t.WebAuthn.Origins,
		},
		"ldap": map[string]any{
			"enabled":       t.LDAP.Enabled,
			"url":           t.LDAP.URL,
			"starttls":      t.LDAP.StartTLS,
			"bind_dn":       t.LDAP.BindDN,
			"bind_password": secretMask(t.LDAP.BindPassword),
			"base_dn":       t.LDAP.BaseDN,
			"user_filter":   t.LDAP.UserFilter,
			"group_base_dn": t.LDAP.GroupBaseDN,
			"group_filter":  t.LDAP.GroupFilter,
			"attrs": map[string]any{
				"email":        t.LDAP.Attrs.Email,
				"phone":        t.LDAP.Attrs.Phone,
				"display_name": t.LDAP.Attrs.DisplayName,
			},
			"allow_groups": t.LDAP.AllowGroups,
			"role_map":     t.LDAP.RoleMap,
		},
		"policy": map[string]any{
			"code_ttl":                t.Policy.CodeTTL.String(),
			"code_length":             t.Policy.CodeLength,
			"max_attempts":            t.Policy.MaxAttempts,
			"resend_cooldown":         t.Policy.ResendCooldown.String(),
			"default_prefer_channels": channelsToAny(t.Policy.DefaultPrefer),
			"push_cooldown":           t.Policy.PushCooldown.String(),
			"push_per_hour":           t.Policy.PushPerHour,
			"trusted_device_ttl":      t.Policy.TrustedDeviceTTL.String(),
			"max_fail":                t.Policy.MaxFail,
			"fail_window":             t.Policy.FailWindow.String(),
			"ban_time":                t.Policy.BanTime.String(),
		},
		"web": map[string]any{
			"session_ttl": t.Policy.SessionTTL.String(),
		},
	}
}
