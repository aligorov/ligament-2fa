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
type T struct {
	Listen struct {
		HTTP       string
		RadiusAuth string
		RadiusAcct string
	}
	MasterKeyB64, AdminToken, RadiusSecret string

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

	TG struct {
		BotToken string
	}

	WebAuthn struct {
		RPID   string
		RPName string
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
func buildT(raw map[string]json.RawMessage) *T {
	def := defaultT()
	t := &T{}

	t.Listen.HTTP = parseString(raw["listen.http"], def.Listen.HTTP)
	t.Listen.RadiusAuth = parseString(raw["listen.radius_auth"], def.Listen.RadiusAuth)
	t.Listen.RadiusAcct = parseString(raw["listen.radius_acct"], def.Listen.RadiusAcct)

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

	wa := fields(raw["webauthn"])
	t.WebAuthn.RPID = parseString(wa["rp_id"], def.WebAuthn.RPID)
	t.WebAuthn.RPName = parseString(wa["rp_name"], def.WebAuthn.RPName)

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

// ---- маскировка ----

// sensitiveKeys — имена JSON-полей внутри sms.*: значения маскируются по
// key path (последний сегмент, без учёта регистра).
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
		"webauthn": map[string]any{
			"rp_id":   t.WebAuthn.RPID,
			"rp_name": t.WebAuthn.RPName,
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
