package settings

import (
	"encoding/json"
	"sort"

	"github.com/aligorov/twofa/internal/secrets"
)

// defaults — статические дефолты известных ключей настроек (спека §8/§10).
// Значения — JSON, записываемый в settings.value при отсутствии ключа.
var defaults = map[string]json.RawMessage{
	"listen.http":        json.RawMessage(`":8080"`),
	"listen.radius_auth": json.RawMessage(`":1812"`),
	"listen.radius_acct": json.RawMessage(`":1813"`),
	"server.domain":      json.RawMessage(`""`),
	"server.timezone":    json.RawMessage(`"Europe/Moscow"`),
	"branding":           json.RawMessage(`{"name":"","mark":"","logo":"","description":""}`),
	"ads":                json.RawMessage(`{"enabled":false,"provider":"rsya","blocks":{"login_left":"","login_right":"","sidebar":""},"message_footer":"","direct":{"url":"","urls":[],"label":"","image":""}}`),
	"proxy":              json.RawMessage(`{"trusted_networks":[]}`),
	"fail2ban":           json.RawMessage(`{"enabled":true,"max_fail":10,"window":"5m","ban_time":"30m"}`),
	"messages": mustJSON(map[string]string{
		"email_body":         DefaultEmailBody,
		"sms_text":           DefaultSMSText,
		"telegram_code_text": DefaultTelegramCode,
		"telegram_push_text": DefaultTelegramPush,
	}),
	"radius.code_lengths":      json.RawMessage(`[6,8]`),
	"radius.max_fail_per_user": json.RawMessage(`10`),
	"radius.fail_window":       json.RawMessage(`"5m"`),
	"radius.push_wait":         json.RawMessage(`"20s"`),
	"radius.reply_attributes":  json.RawMessage(`{}`),
	"radius.cert_file":         json.RawMessage(`""`),
	"radius.key_file":          json.RawMessage(`""`),
	// radius.eap_cert — пара self-signed сертификата EAP-TTLS (RSA-2048,
	// JSON {"cert_pem","key_pem"}). Дефолт null — «сертификат не создан»:
	// генерируется RADIUS-сервером при первом старте
	// (internal/radiusserver.EnsureEAPCert) и записывается через Put, а не
	// здесь. Секрет: не экспортируется/не импортируется и маскируется.
	"radius.eap_cert": json.RawMessage(`null`),
	"acme":            json.RawMessage(`{"enabled":false,"domain":"","email":"","staging":false}`),
	"smtp":            json.RawMessage(`{"host":"","port":0,"starttls":false,"user":"","password":"","from":"","subject":"","timeout":"0s"}`),
	"sms.gateway":     json.RawMessage(`{}`),
	"sms.presets":     json.RawMessage(`{}`),
	"totp":            json.RawMessage(`{"issuer":"twofa","digits":6,"period":30,"skew":1}`),
	"telegram":        json.RawMessage(`{"bot_token":""}`),
	"webauthn":        json.RawMessage(`{"rp_id":"","rp_name":"twofa","origins":[]}`),
	"policy":          json.RawMessage(`{"code_ttl":"5m","code_length":6,"max_attempts":5,"resend_cooldown":"60s","default_prefer_channels":["totp","telegram","email","sms"],"push_cooldown":"30s","push_per_hour":10,"trusted_device_ttl":"720h","max_fail":5,"fail_window":"5m","ban_time":"15m"}`),
	"web.session_ttl": json.RawMessage(`"12h"`),
	"ldap":            json.RawMessage(`{"enabled":false,"url":"","starttls":false,"bind_dn":"","bind_password":"","base_dn":"","user_filter":"(&(objectClass=user)(sAMAccountName={login}))","group_base_dn":"","group_filter":"(&(objectClass=group)(member={dn}))","attrs":{"email":"mail","phone":"telephoneNumber","display_name":"displayName"},"allow_groups":[],"role_map":{},"group_radius_map":{}}`),
	// oidc.keys — пара ключей подписи ID-токенов (RSA-2048, JSON
	// {"current":{"kid","private_pem"},"previous":null}). Дефолт null —
	// «ключ не создан»: генерируется менеджером OIDC при первом старте
	// (internal/oidc.NewManager) и записывается через Put, а не здесь.
	"oidc.keys": json.RawMessage(`null`),
}

// generatedKeys — секретные ключи без статического дефолта: при отсутствии
// в БД получают случайное значение (crypto/rand). На первом старте
// (пустая таблица) именно так создаются master_key/admin_token/radius.secret.
var generatedKeys = map[string]func() string{
	"master_key":    secrets.NewMasterKeyB64,
	"admin_token":   func() string { return secrets.RandomToken(32) },
	"radius.secret": func() string { return secrets.RandomToken(32) },
}

// knownKeys — множество всех известных ключей (дефолтных и генерируемых).
var knownKeys = func() map[string]struct{} {
	set := make(map[string]struct{}, len(defaults)+len(generatedKeys))
	for k := range defaults {
		set[k] = struct{}{}
	}
	for k := range generatedKeys {
		set[k] = struct{}{}
	}
	return set
}()

// mustJSON кодирует значение в JSON-дефолт настроек (для составных
// дефолтов, собираемых из констант).
func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic("settings: дефолт не кодируется в JSON: " + err.Error())
	}
	return json.RawMessage(b)
}

// isKnownKey сообщает, известен ли ключ настроек.
func isKnownKey(k string) bool {
	_, ok := knownKeys[k]
	return ok
}

// sortedKnownKeys — известные ключи в стабильном (отсортированном) порядке.
func sortedKnownKeys() []string {
	keys := make([]string, 0, len(knownKeys))
	for k := range knownKeys {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
