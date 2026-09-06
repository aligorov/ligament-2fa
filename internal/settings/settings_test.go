package settings

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aligorov/twofa/internal/channel"
)

// TestBuildTDefaults: пустой raw-набор -> полностью дефолтный снимок.
func TestBuildTDefaults(t *testing.T) {
	snap := buildT(map[string]json.RawMessage{})

	if snap.Listen.HTTP != ":8080" || snap.Listen.RadiusAuth != ":1812" || snap.Listen.RadiusAcct != ":1813" {
		t.Errorf("listen = %+v", snap.Listen)
	}
	if snap.Radius.CodeLengths == nil || len(snap.Radius.CodeLengths) != 2 || snap.Radius.CodeLengths[0] != 6 || snap.Radius.CodeLengths[1] != 8 {
		t.Errorf("radius.code_lengths = %v, ожидалось [6 8]", snap.Radius.CodeLengths)
	}
	if snap.Radius.MaxFailPerUser != 10 {
		t.Errorf("radius.max_fail_per_user = %d, ожидалось 10", snap.Radius.MaxFailPerUser)
	}
	if snap.Radius.FailWindow != 5*time.Minute {
		t.Errorf("radius.fail_window = %s, ожидалось 5m", snap.Radius.FailWindow)
	}
	if snap.Radius.PushWait != 20*time.Second {
		t.Errorf("radius.push_wait = %s, ожидалось 20s", snap.Radius.PushWait)
	}
	if snap.Radius.ReplyAttributes == nil {
		t.Error("radius.reply_attributes = nil, ожидался пустой map")
	}
	if snap.TOTP.Issuer != "twofa" || snap.TOTP.Digits != 6 || snap.TOTP.Period != 30 || snap.TOTP.Skew != 1 {
		t.Errorf("totp = %+v", snap.TOTP)
	}
	if snap.WebAuthn.RPID != "" || snap.WebAuthn.RPName != "twofa" || len(snap.WebAuthn.Origins) != 0 {
		t.Errorf("webauthn = %+v", snap.WebAuthn)
	}
	// Шаблоны сообщений заполнены по умолчанию и содержат {code}.
	if !strings.Contains(snap.Messages.EmailBody, "{code}") ||
		!strings.Contains(snap.Messages.SMSText, "{code}") ||
		!strings.Contains(snap.Messages.TelegramCode, "{code}") {
		t.Errorf("messages без {code}: %+v", snap.Messages)
	}
	if strings.Contains(snap.Messages.TelegramPush, "{code}") {
		t.Errorf("push-шаблон не должен содержать {code}: %q", snap.Messages.TelegramPush)
	}
	if snap.Server.Domain != "" {
		t.Errorf("server.domain = %q, want пусто", snap.Server.Domain)
	}
	if snap.Policy.CodeTTL != 5*time.Minute || snap.Policy.ResendCooldown != 60*time.Second ||
		snap.Policy.PushCooldown != 30*time.Second || snap.Policy.TrustedDeviceTTL != 720*time.Hour ||
		snap.Policy.SessionTTL != 12*time.Hour || snap.Policy.FailWindow != 5*time.Minute || snap.Policy.BanTime != 15*time.Minute {
		t.Errorf("policy durations = %+v", snap.Policy)
	}
	if snap.Policy.CodeLength != 6 || snap.Policy.MaxAttempts != 5 || snap.Policy.PushPerHour != 10 || snap.Policy.MaxFail != 5 {
		t.Errorf("policy ints = %+v", snap.Policy)
	}
	want := []channel.Channel{channel.TOTP, channel.Telegram, channel.Email, channel.SMS}
	if len(snap.Policy.DefaultPrefer) != len(want) {
		t.Fatalf("policy.default_prefer = %v, ожидалось %v", snap.Policy.DefaultPrefer, want)
	}
	for i, c := range want {
		if snap.Policy.DefaultPrefer[i] != c {
			t.Errorf("policy.default_prefer[%d] = %q, ожидалось %q", i, snap.Policy.DefaultPrefer[i], c)
		}
	}
}

// TestBuildTValid: полностью заполненный raw-набор разбирается точно.
func TestBuildTValid(t *testing.T) {
	raw := map[string]json.RawMessage{
		"listen.http":              json.RawMessage(`":9999"`),
		"listen.radius_auth":       json.RawMessage(`":2812"`),
		"listen.radius_acct":       json.RawMessage(`":2813"`),
		"server.domain":            json.RawMessage(`"https://2fa.example.com/"`),
		"messages":                 json.RawMessage(`{"email_body":"Код {code} на {domain}","sms_text":"S:{code}","telegram_code_text":"T:{code} {ttl}","telegram_push_text":"вход {username}"}`),
		"master_key":               json.RawMessage(`"bWFzdGVy"`),
		"admin_token":              json.RawMessage(`"tok"`),
		"radius.secret":            json.RawMessage(`"sec"`),
		"radius.code_lengths":      json.RawMessage(`[8]`),
		"radius.max_fail_per_user": json.RawMessage(`3`),
		"radius.fail_window":       json.RawMessage(`"2m"`),
		"radius.push_wait":         json.RawMessage(`"7s"`),
		"radius.reply_attributes":  json.RawMessage(`{"Reply-Message":"hello"}`),
		"smtp":                     json.RawMessage(`{"host":"h","port":25,"starttls":true,"user":"u","password":"p","from":"f","subject":"s","timeout":"3s"}`),
		"sms.gateway":              json.RawMessage(`{"method":"POST"}`),
		"sms.presets":              json.RawMessage(`{"smsc":{"x":1}}`),
		"totp":                     json.RawMessage(`{"issuer":"iss","digits":8,"period":60,"skew":2}`),
		"telegram":                 json.RawMessage(`{"bot_token":"bt"}`),
		"webauthn":                 json.RawMessage(`{"rp_id":"2fa.example.com","rp_name":"name","origins":["https://2fa.example.com","http://localhost:8080"]}`),
		"policy":                   json.RawMessage(`{"code_ttl":"1m","code_length":8,"max_attempts":2,"resend_cooldown":"11s","default_prefer_channels":["sms"],"push_cooldown":"12s","push_per_hour":1,"trusted_device_ttl":"2h","max_fail":1,"fail_window":"13s","ban_time":"14s"}`),
		"web.session_ttl":          json.RawMessage(`"1h"`),
	}
	snap := buildT(raw)

	if snap.Listen.HTTP != ":9999" || snap.Listen.RadiusAuth != ":2812" || snap.Listen.RadiusAcct != ":2813" {
		t.Errorf("listen = %+v", snap.Listen)
	}
	if snap.Server.Domain != "https://2fa.example.com" {
		t.Errorf("server.domain = %q (хвостовой слэш срезан?)", snap.Server.Domain)
	}
	if snap.Messages.EmailBody != "Код {code} на {domain}" || snap.Messages.SMSText != "S:{code}" ||
		snap.Messages.TelegramCode != "T:{code} {ttl}" || snap.Messages.TelegramPush != "вход {username}" {
		t.Errorf("messages = %+v", snap.Messages)
	}
	vars := snap.MessageVars()
	if vars["domain"] != "https://2fa.example.com" {
		t.Errorf("MessageVars.domain = %q", vars["domain"])
	}
	if vars["ttl"] != "1 мин" { // policy.code_ttl ниже переопределён на 1m
		t.Errorf("MessageVars.ttl = %q, want 1 мин", vars["ttl"])
	}
	if snap.MasterKeyB64 != "bWFzdGVy" || snap.AdminToken != "tok" || snap.RadiusSecret != "sec" {
		t.Errorf("секреты = %q/%q/%q", snap.MasterKeyB64, snap.AdminToken, snap.RadiusSecret)
	}
	if len(snap.Radius.CodeLengths) != 1 || snap.Radius.CodeLengths[0] != 8 {
		t.Errorf("radius.code_lengths = %v, ожидалось [8]", snap.Radius.CodeLengths)
	}
	if snap.Radius.MaxFailPerUser != 3 || snap.Radius.FailWindow != 2*time.Minute || snap.Radius.PushWait != 7*time.Second {
		t.Errorf("radius = %+v", snap.Radius)
	}
	if snap.Radius.ReplyAttributes["Reply-Message"] != "hello" {
		t.Errorf("radius.reply_attributes = %v", snap.Radius.ReplyAttributes)
	}
	if snap.SMTP.Host != "h" || snap.SMTP.Port != 25 || !snap.SMTP.StartTLS || snap.SMTP.User != "u" ||
		snap.SMTP.Password != "p" || snap.SMTP.From != "f" || snap.SMTP.Subject != "s" || snap.SMTP.Timeout != 3*time.Second {
		t.Errorf("smtp = %+v", snap.SMTP)
	}
	if snap.TOTP.Issuer != "iss" || snap.TOTP.Digits != 8 || snap.TOTP.Period != 60 || snap.TOTP.Skew != 2 {
		t.Errorf("totp = %+v", snap.TOTP)
	}
	if snap.TG.BotToken != "bt" {
		t.Errorf("telegram.bot_token = %q", snap.TG.BotToken)
	}
	if snap.WebAuthn.RPID != "2fa.example.com" || snap.WebAuthn.RPName != "name" {
		t.Errorf("webauthn = %+v", snap.WebAuthn)
	}
	wantOrigins := []string{"https://2fa.example.com", "http://localhost:8080"}
	if !reflect.DeepEqual(snap.WebAuthn.Origins, wantOrigins) {
		t.Errorf("webauthn.origins = %v, want %v", snap.WebAuthn.Origins, wantOrigins)
	}
	if snap.Policy.CodeTTL != time.Minute || snap.Policy.CodeLength != 8 || snap.Policy.MaxAttempts != 2 ||
		snap.Policy.ResendCooldown != 11*time.Second || snap.Policy.PushCooldown != 12*time.Second ||
		snap.Policy.PushPerHour != 1 || snap.Policy.TrustedDeviceTTL != 2*time.Hour ||
		snap.Policy.MaxFail != 1 || snap.Policy.FailWindow != 13*time.Second || snap.Policy.BanTime != 14*time.Second {
		t.Errorf("policy = %+v", snap.Policy)
	}
	if len(snap.Policy.DefaultPrefer) != 1 || snap.Policy.DefaultPrefer[0] != channel.SMS {
		t.Errorf("policy.default_prefer = %v, ожидалось [sms]", snap.Policy.DefaultPrefer)
	}
	if snap.Policy.SessionTTL != time.Hour {
		t.Errorf("web.session_ttl = %s, ожидалось 1h", snap.Policy.SessionTTL)
	}
	// SMS-сырье сохраняется как есть.
	if string(snap.SMS) != `{"method":"POST"}` {
		t.Errorf("sms.gateway raw = %s", snap.SMS)
	}
	if string(snap.SMSPresets) != `{"smsc":{"x":1}}` {
		t.Errorf("sms.presets raw = %s", snap.SMSPresets)
	}
}

// TestBuildTFallback: битые длительности/числа/типы -> дефолты, без паники.
func TestBuildTFallback(t *testing.T) {
	raw := map[string]json.RawMessage{
		"listen.http":              json.RawMessage(`8080`),                           // не строка
		"radius.fail_window":       json.RawMessage(`"не-длительность"`),              // битая duration
		"radius.push_wait":         json.RawMessage(`12`),                             // число вместо duration
		"radius.max_fail_per_user": json.RawMessage(`"много"`),                        // строка вместо int
		"radius.code_lengths":      json.RawMessage(`"6"`),                            // не массив
		"radius.reply_attributes":  json.RawMessage(`[1,2]`),                          // не объект
		"smtp":                     json.RawMessage(`{битый json`),                    // битый объект
		"totp":                     json.RawMessage(`{"digits":"шесть","issuer":42}`), // битые поля
		"policy":                   json.RawMessage(`{"code_ttl":"сломано","code_length":"x","push_per_hour":7,"default_prefer_channels":"not-a-list"}`),
		"web.session_ttl":          json.RawMessage(`"later"`),            // битая duration
		"telegram":                 json.RawMessage(`{"bot_token":true}`), // не строка
	}
	snap := buildT(raw)

	if snap.Listen.HTTP != ":8080" {
		t.Errorf("listen.http после числа = %q, ожидался дефолт", snap.Listen.HTTP)
	}
	if snap.Radius.FailWindow != 5*time.Minute {
		t.Errorf("radius.fail_window = %s, ожидался дефолт 5m", snap.Radius.FailWindow)
	}
	if snap.Radius.PushWait != 20*time.Second {
		t.Errorf("radius.push_wait = %s, ожидался дефолт 20s", snap.Radius.PushWait)
	}
	if snap.Radius.MaxFailPerUser != 10 {
		t.Errorf("radius.max_fail_per_user = %d, ожидался дефолт 10", snap.Radius.MaxFailPerUser)
	}
	if snap.Radius.CodeLengths == nil || len(snap.Radius.CodeLengths) != 2 {
		t.Errorf("radius.code_lengths = %v, ожидался дефолт [6 8]", snap.Radius.CodeLengths)
	}
	if snap.Radius.ReplyAttributes == nil || len(snap.Radius.ReplyAttributes) != 0 {
		t.Errorf("radius.reply_attributes = %v, ожидался пустой map", snap.Radius.ReplyAttributes)
	}
	if snap.SMTP.Host != "" || snap.SMTP.Port != 0 || snap.SMTP.Timeout != 0 {
		t.Errorf("smtp после битого JSON = %+v, ожидались нули", snap.SMTP)
	}
	if snap.TOTP.Issuer != "twofa" || snap.TOTP.Digits != 6 {
		t.Errorf("totp после битых полей = %+v, ожидались дефолты", snap.TOTP)
	}
	if snap.Policy.CodeTTL != 5*time.Minute {
		t.Errorf("policy.code_ttl = %s, ожидался дефолт 5m", snap.Policy.CodeTTL)
	}
	if snap.Policy.CodeLength != 6 {
		t.Errorf("policy.code_length = %d, ожидался дефолт 6", snap.Policy.CodeLength)
	}
	if snap.Policy.PushPerHour != 7 {
		t.Errorf("policy.push_per_hour = %d, ожидалось 7 (валидное поле среди битых)", snap.Policy.PushPerHour)
	}
	if len(snap.Policy.DefaultPrefer) != 4 {
		t.Errorf("policy.default_prefer = %v, ожидался дефолт из 4 каналов", snap.Policy.DefaultPrefer)
	}
	if snap.Policy.SessionTTL != 12*time.Hour {
		t.Errorf("web.session_ttl = %s, ожидался дефолт 12h", snap.Policy.SessionTTL)
	}
	if snap.TG.BotToken != "" {
		t.Errorf("telegram.bot_token = %q, ожидался пустой дефолт", snap.TG.BotToken)
	}
	if snap.LDAP.Enabled {
		t.Error("ldap.enabled по умолчанию должен быть выключен")
	}
}

// TestBuildTLDAP: ключ ldap — дефолты, полный разбор и откат битых полей.
func TestBuildTLDAP(t *testing.T) {
	// Дефолты: выключен, AD-ориентированные фильтры, пустые креды.
	def := buildT(map[string]json.RawMessage{})
	if def.LDAP.Enabled || def.LDAP.StartTLS {
		t.Errorf("ldap дефолт: enabled=%v starttls=%v, ожидались false", def.LDAP.Enabled, def.LDAP.StartTLS)
	}
	if def.LDAP.URL != "" || def.LDAP.BindDN != "" || def.LDAP.BindPassword != "" || def.LDAP.BaseDN != "" {
		t.Errorf("ldap дефолт: соединение не пустое: %+v", def.LDAP)
	}
	if def.LDAP.UserFilter != `(&(objectClass=user)(sAMAccountName={login}))` {
		t.Errorf("ldap.user_filter дефолт = %q", def.LDAP.UserFilter)
	}
	if def.LDAP.GroupFilter != `(&(objectClass=group)(member={dn}))` {
		t.Errorf("ldap.group_filter дефолт = %q", def.LDAP.GroupFilter)
	}
	if def.LDAP.GroupBaseDN != "" {
		t.Errorf("ldap.group_base_dn дефолт = %q, ожидался пустой (= base_dn)", def.LDAP.GroupBaseDN)
	}
	if def.LDAP.Attrs.Email != "mail" || def.LDAP.Attrs.Phone != "telephoneNumber" || def.LDAP.Attrs.DisplayName != "displayName" {
		t.Errorf("ldap.attrs дефолт = %+v", def.LDAP.Attrs)
	}
	if len(def.LDAP.AllowGroups) != 0 {
		t.Errorf("ldap.allow_groups дефолт = %v, ожидался пустой", def.LDAP.AllowGroups)
	}
	if len(def.LDAP.RoleMap) != 0 {
		t.Errorf("ldap.role_map дефолт = %v, ожидался пустой", def.LDAP.RoleMap)
	}

	// Полный разбор.
	raw := json.RawMessage(`{"enabled":true,"url":"ldaps://dc1.example.com:636","starttls":true,` +
		`"bind_dn":"CN=svc,DC=example,DC=com","bind_password":"pw","base_dn":"DC=example,DC=com",` +
		`"user_filter":"(uid={login})","group_base_dn":"OU=Groups,DC=example,DC=com",` +
		`"group_filter":"(member={dn})","attrs":{"email":"mail","phone":"mobile","display_name":"cn"},` +
		`"allow_groups":["CN=VPN-Users,DC=example,DC=com"],"role_map":{"CN=VPN-Admins,DC=example,DC=com":"admin"}}`)
	snap := buildT(map[string]json.RawMessage{"ldap": raw})
	if !snap.LDAP.Enabled || !snap.LDAP.StartTLS || snap.LDAP.URL != "ldaps://dc1.example.com:636" ||
		snap.LDAP.BindDN != "CN=svc,DC=example,DC=com" || snap.LDAP.BindPassword != "pw" ||
		snap.LDAP.BaseDN != "DC=example,DC=com" || snap.LDAP.UserFilter != "(uid={login})" ||
		snap.LDAP.GroupBaseDN != "OU=Groups,DC=example,DC=com" || snap.LDAP.GroupFilter != "(member={dn})" {
		t.Errorf("ldap разбор = %+v", snap.LDAP)
	}
	if snap.LDAP.Attrs.Email != "mail" || snap.LDAP.Attrs.Phone != "mobile" || snap.LDAP.Attrs.DisplayName != "cn" {
		t.Errorf("ldap.attrs = %+v", snap.LDAP.Attrs)
	}
	if len(snap.LDAP.AllowGroups) != 1 || snap.LDAP.AllowGroups[0] != "CN=VPN-Users,DC=example,DC=com" {
		t.Errorf("ldap.allow_groups = %v", snap.LDAP.AllowGroups)
	}
	if snap.LDAP.RoleMap["CN=VPN-Admins,DC=example,DC=com"] != "admin" {
		t.Errorf("ldap.role_map = %v", snap.LDAP.RoleMap)
	}

	// Битые поля откатываются к дефолтам, валидные сохраняются.
	snap = buildT(map[string]json.RawMessage{
		"ldap": json.RawMessage(`{"enabled":"да","url":42,"attrs":{"email":7},"allow_groups":"nope","role_map":[1]}`),
	})
	if snap.LDAP.Enabled || snap.LDAP.URL != "" || snap.LDAP.Attrs.Email != "mail" ||
		len(snap.LDAP.AllowGroups) != 0 || len(snap.LDAP.RoleMap) != 0 {
		t.Errorf("ldap после битых полей = %+v, ожидались дефолты", snap.LDAP)
	}
}

// TestParseDur/parseInt/parseString — точечные проверки хелперов.
func TestParseHelpers(t *testing.T) {
	if got := parseDur(json.RawMessage(`"1h30m"`), time.Second); got != 90*time.Minute {
		t.Errorf("parseDur(1h30m) = %s", got)
	}
	if got := parseDur(json.RawMessage(`"junk"`), 5*time.Second); got != 5*time.Second {
		t.Errorf("parseDur(junk) = %s, ожидался дефолт", got)
	}
	if got := parseDur(nil, 5*time.Second); got != 5*time.Second {
		t.Errorf("parseDur(nil) = %s, ожидался дефолт", got)
	}
	if got := parseDur(json.RawMessage(`17`), 5*time.Second); got != 5*time.Second {
		t.Errorf("parseDur(17) = %s, ожидался дефолт", got)
	}
	if got := parseInt(json.RawMessage(`42`), 1); got != 42 {
		t.Errorf("parseInt(42) = %d", got)
	}
	if got := parseInt(json.RawMessage(`"x"`), 9); got != 9 {
		t.Errorf("parseInt(x) = %d, ожидался дефолт", got)
	}
	if got := parseInt(nil, 9); got != 9 {
		t.Errorf("parseInt(nil) = %d, ожидался дефолт", got)
	}
	if got := parseString(json.RawMessage(`":1812"`), "d"); got != ":1812" {
		t.Errorf("parseString = %q", got)
	}
	if got := parseString(json.RawMessage(`123`), "d"); got != "d" {
		t.Errorf("parseString(123) = %q, ожидался дефолт", got)
	}
}

// TestBuildTNullValues: JSON null в БД означает «значение не задано» и
// обязан откатываться к дефолту. json.Unmarshal("null", &v) — no-op без
// ошибки, поэтому без явной проверки null возвращал нулевое значение
// (например listen.http == "" вместо ":8080").
func TestBuildTNullValues(t *testing.T) {
	raw := map[string]json.RawMessage{
		"listen.http":              json.RawMessage(`null`),
		"listen.radius_auth":       json.RawMessage(`null`),
		"radius.max_fail_per_user": json.RawMessage(`null`),
		"radius.fail_window":       json.RawMessage(`null`),
		"radius.code_lengths":      json.RawMessage(`null`),
		"radius.reply_attributes":  json.RawMessage(`null`),
		"totp":                     json.RawMessage(`{"skew":null,"issuer":null,"digits":null,"period":null}`),
		"smtp":                     json.RawMessage(`{"starttls":null,"port":null,"timeout":null}`),
		"policy":                   json.RawMessage(`{"default_prefer_channels":null,"code_ttl":null,"code_length":null,"max_attempts":null}`),
		"web.session_ttl":          json.RawMessage(`null`),
	}
	snap := buildT(raw)

	if snap.Listen.HTTP != ":8080" {
		t.Errorf("listen.http(null) = %q, ожидался дефолт :8080", snap.Listen.HTTP)
	}
	if snap.Listen.RadiusAuth != ":1812" {
		t.Errorf("listen.radius_auth(null) = %q, ожидался дефолт :1812", snap.Listen.RadiusAuth)
	}
	if snap.Radius.MaxFailPerUser != 10 {
		t.Errorf("radius.max_fail_per_user(null) = %d, ожидался дефолт 10", snap.Radius.MaxFailPerUser)
	}
	if snap.Radius.FailWindow != 5*time.Minute {
		t.Errorf("radius.fail_window(null) = %s, ожидался дефолт 5m", snap.Radius.FailWindow)
	}
	if len(snap.Radius.CodeLengths) != 2 || snap.Radius.CodeLengths[0] != 6 || snap.Radius.CodeLengths[1] != 8 {
		t.Errorf("radius.code_lengths(null) = %v, ожидался дефолт [6 8]", snap.Radius.CodeLengths)
	}
	if snap.Radius.ReplyAttributes == nil {
		t.Error("radius.reply_attributes(null) = nil, ожидался пустой map")
	}
	if snap.TOTP.Issuer != "twofa" || snap.TOTP.Digits != 6 || snap.TOTP.Period != 30 || snap.TOTP.Skew != 1 {
		t.Errorf("totp(null-поля) = %+v, ожидались дефолты", snap.TOTP)
	}
	if snap.SMTP.StartTLS {
		t.Error("smtp.starttls(null) = true, ожидался дефолт false")
	}
	if snap.SMTP.Port != 0 || snap.SMTP.Timeout != 0 {
		t.Errorf("smtp(null-поля) = %+v, ожидались нулевые дефолты", snap.SMTP)
	}
	want := []channel.Channel{channel.TOTP, channel.Telegram, channel.Email, channel.SMS}
	if len(snap.Policy.DefaultPrefer) != len(want) {
		t.Fatalf("policy.default_prefer(null) = %v, ожидался дефолт %v", snap.Policy.DefaultPrefer, want)
	}
	for i, c := range want {
		if snap.Policy.DefaultPrefer[i] != c {
			t.Errorf("policy.default_prefer[%d] = %q, ожидалось %q", i, snap.Policy.DefaultPrefer[i], c)
		}
	}
	if snap.Policy.CodeTTL != 5*time.Minute || snap.Policy.CodeLength != 6 || snap.Policy.MaxAttempts != 5 {
		t.Errorf("policy(null-поля) = %+v, ожидались дефолты", snap.Policy)
	}
	if snap.Policy.SessionTTL != 12*time.Hour {
		t.Errorf("web.session_ttl(null) = %s, ожидался дефолт 12h", snap.Policy.SessionTTL)
	}
}

// TestParseHelpersNull: null на входе любого парсера — как отсутствие
// значения: возвращается дефолт, а не нулевое значение типа.
func TestParseHelpersNull(t *testing.T) {
	if got := parseString(json.RawMessage(`null`), ":8080"); got != ":8080" {
		t.Errorf("parseString(null) = %q, ожидался дефолт", got)
	}
	if got := parseInt(json.RawMessage(`null`), 10); got != 10 {
		t.Errorf("parseInt(null) = %d, ожидался дефолт", got)
	}
	if got := parseUint(json.RawMessage(`null`), 1); got != 1 {
		t.Errorf("parseUint(null) = %d, ожидался дефолт", got)
	}
	if got := parseBool(json.RawMessage(`null`), true); got != true {
		t.Errorf("parseBool(null) = %v, ожидался дефолт true", got)
	}
	if got := parseBool(json.RawMessage(`null`), false); got != false {
		t.Errorf("parseBool(null) = %v, ожидался дефолт false", got)
	}
	if got := parseDur(json.RawMessage(`null`), 5*time.Minute); got != 5*time.Minute {
		t.Errorf("parseDur(null) = %s, ожидался дефолт", got)
	}
	if got := parseInts(json.RawMessage(`null`), []int{6, 8}); len(got) != 2 {
		t.Errorf("parseInts(null) = %v, ожидался дефолт", got)
	}
	if got := parseStringMap(json.RawMessage(`null`), map[string]string{}); got == nil {
		t.Error("parseStringMap(null) = nil, ожидался пустой map")
	}
	// Пустой массив каналов — как отсутствующее значение: дефолтный список.
	def := []channel.Channel{channel.TOTP, channel.Telegram, channel.Email, channel.SMS}
	if got := parseChannels(json.RawMessage(`null`), def); len(got) != 4 {
		t.Errorf("parseChannels(null) = %v, ожидался дефолт", got)
	}
	if got := parseChannels(json.RawMessage(`[]`), def); len(got) != 4 {
		t.Errorf("parseChannels(пустой массив) = %v, ожидался дефолт", got)
	}
}

// TestMaskedUnit: маскировка по key path без БД.
func TestMaskedUnit(t *testing.T) {
	const (
		realMaster = "UkVBTE1BU1RlUi0zMi1ieXRlcy1iYXNlNjQh"
		realAdmin  = "real-admin-token-42"
		realRadSec = "real-radius-secret"
		realPass   = "real-pass"
		realBotTok = "123456:real"
		realSMSTok = "real-sms-token"
		realTwilio = "real-twilio"
		realLdapPw = "real-ldap-bind-password"
	)
	snap := buildT(map[string]json.RawMessage{
		"master_key":    json.RawMessage(`"` + realMaster + `"`),
		"admin_token":   json.RawMessage(`"` + realAdmin + `"`),
		"radius.secret": json.RawMessage(`"` + realRadSec + `"`),
		"smtp":          json.RawMessage(`{"host":"h","password":"` + realPass + `"}`),
		"telegram":      json.RawMessage(`{"bot_token":"` + realBotTok + `"}`),
		"sms.gateway":   json.RawMessage(`{"method":"POST","headers":{"Authorization":"Bearer ` + realSMSTok + `","X-Ok":"visible"},"success":{"http_status":200}}`),
		"sms.presets":   json.RawMessage(`{"twilio":{"sid":"` + realTwilio + `","token":"` + realTwilio + `"}}`),
		"ldap":          json.RawMessage(`{"enabled":true,"url":"ldap://d","bind_dn":"CN=svc","bind_password":"` + realLdapPw + `"}`),
	})

	// Креды всех пресетов шлюзов маскируются (SEC-004): login/psw (smsc,
	// prostor), auth_base64 (smsaero), project/api_key/api_id (mainsms,
	// unisender, smsru), id/key (bytehand), sid/token (twilio),
	// device_id/token (smsgateway24).
	presetCreds := map[string]string{
		"login":       "real-login",
		"psw":         "real-psw",
		"password":    "real-pass2",
		"auth_base64": "real-auth-b64",
		"project":     "real-project",
		"api_key":     "real-api-key",
		"api_id":      "real-api-id",
		"id":          "real-id",
		"key":         "real-key",
		"device_id":   "real-device",
	}
	hdr := make(map[string]string, len(presetCreds))
	for k, v := range presetCreds {
		hdr[k] = v
	}
	hdr["sender"] = "open-sender" // не кред
	snapCreds := buildT(map[string]json.RawMessage{
		"sms.gateway": json.RawMessage(func() string {
			b, _ := json.Marshal(map[string]any{"headers": hdr})
			return string(b)
		}()),
	})
	dumpCreds, err := json.Marshal(snapCreds.masked())
	if err != nil {
		t.Fatalf("Marshal(masked creds): %v", err)
	}
	sc := string(dumpCreds)
	for k, v := range presetCreds {
		if strings.Contains(sc, v) {
			t.Errorf("кред %q (%s) попал в Masked-дамп: %s", v, k, sc)
		}
	}
	if !strings.Contains(sc, "open-sender") {
		t.Errorf("sender не кред и должен оставаться открытым: %s", sc)
	}

	masked := snap.masked()
	dump, err := json.Marshal(masked)
	if err != nil {
		t.Fatalf("Marshal(masked): %v", err)
	}
	s := string(dump)
	for name, secret := range map[string]string{
		"master_key":         realMaster,
		"admin_token":        realAdmin,
		"radius.secret":      realRadSec,
		"smtp.password":      realPass,
		"bot_token":          realBotTok,
		"sms.auth":           realSMSTok,
		"sms.twilio":         realTwilio,
		"ldap.bind_password": realLdapPw,
	} {
		if strings.Contains(s, secret) {
			t.Errorf("секрет %q попал в Masked-дамп: %s", name, s)
		}
	}

	maskObj := func(path string, v any) map[string]any {
		t.Helper()
		mm, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("%s: не объект маски: %#v", path, v)
		}
		if mm["value"] != maskValue {
			t.Errorf("%s: value = %#v, ожидалось %q", path, mm["value"], maskValue)
		}
		if set, _ := mm["set"].(bool); !set {
			t.Errorf("%s: set = false, ожидалось true", path)
		}
		return mm
	}
	maskObj("master_key", masked["master_key"])
	maskObj("admin_token", masked["admin_token"])
	radius := masked["radius"].(map[string]any)
	maskObj("radius.secret", radius["secret"])
	smtp := masked["smtp"].(map[string]any)
	maskObj("smtp.password", smtp["password"])
	if smtp["host"] != "h" {
		t.Errorf("smtp.host = %#v, ожидался открытым", smtp["host"])
	}
	ldapSec := masked["ldap"].(map[string]any)
	maskObj("ldap.bind_password", ldapSec["bind_password"])
	if ldapSec["url"] != "ldap://d" || ldapSec["enabled"] != true {
		t.Errorf("ldap.url/enabled = %#v/%#v, ожидались открытыми", ldapSec["url"], ldapSec["enabled"])
	}
	tg := masked["telegram"].(map[string]any)
	maskObj("telegram.bot_token", tg["bot_token"])
	sms := masked["sms"].(map[string]any)
	gw := sms["gateway"].(map[string]any)
	headers := gw["headers"].(map[string]any)
	maskObj("sms.gateway.headers.Authorization", headers["Authorization"])
	if headers["X-Ok"] != "visible" {
		t.Errorf("X-Ok = %#v, ожидался открытым", headers["X-Ok"])
	}
	if gw["method"] != "POST" {
		t.Errorf("sms.gateway.method = %#v, ожидался открытым", gw["method"])
	}
	presets := sms["presets"].(map[string]any)
	twilio := presets["twilio"].(map[string]any)
	maskObj("sms.presets.twilio.token", twilio["token"])
	// sid — Account SID Twilio, кред: маскируется (SEC-004).
	maskObj("sms.presets.twilio.sid", twilio["sid"])
}

// TestMaskedJSONTree (SEC-004): pretty-JSON для HTML-формы настроек —
// креды масками-объектами, прочие поля как есть; мерж таких значений
// (mergeSettingMap/isNoChangeValue в api) трактует их как «не менять».
func TestMaskedJSONTree(t *testing.T) {
	raw := json.RawMessage(`{"preset":"smsc","method":"GET","url":"https://x/y","headers":{"login":"LOG","psw":"PW","sender":"S"},"success":{"http_status":200}}`)
	out := MaskedJSONTree(raw)
	if strings.Contains(out, "LOG") || strings.Contains(out, "PW") {
		t.Fatalf("MaskedJSONTree раскрыл креды: %s", out)
	}
	for _, want := range []string{`"preset": "smsc"`, `"method": "GET"`, `"sender": "S"`, maskValue} {
		if !strings.Contains(out, want) {
			t.Fatalf("MaskedJSONTree потерял %q: %s", want, out)
		}
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("разбор MaskedJSONTree: %v", err)
	}
}

// TestMaskedEmptySecret: пустой секрет -> set=false.
func TestMaskedEmptySecret(t *testing.T) {
	snap := buildT(nil) // всё дефолтное: секреты пустые, кроме отсутствующих сгенерированных
	masked := snap.masked()
	smtp := masked["smtp"].(map[string]any)
	mm, ok := smtp["password"].(map[string]any)
	if !ok {
		t.Fatalf("smtp.password не объект маски: %#v", smtp["password"])
	}
	if set, _ := mm["set"].(bool); set {
		t.Error("smtp.password: set=true при пустом пароле, ожидалось false")
	}
	if mm["value"] != maskValue {
		t.Errorf("smtp.password: value = %#v", mm["value"])
	}
	tg := masked["telegram"].(map[string]any)
	if mm, _ := tg["bot_token"].(map[string]any); mm != nil && mm["set"] == true {
		t.Error("telegram.bot_token: set=true при пустом токене")
	}
	// master_key/admin_token/radius.secret при пустых значениях тоже set=false.
	for _, k := range []string{"master_key", "admin_token"} {
		if mm, _ := masked[k].(map[string]any); mm != nil && mm["set"] == true {
			t.Errorf("%s: set=true при пустом значении", k)
		}
	}
}

// TestSMSGatewayMethod: метод снимка декодирует конфиг шлюза.
func TestSMSGatewayMethod(t *testing.T) {
	snap := buildT(map[string]json.RawMessage{
		"sms.gateway": json.RawMessage(`{"preset":"smsc","method":"GET","url":"https://x/y","headers":{"A":"b"},"body":"b","content_type":"text/plain","success":{"http_status":200,"body_contains":"OK","json_path":"$.status","equals":"ok"}}`),
	})
	gw, err := snap.SMSGateway()
	if err != nil {
		t.Fatalf("SMSGateway: %v", err)
	}
	if gw.Preset != "smsc" || gw.Method != "GET" || gw.URL != "https://x/y" ||
		gw.Body != "b" || gw.ContentType != "text/plain" || gw.Headers["A"] != "b" {
		t.Errorf("gateway = %+v", gw)
	}
	if gw.Success.HTTPStatus != 200 || gw.Success.BodyContains != "OK" ||
		gw.Success.JSONPath != "$.status" || gw.Success.Equals != "ok" {
		t.Errorf("success = %+v", gw.Success)
	}

	// Пустой/нулевый SMS -> нулевой конфиг без ошибки.
	empty := buildT(nil)
	if _, err := empty.SMSGateway(); err != nil {
		t.Errorf("SMSGateway на пустом SMS: %v", err)
	}

	// Битый JSON -> ошибка.
	bad := buildT(map[string]json.RawMessage{"sms.gateway": json.RawMessage(`{broken`)})
	if _, err := bad.SMSGateway(); err == nil {
		t.Error("SMSGateway на битом JSON должен вернуть ошибку")
	}
}

// TestDefaultsConsistent: статические дефолты из defaults.go и дефолты
// парсера (defaultT) дают одинаковый снимок — двойного источника правды нет.
func TestDefaultsConsistent(t *testing.T) {
	fromDB := buildT(defaults)
	fromCode := buildT(nil)
	a, err := json.Marshal(fromDB)
	if err != nil {
		t.Fatalf("Marshal(buildT(defaults)): %v", err)
	}
	b, err := json.Marshal(fromCode)
	if err != nil {
		t.Fatalf("Marshal(buildT(nil)): %v", err)
	}
	if string(a) != string(b) {
		t.Errorf("дефолты из defaults.go и дефолты парсера расходятся:\nБД:     %s\nпарсер: %s", a, b)
	}
}

// TestDefaultsCoverKnownKeys: каждый известный ключ имеет либо статический
// дефолт, либо генератор; и никаких посторонних ключей.
func TestDefaultsCoverKnownKeys(t *testing.T) {
	for k := range generatedKeys {
		if _, ok := defaults[k]; ok {
			t.Errorf("ключ %q и в defaults, и в generatedKeys", k)
		}
	}
	want := []string{
		"listen.http", "listen.radius_auth", "listen.radius_acct",
		"server.domain", "messages", "fail2ban", "ads", "branding",
		"master_key", "admin_token",
		"radius.secret", "radius.code_lengths", "radius.max_fail_per_user",
		"radius.fail_window", "radius.push_wait", "radius.reply_attributes",
		"smtp", "sms.gateway", "sms.presets", "totp", "telegram", "webauthn",
		"policy", "web.session_ttl", "ldap", "oidc.keys",
	}
	if len(knownKeys) != len(want) {
		t.Fatalf("knownKeys: %d ключей, ожидалось %d (%v)", len(knownKeys), len(want), knownKeys)
	}
	for _, k := range want {
		if !isKnownKey(k) {
			t.Errorf("ключ %q отсутствует в knownKeys", k)
		}
		if _, hasDef := defaults[k]; !hasDef {
			if _, hasGen := generatedKeys[k]; !hasGen {
				t.Errorf("ключ %q не имеет ни дефолта, ни генератора", k)
			}
		}
	}
	// Дефолты — валидный JSON.
	for k, v := range defaults {
		if !json.Valid(v) {
			t.Errorf("дефолт ключа %q не является валидным JSON: %s", k, v)
		}
	}
}

// TestIsKnownKeyExported: экспортированная обёртка IsKnownKey зеркалит
// isKnownKey — API-слой валидирует ключи PUT /settings до применения.
func TestIsKnownKeyExported(t *testing.T) {
	for _, k := range []string{"totp", "smtp", "policy", "web.session_ttl", "admin_token", "master_key", "radius.secret"} {
		if !IsKnownKey(k) {
			t.Errorf("IsKnownKey(%q) = false, want true", k)
		}
		if isKnownKey(k) != IsKnownKey(k) {
			t.Errorf("IsKnownKey(%q) расходится с isKnownKey", k)
		}
	}
	for _, k := range []string{"", "no-such-key", "totp.issuer", "smtp.host", "TOTP"} {
		if IsKnownKey(k) {
			t.Errorf("IsKnownKey(%q) = true, want false", k)
		}
	}
}
