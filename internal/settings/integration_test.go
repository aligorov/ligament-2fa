//go:build integration

// Интеграционный тест настроек: требует Docker (testcontainers-go,
// postgres:16-alpine). Запуск: go test -tags integration ./internal/settings/
package settings

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/aligorov/twofa/internal/channel"
	"github.com/aligorov/twofa/internal/store"
)

func dockerAvailable() bool {
	return exec.Command("docker", "info").Run() == nil
}

// startPG поднимает ephemeral postgres и применяет миграции.
func startPG(t *testing.T) *store.Store {
	t.Helper()
	if !dockerAvailable() {
		t.Skip("docker недоступен (docker info завершается с ошибкой) — интеграционный тест пропущен")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	pg, err := tcpostgres.RunContainer(ctx,
		testcontainers.WithImage("postgres:16-alpine"),
		tcpostgres.WithDatabase("twofa"),
		tcpostgres.WithUsername("twofa"),
		tcpostgres.WithPassword("twofa"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("запуск testcontainer postgres: %v", err)
	}
	dsn, err := pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("получение DSN: %v", err)
	}
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := st.Migrate(ctx); err != nil {
		st.Close()
		t.Fatalf("Migrate: %v", err)
	}
	t.Cleanup(func() {
		st.Close()
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer stopCancel()
		if err := pg.Terminate(stopCtx); err != nil {
			t.Logf("остановка контейнера: %v", err)
		}
	})
	return st
}

// TestSettingsFirstLoad проверяет первый Load на пустой БД: генерация
// master_key/admin_token/radius.secret, запись дефолтов, стабильность
// при повторном чтении.
func TestSettingsFirstLoad(t *testing.T) {
	st := startPG(t)
	ctx := context.Background()

	m, err := NewManager(ctx, st)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	snap := m.Get()
	if snap == nil {
		t.Fatal("Get() вернул nil после NewManager")
	}

	// master_key — валидный base64 ровно 32 байта.
	key, err := base64.StdEncoding.Strict().DecodeString(snap.MasterKeyB64)
	if err != nil {
		t.Fatalf("master_key не является строгим base64: %v (значение %q)", err, snap.MasterKeyB64)
	}
	if len(key) != 32 {
		t.Fatalf("master_key декодируется в %d байт, нужно 32", len(key))
	}
	if snap.AdminToken == "" {
		t.Error("admin_token пуст после первого старта")
	}
	if snap.RadiusSecret == "" {
		t.Error("radius.secret пуст после первого старта")
	}

	// Дефолты из спеки §8/§10.
	if snap.Listen.HTTP != ":8080" {
		t.Errorf("listen.http = %q, ожидалось :8080", snap.Listen.HTTP)
	}
	if snap.Listen.RadiusAuth != ":1812" {
		t.Errorf("listen.radius_auth = %q, ожидалось :1812", snap.Listen.RadiusAuth)
	}
	if snap.Listen.RadiusAcct != ":1813" {
		t.Errorf("listen.radius_acct = %q, ожидалось :1813", snap.Listen.RadiusAcct)
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
	if snap.TOTP.Issuer != "twofa" || snap.TOTP.Digits != 6 || snap.TOTP.Period != 30 || snap.TOTP.Skew != 1 {
		t.Errorf("totp = %+v, ожидалось issuer=twofa digits=6 period=30 skew=1", snap.TOTP)
	}
	if snap.Policy.CodeTTL != 5*time.Minute {
		t.Errorf("policy.code_ttl = %s, ожидалось 5m", snap.Policy.CodeTTL)
	}
	if snap.Policy.ResendCooldown != 60*time.Second {
		t.Errorf("policy.resend_cooldown = %s, ожидалось 60s", snap.Policy.ResendCooldown)
	}
	if snap.Policy.PushCooldown != 30*time.Second {
		t.Errorf("policy.push_cooldown = %s, ожидалось 30s", snap.Policy.PushCooldown)
	}
	if snap.Policy.TrustedDeviceTTL != 720*time.Hour {
		t.Errorf("policy.trusted_device_ttl = %s, ожидалось 720h", snap.Policy.TrustedDeviceTTL)
	}
	if snap.Policy.SessionTTL != 12*time.Hour {
		t.Errorf("web.session_ttl = %s, ожидалось 12h", snap.Policy.SessionTTL)
	}
	if snap.Policy.FailWindow != 5*time.Minute {
		t.Errorf("policy.fail_window = %s, ожидалось 5m", snap.Policy.FailWindow)
	}
	if snap.Policy.BanTime != 15*time.Minute {
		t.Errorf("policy.ban_time = %s, ожидалось 15m", snap.Policy.BanTime)
	}
	if snap.Policy.CodeLength != 6 || snap.Policy.MaxAttempts != 5 || snap.Policy.PushPerHour != 10 || snap.Policy.MaxFail != 5 {
		t.Errorf("policy ints = len:%d att:%d push:%d fail:%d, ожидалось 6/5/10/5",
			snap.Policy.CodeLength, snap.Policy.MaxAttempts, snap.Policy.PushPerHour, snap.Policy.MaxFail)
	}
	wantPrefer := []channel.Channel{channel.TOTP, channel.Telegram, channel.Email, channel.SMS}
	if len(snap.Policy.DefaultPrefer) != len(wantPrefer) {
		t.Errorf("policy.default_prefer_channels = %v, ожидалось %v", snap.Policy.DefaultPrefer, wantPrefer)
	} else {
		for i, c := range wantPrefer {
			if snap.Policy.DefaultPrefer[i] != c {
				t.Errorf("policy.default_prefer_channels[%d] = %q, ожидалось %q", i, snap.Policy.DefaultPrefer[i], c)
			}
		}
	}

	// Повторный Load: сгенерированные значения стабильны.
	if err := m.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	snap2 := m.Get()
	if snap2.MasterKeyB64 != snap.MasterKeyB64 {
		t.Error("master_key изменился при повторном Load")
	}
	if snap2.AdminToken != snap.AdminToken {
		t.Error("admin_token изменился при повторном Load")
	}
	if snap2.RadiusSecret != snap.RadiusSecret {
		t.Error("radius.secret изменился при повторном Load")
	}

	// Load напрямую (вне менеджера) тоже стабилен.
	snap3, err := Load(ctx, st)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if snap3.AdminToken != snap.AdminToken || snap3.MasterKeyB64 != snap.MasterKeyB64 || snap3.RadiusSecret != snap.RadiusSecret {
		t.Error("прямой Load вернул другие сгенерированные значения")
	}
}

// TestSettingsPut проверяет точечную запись ключа и обновление снимка.
func TestSettingsPut(t *testing.T) {
	st := startPG(t)
	ctx := context.Background()

	m, err := NewManager(ctx, st)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	before := m.Get().SMTP.Host

	smtpJSON := json.RawMessage(`{"host":"smtp.example.com","port":587,"starttls":true,"user":"u1","password":"hunter2","from":"2fa@example.com","subject":"Код","timeout":"10s"}`)
	if err := m.Put(ctx, "smtp", smtpJSON); err != nil {
		t.Fatalf("Put(smtp): %v", err)
	}
	after := m.Get()
	if after.SMTP.Host != "smtp.example.com" {
		t.Errorf("smtp.host = %q (был %q), ожидался smtp.example.com", after.SMTP.Host, before)
	}
	if after.SMTP.Port != 587 || !after.SMTP.StartTLS || after.SMTP.User != "u1" ||
		after.SMTP.Password != "hunter2" || after.SMTP.From != "2fa@example.com" || after.SMTP.Subject != "Код" {
		t.Errorf("smtp = %+v, ожидались значения из Put", after.SMTP)
	}
	if after.SMTP.Timeout != 10*time.Second {
		t.Errorf("smtp.timeout = %s, ожидалось 10s", after.SMTP.Timeout)
	}

	// Неизвестный ключ отклоняется, битый JSON отклоняется.
	if err := m.Put(ctx, "no.such_key", json.RawMessage(`"x"`)); err == nil {
		t.Error("Put с неизвестным ключом должен возвращать ошибку")
	}
	if err := m.Put(ctx, "totp", json.RawMessage(`{broken`)); err == nil {
		t.Error("Put с невалидным JSON должен возвращать ошибку")
	}

	// Повторный менеджер на той же БД читает записанное значение.
	m2, err := NewManager(ctx, st)
	if err != nil {
		t.Fatalf("NewManager (второй): %v", err)
	}
	if m2.Get().SMTP.Host != "smtp.example.com" {
		t.Errorf("второй менеджер видит smtp.host = %q, ожидался smtp.example.com", m2.Get().SMTP.Host)
	}
}

// TestSettingsFallback: битые duration/int в БД -> дефолт, без ошибки.
func TestSettingsFallback(t *testing.T) {
	st := startPG(t)
	ctx := context.Background()

	m, err := NewManager(ctx, st)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	// Валидный JSON, но недопустимые значения полей.
	if err := m.Put(ctx, "radius.fail_window", json.RawMessage(`"не-длительность"`)); err != nil {
		t.Fatalf("Put(radius.fail_window): %v", err)
	}
	if err := m.Put(ctx, "web.session_ttl", json.RawMessage(`42`)); err != nil {
		t.Fatalf("Put(web.session_ttl): %v", err)
	}
	if err := m.Put(ctx, "radius.max_fail_per_user", json.RawMessage(`"много"`)); err != nil {
		t.Fatalf("Put(radius.max_fail_per_user): %v", err)
	}
	if err := m.Put(ctx, "policy", json.RawMessage(`{"code_ttl":"сломано","code_length":"не-число","push_per_hour":3}`)); err != nil {
		t.Fatalf("Put(policy): %v", err)
	}

	snap := m.Get()
	if snap.Radius.FailWindow != 5*time.Minute {
		t.Errorf("radius.fail_window после битого значения = %s, ожидался дефолт 5m", snap.Radius.FailWindow)
	}
	if snap.Policy.SessionTTL != 12*time.Hour {
		t.Errorf("web.session_ttl после битого значения = %s, ожидался дефолт 12h", snap.Policy.SessionTTL)
	}
	if snap.Radius.MaxFailPerUser != 10 {
		t.Errorf("radius.max_fail_per_user после битого значения = %d, ожидался дефолт 10", snap.Radius.MaxFailPerUser)
	}
	if snap.Policy.CodeTTL != 5*time.Minute {
		t.Errorf("policy.code_ttl после битого значения = %s, ожидался дефолт 5m", snap.Policy.CodeTTL)
	}
	if snap.Policy.CodeLength != 6 {
		t.Errorf("policy.code_length после битого значения = %d, ожидался дефолт 6", snap.Policy.CodeLength)
	}
	// Корректные поля того же объекта читаются.
	if snap.Policy.PushPerHour != 3 {
		t.Errorf("policy.push_per_hour = %d, ожидалось 3 (валидное поле)", snap.Policy.PushPerHour)
	}
}

// TestSettingsMasked: секреты маскируются, реальных значений в дамке нет.
func TestSettingsMasked(t *testing.T) {
	st := startPG(t)
	ctx := context.Background()

	m, err := NewManager(ctx, st)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	realToken := m.Get().AdminToken
	realKey := m.Get().MasterKeyB64
	realSecret := m.Get().RadiusSecret
	if realToken == "" || realKey == "" || realSecret == "" {
		t.Fatal("сгенерированные секреты пусты")
	}

	// Настроить smtp и sms с секретами.
	if err := m.Put(ctx, "smtp", json.RawMessage(`{"host":"smtp.example.com","port":587,"password":"hunter2"}`)); err != nil {
		t.Fatalf("Put(smtp): %v", err)
	}
	if err := m.Put(ctx, "telegram", json.RawMessage(`{"bot_token":"123456:ABC-DEF"}`)); err != nil {
		t.Fatalf("Put(telegram): %v", err)
	}
	if err := m.Put(ctx, "sms.gateway", json.RawMessage(`{"method":"POST","url":"https://sms.example.com/send","headers":{"Authorization":"Bearer tok-321","X-Trail":"ok"},"success":{"http_status":200}}`)); err != nil {
		t.Fatalf("Put(sms.gateway): %v", err)
	}
	if err := m.Put(ctx, "sms.presets", json.RawMessage(`{"twilio":{"token":"SK9999"}}`)); err != nil {
		t.Fatalf("Put(sms.presets): %v", err)
	}

	masked, err := m.Masked(ctx)
	if err != nil {
		t.Fatalf("Masked: %v", err)
	}
	dump, err := json.Marshal(masked)
	if err != nil {
		t.Fatalf("Marshal(masked): %v", err)
	}
	s := string(dump)

	// Ни один реальный секрет не встречается в дамке.
	for name, secret := range map[string]string{
		"admin_token":   realToken,
		"master_key":    realKey,
		"radius.secret": realSecret,
		"smtp.password": "hunter2",
		"bot_token":     "123456:ABC-DEF",
		"sms.auth":      "tok-321",
		"sms.preset":    "SK9999",
	} {
		if secret != "" && strings.Contains(s, secret) {
			t.Errorf("реальное значение %s попало в Masked-дамп", name)
		}
	}

	// Точечная структура масок.
	assertMask := func(v any, keyPath string) {
		t.Helper()
		mm, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("%s: значение не является объектом маски: %#v", keyPath, v)
		}
		if mm["value"] != maskValue {
			t.Errorf("%s: mask value = %#v, ожидалось %q", keyPath, mm["value"], maskValue)
		}
		set, ok := mm["set"].(bool)
		if !ok {
			t.Fatalf("%s: флаг set не bool: %#v", keyPath, mm["set"])
		}
		if !set {
			t.Errorf("%s: set = false, ожидалось true (секрет задан)", keyPath)
		}
	}
	radius, _ := masked["radius"].(map[string]any)
	if radius == nil {
		t.Fatal("нет объекта radius в Masked")
	}
	assertMask(masked["admin_token"], "admin_token")
	assertMask(masked["master_key"], "master_key")
	assertMask(radius["secret"], "radius.secret")
	smtp, _ := masked["smtp"].(map[string]any)
	if smtp == nil {
		t.Fatal("нет объекта smtp в Masked")
	}
	assertMask(smtp["password"], "smtp.password")
	if smtp["host"] != "smtp.example.com" {
		t.Errorf("smtp.host в Masked = %#v, ожидался открытым", smtp["host"])
	}
	tg, _ := masked["telegram"].(map[string]any)
	if tg == nil {
		t.Fatal("нет объекта telegram в Masked")
	}
	assertMask(tg["bot_token"], "telegram.bot_token")

	// Маскировка SMS по key path: Authorization скрыт, прочие поля открыты.
	sms, _ := masked["sms"].(map[string]any)
	if sms == nil {
		t.Fatal("нет объекта sms в Masked")
	}
	gw, _ := sms["gateway"].(map[string]any)
	if gw == nil {
		t.Fatal("нет объекта sms.gateway в Masked")
	}
	headers, _ := gw["headers"].(map[string]any)
	if headers == nil {
		t.Fatal("нет объекта sms.gateway.headers в Masked")
	}
	assertMask(headers["Authorization"], "sms.gateway.headers.Authorization")
	if headers["X-Trail"] != "ok" {
		t.Errorf("sms.gateway.headers.X-Trail = %#v, ожидался открытым", headers["X-Trail"])
	}
	if gw["url"] != "https://sms.example.com/send" {
		t.Errorf("sms.gateway.url = %#v, ожидался открытым", gw["url"])
	}
	presets, _ := sms["presets"].(map[string]any)
	if presets == nil {
		t.Fatal("нет объекта sms.presets в Masked")
	}
	twilio, _ := presets["twilio"].(map[string]any)
	if twilio == nil {
		t.Fatal("нет объекта sms.presets.twilio в Masked")
	}
	assertMask(twilio["token"], "sms.presets.twilio.token")
}
