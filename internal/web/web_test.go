package web

import (
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/aligorov/twofa/internal/channel"
	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
)

// wantPages — все страницы пакета; тесты ниже опираются на этот набор.
var wantPages = []string{
	"login", "me_profile", "me_totp", "me_backup", "me_telegram",
	"me_passkeys", "me_devices", "admin_users", "admin_audit",
	"admin_challenges", "admin_settings", "error",
}

const (
	testCSRF = "csrf-token-123"
	otpauth  = "otpauth://totp/twofa:admin?issuer=twofa&secret=JBSWY3DPEHPK3PXP&digits=6&period=30"
)

func base(title string) BaseData {
	return BaseData{Title: title, Username: "admin", IsAdmin: true, CSRF: testCSRF}
}

func testUser() store.User {
	uid := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	return store.User{
		ID:             uid,
		Username:       "vasya",
		Role:           "user",
		Enabled:        true,
		Email:          "vasya@example.com",
		Phone:          "+79990001122",
		PreferChannels: []channel.Channel{channel.TOTP, channel.Email},
		RadiusPush:     false,
		RadiusReply:    map[string]string{"Mikrotik-Group": "vpn"},
	}
}

func testSettings() *settings.T {
	s := &settings.T{}
	s.Listen.HTTP = ":8080"
	s.Listen.RadiusAuth = ":1812"
	s.Listen.RadiusAcct = ":1813"
	s.Radius.CodeLengths = []int{6, 8}
	s.Radius.MaxFailPerUser = 10
	s.Radius.FailWindow = 5 * time.Minute
	s.Radius.PushWait = 20 * time.Second
	s.Radius.ReplyAttributes = map[string]string{"Mikrotik-Group": "vpn"}
	s.SMTP.Host = "smtp.example.com"
	s.SMTP.Port = 587
	s.SMTP.StartTLS = true
	s.SMTP.User = "postmaster"
	s.SMTP.Password = "smtp-secret"
	s.SMTP.From = "2fa@example.com"
	s.SMTP.Subject = "Код подтверждения"
	s.SMTP.Timeout = 10 * time.Second
	s.SMS = json.RawMessage(`{"preset":"","method":"POST","url":"https://sms.example/send"}`)
	s.SMSPresets = json.RawMessage(`{"smsc":{"url":"https://smsc.example"}}`)
	s.TOTP.Issuer = "twofa"
	s.TOTP.Digits = 6
	s.TOTP.Period = 30
	s.TOTP.Skew = 1
	s.TG.BotToken = "123456:bot-token"
	s.WebAuthn.RPID = "2fa.example.com"
	s.WebAuthn.RPName = "twofa"
	s.Policy.CodeTTL = 5 * time.Minute
	s.Policy.CodeLength = 6
	s.Policy.MaxAttempts = 5
	s.Policy.ResendCooldown = 60 * time.Second
	s.Policy.PushCooldown = 30 * time.Second
	s.Policy.PushPerHour = 10
	s.Policy.TrustedDeviceTTL = 720 * time.Hour
	s.Policy.SessionTTL = 12 * time.Hour
	s.Policy.MaxFail = 5
	s.Policy.FailWindow = 5 * time.Minute
	s.Policy.BanTime = 15 * time.Minute
	s.Policy.DefaultPrefer = []channel.Channel{channel.TOTP, channel.Telegram, channel.Email, channel.SMS}
	return s
}

func TestNewParsesAllPages(t *testing.T) {
	r, err := New()
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	got := map[string]bool{}
	for _, p := range r.Pages() {
		got[p] = true
	}
	for _, want := range wantPages {
		if !got[want] {
			t.Errorf("страница %q не разобрана; есть: %v", want, r.Pages())
		}
	}
	if len(got) != len(wantPages) {
		t.Errorf("страниц разобрано %d, ожидалось %d (%v)", len(got), len(wantPages), r.Pages())
	}
}

func TestRenderPages(t *testing.T) {
	r := mustNew(t)
	uid := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	chatID := int64(4242)
	pushState := "pending"
	lastUsed := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name string // имя подтеста
		tmpl string // имя шаблона
		data any
		want []string
	}{
		{
			name: "login",
			tmpl: "login",
			data: LoginData{BaseData: BaseData{Title: "Вход"}, Err: "Неверный код", Prefill: "vasya"},
			want: []string{"Вход", `action="/login"`, "Запомнить это устройство", "Код 2FA", "Неверный код", `value="vasya"`},
		},
		{
			name: "me_profile",
			tmpl: "me_profile",
			data: MeProfileData{BaseData: base("Профиль"), User: testUser(),
				TOTPConfirmed: true, TelegramLinked: false, BackupRemaining: 3, PasskeyCount: 1},
			want: []string{
				"Профиль", `action="/me/contacts"`, `action="/me/contacts/send-code"`,
				`action="/me/prefer"`, `action="/me/password"`, `value="totp"`, `value="email"`,
				"Смена пароля", "vasya@example.com", "осталось: 3",
			},
		},
		{
			name: "me_totp_fresh",
			tmpl: "me_totp",
			data: MeTOTPData{BaseData: base("TOTP")},
			want: []string{"TOTP не привязан", `action="/me/totp/enroll"`, "Привязать приложение"},
		},
		{
			name: "me_totp_enrolled",
			tmpl: "me_totp",
			data: MeTOTPData{BaseData: base("TOTP"), OtpauthURL: otpauth},
			// otpauth сравниваем до «&»: html/template экранирует & в &amp;.
			want: []string{"data:image/png;base64,", `action="/me/totp/confirm"`,
				"otpauth://totp/twofa:admin?issuer=twofa", "Шаг 2"},
		},
		{
			name: "me_totp_confirmed",
			tmpl: "me_totp",
			data: MeTOTPData{BaseData: base("TOTP"), Confirmed: true},
			want: []string{"TOTP привязан", `action="/me/totp/delete"`},
		},
		{
			name: "me_backup",
			tmpl: "me_backup",
			data: MeBackupData{BaseData: base("Резервные коды"), Generated: true,
				Codes: []string{"ABCD-EFGH", "IJKL-MNOP"}, Remaining: 2},
			want: []string{"Резервные коды", `action="/me/backup/regenerate"`, "ABCD-EFGH",
				"показываются только один раз"},
		},
		{
			name: "me_telegram_linked",
			tmpl: "me_telegram",
			data: MeTelegramData{BaseData: base("Telegram"), Linked: true, ChatID: &chatID},
			want: []string{"Telegram привязан", `action="/me/telegram/delete"`},
		},
		{
			name: "me_telegram_code",
			tmpl: "me_telegram",
			data: MeTelegramData{BaseData: base("Telegram"), LinkCode: "LINK-7Q4X"},
			want: []string{"LINK-7Q4X", `action="/me/telegram/link"`},
		},
		{
			name: "me_passkeys",
			tmpl: "me_passkeys",
			data: MePasskeysData{BaseData: base("Passkeys"), Creds: []store.WACred{
				{ID: 7, Name: "MacBook · Touch ID", Attachment: "platform"},
				{ID: 9, Attachment: "cross-platform", LastUsedAt: &lastUsed},
			}},
			want: []string{
				`action="/me/webauthn/credentials"`, `action="/me/webauthn/credentials/7/delete"`,
				"twofaRegisterPasskey", "MacBook · Touch ID", "Добавить passkey",
			},
		},
		{
			name: "me_devices",
			tmpl: "me_devices",
			data: MeDevicesData{BaseData: base("Устройства"), Devices: []store.Device{
				{ID: 42, UA: "Mozilla/5.0 (Macintosh)", IP: "203.0.113.5",
					LastSeenAt: lastUsed, ExpiresAt: lastUsed.Add(720 * time.Hour)},
			}},
			want: []string{`action="/me/devices/42/delete"`, "Отозвать", "203.0.113.5", "Mozilla/5.0 (Macintosh)"},
		},
		{
			name: "admin_users",
			tmpl: "admin_users",
			data: AdminUsersData{BaseData: base("Пользователи"),
				Users: []store.User{testUser()}},
			want: []string{
				"Пользователи", `action="/admin/users"`, "Редактировать",
				`href="/admin/users/11111111-1111-1111-1111-111111111111"`,
				"Сброс TOTP", "Сброс passkeys", "Отвязать Telegram", "vasya",
			},
		},
		{
			name: "admin_users_edit",
			tmpl: "admin_users",
			data: AdminUsersData{BaseData: base("Пользователи"),
				Users: []store.User{testUser()}, Edit: ptrUser(testUser()),
				EditReplyJSON: `{"Mikrotik-Group": "vpn"}`},
			want: []string{
				`action="/admin/users/11111111-1111-1111-1111-111111111111"`,
				"Редактирование: vasya", "Mikrotik-Group", "vpn",
			},
		},
		{
			name: "admin_audit",
			tmpl: "admin_audit",
			data: AdminAuditData{BaseData: base("Аудит"), Rows: []store.AuditRow{
				{Ts: lastUsed, Username: "vasya", Event: "login",
					Detail: map[string]any{"ip": "203.0.113.5"}, SrcIP: "203.0.113.5", Result: "ok"},
			}},
			want: []string{"Журнал аудита", "vasya", "login", "203.0.113.5"},
		},
		{
			name: "admin_challenges",
			tmpl: "admin_challenges",
			data: AdminChallengesData{BaseData: base("Challenge"),
				Challenges: []store.Challenge{{
					UserID: uid, Channel: channel.TelegramPush, Purpose: "radius_prefetch",
					PushState: &pushState, ExpiresAt: lastUsed.Add(3 * time.Minute), AttemptsLeft: 5,
				}},
				Usernames: map[uuid.UUID]string{uid: "vasya"}},
			want: []string{"Активные challenge", "vasya", "telegram_push", "radius_prefetch", "pending"},
		},
		{
			name: "admin_settings",
			tmpl: "admin_settings",
			data: AdminSettingsData{BaseData: base("Настройки"), S: testSettings(),
				RadiusSecretSet: true, SMTPPasswordSet: true,
				TGBotTokenSet: true, SMSGatewayJSON: `{"method":"POST"}`,
				SMSPresetsJSON: `{"smsc":{}}`, ReplyAttrsJSON: `{"Mikrotik-Group":"vpn"}`},
			want: []string{
				"нужен перезапуск", "•••• (задано)", "введите новое, чтобы изменить",
				`action="/admin/settings"`, "Перегенерировать секрет",
				"smtp.example.com", "2fa.example.com", "twofa",
			},
		},
		{
			name: "error",
			tmpl: "error",
			data: ErrorData{BaseData: base("Ошибка"), Code: 404, Message: "Страница не найдена"},
			want: []string{"Ошибка 404", "Страница не найдена"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var sb strings.Builder
			if err := r.Render(&sb, tc.tmpl, tc.data); err != nil {
				t.Fatalf("Render(%s): %v", tc.tmpl, err)
			}
			out := sb.String()
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("Render(%s): в выводе нет %q", tc.tmpl, w)
				}
			}
			// Макет: общий для всех авторизованных страниц.
			if !strings.Contains(out, `href="/static/style.css"`) {
				t.Errorf("Render(%s): нет ссылки на style.css", tc.tmpl)
			}
			if !strings.Contains(out, `src="/static/webauthn.js"`) {
				t.Errorf("Render(%s): нет подключения webauthn.js", tc.tmpl)
			}
			// CSRF несут страницы с мутациями (logout и формы); login и
			// error — карточки без форм сессии.
			if tc.tmpl != "login" && tc.tmpl != "error" && !strings.Contains(out, `name="csrf_token"`) {
				t.Errorf("Render(%s): нет CSRF-поля", tc.tmpl)
			}
		})
	}
}

func TestRenderLoginLayoutAnonymous(t *testing.T) {
	r := mustNew(t)
	var sb strings.Builder
	if err := r.Render(&sb, "login", LoginData{}); err != nil {
		t.Fatalf("Render(login): %v", err)
	}
	out := sb.String()
	if strings.Contains(out, `action="/logout"`) {
		t.Error("анонимный логин не должен показывать кнопку выхода")
	}
	if strings.Contains(out, `name="csrf_token"`) {
		t.Error("у формы логина нет CSRF-поля до создания сессии")
	}
}

func TestRenderAdminLogoutAndFlash(t *testing.T) {
	r := mustNew(t)
	bd := base("Профиль")
	bd.Flash = "Контакты сохранены"
	bd.FlashErr = ""
	var sb strings.Builder
	if err := r.Render(&sb, "me_profile", MeProfileData{BaseData: bd, User: testUser()}); err != nil {
		t.Fatalf("Render(me_profile): %v", err)
	}
	out := sb.String()
	for _, w := range []string{`action="/logout"`, "Выйти", "Контакты сохранены", `value="csrf-token-123"`} {
		if !strings.Contains(out, w) {
			t.Errorf("нет %q", w)
		}
	}
}

// wantNavItems — пункты бокового меню: подпись → href.
var wantNavItems = map[string]string{
	"Профиль":            "/me",
	"Приложение TOTP":    "/me/totp",
	"Резервные коды":     "/me/backup",
	"Telegram":           "/me/telegram",
	"Passkeys":           "/me/passkeys",
	"Устройства":         "/me/devices",
	"Пользователи":       "/admin/users",
	"Аудит":              "/admin/audit",
	"Активные challenge": "/admin/challenges",
	"Настройки":          "/admin/settings",
}

// wantAdminNavItems — пункты, видимые только админу.
var wantAdminNavItems = []string{"/admin/users", "/admin/audit", "/admin/challenges", "/admin/settings"}

// TestRenderSidebar: боковое меню авторизованной страницы содержит все
// пункты (админу — включая раздел «Админ»), не-админу админ-пункты скрыты.
func TestRenderSidebar(t *testing.T) {
	r := mustNew(t)

	bd := base("Профиль")
	var sb strings.Builder
	if err := r.Render(&sb, "me_profile", MeProfileData{BaseData: bd, User: testUser()}); err != nil {
		t.Fatalf("Render(me_profile): %v", err)
	}
	adminOut := sb.String()
	for label, href := range wantNavItems {
		if !strings.Contains(adminOut, `href="`+href+`"`) {
			t.Errorf("сайдбар админа: нет пункта %q (%s)", label, href)
		}
	}
	for _, w := range []string{"Кабинет", "Админ", "twofa"} {
		if !strings.Contains(adminOut, w) {
			t.Errorf("сайдбар админа: нет %q", w)
		}
	}

	bd = BaseData{Title: "Профиль", Username: "vasya", IsAdmin: false, CSRF: testCSRF}
	sb.Reset()
	if err := r.Render(&sb, "me_profile", MeProfileData{BaseData: bd, User: testUser()}); err != nil {
		t.Fatalf("Render(me_profile): %v", err)
	}
	userOut := sb.String()
	for _, href := range wantAdminNavItems {
		if strings.Contains(userOut, `href="`+href+`"`) {
			t.Errorf("сайдбар не-админа: не должен содержать %q", href)
		}
	}
	if !strings.Contains(userOut, `href="/me/totp"`) {
		t.Error("сайдбар не-админа: нет пункта кабинета /me/totp")
	}
}

// TestRenderNavActive: Nav подсвечивает ровно один пункт меню классом
// nav-link active.
func TestRenderNavActive(t *testing.T) {
	r := mustNew(t)
	cases := []struct{ nav, href string }{
		{"me", "/me"},
		{"totp", "/me/totp"},
		{"backup", "/me/backup"},
		{"telegram", "/me/telegram"},
		{"passkeys", "/me/passkeys"},
		{"devices", "/me/devices"},
		{"admin-users", "/admin/users"},
		{"admin-audit", "/admin/audit"},
		{"admin-challenges", "/admin/challenges"},
		{"admin-settings", "/admin/settings"},
	}
	for _, tc := range cases {
		bd := base("Профиль")
		bd.Nav = tc.nav
		var sb strings.Builder
		if err := r.Render(&sb, "me_profile", MeProfileData{BaseData: bd, User: testUser()}); err != nil {
			t.Fatalf("Render(me_profile): %v", err)
		}
		out := sb.String()
		if !strings.Contains(out, `class="nav-link active" href="`+tc.href+`"`) {
			t.Errorf("Nav=%q: пункт %s не подсвечен", tc.nav, tc.href)
		}
		// Активен ровно один пункт.
		if n := strings.Count(out, `class="nav-link active"`); n != 1 {
			t.Errorf("Nav=%q: активных пунктов %d, ожидался 1", tc.nav, n)
		}
	}

	// Пустой Nav (страницы без меню) — ничего не подсвечено.
	var sb strings.Builder
	if err := r.Render(&sb, "me_profile", MeProfileData{BaseData: base("Профиль"), User: testUser()}); err != nil {
		t.Fatalf("Render(me_profile): %v", err)
	}
	if strings.Contains(sb.String(), `class="nav-link active"`) {
		t.Error("пустой Nav не должен подсвечивать пункты")
	}
}

// TestStyleCSSDesignSystem: в style.css есть автоматическая тёмная тема
// (prefers-color-scheme) и мобильная точка перелома (max-width: 900px).
func TestStyleCSSDesignSystem(t *testing.T) {
	rec := httptest.NewRecorder()
	http.FileServer(Static()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/style.css", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /style.css: статус %d, ожидался 200", rec.Code)
	}
	css := rec.Body.String()
	for _, w := range []string{
		"prefers-color-scheme: dark",
		"--accent",
		"(max-width: 900px)",
		"prefers-color-scheme",
	} {
		if !strings.Contains(css, w) {
			t.Errorf("style.css: нет %q", w)
		}
	}
}

func TestRenderUnknownTemplate(t *testing.T) {
	r := mustNew(t)
	if err := r.Render(&strings.Builder{}, "no_such_page", nil); err == nil {
		t.Error("ожидалась ошибка для неизвестного шаблона")
	}
}

func TestQrPNG(t *testing.T) {
	u, err := qrPNG(otpauth)
	if err != nil {
		t.Fatalf("qrPNG: %v", err)
	}
	if !strings.HasPrefix(string(u), "data:image/png;base64,") {
		t.Errorf("qrPNG: нет data-URI префикса, получено %.40q", string(u))
	}
	if len(string(u)) < len("data:image/png;base64,")+100 {
		t.Errorf("qrPNG: подозрительно короткий PNG (%d байт)", len(string(u)))
	}
}

func TestStatic(t *testing.T) {
	h := http.FileServer(Static())
	for _, name := range []string{"style.css", "webauthn.js"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/"+name, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("GET /%s: статус %d, ожидался 200", name, rec.Code)
			continue
		}
		if rec.Body.Len() == 0 {
			t.Errorf("GET /%s: пустой ответ", name)
		}
	}
}

// TestRenderAdminSettingsSMSPresets — карточка SMS на странице настроек
// содержит выбор пресета шлюза: select с 9 пресетами (без name — поле не
// отправляется, JS заполняет textarea sms.gateway), каждый option несёт
// конфиг (data-config) и описание; контракт формы не меняется.
func TestRenderAdminSettingsSMSPresets(t *testing.T) {
	r := mustNew(t)
	choices := []SMSPresetChoice{
		{Name: "bytehand", Title: "ByteHand", Description: "Креды: id, key, sender.", ConfigJSON: `{"preset":"bytehand","method":"GET","url":"https://api.bytehand.com/v1/send?id={id}","headers":{"id":"","key":"","sender":""},"success":{"json_path":"$.status","equals":"0"}}`},
		{Name: "mainsms", Title: "MainSMS", Description: "Креды: project и api_key.", ConfigJSON: `{"preset":"mainsms","method":"GET","url":"https://mainsms.ru/","headers":{"project":"","api_key":""},"success":{"json_path":"$.status","equals":"success"}}`},
		{Name: "prostor", Title: "Простор-СМС", Description: "Креды: login, password и sender.", ConfigJSON: `{"preset":"prostor","method":"POST","url":"https://api.prostor-sms.ru/messages/v2/send.json","content_type":"application/json","headers":{"login":"","password":"","sender":""},"success":{"json_path":"$.status","equals":"ok"}}`},
		{Name: "smsaero", Title: "SMS Aero", Description: "Креды: auth_base64 = base64(email:api_key).", ConfigJSON: `{"preset":"smsaero","method":"GET","url":"https://gate.smsaero.ru/v2/sms/send","headers":{"Authorization":"Basic {auth_base64}","auth_base64":"","sender":"SMS Aero"},"success":{"http_status":200}}`},
		{Name: "smsc", Title: "SMSC.ru", Description: "Креды: login и psw.", ConfigJSON: `{"preset":"smsc","method":"GET","url":"https://smsc.ru/sys/send.php","headers":{"login":"","psw":""},"success":{"http_status":200,"json_path":"$.cnt","equals":"1"}}`},
		{Name: "smsgateway24", Title: "SMSGateway24", Description: "Креды: token и device_id.", ConfigJSON: `{"preset":"smsgateway24","method":"GET","url":"https://smsgateway24.com/getdata/addsms","headers":{"token":"","device_id":""},"success":{"json_path":"$.error","equals":"0"}}`},
		{Name: "smsru", Title: "SMS.ru", Description: "Кред: api_id.", ConfigJSON: `{"preset":"smsru","method":"GET","url":"https://sms.ru/sms/send","headers":{"api_id":""},"success":{"json_path":"$.status","equals":"OK"}}`},
		{Name: "twilio", Title: "Twilio", Description: "Креды: sid, token и from.", ConfigJSON: `{"preset":"twilio","method":"POST","url":"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json","headers":{"sid":"","token":"","from":""},"success":{}}`},
		{Name: "unisender", Title: "Unisender", Description: "Креды: api_key и sender.", ConfigJSON: `{"preset":"unisender","method":"GET","url":"https://api.unisender.com/ru/api/sendSms","headers":{"api_key":"","sender":""},"success":{"http_status":200}}`},
	}
	var sb strings.Builder
	if err := r.Render(&sb, "admin_settings", AdminSettingsData{
		BaseData: base("Настройки"), S: testSettings(),
		SMSPresetChoices: choices,
	}); err != nil {
		t.Fatalf("Render(admin_settings): %v", err)
	}
	out := sb.String()

	// Select пресетов + все 9 пунктов; конфиг виден браузеру (dataset)
	// после разэкранирования HTML-сущностей атрибута.
	unescaped := html.UnescapeString(out)
	for _, ch := range choices {
		if !strings.Contains(out, `<option value="`+ch.Name+`"`) {
			t.Errorf("нет option пресета %q", ch.Name)
		}
		if !strings.Contains(unescaped, `data-config='`+ch.ConfigJSON+`'`) {
			t.Errorf("у пресета %q нет data-config с JSON конфига", ch.Name)
		}
	}
	// Select пресетов присутствует.
	if !strings.Contains(out, `data-sms-preset`) {
		t.Error("нет select выбора пресета (data-sms-preset)")
	}
	// Контракт формы не меняется: textarea sms.gateway остаётся.
	if !strings.Contains(out, `name="sms.gateway"`) {
		t.Error("textarea sms.gateway пропала (контракт формы)")
	}
	// У select НЕТ name — поле не отправляется на сервер.
	if strings.Contains(out, "name=\"sms.preset\"") {
		t.Error("select пресета не должен иметь name (не часть формы)")
	}
}

// TestAppJSSMSPreset — app.js подключён к макету и знает о пресетах
// SMS (заполняет textarea sms.gateway из data-config выбранной option).
func TestAppJSSMSPreset(t *testing.T) {
	rec := httptest.NewRecorder()
	http.FileServer(Static()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/app.js", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /app.js: статус %d, ожидался 200", rec.Code)
	}
	js := rec.Body.String()
	for _, w := range []string{"data-sms-preset", "sms.gateway", "data-config", "JSON.stringify"} {
		if !strings.Contains(js, w) {
			t.Errorf("app.js: нет %q (обработчик выбора пресета)", w)
		}
	}
}

func mustNew(t *testing.T) *Renderer {
	t.Helper()
	r, err := New()
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	return r
}

func ptrUser(u store.User) *store.User { return &u }
