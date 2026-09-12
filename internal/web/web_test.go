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
	"github.com/aligorov/twofa/internal/license"
	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
)

// wantPages — все страницы пакета; тесты ниже опираются на этот набор.
var wantPages = []string{
	"login", "me_profile", "me_totp", "me_backup", "me_telegram",
	"me_passkeys", "me_devices", "admin_users", "admin_groups", "admin_audit", "admin_firewall",
	"admin_challenges", "admin_settings", "admin_license", "error",
	"oidc_consent", "admin_oidc", "admin_oidc_edit",
	"admin_support", "admin_support_viewer",
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
			name: "login_need_code_info",
			tmpl: "login",
			data: LoginData{BaseData: BaseData{Title: "Вход"}, NeedCode: true, Info: "Код отправлен в Telegram.", Prefill: "vasya"},
			want: []string{"Вход", `action="/login"`, "Введите код второго фактора.", "Код отправлен в Telegram.", `value="vasya"`},
		},
		{
			name: "login_need_code_sms",
			tmpl: "login",
			data: LoginData{BaseData: BaseData{Title: "Вход"}, NeedCode: true, CanSMS: true, Prefill: "vasya"},
			want: []string{"Вход", `action="/login"`, "Введите код второго фактора.", "Отправить код по SMS", `value="send_sms"`},
		},
		{
			name: "login_need_code_email",
			tmpl: "login",
			data: LoginData{BaseData: BaseData{Title: "Вход"}, NeedCode: true, CanEmail: true, Prefill: "vasya"},
			want: []string{"Вход", `action="/login"`, "Введите код второго фактора.", "Отправить на почту", `value="send_email"`},
		},
		{
			name: "me_profile",
			tmpl: "me_profile",
			data: MeProfileData{BaseData: base("Профиль"), User: testUser(),
				TOTPConfirmed: true, TelegramLinked: false, BackupRemaining: 3, PasskeyCount: 1},
			want: []string{
				"Профиль", `action="/me/contacts"`, `action="/me/contacts/send-code"`,
				`action="/me/prefer"`, `action="/me/password"`, `value="totp"`, `value="email"`,
				"Смена пароля", "vasya@example.com", "осталось: 3", "data-request-code", "field-with-btn",
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
			want: []string{"TOTP привязан", `action="/me/totp/delete"`, "data-request-code", "field-with-btn"},
		},
		{
			name: "me_backup",
			tmpl: "me_backup",
			data: MeBackupData{BaseData: base("Резервные коды"), Generated: true,
				Codes: []string{"ABCD-EFGH", "IJKL-MNOP"}, Remaining: 2},
			want: []string{"Резервные коды", `action="/me/backup/regenerate"`, "ABCD-EFGH",
				"показываются только один раз", "data-request-code", "field-with-btn"},
		},
		{
			name: "me_telegram_linked",
			tmpl: "me_telegram",
			data: MeTelegramData{BaseData: base("Telegram"), Linked: true, ChatID: &chatID},
			want: []string{"Telegram привязан", `action="/me/telegram/delete"`, "data-request-code", "field-with-btn"},
		},
		{
			name: "me_telegram_code",
			tmpl: "me_telegram",
			data: MeTelegramData{BaseData: base("Telegram"), LinkCode: "LINK-7Q4X"},
			want: []string{"LINK-7Q4X", `action="/me/telegram/link"`, "data-request-code", "field-with-btn"},
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
				"data-passkey-register", "MacBook · Touch ID", "Добавить passkey",
				"data-request-code", "field-with-btn",
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
				"gr-section", "gr-groups-container", "radius-common-attrs",
			},
		},
		{
			name: "error",
			tmpl: "error",
			data: ErrorData{BaseData: base("Ошибка"), Code: 404, Message: "Страница не найдена"},
			want: []string{"Ошибка 404", "Страница не найдена"},
		},
		{
			name: "oidc_consent",
			tmpl: "oidc_consent",
			data: OIDCConsentData{
				BaseData:   BaseData{Title: "Вход в приложение", Username: "vasya", CSRF: testCSRF},
				ClientName: "Grafana",
				ClientID:   "mfa_aBcD1234",
				Scopes:     []string{"подтверждение вашей личности (openid)", "профиль: имя пользователя и роль (profile)"},
				Fields: []FormField{
					{"client_id", "mfa_aBcD1234"},
					{"redirect_uri", "https://grafana.example.com/login/generic_oauth"},
					{"response_type", "code"},
					{"scope", "openid profile"},
					{"state", "st-123"},
				},
			},
			want: []string{
				"Вход в приложение", "Grafana", "mfa_aBcD1234",
				`action="/oidc/authorize/confirm"`, "Разрешить вход",
				`name="client_id"`, `name="redirect_uri"`, `name="state"`,
				`name="csrf_token"`,
			},
		},
		{
			name: "oidc_consent_rich",
			tmpl: "oidc_consent",
			data: OIDCConsentData{
				BaseData:        BaseData{Title: "Вход в приложение", Username: "ivanov", CSRF: testCSRF},
				ClientName:      "1С:Предприятие",
				ClientID:        "1c_enterprise",
				ClientInitial:   "1",
				RedirectURI:     "https://1c.corp.example.com/oauth/callback",
				RedirectHost:    "1c.corp.example.com",
				UserDisplayName: "Иван Иванов",
				UserEmail:       "ivanov@corp.example.com",
				UserInitial:     "И",
				ScopeDetails: []OIDCScopeInfo{
					{Scope: "openid", Title: "Подтверждение личности (OpenID)", Description: "Уникальный идентификатор учётной записи (sub)", Icon: "🪪"},
					{Scope: "profile", Title: "Данные профиля (profile)", Description: "Имя пользователя и системная роль", Icon: "👤"},
				},
				Fields: []FormField{
					{"client_id", "1c_enterprise"},
					{"redirect_uri", "https://1c.corp.example.com/oauth/callback"},
					{"response_type", "code"},
					{"scope", "openid profile"},
					{"state", "state-999"},
				},
			},
			want: []string{
				"Вход в приложение", "1С:Предприятие", "1c_enterprise",
				"1c.corp.example.com", "Иван Иванов", "ivanov@corp.example.com",
				"Подтверждение личности (OpenID)", "Данные профиля (profile)",
				"2FA Защита", "Сессия активна", "Разрешить вход",
			},
		},
		{
			name: "admin_oidc",
			tmpl: "admin_oidc",
			data: AdminOIDCClientsData{
				BaseData: base("OIDC"),
				Clients: []store.OIDCClient{{
					ID:           uuid.MustParse("22222222-2222-2222-2222-222222222222"),
					ClientID:     "mfa_aBcD1234",
					Name:         "Grafana",
					RedirectURIs: []string{"https://grafana.example.com/login/generic_oauth"},
					IsPublic:     false,
					CreatedAt:    lastUsed,
				}},
				OneTimeClientID: "mfa_Zz9Y8x7w",
				OneTimeSecret:   "one-time-secret",
			},
			want: []string{
				"OpenID Connect", "mfa_aBcD1234", "Grafana",
				`action="/admin/oidc/clients"`, `name="redirect_uris"`,
				`name="is_public"`, "one-time-secret",
				`action="/admin/oidc/clients/22222222-2222-2222-2222-222222222222/delete"`,
				"openid-configuration",
			},
		},
		{
			name: "admin_groups",
			tmpl: "admin_groups",
			data: AdminGroupsData{
				BaseData: base("Группы"),
				Groups: []store.Group{{
					ID:          uuid.MustParse("33333333-3333-3333-3333-333333333333"),
					Name:        "DevOps",
					Description: "Инженеры инфраструктуры",
					MemberCount: 2,
					CreatedAt:   lastUsed,
				}},
				AllUsers: []*store.User{
					{
						ID:          uuid.MustParse("11111111-1111-1111-1111-111111111111"),
						Username:    "ivanov",
						DisplayName: "Иван Иванов",
						LDAPGroups:  []string{"CN=VPN_WORK,OU=Groups,DC=example,DC=org"},
					},
				},
				LDAPGroups: []string{"CN=VPN_WORK,OU=Groups,DC=example,DC=org", "CN=IT_STAFF,DC=example,DC=org"},
			},
			want: []string{
				"Группы пользователей", "DevOps", "Инженеры инфраструктуры",
				"2 польз.", `action="/admin/groups"`,
				"btn-ad-group-select", "VPN_WORK", "IT_STAFF",
				"member-chip", "ivanov", "Иван Иванов", "member-search-input",
			},
		},
		{
			name: "admin_oidc_edit",
			tmpl: "admin_oidc_edit",
			data: AdminOIDCEditData{
				BaseData: base("Редактирование OIDC"),
				Client: &store.OIDCClient{
					ID:           uuid.MustParse("22222222-2222-2222-2222-222222222222"),
					ClientID:     "mfa_aBcD1234",
					Name:         "Proxmox PVE",
					RedirectURIs: []string{"https://pve.example.com:8006"},
					IsPublic:     false,
					AllowedUsers: []string{"admin"},
				},
			},
			want: []string{
				"Редактирование приложения OIDC", "mfa_aBcD1234", "Proxmox PVE",
				`action="/admin/oidc/clients/22222222-2222-2222-2222-222222222222"`,
			},
		},
		{
			name: "admin_license",
			tmpl: "admin_license",
			data: AdminLicenseData{
				BaseData: func() BaseData {
					b := base("Лицензия")
					b.Nav = "admin-license"
					b.LicenseWarnings = []string{"Демо-режим: осталось 3 дн. — загрузите лицензию."}
					return b
				}(),
				Status: license.Status{
					Mode: license.ModeTrial, TrialDaysLeft: 3, UsersActive: 2,
				},
				ModeText:  "Демо (30 дней, полный функционал)",
				LimitText: "не ограничено",
			},
			want: []string{
				"Лицензия", `href="/admin/license"`, "Демо-режим: осталось 3 дн.",
				"не ограничено", `action="/admin/license"`,
				`name="blob"`, `name="crl"`, `name="csrf_token"`,
				"BEGIN LIGAMENT LICENSE", "BEGIN LIGAMENT REVOCATION",
			},
		},
		{
			name: "admin_support",
			tmpl: "admin_support",
			data: AdminSupportData{
				BaseData:       base("Удаленная помощь"),
				CategoryFilter: "it",
				Sessions: []store.SupportSession{
					{
						ID:             uuid.MustParse("44444444-4444-4444-4444-444444444444"),
						Username:       "petrov",
						DisplayName:    "Петр Петров",
						Category:       "it",
						Status:         "requested",
						ProblemSummary: "Не открывается сетевая папка",
						DeviceName:     "PC-PETROV",
						Platform:       "windows",
						LastIP:         "192.168.1.55",
						CreatedAt:      lastUsed,
					},
				},
			},
			want: []string{
				"Удаленная помощь", "Петр Петров", "Не открывается сетевая папка",
				"PC-PETROV", "192.168.1.55", "Ожидает инженера",
			},
		},
		{
			name: "admin_support_viewer",
			tmpl: "admin_support_viewer",
			data: AdminSupportViewerData{
				BaseData: base("Управление ПК"),
				Session: &store.SupportSession{
					ID:             uuid.MustParse("44444444-4444-4444-4444-444444444444"),
					Username:       "petrov",
					DisplayName:    "Петр Петров",
					Category:       "1c",
					Status:         "active",
					ProblemSummary: "Ошибка 1С при формировании отчета",
					DeviceName:     "PC-PETROV",
					Platform:       "windows",
					LastIP:         "192.168.1.55",
					AccessMode:     "full_control",
					CreatedAt:      lastUsed,
				},
				WSEndpoint: "/api/v1/support/ws/44444444-4444-4444-4444-444444444444",
			},
			want: []string{
				"Петр Петров", "1С-поддержка", "Ошибка 1С при формировании отчета",
				"Включить управление", "Переадресовать сессию", "Завершить сеанс",
			},
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
			if !strings.Contains(out, `/static/style.css`) {
				t.Errorf("Render(%s): нет ссылки на style.css", tc.tmpl)
			}
			if !strings.Contains(out, `/static/webauthn.js`) {
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
	"OIDC":               "/admin/oidc",
	"Активные challenge": "/admin/challenges",
	"Настройки":          "/admin/settings",
}

// wantAdminNavItems — пункты, видимые только админу.
var wantAdminNavItems = []string{"/admin/users", "/admin/audit", "/admin/oidc", "/admin/challenges", "/admin/settings"}

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
	for _, w := range []string{"Кабинет", "Админ", "Ligament"} {
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

// TestRenderHTMLCSP — CSP-решение рендера: middleware ставит строгую базовую
// политику всем ответам; RenderHTML ПЕРЕЗАПИСЫВАЕТ её на relaxed только у
// страницы с фактически отрендеренными рекламными слотами (админка и
// страницы без слотов остаются строгими — report 2026-09-11, Web UI-1).
func TestRenderHTMLCSP(t *testing.T) {
	r := mustNew(t)
	// mk — данные соответствующей страницы с подставленной рекламой
	// (решение CSP делается по полю Ads в BaseData любых страниц).
	adsOf := func(b BaseData, ads AdsData) BaseData { b.Ads = ads; return b }
	login := func(a AdsData) any { return LoginData{BaseData: adsOf(BaseData{Title: "Вход"}, a)} }
	cases := []struct {
		name string
		page string
		mk   func(AdsData) any
		ads  AdsData
		want string
	}{
		{"no_ads", "login", login, AdsData{}, ContentSecurityPolicy},
		{"rsya_no_slots", "login", login, AdsData{Show: true, Provider: "rsya"}, ContentSecurityPolicy},
		{"rsya_login_left", "login", login, AdsData{Show: true, Provider: "rsya", LoginLeft: "R-A-1"}, ContentSecurityPolicyAds},
		{"rsya_login_right", "error", func(a AdsData) any {
			return ErrorData{BaseData: adsOf(BaseData{Title: "Ошибка"}, a), Code: 404, Message: "нет"}
		}, AdsData{Show: true, Provider: "rsya", LoginRight: "R-A-2"}, ContentSecurityPolicyAds},
		{"rsya_consent_left", "oidc_consent", func(a AdsData) any {
			return OIDCConsentData{BaseData: adsOf(BaseData{Title: "Вход в приложение", Username: "vasya", CSRF: testCSRF}, a), ClientID: "mfa_x"}
		}, AdsData{Show: true, Provider: "rsya", LoginLeft: "R-A-7"}, ContentSecurityPolicyAds},
		// App-страницы игнорируют login-слоты: рендерится только Sidebar.
		{"rsya_login_slots_on_app_page", "me_profile", func(a AdsData) any {
			return MeProfileData{BaseData: adsOf(BaseData{Title: "Профиль", Username: "vasya", CSRF: testCSRF}, a), User: testUser()}
		}, AdsData{Show: true, Provider: "rsya", LoginLeft: "R-A-1", LoginRight: "R-A-2"}, ContentSecurityPolicy},
		{"rsya_sidebar_on_app_page", "admin_users", func(a AdsData) any {
			return AdminUsersData{BaseData: adsOf(BaseData{Title: "Пользователи", Username: "vasya", CSRF: testCSRF}, a)}
		}, AdsData{Show: true, Provider: "rsya", Sidebar: "R-A-3"}, ContentSecurityPolicyAds},
		{"rsya_sidebar_empty", "me_profile", func(a AdsData) any {
			return MeProfileData{BaseData: adsOf(BaseData{Title: "Профиль", Username: "vasya", CSRF: testCSRF}, a), User: testUser()}
		}, AdsData{Show: true, Provider: "rsya"}, ContentSecurityPolicy},
		{"rsya_sidebar_on_login", "login", login, AdsData{Show: true, Provider: "rsya", Sidebar: "R-A-3"}, ContentSecurityPolicy},
		{"rsya_on_support_viewer", "admin_support_viewer", func(a AdsData) any {
			return AdminSupportViewerData{
				BaseData: adsOf(BaseData{Title: "Управление ПК", Username: "vasya", CSRF: testCSRF}, a),
				Session:  &store.SupportSession{ID: uuid.MustParse("44444444-4444-4444-4444-444444444444")},
			}
		}, AdsData{Show: true, Provider: "rsya", Sidebar: "R-A-3", LoginLeft: "R-A-1"}, ContentSecurityPolicy},
		{"direct_no_image", "login", login, AdsData{Show: true, Provider: "direct", DirectURL: "https://ads.example/x"}, ContentSecurityPolicy},
		{"direct_image", "login", login, AdsData{Show: true, Provider: "direct", DirectImage: "https://ads.example/banner.png"}, ContentSecurityPolicyAds},
		{"direct_image_on_app_page", "admin_users", func(a AdsData) any {
			return AdminUsersData{BaseData: adsOf(BaseData{Title: "Пользователи", Username: "vasya", CSRF: testCSRF}, a)}
		}, AdsData{Show: true, Provider: "direct", DirectImage: "https://ads.example/banner.png"}, ContentSecurityPolicyAds},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			if err := r.RenderHTML(rec, http.StatusOK, tc.page, tc.mk(tc.ads)); err != nil {
				t.Fatalf("RenderHTML(%s): %v", tc.page, err)
			}
			if got := rec.Header().Get("Content-Security-Policy"); got != tc.want {
				t.Errorf("CSP = %q, want %q", got, tc.want)
			}
			if got := rec.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
				t.Errorf("Content-Type = %q", got)
			}
			if rec.Code != http.StatusOK {
				t.Errorf("статус %d, ожидался 200 (заголовки до первого Write)", rec.Code)
			}
		})
	}

	// Страница без рекламных данных (any, не содержащий BaseData) — строгая CSP.
	rec := httptest.NewRecorder()
	if err := r.RenderHTML(rec, http.StatusOK, "login", nil); err != nil {
		t.Fatalf("RenderHTML(login, nil): %v", err)
	}
	if got := rec.Header().Get("Content-Security-Policy"); got != ContentSecurityPolicy {
		t.Errorf("CSP без данных = %q, want %q", got, ContentSecurityPolicy)
	}
}

// TestRenderBrandLogoSameOrigin — логотип белого лейбла рендерится
// same-origin ресурсом /branding/logo (report 2026-09-11, Web UI-2):
// data:URI в src заменялся фильтром html/template на #ZgotmplZ, а внешний
// https-URL резался строгой img-src.
func TestRenderBrandLogoSameOrigin(t *testing.T) {
	r := mustNew(t)
	dataURI := "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg=="
	consentBase := BaseData{Title: "Вход в приложение", Username: "vasya", CSRF: testCSRF,
		Brand: BrandData{Name: "Acme", Logo: dataURI}}
	cases := []struct {
		name string
		tmpl string
		data any
	}{
		{"login", "login", LoginData{BaseData: BaseData{Title: "Вход", Brand: BrandData{Name: "Acme", Logo: dataURI}}}},
		{"me_profile", "me_profile", MeProfileData{BaseData: BaseData{Title: "Профиль", Username: "admin", IsAdmin: true, CSRF: testCSRF, Brand: BrandData{Name: "Acme", Logo: dataURI}}, User: testUser()}},
		{"oidc_consent", "oidc_consent", OIDCConsentData{
			BaseData: consentBase,
			ClientID: "mfa_x",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var sb strings.Builder
			if err := r.Render(&sb, tc.tmpl, tc.data); err != nil {
				t.Fatalf("Render(%s): %v", tc.tmpl, err)
			}
			out := sb.String()
			if !strings.Contains(out, `src="/branding/logo"`) {
				t.Errorf("Render(%s): нет src=\"/branding/logo\"", tc.tmpl)
			}
			if strings.Contains(out, "ZgotmplZ") {
				t.Errorf("Render(%s): data:URI превратился в #ZgotmplZ", tc.tmpl)
			}
			if strings.Contains(out, dataURI) {
				t.Errorf("Render(%s): сырой data:URI попал в разметку", tc.tmpl)
			}
		})
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

// TestAppJSGroupRadiusBuilder — app.js содержит интерактивный конструктор
// сопоставления групп AD с RADIUS-атрибутами без необходимости ручного ввода JSON.
func TestAppJSGroupRadiusBuilder(t *testing.T) {
	rec := httptest.NewRecorder()
	http.FileServer(Static()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/app.js", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /app.js: статус %d, ожидался 200", rec.Code)
	}
	js := rec.Body.String()
	for _, w := range []string{
		"initGroupRadiusBuilder",
		"gr-groups-container",
		"ldap-group-radius-raw",
		"gr-empty-state",
		"createGroupCard",
		"createAttrRow",
		"data-gr-preset",
		"data-gr-add-group",
		"Filter-Id",
	} {
		if !strings.Contains(js, w) {
			t.Errorf("app.js: нет %q (интерактивный конструктор групп RADIUS)", w)
		}
	}
}

func TestAppJSAndCSSRequestCode(t *testing.T) {
	// Проверка app.js
	recJS := httptest.NewRecorder()
	http.FileServer(Static()).ServeHTTP(recJS, httptest.NewRequest(http.MethodGet, "/app.js", nil))
	if recJS.Code != http.StatusOK {
		t.Fatalf("GET /app.js: статус %d", recJS.Code)
	}
	js := recJS.Body.String()
	for _, w := range []string{"data-request-code", "/me/send-code", "request-code-status", "csrf-token"} {
		if !strings.Contains(js, w) {
			t.Errorf("app.js: нет %q", w)
		}
	}

	// Проверка style.css
	recCSS := httptest.NewRecorder()
	http.FileServer(Static()).ServeHTTP(recCSS, httptest.NewRequest(http.MethodGet, "/style.css", nil))
	if recCSS.Code != http.StatusOK {
		t.Fatalf("GET /style.css: статус %d", recCSS.Code)
	}
	css := recCSS.Body.String()
	for _, w := range []string{".field-with-btn", ".request-code-status"} {
		if !strings.Contains(css, w) {
			t.Errorf("style.css: нет %q", w)
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

func TestGroupCN(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"CN=VPN_WORK,CN=Users,DC=test,DC=corp", "VPN_WORK"},
		{"CN=VPN_VIP,CN=Users,DC=test,DC=corp", "VPN_VIP"},
		{"CN=Группа с запрещением репликации паролей RODC,CN=Users,DC=test,DC=corp", "Группа с запрещением репликации паролей RODC"},
		{"CN=ad_trusted-publishers,OU=it,OU=groups,DC=test,DC=corp", "ad_trusted-publishers"},
		{"CN=Администраторы домена,CN=Users,DC=test,DC=corp", "Администраторы домена"},
		{"CN=Пользователи,CN=Builtin,DC=test,DC=corp", "Пользователи"},
		{"CN=Администраторы,CN=Builtin,DC=test,DC=corp", "Администраторы"},
		{"CN=Гости,CN=Builtin,DC=test,DC=corp", "Гости"},
		{"OU=Managers,DC=test,DC=corp", "Managers"},
		{"CN=VPN\\, Special,DC=test,DC=corp", "VPN, Special"},
		{"PlainGroupName", "PlainGroupName"},
	}
	for _, tc := range cases {
		got := groupCN(tc.in)
		if got != tc.want {
			t.Errorf("groupCN(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
