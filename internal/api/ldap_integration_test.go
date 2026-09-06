//go:build integration

// Сквозные интеграционные тесты LDAP/AD-бэкенда: настоящий openldap
// (testcontainers-go, osixia/openldap с LDIF-сидом) + postgres + полный
// REST-флоу входа через CompositeVerifier. Проверяются live: авто-
// провижининг при первом входе, синк атрибутов, роль из role_map,
// allow_groups, неверный пароль, неприкосновенность локальных
// пользователей и 2FA (TOTP) поверх LDAP-пароля.
// Запуск: go test -tags integration ./internal/api/ -run TestLDAP
package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	gldap "github.com/go-ldap/ldap/v3"
	"github.com/pquerna/otp/totp"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/aligorov/twofa/internal/auth"
	"github.com/aligorov/twofa/internal/channel"
	"github.com/aligorov/twofa/internal/delivery"
	"github.com/aligorov/twofa/internal/secrets"
	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
	"github.com/aligorov/twofa/internal/webauthn"
)

// openldapSeed — каталог: 2 пользователя в группах VPN-Users/VPN-Admins и
// один вне групп (для allow-list), атрибуты mail/telephoneNumber/displayName.
const openldapSeed = `# Пользователи.
dn: ou=Users,dc=example,dc=com
objectClass: organizationalUnit
ou: Users

dn: cn=vpn-user,ou=Users,dc=example,dc=com
objectClass: inetOrgPerson
cn: vpn-user
sn: Userov
uid: vpn-user
mail: vpn-user@example.com
telephoneNumber: +79990001122
displayName: ВПН Юзеров
userPassword: vpn-secret

dn: cn=admin-user,ou=Users,dc=example,dc=com
objectClass: inetOrgPerson
cn: admin-user
sn: Adminov
uid: admin-user
mail: admin-user@example.com
userPassword: admin-secret

dn: cn=nogroup-user,ou=Users,dc=example,dc=com
objectClass: inetOrgPerson
cn: nogroup-user
sn: Outside
uid: nogroup-user
userPassword: nogroup-secret

# Группы.
dn: ou=Groups,dc=example,dc=com
objectClass: organizationalUnit
ou: Groups

dn: cn=VPN-Users,ou=Groups,dc=example,dc=com
objectClass: groupOfNames
cn: VPN-Users
member: cn=vpn-user,ou=Users,dc=example,dc=com

dn: cn=VPN-Admins,ou=Groups,dc=example,dc=com
objectClass: groupOfNames
cn: VPN-Admins
member: cn=admin-user,ou=Users,dc=example,dc=com
`

var (
	ldapOnce    sync.Once
	ldapHost    string // host:port открытого контейнера
	ldapInitErr error
)

// startOpenldap лениво поднимает общий на пакет контейнер osixia/openldap
// с сидом; возвращает адрес "host:port" для ldap://.
func startOpenldap(t *testing.T) string {
	t.Helper()
	if !dockerAvailable() {
		t.Skip("docker недоступен (docker info завершается с ошибкой) — интеграционный тест пропущен")
	}
	ldapOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
		defer cancel()

		req := testcontainers.ContainerRequest{
			Image: "osixia/openldap:latest",
			Env: map[string]string{
				"LDAP_ORGANISATION":   "Example Corp",
				"LDAP_DOMAIN":         "example.com",
				"LDAP_BASE_DN":        "dc=example,dc=com",
				"LDAP_ADMIN_PASSWORD": "adminpassword",
			},
			ExposedPorts: []string{"389/tcp"},
			// LDIF монтируется в bootstrap-каталог образа и применяется
			// при первом старте slapd.
			Files: []testcontainers.ContainerFile{{
				Reader:            strings.NewReader(openldapSeed),
				ContainerFilePath: "/container/service/slapd/assets/config/bootstrap/ldif/custom/50-seed.ldif",
			}},
			WaitingFor: wait.ForListeningPort("389/tcp").WithStartupTimeout(120 * time.Second),
		}
		c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: req,
			Started:          true,
		})
		if err != nil {
			ldapInitErr = err
			return
		}
		// Жизнь контейнера — до конца процесса тестов (ryuk приберёт).
		port, err := c.MappedPort(ctx, "389")
		if err != nil {
			ldapInitErr = err
			return
		}
		host, err := c.Host(ctx)
		if err != nil {
			ldapInitErr = err
			return
		}
		ldapHost = host + ":" + port.Port()

		// Порт открывается ДО применения bootstrap-LDIF: ждём функционально —
		// пока поиск сида не начнёт отвечать записью vpn-user.
		if err := probeLDAPSeed("ldap://" + ldapHost); err != nil {
			_ = c.Terminate(ctx)
			ldapInitErr = err
			return
		}
	})
	if ldapInitErr != nil {
		t.Fatalf("подготовка openldap-контейнера: %v", ldapInitErr)
	}
	return ldapHost
}

// probeLDAPSeed опрашивает каталог до появления сида (bootstrap-LDIF
// применяется после открытия порта — гонка под нагрузкой полного прогона):
// сервисный bind + поиск uid=vpn-user должны вернуть запись.
func probeLDAPSeed(url string) error {
	var lastErr error
	for i := 0; i < 30; i++ {
		conn, err := gldap.DialURL(url)
		if err != nil {
			lastErr = err
		} else {
			defer conn.Close()
			if err = conn.Bind("cn=admin,dc=example,dc=com", "adminpassword"); err != nil {
				lastErr = err
			} else {
				res, serr := conn.Search(gldap.NewSearchRequest(
					"dc=example,dc=com", gldap.ScopeWholeSubtree, gldap.NeverDerefAliases,
					1, 0, false, "(&(objectClass=inetOrgPerson)(uid=vpn-user))", nil, nil))
				if serr == nil && len(res.Entries) == 1 {
					return nil
				} else if serr != nil {
					lastErr = serr
				} else {
					lastErr = errors.New("сид openldap ещё не применён")
				}
			}
		}
		time.Sleep(time.Second)
	}
	return lastErr
}

// newLDAPRouter — роутер публичного API с композитным верификатором
// (как в main): локальный argon2 + LdapVerifier.
func newLDAPRouter(t *testing.T, st *store.Store, set *settings.M, box *secrets.Box) http.Handler {
	t.Helper()
	email := &fakeSender{ch: channel.Email}
	pv := auth.NewCompositeVerifier(st, auth.NewLocalVerifier(st), auth.NewLdapVerifier(st, set))
	core := auth.NewCore(st, set, box,
		map[channel.Channel]delivery.Sender{channel.Email: email}, pv, nil)
	p := NewPublicAPI(core, (*webauthn.Svc)(nil), st, pv, set)
	t.Cleanup(p.Stop)
	r := chi.NewRouter()
	p.Register(r)
	return r
}

// enableLiveLDAP настраивает бэкенд на контейнер openldap; восстановление —
// дефолты (контейнер общий на пакет).
func enableLiveLDAP(t *testing.T, addr string) {
	t.Helper()
	st, set, _ := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cfg := map[string]any{
		"enabled":       true,
		"url":           "ldap://" + addr,
		"starttls":      false,
		"bind_dn":       "cn=admin,dc=example,dc=com",
		"bind_password": "adminpassword",
		"base_dn":       "dc=example,dc=com",
		"user_filter":   "(&(objectClass=inetOrgPerson)(uid={login}))",
		"group_base_dn": "ou=Groups,dc=example,dc=com",
		"group_filter":  "(&(objectClass=groupOfNames)(member={dn}))",
		"attrs":         map[string]string{"email": "mail", "phone": "telephoneNumber", "display_name": "displayName"},
		"allow_groups":  []string{"CN=VPN-Users,ou=Groups,dc=example,dc=com", "CN=VPN-Admins,ou=Groups,dc=example,dc=com"},
		"role_map":      map[string]string{"CN=VPN-Admins,ou=Groups,dc=example,dc=com": "admin"},
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal ldap cfg: %v", err)
	}
	if err := set.Put(ctx, "ldap", b); err != nil {
		t.Fatalf("settings.Put(ldap): %v", err)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer ccancel()
		_ = set.Put(cctx, "ldap", json.RawMessage(`{"enabled":false,"starttls":false,"bind_dn":"","bind_password":"","base_dn":"","user_filter":"(&(objectClass=user)(sAMAccountName={login}))","group_base_dn":"","group_filter":"(&(objectClass=group)(member={dn}))","attrs":{"email":"mail","phone":"telephoneNumber","display_name":"displayName"},"allow_groups":[],"role_map":{}}`))
	})
	_ = st
}

// TestLDAPLiveLoginFlow — сквозной флоу на настоящем openldap: вход
// каталогного пользователя (авто-провижининг + синк атрибутов), роль из
// role_map, allow-list, неверный пароль, локальные пользователи и TOTP.
func TestLDAPLiveLoginFlow(t *testing.T) {
	addr := startOpenldap(t)
	st, set, box := setup(t)
	ctx := context.Background()
	enableLiveLDAP(t, addr)
	h := newLDAPRouter(t, st, set, box)

	// 1. Авто-провижининг: первого входа в БД пользователя нет.
	if _, err := st.UserByUsername(ctx, "vpn-user"); err == nil {
		t.Fatal("vpn-user уже существует в БД (остаток прошлого прогона?)")
	}
	rec := doReq(t, h, http.MethodPost, "/api/v1/auth/start",
		map[string]string{"username": "vpn-user", "password": "vpn-secret"})
	wantStatus(t, rec, http.StatusOK)
	body := jsonBody(t, rec)
	if _, ok := body["challenge_id"]; !ok {
		t.Fatalf("start: body = %s", rec.Body.String())
	}
	u, err := st.UserByUsername(ctx, "vpn-user")
	if err != nil {
		t.Fatalf("авто-провижининг: %v", err)
	}
	if u.Source != store.SourceLDAP || !u.Enabled || u.Role != "user" {
		t.Fatalf("авто-провижининг: source=%q role=%q enabled=%v", u.Source, u.Role, u.Enabled)
	}
	if u.Email != "vpn-user@example.com" || u.Phone != "+79990001122" || u.DisplayName != "ВПН Юзеров" {
		t.Fatalf("атрибуты не синхронизированы: %+v", u)
	}
	if u.PasswordHash == "" || u.PasswordHash == "vpn-secret" {
		t.Fatalf("password_hash = %q, ожидался случайный непригодный хеш", u.PasswordHash)
	}

	// 2. role_map: участник VPN-Admins получает admin.
	rec = doReq(t, h, http.MethodPost, "/api/v1/auth/start",
		map[string]string{"username": "admin-user", "password": "admin-secret"})
	wantStatus(t, rec, http.StatusOK)
	admin, err := st.UserByUsername(ctx, "admin-user")
	if err != nil {
		t.Fatalf("admin-user не провижен: %v", err)
	}
	if admin.Role != "admin" {
		t.Fatalf("role_map не выдал admin: %q", admin.Role)
	}

	// 3. allow_groups: пользователь вне групп — 401 (единый ответ).
	rec = doReq(t, h, http.MethodPost, "/api/v1/auth/start",
		map[string]string{"username": "nogroup-user", "password": "nogroup-secret"})
	wantStatus(t, rec, http.StatusUnauthorized)
	if _, err := st.UserByUsername(ctx, "nogroup-user"); err == nil {
		t.Fatal("nogroup-user не должен провижиниться (allow_groups)")
	}

	// 4. Неверный пароль каталога — 401.
	rec = doReq(t, h, http.MethodPost, "/api/v1/auth/start",
		map[string]string{"username": "vpn-user", "password": "wrong-secret"})
	wantStatus(t, rec, http.StatusUnauthorized)

	// 5. Локальный пользователь неприкосновенен: входит по локальному
	// паролю, каталоговый пароль не подходит (и не провижинит тёзку).
	// Свежий роутер — независимая token-корзина rate-limiter (общий IP
	// httptest исчерпал бы burst предыдущими фазами).
	local := mkUser(t, ctx, st, "local-bystander", func(u *store.User) {
		u.Email = "bystander@example.com"
		u.PreferChannels = []channel.Channel{channel.Email}
	})
	hLocal := newLDAPRouter(t, st, set, box)
	rec = doReq(t, hLocal, http.MethodPost, "/api/v1/auth/start",
		map[string]string{"username": local.Username, "password": testPassword})
	wantStatus(t, rec, http.StatusOK)
	rec = doReq(t, hLocal, http.MethodPost, "/api/v1/auth/start",
		map[string]string{"username": local.Username, "password": "vpn-secret"})
	wantStatus(t, rec, http.StatusUnauthorized)
	got, err := st.UserByUsername(ctx, local.Username)
	if err != nil || got.Source != store.SourceLocal {
		t.Fatalf("локальный пользователь изменён: %+v %v", got, err)
	}

	// 6. 2FA поверх LDAP-пароля: TOTP энроллится, combined-вход с кодом.
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "twofa", AccountName: "vpn-user", Digits: 6, Period: 30})
	if err != nil {
		t.Fatalf("totp.Generate: %v", err)
	}
	enc := box.EncryptAAD(auth.AADTOTP("vpn-user"), []byte(key.Secret()))
	if err := st.TOTPSave(ctx, u.ID, enc, 6, 30); err != nil {
		t.Fatalf("TOTPSave: %v", err)
	}
	if err := st.TOTPConfirm(ctx, u.ID); err != nil {
		t.Fatalf("TOTPConfirm: %v", err)
	}
	code, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("totp.GenerateCode: %v", err)
	}
	hTotp := newLDAPRouter(t, st, set, box)
	rec = doReq(t, hTotp, http.MethodPost, "/api/v1/auth/combined",
		map[string]string{"username": "vpn-user", "password": "vpn-secret", "code": code})
	wantStatus(t, rec, http.StatusOK)
	if body := jsonBody(t, rec); body["ok"] != true || body["username"] != "vpn-user" {
		t.Fatalf("combined LDAP+TOTP: body = %s", rec.Body.String())
	}

	// 7. Синк при повторном входе: атрибуты стабильны, роль не дрейфует.
	hSync := newLDAPRouter(t, st, set, box)
	rec = doReq(t, hSync, http.MethodPost, "/api/v1/auth/start",
		map[string]string{"username": "vpn-user", "password": "vpn-secret"})
	wantStatus(t, rec, http.StatusOK)
	u2, err := st.UserByUsername(ctx, "vpn-user")
	if err != nil || u2.ID != u.ID || u2.Role != "user" || u2.DisplayName != "ВПН Юзеров" {
		t.Fatalf("повторный вход изменил пользователя некорректно: %+v %v", u2, err)
	}
}
