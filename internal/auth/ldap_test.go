// Unit-тесты LDAP-бэкенда без каталога и БД: экранирование фильтров
// (RFC 4515), регистронезависимое сравнение DN, разрешение ролей по
// группам, allow-list и протокольная часть authenticate на фейковом
// соединении (поиск пользователя/групп, bind, отказ пустого пароля).
// Полные потоки с PostgreSQL и настоящим openldap — в
// ldap_integration_test.go (тег integration).
package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"

	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
)

// ---- подстановка и экранирование ----

func TestLdapSubstFilterEscapesRFC4515(t *testing.T) {
	// Спецсимволы фильтра в логине экранируются: ( ) \ * NUL — иначе
	// ввод «*» раскрывает фильтр в поиск по всем записям каталога.
	filter := substFilter(`(&(objectClass=user)(sAMAccountName={login}))`, "{login}", `a*b(c)d\e`)
	want := `(&(objectClass=user)(sAMAccountName=a\2ab\28c\29d\5ce))`
	if filter != want {
		t.Fatalf("substFilter = %q, want %q", filter, want)
	}
	if got := substFilter("(member={dn})", "{dn}", "CN=a\\b,DC=x"); got != `(member=CN=a\5cb,DC=x)` {
		t.Fatalf("substFilter DN = %q", got)
	}
	// Обычный логин не меняется.
	if got := substFilter("(uid={login})", "{login}", "ivanov"); got != "(uid=ivanov)" {
		t.Fatalf("substFilter обычный = %q", got)
	}
}

// ---- сравнение DN ----

func TestLdapDNEqualCaseInsensitive(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"cn=vpn-admins,ou=groups,dc=example,dc=com", "CN=VPN-Admins,OU=Groups,DC=example,DC=com", true},
		{"CN=VPN-Users,DC=example,DC=com", "CN=VPN-Admins,DC=example,DC=com", false},
		{" CN=x ", "cn=x", true},
		// Порядок RDN значим: перестановка — другой DN (RFC 4514).
		{"CN=x,OU=g,DC=e", "DC=e,OU=g,CN=x", false},
		// Пробелы после разделителей не значимы.
		{"CN=Ivanov, OU=Users, DC=e", "cn=ivanov,ou=users,dc=e", true},
	}
	for _, c := range cases {
		if got := dnEqual(c.a, c.b); got != c.want {
			t.Errorf("dnEqual(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestLdapGroupCN(t *testing.T) {
	if got := groupCN("CN=VPN-Admins,OU=Groups,DC=example,DC=com"); got != "VPN-Admins" {
		t.Fatalf("groupCN = %q", got)
	}
	// Первый RDN может быть не CN.
	if got := groupCN("OU=Staff,DC=e"); got != "Staff" {
		t.Fatalf("groupCN OU = %q", got)
	}
	// Битый DN — грубый разбор без паники.
	if got := groupCN("no-equals-sign"); got != "no-equals-sign" {
		t.Fatalf("groupCN битый = %q", got)
	}
}

// ---- allow_groups ----

func TestLdapMemberAllowed(t *testing.T) {
	groups := []string{"CN=VPN-Users,DC=example,DC=com", "CN=Other,DC=example,DC=com"}
	if !memberAllowed(groups, nil) {
		t.Error("пустой allow_groups разрешает всех")
	}
	if !memberAllowed(groups, []string{"cn=vpn-users,dc=example,dc=com"}) {
		t.Error("вхождение не распознано (регистр DN)")
	}
	if memberAllowed(groups, []string{"CN=Nope,DC=example,DC=com"}) {
		t.Error("чужая группа не должна проходить")
	}
	if memberAllowed(nil, []string{"CN=VPN-Users,DC=example,DC=com"}) {
		t.Error("нет групп — нет вхождения")
	}
}

// ---- role_map ----

func TestLdapResolveRole(t *testing.T) {
	roleMap := map[string]string{
		"CN=VPN-Admins,OU=Groups,DC=example,DC=com": "admin",
		"vpn-editors":                    "admin",
		"CN=VPN-Users,DC=example,DC=com": "user",
	}
	if got := resolveRole([]string{"CN=VPN-Admins,OU=Groups,DC=example,DC=com"}, roleMap); got != "admin" {
		t.Fatalf("роль по DN = %q, want admin", got)
	}
	// Короткий ключ role_map — CN группы.
	if got := resolveRole([]string{"CN=VPN-Editors,OU=Groups,DC=e"}, roleMap); got != "admin" {
		t.Fatalf("роль по CN = %q, want admin", got)
	}
	// admin имеет приоритет над user при нескольких группах.
	if got := resolveRole([]string{
		"cn=vpn-users,dc=example,dc=com",
		"cn=vpn-admins,ou=groups,dc=example,dc=com",
	}, roleMap); got != "admin" {
		t.Fatalf("admin не победил: %q", got)
	}
	// Без совпадений — user.
	if got := resolveRole([]string{"CN=Other,DC=e"}, roleMap); got != "user" {
		t.Fatalf("роль по умолчанию = %q", got)
	}
	// Бессмысленное значение role_map не даёт админа.
	if got := resolveRole([]string{"CN=X,DC=e"}, map[string]string{"CN=X,DC=e": "root"}); got != "user" {
		t.Fatalf("неизвестная роль = %q, want user", got)
	}
}

// ---- group_radius_map ----

func TestResolveGroupRadiusAttrs(t *testing.T) {
	groupMap := map[string]map[string]string{
		"CN=VPN-Users,OU=Groups,DC=example,DC=com": {
			"Filter-Id":       "vpn_users_filter",
			"Session-Timeout": "28800",
		},
		"wifi-staff": {
			"Mikrotik-Group": "staff_access",
			"Framed-Pool":    "pool_staff",
		},
	}

	// 1. Совпадение по полному DN (регистронезависимо)
	attrs := ResolveGroupRadiusAttrs([]string{"cn=vpn-users,ou=groups,dc=example,dc=com"}, groupMap)
	if attrs == nil || attrs["Filter-Id"] != "vpn_users_filter" || attrs["Session-Timeout"] != "28800" {
		t.Fatalf("attrs по DN = %v, want Filter-Id и Session-Timeout", attrs)
	}

	// 2. Совпадение по короткому имени CN
	attrs = ResolveGroupRadiusAttrs([]string{"CN=WiFi-Staff,OU=Wireless,DC=corp,DC=net"}, groupMap)
	if attrs == nil || attrs["Mikrotik-Group"] != "staff_access" || attrs["Framed-Pool"] != "pool_staff" {
		t.Fatalf("attrs по CN = %v, want Mikrotik-Group и Framed-Pool", attrs)
	}

	// 3. Объединение нескольких групп
	attrs = ResolveGroupRadiusAttrs([]string{
		"CN=VPN-Users,OU=Groups,DC=example,DC=com",
		"CN=WiFi-Staff,OU=Wireless,DC=corp,DC=net",
	}, groupMap)
	if len(attrs) != 4 || attrs["Filter-Id"] != "vpn_users_filter" || attrs["Mikrotik-Group"] != "staff_access" {
		t.Fatalf("слияние атрибутов = %v, want 4 атрибута", attrs)
	}

	// 4. Без совпадений
	if attrs := ResolveGroupRadiusAttrs([]string{"CN=Guests,DC=example,DC=com"}, groupMap); attrs != nil {
		t.Fatalf("attrs для чужой группы = %v, want nil", attrs)
	}

	// 5. Пустые входные данные
	if attrs := ResolveGroupRadiusAttrs(nil, groupMap); attrs != nil {
		t.Fatalf("attrs для nil groups = %v, want nil", attrs)
	}
	if attrs := ResolveGroupRadiusAttrs([]string{"CN=VPN-Users,OU=Groups,DC=example,DC=com"}, nil); attrs != nil {
		t.Fatalf("attrs для nil groupMap = %v, want nil", attrs)
	}
}

// ---- фейковое соединение ----

// fakeLdapConn — соединение-двойник: bind по карте DN→пароль, поиск —
// функцией из теста (полный контроль над фильтрами и записями).
type fakeLdapConn struct {
	t        *testing.T
	binds    []string              // DN всех Bind
	searches []*ldap.SearchRequest // все Search
	bindOK   map[string]string     // DN → верный пароль
	searchFn func(*ldap.SearchRequest) (*ldap.SearchResult, error)
	closed   bool
}

func (f *fakeLdapConn) Bind(dn, password string) error {
	f.binds = append(f.binds, dn)
	if want, ok := f.bindOK[dn]; ok && want == password {
		return nil
	}
	return ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid credentials"))
}

func (f *fakeLdapConn) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	f.searches = append(f.searches, req)
	if f.searchFn == nil {
		return &ldap.SearchResult{}, nil
	}
	return f.searchFn(req)
}

func (f *fakeLdapConn) Close() error { f.closed = true; return nil }

// testLDAPCfg — типовая конфигурация каталога для фейковых тестов.
func testLDAPCfg() settings.LDAPSettings {
	return settings.LDAPSettings{
		Enabled:      true,
		URL:          "ldap://ldap.example.com:389",
		BindDN:       "CN=svc-twofa,DC=example,DC=com",
		BindPassword: "svc-secret",
		BaseDN:       "DC=example,DC=com",
		UserFilter:   "(&(objectClass=user)(sAMAccountName={login}))",
		GroupFilter:  "(&(objectClass=group)(member={dn}))",
		Attrs:        settings.LDAPAttrs{Email: "mail", Phone: "telephoneNumber", DisplayName: "displayName"},
	}
}

// userEntry — запись пользователя каталога (аналог ldap.Entry).
func userEntry(dn string, attrs map[string][]string) *ldap.Entry {
	entries := make([]*ldap.EntryAttribute, 0, len(attrs))
	for name, vals := range attrs {
		entries = append(entries, &ldap.EntryAttribute{Name: name, Values: vals})
	}
	return &ldap.Entry{DN: dn, Attributes: entries}
}

// newFakeVerifier — LdapVerifier с подменённым dial (без БД: только
// authenticate; syncUser требует store и покрыт интеграцией).
func newFakeVerifier(conn *fakeLdapConn) *LdapVerifier {
	m := settings.NewDefaultManager()
	cur := *m.Get()
	cur.LDAP = testLDAPCfg()
	m.SetForTest(&cur)
	return &LdapVerifier{
		set:  m,
		dial: func(context.Context, string, bool) (LdapConn, error) { return conn, nil },
	}
}

// searchByBase — фейковый поиск: запрос с (member= — поиск групп, прочий —
// поиск пользователя.
func searchByBase(user *ldap.Entry, groups ...*ldap.Entry) func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
	return func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
		if strings.Contains(req.Filter, "(member=") {
			return &ldap.SearchResult{Entries: groups}, nil
		}
		if user != nil {
			return &ldap.SearchResult{Entries: []*ldap.Entry{user}}, nil
		}
		return &ldap.SearchResult{}, nil
	}
}

func TestLdapAuthenticateSuccess(t *testing.T) {
	user := userEntry("CN=Ivanov,OU=Users,DC=example,DC=com", map[string][]string{
		"mail": {"ivanov@example.com"}, "telephoneNumber": {"+79990001122"}, "displayName": {"Иван Иванов"},
	})
	groups := []*ldap.Entry{{DN: "CN=VPN-Users,OU=Groups,DC=example,DC=com"}}
	cfg := testLDAPCfg()
	cfg.AllowGroups = []string{"cn=vpn-users,ou=groups,dc=example,dc=com"} // регистр DN не важен
	conn := &fakeLdapConn{
		bindOK: map[string]string{
			"CN=svc-twofa,DC=example,DC=com":       "svc-secret",
			"CN=Ivanov,OU=Users,DC=example,DC=com": "user-password",
		},
		searchFn: searchByBase(user, groups...),
	}
	v := newFakeVerifier(conn)

	res, err := v.authenticate(context.Background(), cfg, "ivanov", "user-password")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if res.dn != user.DN || res.email != "ivanov@example.com" ||
		res.phone != "+79990001122" || res.displayName != "Иван Иванов" {
		t.Fatalf("результат = %+v", res)
	}
	if res.role != "user" {
		t.Fatalf("роль = %q", res.role)
	}
	// Порядок: сервисный bind → поиск пользователя → поиск групп → bind паролем.
	if len(conn.binds) != 2 || conn.binds[0] != "CN=svc-twofa,DC=example,DC=com" || conn.binds[1] != user.DN {
		t.Fatalf("binds = %v", conn.binds)
	}
	if !conn.closed {
		t.Error("соединение не закрыто")
	}
	// Логин в фильтре экранирован и подставлен.
	if len(conn.searches) == 0 || !strings.Contains(conn.searches[0].Filter, "sAMAccountName=ivanov") {
		t.Fatalf("фильтр пользователя = %+v", conn.searches)
	}
	if !strings.Contains(conn.searches[0].Filter, "objectClass=user") {
		t.Fatalf("фильтр без objectClass: %s", conn.searches[0].Filter)
	}
	// Поиск групп: DN пользователя подставлен экранированно.
	if len(conn.searches) < 2 || !strings.Contains(conn.searches[1].Filter, "member=CN=Ivanov,OU=Users,DC=example,DC=com") {
		t.Fatalf("фильтр групп = %+v", conn.searches)
	}
	// Атрибуты контактов запрошены у поиска пользователя.
	wantAttrs := map[string]bool{"mail": false, "telephoneNumber": false, "displayName": false}
	for _, a := range conn.searches[0].Attributes {
		if _, ok := wantAttrs[a]; ok {
			wantAttrs[a] = true
		}
	}
	for a, seen := range wantAttrs {
		if !seen {
			t.Errorf("атрибут %s не запрошен (attrs = %v)", a, conn.searches[0].Attributes)
		}
	}
}

func TestLdapAuthenticateRoleAndAllowGroups(t *testing.T) {
	admin := userEntry("CN=Adminov,OU=Users,DC=example,DC=com", map[string][]string{
		"mail": {"adminov@example.com"},
	})
	cfg := testLDAPCfg()
	cfg.GroupBaseDN = "OU=Groups,DC=example,DC=com"
	cfg.RoleMap = map[string]string{"CN=VPN-Admins,OU=Groups,DC=example,DC=com": "admin"}
	conn := &fakeLdapConn{
		bindOK: map[string]string{
			"CN=svc-twofa,DC=example,DC=com":        "svc-secret",
			"CN=Adminov,OU=Users,DC=example,DC=com": "pw",
		},
		searchFn: searchByBase(admin, &ldap.Entry{DN: "CN=VPN-Admins,OU=Groups,DC=example,DC=com"}),
	}
	if _, err := newFakeVerifier(conn).authenticate(context.Background(), cfg, "adminov", "pw"); err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if len(conn.searches) != 2 {
		t.Fatalf("ожидались поиски пользователя и группы, получено %d", len(conn.searches))
	}
	if !strings.EqualFold(conn.searches[1].BaseDN, "OU=Groups,DC=example,DC=com") {
		t.Fatalf("group_base_dn = %q", conn.searches[1].BaseDN)
	}
}

func TestLdapAuthenticateNotFound(t *testing.T) {
	conn := &fakeLdapConn{bindOK: map[string]string{"CN=svc-twofa,DC=example,DC=com": "svc-secret"}}
	v := newFakeVerifier(conn)
	if _, err := v.authenticate(context.Background(), testLDAPCfg(), "ghost", "pw"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ghost = %v, want ErrNotFound", err)
	}
}

func TestLdapAuthenticateAmbiguousMatch(t *testing.T) {
	// Две записи по одному фильтру — неоднозначность, вход отклоняется
	// как «не найден» (без раскрытия причины наружу).
	conn := &fakeLdapConn{
		bindOK: map[string]string{"CN=svc-twofa,DC=example,DC=com": "svc-secret"},
		searchFn: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				{DN: "CN=a,DC=e"}, {DN: "CN=b,DC=e"},
			}}, nil
		},
	}
	if _, err := newFakeVerifier(conn).authenticate(context.Background(), testLDAPCfg(), "dup", "pw"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("неоднозначный поиск = %v, want ErrNotFound", err)
	}
}

func TestLdapAuthenticateBadPassword(t *testing.T) {
	user := userEntry("CN=Ivanov,OU=Users,DC=example,DC=com", nil)
	conn := &fakeLdapConn{
		bindOK:   map[string]string{"CN=svc-twofa,DC=example,DC=com": "svc-secret"},
		searchFn: searchByBase(user),
	}
	if _, err := newFakeVerifier(conn).authenticate(context.Background(), testLDAPCfg(), "ivanov", "wrong"); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("неверный пароль = %v, want ErrBadCredentials", err)
	}
	// Пользовательский bind был единственной проверкой пароля.
	if len(conn.binds) != 2 || conn.binds[1] != user.DN {
		t.Fatalf("binds = %v", conn.binds)
	}
}

func TestLdapAuthenticateEmptyPasswordRejectedBeforeDial(t *testing.T) {
	// Пустой пароль запрещён ДО соединения: bind с пустым паролем многие
	// каталоги трактуют как анонимный (unauthenticated bind) и отвечают
	// успехом — обход проверки.
	dialed := false
	v := &LdapVerifier{dial: func(context.Context, string, bool) (LdapConn, error) {
		dialed = true
		return &fakeLdapConn{}, nil
	}}
	if _, err := v.authenticate(context.Background(), testLDAPCfg(), "ivanov", ""); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("пустой пароль = %v, want ErrBadCredentials", err)
	}
	if dialed {
		t.Fatal("не должно быть соединения при пустом пароле")
	}
}

func TestLdapAuthenticateAllowGroupsRejectsNonMember(t *testing.T) {
	user := userEntry("CN=Outsider,OU=Users,DC=example,DC=com", nil)
	cfg := testLDAPCfg()
	cfg.AllowGroups = []string{"CN=VPN-Users,OU=Groups,DC=example,DC=com"}
	// Пользователь не состоит ни в одной группе: поиск групп пуст.
	conn := &fakeLdapConn{
		bindOK:   map[string]string{"CN=svc-twofa,DC=example,DC=com": "svc-secret"},
		searchFn: searchByBase(user),
	}
	if _, err := newFakeVerifier(conn).authenticate(context.Background(), cfg, "outsider", "pw"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("не-участник allow_groups = %v, want ErrNotFound", err)
	}
	// Проверка пароля (bind) не выполняется для отклонённого.
	if len(conn.binds) != 1 {
		t.Fatalf("binds = %v, ожидался только сервисный", conn.binds)
	}
}

func TestLdapAuthenticateSearchError(t *testing.T) {
	conn := &fakeLdapConn{
		bindOK: map[string]string{"CN=svc-twofa,DC=example,DC=com": "svc-secret"},
		searchFn: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, fmt.Errorf("каталог недоступен")
		},
	}
	if _, err := newFakeVerifier(conn).authenticate(context.Background(), testLDAPCfg(), "ivanov", "pw"); err == nil || errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ошибка поиска = %v, want внутренняя ошибка (не «не найден»)", err)
	}
}

func TestLdapAuthenticateAnonymousSearchWithoutBindDN(t *testing.T) {
	user := userEntry("CN=Ivanov,OU=Users,DC=example,DC=com", nil)
	cfg := testLDAPCfg()
	cfg.BindDN = "" // анонимный поиск: сервисного bind нет
	conn := &fakeLdapConn{
		bindOK:   map[string]string{"CN=Ivanov,OU=Users,DC=example,DC=com": "pw"},
		searchFn: searchByBase(user),
	}
	if _, err := newFakeVerifier(conn).authenticate(context.Background(), cfg, "ivanov", "pw"); err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if len(conn.binds) != 1 || conn.binds[0] != user.DN {
		t.Fatalf("binds = %v, ожидался только пользовательский", conn.binds)
	}
}

func TestLdapAuthenticateSkipsGroupSearchWhenUnused(t *testing.T) {
	// Ни allow_groups, ни role_map — поиск групп не нужен.
	user := userEntry("CN=Ivanov,OU=Users,DC=example,DC=com", nil)
	conn := &fakeLdapConn{
		bindOK:   map[string]string{"CN=svc-twofa,DC=example,DC=com": "svc-secret", user.DN: "pw"},
		searchFn: searchByBase(user),
	}
	if _, err := newFakeVerifier(conn).authenticate(context.Background(), testLDAPCfg(), "ivanov", "pw"); err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if len(conn.searches) != 1 {
		t.Fatalf("поисков = %d, ожидался один (пользователь)", len(conn.searches))
	}
}

func TestLdapEscapeFilterSpecialChars(t *testing.T) {
	// Напрямую проверяем отображение опасных символов логина.
	in := `()\<NUL>*`
	got := ldap.EscapeFilter(in)
	for _, want := range []string{`\28`, `\29`, `\5c`, `\2a`} {
		if !strings.Contains(got, want) {
			t.Errorf("EscapeFilter(%q) = %q, нет %s", in, got, want)
		}
	}
}

func TestLdapTestConnection(t *testing.T) {
	conn := &fakeLdapConn{
		bindOK: map[string]string{"CN=svc-twofa,DC=example,DC=com": "svc-secret"},
	}
	v := newFakeVerifier(conn)

	// Успешная проверка связи
	res, err := v.TestConnection(context.Background())
	if err != nil {
		t.Fatalf("TestConnection failed: %v", err)
	}
	if !res.BindOK || !res.BaseDNOK {
		t.Fatalf("TestConnection result: %+v", res)
	}

	// Ошибка Bind
	connBadBind := &fakeLdapConn{
		bindOK: map[string]string{},
	}
	vBad := newFakeVerifier(connBadBind)
	_, err = vBad.TestConnection(context.Background())
	if err == nil || !strings.Contains(err.Error(), "сервисный bind") {
		t.Fatalf("expected bind error, got: %v", err)
	}

	// Ошибка чтения Base DN
	connBadBase := &fakeLdapConn{
		bindOK: map[string]string{"CN=svc-twofa,DC=example,DC=com": "svc-secret"},
		searchFn: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, errors.New("base dn not found")
		},
	}
	vBadBase := newFakeVerifier(connBadBase)
	_, err = vBadBase.TestConnection(context.Background())
	if err == nil || !strings.Contains(err.Error(), "недоступен") {
		t.Fatalf("expected base dn error, got: %v", err)
	}
}

func TestLdapTestUserLookup(t *testing.T) {
	user := userEntry("CN=Ivanov,OU=Users,DC=example,DC=com", map[string][]string{
		"mail":            {"ivanov@example.com"},
		"telephoneNumber": {"+79990001122"},
		"displayName":     {"Иван Иванов"},
	})
	group := &ldap.Entry{DN: "CN=VPN-Admins,OU=Groups,DC=example,DC=com"}

	conn := &fakeLdapConn{
		bindOK: map[string]string{"CN=svc-twofa,DC=example,DC=com": "svc-secret"},
		searchFn: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			if strings.Contains(req.Filter, "(member=") {
				return &ldap.SearchResult{Entries: []*ldap.Entry{group}}, nil
			}
			return &ldap.SearchResult{Entries: []*ldap.Entry{user}}, nil
		},
	}
	v := newFakeVerifier(conn)

	// Настройка role_map и allow_groups
	m := v.set
	cur := *m.Get()
	cur.LDAP.AllowGroups = []string{"CN=VPN-Admins,OU=Groups,DC=example,DC=com"}
	cur.LDAP.RoleMap = map[string]string{"CN=VPN-Admins,OU=Groups,DC=example,DC=com": "admin"}
	m.SetForTest(&cur)

	res, err := v.TestUserLookup(context.Background(), "ivanov")
	if err != nil {
		t.Fatalf("TestUserLookup failed: %v", err)
	}
	if !res.Allowed {
		t.Errorf("expected user to be allowed, got false")
	}
	if res.Role != "admin" {
		t.Errorf("expected role admin, got %q", res.Role)
	}
	if res.Email != "ivanov@example.com" {
		t.Errorf("expected email ivanov@example.com, got %q", res.Email)
	}
	if len(res.Groups) != 1 || res.Groups[0] != group.DN {
		t.Errorf("expected group %q, got %v", group.DN, res.Groups)
	}

	// Проверка запрета пользователя, если группа не разрешена
	cur.LDAP.AllowGroups = []string{"CN=Other-Group,DC=example,DC=com"}
	m.SetForTest(&cur)

	resDisallowed, err := v.TestUserLookup(context.Background(), "ivanov")
	if err != nil {
		t.Fatalf("TestUserLookup failed: %v", err)
	}
	if resDisallowed.Allowed {
		t.Errorf("expected user to be disallowed")
	}
	if !strings.Contains(resDisallowed.Message, "ЗАПРЕЩЕН") {
		t.Errorf("expected message to mention forbidden access, got %q", resDisallowed.Message)
	}
}

func TestLdapSearchUsersPagingAndSizeLimit(t *testing.T) {
	u1 := userEntry("CN=User1,OU=Users,DC=example,DC=com", map[string][]string{"sAMAccountName": {"user1"}})
	u2 := userEntry("CN=User2,OU=Users,DC=example,DC=com", map[string][]string{"sAMAccountName": {"user2"}})

	// 1. Тестируем, что при ошибке SizeLimitExceeded от сервера с возвращенными записями,
	// searchUsers не падает, а возвращает имеющиеся записи.
	connLimit := &fakeLdapConn{
		searchFn: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{u1, u2}}, ldap.NewError(ldap.LDAPResultSizeLimitExceeded, errors.New("size limit exceeded"))
		},
	}
	v := newFakeVerifier(connLimit)
	cfg := testLDAPCfg()
	entries, err := v.searchUsers(connLimit, cfg, "(&(objectClass=user)(sAMAccountName=*))", 100)
	if err != nil {
		t.Fatalf("searchUsers with SizeLimitExceeded returned error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	// 2. Тестируем многостраничный поиск с ControlPaging cookie
	called := 0
	connPaging := &fakeLdapConn{
		searchFn: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			called++
			if called == 1 {
				ctrl := ldap.NewControlPaging(2)
				ctrl.SetCookie([]byte("page2-cookie"))
				return &ldap.SearchResult{
					Entries:  []*ldap.Entry{u1},
					Controls: []ldap.Control{ctrl},
				}, nil
			}
			return &ldap.SearchResult{
				Entries: []*ldap.Entry{u2},
			}, nil
		},
	}
	vPaging := newFakeVerifier(connPaging)
	entriesPaging, err := vPaging.searchUsers(connPaging, cfg, "(&(objectClass=user)(sAMAccountName=*))", 100)
	if err != nil {
		t.Fatalf("searchUsers with paging returned error: %v", err)
	}
	if len(entriesPaging) != 2 {
		t.Fatalf("expected 2 entries from 2 pages, got %d", len(entriesPaging))
	}
	if called != 2 {
		t.Fatalf("expected 2 search queries for 2 pages, got %d", called)
	}
}
