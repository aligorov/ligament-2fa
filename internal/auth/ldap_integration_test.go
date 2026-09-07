//go:build integration

// Интеграционные тесты LDAP-бэкенда на PostgreSQL (testcontainers-go) с
// фейковым LDAP-соединением: полный Verify с авто-провижинингом и синком,
// матрица маршрутизации CompositeVerifier, тайминг-приманка на
// «не найден в каталоге». Настоящий каталог (openldap) проверяется на
// уровне API — internal/api/ldap_integration_test.go.
package auth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"

	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
)

// fakeDialOf — конфигурация фейкового каталога для интеграционных тестов:
// пользователь с атрибутами и группами, пароль для bind.
type fakeDirectory struct {
	mu      sync.Mutex
	conn    *fakeLdapConn
	entries map[string]*ldap.Entry // username → запись
	binds   map[string]string      // DN → верный пароль
	groups  map[string][]string    // username → DN групп
}

func newFakeDirectory() *fakeDirectory {
	d := &fakeDirectory{
		entries: map[string]*ldap.Entry{},
		binds:   map[string]string{},
		groups:  map[string][]string{},
	}
	// Сервисная учётка поиска — как в enableLDAP ниже.
	d.binds["CN=svc-twofa,DC=example,DC=com"] = "svc-secret"
	return d
}

func (d *fakeDirectory) addUser(username, password string, attrs map[string][]string, groups ...string) {
	dn := "CN=" + username + ",OU=Users,DC=example,DC=com"
	full := map[string][]string{
		"mail":           {"ldap+" + username + "@example.com"},
		"sAMAccountName": {username},
	}
	for k, v := range attrs {
		full[k] = v
	}
	d.entries[username] = userEntry(dn, full)
	d.binds[dn] = password
	d.groups[username] = groups
}

// dial возвращает фабрику соединений, отвечающую содержимым каталога.
func (d *fakeDirectory) dial() func(context.Context, string, bool) (LdapConn, error) {
	return func(context.Context, string, bool) (LdapConn, error) {
		d.mu.Lock()
		defer d.mu.Unlock()
		conn := &fakeLdapConn{bindOK: d.binds}
		conn.searchFn = func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			if strings.Contains(req.Filter, "(member=") {
				// DN пользователя — из подставленного {dn}; возвращаем его группы.
				dn := filterMemberDN(req.Filter)
				var out []*ldap.Entry
				for username, gs := range d.groups {
					if strings.EqualFold("CN="+username+",OU=Users,DC=example,DC=com", dn) {
						for _, g := range gs {
							out = append(out, &ldap.Entry{DN: g})
						}
					}
				}
				return &ldap.SearchResult{Entries: out}, nil
			}
			for _, e := range d.entries {
				login := attrOf(e, "sAMAccountName")
				if login != "" && strings.Contains(req.Filter, "sAMAccountName="+login) {
					return &ldap.SearchResult{Entries: []*ldap.Entry{e}}, nil
				}
			}
			return &ldap.SearchResult{}, nil
		}
		d.conn = conn
		return conn, nil
	}
}

// filterMemberDN извлекает значение после «member=» до закрывающей скобки.
func filterMemberDN(filter string) string {
	i := strings.Index(filter, "member=")
	if i < 0 {
		return ""
	}
	v := filter[i+len("member="):]
	if j := strings.IndexByte(v, ')'); j >= 0 {
		v = v[:j]
	}
	return v
}

func attrOf(e *ldap.Entry, name string) string {
	for _, a := range e.Attributes {
		if strings.EqualFold(a.Name, name) && len(a.Values) > 0 {
			return a.Values[0]
		}
	}
	return ""
}

// newLdapVerifier над фейковым каталогом и общей тестовой БД.
func newLdapVerifier(t *testing.T, dir *fakeDirectory) (*LdapVerifier, *settings.M) {
	t.Helper()
	st, set, _ := setup(t)
	return &LdapVerifier{st: st, set: set, dial: dir.dial()}, set
}

// enableLDAP включает бэкенд с типовыми параметрами под фейковый каталог.
func enableLDAP(t *testing.T, ctx context.Context, m *settings.M, mutate func(*settings.LDAPSettings)) {
	t.Helper()
	cfg := testLDAPCfg()
	if mutate != nil {
		mutate(&cfg)
	}
	mustPut(t, ctx, m, "ldap", ldapSettingsJSON(t, cfg))
	// Восстановление — выключенный бэкенд с дефолтами (контейнер общий).
	// Свежий контекст: t.Context() к моменту Cleanup уже отменён.
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		mustPut(t, cctx, m, "ldap", `{"enabled":false,"starttls":false,`+
			`"bind_dn":"","bind_password":"","base_dn":"",`+
			`"user_filter":"(&(objectClass=user)(sAMAccountName={login}))",`+
			`"group_base_dn":"","group_filter":"(&(objectClass=group)(member={dn}))",`+
			`"attrs":{"email":"mail","phone":"telephoneNumber","display_name":"displayName"},`+
			`"allow_groups":[],"role_map":{}}`)
	})
}

func ldapSettingsJSON(t *testing.T, cfg settings.LDAPSettings) string {
	t.Helper()
	return `{"enabled":` + boolJSON(cfg.Enabled) + `,"url":"` + cfg.URL +
		`","starttls":` + boolJSON(cfg.StartTLS) +
		`,"bind_dn":"CN=svc-twofa,DC=example,DC=com","bind_password":"svc-secret"` +
		`,"base_dn":"DC=example,DC=com"` +
		`,"user_filter":"(&(objectClass=user)(sAMAccountName={login}))"` +
		`,"group_base_dn":"","group_filter":"(&(objectClass=group)(member={dn}))"` +
		`,"attrs":{"email":"mail","phone":"telephoneNumber","display_name":"displayName"},` +
		`"allow_groups":` + stringsJSON(cfg.AllowGroups) + `,"role_map":` + roleMapJSON(cfg.RoleMap) + `}`
}

func boolJSON(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func stringsJSON(ss []string) string {
	if len(ss) == 0 {
		return "[]"
	}
	out := "["
	for i, s := range ss {
		if i > 0 {
			out += ","
		}
		out += `"` + s + `"`
	}
	return out + "]"
}

func roleMapJSON(m map[string]string) string {
	if len(m) == 0 {
		return "{}"
	}
	out := "{"
	first := true
	for k, v := range m {
		if !first {
			out += ","
		}
		first = false
		out += `"` + k + `":"` + v + `"`
	}
	return out + "}"
}

// TestLdapVerifyAutoProvisionAndSync — полный Verify на фейковом каталоге:
// авто-провижининг при первом входе, синк изменившихся атрибутов при
// повторном, непригодный локальный пароль у LDAP-пользователя.
func TestLdapVerifyAutoProvisionAndSync(t *testing.T) {
	dir := newFakeDirectory()
	dir.addUser("syncuser", "dir-pass-1", map[string][]string{
		"telephoneNumber": {"+79990001122"}, "displayName": {"Иван Первоначальный"},
	}, "CN=VPN-Users,OU=Groups,DC=example,DC=com")
	v, set := newLdapVerifier(t, dir)
	ctx := t.Context()
	enableLDAP(t, ctx, set, nil)

	// Первый вход: пользователя нет в БД — авто-провижининг.
	u, err := v.Verify(ctx, "syncuser", "dir-pass-1")
	if err != nil {
		t.Fatalf("первый Verify: %v", err)
	}
	if u.Source != store.SourceLDAP || !u.Enabled || u.Role != "user" {
		t.Fatalf("авто-провижининг: %+v", u)
	}
	if u.Email != "ldap+syncuser@example.com" || u.Phone != "+79990001122" ||
		u.DisplayName != "Иван Первоначальный" {
		t.Fatalf("атрибуты не синхронизированы: %+v", u)
	}
	if u.PasswordHash == "" || strings.Contains(u.PasswordHash, "dir-pass") {
		t.Fatalf("password_hash = %q, ожидался случайный непригодный хеш", u.PasswordHash)
	}
	// Локальный пароль не работает (хеш случайного секрета).
	st, _, _ := setup(t)
	if _, err := NewLocalVerifier(st).Verify(ctx, "syncuser", "dir-pass-1"); err == nil {
		t.Fatal("локальная проверка LDAP-пароля должна проваливаться")
	}

	// Второй вход: атрибут в каталоге изменился — синк обновляет.
	dir.mu.Lock()
	dir.entries["syncuser"] = userEntry("CN=syncuser,OU=Users,DC=example,DC=com", map[string][]string{
		"mail": {"ldap+syncuser@example.com"}, "displayName": {"Иван Обновлённый"},
		"sAMAccountName": {"syncuser"},
	})
	dir.mu.Unlock()
	u2, err := v.Verify(ctx, "syncuser", "dir-pass-1")
	if err != nil {
		t.Fatalf("повторный Verify: %v", err)
	}
	if u2.DisplayName != "Иван Обновлённый" {
		t.Fatalf("display_name не синхронизирован: %q", u2.DisplayName)
	}
	if u2.ID != u.ID {
		t.Fatalf("повторный вход создал новую строку: %s vs %s", u2.ID, u.ID)
	}

	// Неверный пароль каталога.
	if _, err := v.Verify(ctx, "syncuser", "wrong"); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("неверный пароль = %v, want ErrBadCredentials", err)
	}
}

// TestLdapVerifyProvisionBareEntry — авто-провижининг записи БЕЗ атрибутов
// (пустые mail/phone/displayName, без групп и role_map): пользователь всё
// равно должен сохраниться в БД, а не вернуться «фантомом» с пустым ID.
// Регрессия: старая ветка создания срабатывала только при изменении полей,
// а у новой записи с нулевыми атрибутами «изменений» нет.
func TestLdapVerifyProvisionBareEntry(t *testing.T) {
	dir := newFakeDirectory()
	dir.addUser("noattrsuser", "pw", nil)
	// Запись без единого атрибута контакта (addUser всегда добавляет mail).
	dir.mu.Lock()
	dir.entries["noattrsuser"] = userEntry("CN=noattrsuser,OU=Users,DC=example,DC=com",
		map[string][]string{"sAMAccountName": {"noattrsuser"}})
	dir.mu.Unlock()
	v, set := newLdapVerifier(t, dir)
	ctx := t.Context()
	enableLDAP(t, ctx, set, nil)

	u, err := v.Verify(ctx, "noattrsuser", "pw")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if u.ID == uuid.Nil {
		t.Fatal("Verify вернул пользователя с пустым ID — строка не сохранена")
	}
	st, _, _ := setup(t)
	persisted, err := st.UserByUsername(ctx, "noattrsuser")
	if err != nil {
		t.Fatalf("строка не найдена в БД после первого входа: %v", err)
	}
	if persisted.Source != store.SourceLDAP || persisted.Role != "user" || persisted.Email != "" {
		t.Fatalf("сохранённая строка: %+v", persisted)
	}
}

// TestLdapVerifyRoleMapGrantsAdmin — role_map повышает роль до admin и
// понижает обратно при пропадании группы (синк роли).
func TestLdapVerifyRoleMapGrantsAdmin(t *testing.T) {
	dir := newFakeDirectory()
	adminDN := "CN=VPN-Admins,OU=Groups,DC=example,DC=com"
	dir.addUser("roleuser", "pw", nil, adminDN)
	v, set := newLdapVerifier(t, dir)
	ctx := t.Context()
	enableLDAP(t, ctx, set, func(cfg *settings.LDAPSettings) {
		cfg.RoleMap = map[string]string{adminDN: "admin"}
	})

	u, err := v.Verify(ctx, "roleuser", "pw")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if u.Role != "admin" {
		t.Fatalf("роль = %q, want admin (role_map по DN группы)", u.Role)
	}

	// Пользователь выведен из группы — роль возвращается к user.
	dir.mu.Lock()
	dir.groups["roleuser"] = nil
	dir.mu.Unlock()
	u2, err := v.Verify(ctx, "roleuser", "pw")
	if err != nil {
		t.Fatalf("Verify после вывода из группы: %v", err)
	}
	if u2.Role != "user" {
		t.Fatalf("роль после вывода из группы = %q, want user", u2.Role)
	}
}

// TestLdapVerifyDisabledLocally — отключённая админом LDAP-учётка не
// входит, синхронизация её не ре-включает.
func TestLdapVerifyDisabledLocally(t *testing.T) {
	dir := newFakeDirectory()
	dir.addUser("offuser", "pw", nil)
	v, set := newLdapVerifier(t, dir)
	ctx := t.Context()
	enableLDAP(t, ctx, set, nil)

	if _, err := v.Verify(ctx, "offuser", "pw"); err != nil {
		t.Fatalf("первый вход: %v", err)
	}
	st, _, _ := setup(t)
	u, err := st.UserByUsername(ctx, "offuser")
	if err != nil {
		t.Fatalf("UserByUsername: %v", err)
	}
	u.Enabled = false
	if err := st.UserUpdate(ctx, u); err != nil {
		t.Fatalf("UserUpdate: %v", err)
	}
	if _, err := v.Verify(ctx, "offuser", "pw"); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("отключённый = %v, want ErrBadCredentials", err)
	}
	u2, _ := st.UserByUsername(ctx, "offuser")
	if u2.Enabled {
		t.Fatal("синхронизация ре-включила отключённого пользователя")
	}
}

// TestCompositeRoutingMatrix — маршрутизация CompositeVerifier:
// локальный известный → argon2; LDAP-известный → каталог; неизвестный при
// включённом LDAP → каталог (авто-провижининг); неизвестный при выключенном
// → локальная ветка с приманкой.
func TestCompositeRoutingMatrix(t *testing.T) {
	st, set, _ := setup(t)
	ctx := t.Context()

	dir := newFakeDirectory()
	dir.addUser("ldaper", "dir-pass", nil)
	local := mkUser(t, ctx, st, "localer", nil)
	composite := NewCompositeVerifier(st, NewLocalVerifier(st), &LdapVerifier{st: st, set: set, dial: dir.dial()})

	// LDAP выключен: всё как раньше.
	u, err := composite.Verify(ctx, local.Username, testPassword)
	if err != nil || u.ID != local.ID {
		t.Fatalf("локальный при выключенном LDAP: %v %v", u, err)
	}
	if _, err := composite.Verify(ctx, "ldaper", "dir-pass"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("каталоговый при выключенном LDAP = %v, want ErrNotFound", err)
	}

	enableLDAP(t, ctx, set, nil)

	// Локальный пользователь по-прежнему проверяется локально.
	if _, err := composite.Verify(ctx, local.Username, "wrong"); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("локальный неверный пароль = %v", err)
	}
	// LDAP-пользователь — каталогом (пароль существует только там).
	u, err = composite.Verify(ctx, "ldaper", "dir-pass")
	if err != nil || u.Source != store.SourceLDAP {
		t.Fatalf("каталоговый пользователь: %v %v", u, err)
	}
	// Локальный пароль каталогового пользователя не работает.
	if _, err := composite.Verify(ctx, "ldaper", testPassword); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("каталоговый с локальным паролем = %v, want ErrBadCredentials", err)
	}
	// Каталоговый пользователь после провижининга проверяется каталогом.
	if _, err := composite.Verify(ctx, "ldaper", "dir-pass"); err != nil {
		t.Fatalf("повторный вход каталогового: %v", err)
	}

	// Локальный пользователь не конвертируется: его имя в каталоге даёт
	// ErrNotFound, вход остаётся по локальному паролю.
	dir.addUser(local.Username, "shadow-pass", nil)
	if _, err := (&LdapVerifier{st: st, set: set, dial: dir.dial()}).Verify(ctx, local.Username, "shadow-pass"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("двойной источник пароля = %v, want ErrNotFound", err)
	}
	if _, err := composite.Verify(ctx, local.Username, testPassword); err != nil {
		t.Fatalf("локальный вход после появления тёзки в каталоге: %v", err)
	}
}

// TestCompositeBurnOnLdapNotFound — «не найден в каталоге» выполняет
// argon2-приманку (единый тайминг с локальной веткой).
func TestCompositeBurnOnLdapNotFound(t *testing.T) {
	st, set, _ := setup(t)
	ctx := t.Context()
	dir := newFakeDirectory()
	composite := NewCompositeVerifier(st, NewLocalVerifier(st),
		&LdapVerifier{st: st, set: set, dial: dir.dial()})

	enableLDAP(t, ctx, set, nil)
	restore, count := withBurnSpy()
	defer restore()
	if _, err := composite.Verify(ctx, "ghost-in-directory", "pw"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ghost = %v, want ErrNotFound", err)
	}
	if count() != 1 {
		t.Fatalf("burn вызван %d раз, ожидался 1 (тайминг-приманка)", count())
	}
}

// TestLdapVerifyDisabledBackend — выключенный бэкенд: ErrNotFound без
// обращения к каталогу.
func TestLdapVerifyDisabledBackend(t *testing.T) {
	st, set, _ := setup(t)
	ctx := t.Context()
	dialed := false
	v := &LdapVerifier{st: st, set: set, dial: func(context.Context, string, bool) (LdapConn, error) {
		dialed = true
		return &fakeLdapConn{}, nil
	}}
	if _, err := v.Verify(ctx, "whoever", "pw"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("выключенный бэкенд = %v, want ErrNotFound", err)
	}
	if dialed {
		t.Fatal("выключенный бэкенд не должен открывать соединение")
	}
}

// blockingLdapConn — соединение «зависшего каталога»: каждая операция
// висит до отмены контекста соединения и возвращает его ошибку.
type blockingLdapConn struct{ ctx context.Context }

func (b blockingLdapConn) Bind(string, string) error {
	<-b.ctx.Done()
	return b.ctx.Err()
}

func (b blockingLdapConn) Search(*ldap.SearchRequest) (*ldap.SearchResult, error) {
	<-b.ctx.Done()
	return nil, b.ctx.Err()
}

func (b blockingLdapConn) Close() error { return nil }

// TestLdapVerifyAppliesDefaultTimeout (FIX-2): веб-вход передаёт
// r.Context() БЕЗ deadline — Verify обязан навесить собственный потолок
// на обмен с каталогом (dial + bind + поиски), иначе зависший каталог
// подвешивает goroutine запроса навсегда. Более ранний deadline родителя
// сохраняется (context.WithTimeout берёт минимум из двух).
func TestLdapVerifyAppliesDefaultTimeout(t *testing.T) {
	st, set, _ := setup(t)
	ctx := t.Context()
	enableLDAP(t, ctx, set, nil)

	saved := ldapOpTimeout
	ldapOpTimeout = 200 * time.Millisecond
	t.Cleanup(func() { ldapOpTimeout = saved })

	var dialed context.Context
	v := &LdapVerifier{st: st, set: set, dial: func(ctx context.Context, _ string, _ bool) (LdapConn, error) {
		dialed = ctx
		return blockingLdapConn{ctx: ctx}, nil
	}}
	verifyAsync := func(parent context.Context) error {
		done := make(chan error, 1)
		go func() {
			_, err := v.Verify(parent, "ivanov", "pw")
			done <- err
		}()
		select {
		case err := <-done:
			return err
		case <-time.After(3 * time.Second):
			t.Fatal("Verify не вернулся — потолок LDAP-операций не применяется")
			return nil
		}
	}

	// Родитель без deadline: потолок навешивает сам Verify.
	start := time.Now()
	if err := verifyAsync(context.Background()); err == nil {
		t.Fatal("ожидалась ошибка (каталог «завис» до отмены)")
	}
	if elapsed := time.Since(start); elapsed > ldapOpTimeout+2*time.Second {
		t.Fatalf("Verify висел %v — потолок не применён", elapsed)
	}
	dl, ok := dialed.Deadline()
	if !ok {
		t.Fatal("dial получил ctx без deadline — таймаут не навешан")
	}
	// Deadline не дальше потолка (отрицательный остаток — уже истёк, это
	// ожидаемо: Verify вернулся именно из-за него).
	if d := time.Until(dl); d > ldapOpTimeout {
		t.Fatalf("deadline dial-а = %v дальше потолка %v", d, ldapOpTimeout)
	}

	// Более короткий deadline родителя не удлиняется потолком.
	parent, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	if err := verifyAsync(parent); err == nil {
		t.Fatal("ожидалась ошибка по короткому родительскому deadline")
	}
	pdl, ok := dialed.Deadline()
	if !ok {
		t.Fatal("второй dial без deadline")
	}
	if d := time.Until(pdl); d > 60*time.Millisecond {
		t.Fatalf("короткий родительский deadline перекрыт потолком: %v", d)
	}
}

// TestLdapSyncUserUniqueViolationRace (FIX-3): гонка авто-провижининга —
// параллельный вход вставил строку между SELECT и INSERT syncUser
// (unique-нарушение 23505): вместо внутренней ошибки (500 на входе)
// перечитываем строку и продолжаем как синк существующей записи.
func TestLdapSyncUserUniqueViolationRace(t *testing.T) {
	st, set, _ := setup(t)
	ctx := t.Context()
	v := &LdapVerifier{st: st, set: set, dial: newFakeDirectory().dial()}

	// «Параллельный вход»: строка вставлена в НЕЗАВЕРШЕННОЙ транзакции —
	// SELECT syncUser её ещё не видит (ErrNotFound → ветка create), а
	// INSERT подвисает на unique-конфликте до commit и получает 23505.
	tx, err := st.Pool().Begin(ctx)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	if _, err := tx.Exec(ctx, `INSERT INTO users (id, username, password_hash, role, enabled, source)
		VALUES (gen_random_uuid(), 'raceuser', 'argon2-race-hash', 'user', true, 'ldap')`); err != nil {
		t.Fatalf("сид-вставка «параллельного входа»: %v", err)
	}

	res := &ldapAuthResult{email: "race@example.com", displayName: "Гонщиков"}
	type outcome struct {
		u   *store.User
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		u, err := v.syncUser(ctx, "raceuser", res, set.Get().LDAP)
		done <- outcome{u, err}
	}()

	time.Sleep(200 * time.Millisecond) // syncUser доходит до INSERT и висит на конфликте
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("гонка 23505: %v (ожидалось продолжение как синк без ошибки)", got.err)
		}
		if got.u.Username != "raceuser" || got.u.Source != store.SourceLDAP {
			t.Fatalf("пользователь после гонки: %+v", got.u)
		}
		// «Чужая» строка до-синхронизирована атрибутами каталога; строка одна.
		fresh, err := st.UserByUsername(ctx, "raceuser")
		if err != nil {
			t.Fatalf("UserByUsername: %v", err)
		}
		if fresh.Email != "race@example.com" || fresh.DisplayName != "Гонщиков" {
			t.Fatalf("атрибуты после гонки не досинхронизированы: %+v", fresh)
		}
		var n int
		if err := st.Pool().QueryRow(ctx,
			`SELECT count(*) FROM users WHERE username = 'raceuser'`).Scan(&n); err != nil || n != 1 {
			t.Fatalf("строк raceuser = %d (err %v), want 1", n, err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("syncUser не вернулся после unique-конфликта")
	}
}
