// LDAP/Active Directory — внешний бэкенд первого фактора (T-ldap).
// Пароль проверяется bind-ом в каталоге (локальный argon2id-хеш для
// LDAP-пользователей не используется), атрибуты контактов и роли из групп
// синхронизируются в локальную строку users (авто-провижининг при первом
// входе). LdapVerifier встраивается в CompositeVerifier; отдельно от него
// не применяется.
package auth

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"reflect"
	"strings"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/aligorov/twofa/internal/secrets"
	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
)

// LdapConn — минимальная поверхность go-ldap-соединения, необходимая
// верификатору: Bind (сервисный и пользовательский), Search (пользователь
// и группы), Close. Узкий интерфейс позволяет подменять соединение
// фейком в unit-тестах и держать протокольную логику тестируемой без
// каталога.
type LdapConn interface {
	Bind(username, password string) error
	Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error)
	Close() error
}

// ldapDial — фабрика соединений с каталогом (переменная для подмены в
// тестах). ldaps:// соединяется сразу по TLS; ldap:// с starttls поднимает
// STARTTLS после подключения; deadline контекста переносится в соединение.
var ldapDial = func(ctx context.Context, rawURL string, starttls bool) (LdapConn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("auth/ldap: неподдерживаемый url %q: %w", rawURL, err)
	}
	host := u.Hostname()
	tlsCfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	scheme := strings.ToLower(u.Scheme)
	var conn *ldap.Conn
	switch scheme {
	case "ldaps":
		if conn, err = ldap.DialURL(rawURL, ldap.DialWithTLSConfig(tlsCfg)); err != nil {
			return nil, fmt.Errorf("auth/ldap: подключение %s: %w", rawURL, err)
		}
	case "ldap", "":
		if conn, err = ldap.DialURL(rawURL); err != nil {
			return nil, fmt.Errorf("auth/ldap: подключение %s: %w", rawURL, err)
		}
		if starttls {
			if err := conn.StartTLS(tlsCfg); err != nil {
				conn.Close()
				return nil, fmt.Errorf("auth/ldap: STARTTLS %s: %w", rawURL, err)
			}
		}
	default:
		return nil, fmt.Errorf("auth/ldap: неподдерживаемая схема %q (ldap:// или ldaps://)", u.Scheme)
	}
	if dl, ok := ctx.Deadline(); ok {
		conn.SetTimeout(time.Until(dl))
	}
	return conn, nil
}

// LdapVerifier — PasswordVerifier поверх каталога LDAP/AD. Конфигурация
// читается из снимка настроек при каждом вызове — SIGHUP-перечитывание
// применяется без пересборки верификатора.
type LdapVerifier struct {
	st   *store.Store
	set  *settings.M
	dial func(ctx context.Context, rawURL string, starttls bool) (LdapConn, error)
}

// NewLdapVerifier возвращает LDAP-верификатор поверх store и настроек.
func NewLdapVerifier(st *store.Store, set *settings.M) *LdapVerifier {
	return &LdapVerifier{st: st, set: set, dial: ldapDial}
}

var _ PasswordVerifier = (*LdapVerifier)(nil)

// Enabled сообщает, включён ли LDAP-бэкенд в текущем снимке настроек.
func (v *LdapVerifier) Enabled() bool {
	t := v.set.Get()
	return t != nil && t.LDAP.Enabled
}

// ldapAuthResult — пользователь каталога после успешной проверки пароля.
type ldapAuthResult struct {
	dn, email, phone, displayName, role string
	groups                              []string
	radiusReply                         map[string]string
}

// ldapOpTimeout — безусловный потолок LDAP-операций (dial + сервисный
// bind + поиски + пользовательский bind). Веб-вход передаёт r.Context()
// без deadline — без потолка зависший каталог подвешивает goroutine
// запроса. Переменная (а не константа) для подмены в тестах.
var ldapOpTimeout = 30 * time.Second

// Verify проверяет пароль bind-ом в каталоге и синхронизирует локальную
// учётную запись (создание при первом входе, обновление атрибутов и роли).
// Ошибки: store.ErrNotFound — пользователь не найден/не прошёл allow-list
// (после argon2-приманки — единый тайминг с LocalVerifier); ErrBadCredentials
// — неверный пароль или отключённая учётная запись; прочие — внутренние
// (каталог недоступен, ошибка конфигурации).
func (v *LdapVerifier) Verify(ctx context.Context, username, password string) (*store.User, error) {
	t := v.set.Get()
	if t == nil || !t.LDAP.Enabled {
		// Бэкенд выключен — «пользователь не найден» (композит уйдёт в local).
		return nil, store.ErrNotFound
	}
	// Безусловный потолок на весь обмен с каталогом (dial + bind + поиски +
	// пользовательский bind): веб-вход передаёт r.Context() без deadline, и
	// без потолка зависший каталог подвешивает goroutine запроса навсегда.
	// Более ранний deadline родителя сохраняется — WithTimeout берёт
	// минимум из двух границ.
	ctx, cancel := context.WithTimeout(ctx, ldapOpTimeout)
	defer cancel()
	res, err := v.authenticate(ctx, t.LDAP, username, password)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Тайминг-оракул (как в LocalVerifier): «нет пользователя» стоит
			// argon2-цену неверного пароля, а не мгновенный ответ.
			burnDummyVerify(password)
		}
		return nil, err
	}
	return v.syncUser(ctx, username, res, t.LDAP)
}

// authenticate — протокольная часть: соединение, сервисный bind (при
// заданном bind_dn), поиск пользователя по user_filter, поиск групп,
// allow-list и проверка пароля bind-ом от имени пользователя. Не касается
// локальной БД — тестируется на фейковом соединении.
func (v *LdapVerifier) authenticate(ctx context.Context, cfg settings.LDAPSettings, username, password string) (*ldapAuthResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Пустой пароль отвергается ДО соединения: bind с пустым паролем многие
	// каталоги выполняют как анонимный (unauthenticated bind) и отвечают
	// успехом — это обход проверки первого фактора.
	if password == "" {
		return nil, ErrBadCredentials
	}

	conn, err := v.dial(ctx, cfg.URL, cfg.StartTLS)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Сервисный bind для поиска (пустой bind_dn — анонимный поиск).
	if cfg.BindDN != "" {
		if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
			return nil, fmt.Errorf("auth/ldap: сервисный bind: %w", err)
		}
	}

	// Поиск записи пользователя; {login} экранируется по RFC 4515.
	userReq := ldap.NewSearchRequest(
		cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 0, false,
		substFilter(cfg.UserFilter, "{login}", username),
		ldapAttrs(cfg), nil,
	)
	userRes, err := conn.Search(userReq)
	if err != nil {
		return nil, fmt.Errorf("auth/ldap: поиск пользователя: %w", err)
	}
	switch len(userRes.Entries) {
	case 1: // единственная запись — продолжаем
	case 0:
		return nil, store.ErrNotFound
	default:
		// Неоднозначное совпадение: без раскрытия деталей наружу.
		slog.WarnContext(ctx, "auth/ldap: фильтр пользователя вернул несколько записей",
			"username", username, "entries", len(userRes.Entries))
		return nil, store.ErrNotFound
	}
	entry := userRes.Entries[0]
	if entry.DN == "" {
		return nil, fmt.Errorf("auth/ldap: запись пользователя без DN")
	}
	res := &ldapAuthResult{
		dn:          entry.DN,
		email:       entry.GetAttributeValue(cfg.Attrs.Email),
		phone:       entry.GetAttributeValue(cfg.Attrs.Phone),
		displayName: entry.GetAttributeValue(cfg.Attrs.DisplayName),
	}

	// Группы нужны для allow-list, role_map и group_radius_map.
	groups := []string{}
	if len(cfg.AllowGroups) > 0 || len(cfg.RoleMap) > 0 || len(cfg.GroupRadiusMap) > 0 {
		base := cfg.GroupBaseDN
		if base == "" {
			base = cfg.BaseDN
		}
		groupReq := ldap.NewSearchRequest(
			base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			substFilter(cfg.GroupFilter, "{dn}", entry.DN), nil, nil,
		)
		groupRes, err := conn.Search(groupReq)
		if err != nil {
			return nil, fmt.Errorf("auth/ldap: поиск групп: %w", err)
		}
		for _, g := range groupRes.Entries {
			if g.DN != "" {
				groups = append(groups, g.DN)
			}
		}
	}
	if !memberAllowed(groups, cfg.AllowGroups) {
		// Не участник разрешённых групп — «не найден» (причина не раскрывается).
		slog.InfoContext(ctx, "auth/ldap: пользователь не в allow_groups", "username", username)
		return nil, store.ErrNotFound
	}
	res.groups = groups
	res.role = resolveRole(groups, cfg.RoleMap)
	res.radiusReply = ResolveGroupRadiusAttrs(groups, cfg.GroupRadiusMap)

	// Проверка пароля: bind от имени пользователя. Неверные учётные данные —
	// ожидаемый 49-й код; прочие ошибки каталога — внутренние.
	if err := conn.Bind(entry.DN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return nil, ErrBadCredentials
		}
		return nil, fmt.Errorf("auth/ldap: пользовательский bind: %w", err)
	}
	return res, nil
}

// syncUser — авто-провижининг и синхронизация локальной строки users после
// успешного bind: неизвестный пользователь создаётся (source='ldap',
// случайный непригодный хеш пароля — локальный вход невозможен);
// существующий LDAP-пользователь обновляется только изменившимися полями
// (email/phone/display_name/role; telegram_chat_id, TOTP, prefer-каналы и
// пр. не трогаются). Локальный пользователь с тем же именем НЕ
// конвертируется (двойной источник пароля запрещён).
func (v *LdapVerifier) syncUser(ctx context.Context, username string, res *ldapAuthResult, cfg settings.LDAPSettings) (*store.User, error) {
	u, err := v.st.UserByUsername(ctx, username)
	create := false
	switch {
	case err == nil && u.Source == store.SourceLDAP:
		// Существующий LDAP-пользователь — синхронизация ниже.
	case err == nil:
		slog.WarnContext(ctx, "auth/ldap: имя занято локальным пользователем, вход только по локальному паролю",
			"username", username)
		return nil, store.ErrNotFound
	case errors.Is(err, store.ErrNotFound):
		create = true
		u = &store.User{
			Username: username,
			Role:     "user",
			Enabled:  true,
			// Локальный вход невозможен: хеш случайного секрета, пароль
			// никто не знает (в т.ч. администратор twofa).
			PasswordHash: secrets.HashPassword(secrets.RandomToken(32)),
			Source:       store.SourceLDAP,
			LDAPGroups:   res.groups,
		}
	default:
		return nil, err
	}
	if !u.Enabled {
		// Отключён админом: синхронизация не ре-включает учётную запись.
		return nil, ErrBadCredentials
	}

	changed := u.Email != res.email || u.Phone != res.phone ||
		u.DisplayName != res.displayName || u.Role != res.role ||
		!reflect.DeepEqual(u.LDAPGroups, res.groups)
	u.Email = res.email
	u.Phone = res.phone
	u.DisplayName = res.displayName
	u.Role = res.role
	u.LDAPGroups = res.groups
	if len(cfg.GroupRadiusMap) > 0 {
		if !reflect.DeepEqual(u.RadiusReply, res.radiusReply) {
			u.RadiusReply = res.radiusReply
			changed = true
		}
	}
	// Новая запись сохраняется всегда — даже с нулевыми атрибутами (иначе
	// Verify вернёт «фантома» с пустым ID); существующая — только при изменениях.
	if create {
		if len(cfg.GroupRadiusMap) > 0 {
			u.RadiusReply = res.radiusReply
		}
		if err := v.st.UserCreate(ctx, u); err != nil {
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
				return nil, fmt.Errorf("auth/ldap: авто-провижининг %q: %w", username, err)
			}
			// Гонка авто-провижининга: параллельный вход успел вставить строку
			// между SELECT и INSERT (username UNIQUE). Перечитываем её и
			// продолжаем как синк существующей записи — а не внутренней
			// ошибкой, которая на входе отдаётся клиенту как 500.
			raced, rerr := v.st.UserByUsername(ctx, username)
			if rerr != nil {
				return nil, fmt.Errorf("auth/ldap: авто-провижининг %q: повторное чтение: %w", username, rerr)
			}
			if raced.Source != store.SourceLDAP {
				// Имя успел занять локальный пользователь — как в обычной ветке
				// выше: двойной источник пароля запрещён.
				slog.WarnContext(ctx, "auth/ldap: имя занято локальным пользователем, вход только по локальному паролю",
					"username", username)
				return nil, store.ErrNotFound
			}
			if !raced.Enabled {
				return nil, ErrBadCredentials
			}
			u = raced
			if u.Email != res.email || u.Phone != res.phone ||
				u.DisplayName != res.displayName || u.Role != res.role ||
				!reflect.DeepEqual(u.LDAPGroups, res.groups) ||
				(len(cfg.GroupRadiusMap) > 0 && !reflect.DeepEqual(u.RadiusReply, res.radiusReply)) {
				u.Email, u.Phone, u.DisplayName, u.Role = res.email, res.phone, res.displayName, res.role
				u.LDAPGroups = res.groups
				if len(cfg.GroupRadiusMap) > 0 {
					u.RadiusReply = res.radiusReply
				}
				if err := v.st.UserUpdate(ctx, u); err != nil {
					return nil, fmt.Errorf("auth/ldap: синхронизация %q: %w", username, err)
				}
			}
			slog.InfoContext(ctx, "auth/ldap: гонка авто-провижининга разрешена синком существующей записи",
				"username", username)
			return u, nil
		}
		slog.InfoContext(ctx, "auth/ldap: пользователь создан авто-провижинингом",
			"username", username, "role", u.Role)
	} else if changed {
		if err := v.st.UserUpdate(ctx, u); err != nil {
			return nil, fmt.Errorf("auth/ldap: синхронизация %q: %w", username, err)
		}
	}
	return u, nil
}

// LdapTestResult содержит результаты проверки связи с LDAP.
type LdapTestResult struct {
	URL      string        `json:"url"`
	Latency  time.Duration `json:"latency"`
	StartTLS bool          `json:"starttls"`
	BindOK   bool          `json:"bind_ok"`
	BaseDNOK bool          `json:"base_dn_ok"`
	Message  string        `json:"message"`
}

// TestConnection проверяет сетевое соединение, TLS/STARTTLS, сервисный Bind и доступность Base DN.
func (v *LdapVerifier) TestConnection(ctx context.Context) (*LdapTestResult, error) {
	t := v.set.Get()
	if t == nil {
		return nil, errors.New("настройки не загружены")
	}
	cfg := t.LDAP
	if cfg.URL == "" {
		return nil, errors.New("URL LDAP-сервера не задан")
	}

	start := time.Now()
	conn, err := v.dial(ctx, cfg.URL, cfg.StartTLS)
	if err != nil {
		return nil, fmt.Errorf("подключение к %s: %w", cfg.URL, err)
	}
	defer conn.Close()
	latency := time.Since(start)

	res := &LdapTestResult{
		URL:      cfg.URL,
		Latency:  latency,
		StartTLS: cfg.StartTLS,
	}

	if cfg.BindDN != "" {
		if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
			return nil, fmt.Errorf("сервисный bind (%s): %w", cfg.BindDN, err)
		}
		res.BindOK = true
	}

	if cfg.BaseDN != "" {
		searchReq := ldap.NewSearchRequest(
			cfg.BaseDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 5, false,
			"(objectClass=*)", []string{"dn"}, nil,
		)
		_, err := conn.Search(searchReq)
		if err != nil {
			subReq := ldap.NewSearchRequest(
				cfg.BaseDN, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 1, 5, false,
				"(objectClass=*)", []string{"dn"}, nil,
			)
			if _, subErr := conn.Search(subReq); subErr != nil {
				return nil, fmt.Errorf("Base DN (%s) недоступен: %w", cfg.BaseDN, err)
			}
		}
		res.BaseDNOK = true
	}

	tlsInfo := "без TLS"
	if strings.HasPrefix(strings.ToLower(cfg.URL), "ldaps://") {
		tlsInfo = "LDAPS"
	} else if cfg.StartTLS {
		tlsInfo = "STARTTLS"
	}
	res.Message = fmt.Sprintf("Подключение успешно (%s, задержка %v). Сервер доступен, авторизация Bind DN пройдена, Base DN корректен.",
		tlsInfo, latency.Round(time.Millisecond))
	return res, nil
}

// LdapUserLookupResult содержит результаты тестового поиска пользователя в AD.
type LdapUserLookupResult struct {
	Username    string            `json:"username"`
	DN          string            `json:"dn"`
	Email       string            `json:"email"`
	Phone       string            `json:"phone"`
	DisplayName string            `json:"display_name"`
	Groups      []string          `json:"groups"`
	Allowed     bool              `json:"allowed"`
	Role        string            `json:"role"`
	RadiusReply map[string]string `json:"radius_reply,omitempty"`
	Message     string            `json:"message"`
}

// TestUserLookup ищет пользователя в AD, проверяет группы и атрибуты без проверки пароля.
func (v *LdapVerifier) TestUserLookup(ctx context.Context, username string) (*LdapUserLookupResult, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, errors.New("логин пользователя не указан")
	}
	t := v.set.Get()
	if t == nil {
		return nil, errors.New("настройки не загружены")
	}
	cfg := t.LDAP
	if cfg.URL == "" {
		return nil, errors.New("URL LDAP-сервера не задан")
	}
	if cfg.BaseDN == "" {
		return nil, errors.New("Base DN не задан")
	}

	conn, err := v.dial(ctx, cfg.URL, cfg.StartTLS)
	if err != nil {
		return nil, fmt.Errorf("подключение к LDAP: %w", err)
	}
	defer conn.Close()

	if cfg.BindDN != "" {
		if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
			return nil, fmt.Errorf("сервисный bind: %w", err)
		}
	}

	filter := cfg.UserFilter
	if filter == "" {
		filter = "(&(objectClass=user)(sAMAccountName={login}))"
	}
	userReq := ldap.NewSearchRequest(
		cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 5, 10, false,
		substFilter(filter, "{login}", username),
		ldapAttrs(cfg), nil,
	)
	userRes, err := conn.Search(userReq)
	if err != nil && (!ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) || userRes == nil || len(userRes.Entries) == 0) {
		return nil, fmt.Errorf("поиск пользователя: %w", err)
	}
	if len(userRes.Entries) == 0 {
		return nil, fmt.Errorf("пользователь %q не найден по фильтру %s в Base DN %s", username, substFilter(filter, "{login}", username), cfg.BaseDN)
	}
	if len(userRes.Entries) > 1 {
		return nil, fmt.Errorf("по фильтру найдено несколько записей (%d) — уточните User Filter", len(userRes.Entries))
	}

	entry := userRes.Entries[0]
	res := &LdapUserLookupResult{
		Username:    username,
		DN:          entry.DN,
		Email:       entry.GetAttributeValue(cfg.Attrs.Email),
		Phone:       entry.GetAttributeValue(cfg.Attrs.Phone),
		DisplayName: entry.GetAttributeValue(cfg.Attrs.DisplayName),
	}

	groups := []string{}
	if memberOf := entry.GetAttributeValues("memberOf"); len(memberOf) > 0 {
		groups = append(groups, memberOf...)
	}
	if len(groups) == 0 {
		base := cfg.GroupBaseDN
		if base == "" {
			base = cfg.BaseDN
		}
		groupFilter := cfg.GroupFilter
		if groupFilter == "" {
			groupFilter = "(&(objectClass=group)(member={dn}))"
		}
		groupReq := ldap.NewSearchRequest(
			base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 10, false,
			substFilter(groupFilter, "{dn}", entry.DN), nil, nil,
		)
		if groupRes, err := conn.Search(groupReq); err == nil {
			for _, g := range groupRes.Entries {
				if g.DN != "" {
					groups = append(groups, g.DN)
				}
			}
		}
	}
	res.Groups = groups
	res.Allowed = memberAllowed(groups, cfg.AllowGroups)
	res.Role = resolveRole(groups, cfg.RoleMap)
	res.RadiusReply = ResolveGroupRadiusAttrs(groups, cfg.GroupRadiusMap)

	if !res.Allowed {
		res.Message = fmt.Sprintf("Пользователь найден (%s), но доступ ЗАПРЕЩЕН: не входит ни в одну из разрешённых групп allow_groups.", entry.DN)
	} else {
		res.Message = fmt.Sprintf("Пользователь найден (%s), групп: %d, роль: %s.", entry.DN, len(groups), res.Role)
	}
	return res, nil
}

// LdapSyncResult содержит результаты принудительной синхронизации пользователей.
type LdapSyncResult struct {
	TotalFound int      `json:"total_found"`
	Created    int      `json:"created"`
	Updated    int      `json:"updated"`
	Skipped    int      `json:"skipped"`
	Errors     []string `json:"errors,omitempty"`
	Message    string   `json:"message"`
}

// SyncUsers выполняет поиск пользователей в каталоге Active Directory/LDAP и синхронизирует их в базу данных.
func (v *LdapVerifier) SyncUsers(ctx context.Context, maxCount int) (*LdapSyncResult, error) {
	t := v.set.Get()
	if t == nil {
		return nil, errors.New("настройки не загружены")
	}
	cfg := t.LDAP
	if cfg.URL == "" {
		return nil, errors.New("URL LDAP-сервера не задан")
	}
	if cfg.BaseDN == "" {
		return nil, errors.New("Base DN не задан")
	}

	conn, err := v.dial(ctx, cfg.URL, cfg.StartTLS)
	if err != nil {
		return nil, fmt.Errorf("подключение к LDAP: %w", err)
	}
	defer conn.Close()

	if cfg.BindDN != "" {
		if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
			return nil, fmt.Errorf("сервисный bind: %w", err)
		}
	}

	filter := cfg.UserFilter
	if filter == "" {
		filter = "(&(objectClass=user)(sAMAccountName={login}))"
	}
	syncFilter := strings.ReplaceAll(filter, "{login}", "*")
	if strings.Contains(syncFilter, "objectClass=user") && !strings.Contains(syncFilter, "objectClass=computer") {
		syncFilter = fmt.Sprintf("(&%s(!(objectClass=computer)))", syncFilter)
	}

	if maxCount <= 0 || maxCount > 10000 {
		maxCount = 2000
	}

	entries, err := v.searchUsers(conn, cfg, syncFilter, maxCount)
	if err != nil {
		return nil, fmt.Errorf("поиск пользователей в LDAP: %w", err)
	}

	groupBase := cfg.GroupBaseDN
	if groupBase == "" {
		groupBase = cfg.BaseDN
	}
	groupFilter := cfg.GroupFilter
	if groupFilter == "" {
		groupFilter = "(&(objectClass=group)(member={dn}))"
	}

	res := &LdapSyncResult{
		TotalFound: len(entries),
	}

	for _, entry := range entries {
		uname := strings.TrimSpace(extractUsername(entry))
		if uname == "" || strings.HasSuffix(uname, "$") {
			res.Skipped++
			continue
		}

		groups := []string{}
		if len(cfg.AllowGroups) > 0 || len(cfg.RoleMap) > 0 || len(cfg.GroupRadiusMap) > 0 {
			if memberOf := entry.GetAttributeValues("memberOf"); len(memberOf) > 0 {
				groups = append(groups, memberOf...)
			}
			if len(groups) == 0 {
				gReq := ldap.NewSearchRequest(
					groupBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 5, false,
					substFilter(groupFilter, "{dn}", entry.DN), nil, nil,
				)
				if gRes, err := conn.Search(gReq); err == nil {
					for _, g := range gRes.Entries {
						if g.DN != "" {
							groups = append(groups, g.DN)
						}
					}
				}
			}
		}

		if !memberAllowed(groups, cfg.AllowGroups) {
			res.Skipped++
			continue
		}

		authRes := &ldapAuthResult{
			dn:          entry.DN,
			email:       entry.GetAttributeValue(cfg.Attrs.Email),
			phone:       entry.GetAttributeValue(cfg.Attrs.Phone),
			displayName: entry.GetAttributeValue(cfg.Attrs.DisplayName),
			groups:      groups,
			role:        resolveRole(groups, cfg.RoleMap),
			radiusReply: ResolveGroupRadiusAttrs(groups, cfg.GroupRadiusMap),
		}

		existing, err := v.st.UserByUsername(ctx, uname)
		if err == nil {
			if existing.Source != store.SourceLDAP {
				res.Skipped++
				continue
			}
			if _, err := v.syncUser(ctx, uname, authRes, cfg); err != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", uname, err))
			} else {
				res.Updated++
			}
		} else if errors.Is(err, store.ErrNotFound) {
			if _, err := v.syncUser(ctx, uname, authRes, cfg); err != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", uname, err))
			} else {
				res.Created++
			}
		} else {
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", uname, err))
		}
	}

	res.Message = fmt.Sprintf("Синхронизация завершена: найдено %d, создано новых %d, обновлено %d, пропущено %d.",
		res.TotalFound, res.Created, res.Updated, res.Skipped)
	if len(res.Errors) > 0 {
		res.Message += fmt.Sprintf(" (ошибок: %d)", len(res.Errors))
	}
	return res, nil
}

// searchUsers выполняет постраничный поиск пользователей с использованием RFC 2696 Simple Paged Results.
// Это предотвращает ошибку LDAP Result Code 4 "Size Limit Exceeded", когда в каталоге Active Directory
// содержится больше объектов, чем лимит страницы сервера (по умолчанию 1000 в AD) или запрошенный лимит.
func (v *LdapVerifier) searchUsers(conn LdapConn, cfg settings.LDAPSettings, syncFilter string, maxCount int) ([]*ldap.Entry, error) {
	if maxCount <= 0 || maxCount > 10000 {
		maxCount = 2000
	}

	var pageSize uint32 = 250
	if maxCount < int(pageSize) {
		pageSize = uint32(maxCount)
	}

	pagingCtrl := ldap.NewControlPaging(pageSize)
	var allEntries []*ldap.Entry

	for {
		searchReq := ldap.NewSearchRequest(
			cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 30, false,
			syncFilter, ldapAttrs(cfg), []ldap.Control{pagingCtrl},
		)

		searchRes, err := conn.Search(searchReq)
		if searchRes != nil && len(searchRes.Entries) > 0 {
			allEntries = append(allEntries, searchRes.Entries...)
		}

		if err != nil {
			// Если сервер вернул ошибку SizeLimitExceeded, но записи уже получены — используем их
			if ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) && len(allEntries) > 0 {
				break
			}
			// Если на первой странице возникла ошибка (например, LDAP-сервер не поддерживает RFC 2696 paging),
			// выполняем fallback на обычный поиск без control paging
			if len(allEntries) == 0 {
				return v.searchUsersFallback(conn, cfg, syncFilter, maxCount)
			}
			break
		}

		if len(allEntries) >= maxCount {
			allEntries = allEntries[:maxCount]
			// RFC 2696: закрываем серверный контекст пейджинга
			pagingCtrl.PagingSize = 0
			_, _ = conn.Search(searchReq)
			break
		}

		// Проверяем наличие следующей страницы
		updatedCtrl := ldap.FindControl(searchRes.Controls, ldap.ControlTypePaging)
		if ctrl, ok := updatedCtrl.(*ldap.ControlPaging); ok && ctrl != nil && len(ctrl.Cookie) > 0 {
			pagingCtrl.SetCookie(ctrl.Cookie)
			continue
		}
		break
	}

	return allEntries, nil
}

func (v *LdapVerifier) searchUsersFallback(conn LdapConn, cfg settings.LDAPSettings, syncFilter string, maxCount int) ([]*ldap.Entry, error) {
	searchReq := ldap.NewSearchRequest(
		cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 30, false,
		syncFilter, ldapAttrs(cfg), nil,
	)
	searchRes, err := conn.Search(searchReq)
	if searchRes != nil && len(searchRes.Entries) > 0 {
		if maxCount > 0 && len(searchRes.Entries) > maxCount {
			return searchRes.Entries[:maxCount], nil
		}
		return searchRes.Entries, nil
	}
	if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
		return nil, fmt.Errorf("поиск пользователей в LDAP: %w", err)
	}
	if searchRes != nil {
		return searchRes.Entries, nil
	}
	return nil, nil
}

// CompositeVerifier — выбор бэкенда первого фактора по источнику учётной
// записи: LDAP-пользователи проверяются bind-ом в каталоге, локальные —
// argon2id; неизвестные пользователи при включённом LDAP ищутся в каталоге
// (авто-провижининг), иначе — локальная ветка с argon2-приманкой. Инвариант
// «ровно одна проверка пароля на запрос» сохраняется: каждый путь делает
// не более одного bind/argon2.
type CompositeVerifier struct {
	st    *store.Store
	local *LocalVerifier
	ldap  *LdapVerifier // nil — LDAP-бэкенд не сконфигурирован
}

// NewCompositeVerifier собирает композитный верификатор; ld может быть nil
// (тогда поведение совпадает с LocalVerifier).
func NewCompositeVerifier(st *store.Store, local *LocalVerifier, ld *LdapVerifier) *CompositeVerifier {
	return &CompositeVerifier{st: st, local: local, ldap: ld}
}

// LDAP возвращает встроенный LDAP-верификатор (или nil).
func (v *CompositeVerifier) LDAP() *LdapVerifier {
	return v.ldap
}

var _ PasswordVerifier = (*CompositeVerifier)(nil)

// Verify маршрутизирует проверку пароля: найден и source='ldap' → каталог;
// найден и локальный → argon2; не найден → каталог при включённом LDAP
// (авто-провижининг), иначе локальная ветка (argon2-приманка).
func (v *CompositeVerifier) Verify(ctx context.Context, username, password string) (*store.User, error) {
	if v.ldap != nil && v.ldap.Enabled() {
		u, err := v.st.UserByUsername(ctx, username)
		switch {
		case err == nil && u.Source == store.SourceLDAP:
			return v.ldap.Verify(ctx, username, password)
		case err == nil:
			return v.local.Verify(ctx, username, password)
		case errors.Is(err, store.ErrNotFound):
			return v.ldap.Verify(ctx, username, password)
		default:
			return nil, err
		}
	}
	return v.local.Verify(ctx, username, password)
}

// ---- чистые помощники (unit-тестируются без каталога) ----

// substFilter подставляет value вместо placeholder в LDAP-фильтр,
// экранируя спецсимволы RFC 4515 (\ ( ) * NUL) — иначе ввод пользователя
// внутри фильтра управляет логикой поиска.
func substFilter(filter, placeholder, value string) string {
	return strings.ReplaceAll(filter, placeholder, ldap.EscapeFilter(value))
}

// ldapAttrs — список запрашиваемых атрибутов контактов (непустые имена).
func ldapAttrs(cfg settings.LDAPSettings) []string {
	attrs := []string{"sAMAccountName", "uid", "userPrincipalName", "cn", "memberOf"}
	for _, a := range []string{cfg.Attrs.Email, cfg.Attrs.Phone, cfg.Attrs.DisplayName} {
		if a != "" {
			attrs = append(attrs, a)
		}
	}
	return attrs
}

// extractUsername извлекает имя пользователя из атрибутов sAMAccountName, uid, userPrincipalName, cn или DN.
func extractUsername(entry *ldap.Entry) string {
	if v := entry.GetAttributeValue("sAMAccountName"); v != "" {
		return v
	}
	if v := entry.GetAttributeValue("uid"); v != "" {
		return v
	}
	if v := entry.GetAttributeValue("userPrincipalName"); v != "" {
		if idx := strings.Index(v, "@"); idx > 0 {
			return v[:idx]
		}
		return v
	}
	if v := entry.GetAttributeValue("cn"); v != "" {
		return v
	}
	return groupCN(entry.DN)
}

// dnEqual сравнивает DN по правилам RFC 4517 distinguishedNameMatch:
// регистр типов и значений RDN не значим (DN.EqualFold go-ldap); порядок
// RDN значим. Битые DN сверяются как строки без регистра — сравнение
// консервативно, паники нет.
func dnEqual(a, b string) bool {
	dnA, errA := ldap.ParseDN(a)
	dnB, errB := ldap.ParseDN(b)
	if errA == nil && errB == nil {
		return dnA.EqualFold(dnB)
	}
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

// groupCN — значение первого RDN записи группы (обычно CN): позволяет
// задавать role_map короткими именами («VPN-Admins») без полного DN.
func groupCN(dn string) string {
	if parsed, err := ldap.ParseDN(dn); err == nil && len(parsed.RDNs) > 0 && len(parsed.RDNs[0].Attributes) > 0 {
		return parsed.RDNs[0].Attributes[0].Value
	}
	// Грубый разбор битого DN: между первым '=' и следующей ','.
	if i := strings.IndexByte(dn, '='); i >= 0 {
		v := dn[i+1:]
		if j := strings.IndexByte(v, ','); j >= 0 {
			v = v[:j]
		}
		return v
	}
	return dn
}

// memberAllowed — вхождение хотя бы в одну группу allow-list (пустой
// список разрешает всех найденных в каталоге).
func memberAllowed(groups, allow []string) bool {
	if len(allow) == 0 {
		return true
	}
	for _, g := range groups {
		for _, a := range allow {
			if dnEqual(g, a) {
				return true
			}
		}
	}
	return false
}

// resolveRole — роль по группам и role_map (ключ — полный DN или CN
// группы). «admin» побеждает при любом совпадении; прочие/отсутствующие
// соответствия оставляют роль «user».
func resolveRole(groups []string, roleMap map[string]string) string {
	for _, g := range groups {
		cn := groupCN(g)
		for key, role := range roleMap {
			if role == "admin" && (dnEqual(g, key) || strings.EqualFold(cn, key)) {
				return "admin"
			}
		}
	}
	return "user"
}

// ResolveGroupRadiusAttrs вычисляет RADIUS reply-атрибуты по группам пользователя
// и group_radius_map (ключ — полный DN или CN группы).
// Если пользователь входит в несколько групп, атрибуты объединяются.
func ResolveGroupRadiusAttrs(groups []string, groupMap map[string]map[string]string) map[string]string {
	if len(groups) == 0 || len(groupMap) == 0 {
		return nil
	}
	var out map[string]string
	for _, g := range groups {
		cn := groupCN(g)
		for key, attrs := range groupMap {
			if dnEqual(g, key) || strings.EqualFold(cn, key) {
				if out == nil {
					out = make(map[string]string, len(attrs))
				}
				for attrK, attrV := range attrs {
					out[attrK] = attrV
				}
			}
		}
	}
	return out
}

