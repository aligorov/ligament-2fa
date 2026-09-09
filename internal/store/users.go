// Package store — репозитории поверх PostgreSQL (pgx/v5).
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aligorov/twofa/internal/channel"
)

// ErrNotFound — запрашиваемая строка отсутствует. Возвращается без обёртки,
// чтобы err == ErrNotFound и errors.Is(err, ErrNotFound) работали одинаково.
var ErrNotFound = errors.New("not found")

// defaultPreferChannels — значение prefer_channels по умолчанию (спека §5).
var defaultPreferChannels = []channel.Channel{channel.TOTP, channel.Email, channel.SMS}

// Источники учётной записи (users.source, миграция 0002).
const (
	// SourceLocal — локальный пароль (argon2id-хеш в password_hash).
	SourceLocal = "local"
	// SourceLDAP — внешний каталог LDAP/AD: пароль проверяется bind-ом,
	// password_hash непригоден (случайный при авто-провижининге).
	SourceLDAP = "ldap"
)

// User — строка таблицы users.
type User struct {
	ID             uuid.UUID
	Username       string
	Role           string // "admin" | "user"
	Enabled        bool
	Email, Phone   string
	TelegramChatID *int64
	PreferChannels []channel.Channel
	RadiusPush     bool
	RadiusReply    map[string]string // JSONB, nil допустим
	WebAuthnID     []byte            // nil до первого webauthn-enroll
	PasswordHash   string
	Source         string // SourceLocal | SourceLDAP (миграция 0002)
	DisplayName    string // отображаемое имя (синк из LDAP-атрибута)
	PasswordEnc    []byte // AES-256-GCM шифрованный пароль под master_key с AAD username (миграция 0005)
	LDAPGroups     []string // группы из каталога LDAP/Active Directory (миграция 0006)
	SupportRoles   []string // роли поддержки: "it", "1c" (миграция 0009)
}

// IsSupportIT проверяет, является ли пользователь инженером IT-поддержки.
func (u *User) IsSupportIT() bool {
	if u == nil {
		return false
	}
	if u.Role == "admin" {
		return true
	}
	for _, r := range u.SupportRoles {
		if r == "it" || r == "all" {
			return true
		}
	}
	return false
}

// IsSupport1C проверяет, является ли пользователь специалистом 1С.
func (u *User) IsSupport1C() bool {
	if u == nil {
		return false
	}
	if u.Role == "admin" {
		return true
	}
	for _, r := range u.SupportRoles {
		if r == "1c" || r == "all" {
			return true
		}
	}
	return false
}

// IsSupportAny проверяет, имеет ли пользователь любые полномочия поддержки или админа.
func (u *User) IsSupportAny() bool {
	return u != nil && (u.Role == "admin" || len(u.SupportRoles) > 0)
}

// VLAN возвращает номер VLAN из RadiusReply (Tunnel-Private-Group-Id), если он задан.
func (u *User) VLAN() string {
	if u == nil || u.RadiusReply == nil {
		return ""
	}
	return u.RadiusReply["Tunnel-Private-Group-Id"]
}

// TelegramLinked сообщает, привязан ли Telegram-аккаунт (наличие chat_id).
func (u *User) TelegramLinked() bool {
	return u != nil && u.TelegramChatID != nil
}

// scanner абстрагирует pgx.Row и pgx.Rows для общего кода сканирования.
type scanner interface{ Scan(dest ...any) error }

// userCols — список колонок users для SELECT/сканирования (без created_at/
// updated_at — они не входят в структуру User).
const userCols = `id, username, password_hash, role, enabled, email, phone,
	telegram_chat_id, prefer_channels, radius_push, radius_reply, webauthn_id,
	source, display_name, password_enc, ldap_groups, support_roles`

// defaultChannels возвращает свежую копию каналов по умолчанию.
func defaultChannels() []channel.Channel {
	out := make([]channel.Channel, len(defaultPreferChannels))
	copy(out, defaultPreferChannels)
	return out
}

// preferChannelsJSON кодирует список каналов для JSONB-колонки
// prefer_channels; nil/пустой список заменяются на ["totp","email","sms"].
func preferChannelsJSON(chs []channel.Channel) ([]byte, error) {
	if len(chs) == 0 {
		chs = defaultPreferChannels
	}
	b, err := json.Marshal(chs)
	if err != nil {
		return nil, fmt.Errorf("store: кодирование prefer_channels: %w", err)
	}
	return b, nil
}

// scanPreferChannels разбирает JSONB prefer_channels; NULL, пустой массив и
// json-null дают каналы по умолчанию.
func scanPreferChannels(raw []byte) ([]channel.Channel, error) {
	if len(raw) == 0 {
		return defaultChannels(), nil
	}
	var chs []channel.Channel
	if err := json.Unmarshal(raw, &chs); err != nil {
		return nil, fmt.Errorf("store: разбор prefer_channels %s: %w", raw, err)
	}
	if len(chs) == 0 {
		return defaultChannels(), nil
	}
	return chs, nil
}

// radiusReplyJSON кодирует RadiusReply для JSONB; nil-словарь → nil (NULL).
func radiusReplyJSON(m map[string]string) ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("store: кодирование radius_reply: %w", err)
	}
	return b, nil
}

// scanRadiusReply разбирает JSONB radius_reply; NULL → nil.
func scanRadiusReply(raw []byte) (map[string]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("store: разбор radius_reply %s: %w", raw, err)
	}
	return m, nil
}

// scanUser сканирует строку users (колонки в порядке userCols).
func scanUser(row scanner) (*User, error) {
	var (
		u         User
		preferRaw []byte
		replyRaw  []byte
	)
	if err := row.Scan(
		&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.Enabled,
		&u.Email, &u.Phone, &u.TelegramChatID, &preferRaw, &u.RadiusPush,
		&replyRaw, &u.WebAuthnID, &u.Source, &u.DisplayName, &u.PasswordEnc,
		&u.LDAPGroups, &u.SupportRoles,
	); err != nil {
		return nil, err
	}
	if u.LDAPGroups == nil {
		u.LDAPGroups = []string{}
	}
	if u.SupportRoles == nil {
		u.SupportRoles = []string{}
	}
	// Пустой source (строки, созданные до миграции 0002, и дефолты форм)
	// трактуется как локальный.
	if u.Source == "" {
		u.Source = SourceLocal
	}
	prefer, err := scanPreferChannels(preferRaw)
	if err != nil {
		return nil, err
	}
	u.PreferChannels = prefer
	reply, err := scanRadiusReply(replyRaw)
	if err != nil {
		return nil, err
	}
	u.RadiusReply = reply
	return &u, nil
}

// UserByUsername возвращает пользователя по имени; ErrNotFound, если нет.
func (s *Store) UserByUsername(ctx context.Context, name string) (*User, error) {
	u, err := scanUser(s.Pool().QueryRow(ctx,
		`SELECT `+userCols+` FROM users WHERE username = $1`, name))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: пользователь по имени %q: %w", name, err)
	}
	return u, nil
}

// UserByID возвращает пользователя по ID; ErrNotFound, если нет.
func (s *Store) UserByID(ctx context.Context, id uuid.UUID) (*User, error) {
	u, err := scanUser(s.Pool().QueryRow(ctx,
		`SELECT `+userCols+` FROM users WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: пользователь %s: %w", id, err)
	}
	return u, nil
}

// UserCreate создаёт пользователя; ID генерируется при нулевом значении.
func (s *Store) UserCreate(ctx context.Context, u *User) error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	if u.Source == "" {
		u.Source = SourceLocal
	}
	if u.LDAPGroups == nil {
		u.LDAPGroups = []string{}
	}
	if u.SupportRoles == nil {
		u.SupportRoles = []string{}
	}
	prefer, err := preferChannelsJSON(u.PreferChannels)
	if err != nil {
		return err
	}
	reply, err := radiusReplyJSON(u.RadiusReply)
	if err != nil {
		return err
	}
	_, err = s.Pool().Exec(ctx, `INSERT INTO users
		(id, username, password_hash, role, enabled, email, phone,
		 telegram_chat_id, prefer_channels, radius_push, radius_reply, webauthn_id,
		 source, display_name, password_enc, ldap_groups, support_roles)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
		u.ID, u.Username, u.PasswordHash, u.Role, u.Enabled, u.Email, u.Phone,
		u.TelegramChatID, prefer, u.RadiusPush, reply, u.WebAuthnID,
		u.Source, u.DisplayName, u.PasswordEnc, u.LDAPGroups, u.SupportRoles)
	if err != nil {
		return fmt.Errorf("store: создать пользователя %q: %w", u.Username, err)
	}
	return nil
}

// UserUpdate сохраняет все поля пользователя, кроме ID; created_at/updated_at
// управляются БД (updated_at = now()).
func (s *Store) UserUpdate(ctx context.Context, u *User) error {
	prefer, err := preferChannelsJSON(u.PreferChannels)
	if err != nil {
		return err
	}
	reply, err := radiusReplyJSON(u.RadiusReply)
	if err != nil {
		return err
	}
	if u.Source == "" {
		u.Source = SourceLocal
	}
	if u.LDAPGroups == nil {
		u.LDAPGroups = []string{}
	}
	if u.SupportRoles == nil {
		u.SupportRoles = []string{}
	}
	ct, err := s.Pool().Exec(ctx, `UPDATE users SET
		username = $2, password_hash = $3, role = $4, enabled = $5,
		email = $6, phone = $7, telegram_chat_id = $8, prefer_channels = $9,
		radius_push = $10, radius_reply = $11, webauthn_id = $12,
		source = $13, display_name = $14, password_enc = $15, ldap_groups = $16,
		support_roles = $17, updated_at = now()
		WHERE id = $1`,
		u.ID, u.Username, u.PasswordHash, u.Role, u.Enabled, u.Email, u.Phone,
		u.TelegramChatID, prefer, u.RadiusPush, reply, u.WebAuthnID,
		u.Source, u.DisplayName, u.PasswordEnc, u.LDAPGroups, u.SupportRoles)
	if err != nil {
		return fmt.Errorf("store: обновить пользователя %s: %w", u.ID, err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// BriefUser — краткая информация о пользователе для списков выбора и переадресации.
type BriefUser struct {
	ID           uuid.UUID `json:"id"`
	Username     string    `json:"username"`
	DisplayName  string    `json:"display_name"`
	Email        string    `json:"email"`
	Role         string    `json:"role"`
	SupportRoles []string  `json:"support_roles"`
}

// AllUsersBrief возвращает список всех активных пользователей для выпадающих списков переадресации.
func (s *Store) AllUsersBrief(ctx context.Context) ([]BriefUser, error) {
	rows, err := s.Pool().Query(ctx, `SELECT id, username, display_name, email, role, support_roles FROM users WHERE enabled = true ORDER BY username ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: AllUsersBrief: %w", err)
	}
	defer rows.Close()

	var list []BriefUser
	for rows.Next() {
		var b BriefUser
		if err := rows.Scan(&b.ID, &b.Username, &b.DisplayName, &b.Email, &b.Role, &b.SupportRoles); err != nil {
			return nil, fmt.Errorf("store: AllUsersBrief scan: %w", err)
		}
		if b.SupportRoles == nil {
			b.SupportRoles = []string{}
		}
		list = append(list, b)
	}
	return list, nil
}

// UserDelete удаляет пользователя (каскад затрагивает секреты, челленджи,
// сессии и устройства); ErrNotFound, если его не было.
func (s *Store) UserDelete(ctx context.Context, id uuid.UUID) error {
	ct, err := s.Pool().Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("store: удалить пользователя %s: %w", id, err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// UserCount возвращает число пользователей.
func (s *Store) UserCount(ctx context.Context) (int, error) {
	var n int64
	if err := s.Pool().QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: подсчёт пользователей: %w", err)
	}
	return int(n), nil
}

// UserList возвращает всех пользователей, отсортированных по username.
func (s *Store) UserList(ctx context.Context) ([]*User, error) {
	rows, err := s.Pool().Query(ctx, `SELECT `+userCols+` FROM users ORDER BY username`)
	if err != nil {
		return nil, fmt.Errorf("store: список пользователей: %w", err)
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("store: список пользователей: %w", err)
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: список пользователей: %w", err)
	}
	return out, nil
}
