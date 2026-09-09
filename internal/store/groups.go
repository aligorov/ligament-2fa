package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/aligorov/twofa/internal/channel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Group представляет локальную группу пользователей.
type Group struct {
	ID             uuid.UUID         `json:"id"`
	Name           string            `json:"name"`
	Description    string            `json:"description"`
	Priority       int               `json:"priority"`
	PreferChannels []channel.Channel `json:"prefer_channels"`
	RadiusPush     bool              `json:"radius_push"`
	RadiusReply    map[string]string `json:"radius_reply"`
	MemberCount    int               `json:"member_count"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
}

// VLAN возвращает номер VLAN из RadiusReply (Tunnel-Private-Group-Id), если он задан.
func (g *Group) VLAN() string {
	if g == nil || g.RadiusReply == nil {
		return ""
	}
	return g.RadiusReply["Tunnel-Private-Group-Id"]
}

// GroupCreate создаёт новую группу.
func (s *Store) GroupCreate(ctx context.Context, g *Group) error {
	if g.ID == uuid.Nil {
		g.ID = uuid.New()
	}
	if g.Priority <= 0 || g.Priority > 100 {
		g.Priority = 50
	}
	var preferJSON []byte
	if len(g.PreferChannels) > 0 {
		var err error
		preferJSON, err = json.Marshal(g.PreferChannels)
		if err != nil {
			return fmt.Errorf("store: кодирование prefer_channels: %w", err)
		}
	}
	replyJSON, err := radiusReplyJSON(g.RadiusReply)
	if err != nil {
		return err
	}
	err = s.Pool().QueryRow(ctx, `
		INSERT INTO groups (id, name, description, priority, prefer_channels, radius_push, radius_reply, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, now(), now())
		RETURNING created_at, updated_at`,
		g.ID, g.Name, g.Description, g.Priority, preferJSON, g.RadiusPush, replyJSON).Scan(&g.CreatedAt, &g.UpdatedAt)
	if err != nil {
		return fmt.Errorf("store: создать группу %q: %w", g.Name, err)
	}
	return nil
}

// GroupUpdate обновляет параметры группы.
func (s *Store) GroupUpdate(ctx context.Context, g *Group) error {
	if g.Priority <= 0 || g.Priority > 100 {
		g.Priority = 50
	}
	var preferJSON []byte
	if len(g.PreferChannels) > 0 {
		var err error
		preferJSON, err = json.Marshal(g.PreferChannels)
		if err != nil {
			return fmt.Errorf("store: кодирование prefer_channels: %w", err)
		}
	}
	replyJSON, err := radiusReplyJSON(g.RadiusReply)
	if err != nil {
		return err
	}
	ct, err := s.Pool().Exec(ctx, `
		UPDATE groups
		SET name = $2, description = $3, priority = $4, prefer_channels = $5, radius_push = $6, radius_reply = $7, updated_at = now()
		WHERE id = $1`, g.ID, g.Name, g.Description, g.Priority, preferJSON, g.RadiusPush, replyJSON)
	if err != nil {
		return fmt.Errorf("store: обновить группу %s: %w", g.ID, err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// GroupDelete удаляет группу (связи в user_groups удаляются каскадно).
func (s *Store) GroupDelete(ctx context.Context, id uuid.UUID) error {
	ct, err := s.Pool().Exec(ctx, `DELETE FROM groups WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("store: удалить группу %s: %w", id, err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// GroupByID возвращает группу по ID вместе с числом участников.
func (s *Store) GroupByID(ctx context.Context, id uuid.UUID) (*Group, error) {
	var (
		g                  Group
		preferRaw, replyRaw []byte
	)
	err := s.Pool().QueryRow(ctx, `
		SELECT g.id, g.name, g.description, g.priority, g.prefer_channels, g.radius_push, g.radius_reply,
		       COALESCE(count(ug.user_id), 0)::int as member_count,
		       g.created_at, g.updated_at
		FROM groups g
		LEFT JOIN user_groups ug ON ug.group_id = g.id
		WHERE g.id = $1
		GROUP BY g.id`, id).Scan(
		&g.ID, &g.Name, &g.Description, &g.Priority, &preferRaw, &g.RadiusPush, &replyRaw,
		&g.MemberCount, &g.CreatedAt, &g.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: группа %s: %w", id, err)
	}
	if len(preferRaw) > 0 && string(preferRaw) != "null" {
		_ = json.Unmarshal(preferRaw, &g.PreferChannels)
	}
	g.RadiusReply, _ = scanRadiusReply(replyRaw)
	return &g, nil
}

// GroupList возвращает все группы, отсортированные по приоритету (DESC) и имени (ASC).
func (s *Store) GroupList(ctx context.Context) ([]Group, error) {
	rows, err := s.Pool().Query(ctx, `
		SELECT g.id, g.name, g.description, g.priority, g.prefer_channels, g.radius_push, g.radius_reply,
		       COALESCE(count(ug.user_id), 0)::int as member_count,
		       g.created_at, g.updated_at
		FROM groups g
		LEFT JOIN user_groups ug ON ug.group_id = g.id
		GROUP BY g.id
		ORDER BY g.priority DESC, g.name ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: список групп: %w", err)
	}
	defer rows.Close()

	var groups []Group
	for rows.Next() {
		var (
			g                  Group
			preferRaw, replyRaw []byte
		)
		if err := rows.Scan(
			&g.ID, &g.Name, &g.Description, &g.Priority, &preferRaw, &g.RadiusPush, &replyRaw,
			&g.MemberCount, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store: сканирование группы: %w", err)
		}
		if len(preferRaw) > 0 && string(preferRaw) != "null" {
			_ = json.Unmarshal(preferRaw, &g.PreferChannels)
		}
		g.RadiusReply, _ = scanRadiusReply(replyRaw)
		groups = append(groups, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: список групп: %w", err)
	}
	return groups, nil
}

// GroupMembers возвращает пользователей, входящих в группу.
func (s *Store) GroupMembers(ctx context.Context, groupID uuid.UUID) ([]*User, error) {
	rows, err := s.Pool().Query(ctx, `
		SELECT `+userCols+`
		FROM users u
		JOIN user_groups ug ON ug.user_id = u.id
		WHERE ug.group_id = $1
		ORDER BY u.username ASC`, groupID)
	if err != nil {
		return nil, fmt.Errorf("store: участники группы %s: %w", groupID, err)
	}
	defer rows.Close()

	var members []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("store: участник группы: %w", err)
		}
		members = append(members, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: участники группы %s: %w", groupID, err)
	}
	return members, nil
}

// SetGroupMembers полностью заменяет состав участников группы.
func (s *Store) SetGroupMembers(ctx context.Context, groupID uuid.UUID, userIDs []uuid.UUID) error {
	tx, err := s.Pool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: начало транзакции: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `DELETE FROM user_groups WHERE group_id = $1`, groupID); err != nil {
		return fmt.Errorf("store: очистка участников группы %s: %w", groupID, err)
	}

	for _, uid := range userIDs {
		if _, err := tx.Exec(ctx, `
			INSERT INTO user_groups (user_id, group_id, created_at)
			VALUES ($1, $2, now())
			ON CONFLICT DO NOTHING`, uid, groupID); err != nil {
			return fmt.Errorf("store: добавление участника %s в группу %s: %w", uid, groupID, err)
		}
	}

	return tx.Commit(ctx)
}

// UserGroups возвращает список групп пользователя, упорядоченный по приоритету (DESC) и имени (ASC).
func (s *Store) UserGroups(ctx context.Context, userID uuid.UUID) ([]Group, error) {
	rows, err := s.Pool().Query(ctx, `
		SELECT g.id, g.name, g.description, g.priority, g.prefer_channels, g.radius_push, g.radius_reply,
		       0 as member_count, g.created_at, g.updated_at
		FROM groups g
		JOIN user_groups ug ON ug.group_id = g.id
		WHERE ug.user_id = $1
		ORDER BY g.priority DESC, g.name ASC`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: группы пользователя %s: %w", userID, err)
	}
	defer rows.Close()

	var list []Group
	for rows.Next() {
		var (
			g                  Group
			preferRaw, replyRaw []byte
		)
		if err := rows.Scan(
			&g.ID, &g.Name, &g.Description, &g.Priority, &preferRaw, &g.RadiusPush, &replyRaw,
			&g.MemberCount, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store: сканирование группы пользователя: %w", err)
		}
		if len(preferRaw) > 0 && string(preferRaw) != "null" {
			_ = json.Unmarshal(preferRaw, &g.PreferChannels)
		}
		g.RadiusReply, _ = scanRadiusReply(replyRaw)
		list = append(list, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: группы пользователя %s: %w", userID, err)
	}
	return list, nil
}

// UserGroupNames возвращает имена локальных групп, в которые входит пользователь.
func (s *Store) UserGroupNames(ctx context.Context, userID uuid.UUID) ([]string, error) {
	rows, err := s.Pool().Query(ctx, `
		SELECT g.name
		FROM groups g
		JOIN user_groups ug ON ug.group_id = g.id
		WHERE ug.user_id = $1
		ORDER BY g.priority DESC, g.name ASC`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: имена групп пользователя %s: %w", userID, err)
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("store: сканирование имени группы: %w", err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: имена групп пользователя %s: %w", userID, err)
	}
	if names == nil {
		names = []string{}
	}
	return names, nil
}

// SetUserGroups задаёт список локальных групп для пользователя.
func (s *Store) SetUserGroups(ctx context.Context, userID uuid.UUID, groupIDs []uuid.UUID) error {
	tx, err := s.Pool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: начало транзакции: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `DELETE FROM user_groups WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("store: очистка групп пользователя %s: %w", userID, err)
	}

	for _, gid := range groupIDs {
		if _, err := tx.Exec(ctx, `
			INSERT INTO user_groups (user_id, group_id, created_at)
			VALUES ($1, $2, now())
			ON CONFLICT DO NOTHING`, userID, gid); err != nil {
			return fmt.Errorf("store: добавление пользователя %s в группу %s: %w", userID, gid, err)
		}
	}

	return tx.Commit(ctx)
}

// AllUserGroupsMap возвращает карту user_id -> []group_names для всех локальных групп.
// Удобно для пакетного вывода бейджей в таблице пользователей без N+1 запросов.
func (s *Store) AllUserGroupsMap(ctx context.Context) (map[uuid.UUID][]string, error) {
	rows, err := s.Pool().Query(ctx, `
		SELECT ug.user_id, g.name
		FROM user_groups ug
		JOIN groups g ON g.id = ug.group_id
		ORDER BY g.priority DESC, g.name ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: карта групп пользователей: %w", err)
	}
	defer rows.Close()

	m := make(map[uuid.UUID][]string)
	for rows.Next() {
		var (
			uid  uuid.UUID
			name string
		)
		if err := rows.Scan(&uid, &name); err != nil {
			return nil, fmt.Errorf("store: сканирование карты групп: %w", err)
		}
		m[uid] = append(m[uid], name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: карта групп пользователей: %w", err)
	}
	return m, nil
}

// AllUserInheritedVLANMap возвращает карты:
// 1. user_id -> vlan (наивысший по приоритету групп, если у группы задан VLAN)
// 2. user_id -> group_name (имя группы, от которой унаследован VLAN)
func (s *Store) AllUserInheritedVLANMap(ctx context.Context) (map[uuid.UUID]string, map[uuid.UUID]string, error) {
	rows, err := s.Pool().Query(ctx, `
		SELECT DISTINCT ON (ug.user_id)
		       ug.user_id, g.name, g.radius_reply->>'Tunnel-Private-Group-Id' as vlan
		FROM user_groups ug
		JOIN groups g ON g.id = ug.group_id
		WHERE g.radius_reply->>'Tunnel-Private-Group-Id' IS NOT NULL
		  AND g.radius_reply->>'Tunnel-Private-Group-Id' != ''
		ORDER BY ug.user_id, g.priority DESC, g.name ASC`)
	if err != nil {
		return nil, nil, fmt.Errorf("store: карта унаследованных VLAN: %w", err)
	}
	defer rows.Close()

	vlans := make(map[uuid.UUID]string)
	gnames := make(map[uuid.UUID]string)
	for rows.Next() {
		var (
			uid   uuid.UUID
			gname string
			vlan  string
		)
		if err := rows.Scan(&uid, &gname, &vlan); err != nil {
			return nil, nil, fmt.Errorf("store: сканирование унаследованного VLAN: %w", err)
		}
		vlans[uid] = vlan
		gnames[uid] = gname
	}
	return vlans, gnames, rows.Err()
}

// AllUserInheritedPushMap возвращает карту user_id -> group_name для пользователей,
// у которых RADIUS Push включён хотя бы одной из групп.
func (s *Store) AllUserInheritedPushMap(ctx context.Context) (map[uuid.UUID]string, error) {
	rows, err := s.Pool().Query(ctx, `
		SELECT DISTINCT ON (ug.user_id)
		       ug.user_id, g.name
		FROM user_groups ug
		JOIN groups g ON g.id = ug.group_id
		WHERE g.radius_push = true
		ORDER BY ug.user_id, g.priority DESC, g.name ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: карта унаследованных Push: %w", err)
	}
	defer rows.Close()

	m := make(map[uuid.UUID]string)
	for rows.Next() {
		var (
			uid   uuid.UUID
			gname string
		)
		if err := rows.Scan(&uid, &gname); err != nil {
			return nil, fmt.Errorf("store: сканирование унаследованного Push: %w", err)
		}
		m[uid] = gname
	}
	return m, rows.Err()
}

// UserEffectiveRadiusReply вычисляет итоговый набор RADIUS-атрибутов для пользователя
// с учётом приоритетов групп (ORDER BY priority DESC, name ASC) и персональных настроек пользователя.
// Персональные атрибуты пользователя (user.RadiusReply) имеют абсолютный приоритет.
func (s *Store) UserEffectiveRadiusReply(ctx context.Context, u *User) (map[string]string, error) {
	if u == nil {
		return nil, nil
	}
	groups, err := s.UserGroups(ctx, u.ID)
	if err != nil {
		return u.RadiusReply, err
	}
	if len(groups) == 0 {
		return u.RadiusReply, nil
	}

	merged := make(map[string]string)
	// Идём от наименее приоритетных групп к наиболее приоритетным,
	// чтобы атрибуты групп с более высоким приоритетом побеждали.
	for i := len(groups) - 1; i >= 0; i-- {
		g := groups[i]
		for k, v := range g.RadiusReply {
			merged[k] = v
		}
	}
	// Личные атрибуты пользователя имеют абсолютный приоритет
	for k, v := range u.RadiusReply {
		merged[k] = v
	}

	if len(merged) == 0 {
		return nil, nil
	}
	return merged, nil
}

// UserEffectivePreferChannels возвращает каналы 2FA для пользователя из наиболее приоритетной
// группы, у которой настроены prefer_channels (если у самого пользователя они не заданы).
func (s *Store) UserEffectivePreferChannels(ctx context.Context, u *User) ([]channel.Channel, error) {
	if u == nil {
		return nil, nil
	}
	if len(u.PreferChannels) > 0 {
		return u.PreferChannels, nil
	}
	groups, err := s.UserGroups(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		if len(g.PreferChannels) > 0 {
			return g.PreferChannels, nil
		}
	}
	return nil, nil
}

// UserEffectiveRadiusPush возвращает true, если RADIUS Push включён у самого пользователя
// ИЛИ хотя бы в одной из его групп (принцип максимальной безопасности).
func (s *Store) UserEffectiveRadiusPush(ctx context.Context, u *User) bool {
	if u == nil {
		return false
	}
	if u.RadiusPush {
		return true
	}
	groups, err := s.UserGroups(ctx, u.ID)
	if err != nil || len(groups) == 0 {
		return false
	}
	for _, g := range groups {
		if g.RadiusPush {
			return true
		}
	}
	return false
}

// UserInheritedVLANInfo возвращает VLAN и имя группы, от которой он унаследован (если у пользователя нет личного VLAN).
func (s *Store) UserInheritedVLANInfo(ctx context.Context, u *User) (vlan string, groupName string) {
	if u == nil || u.VLAN() != "" {
		return "", ""
	}
	groups, err := s.UserGroups(ctx, u.ID)
	if err != nil {
		return "", ""
	}
	for _, g := range groups {
		if g.VLAN() != "" {
			return g.VLAN(), g.Name
		}
	}
	return "", ""
}

// ApplyGroupSettingsToMembers принудительно перезаписывает настройки (VLAN, RADIUS Reply,
// каналы 2FA, RADIUS Push) у всех участников группы.
func (s *Store) ApplyGroupSettingsToMembers(ctx context.Context, groupID uuid.UUID) error {
	g, err := s.GroupByID(ctx, groupID)
	if err != nil {
		return err
	}
	members, err := s.GroupMembers(ctx, groupID)
	if err != nil {
		return err
	}
	for _, m := range members {
		if len(g.PreferChannels) > 0 {
			m.PreferChannels = g.PreferChannels
		}
		if g.RadiusPush {
			m.RadiusPush = true
		}
		if len(g.RadiusReply) > 0 {
			if m.RadiusReply == nil {
				m.RadiusReply = make(map[string]string)
			}
			for k, v := range g.RadiusReply {
				m.RadiusReply[k] = v
			}
		}
		if err := s.UserUpdate(ctx, m); err != nil {
			return fmt.Errorf("store: применение настроек к пользователю %s: %w", m.Username, err)
		}
	}
	return nil
}
