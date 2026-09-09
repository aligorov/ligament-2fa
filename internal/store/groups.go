package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Group представляет локальную группу пользователей.
type Group struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	MemberCount int       `json:"member_count"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// GroupCreate создаёт новую группу.
func (s *Store) GroupCreate(ctx context.Context, g *Group) error {
	if g.ID == uuid.Nil {
		g.ID = uuid.New()
	}
	err := s.Pool().QueryRow(ctx, `
		INSERT INTO groups (id, name, description, created_at, updated_at)
		VALUES ($1, $2, $3, now(), now())
		RETURNING created_at, updated_at`,
		g.ID, g.Name, g.Description).Scan(&g.CreatedAt, &g.UpdatedAt)
	if err != nil {
		return fmt.Errorf("store: создать группу %q: %w", g.Name, err)
	}
	return nil
}

// GroupUpdate обновляет имя и описание группы.
func (s *Store) GroupUpdate(ctx context.Context, id uuid.UUID, name, description string) error {
	ct, err := s.Pool().Exec(ctx, `
		UPDATE groups
		SET name = $2, description = $3, updated_at = now()
		WHERE id = $1`, id, name, description)
	if err != nil {
		return fmt.Errorf("store: обновить группу %s: %w", id, err)
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
	var g Group
	err := s.Pool().QueryRow(ctx, `
		SELECT g.id, g.name, g.description,
		       COALESCE(count(ug.user_id), 0)::int as member_count,
		       g.created_at, g.updated_at
		FROM groups g
		LEFT JOIN user_groups ug ON ug.group_id = g.id
		WHERE g.id = $1
		GROUP BY g.id`, id).Scan(&g.ID, &g.Name, &g.Description, &g.MemberCount, &g.CreatedAt, &g.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: группа %s: %w", id, err)
	}
	return &g, nil
}

// GroupList возвращает все группы, отсортированные по имени, с количеством участников.
func (s *Store) GroupList(ctx context.Context) ([]Group, error) {
	rows, err := s.Pool().Query(ctx, `
		SELECT g.id, g.name, g.description,
		       COALESCE(count(ug.user_id), 0)::int as member_count,
		       g.created_at, g.updated_at
		FROM groups g
		LEFT JOIN user_groups ug ON ug.group_id = g.id
		GROUP BY g.id
		ORDER BY g.name ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: список групп: %w", err)
	}
	defer rows.Close()

	var groups []Group
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.MemberCount, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store: сканирование группы: %w", err)
		}
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

// UserGroups возвращает список групп, в которые входит пользователь.
func (s *Store) UserGroups(ctx context.Context, userID uuid.UUID) ([]Group, error) {
	rows, err := s.Pool().Query(ctx, `
		SELECT g.id, g.name, g.description, 0, g.created_at, g.updated_at
		FROM groups g
		JOIN user_groups ug ON ug.group_id = g.id
		WHERE ug.user_id = $1
		ORDER BY g.name ASC`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: группы пользователя %s: %w", userID, err)
	}
	defer rows.Close()

	var list []Group
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.MemberCount, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store: сканирование группы пользователя: %w", err)
		}
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
		ORDER BY g.name ASC`, userID)
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
		ORDER BY g.name ASC`)
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
