package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SupportSession — сессия экстренной удаленной помощи и поддержки.
type SupportSession struct {
	ID                uuid.UUID      `json:"id"`
	UserID            uuid.UUID      `json:"user_id"`
	DeviceID          uuid.UUID      `json:"device_id"`
	Category          string         `json:"category"` // "it" | "1c"
	Status            string         `json:"status"`   // "requested" | "authorizing" | "approved" | "active" | "transferred" | "rejected" | "completed" | "cancelled"
	ProblemSummary    string         `json:"problem_summary"`
	AssignedAdminID   *uuid.UUID     `json:"assigned_admin_id,omitempty"`
	TransferredFromID *uuid.UUID     `json:"transferred_from_id,omitempty"`
	TransferredToID   *uuid.UUID     `json:"transferred_to_id,omitempty"`
	TransferTokenHash []byte         `json:"-"`
	NumberMatch       string         `json:"number_match,omitempty"`
	AccessMode        string         `json:"access_mode"` // "full_control" | "view_only"
	StartedAt         *time.Time     `json:"started_at,omitempty"`
	EndedAt           *time.Time     `json:"ended_at,omitempty"`
	Metadata          map[string]any `json:"metadata"`
	CreatedAt         time.Time      `json:"created_at"`

	// Виртуальные поля (присоединяемые при выборке для UI)
	Username    string `json:"username,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	DeviceName  string `json:"device_name,omitempty"`
	Platform    string `json:"platform,omitempty"`
	LastIP      string `json:"last_ip,omitempty"`
}

// SupportFilter — фильтры для списка сессий поддержки.
type SupportFilter struct {
	Category   string
	Categories []string
	Status     string
	Statuses   []string
	UserID     *uuid.UUID
	ActiveOnly bool
	Limit      int
}

// supportPendingTTL — время жизни неразыгранной заявки: requested/connecting
// старше этого срока считаются истёкшими (фильтры выборки переводят их в
// expired при cleanup). Окно усталости закрывается, «залежавшуюся» заявку
// нельзя подключить через сколь угодно долгое время.
const supportPendingTTL = 15 * time.Minute

// supportTransferTTL — окно действия transfer-токена переадресации.
const supportTransferTTL = 10 * time.Minute

// notStalePending — SQL-фрагмент «неразыгранная заявка не просрочена»
// (используется фильтрами активных сессий).
const notStalePending = ` NOT (s.status IN ('requested', 'connecting')
		       AND s.created_at < now() - interval '15 minutes')`

// SupportSessionCreate создаёт новую сессию поддержки.
func (s *Store) SupportSessionCreate(ctx context.Context, ss *SupportSession) error {
	if ss.ID == uuid.Nil {
		ss.ID = uuid.New()
	}
	if ss.Category == "" {
		ss.Category = "it"
	}
	if ss.Status == "" {
		ss.Status = "requested"
	}
	if ss.AccessMode == "" {
		ss.AccessMode = "full_control"
	}
	if ss.Metadata == nil {
		ss.Metadata = make(map[string]any)
	}

	metaJSON, err := json.Marshal(ss.Metadata)
	if err != nil {
		return fmt.Errorf("store: маршалинг metadata support_session: %w", err)
	}

	_, err = s.Pool().Exec(ctx, `INSERT INTO support_sessions
		(id, user_id, device_id, category, status, problem_summary,
		 assigned_admin_id, transferred_from_id, transferred_to_id,
		 transfer_token_hash, number_match, access_mode, started_at, ended_at,
		 metadata, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, now())`,
		ss.ID, ss.UserID, ss.DeviceID, ss.Category, ss.Status, ss.ProblemSummary,
		ss.AssignedAdminID, ss.TransferredFromID, ss.TransferredToID,
		ss.TransferTokenHash, ss.NumberMatch, ss.AccessMode, ss.StartedAt, ss.EndedAt,
		metaJSON)
	if err != nil {
		return fmt.Errorf("store: создать support_session: %w", err)
	}
	return nil
}

// SupportSessionGet возвращает сессию поддержки по ID вместе с данными пользователя и устройства.
func (s *Store) SupportSessionGet(ctx context.Context, id uuid.UUID) (*SupportSession, error) {
	row := s.Pool().QueryRow(ctx, `
		SELECT s.id, s.user_id, s.device_id, s.category, s.status, s.problem_summary,
		       s.assigned_admin_id, s.transferred_from_id, s.transferred_to_id,
		       s.transfer_token_hash, s.number_match, s.access_mode, s.started_at, s.ended_at,
		       s.metadata, s.created_at,
		       COALESCE(u.username, ''), COALESCE(u.display_name, ''),
		       COALESCE(d.device_name, ''), COALESCE(d.platform, ''), COALESCE(d.last_ip, '')
		FROM support_sessions s
		LEFT JOIN users u ON u.id = s.user_id
		LEFT JOIN app_devices d ON d.id = s.device_id
		WHERE s.id = $1`, id)

	var ss SupportSession
	var metaRaw []byte
	if err := row.Scan(
		&ss.ID, &ss.UserID, &ss.DeviceID, &ss.Category, &ss.Status, &ss.ProblemSummary,
		&ss.AssignedAdminID, &ss.TransferredFromID, &ss.TransferredToID,
		&ss.TransferTokenHash, &ss.NumberMatch, &ss.AccessMode, &ss.StartedAt, &ss.EndedAt,
		&metaRaw, &ss.CreatedAt,
		&ss.Username, &ss.DisplayName,
		&ss.DeviceName, &ss.Platform, &ss.LastIP,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: support_session %s: %w", id, err)
	}
	if len(metaRaw) > 0 {
		_ = json.Unmarshal(metaRaw, &ss.Metadata)
	}
	if ss.Metadata == nil {
		ss.Metadata = make(map[string]any)
	}
	return &ss, nil
}

// SupportSessionGetByTransferToken возвращает сессию по хешу токена
// переадресации. Токен действует supportTransferTTL (10 минут) от момента
// передачи; после принятия хеш очищается (single-use).
func (s *Store) SupportSessionGetByTransferToken(ctx context.Context, tokenHash []byte) (*SupportSession, error) {
	row := s.Pool().QueryRow(ctx, `
		SELECT s.id, s.user_id, s.device_id, s.category, s.status, s.problem_summary,
		       s.assigned_admin_id, s.transferred_from_id, s.transferred_to_id,
		       s.transfer_token_hash, s.number_match, s.access_mode, s.started_at, s.ended_at,
		       s.metadata, s.created_at,
		       COALESCE(u.username, ''), COALESCE(u.display_name, ''),
		       COALESCE(d.device_name, ''), COALESCE(d.platform, ''), COALESCE(d.last_ip, '')
		FROM support_sessions s
		LEFT JOIN users u ON u.id = s.user_id
		LEFT JOIN app_devices d ON d.id = s.device_id
		WHERE s.transfer_token_hash = $1 AND s.status IN ('approved', 'active', 'transferred')
		  AND s.transferred_at > now() - interval '10 minutes'`, tokenHash)

	var ss SupportSession
	var metaRaw []byte
	if err := row.Scan(
		&ss.ID, &ss.UserID, &ss.DeviceID, &ss.Category, &ss.Status, &ss.ProblemSummary,
		&ss.AssignedAdminID, &ss.TransferredFromID, &ss.TransferredToID,
		&ss.TransferTokenHash, &ss.NumberMatch, &ss.AccessMode, &ss.StartedAt, &ss.EndedAt,
		&metaRaw, &ss.CreatedAt,
		&ss.Username, &ss.DisplayName,
		&ss.DeviceName, &ss.Platform, &ss.LastIP,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: support_session по токену: %w", err)
	}
	if len(metaRaw) > 0 {
		_ = json.Unmarshal(metaRaw, &ss.Metadata)
	}
	if ss.Metadata == nil {
		ss.Metadata = make(map[string]any)
	}
	return &ss, nil
}

// SupportSessionActiveByUser возвращает активную или ожидающую сессию
// пользователя (неразыгранные заявки старше supportPendingTTL не считаются
// активными — окно усталости закрыто).
func (s *Store) SupportSessionActiveByUser(ctx context.Context, userID uuid.UUID) (*SupportSession, error) {
	row := s.Pool().QueryRow(ctx, `
		SELECT s.id, s.user_id, s.device_id, s.category, s.status, s.problem_summary,
		       s.assigned_admin_id, s.transferred_from_id, s.transferred_to_id,
		       s.transfer_token_hash, s.number_match, s.access_mode, s.started_at, s.ended_at,
		       s.metadata, s.created_at,
		       COALESCE(u.username, ''), COALESCE(u.display_name, ''),
		       COALESCE(d.device_name, ''), COALESCE(d.platform, ''), COALESCE(d.last_ip, '')
		FROM support_sessions s
		LEFT JOIN users u ON u.id = s.user_id
		LEFT JOIN app_devices d ON d.id = s.device_id
		WHERE s.user_id = $1 AND s.status IN ('requested', 'connecting', 'authorizing', 'approved', 'active', 'transferred')
		  AND`+notStalePending+`
		ORDER BY s.created_at DESC LIMIT 1`, userID)

	var ss SupportSession
	var metaRaw []byte
	if err := row.Scan(
		&ss.ID, &ss.UserID, &ss.DeviceID, &ss.Category, &ss.Status, &ss.ProblemSummary,
		&ss.AssignedAdminID, &ss.TransferredFromID, &ss.TransferredToID,
		&ss.TransferTokenHash, &ss.NumberMatch, &ss.AccessMode, &ss.StartedAt, &ss.EndedAt,
		&metaRaw, &ss.CreatedAt,
		&ss.Username, &ss.DisplayName,
		&ss.DeviceName, &ss.Platform, &ss.LastIP,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: активная сессия пользователя %s: %w", userID, err)
	}
	if len(metaRaw) > 0 {
		_ = json.Unmarshal(metaRaw, &ss.Metadata)
	}
	return &ss, nil
}

// SupportSessionList возвращает список сессий поддержки с фильтрацией.
func (s *Store) SupportSessionList(ctx context.Context, f SupportFilter) ([]SupportSession, error) {
	query := `
		SELECT s.id, s.user_id, s.device_id, s.category, s.status, s.problem_summary,
		       s.assigned_admin_id, s.transferred_from_id, s.transferred_to_id,
		       s.transfer_token_hash, s.number_match, s.access_mode, s.started_at, s.ended_at,
		       s.metadata, s.created_at,
		       COALESCE(u.username, ''), COALESCE(u.display_name, ''),
		       COALESCE(d.device_name, ''), COALESCE(d.platform, ''), COALESCE(d.last_ip, '')
		FROM support_sessions s
		LEFT JOIN users u ON u.id = s.user_id
		LEFT JOIN app_devices d ON d.id = s.device_id
		WHERE 1=1`
	args := make([]any, 0)
	argIdx := 1

	if f.Category != "" && f.Category != "all" {
		query += fmt.Sprintf(" AND LOWER(s.category) = $%d", argIdx)
		args = append(args, strings.ToLower(strings.TrimSpace(f.Category)))
		argIdx++
	} else if len(f.Categories) > 0 {
		hasAll := false
		cats := make([]string, 0, len(f.Categories))
		for _, c := range f.Categories {
			clean := strings.ToLower(strings.TrimSpace(c))
			if clean == "all" || clean == "*" {
				hasAll = true
				break
			}
			if clean != "" {
				cats = append(cats, clean)
			}
		}
		if !hasAll && len(cats) > 0 {
			query += fmt.Sprintf(" AND LOWER(s.category) = ANY($%d)", argIdx)
			args = append(args, cats)
			argIdx++
		}
	}
	if f.ActiveOnly {
		query += ` AND s.status IN ('requested', 'connecting', 'authorizing', 'approved', 'active', 'transferred')
		   AND` + notStalePending
	} else if len(f.Statuses) > 0 {
		query += fmt.Sprintf(" AND s.status = ANY($%d)", argIdx)
		args = append(args, f.Statuses)
		argIdx++
	} else if f.Status != "" && f.Status != "all" {
		query += fmt.Sprintf(" AND s.status = $%d", argIdx)
		args = append(args, f.Status)
		argIdx++
	}
	if f.UserID != nil {
		query += fmt.Sprintf(" AND s.user_id = $%d", argIdx)
		args = append(args, *f.UserID)
		argIdx++
	}

	query += " ORDER BY s.created_at DESC"
	limit := f.Limit
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	query += fmt.Sprintf(" LIMIT $%d", argIdx)
	args = append(args, limit)

	rows, err := s.Pool().Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: список support_sessions: %w", err)
	}
	defer rows.Close()

	var list []SupportSession
	for rows.Next() {
		var ss SupportSession
		var metaRaw []byte
		if err := rows.Scan(
			&ss.ID, &ss.UserID, &ss.DeviceID, &ss.Category, &ss.Status, &ss.ProblemSummary,
			&ss.AssignedAdminID, &ss.TransferredFromID, &ss.TransferredToID,
			&ss.TransferTokenHash, &ss.NumberMatch, &ss.AccessMode, &ss.StartedAt, &ss.EndedAt,
			&metaRaw, &ss.CreatedAt,
			&ss.Username, &ss.DisplayName,
			&ss.DeviceName, &ss.Platform, &ss.LastIP,
		); err != nil {
			return nil, fmt.Errorf("store: сканирование support_session: %w", err)
		}
		if len(metaRaw) > 0 {
			_ = json.Unmarshal(metaRaw, &ss.Metadata)
		}
		list = append(list, ss)
	}
	return list, nil
}

// SupportSessionUpdateStatus обновляет статус сессии, назначенного администратора и код 2FA.
func (s *Store) SupportSessionUpdateStatus(ctx context.Context, id uuid.UUID, status string, adminID *uuid.UUID, numberMatch string) error {
	now := time.Now()
	var startedAt *time.Time
	if status == "active" {
		startedAt = &now
	}

	query := `UPDATE support_sessions SET status = $2, updated_at = now()`
	args := []any{id, status}
	argIdx := 3

	if adminID != nil {
		query += fmt.Sprintf(", assigned_admin_id = $%d", argIdx)
		args = append(args, *adminID)
		argIdx++
	}
	if numberMatch != "" {
		query += fmt.Sprintf(", number_match = $%d", argIdx)
		args = append(args, numberMatch)
		argIdx++
	}
	if startedAt != nil {
		query += fmt.Sprintf(", started_at = COALESCE(started_at, $%d)", argIdx)
		args = append(args, *startedAt)
		argIdx++
	}

	query += ` WHERE id = $1`
	ct, err := s.Pool().Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("store: обновить статус support_session %s: %w", id, err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SupportSessionTransfer выполняет переадресацию сессии на другого сотрудника:
// фиксирует момент выдачи transfer-токена (transferred_at — старт окна
// supportTransferTTL, в течение которого токен можно принять).
func (s *Store) SupportSessionTransfer(ctx context.Context, id uuid.UUID, fromID uuid.UUID, toID *uuid.UUID, tokenHash []byte) error {
	_, err := s.Pool().Exec(ctx, `UPDATE support_sessions SET
		status = 'transferred',
		transferred_from_id = $2,
		transferred_to_id = $3,
		transfer_token_hash = $4,
		transferred_at = now()
		WHERE id = $1`,
		id, fromID, toID, tokenHash)
	if err != nil {
		return fmt.Errorf("store: переадресовать support_session %s: %w", id, err)
	}
	return nil
}

// SupportSessionAcceptTransfer принимает переадресованную сессию новым
// оператором. Transfer-токен одноразовый: хеш очищается, повторное
// принятие по той же ссылке невозможно.
func (s *Store) SupportSessionAcceptTransfer(ctx context.Context, id uuid.UUID, newAdminID uuid.UUID) error {
	_, err := s.Pool().Exec(ctx, `UPDATE support_sessions SET
		status = 'active',
		assigned_admin_id = $2,
		transfer_token_hash = NULL
		WHERE id = $1`,
		id, newAdminID)
	if err != nil {
		return fmt.Errorf("store: принять переадресацию support_session %s: %w", id, err)
	}
	return nil
}

// SupportSessionClearNumberMatch гасит код number-match после успешного
// approve: подсмотренный/подобранный код нельзя использовать повторно.
func (s *Store) SupportSessionClearNumberMatch(ctx context.Context, id uuid.UUID) error {
	_, err := s.Pool().Exec(ctx,
		`UPDATE support_sessions SET number_match = '' WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("store: погасить number_match support_session %s: %w", id, err)
	}
	return nil
}

// SupportSessionEnd завершает сессию удаленного доступа.
func (s *Store) SupportSessionEnd(ctx context.Context, id uuid.UUID, finalStatus string) error {
	if finalStatus == "" {
		finalStatus = "completed"
	}
	_, err := s.Pool().Exec(ctx, `UPDATE support_sessions SET
		status = $2,
		ended_at = now()
		WHERE id = $1`, id, finalStatus)
	if err != nil {
		return fmt.Errorf("store: завершить support_session %s: %w", id, err)
	}
	return nil
}

// SupportSessionDelete удаляет сессию удаленного доступа по ID.
func (s *Store) SupportSessionDelete(ctx context.Context, id uuid.UUID) error {
	ct, err := s.Pool().Exec(ctx, `DELETE FROM support_sessions WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("store: удалить support_session %s: %w", id, err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SupportSessionCleanupClosed переводит «залежавшиеся» неразыгранные заявки
// (requested/connecting старше supportPendingTTL) в expired и удаляет все
// завершённые сессии (включая expired).
func (s *Store) SupportSessionCleanupClosed(ctx context.Context) (int64, error) {
	if _, err := s.Pool().Exec(ctx, `
		UPDATE support_sessions SET
			status = 'expired',
			ended_at = now(),
			updated_at = now()
		WHERE status IN ('requested', 'connecting')
		  AND created_at < now() - interval '15 minutes'`); err != nil {
		return 0, fmt.Errorf("store: истечь просроченные support_sessions: %w", err)
	}
	ct, err := s.Pool().Exec(ctx, `DELETE FROM support_sessions
		WHERE status IN ('completed', 'ended_by_admin', 'ended_by_user', 'rejected', 'cancelled', 'expired')`)
	if err != nil {
		return 0, fmt.Errorf("store: очистить завершенные support_sessions: %w", err)
	}
	return ct.RowsAffected(), nil
}

// SupportMessage представляет сохраненное сообщение в чате сессии удаленной поддержки.
type SupportMessage struct {
	ID         uuid.UUID `json:"id"`
	SessionID  uuid.UUID `json:"session_id"`
	Sender     string    `json:"sender"` // "user" | "operator"
	SenderName string    `json:"sender_name"`
	Text       string    `json:"text"`
	CreatedAt  time.Time `json:"created_at"`
}

// SupportMessageCreate сохраняет сообщение чата в базе данных.
func (s *Store) SupportMessageCreate(ctx context.Context, msg *SupportMessage) error {
	if msg.ID == uuid.Nil {
		msg.ID = uuid.New()
	}
	if msg.CreatedAt.IsZero() {
		msg.CreatedAt = time.Now()
	}
	_, err := s.Pool().Exec(ctx, `INSERT INTO support_messages
		(id, session_id, sender, sender_name, text, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		msg.ID, msg.SessionID, msg.Sender, msg.SenderName, msg.Text, msg.CreatedAt)
	if err != nil {
		return fmt.Errorf("store: сохранить support_message: %w", err)
	}
	return nil
}

// SupportMessagesList возвращает хронологический список сообщений для указанной сессии.
func (s *Store) SupportMessagesList(ctx context.Context, sessionID uuid.UUID) ([]*SupportMessage, error) {
	rows, err := s.Pool().Query(ctx, `SELECT id, session_id, sender, sender_name, text, created_at
		FROM support_messages WHERE session_id = $1 ORDER BY created_at ASC`, sessionID)
	if err != nil {
		return nil, fmt.Errorf("store: список support_messages для %s: %w", sessionID, err)
	}
	defer rows.Close()

	var out []*SupportMessage
	for rows.Next() {
		m := &SupportMessage{}
		if err := rows.Scan(&m.ID, &m.SessionID, &m.Sender, &m.SenderName, &m.Text, &m.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: сканирование support_message: %w", err)
		}
		out = append(out, m)
	}
	if out == nil {
		out = []*SupportMessage{}
	}
	return out, rows.Err()
}
