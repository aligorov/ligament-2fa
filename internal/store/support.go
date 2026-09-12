package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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

// supportActiveMaxAge — максимальный срок жизни активной сессии удалённого
// доступа: активные/переадресованные сессии старше этого срока автоматически
// переводятся в completed («вечных» сессий не бывает).
const supportActiveMaxAge = 4 * time.Hour

// SupportMaxNMAttempts — максимум неудачных вводов контрольного числа
// number-match до принудительного отклонения сессии (код 2 цифры — без
// лимита он перебирается за ~90 запросов).
const SupportMaxNMAttempts = 3

// notStalePending — SQL-фрагмент «неразыгранная заявка не просрочена»
// (используется фильтрами активных сессий).
const notStalePending = ` NOT (s.status IN ('requested', 'connecting')
			       AND s.created_at < now() - interval '15 minutes')`

// notStaleActive — SQL-фрагмент «активная сессия не превысила лимит 4 часа»
// (читается как completed автоматикой; вечные active-сессии исключены).
const notStaleActive = ` NOT (s.status IN ('active', 'transferred')
			       AND s.started_at < now() - interval '4 hours')`

// ---- Машина состояний support_sessions -------------------------------------
//
// Единая серверная таблица переходов: любую мутацию статуса сессии поддержки
// выполняет ТОЛЬКО через store-функции, валидирующие переход
// (SupportTransitionAllowed) и защищённые атомарным UPDATE по ожидаемому
// исходному статусу. Нарушение последовательности → ErrInvalidTransition
// (HTTP 409 invalid_transition).
//
// Штатная последовательность:
//   user: request → requested
//   operator: connect → connecting (назначает оператора, генерирует number_match)
//   user: decision(approve, number_match) → active   ← ЕДИНСТВЕННЫЙ путь к active
//   operator: transfer → transferred (только из active/transferred)
//   user/assigned/admin: end → completed / ended_by_admin
//   system: TTL → expired (pending 15м) / completed (active 4ч)

// SupportActor — роль инициатора перехода.
type SupportActor string

const (
	SupportActorUser     SupportActor = "user"     // владелец сессии
	SupportActorOperator SupportActor = "operator" // инженер поддержки с ролью категории (не назначен)
	SupportActorAssigned SupportActor = "assigned" // назначенный оператор (assigned_admin_id / transferred_to_id)
	SupportActorAdmin    SupportActor = "admin"    // роль admin либо глобальный admin_token
	SupportActorSystem   SupportActor = "system"   // автоматика: TTL, cleanup
)

// Ошибки машины состояний (маппятся в HTTP-коды API).
var (
	// ErrInvalidTransition — переход вне таблицы (включая воскрешение
	// терминальных статусов и гонку состояний).
	ErrInvalidTransition = errors.New("invalid_transition")
	// ErrSessionTaken — сессия уже занята другим оператором.
	ErrSessionTaken = errors.New("session_taken")
	// ErrDuplicateSession — у пользователя уже есть живая сессия.
	ErrDuplicateSession = errors.New("duplicate_session")
)

// supportTerminalStatuses — терминальные статусы: из них нет переходов
// (завершённую сессию нельзя подключить/переадресовать повторно).
var supportTerminalStatuses = map[string]bool{
	"rejected": true, "completed": true, "cancelled": true,
	"expired": true, "ended_by_admin": true, "ended_by_user": true,
}

// SupportLiveStatuses возвращает множество «живых» статусов сессии.
func SupportLiveStatuses() []string {
	return []string{"requested", "connecting", "authorizing", "approved", "active", "transferred"}
}

// SupportIsTerminal сообщает, является ли статус терминальным.
func SupportIsTerminal(status string) bool { return supportTerminalStatuses[status] }

// supportPendingStatuses — статусы ожидания решения (до approve).
func supportPendingStatuses(s string) bool {
	return s == "requested" || s == "connecting" || s == "authorizing" || s == "approved"
}

// SupportTransitionAllowed — единый валидатор переходов машины состояний.
// Чистая функция: контекстные условия (кто именно назначен, совпадение
// number_match) проверяются поверх таблицы в store-функциях и хендлерах.
func SupportTransitionAllowed(from, to string, actor SupportActor) error {
	if supportTerminalStatuses[from] {
		return fmt.Errorf("%w: терминальный статус %q", ErrInvalidTransition, from)
	}
	allow := func(actors ...SupportActor) error {
		for _, a := range actors {
			if a == actor {
				return nil
			}
		}
		return fmt.Errorf("%w: %s не может выполнить %s→%s", ErrInvalidTransition, actor, from, to)
	}
	switch to {
	case "connecting":
		if from != "requested" && from != "connecting" {
			return fmt.Errorf("%w: connect возможен только из requested/connecting, не из %q", ErrInvalidTransition, from)
		}
		// Подключение/повторный запрос кода — операторское действие.
		return allow(SupportActorOperator, SupportActorAdmin)
	case "active":
		// ГЛАВНЫЙ ИНВАРИАНТ: в active сессию переводит ТОЛЬКО решение
		// владельца (decision approve с совпавшим number_match). Ни
		// оператор, ни админ, ни автоматика не могут активировать доступ
		// к рабочему столу без явного подтверждения пользователя.
		// Исключение — transferred→active (принятие переадресации):
		// сессия УЖЕ была подтверждена владельцем до переадресации,
		// новый доступ с нуля не возникает.
		if from == "transferred" {
			return allow(SupportActorAssigned, SupportActorAdmin)
		}
		if !supportPendingStatuses(from) {
			return fmt.Errorf("%w: approve возможен только из pending-статусов, не из %q", ErrInvalidTransition, from)
		}
		return allow(SupportActorUser)
	case "transferred":
		if from != "active" && from != "transferred" {
			return fmt.Errorf("%w: переадресация возможна только из active/transferred, не из %q", ErrInvalidTransition, from)
		}
		return allow(SupportActorAssigned, SupportActorAdmin)
	case "rejected":
		if supportPendingStatuses(from) || from == "active" || from == "transferred" {
			return allow(SupportActorUser, SupportActorSystem)
		}
		return fmt.Errorf("%w: reject невозможен из %q", ErrInvalidTransition, from)
	case "cancelled":
		if supportPendingStatuses(from) {
			return allow(SupportActorUser, SupportActorAdmin, SupportActorSystem)
		}
		return fmt.Errorf("%w: cancel возможен только до подключения, не из %q", ErrInvalidTransition, from)
	case "completed", "ended_by_admin", "ended_by_user":
		switch {
		case to == "ended_by_admin":
			if err := allow(SupportActorAdmin, SupportActorAssigned); err != nil {
				return err
			}
		case to == "ended_by_user":
			if err := allow(SupportActorUser); err != nil {
				return err
			}
		default:
			if err := allow(SupportActorUser, SupportActorAssigned, SupportActorAdmin, SupportActorSystem); err != nil {
				return err
			}
		}
		if supportPendingStatuses(from) || from == "active" || from == "transferred" {
			return nil
		}
		return fmt.Errorf("%w: завершение невозможно из %q", ErrInvalidTransition, from)
	case "expired":
		// Истечение — только автоматикой (TTL pending-заявок).
		if !supportPendingStatuses(from) {
			return fmt.Errorf("%w: expire возможен только для pending-статусов, не из %q", ErrInvalidTransition, from)
		}
		return allow(SupportActorSystem)
	default:
		return fmt.Errorf("%w: неизвестный целевой статус %q", ErrInvalidTransition, to)
	}
}

// supportSessionInsert — INSERT строки support_sessions (без валидации
// полей; значения по умолчанию проставляет SupportSessionCreate).
func (s *Store) supportSessionInsert(ctx context.Context, ss *SupportSession) error {
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
	return err
}

// SupportSessionExpireStaleByUser гасит залежавшиеся live-строки одного
// пользователя — тот же TTL, что у ленивого sweep (SupportSessionSweepStale):
// pending-заявки (requested/connecting/authorizing/approved) старше
// supportPendingTTL → expired, active/transferred старше 4 часов →
// completed (актёр system). Вызывается при 23505 в SupportSessionCreate:
// partial unique index «одна живая сессия» покрывает и stale-строки, а
// фильтры выборки их уже не видят — без этого новое обращение блокировалось
// бы навсегда, пока ближайший sweep не догадается почистить
// (аудит 2026-09-11).
func (s *Store) SupportSessionExpireStaleByUser(ctx context.Context, userID uuid.UUID) error {
	if _, err := s.Pool().Exec(ctx, `
		UPDATE support_sessions SET
			status = 'expired', ended_at = now(), updated_at = now()
		WHERE user_id = $1
		  AND status IN ('requested', 'connecting', 'authorizing', 'approved')
		  AND created_at < now() - interval '15 minutes'`, userID); err != nil {
		return fmt.Errorf("store: истечь просроченные заявки пользователя %s: %w", userID, err)
	}
	if _, err := s.Pool().Exec(ctx, `
		UPDATE support_sessions SET
			status = 'completed', ended_at = now(), updated_at = now(),
			transfer_token_hash = NULL
		WHERE user_id = $1
		  AND status IN ('active', 'transferred')
		  AND started_at < now() - interval '4 hours'`, userID); err != nil {
		return fmt.Errorf("store: завершить устаревшие active-сессии пользователя %s: %w", userID, err)
	}
	return nil
}

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

	err := s.supportSessionInsert(ctx, ss)
	var pgErr *pgconn.PgError
	if err != nil && errors.As(err, &pgErr) && pgErr.Code == "23505" {
		// Partial unique index «одна живая сессия на пользователя».
		// Конкурентное свежее обращение → ErrDuplicateSession; но индекс
		// может держать и stale live-строка (TTL истёк, ленивый sweep ещё
		// не дошёл) — гасим её и ретраим вставку ровно один раз.
		if expErr := s.SupportSessionExpireStaleByUser(ctx, ss.UserID); expErr != nil {
			slog.Warn("store: гашение stale live-строк перед ретраем support_session", "error", expErr)
			return ErrDuplicateSession
		}
		if err = s.supportSessionInsert(ctx, ss); err != nil && errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrDuplicateSession
		}
	}
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
// активными; active/transferred старше supportActiveMaxAge — завершены
// автоматикой и тоже не считаются живыми — «вечных» сессий нет).
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
		  AND`+notStaleActive+`
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
		   AND ` + notStalePending + `
		   AND ` + notStaleActive
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

// supportTransitionExec выполняет атомарный переход: UPDATE выполняется
// только если текущий статус совпадает с ожидаемым (защита от гонок и
// «воскрешения» терминальных статусов). setFmt обязан содержать только
// безопасные литералы — параметры передаются через $N.
func (s *Store) supportTransitionExec(ctx context.Context, id uuid.UUID, fromStatuses []string, setSQL string, args ...any) error {
	all := append([]any{id, fromStatuses}, args...)
	ct, err := s.Pool().Exec(ctx, `UPDATE support_sessions SET `+setSQL+`,
			updated_at = now()
		WHERE id = $1 AND status = ANY($2)`, all...)
	if err != nil {
		return fmt.Errorf("store: переход support_session %s: %w", id, err)
	}
	if ct.RowsAffected() == 0 {
		// Сессии нет вовсе — NotFound; есть, но статус другой —
		// нарушение последовательности (или гонка).
		var exists bool
		if err := s.Pool().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM support_sessions WHERE id = $1)`, id).Scan(&exists); err != nil {
			return fmt.Errorf("store: проверка support_session %s: %w", id, err)
		}
		if !exists {
			return ErrNotFound
		}
		return ErrInvalidTransition
	}
	return nil
}

// SupportSessionConnect — подключение оператора: requested/connecting →
// connecting с назначением оператора и свежим кодом number-match.
// Перехват чужой сессии запрещён: владение проверяется В УСЛОВИИ UPDATE —
// чужая (уже назначенная другому) сессия не мутируется вовсе, ни код
// number-match, ни счётчик попыток не перетираются; конфликт →
// ErrSessionTaken без побочных эффектов. adminID == nil допустим только
// для глобального admin_token (актёр admin), сессия остаётся
// «безымянной» до approve; админ (роль/токен) может перезапросить код и
// для чужой сессии.
func (s *Store) SupportSessionConnect(ctx context.Context, id uuid.UUID, actor SupportActor, adminID *uuid.UUID, numberMatch string) error {
	if actor != SupportActorOperator && actor != SupportActorAdmin {
		return fmt.Errorf("%w: connect доступен только оператору/админу, не %s", ErrInvalidTransition, actor)
	}

	// Атомарно: только requested/connecting; назначение оператора не
	// перетирает уже существующее чужое (COALESCE).
	setSQL := `status = 'connecting',
		number_match = $3,
		nm_attempts = 0`
	args := []any{numberMatch}
	whereSQL := ""
	if adminID != nil {
		setSQL += `,
		assigned_admin_id = COALESCE(assigned_admin_id, $4)`
		args = append(args, *adminID)
		if actor == SupportActorOperator {
			// Оператор подключает только ничью или свою сессию: условие
			// владения — в самом UPDATE (аудит 2026-09-11).
			whereSQL = ` AND (assigned_admin_id IS NULL OR assigned_admin_id = $5)`
			args = append(args, *adminID)
		}
	}
	all := append([]any{id, []string{"requested", "connecting"}}, args...)
	ct, err := s.Pool().Exec(ctx, `UPDATE support_sessions SET `+setSQL+`,
			updated_at = now()
		WHERE id = $1 AND status = ANY($2)`+whereSQL, all...)
	if err != nil {
		return fmt.Errorf("store: подключение оператора support_session %s: %w", id, err)
	}
	if ct.RowsAffected() == 0 {
		// 0 строк: сессии нет / статус ушёл / занята другим оператором —
		// разбор только чтением, без мутаций.
		var (
			exists   bool
			status   string
			assigned *uuid.UUID
		)
		if err := s.Pool().QueryRow(ctx, `
			SELECT EXISTS(SELECT 1 FROM support_sessions WHERE id = $1),
			       COALESCE((SELECT status FROM support_sessions WHERE id = $1), ''),
			       (SELECT assigned_admin_id FROM support_sessions WHERE id = $1)`, id,
		).Scan(&exists, &status, &assigned); err != nil {
			return fmt.Errorf("store: проверка support_session %s: %w", id, err)
		}
		if !exists {
			return ErrNotFound
		}
		if status != "requested" && status != "connecting" {
			return ErrInvalidTransition
		}
		if actor == SupportActorOperator && adminID != nil &&
			assigned != nil && *assigned != *adminID {
			return ErrSessionTaken
		}
		return ErrInvalidTransition
	}
	return nil
}

// SupportSessionApprove — подтверждение доступа пользователем:
// requested/connecting → active. Единственный легальный путь в active:
// вызывается только из decision-хендлера владельца после сверки
// number-match. Код гасится (одноразовость), счётчик попыток сбрасывается.
func (s *Store) SupportSessionApprove(ctx context.Context, id uuid.UUID) error {
	return s.supportTransitionExec(ctx, id, []string{"requested", "connecting"},
		`status = 'active',
		started_at = COALESCE(started_at, now()),
		number_match = '',
		nm_attempts = 0`)
}

// SupportSessionUpdateStatus — только для служебных переходов (проходят
// через таблицу). Производственный код использует типизированные функции
// выше; функция оставлена для диагностики/тестов и валидирует переход.
func (s *Store) SupportSessionUpdateStatus(ctx context.Context, id uuid.UUID, from, status string, adminID *uuid.UUID, numberMatch string, actor SupportActor) error {
	if err := SupportTransitionAllowed(from, status, actor); err != nil {
		return err
	}
	setSQL := `status = $3`
	args := []any{status}
	if adminID != nil {
		setSQL += `, assigned_admin_id = $4`
		args = append(args, *adminID)
	}
	if numberMatch != "" {
		setSQL += `, number_match = $5, nm_attempts = 0`
		args = append(args, numberMatch)
	}
	return s.supportTransitionExec(ctx, id, []string{from}, setSQL, args...)
}

// SupportSessionFailNumberMatch инкрементирует счётчик несовпадений кода и
// возвращает новое значение. Достигнут лимит — сессия принудительно
// отклоняется (автоматика), код больше не принять.
func (s *Store) SupportSessionFailNumberMatch(ctx context.Context, id uuid.UUID) (int, error) {
	var attempts int
	err := s.Pool().QueryRow(ctx,
		`UPDATE support_sessions SET nm_attempts = nm_attempts + 1, updated_at = now()
		WHERE id = $1 RETURNING nm_attempts`, id).Scan(&attempts)
	if err != nil {
		return 0, fmt.Errorf("store: инкремент nm_attempts %s: %w", id, err)
	}
	if attempts >= SupportMaxNMAttempts {
		_ = s.SupportSessionEnd(ctx, id, "rejected", SupportActorSystem)
	}
	return attempts, nil
}

// SupportSessionTransfer выполняет переадресацию сессии на другого сотрудника:
// фиксирует момент выдачи transfer-токена (transferred_at — старт окна
// supportTransferTTL, в течение которого токен можно принять). Переадресация
// возможна ТОЛЬКО из active/transferred (завершённые и неподтверждённые
// сессии переадресовать нельзя — доступ без approve пользователя исключён).
func (s *Store) SupportSessionTransfer(ctx context.Context, id uuid.UUID, fromID uuid.UUID, toID *uuid.UUID, tokenHash []byte) error {
	ct, err := s.Pool().Exec(ctx, `UPDATE support_sessions SET
		status = 'transferred',
		transferred_from_id = $2,
		transferred_to_id = $3,
		transfer_token_hash = $4,
		transferred_at = now(),
		updated_at = now()
		WHERE id = $1 AND status IN ('active', 'transferred')`,
		id, fromID, toID, tokenHash)
	if err != nil {
		return fmt.Errorf("store: переадресовать support_session %s: %w", id, err)
	}
	if ct.RowsAffected() == 0 {
		var exists bool
		if qerr := s.Pool().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM support_sessions WHERE id = $1)`, id).Scan(&exists); qerr == nil && exists {
			return ErrInvalidTransition
		}
		return ErrNotFound
	}
	return nil
}

// SupportSessionAcceptTransfer принимает переадресованную сессию новым
// оператором: transferred → active (сессия была подтверждена пользователем
// до переадресации — повторное согласие не требуется, но и доступа «с нуля»
// без approve не возникает). Transfer-токен одноразовый: хеш очищается,
// повторное принятие по той же ссылке невозможно.
func (s *Store) SupportSessionAcceptTransfer(ctx context.Context, id uuid.UUID, newAdminID uuid.UUID) error {
	ct, err := s.Pool().Exec(ctx, `UPDATE support_sessions SET
		status = 'active',
		assigned_admin_id = $2,
		transfer_token_hash = NULL,
		updated_at = now()
		WHERE id = $1 AND status = 'transferred'`,
		id, newAdminID)
	if err != nil {
		return fmt.Errorf("store: принять переадресацию support_session %s: %w", id, err)
	}
	if ct.RowsAffected() == 0 {
		var exists bool
		if qerr := s.Pool().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM support_sessions WHERE id = $1)`, id).Scan(&exists); qerr == nil && exists {
			return ErrInvalidTransition
		}
		return ErrNotFound
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

// SupportSessionEnd завершает сессию удаленного доступа. Переход проходит
// серверную таблицу: живую сессию завершает владелец, назначенный оператор
// или админ; терминальный статус не меняется повторно (409 на «дозакрытие»).
func (s *Store) SupportSessionEnd(ctx context.Context, id uuid.UUID, finalStatus string, actor SupportActor) error {
	if finalStatus == "" {
		finalStatus = "completed"
	}
	// Валидность прав актёра проверяем для каждого живого исходного статуса:
	// таблица разрешает завершение из pending только владельцу/админу/системе,
	// из active/transferred — ещё и назначенному оператору.
	live := SupportLiveStatuses()
	for _, from := range live {
		if err := SupportTransitionAllowed(from, finalStatus, actor); err == nil {
			// Найден допустимый контракт — выполняем атомарный переход
			// из любого живого статуса (какой есть).
			return s.supportTransitionExec(ctx, id, live,
				`status = $3,
				ended_at = now(),
				number_match = '',
				transfer_token_hash = NULL`, finalStatus)
		}
	}
	return fmt.Errorf("%w: %s не может завершить сессию в %q", ErrInvalidTransition, actor, finalStatus)
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

// SupportSessionCleanupClosed — автоматика машины состояний (актёр system):
//   - pending-заявки (requested/connecting + легаси authorizing/approved)
//     старше supportPendingTTL → expired;
//   - активные/переадресованные сессии старше supportActiveMaxAge (4 часа)
//     → completed (защита от «вечных» сессий удалённого доступа);
//   - завершённые сессии (включая expired) удаляются.
func (s *Store) SupportSessionCleanupClosed(ctx context.Context) (int64, error) {
	if _, err := s.Pool().Exec(ctx, `
		UPDATE support_sessions SET
			status = 'expired',
			ended_at = now(),
			updated_at = now()
		WHERE status IN ('requested', 'connecting', 'authorizing', 'approved')
		  AND created_at < now() - interval '15 minutes'`); err != nil {
		return 0, fmt.Errorf("store: истечь просроченные support_sessions: %w", err)
	}
	if _, err := s.Pool().Exec(ctx, `
		UPDATE support_sessions SET
			status = 'completed',
			ended_at = now(),
			updated_at = now(),
			transfer_token_hash = NULL
		WHERE status IN ('active', 'transferred')
		  AND started_at < now() - interval '4 hours'`); err != nil {
		return 0, fmt.Errorf("store: завершить просроченные active support_sessions: %w", err)
	}
	ct, err := s.Pool().Exec(ctx, `DELETE FROM support_sessions
		WHERE status IN ('completed', 'ended_by_admin', 'ended_by_user', 'rejected', 'cancelled', 'expired')`)
	if err != nil {
		return 0, fmt.Errorf("store: очистить завершенные support_sessions: %w", err)
	}
	return ct.RowsAffected(), nil
}

// SupportSessionSweepStale — ленивая автоматика без удаления: переводит
// просроченные сессии в терминальные статусы (pending → expired,
// active/transferred > 4ч → completed). Вызывается из часто опрашиваемых
// ручек (support/current, queue), чтобы TTL работал без внешнего крона.
func (s *Store) SupportSessionSweepStale(ctx context.Context) error {
	if _, err := s.Pool().Exec(ctx, `
		UPDATE support_sessions SET
			status = 'expired', ended_at = now(), updated_at = now()
		WHERE status IN ('requested', 'connecting', 'authorizing', 'approved')
		  AND created_at < now() - interval '15 minutes'`); err != nil {
		return fmt.Errorf("store: sweep expired support_sessions: %w", err)
	}
	if _, err := s.Pool().Exec(ctx, `
		UPDATE support_sessions SET
			status = 'completed', ended_at = now(), updated_at = now(),
			transfer_token_hash = NULL
		WHERE status IN ('active', 'transferred')
		  AND started_at < now() - interval '4 hours'`); err != nil {
		return fmt.Errorf("store: sweep устаревших active support_sessions: %w", err)
	}
	return nil
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
