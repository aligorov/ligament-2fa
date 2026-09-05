// Репозиторий аудита: запись событий безопасности и выборка с фильтрами.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// auditListDefaultLimit — лимит AuditList, если фильтр не задан иного.
const auditListDefaultLimit = 100

// AuditRow — строка audit_log.
type AuditRow struct {
	ID       int64
	Ts       time.Time
	Username string // NULL читается как ""
	Event    string
	Detail   map[string]any // JSONB; NULL → nil
	SrcIP    string         // NULL читается как ""
	Result   string         // NULL читается как ""
}

// AuditFilter — необязательные фильтры AuditList; нулевые значения не
// ограничивают выборку.
type AuditFilter struct {
	Username string
	Event    string
	Since    time.Time
	Until    time.Time
	Limit    int // <=0 → 100
}

// Audit записывает событие в audit_log. detail == nil сохраняется как NULL;
// пустой username сохраняется как NULL (системные события).
func (s *Store) Audit(ctx context.Context, username, event string, detail map[string]any, ip, result string) error {
	var detailJSON []byte
	if detail != nil {
		b, err := json.Marshal(detail)
		if err != nil {
			return fmt.Errorf("store: кодирование detail аудита: %w", err)
		}
		detailJSON = b
	}
	var uname any
	if username != "" {
		uname = username
	}
	_, err := s.Pool().Exec(ctx,
		`INSERT INTO audit_log (username, event, detail, src_ip, result)
		 VALUES ($1, $2, $3, $4, $5)`,
		uname, event, detailJSON, ip, result)
	if err != nil {
		return fmt.Errorf("store: записать аудит (%s): %w", event, err)
	}
	return nil
}

// AuditList возвращает записи аудита по фильтру, новые первыми
// (ORDER BY ts DESC, id DESC); лимит по умолчанию 100.
func (s *Store) AuditList(ctx context.Context, f AuditFilter) ([]*AuditRow, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = auditListDefaultLimit
	}

	where := strings.Builder{}
	where.WriteString("true")
	args := make([]any, 0, 5)
	if f.Username != "" {
		args = append(args, f.Username)
		fmt.Fprintf(&where, " AND username = $%d", len(args))
	}
	if f.Event != "" {
		args = append(args, f.Event)
		fmt.Fprintf(&where, " AND event = $%d", len(args))
	}
	if !f.Since.IsZero() {
		args = append(args, f.Since)
		fmt.Fprintf(&where, " AND ts >= $%d", len(args))
	}
	if !f.Until.IsZero() {
		args = append(args, f.Until)
		fmt.Fprintf(&where, " AND ts <= $%d", len(args))
	}
	args = append(args, limit)

	rows, err := s.Pool().Query(ctx, `
		SELECT id, ts, COALESCE(username, ''), event, detail,
		       COALESCE(src_ip, ''), COALESCE(result, '')
		FROM audit_log
		WHERE `+where.String()+fmt.Sprintf(`
		ORDER BY ts DESC, id DESC
		LIMIT $%d`, len(args)), args...)
	if err != nil {
		return nil, fmt.Errorf("store: список аудита: %w", err)
	}
	defer rows.Close()

	var out []*AuditRow
	for rows.Next() {
		var (
			r      AuditRow
			detail []byte
		)
		if err := rows.Scan(&r.ID, &r.Ts, &r.Username, &r.Event, &detail,
			&r.SrcIP, &r.Result); err != nil {
			return nil, fmt.Errorf("store: список аудита: %w", err)
		}
		if len(detail) > 0 {
			if err := json.Unmarshal(detail, &r.Detail); err != nil {
				return nil, fmt.Errorf("store: разбор detail аудита %d: %w", r.ID, err)
			}
		}
		out = append(out, &r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: список аудита: %w", err)
	}
	return out, nil
}
