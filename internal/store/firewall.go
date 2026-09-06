// Файрвол/fail2ban: чёрные/белые списки CIDR и автоблокировки по IP.
package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// IPList — запись чёрного (deny) или белого (allow) списка.
type IPList struct {
	ID        uuid.UUID `json:"id"`
	Kind      string    `json:"kind"` // allow | deny
	CIDR      string    `json:"cidr"`
	Note      string    `json:"note"`
	CreatedAt time.Time `json:"created_at"`
}

// IPBan — активная/недавняя автоблокировка IP (fail2ban).
type IPBan struct {
	IP          string    `json:"ip"`
	Reason      string    `json:"reason"`
	Fails       int       `json:"fails"`
	BannedUntil time.Time `json:"banned_until"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// NormalizeCIDR — IP или префикс → каноничная строка («10.0.0.5» →
// «10.0.0.5/32», «2001:db8::/32» без изменений).
func NormalizeCIDR(s string) (string, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		a, err2 := netip.ParseAddr(s)
		if err2 != nil {
			return "", fmt.Errorf("cidr %q: не IP и не префикс", s)
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	return p.Masked().String(), nil
}

// IPListAdd добавляет CIDR в список kind (allow|deny); дубликат по
// (kind, cidr) игнорируется.
func (s *Store) IPListAdd(ctx context.Context, kind, cidr, note string) (*IPList, error) {
	norm, err := NormalizeCIDR(cidr)
	if err != nil {
		return nil, err
	}
	row := &IPList{Kind: kind, CIDR: norm, Note: note}
	err = s.Pool().QueryRow(ctx,
		`INSERT INTO ip_lists (kind, cidr, note) VALUES ($1, $2, $3)
		 ON CONFLICT (kind, cidr) DO UPDATE SET note = EXCLUDED.note
		 RETURNING id, created_at`, kind, norm, note).
		Scan(&row.ID, &row.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("store: ip_lists add %s %s: %w", kind, norm, err)
	}
	return row, nil
}

// IPListDelete удаляет запись списка по id.
func (s *Store) IPListDelete(ctx context.Context, id uuid.UUID) error {
	ct, err := s.Pool().Exec(ctx, `DELETE FROM ip_lists WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("store: ip_lists delete: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// IPLists возвращает оба списка одной выборкой, отсортированной по kind,cidr.
func (s *Store) IPLists(ctx context.Context) ([]IPList, error) {
	rows, err := s.Pool().Query(ctx,
		`SELECT id, kind, cidr, note, created_at FROM ip_lists ORDER BY kind, cidr`)
	if err != nil {
		return nil, fmt.Errorf("store: ip_lists: %w", err)
	}
	defer rows.Close()
	var out []IPList
	for rows.Next() {
		var l IPList
		if err := rows.Scan(&l.ID, &l.Kind, &l.CIDR, &l.Note, &l.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: ip_lists scan: %w", err)
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// BanFail атомарно считает неудачу с IP: счётчик растёт, пока updated_at
// внутри окна window; при достижении threshold в окне и если бан неактивен —
// banned_until = now()+banTime. Возвращает актуальное состояние бана.
func (s *Store) BanFail(ctx context.Context, ip, reason string, window, banTime time.Duration, threshold int) (IPBan, error) {
	var b IPBan
	err := s.Pool().QueryRow(ctx, `
		INSERT INTO ip_bans (ip, reason, fails, banned_until, updated_at)
		VALUES ($1, $2, 1, now(), now())
		ON CONFLICT (ip) DO UPDATE SET
		  fails = CASE WHEN ip_bans.updated_at > now() - make_interval(secs => $3)
		               THEN ip_bans.fails + 1 ELSE 1 END,
		  reason = EXCLUDED.reason,
		  banned_until = CASE
		    WHEN (CASE WHEN ip_bans.updated_at > now() - make_interval(secs => $3)
		               THEN ip_bans.fails + 1 ELSE 1 END) >= $4
		         AND ip_bans.banned_until <= now()
		      THEN now() + make_interval(secs => $5)
		    ELSE ip_bans.banned_until END,
		  updated_at = now()
		RETURNING ip, reason, fails, banned_until, updated_at`,
		ip, reason, int(window.Seconds()), threshold, int(banTime.Seconds())).
		Scan(&b.IP, &b.Reason, &b.Fails, &b.BannedUntil, &b.UpdatedAt)
	if err != nil {
		return b, fmt.Errorf("store: ip_bans fail %s: %w", ip, err)
	}
	return b, nil
}

// BanActive сообщает, действует ли бан IP прямо сейчас.
func (s *Store) BanActive(ctx context.Context, ip string) (bool, time.Time, error) {
	var until time.Time
	err := s.Pool().QueryRow(ctx,
		`SELECT banned_until FROM ip_bans WHERE ip = $1 AND banned_until > now()`, ip).
		Scan(&until)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, time.Time{}, nil
	}
	if err != nil {
		return false, until, fmt.Errorf("store: ip_bans active %s: %w", ip, err)
	}
	return true, until, nil
}

// BansActive — активные банки (для админки), включая только что истёкшие
// (для ручного разбана показываем и «спящие» записи последних суток).
func (s *Store) BansActive(ctx context.Context) ([]IPBan, error) {
	rows, err := s.Pool().Query(ctx, `
		SELECT ip, reason, fails, banned_until, updated_at FROM ip_bans
		WHERE banned_until > now() - interval '24 hours'
		ORDER BY banned_until DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: ip_bans list: %w", err)
	}
	defer rows.Close()
	var out []IPBan
	for rows.Next() {
		var b IPBan
		if err := rows.Scan(&b.IP, &b.Reason, &b.Fails, &b.BannedUntil, &b.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store: ip_bans scan: %w", err)
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// BanDelete снимает бан (ручной разбан в админке).
func (s *Store) BanDelete(ctx context.Context, ip string) error {
	_, err := s.Pool().Exec(ctx, `DELETE FROM ip_bans WHERE ip = $1`, ip)
	if err != nil {
		return fmt.Errorf("store: ip_bans delete %s: %w", ip, err)
	}
	return nil
}
