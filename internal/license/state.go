// Машина состояний лицензии и персистентность в таблице settings (ключи
// license.*): free (5 пользователей навсегда), trial (30 дней full от
// первого старта), licensed (limits из payload). Отзыв — CRL; истёкшая
// подписка гаснет в Free ЧЕРЕЗ grace-окно, вход существующим не блокируется
// никогда (report §3.3). Гейт обновлений — CheckBuildAllowed по build_date.
package license

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aligorov/twofa/internal/store"
)

// Режимы и константы модели (report §3.2, §3.5).
const (
	ModeFree     Mode = "free"
	ModeTrial    Mode = "trial"
	ModeLicensed Mode = "licensed"

	// FreeUserLimit — лимит активных пользователей без лицензии (навсегда).
	FreeUserLimit = 5
	// TrialDuration — длительность демо с первого старта.
	TrialDuration = 30 * 24 * time.Hour
	// graceLic — опциональное grace-окно ПОСЛЕ expires_at подписки
	// (Keygen-style, report §3.5: «+ опциональный grace 5 дней»).
	graceLic = 5 * 24 * time.Hour
)

// Ключи в таблице settings (значения — JSON-строки).
const (
	keyBlob   = "license.blob"
	keyCRL    = "license.crl"
	keyTrial  = "license.trial_started"
	buildDate = "2006-01-02" // формат BuildDate (-ldflags -X main.BuildDate)
)

// Mode — текущий режим сервера.
type Mode string

// Status — эффективное состояние лицензии на момент времени. UsersActive и
// AtLimit заполняет API-слой (подсчёт активных пользователей — запрос к БД).
type Status struct {
	Mode      Mode
	UserLimit int // 0 — не ограничено (trial/безлимитная лицензия)

	LicID    string
	Customer string
	Plan     string // licensed: subscription | perpetual
	Features []string

	Revoked bool // лицензия отозвана CRL (Mode=free)
	Expired bool // подписка истекла позже grace (Mode=free)
	Grace   bool // подписка истекла, действует grace-окно (Mode=licensed)

	DaysLeft      int // дней подписки (0 в grace)
	TrialDaysLeft int // дней демо
	UpdatesUntil  time.Time

	UsersActive int  // заполняет API-слой
	AtLimit     bool // заполняет API-слой
}

// ErrBuildTooNew — сборка новее окна обновлений лицензии (report §3.4).
var ErrBuildTooNew = errors.New(
	"license: версия новее окна обновлений лицензии — откатитесь на предыдущую версию или продлите maintenance")

// Manager — лицензионное состояние поверх Store; Now инъектируется тестами.
type Manager struct {
	st  *store.Store
	now func() time.Time
}

// NewManager собирает менеджер лицензий.
func NewManager(st *store.Store) *Manager { return &Manager{st: st, now: time.Now} }

// Now — текущее время менеджера (подмена в тестах).
func (m *Manager) Now() time.Time { return m.now() }

// ---- чистая логика состояний ----

// computeStatus вычисляет статус по сырому состоянию (blob/CRL/trial) на
// момент now. Битый blob — деградация в free (лицензирование — юридический
// барьер, не причина для аварии сервера; report §3.8).
func computeStatus(now time.Time, blob, crl string, trialStarted *time.Time) Status {
	if blob == "" {
		if trialStarted != nil {
			until := trialStarted.Add(TrialDuration)
			if now.Before(until) {
				return Status{
					Mode:          ModeTrial,
					TrialDaysLeft: daysLeft(now, until),
				}
			}
		}
		return Status{Mode: ModeFree, UserLimit: FreeUserLimit}
	}

	lic, err := ParseLicense(blob)
	if err != nil {
		slog.Warn("license: загруженная лицензия не проверяется — работаю как free", "error", err)
		return Status{Mode: ModeFree, UserLimit: FreeUserLimit}
	}

	meta := Status{
		UserLimit:    lic.UserLimit,
		LicID:        lic.LicID,
		Customer:     lic.Customer,
		Plan:         lic.Plan,
		Features:     lic.Features,
		UpdatesUntil: lic.MaintenanceExpires,
	}

	// Досрочный отзыв: CRL подписан вендором и адресован этой лицензии.
	if crl != "" {
		if rev, err := ParseRevocation(crl); err == nil && rev.LicID == lic.LicID {
			return Status{
				Mode: ModeFree, UserLimit: FreeUserLimit, Revoked: true,
				LicID: lic.LicID, Customer: lic.Customer, Plan: lic.Plan,
			}
		}
	}

	if lic.Plan == PlanSubscription && lic.ExpiresAt != nil {
		if now.After(lic.ExpiresAt.Add(graceLic)) {
			// Подписка погасла: free-лимит, метаданные — для баннера/UI.
			meta.Mode = ModeFree
			meta.UserLimit = FreeUserLimit
			meta.Expired = true
			return meta
		}
		meta.Mode = ModeLicensed
		if now.After(*lic.ExpiresAt) {
			meta.Grace = true // истекла, grace-окно ещё действует
		} else {
			meta.DaysLeft = daysLeft(now, *lic.ExpiresAt)
		}
		return meta
	}

	// Perpetual — бессрочная (право на версии до maintenance_expires
	// проверяет гейт CheckBuildAllowed, а не время).
	meta.Mode = ModeLicensed
	return meta
}

// daysLeft — целое число дней до deadline (округление вверх: «сегодня
// истекает» = 1; в grace не вызывается).
func daysLeft(now, deadline time.Time) int {
	d := deadline.Sub(now).Hours() / 24
	return int(math.Ceil(d))
}

// CheckBuildAllowed — гейт обновлений (report §3.4): licensed-сборка новее
// maintenance_expires не стартует. free/trial, пустая или неразобранная
// дата сборки — разрешены (лицензирование — не DRM, битая дата — проблема
// сборки вендора, не клиента).
func CheckBuildAllowed(dateStr string, st Status) error {
	if st.Mode != ModeLicensed || dateStr == "" {
		return nil
	}
	bd, err := time.Parse(buildDate, dateStr)
	if err != nil {
		return nil
	}
	maint := st.UpdatesUntil.UTC().Truncate(24 * time.Hour)
	if bd.After(maint) {
		return fmt.Errorf("%w (сборка %s, обновления до %s)",
			ErrBuildTooNew, dateStr, maint.Format(buildDate))
	}
	return nil
}

// ---- персистентность (settings.license.*) ----

// Init вызывается на старте сервера: без лицензии и без отмеченного старта
// демо — персистит trial_started (сбрасывается только с БД, report §3.2).
func (m *Manager) Init(ctx context.Context) error {
	blob, err := m.loadString(ctx, keyBlob)
	if err != nil {
		return err
	}
	if blob != "" {
		return nil // лицензия есть — демо неактуально
	}
	started, err := m.loadTime(ctx, keyTrial)
	if err != nil {
		return err
	}
	if started != nil {
		return nil // уже отмечен
	}
	now := m.now()
	if err := m.saveTime(ctx, keyTrial, now); err != nil {
		return err
	}
	slog.Info("license: старт демо-режима (30 дней, full-featured)", "until", now.Add(TrialDuration).Format(time.RFC3339))
	return nil
}

// Effective загружает персистентное состояние и вычисляет статус.
func (m *Manager) Effective(ctx context.Context) (Status, error) {
	blob, err := m.loadString(ctx, keyBlob)
	if err != nil {
		return Status{}, err
	}
	crl, err := m.loadString(ctx, keyCRL)
	if err != nil {
		return Status{}, err
	}
	trial, err := m.loadTime(ctx, keyTrial)
	if err != nil {
		return Status{}, err
	}
	return computeStatus(m.now(), blob, crl, trial), nil
}

// Upload проверяет и сохраняет лицензию. Отозванная (по текущему CRL)
// отклоняется; пробный старт сбрасывается — демо «израсходовано» покупкой,
// удаление лицензии возвращает сервер в free (не в демо).
func (m *Manager) Upload(ctx context.Context, blob string) (Payload, error) {
	lic, err := ParseLicense(blob)
	if err != nil {
		return lic, err
	}
	if crl, err := m.loadString(ctx, keyCRL); err == nil && crl != "" {
		if rev, rerr := ParseRevocation(crl); rerr == nil && rev.LicID == lic.LicID {
			return lic, ErrRevoked
		}
	}
	if err := m.saveString(ctx, keyBlob, blob); err != nil {
		return lic, err
	}
	_ = m.deleteKey(ctx, keyTrial)
	return lic, nil
}

// ErrRevoked — загружаемая лицензия отозвана CRL.
var ErrRevoked = errors.New("license: лицензия отозвана (CRL)")

// UploadCRL проверяет подпись и сохраняет CRL-отзыв.
func (m *Manager) UploadCRL(ctx context.Context, blob string) (Revocation, error) {
	rev, err := ParseRevocation(blob)
	if err != nil {
		return rev, err
	}
	return rev, m.saveString(ctx, keyCRL, blob)
}

// Remove удаляет лицензию (free-режим).
func (m *Manager) Remove(ctx context.Context) error { return m.deleteKey(ctx, keyBlob) }

// loadString читает JSON-строку из settings; отсутствующий ключ — "".
func (m *Manager) loadString(ctx context.Context, key string) (string, error) {
	var raw json.RawMessage
	err := m.st.Pool().QueryRow(ctx,
		`SELECT value FROM settings WHERE key = $1`, key).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("license: чтение %s: %w", key, err)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("license: значение %s не строка: %w", key, err)
	}
	return s, nil
}

// loadTime читает RFC3339-время из settings; отсутствующий ключ — nil.
func (m *Manager) loadTime(ctx context.Context, key string) (*time.Time, error) {
	s, err := m.loadString(ctx, key)
	if err != nil || s == "" {
		return nil, err
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil, fmt.Errorf("license: значение %s не RFC3339: %w", key, err)
	}
	return &t, nil
}

// saveString записывает строку как JSON-значение settings.
func (m *Manager) saveString(ctx context.Context, key, val string) error {
	b, err := json.Marshal(val)
	if err != nil {
		return err
	}
	if _, err := m.st.Pool().Exec(ctx,
		`INSERT INTO settings (key, value) VALUES ($1, $2)
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, key, b); err != nil {
		return fmt.Errorf("license: запись %s: %w", key, err)
	}
	return nil
}

// saveTime записывает время RFC3339; ON CONFLICT DO NOTHING — конкурентный
// процесс мог отметить старт демо первым.
func (m *Manager) saveTime(ctx context.Context, key string, t time.Time) error {
	b, err := json.Marshal(t.Format(time.RFC3339))
	if err != nil {
		return err
	}
	if _, err := m.st.Pool().Exec(ctx,
		`INSERT INTO settings (key, value) VALUES ($1, $2)
		 ON CONFLICT (key) DO NOTHING`, key, b); err != nil {
		return fmt.Errorf("license: запись %s: %w", key, err)
	}
	return nil
}

// deleteKey удаляет ключ из settings (отсутствующий — не ошибка).
func (m *Manager) deleteKey(ctx context.Context, key string) error {
	if _, err := m.st.Pool().Exec(ctx,
		`DELETE FROM settings WHERE key = $1`, key); err != nil {
		return fmt.Errorf("license: удаление %s: %w", key, err)
	}
	return nil
}
