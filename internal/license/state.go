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
	// overLimitGrace — окно, в котором создание сверх лимита ещё разрешено
	// (первое превышение фиксируется, report §3.3).
	overLimitGrace = 30 * 24 * time.Hour
)

// Ключи в таблице settings (значения — JSON-строки).
const (
	keyBlob = "license.blob"
	keyCRL  = "license.crl"
	keyOverLimit = "license.over_limit_since" // фиксация первого превышения лимита создания
	buildDate    = "2006-01-02"               // формат BuildDate (-ldflags -X main.BuildDate)
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
// барьер, не причина для аварии сервера; report §3.8). trialUsed — демо
// «израсходовано» покупкой лицензии: остаток дней не восстанавливается.
// Демо-режим включается ТОЛЬКО подписанной вендором demo-лицензией
// (plan=demo, expires_at ≤ 30 дней от issuance): без файла сервер живёт
// в free. Снос базы демо не воскрешает — файл не подделать и не продлить.
func computeStatus(now time.Time, blob, crl string) Status {
	if blob == "" {
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
	// Действует ТОЛЬКО на подписки — perpetual технически не отзывается
	// (report §3.5, README): совпадающий lic_id игнорируем с предупреждением.
	// Демо: полный функционал до expires_at (grace нет — демо истекает
	// жёстко); отзывается CRL наравне с подпиской.
	if lic.Plan == PlanDemo {
		meta.Plan = PlanDemo
		if lic.ExpiresAt != nil && now.Before(*lic.ExpiresAt) {
			meta.Mode = ModeTrial
			meta.TrialDaysLeft = daysLeft(now, *lic.ExpiresAt)
			return meta
		}
		meta.Mode = ModeFree
		meta.UserLimit = FreeUserLimit
		meta.Expired = true
		return meta
	}

	if (lic.Plan == PlanSubscription || lic.Plan == PlanDemo) && crl != "" {
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


// Effective загружает персистентное состояние и вычисляет статус. Битые
// значения — предупреждение и деградация (не авария сервера; §3.8).
func (m *Manager) Effective(ctx context.Context) (Status, error) {
	blob, err := m.loadString(ctx, keyBlob)
	if err != nil {
		return Status{}, err
	}
	crl, err := m.loadString(ctx, keyCRL)
	if err != nil {
		return Status{}, err
	}
	return computeStatus(m.now(), blob, crl), nil
}

// Upload проверяет и сохраняет лицензию. Отозванная (по текущему CRL)
// подписка/демо отклоняется — perpetual CRL-отзыву не подлежит (§3.5).
func (m *Manager) Upload(ctx context.Context, blob string) (Payload, error) {
	lic, err := ParseLicense(blob)
	if err != nil {
		return lic, err
	}
	if lic.Plan == PlanSubscription || lic.Plan == PlanDemo {
		if crl, err := m.loadString(ctx, keyCRL); err == nil && crl != "" {
			if rev, rerr := ParseRevocation(crl); rerr == nil && rev.LicID == lic.LicID {
				return lic, ErrRevoked
			}
		}
	}
	if err := m.saveString(ctx, keyBlob, blob); err != nil {
		return lic, err
	}
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

// Remove удаляет лицензию (free-режим). trial_started/trial_used не
// трогаются: демо не воскрешается, сервер остаётся в free.
func (m *Manager) Remove(ctx context.Context) error { return m.deleteKey(ctx, keyBlob) }

// ---- 30-дневный grace на превышение лимита создания (report §3.3) ----

// OverLimitDecision — вердикт по созданию/включению сверх лимита.
type OverLimitDecision struct {
	Allowed bool
	Since   time.Time // фиксация начала превышения (для аудита)
	First   bool      // превышение зафиксировано только что
}

// OverLimit вызывается ТОЛЬКО когда +1 активного пользователя превышает
// лимит: первое попадание персистит license.over_limit_since, в пределах
// 30 дней создание разрешается (вызывающий пишет аудит-предупреждение),
// после — запрещается (403 license_limit).
func (m *Manager) OverLimit(ctx context.Context) (OverLimitDecision, error) {
	since, err := m.loadTimeTolerant(ctx, keyOverLimit)
	if err != nil {
		return OverLimitDecision{}, err
	}
	now := m.now()
	if since == nil {
		if err := m.saveTime(ctx, keyOverLimit, now); err != nil {
			return OverLimitDecision{}, err
		}
		// Конкурентный процесс мог зафиксировать раньше (ON CONFLICT DO
		// NOTHING) — берём фактическое значение.
		if actual, err := m.loadTimeTolerant(ctx, keyOverLimit); err == nil && actual != nil {
			return OverLimitDecision{Allowed: true, Since: *actual, First: true}, nil
		}
		return OverLimitDecision{Allowed: true, Since: now, First: true}, nil
	}
	return OverLimitDecision{Allowed: now.Sub(*since) <= overLimitGrace, Since: *since}, nil
}

// ClearOverLimit сбрасывает фиксацию превышения (активных стало меньше
// лимита) — следующее превышение начнёт grace-окно заново.
func (m *Manager) ClearOverLimit(ctx context.Context) error {
	return m.deleteKey(ctx, keyOverLimit)
}

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

// loadTimeTolerant читает RFC3339-время из settings с деградацией:
// отсутствующий ключ — nil; битое значение — предупреждение и nil
// (трактуется как отсутствующее), а не ошибка старта и не молчаливая
// перезапись (report §3.8: лицензирование — не повод для аварии сервера).
func (m *Manager) loadTimeTolerant(ctx context.Context, key string) (*time.Time, error) {
	s, err := m.loadString(ctx, key)
	if err != nil || s == "" {
		return nil, err
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		slog.Warn("license: значение не RFC3339 — трактую как отсутствующее", "key", key, "value", s)
		return nil, nil
	}
	return &t, nil
}

// loadBool читает JSON-bool из settings; отсутствующий ключ — false, битое
// значение — предупреждение и false (деградация, не авария).
func (m *Manager) loadBool(ctx context.Context, key string) (bool, error) {
	var raw json.RawMessage
	err := m.st.Pool().QueryRow(ctx,
		`SELECT value FROM settings WHERE key = $1`, key).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("license: чтение %s: %w", key, err)
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err != nil {
		slog.Warn("license: значение не bool — трактую как false", "key", key)
		return false, nil
	}
	return b, nil
}

// saveBool записывает bool как JSON-значение settings.
func (m *Manager) saveBool(ctx context.Context, key string, v bool) error {
	b, err := json.Marshal(v)
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
