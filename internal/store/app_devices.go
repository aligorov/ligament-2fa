// Репозиторий клиентских приложений (Windows, Android, iOS) и телеметрии.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AppDevice — клиентское приложение (Windows, Android, iOS), авторизованное пользователем.
type AppDevice struct {
	ID              uuid.UUID      `json:"id"`
	UserID          uuid.UUID      `json:"user_id"`
	DeviceName      string         `json:"device_name"`
	Platform        string         `json:"platform"` // windows | android | ios
	PublicKey       []byte         `json:"-"`
	PushToken       string         `json:"push_token,omitempty"`
	TokenHash       []byte         `json:"-"`
	Active          bool           `json:"active"`
	OSVersion       string         `json:"os_version"`
	AppVersion      string         `json:"app_version"`
	SecurityPosture map[string]any `json:"security_posture"`
	LastIP          string         `json:"last_ip"`
	LastSeenAt      time.Time      `json:"last_seen_at"`
	CreatedAt       time.Time      `json:"created_at"`
}

const appDeviceCols = `id, user_id, device_name, platform, public_key, push_token,
	token_hash, active, os_version, app_version, COALESCE(security_posture, '{}'::jsonb),
	last_ip, last_seen_at, created_at`

func scanAppDevice(row scanner) (*AppDevice, error) {
	var d AppDevice
	var postureBytes []byte
	if err := row.Scan(
		&d.ID, &d.UserID, &d.DeviceName, &d.Platform, &d.PublicKey,
		&d.PushToken, &d.TokenHash, &d.Active, &d.OSVersion, &d.AppVersion,
		&postureBytes, &d.LastIP, &d.LastSeenAt, &d.CreatedAt,
	); err != nil {
		return nil, err
	}
	if len(postureBytes) > 0 {
		_ = json.Unmarshal(postureBytes, &d.SecurityPosture)
	}
	if d.SecurityPosture == nil {
		d.SecurityPosture = make(map[string]any)
	}
	return &d, nil
}

// AppDeviceCreate регистрирует новое устройство приложения.
func (s *Store) AppDeviceCreate(ctx context.Context, d *AppDevice) error {
	if d.ID == uuid.Nil {
		d.ID = uuid.New()
	}
	if d.SecurityPosture == nil {
		d.SecurityPosture = make(map[string]any)
	}
	postureJSON, _ := json.Marshal(d.SecurityPosture)
	err := s.Pool().QueryRow(ctx, `
		INSERT INTO app_devices
		(id, user_id, device_name, platform, public_key, push_token, token_hash,
		 active, os_version, app_version, security_posture, last_ip)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING last_seen_at, created_at`,
		d.ID, d.UserID, d.DeviceName, d.Platform, d.PublicKey, d.PushToken,
		d.TokenHash, d.Active, d.OSVersion, d.AppVersion, postureJSON, d.LastIP,
	).Scan(&d.LastSeenAt, &d.CreatedAt)
	if err != nil {
		return fmt.Errorf("store: создать app_device: %w", err)
	}
	return nil
}

// AppDeviceGetByTokenHash находит активное устройство по хешу bearer-токена.
func (s *Store) AppDeviceGetByTokenHash(ctx context.Context, tokenHash []byte) (*AppDevice, error) {
	d, err := scanAppDevice(s.Pool().QueryRow(ctx,
		`SELECT `+appDeviceCols+` FROM app_devices WHERE token_hash = $1 AND active = true`, tokenHash))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: поиск app_device по токену: %w", err)
	}
	return d, nil
}

// AppDeviceListByUser возвращает все зарегистрированные устройства пользователя (включая неактивные).
func (s *Store) AppDeviceListByUser(ctx context.Context, userID uuid.UUID) ([]*AppDevice, error) {
	rows, err := s.Pool().Query(ctx,
		`SELECT `+appDeviceCols+` FROM app_devices WHERE user_id = $1 ORDER BY last_seen_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: список app_devices для %s: %w", userID, err)
	}
	defer rows.Close()

	var out []*AppDevice
	for rows.Next() {
		d, err := scanAppDevice(rows)
		if err != nil {
			return nil, fmt.Errorf("store: сканирование app_device: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// AppDeviceActiveListByUser возвращает только активные авторизованные устройства пользователя.
func (s *Store) AppDeviceActiveListByUser(ctx context.Context, userID uuid.UUID) ([]*AppDevice, error) {
	rows, err := s.Pool().Query(ctx,
		`SELECT `+appDeviceCols+` FROM app_devices WHERE user_id = $1 AND active = true ORDER BY last_seen_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: список активных app_devices для %s: %w", userID, err)
	}
	defer rows.Close()

	var out []*AppDevice
	for rows.Next() {
		d, err := scanAppDevice(rows)
		if err != nil {
			return nil, fmt.Errorf("store: сканирование активного app_device: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// AppDeviceHasActive проверяет, авторизован ли пользователь хотя бы в одном активном приложении.
func (s *Store) AppDeviceHasActive(ctx context.Context, userID uuid.UUID) (bool, error) {
	var exists bool
	err := s.Pool().QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM app_devices WHERE user_id = $1 AND active = true)`, userID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("store: проверка активных app_devices %s: %w", userID, err)
	}
	return exists, nil
}

// AppDeviceUpdateSeen обновляет время активности, IP и снимок телеметрии устройства.
func (s *Store) AppDeviceUpdateSeen(ctx context.Context, id uuid.UUID, ip string, posture map[string]any) error {
	if posture == nil {
		posture = make(map[string]any)
	}
	postureJSON, _ := json.Marshal(posture)
	_, err := s.Pool().Exec(ctx,
		`UPDATE app_devices
		 SET last_seen_at = now(), last_ip = $2, security_posture = $3
		 WHERE id = $1`, id, ip, postureJSON)
	if err != nil {
		return fmt.Errorf("store: обновление активности app_device %s: %w", id, err)
	}
	return nil
}

// AppDeviceUpdatePosture обновляет снимок телеметрии устройства и статус соответствия.
func (s *Store) AppDeviceUpdatePosture(ctx context.Context, id uuid.UUID, posture map[string]any) error {
	if posture == nil {
		posture = make(map[string]any)
	}
	postureJSON, _ := json.Marshal(posture)
	_, err := s.Pool().Exec(ctx,
		`UPDATE app_devices
		 SET last_seen_at = now(), security_posture = $2
		 WHERE id = $1`, id, postureJSON)
	if err != nil {
		return fmt.Errorf("store: обновление телеметрии app_device %s: %w", id, err)
	}
	return nil
}

// AppDeviceUpdatePushToken обновляет APNs/FCM токен устройства.
func (s *Store) AppDeviceUpdatePushToken(ctx context.Context, id uuid.UUID, pushToken string) error {
	_, err := s.Pool().Exec(ctx,
		`UPDATE app_devices SET push_token = $2, last_seen_at = now() WHERE id = $1`, id, pushToken)
	if err != nil {
		return fmt.Errorf("store: обновление push-токена app_device %s: %w", id, err)
	}
	return nil
}

// AppDeviceSetActive включает или отключает устройство (например при logout).
func (s *Store) AppDeviceSetActive(ctx context.Context, id uuid.UUID, userID uuid.UUID, active bool) error {
	ct, err := s.Pool().Exec(ctx,
		`UPDATE app_devices SET active = $3 WHERE id = $1 AND user_id = $2`, id, userID, active)
	if err != nil {
		return fmt.Errorf("store: изменение активности app_device %s: %w", id, err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// AppDeviceDelete удаляет устройство по id и user_id.
func (s *Store) AppDeviceDelete(ctx context.Context, id uuid.UUID, userID uuid.UUID) error {
	ct, err := s.Pool().Exec(ctx,
		`DELETE FROM app_devices WHERE id = $1 AND user_id = $2`, id, userID)
	if err != nil {
		return fmt.Errorf("store: удаление app_device %s: %w", id, err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// AppDeviceRevokeAllForUser отзывает все устройства пользователя (экстренный сброс).
func (s *Store) AppDeviceRevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	_, err := s.Pool().Exec(ctx,
		`UPDATE app_devices SET active = false WHERE user_id = $1`, userID)
	if err != nil {
		return fmt.Errorf("store: отзыв всех app_devices для %s: %w", userID, err)
	}
	return nil
}
