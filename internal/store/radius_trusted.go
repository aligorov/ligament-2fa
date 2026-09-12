// Репозиторий окна доверия RADIUS (настройка radius.trust_days): после
// успешного второго фактора по RADIUS (push_ok или верный TOTP-код) пара
// (пользователь, Calling-Station-Id) доверяется на N дней — повторные
// Wi-Fi/VPN-подключения проходят без второго фактора. Первый фактор
// (пароль) проверяется всегда: доверие снимает только повторный запрос 2FA.
package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// radiusTrustCleanupGrace — janitor удаляет записи, просроченные дольше
// этого срока (запас на ретрансмиты NAS и разбор инцидентов по аудиту).
const radiusTrustCleanupGrace = 7 * 24 * time.Hour

// NormalizeRADIUSCSID приводит Calling-Station-Id к канонической форме:
// lowercase, без разделителей ':' и '-' («AA-BB-CC-DD-EE-FF» и
// «aa:bb:cc:dd:ee:ff» дают один ключ). Пустой результат — доверие
// неприменимо (атрибут отсутствует или не задан NAS-ом).
func NormalizeRADIUSCSID(csid string) string {
	csid = strings.TrimSpace(csid)
	if csid == "" {
		return ""
	}
	return strings.NewReplacer(":", "", "-", "").Replace(strings.ToLower(csid))
}

// RadiusTrustIsTrusted сообщает, действует ли окно доверия для пары
// (пользователь, CSID): запись существует и expires_at > now. Ошибка БД
// трактуется как «не доверенный» (fail-closed); пустой CSID / нулевой
// userID — доверие неприменимо.
func (s *Store) RadiusTrustIsTrusted(ctx context.Context, userID uuid.UUID, csid string) bool {
	key := NormalizeRADIUSCSID(csid)
	if key == "" || userID == uuid.Nil {
		return false
	}
	var ok bool
	err := s.Pool().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM radius_trusted_devices
		WHERE user_id = $1 AND calling_station_id = $2 AND expires_at > now())`,
		userID, key).Scan(&ok)
	if err != nil {
		return false
	}
	return ok
}

// RadiusTrustUpsert создаёт/продлевает окно доверия: expires_at =
// now() + days. days <= 0 (окно выключено) или пустой CSID — no-op.
// Попутно выполняется ленивый janitor просроченных записей — тот же
// цикл, что у challenges (ChallengeCreate): отдельный фоновый воркер
// не нужен, таблица подчищается при очередной записи.
func (s *Store) RadiusTrustUpsert(ctx context.Context, userID uuid.UUID, csid string, days int) error {
	key := NormalizeRADIUSCSID(csid)
	if days <= 0 || key == "" || userID == uuid.Nil {
		return nil
	}
	if _, err := s.Pool().Exec(ctx, `
		WITH cleanup AS (DELETE FROM radius_trusted_devices
			WHERE expires_at < now() - make_interval(secs => $3))
		INSERT INTO radius_trusted_devices (user_id, calling_station_id, expires_at)
		VALUES ($1, $2, now() + make_interval(days => $4))
		ON CONFLICT (user_id, calling_station_id)
		DO UPDATE SET expires_at = EXCLUDED.expires_at`,
		userID, key, int(radiusTrustCleanupGrace.Seconds()), days); err != nil {
		return fmt.Errorf("store: окно доверия RADIUS (user %s): %w", userID, err)
	}
	return nil
}

// RadiusTrustCleanup — janitor таблицы radius_trusted_devices: удаляет
// записи, у которых окно истекло больше radiusTrustCleanupGrace назад.
// Вызывается лениво из RadiusTrustUpsert; пригоден и для фонового цикла.
func (s *Store) RadiusTrustCleanup(ctx context.Context) (int64, error) {
	ct, err := s.Pool().Exec(ctx,
		`DELETE FROM radius_trusted_devices
		 WHERE expires_at < now() - make_interval(secs => $1)`,
		int(radiusTrustCleanupGrace.Seconds()))
	if err != nil {
		return 0, fmt.Errorf("store: janitor radius_trusted_devices: %w", err)
	}
	return ct.RowsAffected(), nil
}
