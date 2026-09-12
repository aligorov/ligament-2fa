-- 0014_radius_trust: окно доверия RADIUS-устройств (настройка radius.trust_days).
-- После успешного второго фактора по RADIUS (push_ok или верный TOTP-код)
-- пара (пользователь, Calling-Station-Id) доверяется на N дней: повторные
-- подключения Wi-Fi/VPN проходят без второго фактора. Пароль (первый
-- фактор) обязателен всегда — доверие снимает только повторный запрос 2FA.
-- CSID хранится в нормализованном виде: lowercase, без ':' и '-'.

CREATE TABLE IF NOT EXISTS radius_trusted_devices (
  id BIGSERIAL PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  calling_station_id TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  UNIQUE (user_id, calling_station_id)
);

-- Janitor удаляет просроченные записи по expires_at (лениво при каждой
-- записи, см. store.RadiusTrustUpsert) — индекс под этот DELETE.
CREATE INDEX IF NOT EXISTS radius_trusted_devices_expires_idx
    ON radius_trusted_devices (expires_at);
