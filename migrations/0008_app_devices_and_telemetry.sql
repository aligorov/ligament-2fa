-- 0008_app_devices_and_telemetry: устройства мобильных и десктопных приложений Ligament 2FA,
-- метаданные челленджей и профиль безопасности (телеметрия).

CREATE TABLE IF NOT EXISTS app_devices (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_name       TEXT NOT NULL DEFAULT '',
    platform          TEXT NOT NULL DEFAULT '',       -- windows | android | ios
    public_key        BYTEA,                          -- Ed25519 публичный ключ для подписи
    push_token        TEXT NOT NULL DEFAULT '',       -- APNs / FCM токен
    token_hash        BYTEA NOT NULL UNIQUE,          -- SHA-256 bearer токена сессии устройства
    active            BOOLEAN NOT NULL DEFAULT true,  -- false при logout или отзыве
    os_version        TEXT NOT NULL DEFAULT '',
    app_version       TEXT NOT NULL DEFAULT '',
    security_posture  JSONB NOT NULL DEFAULT '{}'::jsonb, -- bitlocker, defender, firewall, root/jailbreak
    last_ip           TEXT NOT NULL DEFAULT '',
    last_seen_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS app_devices_user_id_idx ON app_devices(user_id);
CREATE INDEX IF NOT EXISTS app_devices_active_idx ON app_devices(user_id, active);

-- Расширение таблицы challenges: метаданные сессии и код для Number Matching
ALTER TABLE challenges ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb;
