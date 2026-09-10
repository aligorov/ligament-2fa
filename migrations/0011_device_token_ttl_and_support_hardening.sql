-- 0011_device_token_ttl_and_support_hardening: TTL device-токенов приложений
-- и метка времени переадресации support-сессий (аудит раунд-2, Фаза 2a).

-- app_devices.expires_at: срок жизни bearer-токена устройства (90 дней,
-- sliding-продление при использовании — см. store.AppDeviceTouch). Существующие
-- строки получают 90 дней от момента применения миграции.
ALTER TABLE app_devices
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '90 days');

-- support_sessions.transferred_at: момент выдачи transfer-токена — окно
-- 10 минут на принятие переадресации (store.SupportSessionGetByTransferToken).
ALTER TABLE support_sessions
    ADD COLUMN IF NOT EXISTS transferred_at TIMESTAMPTZ;
