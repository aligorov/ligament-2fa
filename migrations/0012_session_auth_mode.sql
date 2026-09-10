-- 0012_session_auth_mode: режим входа web-сессии для честного клейма amr
-- (аудит раунд-2, Фаза 2b: OIDC раньше всегда заверял pwd,mfa).

-- sessions.auth_mode: каким способом пользователь аутентифицировался при
-- выдаче сессии — password+code / passkey / push_match / trusted_device /
-- password_only (см. api startSession). Пусто — легаси-сессии, созданные до
-- миграции: OIDC маппит их в безопасный дефолт pwd,mfa (не занижает заверение).
ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS auth_mode TEXT NOT NULL DEFAULT '';
