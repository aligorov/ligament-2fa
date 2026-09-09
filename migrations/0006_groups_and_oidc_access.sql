-- 0006_groups_and_oidc_access: локальные группы пользователей,
-- сохранение групп LDAP и контроль доступа к приложениям OIDC.

CREATE TABLE IF NOT EXISTS groups (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT UNIQUE NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS user_groups (
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id   UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, group_id)
);
CREATE INDEX IF NOT EXISTS user_groups_group_id_idx ON user_groups (group_id);
CREATE INDEX IF NOT EXISTS user_groups_user_id_idx ON user_groups (user_id);

-- Сохранение LDAP-групп пользователя для проверок доступа
ALTER TABLE users ADD COLUMN IF NOT EXISTS ldap_groups TEXT[] NOT NULL DEFAULT '{}';

-- Ограничение доступа к OIDC-приложениям (пусто = доступ открыт всем)
ALTER TABLE oidc_clients ADD COLUMN IF NOT EXISTS allowed_users TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE oidc_clients ADD COLUMN IF NOT EXISTS allowed_groups TEXT[] NOT NULL DEFAULT '{}';
