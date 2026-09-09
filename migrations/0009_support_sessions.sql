-- 0009_support_sessions: поддержка категорий (IT / 1C), сессии удаленного доступа и делегирование
ALTER TABLE users ADD COLUMN IF NOT EXISTS support_roles TEXT[] NOT NULL DEFAULT '{}';
CREATE INDEX IF NOT EXISTS users_support_roles_idx ON users USING GIN (support_roles);

CREATE TABLE IF NOT EXISTS support_sessions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id           UUID NOT NULL REFERENCES app_devices(id) ON DELETE CASCADE,
    category            TEXT NOT NULL DEFAULT 'it', -- 'it' | '1c'
    status              TEXT NOT NULL DEFAULT 'requested', -- requested | authorizing | approved | active | transferred | rejected | completed | cancelled
    problem_summary     TEXT NOT NULL DEFAULT '',
    assigned_admin_id   UUID REFERENCES users(id) ON DELETE SET NULL,
    transferred_from_id UUID REFERENCES users(id) ON DELETE SET NULL,
    transferred_to_id   UUID REFERENCES users(id) ON DELETE SET NULL,
    transfer_token_hash BYTEA,
    number_match        TEXT NOT NULL DEFAULT '',
    access_mode         TEXT NOT NULL DEFAULT 'full_control', -- full_control | view_only
    started_at          TIMESTAMPTZ,
    ended_at            TIMESTAMPTZ,
    metadata            JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS support_sessions_category_idx ON support_sessions(category, status);
CREATE INDEX IF NOT EXISTS support_sessions_user_idx ON support_sessions(user_id);
CREATE INDEX IF NOT EXISTS support_sessions_status_idx ON support_sessions(status);
