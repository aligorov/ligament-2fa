-- Файрвол/fail2ban: статичные чёрные/белые списки CIDR и автоблокировки
-- по IP (счётчик неудач входа/кода/RADIUS в окне → бан на срок).

CREATE TABLE IF NOT EXISTS ip_lists (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind       TEXT NOT NULL CHECK (kind IN ('allow', 'deny')),
    cidr       TEXT NOT NULL,              -- нормализованный IP или CIDR
    note       TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (kind, cidr)
);

CREATE TABLE IF NOT EXISTS ip_bans (
    ip           TEXT PRIMARY KEY,         -- конкретный IP клиента (не CIDR)
    reason       TEXT NOT NULL,            -- login_fail | code_fail | radius_fail
    fails        INT  NOT NULL,
    banned_until TIMESTAMPTZ NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ip_bans_until_idx ON ip_bans (banned_until);
